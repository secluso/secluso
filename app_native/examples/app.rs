//! Simple app to use Secluso's native API
//!
//! SPDX-License-Identifier: GPL-3.0-or-later

#[macro_use]
extern crate serde_derive;

use secluso_client_lib::livestream_session::LivestreamSession;
use secluso_app_native::{
    get_subscription_uuid,
    Clients, add_camera, decrypt_video, deregister, generate_heartbeat_request_config_command,
    get_group_name, initialize, livestream_decrypt, livestream_update,
    process_heartbeat_config_response, generate_add_app_request_config_command,
    process_add_app_config_response, join_camera_groups,
    get_key_packages, decrypt_thumbnail, generate_remove_app_request_config_command,
    process_remove_app_config_response,
};
use secluso_client_lib::http_client::HttpClient;
use secluso_client_lib::pairing::{NUM_SECRET_BYTES};
use secluso_app_native::get_object_key;
use secluso_client_lib::object_name::{object_name, object_name_with_kind};
use secluso_client_server_lib::auth::parse_user_credentials_any;
use secluso_client_lib::mls_clients::{MOTION, THUMBNAIL, NUM_MLS_CLIENTS};
use docopt::Docopt;
use std::env;
use std::fs;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;
use std::sync::Arc;
use std::sync::{LazyLock, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// This is a simple app that pairs with the Secluso camera, receives motion videos,
// and launches livestream sessions.
// To use it, place the user_credentials and camera_secret file in the app root directory.
// It assumes that the camera and the server run in the same machine.
// If needed, change the constants below to change that assumption.
// To run:
// $ cargo run --release --example app --features for-example

const CAMERA_ADDR: &str = "127.0.0.1";
const CAMERA_NAME: &str = "Camera";
const DATA_DIR: &str = "example_app_data";

pub const MAX_ALLOWED_MSG_LEN: u64 = 65536;

// The name used by the camera to refer to this app.
static MY_NAME: LazyLock<Mutex<String>> =
    LazyLock::new(|| Mutex::new(String::new()));

const USAGE: &str = "
Runs a simple Secluso app.

Usage:
  app [--num-iters ITERS] [--secondary-app]
  app --reset
  secluso-config-tool (--version | -v)
  secluso-config-tool (--help | -h)

Options:
    --num-iters ITERS               Sets the number of iterations in the app's main loop. Each iteration is about 1 second. [default: 150]
    --secondary-app                 Specifies that this app needs to join the camera group via another app.
    --reset                         Resets the state
    --version, -v                   Show tool version.
    --help, -h                      Show this screen.
";

#[derive(Debug, Deserialize)]
struct Args {
    flag_num_iters: usize,
    flag_secondary_app: bool,
    flag_reset: bool,
}

/// The naming key for a group (or None when self-hosted)
fn object_key_for(
    http_client: &HttpClient,
    clients: &mut Option<Box<Clients>>,
    client_tag: &str,
) -> Option<Vec<u8>> {
    if !http_client.backend().is_enterprise() {
        return None;
    }

    match get_object_key(clients, client_tag) {
        Ok(key) => Some(key),
        Err(e) => {
            println!("Could not derive the object naming key: {e}");
            None
        }
    }
}

fn main() -> io::Result<()> {
    let version = env!("CARGO_PKG_NAME").to_string() + ", version: " + env!("CARGO_PKG_VERSION");

    let args: Args = Docopt::new(USAGE)
        .map(|d| d.help(true))
        .map(|d| d.version(Some(version)))
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    let file = File::open("user_credentials").expect("Cannot open file to read");
    let mut reader =
        BufReader::with_capacity(file.metadata().unwrap().len().try_into().unwrap(), file);
    let credentials_full = reader.fill_buf().unwrap();
    let credentials = parse_user_credentials_any(credentials_full.to_vec()).unwrap();
    let (server_username, server_password, server_addr) = (
        credentials.username.clone(),
        credentials.password.clone(),
        credentials.server_addr.clone(),
    );

    fs::create_dir_all(format!("{}/videos", DATA_DIR)).unwrap();
    fs::create_dir_all(format!("{}/encrypted", DATA_DIR)).unwrap();

    let first_time_path = Path::new(DATA_DIR).join("first_time_done");
    let first_time: bool = !first_time_path.exists();

    let clients: Arc<Mutex<Option<Box<Clients>>>> = Arc::new(Mutex::new(None));
    let http_client = HttpClient::new_with_backend(
        server_addr,
        server_username,
        server_password,
        credentials.backend,
    );

    // No-op against the self-hosted DS, which has no accounts.
    if let Err(e) = http_client.register() {
        println!("Could not register with the delivery service: {e}");
    }

    // We assume here that the new secret is shared via
    // another channel, e.g., QR code scan.
    // Also, a new secret needs to be used for every app added.
    let add_app_secret = vec![2u8; NUM_SECRET_BYTES];

    if first_time {
        if args.flag_reset {
            panic!("No state to reset!");
        }

        initialize(&mut clients.lock().unwrap(), format!("{}", DATA_DIR), true)?;
        
        let credentials_full_string = String::from_utf8(credentials_full.to_vec()).unwrap();

        let add_camera_result = if !args.flag_secondary_app {
            let file2 = File::open("camera_secret").expect("Cannot open file to send");
            let mut reader2 =
                BufReader::with_capacity(file2.metadata().unwrap().len().try_into().unwrap(), file2);
            let secret_vec = reader2.fill_buf().unwrap();

            add_camera(
                &mut clients.lock().unwrap(),
                CAMERA_NAME.to_string(),
                CAMERA_ADDR.to_string(),
                secret_vec.to_vec(),
                false,
                "".to_string(),
                "".to_string(),
                "".to_string(),
                credentials_full_string,
                false,
                http_client.subscription_uuid().unwrap_or_default(),
            )
        } else {
            println!("Sending the add_app request");

            // get key packages
            let key_packages_vec = get_key_packages(&mut clients.lock().unwrap())?;

            println!("About to send add_app request");
            http_client.send_msg("test_add_app_request_token", key_packages_vec)?;
            println!("About to wait for add_app response");
            let new_app_data_vec = http_client.receive_msg("test_add_app_response_token")?;
            println!("Received add_app response");

            let (epochs, my_name): ([u64; NUM_MLS_CLIENTS], String) = join_camera_groups(
                &mut clients.lock().unwrap(),
                add_app_secret.clone(),
                new_app_data_vec,
            )?;

            *MY_NAME.lock().unwrap() = my_name;

            write_epoch("motion_epoch", epochs[MOTION] + 1);
            write_epoch("thumbnail_epoch", epochs[THUMBNAIL] + 1);

            "".to_string()
        };

        if add_camera_result == "Error".to_string() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Error: Failed to add camera."),
            ));
        }

        File::create(&first_time_path).expect("Could not create file");
    } else {
        initialize(&mut clients.lock().unwrap(), format!("{}", DATA_DIR), false)?;

        if args.flag_reset {
            return deregister_all(clients, &http_client);
        }
    }

    // The paired camera's subscription which is saved during pairing/add-app.
    if let Ok(uuid) = get_subscription_uuid(&clients.lock().unwrap()) {
        http_client.set_subscription_uuid(Some(uuid));
    }

    let add_app_request: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));

    if !args.flag_secondary_app {
        let add_app_request_clone = Arc::clone(&add_app_request);
        let http_client_clone = http_client.clone();

        thread::spawn(move || loop {
            println!("About to wait for add_app request");
            match http_client_clone.receive_msg("test_add_app_request_token") {
                Ok(data) => {
                    println!("Received add_app request.");
                    let mut data_opt = add_app_request_clone.lock().unwrap();
                    *data_opt = Some(data);
                },

                Err(e) => {
                    println!("Error listening for add_app requests: {e}");
                }
            }        
        });
    }

    main_loop(
        clients,
        http_client,
        add_app_request,
        args.flag_num_iters,
        add_app_secret,
    )?;

    Ok(())
}

fn deregister_all(
    clients: Arc<Mutex<Option<Box<Clients>>>>,
    http_client: &HttpClient,
) -> io::Result<()> {
    let motion_group_name = get_group_name(&mut clients.lock().unwrap(), "motion")?;
    let livestream_group_name = get_group_name(&mut clients.lock().unwrap(), "livestream")?;
    deregister(&mut clients.lock().unwrap());
    let _ = http_client.deregister(&motion_group_name);
    let _ = http_client.deregister(&livestream_group_name);

    fs::remove_dir_all(DATA_DIR).unwrap();

    Ok(())
}

fn main_loop(
    clients: Arc<Mutex<Option<Box<Clients>>>>,
    http_client: HttpClient,
    add_app_request: Arc<Mutex<Option<Vec<u8>>>>,
    num_iters: usize,
    add_app_secret: Vec<u8>,
) -> io::Result<()> {
    let mut remove_app_needed = false;
    let mut remove_app_iter: usize = 60;
    let mut remove_app_name = "".to_string();

    for iter in 0..num_iters {
        thread::sleep(Duration::from_secs(1));

        fetch_motion_videos(Arc::clone(&clients), &http_client)?;

        fetch_thumbnails(Arc::clone(&clients), &http_client)?;

        if iter % 60 == 29 {
            let terminate = heartbeat(Arc::clone(&clients), &http_client)?;
            if terminate {
                return Ok(());
            }
        }

        if iter % 60 == 59 {
            livestream(Arc::clone(&clients), &http_client, 2)?;
        }

        if remove_app_needed {
            remove_app_iter -= 1;
            if remove_app_iter <= 0 {
                remove_app(
                    Arc::clone(&clients),
                    &http_client,
                    &remove_app_name
                )?;
            }
        }

        let mut add_app_data_opt = add_app_request.lock().unwrap();
        if let Some(add_app_data) = add_app_data_opt.as_ref() {
            println!("Add app request detected");
            let app_name = handle_add_app_request(
                Arc::clone(&clients),
                &http_client,
                add_app_data,
                add_app_secret.clone(),
            )?;
            *add_app_data_opt = None;

            if !remove_app_needed {
                println!("Scheduling this app to be removed");
                remove_app_needed = true;
                remove_app_name = app_name;
            }
        }
    }

    Ok(())
}

fn handle_add_app_request(
    clients: Arc<Mutex<Option<Box<Clients>>>>,
    http_client: &HttpClient,
    add_app_data: &Vec<u8>,
    add_app_secret: Vec<u8>,
) -> io::Result<String> {
    println!("handle_add_app_request called");

    let new_app_key_packages_vec = add_app_data.clone();

    let config_msg_enc =
        generate_add_app_request_config_command(&mut clients.lock().unwrap(), new_app_key_packages_vec, add_app_secret.clone())?;

    let config_group_name = get_group_name(&mut clients.lock().unwrap(), "config")?;

    println!("Sending add_app request.");
    http_client.config_command(&config_group_name, config_msg_enc)?;

    let mut config_response_opt: Option<Vec<u8>> = None;
    for _i in 0..30 {
        println!("Attempt {_i}");
        thread::sleep(Duration::from_secs(2));
        match http_client.fetch_config_response(&config_group_name) {
            Ok(resp) => {
                config_response_opt = Some(resp);
                break;
            }
            Err(_) => {}
        }
    }

    if config_response_opt.is_none() {
        println!("Error: couldn't fetch the add_app response. Camera might be offline.");
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Error: couldn't fetch the add_app response. Camera might be offline."),
        ));
    }

    let config_response = config_response_opt.unwrap();

    let (new_app_data_vec, new_app_name) = process_add_app_config_response(
        &mut clients.lock().unwrap(),
        config_response.clone(),
        add_app_secret,
    ).unwrap();

    increment_epoch("motion_epoch");
    increment_epoch("thumbnail_epoch");

    http_client.send_msg("test_add_app_response_token", new_app_data_vec)?;

    Ok(new_app_name)
}

fn remove_app(
    clients: Arc<Mutex<Option<Box<Clients>>>>,
    http_client: &HttpClient,
    app_name: &str,
) -> io::Result<()> {
    println!("remove_app called");

    let config_msg_enc =
        generate_remove_app_request_config_command(&mut clients.lock().unwrap(), app_name)?;

    let config_group_name = get_group_name(&mut clients.lock().unwrap(), "config")?;

    println!("Sending remove_app request.");
    http_client.config_command(&config_group_name, config_msg_enc)?;

    let mut config_response_opt: Option<Vec<u8>> = None;
    for _i in 0..30 {
        println!("Attempt {_i}");
        thread::sleep(Duration::from_secs(2));
        match http_client.fetch_config_response(&config_group_name) {
            Ok(resp) => {
                config_response_opt = Some(resp);
                break;
            }
            Err(_) => {}
        }
    }

    if config_response_opt.is_none() {
        println!("Error: couldn't fetch the remove_app response. Camera might be offline.");
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Error: couldn't fetch the add_app response. Camera might be offline."),
        ));
    }

    let config_response = config_response_opt.unwrap();

    process_remove_app_config_response(
        &mut clients.lock().unwrap(),
        config_response.clone(),
    ).unwrap();

    increment_epoch("motion_epoch");
    increment_epoch("thumbnail_epoch");

    Ok(())
}

fn heartbeat(
    clients: Arc<Mutex<Option<Box<Clients>>>>,
    http_client: &HttpClient,
) -> io::Result<bool> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Could not convert time")
        .as_secs();

    let config_msg_enc =
        generate_heartbeat_request_config_command(&mut clients.lock().unwrap(), timestamp)?;

    let config_group_name = get_group_name(&mut clients.lock().unwrap(), "config")?;
    let livestream_group_name = get_group_name(&mut clients.lock().unwrap(), "livestream")?;

    println!("Sending heartbeat request: {}", timestamp);

    http_client.config_command(&config_group_name, config_msg_enc)?;

    let mut received_heartbeat: bool = false;
    for _i in 0..30 {
        println!("Attempt {_i}");
        thread::sleep(Duration::from_secs(2));
        // We want to fetch all pending videos and thumbnails before checking for the heartbeat response.
        let _ = fetch_motion_videos(Arc::clone(&clients), http_client);
        let _ = fetch_thumbnails(Arc::clone(&clients), http_client);
        let mut config_response_opt: Option<Vec<u8>> = None;
        match http_client.fetch_config_response(&config_group_name) {
            Ok(resp) => {
                config_response_opt = Some(resp);
            }
            Err(_) => {}
        }

        if config_response_opt.is_none() {
            continue;
        }

        let config_response = config_response_opt.unwrap();

        println!("About to call process_heartbeat_config");
        match process_heartbeat_config_response(
            &mut clients.lock().unwrap(),
            config_response.clone(),
            timestamp,
        ) {
            Ok(response) if response.contains("\"status\":\"healthy\"") => {
                println!("Healthy heartbeat");
                println!("{response}");
                received_heartbeat = true;
                break;
            }
            Ok(response) if response.contains("\"status\":\"invalid ciphertext\"") => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("The connection to the camera is corrupted. Pair the app with the camera again."),
                ));
            }
            Ok(response) if response.contains("add_app") => {
                println!("Received and processed the new add_app commit.");
                println!("{response}");
                increment_epoch("motion_epoch");
                increment_epoch("thumbnail_epoch");
            }
            Ok(response) if response.contains("remove_app") => {
                println!("Received remove_app notification.");
                let my_name: String = MY_NAME.lock().unwrap().clone();
                println!("my_name = {my_name}");
                let removed_app_name = response
                    .strip_prefix("remove_app")
                    .expect("Couldn't extract the removed app name");

                println!("removed_app_name = {response}");
                if my_name == removed_app_name {
                    println!("We have been removed. Terminating now.");
                    // Remove dedicated group names from server before terminating
                    http_client.deregister(&livestream_group_name)?;
                    http_client.deregister(&config_group_name)?;
                    return Ok(true);
                } else {
                    println!("Another app has been removed. Updating epochs.");
                    increment_epoch("motion_epoch");
                    increment_epoch("thumbnail_epoch");
                }
            }
            Ok(response) => {
                //invalid timestamp || invalid epoch
                // FIXME: Before processing the heartbeat response, we should make sure all motion videos are fetched and processed.
                // But we're not doing that here, therefore an "invalid epoch" might not mean a corrupted channel.
                println!("{response}");
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("The connection to the camera might have got corrupted. Consider pairing the app with the camera again."),
                ));
            }
            Err(e) => {
                println!("Error processing heartbeat response {e}");
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("The connection to the camera might have got corrupted. Consider pairing the app with the camera again."),
                ));
            }
        }
    }

    if !received_heartbeat {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Error: couldn't fetch the heartbeat response. Camera might be offline."),
        ));
    }

    Ok(false)
}

fn read_epoch(epoch_filename: &str) -> u64 {
    let epoch_file_path = Path::new(DATA_DIR).join(epoch_filename);

    if epoch_file_path.exists() {
        let file = File::open(&epoch_file_path).expect("Cannot open motion_epoch file");
        let mut reader =
            BufReader::with_capacity(file.metadata().unwrap().len().try_into().unwrap(), file);
        let epoch_data = reader.fill_buf().unwrap();
        bincode::deserialize(epoch_data).unwrap()
    } else {
        // The first motion video will be sent in MLS epoch 2.
        2
    }
}

fn write_epoch(epoch_filename: &str, epoch: u64) {
    let epoch_file_path = Path::new(DATA_DIR).join(epoch_filename);

    let epoch_data = bincode::serialize(&epoch).unwrap();
    let mut file =
        fs::File::create(&epoch_file_path).expect("Could not create motion_epoch file");
    file.write_all(&epoch_data).unwrap();
    file.flush().unwrap();
    file.sync_all().unwrap();
}

fn increment_epoch(epoch_filename: &str) {
    let epoch = read_epoch(epoch_filename);
    write_epoch(epoch_filename, epoch + 1);
}

fn fetch_motion_videos(
    clients: Arc<Mutex<Option<Box<Clients>>>>,
    http_client: &HttpClient,
) -> io::Result<()> {
    let mut clients_locked = clients.lock().unwrap();
    let mut epoch = read_epoch("motion_epoch");
    println!("fetch_motion_videos: checking for epoch {epoch}");  

    loop {
        let group_name = get_group_name(&mut clients_locked, "motion")?;

        let enc_filename = format!("{}", epoch);
        let enc_filepath = Path::new(DATA_DIR).join("encrypted").join(&enc_filename);

        let derived = object_key_for(http_client, &mut clients_locked, "motion")
            .map(|key| object_name(key.as_slice(), &group_name, epoch))
            .transpose()?;
        match http_client.fetch_enc_file(&group_name, &enc_filepath, derived.as_deref()) {
            Ok(_) => {
                let dec_filename = decrypt_video(&mut clients_locked, enc_filename).unwrap();
                let _ = fs::remove_file(enc_filepath);
                println!("Received and decrypted {:?} (epoch = {epoch})", dec_filename);
                epoch += 1;
                write_epoch("motion_epoch", epoch);

                return Ok(());
            }

            Err(e) => {
                if e.to_string().contains("404") {
                    return Ok(());
                } else {
                    return Err(e);
                }
            }
        }
    }
}

fn fetch_thumbnails(
    clients: Arc<Mutex<Option<Box<Clients>>>>,
    http_client: &HttpClient,
) -> io::Result<()> {
    let mut clients_locked = clients.lock().unwrap();
    let mut epoch = read_epoch("thumbnail_epoch");

    loop {
        let group_name = get_group_name(&mut clients_locked, "thumbnail")?;

        let enc_filename = format!("{}", epoch);
        let enc_filepath = Path::new(DATA_DIR).join("encrypted").join(&enc_filename);
        // A thumbnail shares its epoch with its video
        let derived = object_key_for(http_client, &mut clients_locked, "thumbnail")
            .map(|key| object_name_with_kind(key.as_slice(), &group_name, epoch, "thumbnail"))
            .transpose()?;
        match http_client.fetch_enc_file(&group_name, &enc_filepath, derived.as_deref()) {
            Ok(_) => {
                let dec_filename = decrypt_thumbnail(&mut clients_locked, enc_filename, DATA_DIR.to_string()).unwrap();
                let _ = fs::remove_file(enc_filepath);
                println!("Received and decrypted {:?} (epoch = {epoch})", dec_filename);
                epoch += 1;
                write_epoch("thumbnail_epoch", epoch);

                return Ok(());
            }

            Err(e) => {
                if e.to_string().contains("404") {
                    return Ok(());
                } else {
                    return Err(e);
                }
            }
        }
    }
}

fn livestream(
    clients: Arc<Mutex<Option<Box<Clients>>>>,
    http_client: &HttpClient,
    num_chunks: u64,
) -> io::Result<()> {
    let group_name = get_group_name(&mut clients.lock().unwrap(), "livestream")?;

    http_client.livestream_start(&group_name)?;

    // Chunk 0 = MLS commit. ALWAYS goes over the relay.
    let commit_msg = fetch_livestream_chunk(http_client, &group_name, 0)?;
    livestream_update(&mut clients.lock().unwrap(), commit_msg)?;

    // Now try for a direct path. (p2p)
    let session = open_livestream_session(http_client, &group_name);
    println!("Livestreaming over the {:?} path", session.path());

    for i in 1..num_chunks {
        let enc_data = fetch_livestream_chunk_via(&session, http_client, &group_name, i)?;
        let dec_data = livestream_decrypt(&mut clients.lock().unwrap(), enc_data, i as u64)?;
        println!("Received {} of livestream data.", dec_data.len());
    }

    http_client.livestream_end(&group_name)?;
    println!("Finished livestreaming!");

    Ok(())
}

/// Open a livestream session, trying for a direct path to the camera
#[cfg(feature = "p2p")]
fn open_livestream_session(http_client: &HttpClient, group_name: &str) -> LivestreamSession {
    LivestreamSession::open_direct(
        http_client.clone(),
        group_name,
        group_name,
        secluso_client_lib::p2p::Role::App,
    )
}

#[cfg(not(feature = "p2p"))]
fn open_livestream_session(http_client: &HttpClient, group_name: &str) -> LivestreamSession {
    LivestreamSession::open(http_client.clone(), group_name, group_name)
}

/// Fetch a chunk.
fn fetch_livestream_chunk_via(
    session: &LivestreamSession,
    http_client: &HttpClient,
    group_name: &str,
    chunk_number: u64,
) -> io::Result<Vec<u8>> {
    for _i in 0..5 {
        match session.retrieve_chunk(chunk_number) {
            Ok(data) => return Ok(data),
            Err(e) => eprintln!("retrieve_chunk({chunk_number}) attempt failed: {e}"),
        }
        thread::sleep(Duration::from_secs(1));
    }

    let _ = http_client;
    let _ = group_name;

    Err(io::Error::other(
        "Error: could not fetch livestream chunk (timeout)!".to_string(),
    ))
}

fn fetch_livestream_chunk(
    http_client: &HttpClient,
    group_name: &str,
    chunk_number: u64,
) -> io::Result<Vec<u8>> {
    for _i in 0..5 {
        match http_client.livestream_retrieve(group_name, chunk_number) {
            Ok(data) => return Ok(data),
            Err(e) => eprintln!("livestream_retrieve({chunk_number}) attempt failed: {e}"),
        }
        thread::sleep(Duration::from_secs(1));
    }

    return Err(io::Error::new(
        io::ErrorKind::Other,
        format!("Error: could not fetch livestream chunk (timeout)!"),
    ));
}
