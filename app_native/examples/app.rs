//! Simple app to use Secluso's native API
//!
//! SPDX-License-Identifier: GPL-3.0-or-later

#[macro_use]
extern crate serde_derive;

use secluso_app_native::{
    Clients, add_camera, decrypt_video, deregister, generate_heartbeat_request_config_command,
    get_group_name, initialize, livestream_decrypt, livestream_update,
    process_heartbeat_config_response, generate_add_app_request_config_command,
    process_add_app_config_response, join_camera_groups,
    get_key_packages, decrypt_thumbnail,
};
use secluso_client_lib::http_client::HttpClient;
use secluso_client_lib::pairing::{NUM_SECRET_BYTES};
use secluso_client_server_lib::auth::parse_user_credentials_full;
use secluso_client_lib::mls_clients::{MOTION, THUMBNAIL, NUM_MLS_CLIENTS};
use docopt::Docopt;
use std::env;
use std::fs;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write, Read};
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::net::{TcpListener, TcpStream, SocketAddr};
use std::str::FromStr;
use std::io::ErrorKind;

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
const FIRST_APP_ADDR: &str = "127.0.0.1";

pub const MAX_ALLOWED_MSG_LEN: u64 = 65536;

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
    let (server_username, server_password, server_addr) =
        parse_user_credentials_full(credentials_full.to_vec()).unwrap();

    fs::create_dir_all(format!("{}/videos", DATA_DIR)).unwrap();
    fs::create_dir_all(format!("{}/encrypted", DATA_DIR)).unwrap();

    let first_time_path = Path::new(DATA_DIR).join("first_time_done");
    let first_time: bool = !first_time_path.exists();

    let clients: Arc<Mutex<Option<Box<Clients>>>> = Arc::new(Mutex::new(None));
    let http_client = HttpClient::new(server_addr, server_username, server_password);

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
            )
        } else {
            println!("Sending the add_app request");
            let addr = SocketAddr::from_str(&(FIRST_APP_ADDR.to_owned() + ":12350"))
                .map_err(|e| io::Error::other(format!("{e}")))?;

            let mut stream = TcpStream::connect(&addr)?;

            // get key packages
            let key_packages_vec = get_key_packages(&mut clients.lock().unwrap())?;

            write_varying_len(&mut stream, &key_packages_vec)?;

            let new_app_data_vec = read_varying_len(&mut stream)?;

            // We assume here that the new secret is shared via
            // another channel, e.g., QR code scan.
            let new_secret = vec![2u8; NUM_SECRET_BYTES];

            let epochs: [u64; NUM_MLS_CLIENTS] = join_camera_groups(
                &mut clients.lock().unwrap(),
                new_secret.clone(),
                new_app_data_vec,
            )?;

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

    let add_app_request: Arc<Mutex<Option<TcpStream>>> = Arc::new(Mutex::new(None));

    if !args.flag_secondary_app {
        let add_app_request_clone = Arc::clone(&add_app_request);

        thread::spawn(move || loop {
            let listener = TcpListener::bind("0.0.0.0:12350").unwrap();
            for incoming in listener.incoming() {
                match incoming {
                    Ok(stream) => {
                        println!("Incoming connection accepted.");
                        let mut stream_opt = add_app_request_clone.lock().unwrap();
                        *stream_opt = Some(stream);
                    },

                    Err(e) => {
                        println!("Incoming connection error: {e}");
                    }
                }        
            }
        });
    }

    main_loop(clients, http_client, add_app_request, args.flag_num_iters)?;

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
    add_app_request: Arc<Mutex<Option<TcpStream>>>,
    num_iters: usize,
) -> io::Result<()> {
    for iter in 0..num_iters {
        thread::sleep(Duration::from_secs(1));

        fetch_motion_videos(Arc::clone(&clients), &http_client)?;

        fetch_thumbnails(Arc::clone(&clients), &http_client)?;

        if iter % 60 == 29 {
            heartbeat(Arc::clone(&clients), &http_client)?;
        }

        if iter % 60 == 59 {
            livestream(Arc::clone(&clients), &http_client, 2)?;
        }

        let mut add_app_stream_opt = add_app_request.lock().unwrap();
        if let Some(add_app_stream) = add_app_stream_opt.as_mut() {
            println!("Add app request detected");
            handle_add_app_request(
                Arc::clone(&clients),
                &http_client,
                add_app_stream,
            )?;
            *add_app_stream_opt = None;
        }
    }

    Ok(())
}

fn handle_add_app_request(
    clients: Arc<Mutex<Option<Box<Clients>>>>,
    http_client: &HttpClient,
    stream: &mut TcpStream,
) -> io::Result<()> {
    println!("handle_add_app_request called");
    let new_secret = vec![2u8; NUM_SECRET_BYTES];

    let new_app_key_packages_vec = read_varying_len(stream)?;

    let config_msg_enc =
        generate_add_app_request_config_command(&mut clients.lock().unwrap(), new_app_key_packages_vec, new_secret.clone())?;

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
        return Ok(());
    }

    let config_response = config_response_opt.unwrap();

    let new_app_data_vec = process_add_app_config_response(
        &mut clients.lock().unwrap(),
        config_response.clone(),
        new_secret,
    ).unwrap();

    increment_epoch("motion_epoch");
    increment_epoch("thumbnail_epoch");

    write_varying_len(stream, &new_app_data_vec)?;

    Ok(())
}

fn heartbeat(
    clients: Arc<Mutex<Option<Box<Clients>>>>,
    http_client: &HttpClient,
) -> io::Result<()> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Could not convert time")
        .as_secs();

    let config_msg_enc =
        generate_heartbeat_request_config_command(&mut clients.lock().unwrap(), timestamp)?;

    let config_group_name = get_group_name(&mut clients.lock().unwrap(), "config")?;

    println!("Sending heartbeat request: {}", timestamp);
    http_client.config_command(&config_group_name, config_msg_enc)?;

    let mut config_response_opt: Option<Vec<u8>> = None;
    for _i in 0..30 {
        println!("Attempt {_i}");
        thread::sleep(Duration::from_secs(2));
        // We want to fetch all pending videos and thumbnails before checking for the heartbeat response.
        let _ = fetch_motion_videos(Arc::clone(&clients), http_client);
        let _ = fetch_thumbnails(Arc::clone(&clients), http_client);
        match http_client.fetch_config_response(&config_group_name) {
            Ok(resp) => {
                config_response_opt = Some(resp);
                break;
            }
            Err(_) => {}
        }
    }

    if config_response_opt.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Error: couldn't fetch the heartbeat response. Camera might be offline."),
        ));
    }

    let config_response = config_response_opt.unwrap();

    match process_heartbeat_config_response(
        &mut clients.lock().unwrap(),
        config_response.clone(),
        timestamp,
    ) {
        Ok(response) if response.contains("\"status\":\"healthy\"") => {
            println!("Healthy heartbeat");
            println!("{response}");
        }
        Ok(response) if response.contains("\"status\":\"invalid ciphertext\"") => {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("The connection to the camera is corrupted. Pair the app with the camera again."),
            ));
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

    Ok(())
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

    loop {
        let group_name = get_group_name(&mut clients_locked, "motion")?;

        let enc_filename = format!("{}", epoch);
        let enc_filepath = Path::new(DATA_DIR).join("encrypted").join(&enc_filename);
        match http_client.fetch_enc_file(&group_name, &enc_filepath) {
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
        match http_client.fetch_enc_file(&group_name, &enc_filepath) {
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

    let commit_msg = fetch_livestream_chunk(http_client, &group_name, 0)?;
    livestream_update(&mut clients.lock().unwrap(), commit_msg)?;

    for i in 1..num_chunks {
        let enc_data = fetch_livestream_chunk(http_client, &group_name, i)?;
        let dec_data = livestream_decrypt(&mut clients.lock().unwrap(), enc_data, i as u64)?;
        println!("Received {} of livestream data.", dec_data.len());
    }

    http_client.livestream_end(&group_name)?;
    println!("Finished livestreaming!");

    Ok(())
}

fn fetch_livestream_chunk(
    http_client: &HttpClient,
    group_name: &str,
    chunk_number: u64,
) -> io::Result<Vec<u8>> {
    for _i in 0..5 {
        if let Ok(data) = http_client.livestream_retrieve(group_name, chunk_number) {
            return Ok(data);
        }
        thread::sleep(Duration::from_secs(1));
    }

    return Err(io::Error::new(
        io::ErrorKind::Other,
        format!("Error: could not fetch livestream chunk (timeout)!"),
    ));
}

// FIXME: copied from camera_hub/src/pairing.rs.
fn write_varying_len(stream: &mut TcpStream, msg: &[u8]) -> io::Result<()> {
    // FIXME: is u64 necessary?
    let len = msg.len() as u64;
    let len_data = len.to_be_bytes();

    stream.write_all(&len_data)?;
    stream.write_all(msg)?;
    stream.flush()?;

    Ok(())
}

fn read_varying_len(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut len_data = [0u8; 8];

    match stream.read_exact(&mut len_data) {
        Ok(_) => {}
        Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
            return Err(io::Error::new(
                ErrorKind::WouldBlock,
                "Length read would block",
            ));
        }
        Err(e) => return Err(e),
    }

    let len = u64::from_be_bytes(len_data);

    if len > MAX_ALLOWED_MSG_LEN {
        println!("Communicated message length ({len}) exceeds the allowed length ({MAX_ALLOWED_MSG_LEN})");
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "Intended message length is too large",
        ))
    }

    let mut msg = vec![0u8; len as usize];
    let mut offset = 0;

    while offset < msg.len() {
        match stream.read(&mut msg[offset..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "Socket closed during read",
                ))
            }
            Ok(n) => {
                offset += n;
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                // retry a few times with a short delay
                thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(e) => return Err(e),
        }
    }

    Ok(msg)
}
