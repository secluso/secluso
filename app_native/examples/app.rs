//! Simple app to use Secluso's native API
//!
//! Copyright (C) 2025  Ardalan Amiri Sani
//!
//! This program is free software: you can redistribute it and/or modify
//! it under the terms of the GNU General Public License as published by
//! the Free Software Foundation, either version 3 of the License, or
//! (at your option) any later version.
//!
//! This program is distributed in the hope that it will be useful,
//! but WITHOUT ANY WARRANTY; without even the implied warranty of
//! MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//! GNU General Public License for more details.
//!
//! You should have received a copy of the GNU General Public License
//! along with this program.  If not, see <https://www.gnu.org/licenses/>.

use secluso_app_native::{
    add_camera, decrypt_video, deregister, generate_heartbeat_request_config_command,
    get_group_name, initialize, livestream_decrypt, livestream_update,
    process_heartbeat_config_response, Clients,
};
use secluso_client_lib::http_client::HttpClient;
use secluso_client_server_lib::auth::parse_user_credentials_full;
use std::env;
use std::fs;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;
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

fn main() -> io::Result<()> {
    let mut test_motion = false;
    let mut test_livestream = false;
    let mut reset = false;

    let args: Vec<String> = env::args().collect();
    if args.len() > 2 {
        panic!("Too many arguments!");
    }

    if args.len() == 2 {
        if args[1] == "--test-motion".to_string() {
            test_motion = true;
        } else if args[1] == "--test-livestream".to_string() {
            test_livestream = true;
        } else if args[1] == "--reset".to_string() {
            reset = true;
        } else {
            panic!("Invalid argument!");
        }
    }

    let file = File::open("user_credentials").expect("Cannot open file to send");
    let mut reader =
        BufReader::with_capacity(file.metadata().unwrap().len().try_into().unwrap(), file);
    let credentials_full = reader.fill_buf().unwrap();
    let (server_username, server_password, server_addr) =
        parse_user_credentials_full(credentials_full.to_vec()).unwrap();

    let file2 = File::open("camera_secret").expect("Cannot open file to send");
    let mut reader2 =
        BufReader::with_capacity(file2.metadata().unwrap().len().try_into().unwrap(), file2);
    let secret_vec = reader2.fill_buf().unwrap();

    fs::create_dir_all(format!("{}/videos", DATA_DIR)).unwrap();

    let first_time_path = Path::new(DATA_DIR).join("first_time_done");
    let first_time: bool = !first_time_path.exists();

    let clients: Arc<Mutex<Option<Box<Clients>>>> = Arc::new(Mutex::new(None));
    let http_client = HttpClient::new(server_addr, server_username, server_password);

    if first_time {
        if reset {
            panic!("No state to reset!");
        }

        initialize(&mut clients.lock().unwrap(), DATA_DIR.to_string(), true)?;

        let credentials_full_string = String::from_utf8(credentials_full.to_vec()).unwrap();

        let add_camera_result = add_camera(
            &mut clients.lock().unwrap(),
            CAMERA_NAME.to_string(),
            CAMERA_ADDR.to_string(),
            secret_vec.to_vec(),
            false,
            "".to_string(),
            "".to_string(),
            "".to_string(),
            credentials_full_string,
        );

        if add_camera_result == "Error".to_string() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Error: Failed to add camera."),
            ));
        }

        File::create(&first_time_path).expect("Could not create file");
    } else {
        initialize(&mut clients.lock().unwrap(), DATA_DIR.to_string(), false)?;

        if reset {
            return deregister_all(clients, &http_client);
        }
    }

    if test_motion {
        motion_loop(Arc::clone(&clients), &http_client, true)?;
        return Ok(());
    }

    if test_livestream {
        livestream(Arc::clone(&clients), &http_client, 2)?;
        return Ok(());
    }

    let clients_clone = Arc::clone(&clients);
    let http_client_clone = http_client.clone();
    let clients_clone_2 = Arc::clone(&clients);
    let http_client_clone_2 = http_client.clone();

    // This thread is used for receiving motion videos
    println!("Launching a thread to listen for motion videos.");
    thread::spawn(move || {
        let _ = motion_loop(clients_clone, &http_client_clone, false);
        println!("Motion loop exited!");
    });

    // This thread is used for sending heartbeats to the camera
    println!("Launching a thread to periodically send heartbeats to the camera.");
    thread::spawn(move || {
        let _ = heartbeat_loop(clients_clone_2, &http_client_clone_2);
        println!("Heartbeat loop exited!");
    });

    // The main thread is used for launching on-demand livestream sessions.
    livestream_loop(Arc::clone(&clients), &http_client)?;

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

fn heartbeat_loop(
    clients: Arc<Mutex<Option<Box<Clients>>>>,
    http_client: &HttpClient,
) -> io::Result<()> {
    let mut ignored_heartbeats = 0;

    loop {
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
            // We want to fetch all pending videos before checking for the heartbeat response.
            fetch_all_motion_videos(Arc::clone(&clients), http_client);
            match http_client.fetch_config_response(&config_group_name) {
                Ok(resp) => {
                    config_response_opt = Some(resp);
                    break;
                }
                Err(_) => {}
            }
        }

        if config_response_opt.is_none() {
            println!("Error: couldn't fetch the heartbeat response. Camera might be offline.");
            thread::sleep(Duration::from_secs(20));
            continue;
        }

        let config_response = config_response_opt.unwrap();

        match process_heartbeat_config_response(
            &mut clients.lock().unwrap(),
            config_response.clone(),
            timestamp,
        ) {
            Ok(response) if response.contains("healthy") => {
                println!("Healthy heartbeat");
                ignored_heartbeats = 0;

                if let Some((_, firmware_version)) = response.split_once('_') {
                    println!("firmware_version = {firmware_version}");
                } else {
                    println!("Error: unknown firmware version");
                }
            }
            Ok(response) if response == "invalid ciphertext".to_string() => {
                println!("The connection to the camera is corrupted. Pair the app with the camera again.");
            }
            Ok(response) => {
                //invalid timestamp || invalid epoch
                // FIXME: Before processing the heartbeat response, we should make sure all motion videos are fetched and processed.
                // But we're not doing that here, therefore an "invalid epoch" might not mean a corrupted channel.
                println!("{response}");
                ignored_heartbeats += 1;
                if ignored_heartbeats >= 4 {
                    println!("The connection to the camera might have got corrupted. Consider pairing the app with the camera again.");
                }
            }
            Err(e) => {
                println!("Error processing heartbeat response {e}");
                ignored_heartbeats += 1;
                if ignored_heartbeats >= 4 {
                    println!("The connection to the camera might have got corrupted. Consider pairing the app with the camera again.");
                }
            }
        }

        thread::sleep(Duration::from_secs(20));
    }
}

fn fetch_all_motion_videos(clients: Arc<Mutex<Option<Box<Clients>>>>, http_client: &HttpClient) {
    loop {
        if let Err(_) = fetch_motion_video(Arc::clone(&clients), http_client) {
            return;
        }
    }
}

fn fetch_motion_video(
    clients: Arc<Mutex<Option<Box<Clients>>>>,
    http_client: &HttpClient,
) -> io::Result<()> {
    let mut clients_locked = clients.lock().unwrap();
    let epoch_file_path = Path::new(DATA_DIR).join("motion_epoch");

    let mut epoch: u64 = if epoch_file_path.exists() {
        let file = File::open(&epoch_file_path).expect("Cannot open motion_epoch file");
        let mut reader =
            BufReader::with_capacity(file.metadata().unwrap().len().try_into().unwrap(), file);
        let epoch_data = reader.fill_buf().unwrap();
        bincode::deserialize(epoch_data).unwrap()
    } else {
        // The first motion video will be sent in MLS epoch 2.
        2
    };

    let group_name = get_group_name(&mut clients_locked, "motion")?;

    let enc_filename = format!("{}", epoch);
    let enc_filepath = Path::new(DATA_DIR).join("videos").join(&enc_filename);
    match http_client.fetch_enc_video(&group_name, &enc_filepath) {
        Ok(_) => {
            let dec_filename = decrypt_video(&mut clients_locked, enc_filename).unwrap();
            println!("Received and decrypted file: {}", dec_filename);
            let _ = fs::remove_file(enc_filepath);
            epoch += 1;

            let epoch_data = bincode::serialize(&epoch).unwrap();
            let mut file =
                fs::File::create(&epoch_file_path).expect("Could not create motion_epoch file");
            file.write_all(&epoch_data).unwrap();
            file.flush().unwrap();
            file.sync_all().unwrap();

            return Ok(());
        }

        Err(e) => {
            return Err(e);
        }
    }
}

fn motion_loop(
    clients: Arc<Mutex<Option<Box<Clients>>>>,
    http_client: &HttpClient,
    one_video_only: bool,
) -> io::Result<()> {
    let mut iter = 0;
    loop {
        match fetch_motion_video(Arc::clone(&clients), http_client) {
            Ok(_) => {
                if one_video_only {
                    return Ok(());
                }
            }

            Err(_) => {
                thread::sleep(Duration::from_secs(1));
            }
        }

        iter += 1;
        if one_video_only && iter > 5 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Error: could not fetch motion video (timeout)!"),
            ));
        }
    }
}

fn livestream_loop(
    clients: Arc<Mutex<Option<Box<Clients>>>>,
    http_client: &HttpClient,
) -> io::Result<()> {
    loop {
        println!("Enter the letter l to start a livestream session and letter q to quit:");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .expect("Failed to read line");

        let command = input.trim();
        match command {
            "l" => {
                println!("Starting a livestream session!");
                match livestream(Arc::clone(&clients), &http_client, 10) {
                    Ok(_) => {}
                    Err(e) => {
                        println!("Livestream failed ({}).", e);
                    }
                }
            }
            "q" => {
                return Ok(());
            }
            _ => {
                println!("Invalid command!");
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
