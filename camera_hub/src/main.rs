//! Privastead camera hub.
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

#[macro_use]
extern crate log;

#[macro_use]
extern crate serde_derive;

use cfg_if::cfg_if;
use docopt::Docopt;
use privastead_client_lib::http_client::HttpClient;
use privastead_client_lib::mls_client::MlsClient;
use privastead_client_lib::mls_clients::{NUM_MLS_CLIENTS, MLS_CLIENT_TAGS, MOTION, LIVESTREAM, FCM, CONFIG, MlsClients};
use serde_yml::Value;
use std::array;
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io;
#[cfg(feature = "ip")]
use std::io::Write;
use std::ops::Add;
use std::path::Path;
use std::process::exit;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::panic;
use std::thread::sleep;
use std::time::SystemTime;
use std::{thread, time::Duration};
use regex::Regex;

mod delivery_monitor;
use crate::delivery_monitor::{DeliveryMonitor, VideoInfo};
mod motion;
use crate::motion::{prepare_motion_video, upload_pending_enc_videos};
mod livestream;
use crate::livestream::livestream;
mod traits;
use crate::traits::Camera;
mod pairing;
use crate::pairing::{
    pair_all, create_wifi_hotspot, get_input_camera_secret, get_names,
    read_parse_full_credentials,
};
mod config;
use crate::config::process_config_command;
mod fmp4;
mod mp4;

cfg_if! {
     if #[cfg(all(feature = "ip", feature = "raspberry"))] {
        mod raspberry_pi;
        use crate::raspberry_pi::rpi_camera::RaspberryPiCamera;
        mod ip;
        use crate::ip::ip_camera::IpCamera;
        use rpassword::read_password;
    } else if #[cfg(feature = "raspberry")] {
        mod raspberry_pi;
        use crate::raspberry_pi::rpi_camera::RaspberryPiCamera;
    } else if #[cfg(feature = "ip")] {
        mod ip;
        use crate::ip::ip_camera::IpCamera;
        use rpassword::read_password;
    } else {
        compile_error!("At least one of the features 'raspberry' or 'ip' must be enabled");
    }
}

const STATE_DIR_GENERAL: &str = "state";
const VIDEO_DIR_GENERAL: &str = "pending_videos";

// A counter representing the amount of active camera threads
static GLOBAL_THREAD_COUNT: AtomicUsize = AtomicUsize::new(0);

const USAGE: &str = "
Privastead camera hub: connects to an IP camera and send videos to the privastead app end-to-end encrypted (through an untrusted server).

Usage:
  privastead-camera-hub
  privastead-camera-hub --reset
  privastead-camera-hub --reset-full
  privastead-camera-hub --test-motion
  privastead-camera-hub --test-livestream
  privastead-camera-hub (--version | -v)
  privastead-camera-hub (--help | -h)

Options:
    --reset             Wipe all the state, but not pending videos
    --reset-full        Wipe all the state and pending videos
    --test-motion       Used for testing motion videos
    --test-livestream   Used for testing video livestreaming
    --version, -v       Show version
    --help, -h          Show help
";

#[derive(Debug, Clone, Deserialize)]
struct Args {
    flag_reset: bool,
    flag_reset_full: bool,
    flag_test_motion: bool,
    #[cfg(feature = "ip")]
    flag_test_livestream: bool,
}

fn main() -> io::Result<()> {
    let version = env!("CARGO_PKG_NAME").to_string() + ", version: " + env!("CARGO_PKG_VERSION");
    env_logger::init();

    let args: Args = Docopt::new(USAGE)
        .map(|d| d.help(true))
        .map(|d| d.version(Some(version)))
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    // Retrieve the cameras.yaml file. If it doesn't exist, print an error message for the user.
    let cameras_file = match File::open("cameras.yaml") {
        Ok(file) => file,

        Err(_error) => {
            println!("Error retrieving cameras.yaml file, see the example_cameras.yaml for an example configuration.");
            exit(1);
        }
    };

    // Load the yml file in for analysis
    let loaded_cameras: HashMap<String, Value> = serde_yml::from_reader(cameras_file)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    // Extract cameras
    let cameras_section = loaded_cameras
        .get("cameras")
        .expect("Cameras section is missing from cameras.yaml");

    // Create the general outer directories (where we'll have inner directories representing each camera)
    fs::create_dir_all(STATE_DIR_GENERAL).unwrap();
    fs::create_dir_all(VIDEO_DIR_GENERAL).unwrap();

    let mut camera_list: Vec<Box<dyn Camera + Send>> = Vec::new();

    cfg_if! {
        if #[cfg(feature = "raspberry")] {
            let mut input_camera_secret: Option<Vec<u8>> = None;
            let mut connect_to_wifi = false;
        } else {
            let mut input_camera_secret: Option<Vec<u8>> = None;
            let connect_to_wifi = false;
        }
    }

    #[cfg(feature = "raspberry")]
    let mut num_raspberry_pi = 0;

    // Iterate through every camera in the cameras.yaml file, accumulating structs representing their data
    if let Value::Sequence(cameras) = cameras_section {
        for camera in cameras {
            if let Value::Mapping(map) = camera {
                let camera_type = map
                    .get(&Value::String("type".to_string()))
                    .expect("Missing camera type (IP or RaspberryPi)")
                    .as_str()
                    .unwrap();
                let camera_name = map
                    .get(&Value::String("name".to_string()))
                    .expect("Missing camera name")
                    .as_str()
                    .unwrap();
                let camera_motion_fps = map
                    .get(&Value::String("motion_fps".to_string()))
                    .expect("Missing Motion FPS")
                    .as_u64()
                    .unwrap();

                if camera_type == "IP" {
                    cfg_if! {
                        if #[cfg(feature = "ip")] {
                            let camera_ip = map
                                .get(&Value::String("ip".to_string()))
                                .expect("Missing IP for camera")
                                .as_str()
                                .unwrap();
                            let camera_rtsp_port = map
                                .get(&Value::String("rtsp_port".to_string()))
                                .expect("Missing RTSP port")
                                .as_u64()
                                .unwrap() as u16;
                            let mut camera_username = map
                                .get(&Value::String("username".to_string()))
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let mut camera_password = map
                                .get(&Value::String("password".to_string()))
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();

                            if camera_username.is_empty() {
                                camera_username = ask_user(format!(
                                    "Enter the username for the IP camera {:?}: ",
                                    camera_name
                                ))
                                    .unwrap();
                            }

                            if camera_password.is_empty() {
                                camera_password = ask_user_password(format!(
                                    "Enter the password for the IP camera {:?}: ",
                                    camera_name
                                ))
                                    .unwrap();
                            }

                            let ip_camera_result = IpCamera::new(
                                camera_name.parse().unwrap(),
                                camera_ip.parse().unwrap(),
                                camera_rtsp_port,
                                camera_username.parse().unwrap(),
                                camera_password.parse().unwrap(),
                                format!(
                                    "{}/{}",
                                    STATE_DIR_GENERAL,
                                    camera_name.replace(" ", "_").to_lowercase()
                                ),
                                format!(
                                    "{}/{}",
                                    VIDEO_DIR_GENERAL,
                                    camera_name.replace(" ", "_").to_lowercase()
                                ),
                                camera_motion_fps,
                            );
                            match ip_camera_result {
                                Ok(camera) => {
                                    camera_list.push(Box::new(camera));
                                }
                                Err(err) => {
                                    panic!("Failed to initialize the IP camera object. Consider resetting the camera. (Error: {err})");
                                }
                            }

                            if args.flag_test_motion || args.flag_test_livestream {
                                input_camera_secret = Some(get_input_camera_secret());
                            }

                        } else {
                             panic!("IP cameras are only supported with the \"ip\" feature.");
                        }
                    }
                } else if camera_type == "RaspberryPi" {
                    cfg_if! {
                       if #[cfg(feature = "raspberry")] {
                            if num_raspberry_pi > 0 {
                                panic!("cameras.yaml can only specify one Raspberry Pi camera!");
                            }
                            num_raspberry_pi += 1;

                            let camera = RaspberryPiCamera::new(
                                camera_name.parse().unwrap(),
                                STATE_DIR_GENERAL.to_string(),
                                VIDEO_DIR_GENERAL.to_string(),
                                camera_motion_fps,
                            );
                            camera_list.push(Box::new(camera));

                            input_camera_secret = Some(get_input_camera_secret());
                            connect_to_wifi = true;
                        } else {
                            panic!(
                                "Raspberry Pi cameras are only supported with the \"raspberry\" feature."
                            )
                        }
                    }
                } else {
                    panic!(
                        "Unknown camera type ({:?}). Supported types are IP and RaspberryPi",
                        camera_type
                    )
                };
            }
        }
    }

    // Set a global panic hook and abort when there's a panic in any of the threads.
    // We typically run the camera_hub using a systemd service, which re-launches it
    // upon abort. We want every panic to abort so that the program can be re-launched.
    panic::set_hook(Box::new(|panic_info| {
        println!("Panic occurred: {:?}", panic_info);
        std::process::abort();
    }));

    // Iterate through each camera struct and spawn in a thread to manage each individual one
    for mut camera in camera_list.into_iter() {
        println!("Starting to instantiate camera: {:?}", camera.get_name());

        let args = args.clone();
        let input_camera_secret = input_camera_secret.clone();

        GLOBAL_THREAD_COUNT.fetch_add(1, Ordering::SeqCst);
        thread::spawn(move || {
            loop {
                if args.flag_reset || args.flag_reset_full {
                    match reset(camera.as_ref(), args.flag_reset_full) {
                        Ok(_) => {}
                        Err(e) => {
                            panic!("reset() returned with: {e}");
                        }
                    };

                    // Deduct one from our thread count for main thread to know when to exit (when all are finished)
                    GLOBAL_THREAD_COUNT.fetch_sub(1, Ordering::SeqCst);
                    return;
                } else {
                    match core(
                        camera.as_mut(),
                        input_camera_secret.clone(),
                        connect_to_wifi,
                        args.flag_test_motion,
                    ) {
                        Ok(_) => {}
                        Err(e) => {
                            error!("core() returned with: {e}");
                        }
                    }
                }
                println!("There was a problem with the connection to the server. Will try to connect again soon.");
                let _ = fs::remove_file(camera.get_state_dir() + "/registration_done");
                sleep(Duration::from_secs(10));
            }
        });
    }

    // Terminate when no cameras are left running
    while GLOBAL_THREAD_COUNT.load(Ordering::SeqCst) != 0 {
        sleep(Duration::from_millis(1));
    }

    Ok(())
}

#[cfg(feature = "ip")]
fn ask_user(prompt: String) -> io::Result<String> {
    print!("{prompt}");
    // Make sure the prompt is displayed before reading input
    io::stdout().flush()?;

    let mut user_input = String::new();
    io::stdin().read_line(&mut user_input)?;
    // Trim the input to remove any extra whitespace or newline characters
    Ok(user_input.trim().to_string())
}

#[cfg(feature = "ip")]
fn ask_user_password(prompt: String) -> io::Result<String> {
    print!("{prompt}");
    // Make sure the prompt is displayed before reading input
    io::stdout().flush()?;

    let password = read_password()?;
    // Trim the input to remove any extra whitespace or newline characters
    Ok(password.trim().to_string())
}

fn reset(
    camera: &dyn Camera,
    reset_full: bool,
) -> io::Result<()> {
    // FIXME: has some code copy/pasted from core()
    let state_dir = camera.get_state_dir();
    let state_dir_path = Path::new(&state_dir);
    let first_time_done_path = state_dir_path.join("first_time_done");
    println!("{:?}", first_time_done_path);
    let first_time: bool = !first_time_done_path.exists();

    if first_time {
        println!("There's no state to reset!");
        return Ok(());
    }

    for i in 0..NUM_MLS_CLIENTS {
        let (camera_name, group_name) = get_names(
            camera,
            first_time,
            format!("camera_{}_name", MLS_CLIENT_TAGS[i]),
            format!("group_{}_name", MLS_CLIENT_TAGS[i]),
        );

        // First, clean up MLS users
        match MlsClient::new(
            camera_name,
            first_time,
            state_dir.clone(),
            MLS_CLIENT_TAGS[i].to_string(),
        ) {
            Ok(mut client) => match client.clean() {
                Ok(_) => {
                    info!("{} client cleaned successfully.", MLS_CLIENT_TAGS[i])
                }
                Err(e) => {
                    error!("Error: Cleaning client_{} failed: {e}", MLS_CLIENT_TAGS[i]);
                }
            },
            Err(e) => {
                error!("Error: Creating client_{} failed: {e}", MLS_CLIENT_TAGS[i]);
            }
        };

        //Second, delete data in the server
        let (server_username, server_password, server_addr) = read_parse_full_credentials();
        let http_client = HttpClient::new(server_addr, server_username, server_password);

        match http_client.deregister(&group_name) {
            Ok(_) => {
                info!("{} data on server deleted successfully.", MLS_CLIENT_TAGS[i])
            }
            Err(e) => {
                error!(
                    "Error: Deleting {} data from server failed: {e}.\
                    Sometimes, this error is okay since the app might have deleted the data already\
                    or no data existed in the first place.",
                    MLS_CLIENT_TAGS[i]
                );
            }
        }
    }

    //Third, delete all the local state files.
    let _ = fs::remove_dir_all(state_dir_path);
    let _ = fs::remove_file("credentials_full");

    //Fourth, (in the case of full reset) delete all the pending videos (those that were never successfully delivered)
    if reset_full {
        let video_dir = camera.get_video_dir();
        let video_dir_path = Path::new(&video_dir);
        let _ = fs::remove_dir_all(video_dir_path);
    }

    println!("Reset finished.");
    Ok(())
}

fn send_pending_motion_videos(
    camera: &mut dyn Camera,
    clients: &mut MlsClients,
    delivery_monitor: &mut DeliveryMonitor,
    http_client: &HttpClient,
) -> io::Result<()> {
    let mut pending_timestamps = Vec::new();
    let video_dir = camera.get_video_dir();

    let re = Regex::new(r"^video_(\d+)\.mp4$").unwrap();

    for entry in fs::read_dir(video_dir)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();

        if let Some(caps) = re.captures(&file_name) {
            if let Some(matched) = caps.get(1) {
                if let Ok(ts) = matched.as_str().parse::<u64>() {
                    pending_timestamps.push(ts);
                }
            }
        }
    }

    for timestamp in &pending_timestamps {
        println!("Recovered pending video {:?}", *timestamp);
        let video_info = VideoInfo::from(*timestamp);
        prepare_motion_video(&mut clients[MOTION], video_info, delivery_monitor)?;

        upload_pending_enc_videos(
            &clients[MOTION].get_group_name().unwrap(),
            delivery_monitor,
            http_client,
        );
    }

    if pending_timestamps.len() > 0 {
        //Timestamp of 0 tells the app it's time to start downloading.
        let dummy_timestamp: u64 = 0;
        let notification_msg = clients[FCM].encrypt(
            &bincode::serialize(&dummy_timestamp).unwrap())?;
        clients[FCM].save_group_state();
        http_client.send_fcm_notification(notification_msg)?;
    }

    Ok(())
}

fn core(
    camera: &mut dyn Camera,
    input_camera_secret: Option<Vec<u8>>,
    connect_to_wifi: bool,
    test_mode: bool,
) -> io::Result<()> {
    let state_dir = camera.get_state_dir();
    let first_time: bool = !Path::new(&(state_dir.clone() + "/first_time_done")).exists();

    if first_time && connect_to_wifi {
        println!("Creating WiFi hotspot.");
        create_wifi_hotspot();
    }

    let mut clients: MlsClients = array::from_fn(|i| {
        let (camera_name, group_name) = get_names(
            camera,
            first_time,
            format!("camera_{}_name", MLS_CLIENT_TAGS[i]),
            format!("group_{}_name", MLS_CLIENT_TAGS[i]),
        );
        debug!("{} camera_name = {}", MLS_CLIENT_TAGS[i], camera_name);
        debug!("{} group_name = {}", MLS_CLIENT_TAGS[i], group_name);

        let mut mls_client = MlsClient::new(
            camera_name,
            first_time,
            state_dir.clone(),
            MLS_CLIENT_TAGS[i].to_string(),
        )
        .expect("MlsClient::new() for returned error.");

        if first_time {
            mls_client.create_group(&group_name).unwrap();
            debug!("Created group.");
        }

        mls_client.save_group_state();

        mls_client
    });

    let camera_name = camera.get_name();

    if first_time {
        println!(
            "[{}] Waiting to be paired with the mobile app.",
            camera_name
        );
        pair_all(
            camera,
            &mut clients,
            input_camera_secret,
            connect_to_wifi,
        )?;

        File::create(camera.get_state_dir() + "/first_time_done").expect("Could not create file");

        println!("[{}] Pairing successful.", camera_name);
    }

    println!("[{}] Running...", camera_name);

    let (server_username, server_password, server_addr) = read_parse_full_credentials();
    let http_client = HttpClient::new(server_addr, server_username, server_password);

    let mut locked_motion_check_time: Option<SystemTime> = None;
    let mut locked_delivery_check_time: Option<SystemTime> = None;
    let mut locked_livestream_check_time: Option<SystemTime> = None;
    let mut locked_config_check_time: Option<SystemTime> = None;
    let video_dir = camera.get_video_dir();
    let mut delivery_monitor = DeliveryMonitor::from_file_or_new(video_dir, state_dir);
    let livestream_request = Arc::new(Mutex::new(false));
    let livestream_request_clone = Arc::clone(&livestream_request);
    let group_livestream_name_clone = clients[LIVESTREAM].get_group_name().unwrap();
    let http_client_clone = http_client.clone();
    let group_config_name_clone = clients[CONFIG].get_group_name().unwrap();
    let http_client_clone_2 = http_client.clone();
    let config_enc_commands: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(vec![]));
    let config_enc_commands_clone = Arc::clone(&config_enc_commands);

    thread::spawn(move || loop {
        if http_client_clone
            .livestream_check(&group_livestream_name_clone)
            .is_ok()
        {
            let mut check = livestream_request_clone.lock().unwrap();
            *check = true;
        } else {
            sleep(Duration::from_secs(1));
        }
    });

    thread::spawn(move || loop {
        if let Ok(enc_command) = http_client_clone_2
            .config_check(&group_config_name_clone) {
            let mut config_enc_commands = config_enc_commands_clone.lock().unwrap();
            config_enc_commands.push(enc_command);
        } else {
            error!("Error in receiving config command");
            sleep(Duration::from_secs(1));
        }
    });

    if first_time {
        // Send pending videos before entering the loop
        // This is needed after re-pairing.
        // For now, re-pairing is done manually and needs physical proximity.
        // Hence, it is safe to send pending videos to the app that is paired with the camera.
        let _ = send_pending_motion_videos(camera, &mut clients, &mut delivery_monitor, &http_client);
    }

    // Used for anti-dither for motion detection
    loop {
        // Check motion events from the camera every second
        let motion_event = match camera.is_there_motion() {
            Ok(event) => event,
            Err(e) => {
                println!("Motion detection error {}", e);
                continue;
            }
        };

        // Send motion events only if we haven't sent one in the past minute
        if (motion_event || test_mode)
            && (locked_motion_check_time.is_none()
                || locked_motion_check_time.unwrap().le(&SystemTime::now()))
        {
            let video_info = VideoInfo::new();
            info!("Detected motion.");
            if !test_mode {
                info!("Sending the FCM notification with timestamp.");
                let notification_msg = clients[FCM].encrypt(
                    &bincode::serialize(&video_info.timestamp).unwrap())?;
                clients[FCM].save_group_state();
                match http_client.send_fcm_notification(notification_msg) {
                    Ok(_) => {}
                    Err(e) => {
                        error!("Failed to send FCM notification ({})", e);
                    }
                }
            }

            info!("Starting to record, prepare, and encrypt video.");
            let duration = if test_mode { 1 } else { 20 };

            camera.record_motion_video(&video_info, duration)?;

            prepare_motion_video(&mut clients[MOTION], video_info, &mut delivery_monitor)?;

            info!("Uploading the encrypted video.");
            upload_pending_enc_videos(
                &clients[MOTION].get_group_name().unwrap(),
                &mut delivery_monitor,
                &http_client,
            );

            if !test_mode {
                info!("Sending the FCM notification to start downloading.");
                //Timestamp of 0 tells the app it's time to start downloading.
                let dummy_timestamp: u64 = 0;
                let notification_msg = clients[FCM].encrypt(
                    &bincode::serialize(&dummy_timestamp).unwrap())?;
                clients[FCM].save_group_state();
                match http_client.send_fcm_notification(notification_msg) {
                    Ok(_) => {}
                    Err(e) => {
                        error!("Failed to send FCM notification ({})", e);
                    }
                }
            }

            locked_motion_check_time = Some(SystemTime::now().add(Duration::from_secs(60)));
        }

        // Check for livestream requests every second
        if locked_livestream_check_time.is_none()
            || locked_livestream_check_time.unwrap().le(&SystemTime::now())
        {
            // Livestream request? Start it.
            let mut check = livestream_request.lock().unwrap();
            if *check == true {
                info!("Livestream start detected");
                *check = false;
                livestream(
                    &mut clients[LIVESTREAM],
                    camera,
                    &mut delivery_monitor,
                    &http_client,
                )?;
            }

            locked_livestream_check_time = Some(SystemTime::now().add(Duration::from_secs(1)));
        }

        // Check with the delivery monitor every minute
        if locked_delivery_check_time.is_none()
            || locked_delivery_check_time.unwrap().le(&SystemTime::now())
        {
            upload_pending_enc_videos(
                &clients[MOTION].get_group_name().unwrap(),
                &mut delivery_monitor,
                &http_client,
            );
            locked_delivery_check_time = Some(SystemTime::now().add(Duration::from_secs(60)));
        }

        // Check for config commands every second
        if locked_config_check_time.is_none()
                    || locked_config_check_time.unwrap().le(&SystemTime::now())
        {
            let mut enc_commands = config_enc_commands.lock().unwrap();
            for enc_command in &*enc_commands {
                let _ = process_config_command(&mut clients, enc_command, &http_client, &mut delivery_monitor);
            }
            enc_commands.clear();
            locked_config_check_time = Some(SystemTime::now().add(Duration::from_secs(1)));
        }

        // Introduce a small delay since we don't need this constantly checked
        sleep(Duration::from_millis(10));
    }
}
