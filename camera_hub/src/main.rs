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
use image::Luma;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::random::OpenMlsRand;
use openmls_traits::OpenMlsProvider;
use privastead_client_lib::http_client::HttpClient;
use privastead_client_lib::pairing;
use privastead_client_lib::user::{KeyPackages, User};
use privastead_client_lib::video_net_info::VideoNetInfo;
use privastead_client_server_lib::auth::parse_user_credentials;
use qrcode::QrCode;
use rand::Rng;
use serde_yml::Value;
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::ops::Add;
use std::path::Path;
use std::process::{exit, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock, Arc};
use std::thread::sleep;
use std::time::SystemTime;
use std::{thread, time::Duration};

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

mod delivery_monitor;

use crate::delivery_monitor::{DeliveryMonitor, VideoInfo};

mod livestream;

use crate::livestream::livestream;

mod fmp4;
mod mp4;
mod traits;

use crate::traits::Camera;

// Used to generate random names.
// With 16 alphanumeric characters, the probability of collision is very low.
// Note: even if collision happens, it has no impact on
// our security guarantees. Will only cause availability issues.
const NUM_RANDOM_CHARS: u8 = 16;

const STATE_DIR_GENERAL: &str = "state";
const VIDEO_DIR_GENERAL: &str = "pending_videos";

// A counter representing the amount of active camera threads
static GLOBAL_THREAD_COUNT: AtomicUsize = AtomicUsize::new(0);

// Used to ensure there can't be attempted concurrent pairing
static LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn write_varying_len(stream: &mut TcpStream, msg: &[u8]) {
    // FIXME: is u64 necessary?
    let len = msg.len() as u64;
    let len_data = len.to_be_bytes();

    stream.write_all(&len_data).unwrap();
    stream.write_all(msg).unwrap();
    stream.flush().unwrap();
}

fn read_varying_len(stream: &mut TcpStream) -> Vec<u8> {
    let mut len_data = [0u8; 8];
    stream.read_exact(&mut len_data).unwrap();
    let len = u64::from_be_bytes(len_data);

    let mut msg = vec![0u8; len as usize];
    stream.read_exact(&mut msg).unwrap();

    msg
}

fn perform_pairing_handshake(
    stream: &mut TcpStream,
    camera_key_packages: KeyPackages,
    camera_secret: [u8; pairing::NUM_SECRET_BYTES],
) -> KeyPackages {
    let pairing = pairing::Camera::new(camera_secret, camera_key_packages);

    let app_msg = read_varying_len(stream);
    let (app_key_packages, camera_msg) = pairing.process_app_msg_and_generate_msg_to_app(app_msg);
    write_varying_len(stream, &camera_msg);

    app_key_packages
}

fn generate_camera_secret(camera: &dyn Camera) -> Vec<u8> {
    let crypto = OpenMlsRustCrypto::default();
    let secret = crypto
        .crypto()
        .random_vec(pairing::NUM_SECRET_BYTES)
        .unwrap();

    // Save as QR code to be shown to the app
    let code = QrCode::new(secret.clone()).unwrap();
    let image = code.render::<Luma<u8>>().build();
    image
        .save(format!(
            "camera_{}_secret_qrcode.png",
            camera.get_name().replace(" ", "_").to_lowercase()
        ))
        .unwrap();

    secret
}

fn get_input_camera_secret() -> Vec<u8> {
    let pathname = "./camera_secret";
    let file = File::open(pathname).expect(
        "Could not open file \"camera_secret\". You can generate this with the config_tool",
    );
    let mut reader =
        BufReader::with_capacity(file.metadata().unwrap().len().try_into().unwrap(), file);
    let data = reader.fill_buf().unwrap();

    data.to_vec()
}

fn pair_with_app(
    stream: &mut TcpStream,
    camera_key_packages: KeyPackages,
    input_camera_secret: Vec<u8>,
) -> KeyPackages {
    if input_camera_secret.len() != pairing::NUM_SECRET_BYTES {
        panic!("Invalid number of bytes in secret!");
    }

    let mut camera_secret = [0u8; pairing::NUM_SECRET_BYTES];
    camera_secret.copy_from_slice(&input_camera_secret[..]);

    let app_key_packages = perform_pairing_handshake(stream, camera_key_packages, camera_secret);

    app_key_packages
}

fn create_group_and_invite(
    stream: &mut TcpStream,
    client: &mut User,
    group_name: String,
    app_key_packages: KeyPackages,
) -> io::Result<()> {
    let app_contact = client.add_contact("app".to_string(), app_key_packages)?;
    debug!("Added contact.");

    client.create_group(group_name.clone());
    client.save_groups_state();
    debug!("Created group.");

    let welcome_msg_vec = client.invite(&app_contact, group_name).map_err(|e| {
        error!("invite() returned error:");
        e
    })?;
    client.save_groups_state();
    debug!("App invited to the group.");

    write_varying_len(stream, &welcome_msg_vec);

    Ok(())
}

fn decrypt_msg(client: &mut User, msg: Vec<u8>) -> io::Result<Vec<u8>> {
    let decrypted_msg = client.decrypt(msg, true)?;
    client.save_groups_state();

    Ok(decrypted_msg)
}

fn get_wifi_info_and_connect(stream: &mut TcpStream, client: &mut User) -> io::Result<()> {
    let ssid_msg = read_varying_len(stream);
    let ssid_bytes = decrypt_msg(client, ssid_msg)?;
    let ssid = String::from_utf8(ssid_bytes).expect("Invalid UTF-8 for WiFi SSID");
    let password_msg = read_varying_len(stream);
    let password_bytes = decrypt_msg(client, password_msg)?;
    let password = String::from_utf8(password_bytes).expect("Invalid UTF-8 for WiFi password");

    // Disable the Hotspot first
    let _ = Command::new("sh")
        .arg("-c")
        .arg("nmcli connection down id Hotspot")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    // Wait a bit for Hotspot to get disabled
    thread::sleep(Duration::from_secs(5));

    // Connect to SSID
    let _ = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "nmcli device wifi connect \"{}\" password \"{}\"",
            ssid.clone(),
            password
        ))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    // Set up autoconnect to SSID on reboot
    let _ = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "nmcli connection modify \"{}\" connection.autoconnect yes",
            ssid
        ))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    Ok(())
}

fn create_wifi_hotspot() {
    let _ = Command::new("sh")
        .arg("-c")
        .arg("nmcli device wifi hotspot ssid Privastead password \"12345678\"")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
}

#[allow(clippy::too_many_arguments)]
fn create_camera_groups(
    camera: &dyn Camera,
    client_motion: &mut User,
    client_livestream: &mut User,
    client_fcm: &mut User,
    client_config: &mut User,
    group_motion_name: String,
    group_livestream_name: String,
    group_fcm_name: String,
    group_config_name: String,
    input_camera_secret: Option<Vec<u8>>,
    connect_to_wifi: bool,
) -> io::Result<()> {
    // Ensure that two cameras don't attempt to pair at the same time (as this would introduce an error when opening two of the same port simultaneously)
    let _lock = LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();

    let secret = if let Some(s) = input_camera_secret.clone() {
        s
    } else {
        generate_camera_secret(camera)
    };

    if input_camera_secret.is_none() {
        println!("[{}] File camera_{}_secret_qrcode.png was just created. Use the QR code in the app to pair.", camera.get_name(), camera.get_name().replace(" ", "_").to_lowercase());
    } else {
        println!("Use the camera QR code in the app to pair.");
    }

    // Wait for the app to connect.
    let listener = TcpListener::bind("0.0.0.0:12348").unwrap();
    let (mut stream, _) = listener.accept().unwrap();

    let app_motion_key_packages =
        pair_with_app(&mut stream, client_motion.key_packages(), secret.clone());
    create_group_and_invite(
        &mut stream,
        client_motion,
        group_motion_name,
        app_motion_key_packages,
    )?;

    let app_livestream_key_packages = pair_with_app(
        &mut stream,
        client_livestream.key_packages(),
        secret.clone(),
    );

    create_group_and_invite(
        &mut stream,
        client_livestream,
        group_livestream_name,
        app_livestream_key_packages,
    )?;

    let app_fcm_key_packages =
        pair_with_app(&mut stream, client_fcm.key_packages(), secret.clone());
    create_group_and_invite(
        &mut stream,
        client_fcm,
        group_fcm_name,
        app_fcm_key_packages,
    )?;

    let app_config_key_packages = pair_with_app(&mut stream, client_config.key_packages(), secret);
    create_group_and_invite(
        &mut stream,
        client_config,
        group_config_name,
        app_config_key_packages,
    )?;

    if input_camera_secret.is_none() {
        let _ = fs::remove_file(format!(
            "camera_{}_secret_qrcode.png",
            camera.get_name().replace(" ", "_").to_lowercase()
        ));
    }

    // FIXME: a fatal crash point here. The app thinks that pairing is finalized, but
    // not the camera.

    // Send WiFi info to the app.
    if connect_to_wifi {
        get_wifi_info_and_connect(&mut stream, client_config)?;
    }

    Ok(())
}

fn get_names(
    camera: &dyn Camera,
    first_time: bool,
    camera_filename: String,
    group_filename: String,
) -> (String, String) {
    let state_dir = camera.get_state_dir();
    let state_dir_path = Path::new(&state_dir);
    let camera_path = state_dir_path.join(camera_filename);
    let group_path = state_dir_path.join(group_filename);

    let (camera_name, group_name) = if first_time {
        let mut rng = rand::thread_rng();
        let cname: String = (0..NUM_RANDOM_CHARS)
            .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
            .collect();

        let mut file = File::create(camera_path).expect("Could not create file");
        file.write_all(cname.as_bytes()).unwrap();
        file.flush().unwrap();
        file.sync_all().unwrap();

        //FIXME: how many random characters should we use here?
        let gname: String = (0..NUM_RANDOM_CHARS)
            .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
            .collect();

        file = File::create(group_path).expect("Could not create file");
        file.write_all(gname.as_bytes()).unwrap();
        file.flush().unwrap();
        file.sync_all().unwrap();

        (cname, gname)
    } else {
        let file = File::open(camera_path).expect("Cannot open file to send");
        let mut reader =
            BufReader::with_capacity(file.metadata().unwrap().len().try_into().unwrap(), file);
        let cname = reader.fill_buf().unwrap();

        let file = File::open(group_path).expect("Cannot open file to send");
        let mut reader =
            BufReader::with_capacity(file.metadata().unwrap().len().try_into().unwrap(), file);
        let gname = reader.fill_buf().unwrap();

        (
            String::from_utf8(cname.to_vec()).unwrap(),
            String::from_utf8(gname.to_vec()).unwrap(),
        )
    };

    (camera_name, group_name)
}

fn append_to_file(mut file: &File, msg: Vec<u8>) {
    let msg_len: u32 = msg.len().try_into().unwrap();
    let msg_len_data = msg_len.to_be_bytes();
    let _ = file.write_all(&msg_len_data);
    let _ = file.write_all(&msg);
}

fn upload_pending_enc_videos(
    group_name: &str,
    delivery_monitor: &mut DeliveryMonitor,
    http_client: &HttpClient,
) {
    // Send pending videos
    let send_list = delivery_monitor.videos_to_send();
    // The send list is sorted. We must send the videos in order.
    for video_info in &send_list {
        let enc_video_file_path = delivery_monitor.get_enc_video_file_path(video_info);
        match http_client.upload_enc_video(group_name, &enc_video_file_path) {
            Ok(_) => {
                info!(
                    "Video {} successfully uploaded to the server.",
                    video_info.timestamp
                );
                delivery_monitor.dequeue_video(video_info);
            }
            Err(e) => {
                info!(
                    "Could not upload video {} ({}). Will try again later.",
                    video_info.timestamp, e
                );
                break;
            }
        }
    }
}

fn prepare_motion_video(
    client: &mut User,
    group_name: String,
    mut video_info: VideoInfo,
    delivery_monitor: &mut DeliveryMonitor,
) -> io::Result<()> {
    let video_file_path = delivery_monitor.get_video_file_path(&video_info);

    debug!("Starting to send video.");

    // Update MLS epoch
    let (commit_msg, epoch) = client.update(group_name.clone())?;

    video_info.epoch = epoch;
    let enc_video_file_path = delivery_monitor.get_enc_video_file_path(&video_info);
    let mut enc_file =
        File::create(&enc_video_file_path).expect("Could not create encrypted video file");

    append_to_file(&enc_file, commit_msg);

    let file = File::open(video_file_path).expect("Could not open video file to send");
    let file_len = file.metadata().unwrap().len();

    const READ_SIZE: usize = 63 * 1024;
    let mut reader = BufReader::with_capacity(READ_SIZE, file);

    let net_info = VideoNetInfo::new(video_info.timestamp, file_len, READ_SIZE as u64);

    let msg = client
        .encrypt(&bincode::serialize(&net_info).unwrap(), group_name.clone())
        .map_err(|e| {
            error!("encrypt() returned error:");
            e
        })?;
    append_to_file(&enc_file, msg);

    for i in 0..net_info.num_msg {
        let buffer = reader.fill_buf().unwrap();
        let length = buffer.len();
        // Sanity checks
        if i < (net_info.num_msg - 1) {
            assert_eq!(length, READ_SIZE);
        } else {
            assert_eq!(
                length,
                <u64 as TryInto<usize>>::try_into(file_len).unwrap() % READ_SIZE
            );
        }

        let msg = client.encrypt(buffer, group_name.clone()).map_err(|e| {
            error!("send_video() returned error:");
            client.save_groups_state();
            e
        })?;
        append_to_file(&enc_file, msg);
        reader.consume(length);
    }

    // Here, we first make sure the enc_file is flushed.
    // Then, we save groups state, which persists the update.
    // Then, we enqueue to be uploaded to the server.
    enc_file.flush().unwrap();
    enc_file.sync_all().unwrap();
    client.save_groups_state();

    //FIXME: fatal crash point here. We have committed the update, but we will never send it.

    info!(
        "Video {} is enqueued for sending to server.",
        video_info.timestamp
    );
    delivery_monitor.enqueue_video(video_info);

    Ok(())
}

fn read_user_credentials(pathname: &str) -> Vec<u8> {
    let file = fs::File::open(pathname).expect("Could not open user_credentials file");
    let mut reader =
        BufReader::with_capacity(file.metadata().unwrap().len().try_into().unwrap(), file);
    let data = reader.fill_buf().unwrap();

    data.to_vec()
}

const USAGE: &str = "
Privastead camera hub: connects to an IP camera and send videos to the privastead app end-to-end encrypted (through an untrusted server).

Usage:
  privastead-camera-hub
  privastead-camera-hub --reset
  privastead-camera-hub --test-motion
  privastead-camera-hub --test-livestream
  privastead-camera-hub (--version | -v)
  privastead-camera-hub (--help | -h)

Options:
    --reset             Wipe all the state
    --test-motion       Used for testing motion videos
    --test-livestream   Used for testing video livestreaming
    --version, -v       Show version
    --help, -h          Show help
";

#[derive(Debug, Clone, Deserialize)]
struct Args {
    flag_reset: bool,
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

    let credentials = read_user_credentials("user_credentials");
    let (server_username, server_password) = parse_user_credentials(credentials).unwrap();

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

    // Extract the server IP and cameras
    let server_section = loaded_cameras
        .get("server")
        .expect("Server section is missing from cameras.yaml");
    let cameras_section = loaded_cameras
        .get("cameras")
        .expect("Cameras section is missing from cameras.yaml");
    let server_ip = server_section
        .get("ip")
        .expect("Missing IP for server")
        .as_str()
        .unwrap();

    // Create the general outer directories (where we'll have inner directories representing each camera)
    fs::create_dir_all(STATE_DIR_GENERAL).unwrap();
    fs::create_dir_all(VIDEO_DIR_GENERAL).unwrap();

    let mut camera_list: Vec<Box<dyn Camera + Send>> = Vec::new();
    let server_addr: String = server_ip.to_owned() + ":8080";

    let http_client = HttpClient::new(server_addr, server_username, server_password);

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

    // Iterate through each camera struct and spawn in a thread to manage each individual one
    for mut camera in camera_list.into_iter() {
        println!("Starting to instantiate camera: {:?}", camera.get_name());

        let http_client_clone = http_client.clone();
        let args = args.clone();
        let input_camera_secret = input_camera_secret.clone();

        GLOBAL_THREAD_COUNT.fetch_add(1, Ordering::SeqCst);
        thread::spawn(move || {
            loop {
                if args.flag_reset {
                    match reset(camera.as_ref(), &http_client_clone) {
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
                        &http_client_clone,
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

fn reset(camera: &dyn Camera, http_client: &HttpClient) -> io::Result<()> {
    // First, deregister from the server
    // FIXME: has some code copy/pasted from core()
    let state_dir = camera.get_state_dir();
    let state_dir_clone = state_dir.clone();
    let state_dir_path = Path::new(&state_dir_clone);
    let first_time_done_path = state_dir_path.join("first_time_done");
    println!("{:?}", first_time_done_path);
    let first_time: bool = !first_time_done_path.exists();

    if first_time {
        println!("There's no state to reset!");
        return Ok(());
    }

    let (camera_motion_name, group_motion_name) = get_names(
        camera,
        first_time,
        "camera_motion_name".to_string(),
        "group_motion_name".to_string(),
    );

    let (camera_livestream_name, group_livestream_name) = get_names(
        camera,
        first_time,
        "camera_livestream_name".to_string(),
        "group_livestream_name".to_string(),
    );

    let (camera_fcm_name, group_fcm_name) = get_names(
        camera,
        first_time,
        "camera_fcm_name".to_string(),
        "group_fcm_name".to_string(),
    );

    let (camera_config_name, group_config_name) = get_names(
        camera,
        first_time,
        "camera_config_name".to_string(),
        "group_config_name".to_string(),
    );

    match User::new(
        camera_motion_name,
        first_time,
        state_dir.clone(),
        "motion".to_string(),
    ) {
        Ok(mut client) => match client.deregister() {
            Ok(_) => {
                info!("Motion client deregistered successfully.")
            }
            Err(e) => {
                error!("Error: Deregistering client_motion failed: {e}");
            }
        },
        Err(e) => {
            error!("Error: Creating client_motion failed: {e}");
        }
    };

    match User::new(
        camera_livestream_name,
        first_time,
        state_dir.clone(),
        "livestream".to_string(),
    ) {
        Ok(mut client) => match client.deregister() {
            Ok(_) => {
                info!("Livestream client deregistered successfully.")
            }
            Err(e) => {
                error!("Error: Deregistering client_livestream failed: {e}");
            }
        },
        Err(e) => {
            error!("Error: Creating client_livestream failed: {e}");
        }
    };

    match User::new(
        camera_fcm_name,
        first_time,
        state_dir.clone(),
        "fcm".to_string(),
    ) {
        Ok(mut client) => match client.deregister() {
            Ok(_) => {
                info!("FCM client deregistered successfully.")
            }
            Err(e) => {
                error!("Error: Deregistering client_fcm failed: {e}");
            }
        },
        Err(e) => {
            error!("Error: Creating client_fcm failed: {e}");
        }
    };

    match User::new(
        camera_config_name,
        first_time,
        state_dir,
        "config".to_string(),
    ) {
        Ok(mut client) => match client.deregister() {
            Ok(_) => {
                info!("Config client deregistered successfully.")
            }
            Err(e) => {
                error!("Error: Deregistering client_config failed: {e}");
            }
        },
        Err(e) => {
            error!("Error: Creating client_config failed: {e}");
        }
    };

    //Second, delete all the local state files.
    let _ = fs::remove_dir_all(state_dir_path);

    //Third, delete all the pending videos (those that were never successfully delivered)
    let video_dir = camera.get_video_dir();
    let video_dir_path = Path::new(&video_dir);
    let _ = fs::remove_dir_all(video_dir_path);

    //Fourth, delete data in the server
    match http_client.deregister(&group_motion_name) {
        Ok(_) => {
            info!("Motion data on server deleted successfully.")
        }
        Err(e) => {
            error!(
                "Error: Deleting motion data from server failed: {e}.\
                Sometimes, this error is okay since the app might have deleted the data already\
                or no data existed in the first place."
            );
        }
    }

    match http_client.deregister(&group_livestream_name) {
        Ok(_) => {
            info!("Livestream data on server deleted successfully.")
        }
        Err(e) => {
            error!(
                "Error: Deleting livestream data from server failed: {e}.\
                Sometimes, this error is okay since the app might have deleted the data already\
                or no data existed in the first place."
            );
        }
    }

    match http_client.deregister(&group_fcm_name) {
        Ok(_) => {
            info!("FCM data on server deleted successfully.")
        }
        Err(e) => {
            error!(
                "Error: Deleting FCM data from server failed: {e}.\
                Sometimes, this error is okay since the app might have deleted the data already\
                or no data existed in the first place."
            );
        }
    }

    match http_client.deregister(&group_config_name) {
        Ok(_) => {
            info!("Config data on server deleted successfully.")
        }
        Err(e) => {
            error!(
                "Error: Deleting config data from server failed: {e}.\
                Sometimes, this error is okay since the app might have deleted the data already\
                or no data existed in the first place."
            );
        }
    }

    println!("Reset finished.");
    Ok(())
}

fn core(
    camera: &mut dyn Camera,
    http_client: &HttpClient,
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

    let (camera_motion_name, group_motion_name) = get_names(
        camera,
        first_time,
        "camera_motion_name".to_string(),
        "group_motion_name".to_string(),
    );
    debug!("camera_motion_name = {}", camera_motion_name);
    debug!("group_motion_name = {}", group_motion_name);

    let (camera_livestream_name, group_livestream_name) = get_names(
        camera,
        first_time,
        "camera_livestream_name".to_string(),
        "group_livestream_name".to_string(),
    );
    debug!("camera_livestream_name = {}", camera_livestream_name);
    debug!("group_livestream_name = {}", group_livestream_name);

    let (camera_fcm_name, group_fcm_name) = get_names(
        camera,
        first_time,
        "camera_fcm_name".to_string(),
        "group_fcm_name".to_string(),
    );
    debug!("camera_fcm_name = {}", camera_fcm_name);
    debug!("group_fcm_name = {}", group_fcm_name);

    let (camera_config_name, group_config_name) = get_names(
        camera,
        first_time,
        "camera_config_name".to_string(),
        "group_config_name".to_string(),
    );
    debug!("camera_config_name = {}", camera_config_name);
    debug!("group_config_name = {}", group_config_name);

    let mut client_motion = User::new(
        camera_motion_name.clone(),
        first_time,
        state_dir.clone(),
        "motion".to_string(),
    )
    .map_err(|e| {
        error!("User::new() returned error:");
        e
    })?;
    debug!("Motion client created.");

    let mut client_livestream = User::new(
        camera_livestream_name.clone(),
        first_time,
        state_dir.clone(),
        "livestream".to_string(),
    )
    .map_err(|e| {
        error!("User::new() returned error:");
        e
    })?;
    debug!("Livestream client created.");

    let mut client_fcm = User::new(
        camera_fcm_name.clone(),
        first_time,
        state_dir.clone(),
        "fcm".to_string(),
    )
    .map_err(|e| {
        error!("User::new() returned error:");
        e
    })?;
    debug!("FCM client created.");

    let mut client_config = User::new(
        camera_config_name.clone(),
        first_time,
        state_dir.clone(),
        "config".to_string(),
    )
    .map_err(|e| {
        error!("User::new() returned error:");
        e
    })?;
    debug!("Config client created.");

    let camera_name = camera.get_name();
    if first_time {
        println!(
            "[{}] Waiting to be paired with the mobile app.",
            camera_name
        );
        create_camera_groups(
            camera,
            &mut client_motion,
            &mut client_livestream,
            &mut client_fcm,
            &mut client_config,
            group_motion_name.clone(),
            group_livestream_name.clone(),
            group_fcm_name.clone(),
            group_config_name.clone(),
            input_camera_secret,
            connect_to_wifi,
        )?;
        File::create(camera.get_state_dir() + "/first_time_done").expect("Could not create file");

        println!("[{}] Pairing successful.", camera_name);
    }

    println!("[{}] Running...", camera_name);

    let mut locked_motion_check_time: Option<SystemTime> = None;
    let mut locked_delivery_check_time: Option<SystemTime> = None;
    let mut locked_livestream_check_time: Option<SystemTime> = None;
    let video_dir = camera.get_video_dir();
    let mut delivery_monitor = DeliveryMonitor::from_file_or_new(video_dir, state_dir);
    let livestream_request = Arc::new(Mutex::new(false));
    let livestream_request_clone = Arc::clone(&livestream_request);
    let group_livestream_name_clone = group_livestream_name.clone();
    let http_client_clone = http_client.clone();

    thread::spawn(move || {
        loop {
            if http_client_clone.livestream_check(&group_livestream_name_clone).is_ok() {
                let mut check = livestream_request_clone.lock().unwrap();
                *check = true;
            } else {
                sleep(Duration::from_secs(1));
            }
        }
    });

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
                let notification_msg = client_fcm.encrypt(
                    &bincode::serialize(&video_info.timestamp).unwrap(),
                    group_fcm_name.clone(),
                )?;
                client_fcm.save_groups_state();
                match http_client.send_fcm_notification(notification_msg) {
                    Ok(_) => {}
                    Err(e) => {
                        error!("Failed to send FCM notification ({})", e);
                    }
                }
            }

            info!("Starting to record, prepare, and encrypt video.");
            let duration = if test_mode {
                1
            } else {
                20
            };

            camera.record_motion_video(&video_info, duration)?;

            prepare_motion_video(
                &mut client_motion,
                group_motion_name.clone(),
                video_info,
                &mut delivery_monitor,
            )?;

            info!("Uploading the encrypted video.");
            upload_pending_enc_videos(&group_motion_name, &mut delivery_monitor, &http_client);

            if !test_mode {
                info!("Sending the FCM notification to start downloading.");
                //Timestamp of 0 tells the app it's time to start downloading.
                let dummy_timestamp: u64 = 0;
                let notification_msg = client_fcm.encrypt(
                    &bincode::serialize(&dummy_timestamp).unwrap(),
                    group_fcm_name.clone(),
                )?;
                client_fcm.save_groups_state();
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
                    &mut client_livestream,
                    group_livestream_name.clone(),
                    camera,
                    http_client,
                )?;
            }

            locked_livestream_check_time = Some(SystemTime::now().add(Duration::from_secs(1)));
        }

        // Check with the delivery monitor every minute
        if locked_delivery_check_time.is_none()
            || locked_delivery_check_time.unwrap().le(&SystemTime::now())
        {
            upload_pending_enc_videos(&group_motion_name, &mut delivery_monitor, &http_client);
            locked_delivery_check_time = Some(SystemTime::now().add(Duration::from_secs(60)));
        }

        // Introduce a small delay since we don't need this constantly checked
        sleep(Duration::from_millis(10));
    }
}
