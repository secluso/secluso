//! Privastead camera hub.
//!
//! Copyright (C) 2024  Ardalan Amiri Sani
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

use docopt::Docopt;
use image::Luma;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::random::OpenMlsRand;
use openmls_traits::OpenMlsProvider;
use privastead_client_lib::pairing;
use privastead_client_lib::user::{KeyPackages, User};
use privastead_client_lib::video_net_info::{VideoAckInfo, VideoNetInfo};
use qrcode::QrCode;
use rand::Rng;
use rpassword::read_password;
use std::fs;
use std::io;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::{thread, time::Duration};

mod ip_camera;
use crate::ip_camera::IpCamera;

mod delivery_monitor;
use crate::delivery_monitor::{DeliveryMonitor, VideoInfo};

mod livestream;
use crate::livestream::{is_there_livestream_start_request, livestream};

mod fmp4;
mod mp4;
mod traits;

// Used to generate random names.
// With 16 alphanumeric characters, the probability of collision is very low.
// Note: even if collision happens, it has no impact on
// our security guarantees. Will only cause availability issues.
const NUM_RANDOM_CHARS: u8 = 16;

const STATE_DIR: &str = "state";
const VIDEO_DIR: &str = "pending_videos";

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

fn generate_camera_secret() -> Vec<u8> {
    let crypto = OpenMlsRustCrypto::default();
    let secret = crypto
        .crypto()
        .random_vec(pairing::NUM_SECRET_BYTES)
        .unwrap();

    // Save as QR code to be shown to the app
    let code = QrCode::new(secret.clone()).unwrap();
    let image = code.render::<Luma<u8>>().build();
    image.save("camera_secret_qrcode.png").unwrap();

    // FIXME: Remove. For testing only.
    let mut file = fs::File::create("camera_secret").expect("Could not create file");
    let _ = file.write_all(&secret);

    secret
}

fn pair_with_app(
    camera_motion_key_packages: KeyPackages,
    camera_livestream_key_packages: KeyPackages,
    camera_fcm_key_packages: KeyPackages,
) -> (KeyPackages, KeyPackages, KeyPackages) {
    let secret = generate_camera_secret();
    if secret.len() != pairing::NUM_SECRET_BYTES {
        panic!("Invalid number of bytes in secret!");
    }

    println!("File camera_secret_qrcode.png was just created. Use the QR code in the app to pair.");

    let mut camera_secret = [0u8; pairing::NUM_SECRET_BYTES];
    camera_secret.copy_from_slice(&secret[..]);

    let listener = TcpListener::bind("0.0.0.0:12348").unwrap();
    let (mut stream, _) = listener.accept().unwrap();

    let app_motion_key_packages =
        perform_pairing_handshake(&mut stream, camera_motion_key_packages, camera_secret);
    let app_livestream_key_packages =
        perform_pairing_handshake(&mut stream, camera_livestream_key_packages, camera_secret);
    let app_fcm_key_packages =
        perform_pairing_handshake(&mut stream, camera_fcm_key_packages, camera_secret);

    let _ = fs::remove_file("camera_secret_qrcode.png");
    let _ = fs::remove_file("camera_secret");

    (
        app_motion_key_packages,
        app_livestream_key_packages,
        app_fcm_key_packages,
    )
}

fn create_group_and_invite(
    client: &mut User,
    group_name: String,
    app_key_packages: KeyPackages,
) -> io::Result<()> {
    let app_contact = client.add_contact("app".to_string(), app_key_packages)?;
    debug!("Added contact.");

    client.create_group(group_name.clone());
    client.save_groups_state();
    debug!("Created group.");

    client.invite(&app_contact, group_name).map_err(|e| {
        error!("invite() returned error:");
        e
    })?;
    client.save_groups_state();
    debug!("App invited to the group.");

    fs::File::create(STATE_DIR.to_owned() + "/first_time_done").expect("Could not create file");

    Ok(())
}

fn create_camera_groups(
    client_motion: &mut User,
    client_livestream: &mut User,
    client_fcm: &mut User,
    group_motion_name: String,
    group_livestream_name: String,
    group_fcm_name: String,
) -> io::Result<()> {
    let (app_motion_key_packages, app_livestream_key_packages, app_fcm_key_packages) =
        pair_with_app(
            client_motion.key_packages(),
            client_livestream.key_packages(),
            client_fcm.key_packages(),
        );

    create_group_and_invite(client_motion, group_motion_name, app_motion_key_packages)?;
    create_group_and_invite(
        client_livestream,
        group_livestream_name,
        app_livestream_key_packages,
    )?;
    create_group_and_invite(client_fcm, group_fcm_name, app_fcm_key_packages)?;

    Ok(())
}

fn get_names(
    first_time: bool,
    camera_filename: String,
    group_filename: String,
) -> (String, String) {
    let (camera_name, group_name) = if first_time {
        let mut rng = rand::thread_rng();
        let cname: String = (0..NUM_RANDOM_CHARS)
            .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
            .collect();

        let mut file = fs::File::create(STATE_DIR.to_owned() + "/" + &camera_filename)
            .expect("Could not create file");
        file.write_all(cname.as_bytes()).unwrap();
        file.flush().unwrap();
        file.sync_all().unwrap();

        //FIXME: how many random characters should we use here?
        let gname: String = (0..NUM_RANDOM_CHARS)
            .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
            .collect();

        file = fs::File::create(STATE_DIR.to_owned() + "/" + &group_filename)
            .expect("Could not create file");
        file.write_all(gname.as_bytes()).unwrap();
        file.flush().unwrap();
        file.sync_all().unwrap();

        (cname, gname)
    } else {
        let file = fs::File::open(STATE_DIR.to_owned() + "/" + &camera_filename)
            .expect("Cannot open file to send");
        let mut reader =
            BufReader::with_capacity(file.metadata().unwrap().len().try_into().unwrap(), file);
        let cname = reader.fill_buf().unwrap();

        let file = fs::File::open(STATE_DIR.to_owned() + "/" + &group_filename)
            .expect("Cannot open file to send");
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

fn get_user_credentials() -> Vec<u8> {
    let pathname = "./user_credentials";
    let file = fs::File::open(pathname).expect("Could not open file");
    let mut reader =
        BufReader::with_capacity(file.metadata().unwrap().len().try_into().unwrap(), file);
    let data = reader.fill_buf().unwrap();

    data.to_vec()
}

fn send_motion_triggered_video(
    client: &mut User,
    group_name: String,
    video_info: VideoInfo,
    delivery_monitor: &mut DeliveryMonitor,
) -> io::Result<()> {
    debug!("Forcing an MLS update.");
    let new_update = client
        .perform_update(group_name.clone())
        .expect("Could not force an MLS update!");
    // We must save state between the calls to perform_update() and send_update().
    // This is to make sure we don't end up sending an update to the app, which
    // we have not successfully committed/saved on our end.
    client.save_groups_state();
    client.send_update(group_name.clone())
        .expect("Could not send the pending update!");
    if !new_update {
        // We don't want the attacker to force us to send more than one video without an update.
        // We add the video to the delivery monitor, hoping that it will be sent in the future
        // after the app acks the update.
        info!("Sent pending update. Will not send video until update is acked (indirectly).");
        delivery_monitor.send_event(video_info);
        return Ok(());
    }

    debug!("Starting to send video.");
    let file = fs::File::open(VIDEO_DIR.to_owned() + "/" + &video_info.filename.clone())
        .expect("Cannot open file to send");
    let file_len = file.metadata().unwrap().len();
    // We want each encrypted message to fit within one TCP packet (max size: 64 kB or 65535 B).
    // With these numbers, some experiments show that the encrypted message will have the max
    // size of 64687 B.
    const READ_SIZE: usize = 63 * 1024;
    let mut reader = BufReader::with_capacity(READ_SIZE, file);

    let net_info = VideoNetInfo::new(video_info.timestamp, file_len, READ_SIZE as u64);

    client
        .send(&bincode::serialize(&net_info).unwrap(), group_name.clone())
        .map_err(|e| {
            error!("send() returned error:");
            e
        })?;

    for i in 0..net_info.num_msg {
        let buffer = reader.fill_buf().unwrap();
        let length = buffer.len();
        // Sanity checks
        if i < (net_info.num_msg - 1) {
            assert!(length == READ_SIZE);
        } else {
            assert!(length == (<u64 as TryInto<usize>>::try_into(file_len).unwrap() % READ_SIZE));
        }

        client.send(buffer, group_name.clone()).map_err(|e| {
            error!("send_video() returned error:");
            client.save_groups_state();
            e
        })?;
        reader.consume(length);
    }
    client.save_groups_state();

    info!("Sending the video ({}).", video_info.timestamp);
    delivery_monitor.send_event(video_info);
    info!("Sent the video.");

    Ok(())
}

fn process_motion_acks(
    client: &mut User,
    delivery_monitor: &mut DeliveryMonitor,
) -> io::Result<bool> {
    let mut any_ack = false;
    //FIXME: check the contact_name.
    let callback = |msg_bytes: Vec<u8>, _contact_name: String| -> io::Result<()> {
        let acked_videos: Vec<VideoAckInfo> = match bincode::deserialize(&msg_bytes) {
            Ok(acked) => acked,
            Err(e) => {
                error!(
                    "Error: could not convert msg_bytes to vec<u64> for acked videos: {}",
                    e
                );
                return Ok(());
            }
        };

        for video_ack_info in acked_videos {
            info!("Acked: {}", video_ack_info.timestamp);
            delivery_monitor.ack_event(video_ack_info.timestamp, video_ack_info.video_ack);
            any_ack = true;
        }

        Ok(())
    };

    client.receive(callback)?;
    client.save_groups_state();

    Ok(any_ack)
}

fn send_video_notification(
    client: &mut User,
    group_name: String,
    video_info: VideoInfo,
    delivery_monitor: &mut DeliveryMonitor,
) -> io::Result<()> {
    // FIXME: We might send a whole bunch of notifications without forcing
    // an update. If the update is not acked, then we should start sending
    // dummy notifications.
    debug!("An MLS update reminder.");
    client
        .perform_update(group_name.clone())
        .expect("Could not force an MLS update!");
    // We must save state between the calls to perform_update() and send_update().
    // This is to make sure we don't end up sending an update to the app, which
    // we have not successfully committed/saved on our end.
    client.save_groups_state();
    client.send_update(group_name.clone())
        .expect("Could not send the pending update!");

    let info_notify = VideoNetInfo::new_notification(video_info.timestamp);

    client
        .send(
            &bincode::serialize(&info_notify).unwrap(),
            group_name.clone(),
        )
        .map_err(|e| {
            error!("send() returned error:");
            e
        })?;
    client.save_groups_state();

    info!("Sending notification for video ({}).", video_info.timestamp);
    delivery_monitor.notify_event(video_info);

    Ok(())
}

fn ask_user(prompt: String) -> io::Result<String> {
    print!("{prompt}");
    // Make sure the prompt is displayed before reading input
    io::stdout().flush()?;

    let mut user_input = String::new();
    io::stdin().read_line(&mut user_input)?;
    // Trim the input to remove any extra whitespace or newline characters
    Ok(user_input.trim().to_string())
}

fn ask_user_password(prompt: String) -> io::Result<String> {
    print!("{prompt}");
    // Make sure the prompt is displayed before reading input
    io::stdout().flush()?;

    let password = read_password()?;
    // Trim the input to remove any extra whitespace or newline characters
    Ok(password.trim().to_string())
}

const USAGE: &str = "
Privastead camera hub: connects to an IP camera and send videos to the privastead app end-to-end encrypted (through an untrusted server).

Usage:
  privastead-camera-hub --server-ip SERVERIP --ip-camera-ip CAMERAIP --ip-camera-rtsp-port CAMERARTSPPORT
  privastead-camera-hub --server-ip SERVERIP --ip-camera-ip CAMERAIP --ip-camera-rtsp-port CAMERARTSPPORT --provide-username-password --ip-camera-username USERNAME --ip-camera-password PASSWORD
  privastead-camera-hub --reset --server-ip SERVERIP
  privastead-camera-hub (--version | -v)
  privastead-camera-hub (--help | -h)

Options:
    --server-ip SERVERIP                        IP address of the server
    --ip-camera-ip CAMERAIP                     IP address of the IP camera
    --ip-camera-rtsp-port CAMERARTSPPORT        RTSP port on the IP camera
    --provide-username-password                 Provide the username and password of the IP camera. If not set, they need to be entered on prompt.
    --ip-camera-username USERNAME               Username of the IP camera.
    --ip-camera-password PASSWORD               Password of the IP camera.
    --reset                                     Wipe all the state
    --version, -v                               Show version
    --help, -h                                  Show help
";

#[derive(Debug, Deserialize)]
struct Args {
    flag_server_ip: String,
    flag_ip_camera_ip: String,
    flag_ip_camera_rtsp_port: u16,
    flag_provide_username_password: bool,
    flag_ip_camera_username: String,
    flag_ip_camera_password: String,
    flag_reset: bool,
}

fn main() -> io::Result<()> {
    let version = env!("CARGO_PKG_NAME").to_string() + ", version: " + env!("CARGO_PKG_VERSION");
    env_logger::init();

    let args: Args = Docopt::new(USAGE)
        .map(|d| d.help(true))
        .map(|d| d.version(Some(version)))
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    let credentials = get_user_credentials();

    let (ip_camera_username, ip_camera_password) = if args.flag_reset {
        ("".to_string(), "".to_string())
    } else if args.flag_provide_username_password {
        (args.flag_ip_camera_username, args.flag_ip_camera_password)
    } else {
        (
            ask_user("Enter the username for the IP camera: ".to_string()).unwrap(),
            ask_user_password("Enter the password for the IP camera: ".to_string()).unwrap(),
        )
    };

    fs::create_dir_all(STATE_DIR).unwrap();
    fs::create_dir_all(VIDEO_DIR).unwrap();

    let delivery_service_addr: String = args.flag_server_ip + ":12346";

    loop {
        let mut motion_stream: Option<TcpStream> = None;
        let mut livestream_stream: Option<TcpStream> = None;
        let mut fcm_stream: Option<TcpStream> = None;

        match TcpStream::connect(delivery_service_addr.clone()) {
            Ok(stream) => motion_stream = Some(stream),
            Err(_) => {
                let _ = fs::remove_file(STATE_DIR.to_owned() + "/registration_done");
            }
        }

        match TcpStream::connect(delivery_service_addr.clone()) {
            Ok(stream) => livestream_stream = Some(stream),
            Err(_) => {
                let _ = fs::remove_file(STATE_DIR.to_owned() + "/registration_done");
            }
        }

        match TcpStream::connect(delivery_service_addr.clone()) {
            Ok(stream) => fcm_stream = Some(stream),
            Err(_) => {
                let _ = fs::remove_file(STATE_DIR.to_owned() + "/registration_done");
            }
        }

        if motion_stream.is_some() && livestream_stream.is_some() && fcm_stream.is_some() {
            if args.flag_reset {
                reset(
                    motion_stream.unwrap(),
                    livestream_stream.unwrap(),
                    fcm_stream.unwrap(),
                    credentials,
                );
                return Ok(());
            } else {
                match core(
                    motion_stream.unwrap(),
                    livestream_stream.unwrap(),
                    fcm_stream.unwrap(),
                    credentials.clone(),
                    args.flag_ip_camera_ip.clone(),
                    args.flag_ip_camera_rtsp_port,
                    ip_camera_username.clone(),
                    ip_camera_password.clone(),
                ) {
                    Ok(_) => {}
                    Err(e) => {
                        error!("core() returned with: {e}");
                    }
                }
            }
        }
        println!("There was a problem with the connection to the server. Will try to connect again soon.");
        let _ = fs::remove_file(STATE_DIR.to_owned() + "/registration_done");
        thread::sleep(Duration::from_secs(10));
    }
}

fn reset(
    server_motion_stream: TcpStream,
    server_livestream_stream: TcpStream,
    server_fcm_stream: TcpStream,
    credentials: Vec<u8>,
) {
    // First, deregister from the server
    // FIXME: has some code copy/pasted from core()
    let first_time: bool = !Path::new(&(STATE_DIR.to_owned() + "/first_time_done")).exists();

    if first_time {
        println!("There's no state to reset!");
        return;
    }

    let reregister = false;

    let (camera_motion_name, _group_motion_name) = get_names(
        first_time,
        "camera_motion_name".to_string(),
        "group_motion_name".to_string(),
    );

    let (camera_livestream_name, _group_livestream_name) = get_names(
        first_time,
        "camera_livestream_name".to_string(),
        "group_livestream_name".to_string(),
    );

    let (camera_fcm_name, _group_fcm_name) = get_names(
        first_time,
        "camera_fcm_name".to_string(),
        "group_fcm_name".to_string(),
    );

    match User::new(
        camera_motion_name,
        Some(server_motion_stream),
        first_time,
        reregister,
        STATE_DIR.to_string(),
        "motion".to_string(),
        credentials.clone(),
        false,
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
        Some(server_livestream_stream),
        first_time,
        reregister,
        STATE_DIR.to_string(),
        "livestream".to_string(),
        credentials.clone(),
        false,
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
        Some(server_fcm_stream),
        first_time,
        reregister,
        STATE_DIR.to_string(),
        "fcm".to_string(),
        credentials,
        false,
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

    //Second, delete all the local state files.
    let state_dir_path = Path::new(STATE_DIR);
    let _ = fs::remove_dir_all(state_dir_path);

    //Third, delete all the pending videos (those that were never successfully delivered)
    let video_dir_path = Path::new(VIDEO_DIR);
    let _ = fs::remove_dir_all(video_dir_path);

    println!("Reset finished.");
}

#[allow(clippy::too_many_arguments)]
fn core(
    server_motion_stream: TcpStream,
    server_livestream_stream: TcpStream,
    server_fcm_stream: TcpStream,
    credentials: Vec<u8>,
    ip_camera_ip: String,
    ip_camera_rtsp_port: u16,
    ip_camera_username: String,
    ip_camera_password: String,
) -> io::Result<()> {
    let first_time: bool = !Path::new(&(STATE_DIR.to_owned() + "/first_time_done")).exists();
    let reregister: bool = !Path::new(&(STATE_DIR.to_owned() + "/registration_done")).exists();

    let (camera_motion_name, group_motion_name) = get_names(
        first_time,
        "camera_motion_name".to_string(),
        "group_motion_name".to_string(),
    );
    debug!("camera_motion_name = {}", camera_motion_name);
    debug!("group_motion_name = {}", group_motion_name);

    let (camera_livestream_name, group_livestream_name) = get_names(
        first_time,
        "camera_livestream_name".to_string(),
        "group_livestream_name".to_string(),
    );
    debug!("camera_livestream_name = {}", camera_livestream_name);
    debug!("group_livestream_name = {}", group_livestream_name);

    let (camera_fcm_name, group_fcm_name) = get_names(
        first_time,
        "camera_fcm_name".to_string(),
        "group_fcm_name".to_string(),
    );
    debug!("camera_fcm_name = {}", camera_fcm_name);
    debug!("group_fcm_name = {}", group_fcm_name);

    let mut client_motion = User::new(
        camera_motion_name,
        Some(server_motion_stream),
        first_time,
        reregister,
        STATE_DIR.to_string(),
        "motion".to_string(),
        credentials.clone(),
        true,
    )
    .map_err(|e| {
        error!("User::new() returned error:");
        e
    })?;
    debug!("Motion client created.");

    let mut client_livestream = User::new(
        camera_livestream_name,
        Some(server_livestream_stream),
        first_time,
        reregister,
        STATE_DIR.to_string(),
        "livestream".to_string(),
        credentials.clone(),
        true,
    )
    .map_err(|e| {
        error!("User::new() returned error:");
        e
    })?;
    debug!("Livestream client created.");

    let mut client_fcm = User::new(
        camera_fcm_name,
        Some(server_fcm_stream),
        first_time,
        reregister,
        STATE_DIR.to_string(),
        "fcm".to_string(),
        credentials,
        true,
    )
    .map_err(|e| {
        error!("User::new() returned error:");
        e
    })?;
    debug!("FCM client created.");

    fs::File::create(STATE_DIR.to_owned() + "/registration_done").expect("Could not create file");

    if first_time {
        println!("Waiting to be paired with the mobile app.");
        create_camera_groups(
            &mut client_motion,
            &mut client_livestream,
            &mut client_fcm,
            group_motion_name.clone(),
            group_livestream_name.clone(),
            group_fcm_name.clone(),
        )?;
        println!("Pairing successful.");
    }

    println!("Running...");

    let mut motion_check_iterations_to_skip: u8 = 0;
    let mut delivery_check_iterations_to_skip: u8 = 0;
    let mut delivery_monitor =
        DeliveryMonitor::from_file_or_new(VIDEO_DIR.to_string(), STATE_DIR.to_string(), 60);

    loop {
        let ip_camera_result = IpCamera::new(
            ip_camera_ip.clone(),
            ip_camera_rtsp_port.to_string(),
            ip_camera_username.clone(),
            ip_camera_password.clone(),
            STATE_DIR.to_string(),
        );
        if ip_camera_result.is_err() {
            // Wait and try again
            println!("Failed to connect to the IP camera. Will try again in a little bit. Consider resetting the camera.");
            thread::sleep(Duration::from_millis(10000));
        } else {
            let ip_camera = ip_camera_result.unwrap();
            // Used for anti-dither for motion detection
            loop {
                let motion_event_result = ip_camera.is_there_onvif_motion_event();
                if motion_event_result.is_err() {
                    // The pull point might be invalid now.
                    // Remove the saved pull url, exit the inner loop, and recreate the ip camera
                    ip_camera.delete_pull_url_file();
                    break;
                }

                // Check motion events from the IP camera every second
                let motion_event = motion_event_result.unwrap();

                // Send motion events only if we haven't sent one in the past minute
                if motion_event && motion_check_iterations_to_skip == 0 {
                    let video_info = VideoInfo::new();
                    info!("Sending the FCM notification with timestamp.");
                    client_fcm.send_fcm(
                        &bincode::serialize(&video_info.timestamp).unwrap(),
                        group_fcm_name.clone(),
                    )?;
                    client_fcm.save_groups_state();
                    match ip_camera.record_motion_video(VIDEO_DIR.to_string(), &video_info) {
                        Ok(_) => {
                            info!("Sending the FCM notification to start downloading.");
                            //Timestamp of 0 tells the app it's time to start downloading.
                            let dummy_timestamp: u64 = 0;
                            client_fcm.send_fcm(
                                &bincode::serialize(&dummy_timestamp).unwrap(),
                                group_fcm_name.clone(),
                            )?;
                            client_fcm.save_groups_state();
                            send_motion_triggered_video(
                                &mut client_motion,
                                group_motion_name.clone(),
                                video_info,
                                &mut delivery_monitor,
                            )?;
                            motion_check_iterations_to_skip = 60;
                        }
                        Err(e) => {
                            error!("Error recording motion video: {e}");
                        }
                    }
                } else {
                    motion_check_iterations_to_skip =
                        motion_check_iterations_to_skip.saturating_sub(1);
                }

                // Livestream requeset? Start it.
                if is_there_livestream_start_request(&mut client_livestream)? {
                    livestream(
                        &mut client_livestream,
                        group_livestream_name.clone(),
                        &ip_camera,
                    )?;
                }

                // Process motion acks
                let any_ack = process_motion_acks(&mut client_motion, &mut delivery_monitor)?;

                // Check with the delivery service every minute
                if any_ack || delivery_check_iterations_to_skip == 0 {
                    let (resend_list, renotify_list) = delivery_monitor.videos_to_resend_renotify();

                    let mut any_resend = false;
                    for video_info in resend_list {
                        any_resend = true;
                        send_motion_triggered_video(
                            &mut client_motion,
                            group_motion_name.clone(),
                            video_info,
                            &mut delivery_monitor,
                        )?;
                    }

                    // If we resend any videos above, that ends up sending a notification
                    // to the app anyway.
                    if !any_resend && !renotify_list.is_empty() {
                        // It's enough to send one notification
                        // We just want to send an FCM message in order to get the app to fetch the messages.
                        debug!("Sending the FCM notification.");
                        let dummy_timestamp: u64 = 0;
                        client_fcm.send_fcm(
                            &bincode::serialize(&dummy_timestamp).unwrap(),
                            group_fcm_name.clone(),
                        )?;
                        client_fcm.save_groups_state();
                        send_video_notification(
                            &mut client_motion,
                            group_motion_name.clone(),
                            renotify_list.first().unwrap().clone(),
                            &mut delivery_monitor,
                        )?;

                        // For the rest, just tell the delivery_monitor that we sent a notification.
                        for video_info in &renotify_list[1..] {
                            delivery_monitor.notify_event(video_info.clone());
                        }
                    }

                    delivery_check_iterations_to_skip = 60;
                } else {
                    delivery_check_iterations_to_skip -= 1;
                }
            }
        }
    }
}
