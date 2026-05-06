//! Secluso camera hub.
//!
//! SPDX-License-Identifier: GPL-3.0-or-later

#[macro_use]
extern crate log;

#[macro_use]
extern crate serde_derive;

use cfg_if::cfg_if;
use docopt::Docopt;
use secluso_client_lib::http_client::HttpClient;
use secluso_client_lib::mls_client::{ClientType, MlsClient};
use secluso_client_lib::mls_clients::{
    MlsClients, FCM, MLS_CLIENT_TAGS, MOTION, NUM_MLS_CLIENTS,
    THUMBNAIL, LIVESTREAM_DED, CONFIG_DED,
    MlsClientsCommon, MlsClientsDedicated,
};
use secluso_client_lib::thumbnail_meta_info::ThumbnailMetaInfo;
use std::array;
use std::fs;
use std::fs::File;
use std::io;
use std::ops::Add;
use std::panic;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::Instant;
use std::{thread, time::Duration};

mod delivery_monitor;

use crate::delivery_monitor::{DeliveryMonitor, VideoInfo};

mod motion;

use crate::motion::{
    prepare_motion_thumbnail, prepare_motion_video,
    upload_pending_enc_thumbnails, upload_pending_enc_videos,
};

mod livestream;

use crate::livestream::livestream;

mod traits;

use crate::traits::Camera;

mod pairing;

use crate::pairing::{
    create_wifi_hotspot, get_input_camera_secret, get_names, pair_all, read_parse_full_credentials,
};

mod config;

use crate::config::process_config_command;

mod version;

mod notification_target;

use crate::notification_target::send_notification;

#[cfg(any(feature = "raspberry", feature = "ip"))]
mod fmp4;
#[cfg(any(feature = "raspberry", feature = "ip"))]
mod mp4;

cfg_if! {
    if #[cfg(feature = "manual")] {
        mod manual;
        use crate::manual::ManualCamera;
    } else if #[cfg(feature = "raspberry")] {
        mod raspberry_pi;
        use crate::raspberry_pi::rpi_camera::RaspberryPiCamera;
    } else if #[cfg(feature = "ip")] {
        mod ip;
        use crate::ip::ip_camera::IpCamera;
    } else if #[cfg(feature = "test")] {
        mod test_camera;
        use crate::test_camera::TestCamera;
    } else {
        compile_error!("One of the features 'manual', 'raspberry', 'ip', or 'test' must be enabled.");
    }
}

const STATE_DIR_GENERAL: &str = "state";
const VIDEO_DIR_GENERAL: &str = "pending_videos";
const THUMBNAIL_DIR_GENERAL: &str = "pending_thumbnails";

// A counter representing the amount of active camera threads
static GLOBAL_THREAD_COUNT: AtomicUsize = AtomicUsize::new(0);

const USAGE: &str = "
Secluso camera hub: connects to an IP camera and send videos to the secluso app end-to-end encrypted (through an untrusted server).

Usage:
  secluso-camera-hub [--save-all]
  secluso-camera-hub [--save-all] --reset
  secluso-camera-hub [--save-all] --reset-full
  secluso-camera-hub (--version | -v)
  secluso-camera-hub (--help | -h)

Options:
    --reset             Wipe all the state, but not pending videos
    --reset-full        Wipe all the state and pending videos
    --save-all          Save all telemetry events, not just human detections
    --version, -v       Show version
    --help, -h          Show help
";

#[derive(Debug, Clone, Deserialize)]
struct Args {
    flag_reset: bool,
    flag_reset_full: bool,
    #[cfg(feature = "raspberry")]
    flag_save_all: bool,
}

fn main() -> io::Result<()> {
    let version = env!("CARGO_PKG_NAME").to_string() + ", version: " + env!("CARGO_PKG_VERSION");
    env_logger::init();

    let args: Args = Docopt::new(USAGE)
        .map(|d| d.help(true))
        .map(|d| d.version(Some(version)))
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    // Create the general outer directories (where we'll have inner directories representing each camera)
    fs::create_dir_all(STATE_DIR_GENERAL).unwrap();
    fs::create_dir_all(VIDEO_DIR_GENERAL).unwrap();
    fs::create_dir_all(THUMBNAIL_DIR_GENERAL).unwrap();

    // Write current package version to a file to be used by the update service if needed.
    fs::write("current_version", format!("v{}", env!("CARGO_PKG_VERSION")))?;

    cfg_if! {
        if #[cfg(feature = "manual")] {
            let camera = ManualCamera::new(
                "RPi".to_string(),
                format!("{}/manual", STATE_DIR_GENERAL),
                format!("{}/manual", VIDEO_DIR_GENERAL),
                format!("{}/manual", THUMBNAIL_DIR_GENERAL),
            )?;

            let camera_list: Vec<Box<dyn Camera + Send>> = vec![Box::new(camera)];
            // Manual mode is meant to stand in for the Raspberry Pi camera during local testing
            let input_camera_secret = Some(get_input_camera_secret());
            let connect_to_wifi = false;
        } else if #[cfg(feature = "raspberry")] {
            let camera = RaspberryPiCamera::new(
                "RPi".to_string(),
                STATE_DIR_GENERAL.to_string(),
                VIDEO_DIR_GENERAL.to_string(),
                THUMBNAIL_DIR_GENERAL.to_string(),
                1,
                args.flag_save_all,
            );

            let camera_list: Vec<Box<dyn Camera + Send>> = vec![Box::new(camera)];

            // This means that the secret will be provided to the hub in the camera_secret file.
            let input_camera_secret = Some(get_input_camera_secret());
            // This means that the camera_hub needs to receive the WiFi info from the app and
            // connect to the WiFi network.
            let connect_to_wifi = true;
        } else if #[cfg(feature = "ip")] {
            // When using IP cameras, the hub can support multiple cameras.
            // The info for these cameras should be encoded in the cameras.yaml
            // file. get_all_cameras_info() parses this file and returns the
            // list of cameras here.
            let camera_list: Vec<Box<dyn Camera + Send>> =
                IpCamera::get_all_cameras_info()?;
            // This means that the hub generates a new secret. This is usable when the user can
            // access the generated secret file in order to scan it in the app.
            // That is the case when using a hub with IP cameras, but not in the case of the
            // Raspberry Pi camera.
            let input_camera_secret: Option<Vec<u8>> = None;

            let connect_to_wifi = false;
        } else if #[cfg(feature = "test")] {
            let camera = TestCamera {
                name: "TestCamera".to_string(),
                state_dir: STATE_DIR_GENERAL.to_string(),
                video_dir: VIDEO_DIR_GENERAL.to_string(),
                thumbnail_dir: THUMBNAIL_DIR_GENERAL.to_string(),
                counter: 15,
            };

            let camera_list: Vec<Box<dyn Camera + Send>> = vec![Box::new(camera)];

            let input_camera_secret = Some(get_input_camera_secret());
            let connect_to_wifi = false;
        } else {
            compile_error!("One of the features 'manual', 'raspberry', 'ip', or 'test' must be enabled.");
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
            if args.flag_reset || args.flag_reset_full {
                match reset(camera.as_ref(), args.flag_reset_full) {
                    Ok(_) => {}
                    Err(e) => {
                        panic!("reset() returned with: {e}");
                    }
                };

                // Deduct one from our thread count for main thread to know when to exit (when all are finished)
                GLOBAL_THREAD_COUNT.fetch_sub(1, Ordering::SeqCst);
            } else {
                match core(
                    camera.as_mut(),
                    input_camera_secret.clone(),
                    connect_to_wifi,
                ) {
                    Ok(_) => {}
                    Err(e) => {
                        panic!("core() returned with: {e}");
                    }
                }
            }
        });
    }

    // Terminate when no cameras are left running
    while GLOBAL_THREAD_COUNT.load(Ordering::SeqCst) != 0 {
        sleep(Duration::from_millis(1));
    }

    Ok(())
}

fn reset(camera: &dyn Camera, reset_full: bool) -> io::Result<()> {
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

    for tag in MLS_CLIENT_TAGS.iter().take(NUM_MLS_CLIENTS) {
        let (camera_name, group_name) = get_names(
            camera.get_state_dir(),
            first_time,
            format!("camera_{}_name", tag),
            format!("group_{}_name", tag),
        );

        // First, clean up MLS users
        match MlsClient::new(
            camera_name,
            first_time,
            state_dir.clone(),
            tag.to_string(),
            ClientType::Camera,
        ) {
            Ok(mut client) => match client.clean() {
                Ok(_) => {
                    info!("{} client cleaned successfully.", tag)
                }
                Err(e) => {
                    error!("Error: Cleaning client_{} failed: {e}", tag);
                }
            },
            Err(e) => {
                error!("Error: Creating client_{} failed: {e}", tag);
            }
        };

        //Second, delete data in the server
        let (server_username, server_password, server_addr) = read_parse_full_credentials();
        let http_client = HttpClient::new(server_addr, server_username, server_password);

        match http_client.deregister(&group_name) {
            Ok(_) => {
                info!("{} data on server deleted successfully.", tag)
            }
            Err(e) => {
                error!(
                    "Error: Deleting {} data from server failed: {e}.\
                    Sometimes, this error is okay since the app might have deleted the data already\
                    or no data existed in the first place.",
                    tag
                );
            }
        }
    }

    //Third, delete all the local state files.
    let _ = fs::remove_dir_all(state_dir_path);
    let _ = fs::remove_file("credentials_full");

    //Fourth, (in the case of full reset) delete all the pending videos and thumbnails (those that were never successfully delivered)
    if reset_full {
        let video_dir = camera.get_video_dir();
        let video_dir_path = Path::new(&video_dir);
        let _ = fs::remove_dir_all(video_dir_path);

        let thumbnail_dir = camera.get_thumbnail_dir();
        let thumbnail_dir_path = Path::new(&thumbnail_dir);
        let _ = fs::remove_dir_all(thumbnail_dir_path);
    }

    println!("Reset finished.");
    Ok(())
}

pub fn initialize_mls_clients(camera: &dyn Camera, first_time: bool) -> MlsClients {
    array::from_fn(|i| {
        let (camera_name, group_name) = get_names(
            camera.get_state_dir(),
            first_time,
            format!("camera_{}_name", MLS_CLIENT_TAGS[i]),
            format!("group_{}_name", MLS_CLIENT_TAGS[i]),
        );
        debug!("{} camera_name = {}", MLS_CLIENT_TAGS[i], camera_name);
        debug!("{} group_name = {}", MLS_CLIENT_TAGS[i], group_name);

        let mut mls_client = MlsClient::new(
            camera_name,
            first_time,
            camera.get_state_dir(),
            MLS_CLIENT_TAGS[i].to_string(),
            ClientType::Camera,
        )
        .expect("MlsClient::new() for returned error.");

        if first_time {
            mls_client.create_group(&group_name).unwrap();
            debug!("Created group.");
        }

        mls_client.save_group_state().unwrap();

        mls_client
    })
}

fn split_clients(clients: MlsClients) -> (MlsClientsCommon, MlsClientsDedicated) {
    let [c0, c1, c2, d0, d1] = clients;
    ([c0, c1, c2], [d0, d1])
}

fn core(
    camera: &mut dyn Camera,
    input_camera_secret: Option<Vec<u8>>,
    connect_to_wifi: bool,
) -> anyhow::Result<()> {
    let state_dir = camera.get_state_dir();
    let first_time: bool = !Path::new(&(state_dir.clone() + "/first_time_done")).exists();

    if first_time && connect_to_wifi {
        println!("Creating WiFi hotspot.");
        create_wifi_hotspot();
    }

    let mut clients: MlsClients = initialize_mls_clients(camera, first_time);

    let camera_name = camera.get_name();

    if first_time {
        println!(
            "[{}] Waiting to be paired with the mobile app.",
            camera_name
        );
        pair_all(camera, &mut clients, input_camera_secret, connect_to_wifi)?;

        File::create(camera.get_state_dir() + "/first_time_done").expect("Could not create file");

        println!("[{}] Pairing successful.", camera_name);
    }

    let (mut clients_com, mut clients_ded_primary) = split_clients(clients);

    println!("[{}] Running...", camera_name);

    let (server_username, server_password, server_addr) = read_parse_full_credentials();
    let http_client = HttpClient::new(server_addr, server_username, server_password);

    let mut locked_motion_check_time: Option<Instant> = None;
    let mut locked_delivery_check_time: Option<Instant> = None;
    let mut locked_livestream_check_time: Option<Instant> = None;
    let mut locked_config_check_time: Option<Instant> = None;
    let video_dir = camera.get_video_dir();
    let thumbnail_dir = camera.get_thumbnail_dir();
    let mut delivery_monitor =
        DeliveryMonitor::from_file_or_new(video_dir, thumbnail_dir, state_dir.clone());
    let livestream_request = Arc::new(Mutex::new((false, true)));
    let livestream_request_clone = Arc::clone(&livestream_request);
    let group_livestream_name_clone = clients_ded_primary[LIVESTREAM_DED].get_group_name().unwrap();
    let http_client_clone = http_client.clone();
    let group_config_name_clone = clients_ded_primary[CONFIG_DED].get_group_name().unwrap();
    let http_client_clone_2 = http_client.clone();
    let config_enc_commands: Arc<Mutex<Vec<(Vec<u8>, bool)>>> = Arc::new(Mutex::new(vec![]));
    let config_enc_commands_clone = Arc::clone(&config_enc_commands);
    let clients_ded_secondary: Arc<Mutex<Option<MlsClientsDedicated>>> = Arc::new(Mutex::new(None));

    thread::spawn(move || loop {
        if http_client_clone
            .livestream_check(&group_livestream_name_clone)
            .is_ok()
        {
            println!("Livestream1 detected");
            let mut check = livestream_request_clone.lock().unwrap();
            *check = (true, true);  // second true -> livestream command from the primary app
        } else {
            sleep(Duration::from_secs(1));
        }
    });

    thread::spawn(move || loop {
        if let Ok(enc_command) = http_client_clone_2.config_check(&group_config_name_clone) {
            let mut config_enc_commands = config_enc_commands_clone.lock().unwrap();
            config_enc_commands.push((enc_command, true)); // true -> config command from the primary app
        } else {
            error!("Error in receiving config command");
            sleep(Duration::from_secs(1));
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
        if (motion_event.motion)
            && (locked_motion_check_time.is_none()
                || locked_motion_check_time.unwrap().le(&Instant::now()))
        {
            let video_info = VideoInfo::new();
            let motion_timestamp = video_info.timestamp;
            println!("Detected motion.");

            let clients_ded_sec_opt = clients_ded_secondary.lock().unwrap();
            let num_apps = if clients_ded_sec_opt.is_some() {
                2
            } else {
                1
            };

            // We send the thumbnail BEFORE the FCM notification, to ensure that when the mobile app receives it, it can download it.
            if let Some(thumbnail_image) = motion_event.thumbnail {
                info!("Starting to save and send video thumbnail");
                let thumbnail_info =
                    ThumbnailMetaInfo::new(video_info.timestamp, 0, motion_event.detections); //0 epoch = unset
                let thumbnail_file = camera.get_thumbnail_dir()
                    + "/"
                    + &ThumbnailMetaInfo::get_filename_from_timestamp(thumbnail_info.timestamp);
                thumbnail_image
                    .save(thumbnail_file)
                    .expect("Failed to save thumbnail PNG file");

                prepare_motion_thumbnail(
                    &mut clients_com[THUMBNAIL],
                    thumbnail_info,
                    &mut delivery_monitor,
                )?;

                info!("Uploading the encrypted thumbnail.");
                let _ = upload_pending_enc_thumbnails(
                    &clients_com[THUMBNAIL].get_group_name().unwrap(),
                    &mut delivery_monitor,
                    &http_client,
                    num_apps,
                );
            }

            let state_dir_ref = state_dir.as_str();
            info!("Sending the motion notification with timestamp.");
            let notification_msg =
                clients_com[FCM].encrypt(&bincode::serialize(&motion_timestamp).unwrap())?;
            clients_com[FCM].save_group_state().unwrap();
            match send_notification(state_dir_ref, &http_client, notification_msg) {
                Ok(_) => {}
                Err(e) => {
                    error!("Failed to send motion notification ({})", e);
                }
            }

            info!("Starting to record, prepare, and encrypt video.");
            let duration = 20;

            camera.record_motion_video(&video_info, duration)?;
            prepare_motion_video(&mut clients_com[MOTION], video_info, &mut delivery_monitor)?;

            info!("Uploading the encrypted video.");
            let _ = upload_pending_enc_videos(
                &clients_com[MOTION].get_group_name().unwrap(),
                &mut delivery_monitor,
                &http_client,
                num_apps,
            );

            let state_dir_ref = state_dir.as_str();
            let target =
                notification_target::refresh_notification_target(state_dir_ref, &http_client);
            let platform_label = target
                .as_ref()
                .map(|target| target.platform.as_str())
                .unwrap_or("fcm");
            info!(
                "Sending the post-upload notification to start downloading over {}.",
                platform_label
            );
            let notification_timestamp: u64 = 0;
            let notification_msg = clients_com[FCM]
                .encrypt(&bincode::serialize(&notification_timestamp).unwrap())?;
            clients_com[FCM].save_group_state().unwrap();
            match send_notification(state_dir_ref, &http_client, notification_msg) {
                Ok(_) => {}
                Err(e) => {
                    error!("Failed to send motion notification ({})", e);
                }
            }

            locked_motion_check_time = Some(Instant::now().add(Duration::from_secs(60)));
        }

        // Check for livestream requests frequently so the app doesn't sit on
        // "starting livestream" for an extra second just waiting for the next poll.
        if locked_livestream_check_time.is_none()
            || locked_livestream_check_time.unwrap().le(&Instant::now())
        {
            // Livestream request? Start it.
            let mut check = livestream_request.lock().unwrap();
            let primary_app = check.1;
            if check.0 {
                info!("Livestream start detected");
                *check = (false, false);
                if primary_app {
                    livestream(
                        &mut clients_ded_primary[LIVESTREAM_DED],
                        camera,
                        &mut delivery_monitor,
                        &http_client,
                    )?;
                } else {
                    let mut clients_ded_sec_opt = clients_ded_secondary.lock().unwrap();
                    if let Some(ref mut clients_ded_sec) = *clients_ded_sec_opt { // Should always be the case if we get here
                        livestream(
                            &mut clients_ded_sec[LIVESTREAM_DED],
                            camera,
                            // FIXME: delivery_monitor should use a separate queue for app2
                            &mut delivery_monitor,
                            &http_client,
                        )?;
                    }
                }
            }

            locked_livestream_check_time = Some(Instant::now().add(Duration::from_millis(100)));
        }

        // Check with the delivery monitor every minute
        if locked_delivery_check_time.is_none()
            || locked_delivery_check_time.unwrap().le(&Instant::now())
        {
            let clients_ded_sec_opt = clients_ded_secondary.lock().unwrap();
            let num_apps = if clients_ded_sec_opt.is_some() {
                2
            } else {
                1
            };

            if upload_pending_enc_videos(
                &clients_com[MOTION].get_group_name().unwrap(),
                &mut delivery_monitor,
                &http_client,
                num_apps,
            )
            .is_ok()
            {
                // After sending all the pending encrypted videos, we might still have
                // some pending videos that are not encrypted. This could happen if we
                // previously failed to encrypt them, e.g., as a result of enforcing a
                // max offline priod for the app. We'll try to send them here.
                // FIXME: since we're not yet enforcing the max offline period,
                // this is not needed for now.
                //let _ = send_pending_motion_videos(camera, &mut clients, &mut delivery_monitor, &http_client);
            }

            if upload_pending_enc_thumbnails(
                &clients_com[THUMBNAIL].get_group_name().unwrap(),
                &mut delivery_monitor,
                &http_client,
                num_apps,
            )
            .is_ok()
            {
                // FIXME: since we're not yet enforcing the max offline period,
                // this is not needed for now.
                //let _ = send_pending_thumbnails(camera, &mut clients, &mut delivery_monitor, &http_client);
            }

            locked_delivery_check_time = Some(Instant::now().add(Duration::from_secs(60)));
        }

        // Check for config commands every second
        if locked_config_check_time.is_none()
            || locked_config_check_time.unwrap().le(&Instant::now())
        {
            let mut enc_commands = config_enc_commands.lock().unwrap();
            for enc_command in &*enc_commands {
                let primary_app = enc_command.1;

                if primary_app {
                    println!("About to call process_config_command for primary app");
                    let mut clients_ded_sec_opt = clients_ded_secondary.lock().unwrap();
                    let process_ret = process_config_command(
                        &mut clients_com,
                        &mut clients_ded_primary,
                        &enc_command.0,
                        &http_client,
                        // TODO: We only keep track of video delivery to the primary app for now.
                        Some(&mut delivery_monitor),
                        true,
                        clients_ded_sec_opt.is_some(),
                    )?;

                    if clients_ded_sec_opt.is_none() {
                        *clients_ded_sec_opt = process_ret;

                        if let Some(ref clients_ded_sec) = *clients_ded_sec_opt {
                            println!("Launching threads for the second app.");
                            let group_livestream2_name_clone = clients_ded_sec[LIVESTREAM_DED].get_group_name()?;
                            let livestream_request_clone_2 = Arc::clone(&livestream_request);
                            let http_client_clone_3 = http_client.clone();
                            let group_config2_name_clone = clients_ded_sec[CONFIG_DED].get_group_name()?;
                            let http_client_clone_4 = http_client.clone();
                            let config_enc_commands_clone_2 = Arc::clone(&config_enc_commands);

                            thread::spawn(move || loop {
                                if http_client_clone_3
                                    .livestream_check(&group_livestream2_name_clone)
                                    .is_ok()
                                {
                                    println!("Livestream2 detected");
                                    let mut check = livestream_request_clone_2.lock().unwrap();
                                    *check = (true, false); // false -> livestream command from the secondary app
                                } else {
                                    sleep(Duration::from_secs(1));
                                }
                            });

                            thread::spawn(move || loop {
                                if let Ok(enc_command) = http_client_clone_4.config_check(&group_config2_name_clone) {
                                    let mut config_enc_commands = config_enc_commands_clone_2.lock().unwrap();
                                    config_enc_commands.push((enc_command, false)); // false -> config command from the secondary app
                                } else {
                                    error!("Error in receiving config command");
                                    sleep(Duration::from_secs(1));
                                }
                            });
                        }
                    }
                } else {
                    println!("About to call process_config_command for secondary app");
                    let mut clients_ded_sec_opt = clients_ded_secondary.lock().unwrap();
                    if let Some(ref mut clients_ded_sec) = *clients_ded_sec_opt {
                        let _ = process_config_command(
                            &mut clients_com,
                            clients_ded_sec, // Will not be None if we get here
                            &enc_command.0,
                            &http_client,
                            None,
                            false,
                            true,
                        )?;
                    }
                }
            }
            enc_commands.clear();
            locked_config_check_time = Some(Instant::now().add(Duration::from_secs(1)));
        }

        // Introduce a small delay since we don't need this constantly checked
        sleep(Duration::from_millis(100));
    }
}
