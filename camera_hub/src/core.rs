//! Secluso camera hub.
//!
//! SPDX-License-Identifier: GPL-3.0-or-later

use cfg_if::cfg_if;
use secluso_client_lib::http_client::HttpClient;
use secluso_client_lib::mls_client::{ClientType, MlsClient};
use secluso_client_lib::mls_clients::{
    MlsClients, FCM, MLS_CLIENT_TAGS, MOTION, NUM_MLS_CLIENTS,
    THUMBNAIL, LIVESTREAM_DED, CONFIG_DED,
    MlsClientsCommon, MlsClientsDedicated,
};
use secluso_client_lib::thumbnail_meta_info::ThumbnailMetaInfo;
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
use anyhow::anyhow;
use crate::delivery_monitor::{DeliveryMonitor, VideoInfo};
use crate::motion::{
    prepare_motion_thumbnail, prepare_motion_video,
    upload_pending_enc_thumbnails, upload_pending_enc_videos,
};
use crate::livestream::livestream;
use crate::traits::Camera;
use crate::config::process_config_command;
use crate::notification_target::{send_notification, refresh_notification_target};
use crate::pairing::flow::pair_all;
use crate::pairing::io::{get_names, read_parse_full_credentials};

cfg_if! {
    if #[cfg(feature = "manual")] {
        use crate::manual::ManualCamera;
        use crate::pairing::io::get_input_camera_secret;
    } else if #[cfg(feature = "raspberry")] {
        use crate::raspberry_pi::rpi_camera::RaspberryPiCamera;
        use crate::pairing::wifi::create_wifi_hotspot;
        use crate::pairing::io::get_input_camera_secret;
    } else if #[cfg(feature = "ip")] {
        use crate::ip::ip_camera::IpCamera;
    } else if #[cfg(feature = "android")] {
        use crate::android::android_camera::AndroidCamera;
        use crate::android::android_dual_stream::{
            AndroidCameraSettings, ANDROID_CAMERA_FACING_BACK, ANDROID_CAMERA_FACING_FRONT,
        };
        use std::io::ErrorKind;
        use std::sync::atomic::AtomicBool;
    } else if #[cfg(feature = "test")] {
        use crate::test_camera::TestCamera;
        use std::sync::atomic::AtomicBool;
        use crate::pairing::io::get_input_camera_secret;
    } else {
        compile_error!("One of the features 'manual', 'raspberry', 'ip', 'android', or 'test' must be enabled.");
    }
}

const STATE_DIR_GENERAL: &str = "state";
const VIDEO_DIR_GENERAL: &str = "pending_videos";
const THUMBNAIL_DIR_GENERAL: &str = "pending_thumbnails";

#[cfg(feature = "test")]
const VERSION_DIR: &str = "current_version";
#[cfg(feature = "test")]
const VERSION_FILE: &str = "current_version/raspberry_camera_hub";

#[cfg(not(any(feature = "test", feature = "android")))]
const VERSION_DIR: &str = "/var/lib/secluso/current_version";
#[cfg(not(any(feature = "test", feature = "android")))]
const VERSION_FILE: &str = "/var/lib/secluso/current_version/raspberry_camera_hub";

#[cfg(feature = "android")]
const VERSION_DIR: &str = "current_version";
#[cfg(feature = "android")]
const VERSION_FILE: &str = "current_version/android_camera_hub";

const PRIMARY_APP_ID: usize = 0;
// Technically, we can support an arbitrary number of secondary apps.
// However, it's best to enforce a reasonable upper bound here.
// Each secondary app required dedicated threads and too many of them
// can impact our performance.
// Note: we have a copy of this upper bound in the server too.
const MAX_SECONDARY_APPS: usize = 6;

// A counter representing the amount of active camera threads
static GLOBAL_THREAD_COUNT: AtomicUsize = AtomicUsize::new(0);
#[cfg(any(feature = "android", feature = "test"))]
pub(crate) static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Args {
    pub flag_reset: bool,
    pub flag_reset_full: bool,
    #[cfg(any(feature = "raspberry", feature = "android"))]
    pub flag_save_all: bool,
}

#[cfg(feature = "android")]
#[derive(Clone, Debug)]
pub struct AndroidServerCredentials {
    pub server_username: String,
    pub server_password: String,
    pub server_addr: String,
}

#[cfg(feature = "android")]
static ANDROID_SERVER_CREDENTIALS: std::sync::OnceLock<
    std::sync::Mutex<Option<AndroidServerCredentials>>,
> = std::sync::OnceLock::new();

#[cfg(feature = "android")]
static ANDROID_CAMERA_SETTINGS: std::sync::OnceLock<
    std::sync::Mutex<AndroidCameraSettings>,
> = std::sync::OnceLock::new();

#[cfg(any(feature = "android", feature = "test"))]
#[derive(Clone)]
enum StopWaiter {
    Livestream {
        http_client: HttpClient,
        group_name: String,
    },
    Config {
        http_client: HttpClient,
        group_name: String,
    },
}

#[cfg(any(feature = "android", feature = "test"))]
impl StopWaiter {
    fn stop(&self) {
        // We use long-standing http requests to check for livestream
        // and config requests. In order to gracefully stop the camera hub,
        // we issue dummy livestream and config requests here causing those
        // threads to come back, at which point they exit since they notice
        // the stop request.
        let result = match self {
            Self::Livestream {
                http_client,
                group_name,
            } => http_client.livestream_start(group_name),
            Self::Config {
                http_client,
                group_name,
            } => http_client.config_command(group_name, vec![0]),
        };

        if let Err(e) = result {
            error!("Failed to stop Android camera worker: {e}");
        }
    }
}

#[cfg(any(feature = "android", feature = "test"))]
static STOP_WAITERS: std::sync::OnceLock<
    std::sync::Mutex<Vec<StopWaiter>>,
> = std::sync::OnceLock::new();

#[cfg(any(feature = "android", feature = "test"))]
fn register_stop_waiter(waiter: StopWaiter) {
    let mut waiters = STOP_WAITERS
        .get_or_init(|| std::sync::Mutex::new(vec![]))
        .lock()
        .unwrap();

    if STOP_REQUESTED.load(Ordering::SeqCst) {
        drop(waiters);
        waiter.stop();
    } else {
        waiters.push(waiter);
    }
}

#[cfg(any(feature = "android", feature = "test"))]
pub fn request_stop() {
    STOP_REQUESTED.store(true, Ordering::SeqCst);

    let waiters = STOP_WAITERS
        .get_or_init(|| std::sync::Mutex::new(vec![]))
        .lock()
        .unwrap()
        .clone();

    for waiter in waiters {
        waiter.stop();
    }
}

#[cfg(any(feature = "android", feature = "test"))]
fn clear_stop_signal() {
    STOP_REQUESTED.store(false, Ordering::SeqCst);
    STOP_WAITERS
        .get_or_init(|| std::sync::Mutex::new(vec![]))
        .lock()
        .unwrap()
        .clear();
}

#[cfg(feature = "android")]
pub fn set_android_server_credentials(
    server_username: String,
    server_password: String,
    server_addr: String,
) -> io::Result<()> {
    if server_username.trim().is_empty() {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "Server username is empty",
        ));
    }
    if server_password.is_empty() {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "Server password is empty",
        ));
    }
    if server_addr.trim().is_empty() {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "Server address is empty",
        ));
    }

    let lock = ANDROID_SERVER_CREDENTIALS
        .get_or_init(|| std::sync::Mutex::new(None));

    *lock.lock().unwrap() = Some(AndroidServerCredentials {
        server_username,
        server_password,
        server_addr,
    });

    Ok(())
}

#[cfg(feature = "android")]
pub fn set_android_camera_settings_core(settings: AndroidCameraSettings) -> io::Result<()> {
    if settings.facing != ANDROID_CAMERA_FACING_BACK
        && settings.facing != ANDROID_CAMERA_FACING_FRONT
    {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "Error: Android camera facing must be front or back",
        ));
    }
    
    if settings.width == 0 || settings.height == 0 {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "Error: Android camera resolution must be non-zero",
        ));
    }

    if settings.width > i32::MAX as usize
        || settings.height > i32::MAX as usize
    {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "Error: Invalid Android camera resolution",
        ));
    }

    if settings.frame_rate_range.min <= 0
        || settings.frame_rate_range.max <= 0
        || settings.frame_rate_range.min > settings.frame_rate_range.max
    {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "Error: Android camera frame rate range must be positive and ordered",
        ));
    }

    let lock = ANDROID_CAMERA_SETTINGS
        .get_or_init(|| std::sync::Mutex::new(AndroidCameraSettings::default()));
    *lock.lock().unwrap() = settings;

    Ok(())
}

#[cfg(feature = "android")]
fn get_android_camera_settings() -> AndroidCameraSettings {
    ANDROID_CAMERA_SETTINGS
        .get_or_init(|| std::sync::Mutex::new(AndroidCameraSettings::default()))
        .lock()
        .unwrap()
        .clone()
}

pub(crate) fn get_server_credentials() -> (String, String, String) {
    #[cfg(feature = "android")]
    {
        if let Some(creds) = ANDROID_SERVER_CREDENTIALS
            .get_or_init(|| std::sync::Mutex::new(None))
            .lock()
            .unwrap()
            .clone()
        {
            log::info!("Using Android-provided server credentials");
            return (
                creds.server_username,
                creds.server_password,
                creds.server_addr,
            );
        }

        log::warn!(
            "Android server credentials were not provided; falling back to credentials_full"
        );
    }

    read_parse_full_credentials()
}

pub(crate) fn run(args: Args) -> io::Result<()> {
    log::info!("Started run()");
    // Create the general outer directories (where we'll have inner directories representing each camera)
    fs::create_dir_all(STATE_DIR_GENERAL)?;
    fs::create_dir_all(VIDEO_DIR_GENERAL)?;
    fs::create_dir_all(THUMBNAIL_DIR_GENERAL)?;

    // Write the updater's component-scoped version marker
    fs::create_dir_all(VERSION_DIR)?;
    fs::write(VERSION_FILE, format!("v{}\n", env!("CARGO_PKG_VERSION")))?;

    #[cfg(any(feature = "android", feature = "test"))]
    clear_stop_signal();

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
        } else if #[cfg(feature = "android")] {
            log::info!("About to call AndroidCamera::new()");
            let android_camera_settings = get_android_camera_settings();
            let camera = AndroidCamera::new(
                "Android".to_string(),
                STATE_DIR_GENERAL.to_string(),
                VIDEO_DIR_GENERAL.to_string(),
                THUMBNAIL_DIR_GENERAL.to_string(),
                1,
                args.flag_save_all,
                android_camera_settings,
            );
            log::info!("Finished calling AndroidCamera::new()");

            let camera_list: Vec<Box<dyn Camera + Send>> = vec![Box::new(camera)];
            let input_camera_secret: Option<Vec<u8>> = None;
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
            let result = if args.flag_reset || args.flag_reset_full {
                reset(camera.as_ref(), args.flag_reset_full)
            } else {
                core(
                    camera.as_mut(),
                    input_camera_secret.clone(),
                )
            };

            // We need to close the native camera in Android.
            #[cfg(feature = "android")]
            drop(camera);

            // Deduct one from our thread count for main thread to know when to exit
            // (when all are finished).
            GLOBAL_THREAD_COUNT.fetch_sub(1, Ordering::SeqCst);

            if let Err(e) = result {
                panic!("camera thread returned with: {e}");
            }
        });
    }

    // Terminate when no cameras are left running
    while GLOBAL_THREAD_COUNT.load(Ordering::SeqCst) != 0 {
        sleep(Duration::from_millis(1));
    }

    Ok(())
}

fn reset(camera: &dyn Camera, reset_full: bool) -> anyhow::Result<()> {
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
            &camera.get_state_dir(),
            first_time,
            format!("camera_{}_name", tag),
            format!("group_{}_name", tag),
        )?;

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
        let (server_username, server_password, server_addr) = get_server_credentials();
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

pub fn initialize_mls_clients(camera: &dyn Camera, first_time: bool) -> anyhow::Result<MlsClients> {
    let mut clients = Vec::with_capacity(MLS_CLIENT_TAGS.len());
    for client_tag in MLS_CLIENT_TAGS {
        let (camera_name, group_name) = get_names(
            &camera.get_state_dir(),
            first_time,
            format!("camera_{}_name", client_tag),
            format!("group_{}_name", client_tag),
        )?;
        debug!("{} camera_name = {}", client_tag, camera_name);
        debug!("{} group_name = {}", client_tag, group_name);

        let mut mls_client = MlsClient::new(
            camera_name,
            first_time,
            camera.get_state_dir(),
            client_tag.to_string(),
            ClientType::Camera,
        )
            .expect("MlsClient::new() for returned error.");

        if first_time {
            mls_client.create_group(&group_name)?;
            debug!("Created group.");
        }

        mls_client.save_group_state()?;
        clients.push(mls_client);
    }

    clients.try_into().map_err(|_| anyhow!("Failed to convert clients vec to MlsClients"))
}

fn split_clients(clients: MlsClients) -> (MlsClientsCommon, MlsClientsDedicated) {
    let [c0, c1, c2, d0, d1] = clients;
    ([c0, c1, c2], [d0, d1])
}

fn spawn_dedicated_check_threads(
    app_id: usize,
    clients_ded: &MlsClientsDedicated,
    http_client: &HttpClient,
    livestream_requests: Arc<Mutex<Vec<usize>>>,
    config_enc_commands: Arc<Mutex<Vec<(Vec<u8>, usize)>>>,
    worker_handles: &mut Vec<std::thread::JoinHandle<()>>,
) -> anyhow::Result<()> {
    let group_livestream_name = clients_ded[LIVESTREAM_DED].get_group_name()?;
    let group_config_name = clients_ded[CONFIG_DED].get_group_name()?;

    #[cfg(any(feature = "android", feature = "test"))]
    {
        register_stop_waiter(StopWaiter::Livestream {
            http_client: http_client.clone(),
            group_name: group_livestream_name.clone(),
        });
        register_stop_waiter(StopWaiter::Config {
            http_client: http_client.clone(),
            group_name: group_config_name.clone(),
        });
    }

    let http_client_livestream = http_client.clone();

    worker_handles.push(thread::spawn(move || loop {
        if http_client_livestream
            .livestream_check(&group_livestream_name)
            .is_ok()
        {
            #[cfg(any(feature = "android", feature = "test"))]
            if STOP_REQUESTED.load(Ordering::SeqCst) {
                break;
            }

            println!("Livestream{} detected", app_id + 1);
            let mut requests = livestream_requests.lock().unwrap();
            requests.push(app_id);
        } else {
            #[cfg(any(feature = "android", feature = "test"))]
            if STOP_REQUESTED.load(Ordering::SeqCst) {
                break;
            }

            sleep(Duration::from_secs(1));
        }
    }));

    let http_client_config = http_client.clone();

    worker_handles.push(thread::spawn(move || loop {
        if let Ok(enc_command) = http_client_config.config_check(&group_config_name) {
            #[cfg(any(feature = "android", feature = "test"))]
            if STOP_REQUESTED.load(Ordering::SeqCst) {
                break;
            }

            let mut config_enc_commands = config_enc_commands.lock().unwrap();
            config_enc_commands.push((enc_command, app_id));
        } else {
            #[cfg(any(feature = "android", feature = "test"))]
            if STOP_REQUESTED.load(Ordering::SeqCst) {
                break;
            }

            error!("Error in receiving config command");
            sleep(Duration::from_secs(1));
        }
    }));

    Ok(())
}

fn core(
    camera: &mut dyn Camera,
    input_camera_secret: Option<Vec<u8>>,
) -> anyhow::Result<()> {
    let state_dir = camera.get_state_dir();
    let first_time: bool = !Path::new(&(state_dir.clone() + "/first_time_done")).exists();

    #[cfg(feature = "raspberry")]
    if first_time {
        println!("Creating WiFi hotspot.");
        create_wifi_hotspot();
    }

    let mut clients: MlsClients = initialize_mls_clients(camera, first_time)?;

    let camera_name = camera.get_name();

    if first_time {
        println!(
            "[{}] Waiting to be paired with the mobile app.",
            camera_name
        );
        pair_all(camera, &mut clients, input_camera_secret)?;

        File::create(camera.get_state_dir() + "/first_time_done").expect("Could not create file");

        println!("[{}] Pairing successful.", camera_name);
    }

    let (mut clients_com, mut clients_ded_primary) = split_clients(clients);

    println!("[{}] Running...", camera_name);

    let (server_username, server_password, server_addr) = get_server_credentials();
    let http_client = HttpClient::new(server_addr, server_username, server_password);

    let mut locked_motion_check_time: Option<Instant> = None;
    let mut locked_delivery_check_time: Option<Instant> = None;
    let mut locked_livestream_check_time: Option<Instant> = None;
    let mut locked_config_check_time: Option<Instant> = None;
    let video_dir = camera.get_video_dir();
    let thumbnail_dir = camera.get_thumbnail_dir();
    let mut delivery_monitor =
        DeliveryMonitor::from_file_or_new(video_dir, thumbnail_dir, state_dir.clone());
    let livestream_requests: Arc<Mutex<Vec<usize>>> = Arc::new(Mutex::new(vec![]));
    let config_enc_commands: Arc<Mutex<Vec<(Vec<u8>, usize)>>> = Arc::new(Mutex::new(vec![]));
    let mut clients_ded_secondary: Vec<MlsClientsDedicated> = Vec::new();

    let mut worker_handles = vec![];

    spawn_dedicated_check_threads(
        PRIMARY_APP_ID,
        &clients_ded_primary,
        &http_client,
        Arc::clone(&livestream_requests),
        Arc::clone(&config_enc_commands),
        &mut worker_handles,
    )?;

    #[cfg(feature = "test")]
    let mut num_iters = 0usize;

    // Used for anti-dither for motion detection
    loop {
        #[cfg(any(feature = "android", feature = "test"))]
        if STOP_REQUESTED.load(Ordering::SeqCst) {
            break;
        }

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

            let num_apps = 1 + clients_ded_secondary.len();

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
                refresh_notification_target(state_dir_ref, &http_client);
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
            let requested_app_ids = {
                let mut requests = livestream_requests.lock().unwrap();
                std::mem::take(&mut *requests)
            };

            for app_id in requested_app_ids {
                info!("Livestream start detected");
                if app_id == PRIMARY_APP_ID {
                    livestream(
                        &mut clients_ded_primary[LIVESTREAM_DED],
                        camera,
                        &mut delivery_monitor,
                        &http_client,
                    )?;
                } else if let Some(clients_ded_sec) = clients_ded_secondary.get_mut(app_id - 1) {
                    livestream(
                        &mut clients_ded_sec[LIVESTREAM_DED],
                        camera,
                        // FIXME: delivery_monitor should use a separate queue for secondary apps
                        &mut delivery_monitor,
                        &http_client,
                    )?;
                }
            }

            locked_livestream_check_time = Some(Instant::now().add(Duration::from_millis(100)));
        }

        // Check with the delivery monitor every minute
        if locked_delivery_check_time.is_none()
            || locked_delivery_check_time.unwrap().le(&Instant::now())
        {
            let num_apps = 1 + clients_ded_secondary.len();

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
            let enc_commands_to_process = {
                let mut enc_commands = config_enc_commands.lock().unwrap();
                std::mem::take(&mut *enc_commands)
            };

            for (enc_command, app_id) in enc_commands_to_process {
                if app_id == PRIMARY_APP_ID {
                    println!("About to call process_config_command for primary app");
                    let secondary_app_limit_reached =
                        clients_ded_secondary.len() >= MAX_SECONDARY_APPS;
                    let next_secondary_app_number = clients_ded_secondary.len() + 2;
                    let process_ret = process_config_command(
                        &mut clients_com,
                        &mut clients_ded_primary,
                        &enc_command,
                        &http_client,
                        // TODO: We only keep track of video delivery to the primary app for now.
                        Some(&mut delivery_monitor),
                        true,
                        secondary_app_limit_reached,
                        Some(next_secondary_app_number),
                        Some(&mut clients_ded_secondary),
                    )?;

                    if let Some(clients_ded_sec) = process_ret {
                        let app_id = clients_ded_secondary.len() + 1;
                        println!("Launching threads for app {}.", app_id + 1);
                        spawn_dedicated_check_threads(
                            app_id,
                            &clients_ded_sec,
                            &http_client,
                            Arc::clone(&livestream_requests),
                            Arc::clone(&config_enc_commands),
                            &mut worker_handles,
                        )?;
                        clients_ded_secondary.push(clients_ded_sec);
                    }
                } else if let Some(clients_ded_sec) = clients_ded_secondary.get_mut(app_id - 1) {
                    println!("About to call process_config_command for secondary app");
                    let _ = process_config_command(
                        &mut clients_com,
                        clients_ded_sec,
                        &enc_command,
                        &http_client,
                        None,
                        false,
                        true,
                        None,
                        None,
                    )?;
                } else {
                    error!("Ignoring config command for unknown app id {}", app_id);
                }
            }
            locked_config_check_time = Some(Instant::now().add(Duration::from_secs(1)));
        }

        // Introduce a small delay since we don't need this constantly checked
        sleep(Duration::from_millis(100));

        #[cfg(feature = "test")]
        {
            num_iters += 1;
            if num_iters > 5000 {
                println!("Terminating...");
                request_stop();
            }
        }
    }

    #[cfg(any(feature = "android", feature = "test"))]
    {
        log::info!("Stop requested; waiting for camera hub workers");
        for handle in worker_handles {
            let _ = handle.join();
        }

        Ok(())
    }
}
