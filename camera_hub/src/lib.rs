use cfg_if::cfg_if;
cfg_if! {
    if #[cfg(feature = "android")] {
        #[macro_use]
        extern crate log;

        #[macro_use]
        extern crate serde_derive;

        mod core;
        mod delivery_monitor;
        mod motion;
        mod livestream;
        mod traits;
        mod pairing;
        mod config;
        mod version;
        mod notification_target;
        mod mp4;
        mod android;
        use crate::android::android_dual_stream::get_available_specs;
        use crate::core::{
            request_stop, run, set_android_camera_settings_core,
            set_android_server_credentials, Args,
        };

        use std::io;
    }
}

#[cfg(feature = "android")]
pub use crate::android::android_dual_stream::{
    AndroidCameraFrameRateRange, AndroidCameraResolution, AndroidCameraSettings,
    AndroidCameraSpec, ANDROID_CAMERA_FACING_BACK, ANDROID_CAMERA_FACING_FRONT,
};

#[cfg(feature = "android")]
pub fn get_android_camera_specs() -> anyhow::Result<Vec<AndroidCameraSpec>> {
    get_available_specs()
}

#[cfg(feature = "android")]
pub fn set_android_camera_settings(settings: AndroidCameraSettings) -> io::Result<()> {
    set_android_camera_settings_core(settings)
}

#[cfg(feature = "android")]
pub fn run_android(
    server_username: String,
    server_password: String,
    server_addr: String,
) -> io::Result<()> {
    log::info!("Reached run_android()");
    set_android_server_credentials(server_username, server_password, server_addr)?;

    let args = Args {
        flag_reset: false,
        flag_reset_full: false,
        flag_save_all: false,
    };

    run(args)
}

#[cfg(feature = "android")]
pub fn stop_android() {
    log::info!("Reached stop_android()");
    request_stop();
}

#[cfg(feature = "android")]
pub fn reset_android(
    server_username: String,
    server_password: String,
    server_addr: String,
) -> io::Result<()> {
    log::info!("Reached reset_android()");
    set_android_server_credentials(server_username, server_password, server_addr)?;

    let args = Args {
        flag_reset: false,
        flag_reset_full: true,
        flag_save_all: false,
    };

    run(args)
}
