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
        mod fmp4;
        mod android;
        use crate::core::{run, set_android_server_credentials, Args};
    }
}

#[cfg(feature = "android")]
pub fn run_android(
    server_username: String,
    server_password: String,
    server_addr: String,
) -> std::io::Result<()> {
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
pub fn reset_android(
    server_username: String,
    server_password: String,
    server_addr: String,
) -> std::io::Result<()> {
    log::info!("Reached reset_android()");
    set_android_server_credentials(server_username, server_password, server_addr)?;

    let args = Args {
        flag_reset: false,
        flag_reset_full: true,
        flag_save_all: false,
    };

    run(args)
}