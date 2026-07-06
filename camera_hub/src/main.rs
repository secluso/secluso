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

use cfg_if::cfg_if;
cfg_if! {
    if #[cfg(feature = "manual")] {
        mod manual;
    } else if #[cfg(feature = "raspberry")] {
        mod mp4;
        mod fmp4;
        mod raspberry_pi;
    } else if #[cfg(feature = "ip")] {
        mod mp4;
        mod fmp4;
        mod ip;
    } else if #[cfg(feature = "test")] {
        mod test_camera;
    } else {
        compile_error!("One of the features 'manual', 'raspberry', 'ip', or 'test' must be enabled.");
    }
}

 use docopt::Docopt;
 use std::io;
 use crate::core::{run, Args};

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

fn main() -> io::Result<()> {
    let version = env!("CARGO_PKG_NAME").to_string() + ", version: " + env!("CARGO_PKG_VERSION");
    env_logger::init();

    let args: Args = Docopt::new(USAGE)
        .map(|d| d.help(true))
        .map(|d| d.version(Some(version)))
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    run(args)
}