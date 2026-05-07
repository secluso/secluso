//! Camera hub version metadata.
//!
//! SPDX-License-Identifier: GPL-3.0-or-later

use secluso_client_lib::config::CameraVersionInfo;
use std::fs;
use std::io;

const OS_VERSION_PATH: &str = "/etc/secluso-os-version";
const UNKNOWN_OS_VERSION: &str = "0.0.0";

pub fn camera_version_info() -> io::Result<CameraVersionInfo> {
    let os_version = match fs::read_to_string(OS_VERSION_PATH) {
        Ok(raw) => {
            let version = raw.trim();
            if version.is_empty() {
                UNKNOWN_OS_VERSION.to_string()
            } else {
                version.to_string()
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => UNKNOWN_OS_VERSION.to_string(),
        Err(e) => return Err(e),
    };

    Ok(CameraVersionInfo {
        firmware_version: format!("v{}", env!("CARGO_PKG_VERSION")),
        os_version,
    })
}
