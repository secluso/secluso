//! Camera hub version metadata.
//!
//! SPDX-License-Identifier: GPL-3.0-or-later

use secluso_client_lib::config::CameraVersionInfo;
use std::fs;
use std::io;

const OS_VERSION_PATH: &str = "/etc/secluso-os-version";

pub fn camera_version_info() -> io::Result<CameraVersionInfo> {
    let raw = fs::read_to_string(OS_VERSION_PATH)?;
    let os_version = raw
        .trim()
        .parse::<u64>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    Ok(CameraVersionInfo {
        firmware_version: format!("v{}", env!("CARGO_PKG_VERSION")),
        os_version,
    })
}
