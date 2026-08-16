//! SPDX-License-Identifier: GPL-3.0-or-later

//! The subscription a camera works under.
use std::fs;
use std::io;
use std::path::Path;

/// File the uuid is persisted under, next to the object secret.
pub const SUBSCRIPTION_UUID_FILE: &str = "subscription_uuid";

pub fn save_subscription_uuid(dir: &Path, uuid: &str) -> io::Result<()> {
    if uuid.is_empty() {
        return Err(io::Error::other("Subscription uuid is empty".to_string()));
    }

    fs::write(dir.join(SUBSCRIPTION_UUID_FILE), uuid)
}

pub fn load_subscription_uuid(dir: &Path) -> io::Result<String> {
    let uuid = fs::read_to_string(dir.join(SUBSCRIPTION_UUID_FILE))?;
    let uuid = uuid.trim().to_string();

    if uuid.is_empty() {
        return Err(io::Error::other(
            "Stored subscription uuid is empty".to_string(),
        ));
    }

    Ok(uuid)
}
