//! SPDX-License-Identifier: GPL-3.0-or-later

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct VideoNetInfo {
    pub timestamp: u64,
    // num_msg = 0 is used for notification purposes.
    pub num_msg: u64,
    pub sanity: String,
}

pub const VIDEONETINFO_SANITY: &str = "deadbeef";

impl VideoNetInfo {
    pub fn new(timestamp: u64, video_size: u64, read_size: u64) -> Self {
        Self {
            timestamp,
            num_msg: (video_size / read_size) + 1,
            sanity: VIDEONETINFO_SANITY.to_string(),
        }
    }

    pub fn new_notification(timestamp: u64) -> Self {
        Self {
            timestamp,
            num_msg: 0,
            sanity: VIDEONETINFO_SANITY.to_string(),
        }
    }
}
