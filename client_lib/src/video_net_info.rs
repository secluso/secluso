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

#[derive(Serialize, Deserialize, PartialEq)]
pub struct VideoAckInfo {
    pub timestamp: u64,
    pub video_ack: bool, //true if ack for video, false if ack for notification
}

impl VideoAckInfo {
    pub fn new(timestamp: u64, video_ack: bool) -> Self {
        Self {
            timestamp,
            video_ack,
        }
    }
}
