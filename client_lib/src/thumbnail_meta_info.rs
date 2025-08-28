//! Copyright (C) 2025  Ardalan Amiri Sani
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

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum GeneralDetectionType {
    Human,
    Pet,
    Car,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ThumbnailMetaInfo {
    pub timestamp: u64,
    pub detections: Vec<GeneralDetectionType>,
    pub sanity: String,
    pub epoch: u64,
    pub filename: String,
}

pub const THUMBNAIL_SANITY: &str = "thumbbeef";

impl ThumbnailMetaInfo {
    pub fn new(timestamp: u64, thumbnail_epoch: u64, detections: Vec<GeneralDetectionType>) -> Self {
        Self {
            timestamp, // Matches video ts
            detections,
            sanity: THUMBNAIL_SANITY.to_string(),
            epoch: thumbnail_epoch,
            filename: Self::get_filename_from_timestamp(timestamp),
        }
    }

    pub fn get_filename_from_timestamp(timestamp: u64) -> String {
        "thumbnail_".to_owned() + &timestamp.to_string() + ".png"
    }
}
