//! SPDX-License-Identifier: GPL-3.0-or-later

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
    pub fn new(
        timestamp: u64,
        thumbnail_epoch: u64,
        detections: Vec<GeneralDetectionType>,
    ) -> Self {
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
