//! Camera notification messages
//!
//! SPDX-License-Identifier: GPL-3.0-or-later

use serde::{Deserialize, Serialize};
use std::io;

pub const NOTIFICATION_VERSION: &str = "v1";

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Notification {
    NewVideo(u64),
    Download,
    NewInfo,
}

#[derive(Deserialize, Serialize)]
enum NotificationType {
    NewVideo,
    Download,
    NewInfo,
}

#[derive(Deserialize, Serialize)]
struct VersionedNotification {
    #[serde(rename = "v", alias = "version")]
    version: String,

    #[serde(rename = "t", alias = "notification_type")]
    notification_type: NotificationType,

    #[serde(rename = "ts", alias = "timestamp")]
    timestamp: Option<u64>,
}

pub fn generate_notification(notification: Notification) -> io::Result<Vec<u8>> {
    let (notification_type, timestamp) = match notification {
        Notification::NewVideo(timestamp) => (NotificationType::NewVideo, Some(timestamp)),
        Notification::Download => (NotificationType::Download, None),
        Notification::NewInfo => (NotificationType::NewInfo, None),
    };
    let notification = VersionedNotification {
        version: NOTIFICATION_VERSION.to_string(),
        notification_type,
        timestamp,
    };

    serde_json::to_vec(&notification)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

pub fn decode_notification(message: &[u8]) -> io::Result<Notification> {
    if let Ok(notification) = serde_json::from_slice::<VersionedNotification>(message) {
        if notification.version != NOTIFICATION_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported notification version",
            ));
        }

        return match (notification.notification_type, notification.timestamp) {
            (NotificationType::NewVideo, Some(timestamp)) => Ok(Notification::NewVideo(timestamp)),
            (NotificationType::Download, None) => Ok(Notification::Download),
            (NotificationType::NewInfo, None) => Ok(Notification::NewInfo),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid notification parameters",
            )),
        };
    }

    // Valid JSON that is not a supported notification must not be interpreted
    // as a legacy timestamp, even when its encoded length happens to be eight
    // bytes.
    if serde_json::from_slice::<serde_json::Value>(message).is_ok() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid JSON notification",
        ));
    }

    // Legacy notifications were bincode-serialized u64 values. Zero requested a
    // download, while every other value was a new-video timestamp.
    if message.len() == size_of::<u64>() {
        let timestamp = u64::from_le_bytes(message.try_into().unwrap());
        return if timestamp == 0 {
            Ok(Notification::Download)
        } else {
            Ok(Notification::NewVideo(timestamp))
        };
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid notification message",
    ))
}