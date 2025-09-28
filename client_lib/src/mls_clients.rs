//! Secluso list of MLS clients/users
//!
//! SPDX-License-Identifier: GPL-3.0-or-later

use crate::mls_client::MlsClient;

pub const NUM_MLS_CLIENTS: usize = 5;
pub static MLS_CLIENT_TAGS: [&str; NUM_MLS_CLIENTS] =
    ["motion", "livestream", "fcm", "config", "thumbnail"];

// indices for different clients
pub const MOTION: usize = 0;
pub const LIVESTREAM: usize = 1;
pub const FCM: usize = 2;
pub const CONFIG: usize = 3;
pub const THUMBNAIL: usize = 4;

pub type MlsClients = [MlsClient; NUM_MLS_CLIENTS];

// Maximum time that we allow other group members to be offline (in seconds)
pub const MAX_OFFLINE_WINDOW: u64 = 24 * 60 * 60;
