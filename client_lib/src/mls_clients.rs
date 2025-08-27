//! Privastead list of MLS clients/users
//!
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

use crate::mls_client::MlsClient;

pub const NUM_MLS_CLIENTS: usize = 5;
pub static MLS_CLIENT_TAGS: [&str; NUM_MLS_CLIENTS] = [
    "motion",
    "livestream",
    "fcm",
    "config",
    "thumbnail",
];

// indices for different clients
pub const MOTION: usize = 0;
pub const LIVESTREAM: usize = 1;
pub const FCM: usize = 2;
pub const CONFIG: usize = 3;
pub const THUMBNAIL: usize = 4;

pub type MlsClients = [MlsClient; NUM_MLS_CLIENTS];

// Maximum time that we allow other group members to be offline (in seconds)
pub const MAX_OFFLINE_WINDOW: u64 = 24 * 60 * 60;