//! Camera hub delivery monitor
//! Sends notifications and resends videos until it receives ack(s).
//!
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

use privastead_client_lib::user::User;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize, Clone)]
pub struct VideoInfo {
    pub timestamp: u64,
    pub filename: String,
    last_send_timestamp: Option<u64>,
    last_notify_timestamp: Option<u64>,
}

impl VideoInfo {
    pub fn new() -> Self {
        let now = DeliveryMonitor::now();
        Self {
            timestamp: now,
            filename: Self::get_filename_from_timestamp(now),
            last_send_timestamp: None,
            last_notify_timestamp: None,
        }
    }

    pub fn get_filename_from_timestamp(timestamp: u64) -> String {
        "video_".to_owned() + &timestamp.to_string() + ".mp4"
    }
}

#[derive(Serialize, Deserialize)]
pub struct DeliveryMonitor {
    watch_list: HashMap<u64, VideoInfo>, //<video timestamp, video info>
    last_ack_timestamp: Option<u64>,
    video_dir: String,
    state_dir: String,
    renotify_threshold: u64,
}

impl DeliveryMonitor {
    pub fn from_file_or_new(video_dir: String, state_dir: String, renotify_threshold: u64) -> Self {
        let d_files = User::get_state_files_sorted(&state_dir, "delivery_monitor_").unwrap();
        for f in &d_files {
            let pathname = state_dir.clone() + "/" + f;
            let file = fs::File::open(pathname).expect("Could not open file");
            let mut reader =
                BufReader::with_capacity(file.metadata().unwrap().len().try_into().unwrap(), file);
            let data = reader.fill_buf().unwrap();
            let deserialize_result = bincode::deserialize(data);
            if let Ok(deserialized_data) = deserialize_result {
                return deserialized_data;
            }
        }

        Self {
            watch_list: HashMap::new(),
            last_ack_timestamp: None,
            video_dir,
            state_dir,
            renotify_threshold,
        }
    }

    /// See the notes for save_groups_state() in client_lib/src/user.rs
    /// about the algorithm used to determine file names.
    pub fn save_state(&self) {
        let current_timestamp = Self::now_in_nanos();
        let data = bincode::serialize(&self).unwrap();

        let pathname =
            self.state_dir.clone() + "/delivery_monitor_" + &current_timestamp.to_string();
        let mut file = fs::File::create(pathname).expect("Could not create file");
        file.write_all(&data).unwrap();
        file.flush().unwrap();
        file.sync_all().unwrap();

        //delete old state files
        let d_files = User::get_state_files_sorted(&self.state_dir, "delivery_monitor_").unwrap();
        assert!(d_files[0] == "delivery_monitor_".to_owned() + &current_timestamp.to_string());
        for f in &d_files[1..] {
            let _ = fs::remove_file(self.state_dir.clone() + "/" + f);
        }
    }

    pub fn send_event(&mut self, mut video_info: VideoInfo) {
        info!("send_event: {}", video_info.timestamp);
        let now = Self::now();
        // Sending a video also sends a notification.
        video_info.last_send_timestamp = Some(now);
        video_info.last_notify_timestamp = Some(now);

        // First send: add to watch list.
        // Resend: update the watch list.
        let _ = self.watch_list.insert(video_info.timestamp, video_info);

        self.save_state();
    }

    pub fn ack_event(&mut self, video_timestamp: u64, video_ack: bool) {
        info!("ack_event: {}, {}", video_timestamp, video_ack);
        self.last_ack_timestamp = Some(Self::now());

        if video_ack {
            let _ = self.watch_list.remove(&video_timestamp);
            let _ = fs::remove_file(
                self.video_dir.clone()
                    + "/"
                    + &VideoInfo::get_filename_from_timestamp(video_timestamp),
            );
        }

        self.save_state();
    }

    pub fn notify_event(&mut self, mut video_info: VideoInfo) {
        info!("notify_event: {}", video_info.timestamp);
        let now = Self::now();
        video_info.last_notify_timestamp = Some(now);

        match self.watch_list.get(&video_info.timestamp) {
            Some(_) => {}
            None => {
                // Should not happen!
                log::debug!("notify_event for video not in the watch list!");
                let _ = self.watch_list.insert(video_info.timestamp, video_info);
            }
        }

        self.save_state();
    }

    pub fn videos_to_resend_renotify(&self) -> (Vec<VideoInfo>, Vec<VideoInfo>) {
        let mut resend_list: Vec<VideoInfo> = Vec::new();
        let mut renotify_list: Vec<VideoInfo> = Vec::new();
        let now = Self::now();
        for info in self.watch_list.values() {
            if self.last_ack_timestamp.is_some()
                && info.last_send_timestamp.is_some()
                && info.last_send_timestamp.unwrap() < self.last_ack_timestamp.unwrap()
            {
                resend_list.push(info.clone());
                info!("adding to resend list: {}", info.timestamp);
            } else if info.last_notify_timestamp.is_some()
                && now - info.last_notify_timestamp.unwrap() > self.renotify_threshold
            {
                renotify_list.push(info.clone());
                info!("adding to renotify list: {}", info.timestamp);
            }
        }

        resend_list.sort_by_key(|key| key.timestamp);
        renotify_list.sort_by_key(|key| key.timestamp);

        (resend_list, renotify_list)
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Could not convert time")
            .as_secs()
    }

    fn now_in_nanos() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Could not convert time")
            .as_nanos()
    }
}

#[test]
fn resend_once() {
    use std::{thread, time::Duration};

    let mut dm = DeliveryMonitor::new("test_dir".to_string(), 1);
    let info = VideoInfo::new();
    let timestamp = info.timestamp;

    dm.send_event(info.clone());
    thread::sleep(Duration::from_secs(2));

    let (resend_list, renotify_list) = dm.videos_to_resend_renotify();
    assert!(!renotify_list.is_empty());
    assert!(resend_list.is_empty());

    dm.notify_event(info.clone());
    let (resend_list, renotify_list) = dm.videos_to_resend_renotify();
    assert!(!renotify_list.is_empty());
    assert!(resend_list.is_empty());

    dm.ack_event(timestamp, false);
    let (resend_list, renotify_list) = dm.videos_to_resend_renotify();
    assert!(renotify_list.is_empty());
    assert!(!resend_list.is_empty());

    dm.send_event(info.clone());
    let (resend_list, renotify_list) = dm.videos_to_resend_renotify();
    assert!(renotify_list.is_empty());
    assert!(resend_list.is_empty());

    thread::sleep(Duration::from_secs(2));
    let (resend_list, renotify_list) = dm.videos_to_resend_renotify();
    assert!(!renotify_list.is_empty());
    assert!(resend_list.is_empty());

    dm.ack_event(timestamp, true);
    let (resend_list, renotify_list) = dm.videos_to_resend_renotify();
    assert!(renotify_list.is_empty());
    assert!(resend_list.is_empty());
}
