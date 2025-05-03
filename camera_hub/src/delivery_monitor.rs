//! Camera hub delivery monitor
//! Sends notifications and resends videos until it receives ack(s).
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

use privastead_client_lib::user::User;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize, Clone)]
pub struct VideoInfo {
    pub timestamp: u64,
    pub filename: String,
    pub epoch: u64,
}

impl VideoInfo {
    pub fn new() -> Self {
        let now = DeliveryMonitor::now();

        Self {
            timestamp: now,
            filename: Self::get_filename_from_timestamp(now),
            epoch: 0,
        }
    }

    pub fn get_filename_from_timestamp(timestamp: u64) -> String {
        "video_".to_owned() + &timestamp.to_string() + ".mp4"
    }
}

#[derive(Serialize, Deserialize)]
pub struct DeliveryMonitor {
    watch_list: HashMap<u64, VideoInfo>, //<video timestamp, video info>
    video_dir: String,
    state_dir: String,
}

impl DeliveryMonitor {
    pub fn from_file_or_new(video_dir: String, state_dir: String) -> Self {
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
            video_dir,
            state_dir,
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

    pub fn enqueue_video(&mut self, video_info: VideoInfo) {
        info!("enqueue_event: {}", video_info.timestamp);
        let _ = self.watch_list.insert(video_info.timestamp, video_info);

        self.save_state();
    }

    pub fn dequeue_video(&mut self, video_info: &VideoInfo) {
        info!("dequeue_event: {}", video_info.timestamp);

        let _ = self.watch_list.remove(&video_info.timestamp);
        let _ = fs::remove_file(self.get_video_file_path(video_info));
        let _ = fs::remove_file(self.get_enc_video_file_path(video_info));

        self.save_state();
    }

    pub fn videos_to_send(&self) -> Vec<VideoInfo> {
        let mut send_list: Vec<VideoInfo> = Vec::new();

        for info in self.watch_list.values() {
            send_list.push(info.clone());
        }

        send_list.sort_by_key(|key| key.timestamp);

        send_list
    }

    pub fn get_video_file_path(&self, info: &VideoInfo) -> PathBuf {
        let video_dir_path = Path::new(&self.video_dir);
        video_dir_path.join(&info.filename)
    }

    pub fn get_enc_video_file_path(&self, info: &VideoInfo) -> PathBuf {
        let video_dir_path = Path::new(&self.video_dir);
        let enc_filename = format!("{}", info.epoch);
        video_dir_path.join(&enc_filename)
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
