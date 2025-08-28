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

use privastead_client_lib::mls_client::MlsClient;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use privastead_client_lib::thumbnail_meta_info::{ThumbnailMetaInfo};

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

    pub fn from(timestamp: u64) -> Self {
        Self {
            timestamp,
            filename: Self::get_filename_from_timestamp(timestamp),
            epoch: 0,
        }
    }

    pub fn get_filename_from_timestamp(timestamp: u64) -> String {
        "video_".to_owned() + &timestamp.to_string() + ".mp4"
    }
}

#[derive(Serialize, Deserialize)]
pub struct DeliveryMonitor {
    // We use the watch_list to keep track of video files that are yet to be
    // uploaded to the server.
    // A video will be removed from this list as soon as it is uploaded to the server.
    // If the video is lost in the server, this list won't know.
    video_watch_list: HashMap<u64, VideoInfo>, //<video timestamp, video info>
    // We use the pending_list to keep track of videos that are not delivered to the app.
    // A video is only removed from this list if a heartbeat signal with an equal or larger
    // motion epoch is received.
    video_pending_list: HashMap<u64, VideoInfo>, //<video epoch, video info>
    thumbnail_watch_list: HashMap<u64, ThumbnailMetaInfo>, // <video timestamp, thumbnail info>
    thumbnail_pending_list: HashMap<u64, ThumbnailMetaInfo>, //<thumbnail epoch, thumbnail info>
    video_dir: String,
    thumbnail_dir: String,
    state_dir: String,
    pending_livestream_updates: Vec<Vec<u8>>,
}

impl DeliveryMonitor {
    pub fn from_file_or_new(video_dir: String, thumbnail_dir: String, state_dir: String) -> Self {
        let d_files = MlsClient::get_state_files_sorted(&state_dir, "delivery_monitor_").unwrap();
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
            video_watch_list: HashMap::new(),
            // TODO: search the file system and add pending videos to this list
            video_pending_list: HashMap::new(),
            thumbnail_watch_list: HashMap::new(),
            thumbnail_pending_list: HashMap::new(),
            video_dir,
            thumbnail_dir,
            state_dir,
            pending_livestream_updates: vec![],
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
        let d_files = MlsClient::get_state_files_sorted(&self.state_dir, "delivery_monitor_").unwrap();
        assert!(d_files[0] == "delivery_monitor_".to_owned() + &current_timestamp.to_string());
        for f in &d_files[1..] {
            let _ = fs::remove_file(self.state_dir.clone() + "/" + f);
        }
    }

    pub fn enqueue_video(&mut self, video_info: VideoInfo) {
        info!("enqueue_event: {}", video_info.timestamp);
        let _ = self.video_watch_list.insert(video_info.timestamp, video_info.clone());
        let _ = self.video_pending_list.insert(video_info.epoch, video_info);

        self.save_state();
    }

    pub fn enqueue_thumbnail(&mut self, thumbnail_info: ThumbnailMetaInfo) {
        info!("enqueue_thumbnail_event: {}", thumbnail_info.timestamp);
        let _ = self.thumbnail_watch_list.insert(thumbnail_info.timestamp, thumbnail_info.clone());
        let _ = self.thumbnail_pending_list.insert(thumbnail_info.epoch, thumbnail_info);

        self.save_state();
    }
    pub fn dequeue_thumbnail(&mut self, thumbnail_info: &ThumbnailMetaInfo) {
        info!("dequeue_thumbnail_event: {}", thumbnail_info.timestamp);

        let _ = self.thumbnail_watch_list.remove(&thumbnail_info.timestamp);
        let _ = fs::remove_file(self.get_enc_thumbnail_file_path(thumbnail_info));

        self.save_state();
    }

    pub fn dequeue_video(&mut self, video_info: &VideoInfo) {
        info!("dequeue_event: {}", video_info.timestamp);

        let _ = self.video_watch_list.remove(&video_info.timestamp);
        let _ = fs::remove_file(self.get_enc_video_file_path(video_info));

        self.save_state();
    }

    pub fn process_heartbeat(&mut self, motion_epoch: u64,  thumbnail_epoch: u64) {
        let mut removed_list = vec![];

        // FIXME: the heartbeat_timestamp comes from the app.
        // The video timestamp is from the camera.
        // If the wall clock times on these two are not synchronized,
        // we could end up with incorrect result here.
        self.video_pending_list.retain(|&epoch, video_info| {
            if epoch <= motion_epoch {
                removed_list.push(video_info.clone());
                false
            } else {
                true
            }
        });

        for video_info in removed_list {
            let _ = fs::remove_file(self.get_video_file_path(&video_info));
        }

        // Process thumbnails now
        let mut removed_list = vec![];
        self.thumbnail_pending_list.retain(|&epoch, thumbnail_info| {
            if epoch <= thumbnail_epoch {
                removed_list.push(thumbnail_info.clone());
                false
            } else {
                true
            }
        });

        for thumbnail_info in removed_list {
            let _ = fs::remove_file(self.get_thumbnail_file_path(&thumbnail_info));
        }

        self.save_state();
    }

    pub fn get_all_pending_video_timestamps(&self) -> Vec<u64> {
        self.video_pending_list
            .values()
            .map(|info| info.timestamp)
            .collect()
    }

    pub fn get_all_pending_thumbnail_timestamps(&self) -> Vec<u64> {
        self.thumbnail_pending_list
            .values()
            .map(|info| info.timestamp)
            .collect()
    }

    pub fn get_thumbnail_meta_by_timestamp(&self, timestamp: &u64) -> &ThumbnailMetaInfo {
        self.thumbnail_pending_list.get(&timestamp).unwrap()
    }

    pub fn videos_to_send(&self) -> Vec<VideoInfo> {
        let mut send_list: Vec<VideoInfo> = Vec::new();

        for info in self.video_watch_list.values() {
            send_list.push(info.clone());
        }

        send_list.sort_by_key(|key| key.timestamp);

        send_list
    }

    pub fn thumbnails_to_send(&self) -> Vec<ThumbnailMetaInfo> {
        let mut send_list: Vec<ThumbnailMetaInfo> = Vec::new();

        for info in self.thumbnail_watch_list.values() {
            send_list.push(info.clone());
        }

        send_list.sort_by_key(|key| key.timestamp);

        send_list
    }

    pub fn enqueue_livestream_update(&mut self, update_commit_msg: Vec<u8>) {
        self.pending_livestream_updates.push(update_commit_msg);

        self.save_state();
    }

    pub fn dequeue_livestream_updates(&mut self) {
        self.pending_livestream_updates.clear();

        self.save_state();
    }

    pub fn get_livestream_updates(&self) -> Vec<Vec<u8>> {
        self.pending_livestream_updates.clone()
    }

    pub fn get_video_file_path(&self, info: &VideoInfo) -> PathBuf {
        let video_dir_path = Path::new(&self.video_dir);
        video_dir_path.join(&info.filename)
    }

    pub fn get_thumbnail_file_path(&self, info: &ThumbnailMetaInfo) -> PathBuf {
        let video_dir_path = Path::new(&self.thumbnail_dir);
        video_dir_path.join(&info.filename)
    }

    pub fn get_enc_video_file_path(&self, info: &VideoInfo) -> PathBuf {
        let video_dir_path = Path::new(&self.video_dir);
        let enc_filename = format!("{}", info.epoch);
        video_dir_path.join(&enc_filename)
    }

    pub fn get_enc_thumbnail_file_path(&self, info: &ThumbnailMetaInfo) -> PathBuf {
        let video_dir_path = Path::new(&self.thumbnail_dir);
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
