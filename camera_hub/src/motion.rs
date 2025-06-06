//! Camera hub motion video
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

use crate::delivery_monitor::{DeliveryMonitor, VideoInfo};
use crate::Client;
use privastead_client_lib::http_client::HttpClient;
use privastead_client_lib::video_net_info::VideoNetInfo;
use std::fs::File;
use std::io;
use std::io::{BufRead, BufReader, Write};

fn append_to_file(mut file: &File, msg: Vec<u8>) {
    let msg_len: u32 = msg.len().try_into().unwrap();
    let msg_len_data = msg_len.to_be_bytes();
    let _ = file.write_all(&msg_len_data);
    let _ = file.write_all(&msg);
}

pub fn upload_pending_enc_videos(
    group_name: &str,
    delivery_monitor: &mut DeliveryMonitor,
    http_client: &HttpClient,
) {
    // Send pending videos
    let send_list = delivery_monitor.videos_to_send();
    // The send list is sorted. We must send the videos in order.
    for video_info in &send_list {
        let enc_video_file_path = delivery_monitor.get_enc_video_file_path(video_info);
        match http_client.upload_enc_video(group_name, &enc_video_file_path) {
            Ok(_) => {
                info!(
                    "Video {} successfully uploaded to the server.",
                    video_info.timestamp
                );
                delivery_monitor.dequeue_video(video_info);
            }
            Err(e) => {
                info!(
                    "Could not upload video {} ({}). Will try again later.",
                    video_info.timestamp, e
                );
                break;
            }
        }
    }
}

pub fn prepare_motion_video(
    client: &mut Client,
    mut video_info: VideoInfo,
    delivery_monitor: &mut DeliveryMonitor,
) -> io::Result<()> {
    let video_file_path = delivery_monitor.get_video_file_path(&video_info);

    debug!("Starting to send video.");

    // Update MLS epoch
    let (commit_msg, epoch) = client.user.update(&client.group_name)?;

    video_info.epoch = epoch;
    let enc_video_file_path = delivery_monitor.get_enc_video_file_path(&video_info);
    let mut enc_file =
        File::create(&enc_video_file_path).expect("Could not create encrypted video file");

    append_to_file(&enc_file, commit_msg);

    let file = File::open(video_file_path).expect("Could not open video file to send");
    let file_len = file.metadata().unwrap().len();

    // FIXME: why this chunk size? Test larger and smaller chunks.
    const READ_SIZE: usize = 64 * 1024;
    let mut reader = BufReader::with_capacity(READ_SIZE, file);

    let net_info = VideoNetInfo::new(video_info.timestamp, file_len, READ_SIZE as u64);

    let msg = client
        .user
        .encrypt(&bincode::serialize(&net_info).unwrap(), &client.group_name)
        .map_err(|e| {
            error!("encrypt() returned error:");
            e
        })?;
    append_to_file(&enc_file, msg);

    for chunk_number in 0..net_info.num_msg {
        // We include the chunk number in the chunk itself (and check it in the app)
        // to prevent a malicious server from reordering the chunks.
        let mut buffer: Vec<u8> = chunk_number.to_be_bytes().to_vec();
        buffer.extend(reader.fill_buf().unwrap());
        let length = buffer.len();
        // Sanity checks
        if chunk_number < (net_info.num_msg - 1) {
            assert_eq!(length, READ_SIZE + 8);
        } else {
            assert_eq!(
                length,
                (<u64 as TryInto<usize>>::try_into(file_len).unwrap() % READ_SIZE) + 8
            );
        }

        let msg = client
            .user
            .encrypt(&buffer, &client.group_name)
            .map_err(|e| {
                error!("send_video() returned error:");
                client.user.save_groups_state();
                e
            })?;
        append_to_file(&enc_file, msg);
        reader.consume(length);
    }

    // Here, we first make sure the enc_file is flushed.
    // Then, we save groups state, which persists the update.
    // Then, we enqueue to be uploaded to the server.
    enc_file.flush().unwrap();
    enc_file.sync_all().unwrap();
    client.user.save_groups_state();

    // FIXME: fatal crash point here. We have committed the update, but we will never enqueue it for sending.
    // Severity: medium.
    // Rationale: Both operations before and after the fatal crash point are file system writes.

    info!(
        "Video {} is enqueued for sending to server.",
        video_info.timestamp
    );
    delivery_monitor.enqueue_video(video_info);

    Ok(())
}
