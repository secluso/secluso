//! Camera hub motion video
//!
//! SPDX-License-Identifier: GPL-3.0-or-later

use crate::delivery_monitor::{DeliveryMonitor, VideoInfo};
use crate::traits::Camera;
use image::RgbImage;
use regex::Regex;
use secluso_client_lib::http_client::HttpClient;
use secluso_client_lib::mls_client::MlsClient;
use secluso_client_lib::mls_clients::{MlsClients, FCM, MAX_OFFLINE_WINDOW, MOTION, THUMBNAIL};
use secluso_client_lib::thumbnail_meta_info::{GeneralDetectionType, ThumbnailMetaInfo};
use secluso_client_lib::video_net_info::VideoNetInfo;
use std::fs;
use std::fs::File;
use std::io;
use std::io::{BufRead, BufReader, Read, Write};

// Used to contain data returned from motion detection from IP + Raspberry cameras
pub struct MotionResult {
    pub motion: bool,
    pub detections: Vec<GeneralDetectionType>,
    pub thumbnail: Option<RgbImage>,
}

fn append_to_file(mut file: &File, msg: Vec<u8>) {
    let msg_len: u32 = msg.len().try_into().unwrap();
    let msg_len_data = msg_len.to_be_bytes();
    let _ = file.write_all(&msg_len_data);
    let _ = file.write_all(&msg);
}

pub fn upload_pending_enc_thumbnails(
    group_name: &str,
    delivery_monitor: &mut DeliveryMonitor,
    http_client: &HttpClient,
) -> io::Result<()> {
    // Send pending thumbnails
    let send_list_thumbnails: Vec<ThumbnailMetaInfo> = delivery_monitor.thumbnails_to_send();
    if let Some(enc_thumbnail) = send_list_thumbnails.first() {
        let enc_video_file_path = delivery_monitor.get_enc_thumbnail_file_path(enc_thumbnail);
        match http_client.upload_enc_file(group_name, &enc_video_file_path) {
            Ok(_) => {
                info!(
                    "Thumbnail (epoch #{}) successfully uploaded to the server.",
                    enc_thumbnail.epoch
                );
                delivery_monitor.dequeue_thumbnail(enc_thumbnail);
                return Ok(());
            }
            Err(e) => {
                info!(
                    "Could not upload thumbnail (epoch #{}) ({}). Will try again later.",
                    enc_thumbnail.epoch, e
                );
                return Err(e);
            }
        }
    }

    Ok(())
}

pub fn upload_pending_enc_videos(
    group_name: &str,
    delivery_monitor: &mut DeliveryMonitor,
    http_client: &HttpClient,
) -> io::Result<()> {
    // Send pending videos
    let send_list_videos = delivery_monitor.videos_to_send();
    // The send list is sorted. We must send the videos in order.
    if let Some(video_info) = send_list_videos.first() {
        let enc_video_file_path = delivery_monitor.get_enc_video_file_path(video_info);
        match http_client.upload_enc_file(group_name, &enc_video_file_path) {
            Ok(_) => {
                info!(
                    "Video {} successfully uploaded to the server.",
                    video_info.timestamp
                );
                delivery_monitor.dequeue_video(video_info);
                return Ok(());
            }
            Err(e) => {
                info!(
                    "Could not upload video {} ({}). Will try again later.",
                    video_info.timestamp, e
                );
                return Err(e);
            }
        }
    }

    Ok(())
}

pub fn prepare_motion_thumbnail(
    mls_client: &mut MlsClient,
    mut thumbnail_info: ThumbnailMetaInfo,
    delivery_monitor: &mut DeliveryMonitor,
) -> io::Result<()> {
    if mls_client.offline_period() > MAX_OFFLINE_WINDOW {
        info!("App has been offline for too long. Won't send any more videos until there is a heartbeat.");
        // FIXME: not enforcing this yet.
        //return Ok(());
    }

    debug!("Starting to send timestamp.");

    // Update MLS epoch
    let (commit_msg, thumbnail_epoch) = mls_client.update()?;
    let thumbnail_file_path = delivery_monitor.get_thumbnail_file_path(&thumbnail_info);

    thumbnail_info.epoch = thumbnail_epoch;

    let enc_thumbnail_file_path = delivery_monitor.get_enc_thumbnail_file_path(&thumbnail_info);
    let mut enc_file =
        File::create(&enc_thumbnail_file_path).expect("Could not create encrypted video file");

    append_to_file(&enc_file, commit_msg);

    // We need to store the timestamp to match against the video's, as otherwise we only have epoch-level info (which can vary between videos and timestamps easily)
    let msg = mls_client
        .encrypt(&bincode::serialize(&thumbnail_info).unwrap())
        .inspect_err(|_| {
            error!("encrypt() returned error:");
        })?;
    append_to_file(&enc_file, msg);

    let mut file = File::open(thumbnail_file_path).expect("Could not open video file to send");
    let mut thumbnail_data: Vec<u8> = Vec::new();
    file.read_to_end(&mut thumbnail_data)?;

    let msg = mls_client.encrypt(&thumbnail_data).inspect_err(|_| {
        error!("encrypt() returned error:");
    })?;
    append_to_file(&enc_file, msg);

    // Here, we first make sure the enc_file is flushed.
    // Then, we save groups state, which persists the update.
    // Then, we enqueue to be uploaded to the server.
    enc_file.flush().unwrap();
    enc_file.sync_all().unwrap();
    mls_client.save_group_state();

    // FIXME: fatal crash point here. We have committed the update, but we will never enqueue it for sending.
    // Severity: medium.
    // Rationale: Both operations before and after the fatal crash point are file system writes.

    info!(
        "Thumbnail (vid timestamp: {}, thumbnail epoch #{:?}) is enqueued for sending to server.",
        thumbnail_info.timestamp, thumbnail_info.epoch
    );
    delivery_monitor.enqueue_thumbnail(thumbnail_info);

    Ok(())
}

pub fn prepare_motion_video(
    mls_client: &mut MlsClient,
    mut video_info: VideoInfo,
    delivery_monitor: &mut DeliveryMonitor,
) -> io::Result<()> {
    if mls_client.offline_period() > MAX_OFFLINE_WINDOW {
        info!("App has been offline for too long. Won't send any more videos until there is a heartbeat.");
        // We return Ok(()) since we want the core() in main.rs to continue;
        // FIXME: not enforcing this yet.
        //return Ok(());
    }

    let video_file_path = delivery_monitor.get_video_file_path(&video_info);

    debug!("Starting to send video.");
    let (commit_msg, epoch) = mls_client.update()?;

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

    let msg = mls_client
        .encrypt(&bincode::serialize(&net_info).unwrap())
        .inspect_err(|_| {
            error!("encrypt() returned error:");
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

        let msg = mls_client.encrypt(&buffer).inspect_err(|_| {
            error!("send_video() returned error:");
            mls_client.save_group_state();
        })?;
        append_to_file(&enc_file, msg);
        reader.consume(length);
    }

    // Here, we first make sure the enc_file is flushed.
    // Then, we save groups state, which persists the update.
    // Then, we enqueue to be uploaded to the server.
    enc_file.flush().unwrap();
    enc_file.sync_all().unwrap();
    mls_client.save_group_state();

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

pub fn send_pending_motion_videos(
    camera: &mut dyn Camera,
    clients: &mut MlsClients,
    delivery_monitor: &mut DeliveryMonitor,
    http_client: &HttpClient,
) -> io::Result<()> {
    if clients[MOTION].offline_period() > MAX_OFFLINE_WINDOW {
        info!("App has been offline for too long. Won't send any more videos until there is a heartbeat.");
        // FIXME: not enforcing this yet.
        //return Ok(());
    }

    let mut pending_timestamps = Vec::new();
    let video_dir = camera.get_video_dir();

    let re = Regex::new(r"^video_(\d+)\.mp4$").unwrap();

    for entry in fs::read_dir(video_dir)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();

        if let Some(caps) = re.captures(&file_name) {
            if let Some(matched) = caps.get(1) {
                if let Ok(ts) = matched.as_str().parse::<u64>() {
                    pending_timestamps.push(ts);
                }
            }
        }
    }

    let delivery_monitor_pending_timestamps = delivery_monitor.get_all_pending_video_timestamps();
    let mut num_recovered = 0;

    for timestamp in &pending_timestamps {
        // Check to make sure the video is not already tracked by the delivery monitor
        if delivery_monitor_pending_timestamps.contains(timestamp) {
            continue;
        }

        println!("Recovered pending video {:?}", *timestamp);
        let video_info = VideoInfo::from(*timestamp);
        prepare_motion_video(&mut clients[MOTION], video_info, delivery_monitor)?;

        let _ = upload_pending_enc_videos(
            &clients[MOTION].get_group_name().unwrap(),
            delivery_monitor,
            http_client,
        );

        num_recovered += 1;
    }

    if num_recovered > 0 {
        //Timestamp of 0 tells the app it's time to start downloading.
        let dummy_timestamp: u64 = 0;
        let notification_msg =
            clients[FCM].encrypt(&bincode::serialize(&dummy_timestamp).unwrap())?;
        clients[FCM].save_group_state();
        http_client.send_fcm_notification(notification_msg)?;
    }

    Ok(())
}

pub fn send_pending_thumbnails(
    camera: &mut dyn Camera,
    clients: &mut MlsClients,
    delivery_monitor: &mut DeliveryMonitor,
    http_client: &HttpClient,
) -> io::Result<()> {
    if clients[THUMBNAIL].offline_period() > MAX_OFFLINE_WINDOW {
        info!("App has been offline for too long. Won't send any more videos until there is a heartbeat.");
        // FIXME: not enforcing this yet.
        //return Ok(());
    }

    let mut pending_timestamps = Vec::new();
    let video_dir = camera.get_thumbnail_dir();

    let re = Regex::new(r"^thumbnail_(\d+)\.png$").unwrap();

    for entry in fs::read_dir(video_dir)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();

        if let Some(caps) = re.captures(&file_name) {
            if let Some(matched) = caps.get(1) {
                if let Ok(ts) = matched.as_str().parse::<u64>() {
                    pending_timestamps.push(ts);
                }
            }
        }
    }

    let delivery_monitor_pending_timestamps =
        delivery_monitor.get_all_pending_thumbnail_timestamps();
    let mut num_recovered = 0;

    for timestamp in &pending_timestamps {
        // Check to make sure the thumbnail is not already tracked by the delivery monitor
        if delivery_monitor_pending_timestamps.contains(timestamp) {
            continue;
        }

        println!("Recovered pending thumbnail {:?}", *timestamp);
        let thumbnail_meta = delivery_monitor.get_thumbnail_meta_by_timestamp(timestamp);

        // We clone the thumbnail meta here, which modifies the epoch. This doesn't matter as it's re-entered into the HashMap in the DeliveryMonitor at the end.
        prepare_motion_thumbnail(
            &mut clients[THUMBNAIL],
            thumbnail_meta.clone(),
            delivery_monitor,
        )?;

        let _ = upload_pending_enc_thumbnails(
            &clients[THUMBNAIL].get_group_name().unwrap(),
            delivery_monitor,
            http_client,
        );

        num_recovered += 1;
    }

    if num_recovered > 0 {
        //Timestamp of 0 tells the app it's time to start downloading.
        let dummy_timestamp: u64 = 0;
        let notification_msg =
            clients[FCM].encrypt(&bincode::serialize(&dummy_timestamp).unwrap())?;
        clients[FCM].save_group_state();
        http_client.send_fcm_notification(notification_msg)?;
    }

    Ok(())
}
