//! Camera hub motion video
//!
//! SPDX-License-Identifier: GPL-3.0-or-later

use crate::delivery_monitor::{DeliveryMonitor, VideoInfo};
use image::RgbImage;
use secluso_client_lib::http_client::HttpClient;
use secluso_client_lib::mls_client::MlsClient;
use secluso_client_lib::mls_clients::{MAX_OFFLINE_WINDOW};
use secluso_client_lib::thumbnail_meta_info::{GeneralDetectionType, ThumbnailMetaInfo};
use secluso_client_lib::video::{encrypt_thumbnail_file, encrypt_video_file};
use std::io;

// Used to contain data returned from motion detection from IP + Raspberry cameras
pub struct MotionResult {
    pub motion: bool,
    pub detections: Vec<GeneralDetectionType>,
    pub thumbnail: Option<RgbImage>,
}

pub fn upload_pending_enc_thumbnails(
    group_name: &str,
    delivery_monitor: &mut DeliveryMonitor,
    http_client: &HttpClient,
    num_apps: usize,
) -> io::Result<()> {
    // Send pending thumbnails
    let send_list_thumbnails: Vec<ThumbnailMetaInfo> = delivery_monitor.thumbnails_to_send();
    if let Some(enc_thumbnail) = send_list_thumbnails.first() {
        let enc_video_file_path = delivery_monitor.get_enc_thumbnail_file_path(enc_thumbnail);
        match http_client.upload_enc_file(group_name, &enc_video_file_path, num_apps) {
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
    num_apps: usize,
) -> io::Result<()> {
    // Send pending videos
    let send_list_videos = delivery_monitor.videos_to_send();
    // The send list is sorted. We must send the videos in order.
    if let Some(video_info) = send_list_videos.first() {
        let enc_video_file_path = delivery_monitor.get_enc_video_file_path(video_info);
        match http_client.upload_enc_file(group_name, &enc_video_file_path, num_apps) {
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

// TODO: for motion videos, we have VideoInfo used by the delivery monitor and
// VideoNetInfo encrypted with the video. For Thumbnail, we only have one, ThumbnailMetaInfo.
// Make them consistent.
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

    // encrypt_thumbnail_file() performs an update, which increases the epoch by 1.
    thumbnail_info.epoch = mls_client.get_epoch()? + 1;
    let thumbnail_file_path = delivery_monitor.get_thumbnail_file_path(&thumbnail_info);
    let enc_thumbnail_file_path = delivery_monitor.get_enc_thumbnail_file_path(&thumbnail_info);

    let epoch = encrypt_thumbnail_file(
        mls_client,
        thumbnail_file_path
            .to_str()
            .expect("Path is not valid UTF-8"),
        enc_thumbnail_file_path
            .to_str()
            .expect("Path is not valid UTF-8"),
        &mut thumbnail_info,
    )?;

    assert!(epoch == thumbnail_info.epoch);

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

    // encrypt_video_file() performs an update, which increases the epoch by 1.
    video_info.epoch = mls_client.get_epoch()? + 1;
    println!("epoch for new motion video = {:?}", video_info.epoch);
    let video_file_path = delivery_monitor.get_video_file_path(&video_info);
    let enc_video_file_path = delivery_monitor.get_enc_video_file_path(&video_info);

    let epoch = encrypt_video_file(
        mls_client,
        video_file_path.to_str().expect("Path is not valid UTF-8"),
        enc_video_file_path
            .to_str()
            .expect("Path is not valid UTF-8"),
        video_info.timestamp,
    )?;

    assert!(epoch == video_info.epoch);

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

// TODO: Keeping these two functions here since we might need them.
/*
pub fn send_pending_motion_videos(
    camera: &mut dyn Camera,
    clients_com: &mut MlsClientsCommon,
    delivery_monitor: &mut DeliveryMonitor,
    http_client: &HttpClient,
    num_apps: u32,
) -> io::Result<()> {
    if clients_com[MOTION].offline_period() > MAX_OFFLINE_WINDOW {
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
        prepare_motion_video(&mut clients_com[MOTION], video_info, delivery_monitor)?;

        let _ = upload_pending_enc_videos(
            &clients_com[MOTION].get_group_name().unwrap(),
            delivery_monitor,
            http_client,
            num_apps,
        );

        num_recovered += 1;
    }

    if num_recovered > 0 {
        //Timestamp of 0 tells the app it's time to start downloading.
        let dummy_timestamp: u64 = 0;
        let notification_msg =
            clients_com[FCM].encrypt(&bincode::serialize(&dummy_timestamp).unwrap())?;
        clients_com[FCM].save_group_state().unwrap();
        send_notification(&camera.get_state_dir(), http_client, notification_msg)?;
    }

    Ok(())
}

pub fn send_pending_thumbnails(
    camera: &mut dyn Camera,
    clients_com: &mut MlsClientsCommon,
    delivery_monitor: &mut DeliveryMonitor,
    http_client: &HttpClient,
    num_apps: u32,
) -> io::Result<()> {
    if clients_com[THUMBNAIL].offline_period() > MAX_OFFLINE_WINDOW {
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
            &mut clients_com[THUMBNAIL],
            thumbnail_meta.clone(),
            delivery_monitor,
        )?;

        let _ = upload_pending_enc_thumbnails(
            &clients_com[THUMBNAIL].get_group_name().unwrap(),
            delivery_monitor,
            http_client,
            num_apps,
        );

        num_recovered += 1;
    }

    if num_recovered > 0 {
        //Timestamp of 0 tells the app it's time to start downloading.
        let dummy_timestamp: u64 = 0;
        let notification_msg =
            clients_com[FCM].encrypt(&bincode::serialize(&dummy_timestamp).unwrap())?;
        clients_com[FCM].save_group_state().unwrap();
        send_notification(&camera.get_state_dir(), http_client, notification_msg)?;
    }

    Ok(())
}
*/
