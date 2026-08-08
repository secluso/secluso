//! Code to manage the Android Camera
//!
//! SPDX-License-Identifier: GPL-3.0-or-later

use std::time::Duration;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
//use std::thread;
use crate::android::android_dual_stream::{self, AndroidCameraSettings};
use crate::mp4::mp4_camera::{CameraResolution, Frame, FrameKind, Mp4Camera};
use crossbeam_channel::unbounded;
//use secluso_motion_ai::logic::pipeline::PipelineController;
//use secluso_motion_ai::pipeline;

const DEFAULT_BITRATE: usize = 2_000_000;
const MIN_BITRATE: usize = 1_000_000;
const MAX_BITRATE: usize = 8_000_000;
const I_FRAME_INTERVAL_SECONDS: usize = 1;

fn bitrate_for_settings(width: usize, height: usize, frame_rate: usize) -> usize {
    const BASE_WIDTH: usize = 1280;
    const BASE_HEIGHT: usize = 720;
    const BASE_FRAME_RATE: usize = 10;

    let numerator = (DEFAULT_BITRATE as u64)
        .saturating_mul(width as u64)
        .saturating_mul(height as u64)
        .saturating_mul(frame_rate.max(1) as u64);
    let denominator = (BASE_WIDTH as u64)
        .saturating_mul(BASE_HEIGHT as u64)
        .saturating_mul(BASE_FRAME_RATE as u64);
    let scaled = numerator
        .saturating_add(denominator.saturating_sub(1))
        / denominator;

    usize::try_from(scaled.clamp(MIN_BITRATE as u64, MAX_BITRATE as u64))
        .unwrap_or(MAX_BITRATE)
}

pub struct AndroidPlatform {
    _stream_handle: android_dual_stream::AndroidStreamHandle,
}

pub type AndroidCamera = Mp4Camera<AndroidPlatform>;

impl Mp4Camera<AndroidPlatform> {
    pub fn new(
        name: String,
        state_dir: String,
        video_dir: String,
        thumbnail_dir: String,
        motion_fps: u64,
        //FIXME
        _save_all: bool,
        settings: AndroidCameraSettings,
    ) -> Self {
        println!("Initializing Android Camera...");

        // Create a channel to receive SPS/PPS frames.
        let (ps_tx, ps_rx) = unbounded::<Frame>();

        // Frame queue holds recently processed H.264 and audio frames.
        let frame_queue = Arc::new(Mutex::new(VecDeque::new()));

        //FIXME
        /*
        // Start motion detection using raw frames from the shared stream.
        let pipeline = pipeline![
            secluso_motion_ai::logic::stages::MotionStage,
            secluso_motion_ai::logic::stages::InferenceStage,
        ];

        let write_logs = cfg!(feature = "telemetry");
        println!("Telemetry Output Enabled: {write_logs}");
        let mut new_controller = match PipelineController::new(pipeline, write_logs, save_all) {
            Ok(c) => c,
            Err(_) => {
                panic!("Failed to instantiate pipeline controller");
            }
        };

        new_controller.start_working();
        let motion_detection = Arc::new(Mutex::new(new_controller));
        let controller_clone = Arc::clone(&motion_detection);
        motion_detection.lock().unwrap().start_working(); // TODO: Should we start processing later, maybe when we get the first frame?

        // Background thread: runs the pipeline's main event loop
        thread::spawn(move || {
            //todo: only loop until exit
            loop {
                // when false (health issue), we should exit + we should also have some way for user to safely exit
                let result = controller_clone.lock().unwrap().tick("cpu_thermal temp1"); //TODO: This string should be put somewhere as a constant

                if let Err(e) = result {
                    println!("Encountered error in tick loop: {e}");
                    break;
                } else if let Ok(accepted) = result {
                    if !accepted {
                        println!("Not accepted");
                        break;
                    }
                }
                thread::sleep(Duration::from_millis(100));
            }

            debug!("Exited controller tick loop");
        });
        */

        let resolution = CameraResolution {
            width: settings.width,
            height: settings.height,
        };
        let frame_rate_range = settings.frame_rate_range;
        let frame_rate_max = usize::try_from(frame_rate_range.max).unwrap_or(1);
        let bitrate = bitrate_for_settings(resolution.width, resolution.height, frame_rate_max);

        log::info!(
            "AndroidCamera: starting dual stream facing={} resolution={}x{} fps={}-{} bitrate={}",
            settings.facing,
            resolution.width,
            resolution.height,
            frame_rate_range.min,
            frame_rate_range.max,
            bitrate
        );

        // Start the new shared stream.
        let stream_handle = android_dual_stream::start(
            settings.facing,
            resolution.width,
            resolution.height,
            frame_rate_range,
            I_FRAME_INTERVAL_SECONDS,
            bitrate,
            //FIXME
            //Arc::clone(&motion_detection),
            Arc::clone(&frame_queue),
            ps_tx,
            motion_fps as u8,
        )
        .expect("Failed to start shared stream");

        log::info!("AndroidCamera: waiting for encoder SPS/PPS");

        // Wait for the SPS and PPS frames before continuing.
        let mut sps_frame_opt = None;
        let mut pps_frame_opt = None;
        while sps_frame_opt.is_none() || pps_frame_opt.is_none() {
            let frame_attempt = ps_rx.recv_timeout(Duration::from_secs(30));
            if frame_attempt.is_err() {
                panic!("Failed to receive PPS/SPS frame from rpicam-vid in 30 seconds.");
            }

            let frame = frame_attempt.unwrap();

            log::info!(
                "AndroidCamera: received frame while waiting for SPS/PPS: kind={:?}, len={}",
                frame.kind,
                frame.data.len()
            );

            match frame.kind {
                FrameKind::Sps => {
                    log::info!("AndroidCamera: received SPS");
                    sps_frame_opt = Some(frame);
                }
                FrameKind::Pps => {
                    log::info!("AndroidCamera: received PPS");
                    pps_frame_opt = Some(frame);
                }
                _ => {}
            }
        }
        let sps_frame = sps_frame_opt.expect("SPS frame missing");
        let pps_frame = pps_frame_opt.expect("PPS frame missing");

        println!("AndroidCamera initialized.");

        Self::from_parts(
            name,
            state_dir,
            video_dir,
            thumbnail_dir,
            frame_queue,
            sps_frame,
            pps_frame,
            //FIXME
            //motion_detection,
            resolution,
            AndroidPlatform {
                _stream_handle: stream_handle,
            }
        )
    }
}