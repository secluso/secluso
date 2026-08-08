//! Code to manage the Raspberry Pi Camera
//!
//! SPDX-License-Identifier: GPL-3.0-or-later

use std::time::Duration;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::process::Command;
use std::thread;
use crate::raspberry_pi::rpi_dual_stream;
use crate::mp4::mp4_camera::{CameraResolution, Frame, FrameKind, Mp4Camera};
use crossbeam_channel::unbounded;
use secluso_motion_ai::logic::pipeline::PipelineController;
use secluso_motion_ai::pipeline;

/*

 
-use std::time::{Instant, SystemTime, UNIX_EPOCH};
-use std::{
-    collections::VecDeque,
-    io,
-    process::Command,
-    sync::{Arc, Mutex},
-    thread,
-    time::Duration,
-};
-
-use crate::motion::MotionResult;
-use crate::raspberry_pi::rpi_dual_stream;
-use crate::traits::Mp4;
-use crate::{
-    delivery_monitor::VideoInfo,
-    fmp4::Fmp4Writer,
-    livestream::LivestreamWriter,
-    mp4::Mp4Writer,
-    traits::{Camera, CodecParameters},
-    mp4::write_box,
-};
-use anyhow::Error;
-use bytes::{BufMut, BytesMut};
 use crossbeam_channel::unbounded;
-use image::RgbImage;
-use secluso_client_lib::thumbnail_meta_info::GeneralDetectionType;
-use secluso_motion_ai::logic::pipeline::PipelineController;
-use secluso_motion_ai::ml::models::DetectionType;
-use secluso_motion_ai::pipeline;
-use tokio::runtime::Runtime;
 */

const TOTAL_FRAME_RATE: usize = 10;
const I_FRAME_INTERVAL: usize = TOTAL_FRAME_RATE; // 1-second fragments

pub struct RaspberryPiPlatform;

pub type RaspberryPiCamera = Mp4Camera<RaspberryPiPlatform>;

impl Mp4Camera<RaspberryPiPlatform> {
    pub fn new(
        name: String,
        state_dir: String,
        video_dir: String,
        thumbnail_dir: String,
        motion_fps: u64,
        save_all: bool,
    ) -> Self {
        println!("Initializing Raspberry Pi Camera...");

        // Create a channel to receive SPS/PPS frames.
        let (ps_tx, ps_rx) = unbounded::<Frame>();

        // Frame queue holds recently processed H.264 and audio frames.
        let frame_queue = Arc::new(Mutex::new(VecDeque::new()));

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

        let resolution: CameraResolution = Self::fetch_resolution().expect("A supported camera module was not found");

        // Start the new shared stream.
        rpi_dual_stream::start(
            resolution.width,
            resolution.height,
            TOTAL_FRAME_RATE,
            I_FRAME_INTERVAL,
            Arc::clone(&motion_detection),
            Arc::clone(&frame_queue),
            ps_tx,
            motion_fps as u8,
        )
            .expect("Failed to start shared stream");

        rpi_dual_stream::start_audio(Arc::clone(&frame_queue))
            .expect("Failed to start audio stream");

        // Wait for the SPS and PPS frames before continuing.
        let mut sps_frame_opt = None;
        let mut pps_frame_opt = None;
        while sps_frame_opt.is_none() || pps_frame_opt.is_none() {
            let frame_attempt = ps_rx.recv_timeout(Duration::from_secs(30));
            if frame_attempt.is_err() {
                panic!("Failed to receive PPS/SPS frame from rpicam-vid in 30 seconds.");
            }

            let frame = frame_attempt.unwrap();
            match frame.kind {
                FrameKind::Sps => sps_frame_opt = Some(frame),
                FrameKind::Pps => pps_frame_opt = Some(frame),
                _ => {} // ignore unexpected frames
            }
        }
        let sps_frame = sps_frame_opt.expect("SPS frame missing");
        let pps_frame = pps_frame_opt.expect("PPS frame missing");

        println!("RaspberryPiCamera initialized.");

        Self::from_parts(
            name,
            state_dir,
            video_dir,
            thumbnail_dir,
            frame_queue,
            sps_frame,
            pps_frame,
            motion_detection,
            resolution,
            RaspberryPiPlatform,
        )
    }

    pub fn fetch_resolution() -> Option<CameraResolution> {
        debug!("Attempting to fetch the type of sensor attached to the Raspberry Pi");

        // Hard coded width x height based on the Camera Module connected to the Raspberry Pi.
        // Camera Module V1 (OV5647): 1296 x 972 (60% of 1080p)
        // Camera Module V2 (IMX219): 1640 x 1232 (97% of 1080p)
        // Camera Module V3 (IMX708): 2304x1296 (140% of 1080p)
        // Even though these support 1080p directly, if we were to use that, the sides would be cropped out due to the aspect ratio of the sensor.
        const CAMERA_RESOLUTION_V1: (usize, usize) = (1296, 972);
        const CAMERA_RESOLUTION_V2: (usize, usize) = (1640, 1232);
        const CAMERA_RESOLUTION_V3: (usize, usize) = (1920, 1080);

        // Detection logic to determine if the attached camera module is a V1, V2 or other (which likely won't reach this point as they aren't supported in the Secluso OS image regardless)
        // Sample Output of "rpicam-hello --list-cameras" that we must parse:
        //
        // Available cameras
        // -----------------
        // 0 : imx219 [3280x2464] (/base/soc/i2c0mux/i2c@1/imx219@10)
        //     Modes: 'SRGGB10_CSI2P' : 640x480 [206.65 fps - (1000, 752)/1280x960 crop]
        //                              1640x1232 [41.85 fps - (0, 0)/3280x2464 crop] **NOTICE** how this says (0,0) crop. That means that unlike 1920x1080, the sides aren't cut out, and we can get a wider view. This is only a 3% drop in resolution
        //                              1920x1080 [47.57 fps - (680, 692)/1920x1080 crop]
        //                              3280x2464 [21.19 fps - (0, 0)/3280x2464 crop]
        //            'SRGGB8' : 640x480 [206.65 fps - (1000, 752)/1280x960 crop]
        //                       1640x1232 [41.85 fps - (0, 0)/3280x2464 crop]
        //                       1920x1080 [47.57 fps - (680, 692)/1920x1080 crop]
        //                       3280x2464 [21.19 fps - (0, 0)/3280x2464 crop]

        /**
            For IMX708, source: https://forums.raspberrypi.com/viewtopic.php?t=381114
            Available cameras
            -----------------
            0 : imx708_wide_noir [4608x2592 10-bit RGGB] (/base/soc/i2c0mux/i2c@1/imx708@1a)
                Modes: 'SRGGB10_CSI2P' : 1536x864 [120.13 fps - (768, 432)/3072x1728 crop]
                                         2304x1296 [56.03 fps - (0, 0)/4608x2592 crop]
                                         4608x2592 [14.35 fps - (0, 0)/4608x2592 crop]
        */

        let output = Command::new("rpicam-hello")
            .args(["--list-cameras"])
            .output()
            .expect("failed to execute rpicam-hello --list-cameras to get sensor type");

        // Extract the raw-bytes that we captured from the rpicam-hello command
        let stdout = String::from_utf8(output.stdout).unwrap();

        // Parse the output (as seen in the example above)
        return if stdout.contains("imx219") {
            Some(CameraResolution {
                width: CAMERA_RESOLUTION_V2.0,
                height: CAMERA_RESOLUTION_V2.1,
            })
        } else if stdout.contains("ov5647") {
            Some(CameraResolution {
                width: CAMERA_RESOLUTION_V1.0,
                height: CAMERA_RESOLUTION_V1.1,
            })
        } else if stdout.contains("imx708") {
            Some(CameraResolution {
                width: CAMERA_RESOLUTION_V3.0,
                height: CAMERA_RESOLUTION_V3.1,
            })
        } else {
            None
        }
    }
}