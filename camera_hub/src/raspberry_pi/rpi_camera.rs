//! Code to manage the Raspberry Pi Camera
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

use std::time::Instant;
use std::{
    collections::VecDeque,
    io,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use anyhow::{Context, Error};
use bytes::{BufMut, BytesMut};
use crossbeam_channel::unbounded;
use privastead_motion_ai::pipeline;
use tokio::runtime::Runtime;
use privastead_motion_ai::logic::pipeline::PipelineController;
use crate::raspberry_pi::rpi_dual_stream;
use crate::traits::Mp4;
use crate::{
    delivery_monitor::VideoInfo,
    fmp4::Fmp4Writer,
    livestream::LivestreamWriter,
    mp4::Mp4Writer,
    traits::{Camera, CodecParameters},
    write_box,
};

// Frame dimensions
const WIDTH: usize = 1296;
const HEIGHT: usize = 972;
const TOTAL_FRAME_RATE: usize = 10;
const I_FRAME_INTERVAL: usize = TOTAL_FRAME_RATE; // 1-second fragments

//These are for our local SPS/PPS channel
#[derive(PartialEq, Debug, Clone)]
pub enum VideoFrameKind {
    RFrame,
    IFrame,
    Sps,
    Pps,
}

#[derive(Debug, Clone)]
pub struct VideoFrame {
    pub data: Vec<u8>,
    pub kind: VideoFrameKind,
    pub timestamp: Instant,
}

impl VideoFrame {
    pub fn new(data: Vec<u8>, kind: VideoFrameKind) -> Self {
        Self {
            data,
            kind,
            timestamp: Instant::now(),
        }
    }
}

/// RaspberryPiCamera uses the shared stream for both motion detection (via raw YUV420 frames) and recording/livestreaming (via H.264).
pub struct RaspberryPiCamera {
    name: String,
    state_dir: String,
    video_dir: String,
    frame_queue: Arc<Mutex<VecDeque<VideoFrame>>>,
    sps_frame: VideoFrame,
    pps_frame: VideoFrame,
    motion_detection: Arc<Mutex<PipelineController>>,
}

impl RaspberryPiCamera {
    pub fn new(name: String, state_dir: String, video_dir: String, motion_fps: u64) -> Self {
        println!("Initializing Raspberry Pi Camera...");

        // Create a channel to receive SPS/PPS frames.
        let (ps_tx, ps_rx) = unbounded::<VideoFrame>();

        // Frame queue holds recently processed H.264 frames.
        let frame_queue = Arc::new(Mutex::new(VecDeque::new()));

        // Start motion detection using raw frames from the shared stream.
        let pipeline = pipeline![
            privastead_motion_ai::logic::stages::MotionStage,
            privastead_motion_ai::logic::stages::InferenceStage,
        ];

        let write_logs = cfg!(feature = "telemetry");
        println!("Telemetry Output Enabled: {write_logs}");
        let mut new_controller = match PipelineController::new(pipeline, write_logs) {
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
                let start_time = Instant::now();
                let result = controller_clone.lock().unwrap().tick("cpu_thermal temp1"); //TODO: This string should be put somewhere as a constant
                println!("Took {}ms to tick", start_time.elapsed().as_millis());

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


        // Start the new shared stream.
        rpi_dual_stream::start(
            WIDTH,
            HEIGHT,
            TOTAL_FRAME_RATE,
            I_FRAME_INTERVAL,
            Arc::clone(&motion_detection),
            Arc::clone(&frame_queue),
            ps_tx,
            motion_fps as u8,
        )
            .expect("Failed to start shared stream");

        // Wait for the SPS and PPS frames before continuing.
        let mut sps_frame_opt = None;
        let mut pps_frame_opt = None;
        while sps_frame_opt.is_none() || pps_frame_opt.is_none() {
            let frame_attempt = ps_rx.recv_timeout(Duration::from_secs(30));
            if let Err(_) = frame_attempt {
                panic!("Failed to receive PPS/SPS frame from rpicam-vid in 30 seconds.");
            }

            let frame = frame_attempt.unwrap();
            match frame.kind {
                VideoFrameKind::Sps => sps_frame_opt = Some(frame),
                VideoFrameKind::Pps => pps_frame_opt = Some(frame),
                _ => {} // ignore unexpected frames
            }
        }
        let sps_frame = sps_frame_opt.expect("SPS frame missing");
        let pps_frame = pps_frame_opt.expect("PPS frame missing");

        println!("RaspberryPiCamera initialized.");

        Self {
            name,
            state_dir,
            video_dir,
            frame_queue,
            sps_frame,
            pps_frame,
            motion_detection,
        }
    }

    // The modified copy function now takes an optional raw_writer.
    // For every frame sent to the MP4 writer, we also write the raw frame data.
    async fn copy<'a, M: Mp4>(
        mp4: &'a mut M,
        duration: Option<u64>,
        frame_queue: Arc<Mutex<VecDeque<VideoFrame>>>,
    ) -> Result<(), Error> {
        let recording_window = duration.map(|secs| Duration::new(secs, 0));
        let recording_start_time = Instant::now();
        let mut first_frame_found = false;
        let mut frame_count: u64 = 0;
        let time_per_frame: u64 = 1_000_000 / TOTAL_FRAME_RATE as u64;

        loop {
            let mut queue = frame_queue.lock().unwrap();
            let frame = match queue.pop_front() {
                Some(f) => f,
                None => {
                    drop(queue);
                    thread::sleep(Duration::from_secs(1));
                    continue;
                }
            };

            // On I-frame, mark the beginning of a fragment.
            if frame.kind == VideoFrameKind::IFrame {
                first_frame_found = true;
                if let Err(_e) = mp4.finish_fragment().await {
                    // End of livestream.
                    break;
                }
            }

            if first_frame_found {
                // Compute the timestamp based on the frame count and fixed frame rate.
                let frame_timestamp_micros = frame_count * time_per_frame;
                // Convert Annex B NAL unit to AVCC format.
                let avcc_data = Self::convert_annexb_to_avcc(&frame.data);
                mp4.video(
                    &avcc_data,
                    frame_timestamp_micros / 10, // Adjust conversion as needed.
                    frame.kind == VideoFrameKind::IFrame,
                )
                    .await
                    .with_context(|| "Error processing video frame")?;
                frame_count += 1;
            }
            drop(queue);

            if let Some(window) = recording_window {
                if Instant::now().duration_since(recording_start_time) > window {
                    info!("Stopping the recording.");
                    break;
                }
            }
        }
        Ok(())
    }

    /// Writes a motion detection .mp4
    async fn write_mp4(
        filename: String,
        duration: u64,
        frame_queue: Arc<Mutex<VecDeque<VideoFrame>>>,
        sps_frame: VideoFrame,
        pps_frame: VideoFrame,
    ) -> Result<(), Error> {
        // Create the primary MP4 file.
        let file = tokio::fs::File::create(&filename).await?;
        let sps_start_len = if sps_frame.data.starts_with(&[0, 0, 0, 1]) {
            4
        } else {
            3
        };
        let pps_start_len = if pps_frame.data.starts_with(&[0, 0, 0, 1]) {
            4
        } else {
            3
        };

        let sps_bytes = sps_frame.data[sps_start_len..].to_vec();
        let pps_bytes = pps_frame.data[pps_start_len..].to_vec();

        let mut mp4 = Mp4Writer::new(
            RpiCameraVideoParameters::new(
                // For MP4, remove the start code (assumes a 4-byte start code).
                sps_bytes, pps_bytes,
            ),
            RpiCameraAudioParameters::default(),
            file,
        )
            .await?;

        // Process the rest of the frames, writing both to the MP4 writer and to the raw file.
        Self::copy(&mut mp4, Some(duration), frame_queue).await?;
        mp4.finish().await?;

        Ok(())
    }

    /// Streams fmp4 video.
    async fn write_fmp4(
        livestream_writer: LivestreamWriter,
        frame_queue: Arc<Mutex<VecDeque<VideoFrame>>>,
        sps_frame: VideoFrame,
        pps_frame: VideoFrame,
    ) -> Result<(), Error> {
        let mut fmp4 = Fmp4Writer::new(
            // Removing the 4-byte length prefix
            RpiCameraVideoParameters::new(
                sps_frame.data[4..].to_vec(),
                pps_frame.data[4..].to_vec(),
            ),
            RpiCameraAudioParameters::default(),
            livestream_writer,
        )
            .await?;
        fmp4.finish_header().await?;
        Self::copy(&mut fmp4, None, frame_queue).await?;

        Ok(())
    }

    // Required for MP4 muxing. Frames from rpicam-vid are in AnnexB, and we need Avcc for our muxer. FFmpeg did not have this output.
    fn convert_annexb_to_avcc(nal: &[u8]) -> Vec<u8> {
        // Determine the start code length.
        let start_code_len = if nal.starts_with(&[0, 0, 0, 1]) {
            4
        } else if nal.starts_with(&[0, 0, 1]) {
            3
        } else {
            0
        };
        let nal_payload = &nal[start_code_len..];
        let nal_len = nal_payload.len() as u32;

        // Create a new vector with the 4-byte big-endian length prefix.
        let mut avcc = nal_len.to_be_bytes().to_vec();
        avcc.extend_from_slice(nal_payload);
        avcc
    }
}

impl Camera for RaspberryPiCamera {
    fn is_there_motion(&mut self) -> Result<bool, Error> {
        Ok(self.motion_detection.lock().unwrap().motion_recently())
    }

    fn record_motion_video(&self, info: &VideoInfo, duration: u64) -> io::Result<()> {
        let rt = Runtime::new()?;

        // FIXME: use a temp name for recording and then rename at the end?
        // If not, we might end up with half-recorded videos on crash, factory reset, etc.
        // This might be okay though.
        let future = Self::write_mp4(
            self.video_dir.clone() + "/" + &info.filename,
            duration,
            Arc::clone(&self.frame_queue),
            self.sps_frame.clone(),
            self.pps_frame.clone(),
        );

        rt.block_on(future).unwrap();
        Ok(())
    }

    fn launch_livestream(&self, livestream_writer: LivestreamWriter) -> io::Result<()> {
        // Drop all the frames from the queue since we won't need them for livestreaming
        let mut queue = self.frame_queue.lock().unwrap();
        queue.clear();
        drop(queue);

        let frame_queue_clone = Arc::clone(&self.frame_queue);
        let sps_frame_clone = self.sps_frame.clone();
        let pps_frame_clone = self.pps_frame.clone();

        thread::spawn(move || {
            let rt = Runtime::new().unwrap();

            let future = Self::write_fmp4(
                livestream_writer,
                frame_queue_clone,
                sps_frame_clone,
                pps_frame_clone,
            );

            rt.block_on(future).unwrap();
        });

        Ok(())
    }

    fn get_name(&self) -> String {
        self.name.clone()
    }

    fn get_state_dir(&self) -> String {
        self.state_dir.clone()
    }

    fn get_video_dir(&self) -> String {
        self.video_dir.clone()
    }
}

struct RpiCameraVideoParameters {
    sps: Vec<u8>,
    pps: Vec<u8>,
}

impl RpiCameraVideoParameters {
    pub fn new(sps: Vec<u8>, pps: Vec<u8>) -> Self {
        Self { sps, pps }
    }
}

//FIXME: Do we need to modify this for the Raspberry PI implementation?
impl CodecParameters for RpiCameraVideoParameters {
    fn write_codec_box(&self, buf: &mut BytesMut) -> Result<(), Error> {
        write_box!(buf, b"avc1", {
            buf.put_u32(0); // predefined & reserved
            buf.put_u32(1); // data reference index
            buf.put_u32(0); // reserved
            buf.put_u64(0); // reserved
            buf.put_u32(0); // reserved
            buf.put_u16(WIDTH as u16); // width
            buf.put_u16(HEIGHT as u16); // height
            let dpi = 72 << 16;
            buf.put_u32(dpi); // horizontal_resolution
            buf.put_u32(dpi); // vertical_resolution
            buf.put_u32(0); // reserved
            buf.put_u16(1); // frame count
            for _ in 0..32 {
                // compressor name
                buf.put_u8(0);
            }
            buf.put_u16(0x0018); // depth
            buf.put_u16(0xffff); // pre-defined

            write_box!(buf, b"avcC", {
                buf.put_u8(1); // configuration version
                buf.put_u8(self.sps[1]); // avc profile indication
                buf.put_u8(self.sps[2]); // profile compatibility
                buf.put_u8(self.sps[3]); // avc level indication
                buf.put_u8(0xfc | 3); // Reserved (6 bits) + LengthSizeMinusOne (2 bits)
                buf.put_u8(0xe0 | 1); // Reserved (3 bits) + numOfSequenceParameterSets (5 bits)
                                      //sequence_parameter_sets (SPS)
                buf.extend_from_slice(&(self.sps.len() as u16).to_be_bytes()); // len of sps
                buf.extend_from_slice(&self.sps);
                //picture_parameter_sets (PPS)
                buf.put_u8(1); // number of pps sets
                buf.extend_from_slice(&(self.pps.len() as u16).to_be_bytes()); // len of pps
                buf.extend_from_slice(&self.pps);
            });
        });

        Ok(())
    }

    // Not used
    fn get_clock_rate(&self) -> u32 {
        0
    }

    fn get_dimensions(&self) -> (u32, u32) {
        let width = (WIDTH as u32) << 16;
        let height = (HEIGHT as u32) << 16;

        (width, height)
    }
}

// Not used for now.
#[derive(Default)]
struct RpiCameraAudioParameters {}

impl CodecParameters for RpiCameraAudioParameters {
    fn write_codec_box(&self, _buf: &mut BytesMut) -> Result<(), Error> {
        Ok(())
    }

    // Not used
    fn get_clock_rate(&self) -> u32 {
        0
    }

    fn get_dimensions(&self) -> (u32, u32) {
        (0, 0)
    }
}
