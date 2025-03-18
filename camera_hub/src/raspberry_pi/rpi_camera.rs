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

use std::sync::atomic::{AtomicI64, Ordering};
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
use tokio::runtime::Runtime;

use crate::traits::Mp4;
use crate::{
    delivery_monitor::VideoInfo,
    fmp4::Fmp4Writer,
    livestream::LivestreamWriter,
    mp4::Mp4Writer,
    raspberry_pi::rpi_dual_stream::SharedCameraStream,
    raspberry_pi::rpi_motion_detection::MotionDetection,
    traits::{Camera, CodecParameters},
    write_box,
};

//These are for our local SPS/PPS channel

#[derive(PartialEq, Debug, Clone)]
pub enum VideoFrameKind {
    RFrame,
    IFrame,
    Sps,
    Pps,
}

static FRAME_COUNTER: AtomicI64 = AtomicI64::new(0);
static LAST_PROCESSED_SEQ: AtomicI64 = AtomicI64::new(-1); // We use -1 to allow the first frame to expect 0 as the next.

#[derive(Debug, Clone)]
pub struct VideoFrame {
    pub data: Vec<u8>,
    pub kind: VideoFrameKind,
    pub timestamp: Instant,
    pub seq: i64, // Unique sequence number
}

impl VideoFrame {
    pub fn new(data: Vec<u8>, kind: VideoFrameKind) -> Self {
        let seq = FRAME_COUNTER.fetch_add(1, Ordering::SeqCst);
        Self {
            data,
            kind,
            timestamp: Instant::now(),
            seq,
        }
    }
}

/// RaspberryPiCamera uses the shared stream for both motion detection (via raw frames) and recording/livestreaming (via H.264).
pub struct RaspberryPiCamera {
    name: String,
    state_dir: String,
    video_dir: String,
    frame_queue: Arc<Mutex<VecDeque<VideoFrame>>>,
    sps_frame: VideoFrame,
    pps_frame: VideoFrame,
    motion_detection: MotionDetection,
}

impl RaspberryPiCamera {
    pub fn new(name: String, state_dir: String, video_dir: String, motion_fps: u64) -> Self {
        // Frame queue holds recently processed H.264 frames.
        let frame_queue = Arc::new(Mutex::new(VecDeque::new()));
        println!("Initializing Raspberry Pi Camera...");

        // Start the new shared stream.
        let shared_stream =
            Arc::new(SharedCameraStream::start().expect("Failed to start shared stream"));

        // Create a channel to receive SPS/PPS frames.
        let (ps_tx, ps_rx) = unbounded::<VideoFrame>();

        let frame_queue_clone = Arc::clone(&frame_queue);
        let shared_stream_clone = Arc::clone(&shared_stream);

        // Spawn a thread to process H.264 data from the shared stream and capture the SPS/PPS frames.
        thread::spawn(move || {
            let mut buffer = BytesMut::with_capacity(1024 * 1024);
            let mut sps_sent = false;
            let mut pps_sent = false;

            // Local sequence enforcer for input from the ring buffer
            let mut last_input_seq: u64 = 0;
            while let Some(chunk) = shared_stream_clone.h264_buffer.acquire_frame() {
                // Enforce sequence ordering for the incoming chunk.
                if chunk.seq != last_input_seq + 1 {
                    println!(
                        "Input sequence gap: expected {} but got {}. Frame seq {} may be out-of-order.",
                        last_input_seq + 1,
                        chunk.seq,
                        chunk.seq
                    );
                }
                last_input_seq = chunk.seq;

                buffer.extend_from_slice(&chunk.data);
                while let Some(mut frame) = Self::extract_h264_frame(&mut buffer) {
                    // Update the frame timestamp on extraction.
                    frame.timestamp = Instant::now();

                    if !sps_sent && frame.kind == VideoFrameKind::Sps {
                        let _ = ps_tx.send(frame.clone());
                        sps_sent = true;
                    }
                    if !pps_sent && frame.kind == VideoFrameKind::Pps {
                        let _ = ps_tx.send(frame.clone());
                        pps_sent = true;
                    }
                    Self::add_frame_and_drop_old(Arc::clone(&frame_queue_clone), frame);
                }
            }
        });

        // Wait for the SPS and PPS frames before continuing.
        // TODO: Handle an error at some point. There's no timeout, so this will hang forever if there's a failure in libcamera-vid
        let mut sps_frame_opt = None;
        let mut pps_frame_opt = None;
        while sps_frame_opt.is_none() || pps_frame_opt.is_none() {
            let frame = ps_rx.recv().expect("Failed to receive frame");
            match frame.kind {
                VideoFrameKind::Sps => sps_frame_opt = Some(frame),
                VideoFrameKind::Pps => pps_frame_opt = Some(frame),
                _ => {} // ignore unexpected frames
            }
        }
        let sps_frame = sps_frame_opt.expect("SPS frame missing");
        let pps_frame = pps_frame_opt.expect("PPS frame missing");

        // Start motion detection using raw frames from the shared stream.
        let motion_detection = MotionDetection::new(motion_fps, shared_stream.clone())
            .expect("Failed to start motion detection");

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

    const MAX_FRAME_QUEUE_CAPACITY: usize = 50;

    fn add_frame_and_drop_old(frame_queue: Arc<Mutex<VecDeque<VideoFrame>>>, frame: VideoFrame) {
        let time_window = Duration::new(5, 0);
        let mut queue = frame_queue.lock().unwrap();

        // Enforce sequence ordering
        let last_processed = LAST_PROCESSED_SEQ.load(Ordering::SeqCst);
        if frame.seq != last_processed + 1 {
            debug!(
                "Output sequence gap: expected {} but got {}. Dropping frame if duplicate or out-of-order.",
                last_processed + 1,
                frame.seq
            );
        }
        if frame.seq <= last_processed {
            debug!(
                "Global check: Frame seq {} is not greater than last processed seq {}. Dropping frame.",
                frame.seq,
                last_processed
            );
            return;
        }

        queue.push_back(frame.clone());

        // Update the global last processed sequence counter.
        LAST_PROCESSED_SEQ.store(frame.seq, Ordering::SeqCst);

        // Enforce a fixed capacity (via ring buffer)
        while queue.len() > Self::MAX_FRAME_QUEUE_CAPACITY {
            queue.pop_front();
        }

        // Also remove frames older than the time window.
        while let Some(front) = queue.front() {
            if Instant::now().duration_since(front.timestamp) > time_window {
                queue.pop_front();
            } else {
                break;
            }
        }
    }

    /// A modified H264 extraction frame method when I had issues working with the old ip.rs one
    fn extract_h264_frame(buffer: &mut BytesMut) -> Option<VideoFrame> {
        let start_code = &[0x00, 0x00, 0x00, 0x01];
        let short_start_code = &[0x00, 0x00, 0x01];

        // Find the first start code
        let start = buffer
            .windows(4)
            .position(|w| w == start_code)
            .or_else(|| buffer.windows(3).position(|w| w == short_start_code))?;

        let start_code_len = if buffer[start..].starts_with(start_code) {
            4
        } else {
            3
        };
        let next_search_start = start + start_code_len;
        let end = buffer[next_search_start..]
            .windows(4)
            .position(|w| w == start_code)
            .or_else(|| {
                buffer[next_search_start..]
                    .windows(3)
                    .position(|w| w == short_start_code)
            })
            .map(|pos| next_search_start + pos)
            .unwrap_or(buffer.len());

        // Extract the NAL unit by skipping the start code.
        let nal_unit = buffer.split_to(end).split_off(start + start_code_len);
        if nal_unit.is_empty() {
            return None;
        }

        let nal_unit_type = nal_unit[0] & 0x1F;
        let mut prefixed = Vec::new();
        Self::append_length_prefixed_nal(&mut prefixed, &nal_unit);

        match nal_unit_type {
            7 => Some(VideoFrame::new(prefixed, VideoFrameKind::Sps)),
            8 => Some(VideoFrame::new(prefixed, VideoFrameKind::Pps)),
            5 => Some(VideoFrame::new(prefixed, VideoFrameKind::IFrame)),
            1 => Some(VideoFrame::new(prefixed, VideoFrameKind::RFrame)),
            _ => None,
        }
    }

    fn append_length_prefixed_nal(output: &mut Vec<u8>, nal: &[u8]) {
        let nal_length = nal.len() as u32;
        output.extend_from_slice(&nal_length.to_be_bytes()); // 4-byte big-endian length prefix
        output.extend_from_slice(nal); // Append the NAL unit itself
    }

    /// Writes the `.mp4`, including trying to finish or clean up the file.
    async fn write_mp4(
        filename: String,
        duration: u64,
        frame_queue: Arc<Mutex<VecDeque<VideoFrame>>>,
        sps_frame: VideoFrame,
        pps_frame: VideoFrame,
    ) -> Result<(), Error> {
        let file = tokio::fs::File::create(&filename).await?;
        let mut mp4 = Mp4Writer::new(
            RpiCameraVideoParameters::new(
                sps_frame.data[4..].to_vec(),
                pps_frame.data[4..].to_vec(),
            ),
            RpiCameraAudioParameters::default(),
            file,
        )
        .await?;
        Self::copy(&mut mp4, Some(duration), frame_queue).await?;
        mp4.finish().await?;

        // FIXME: do we need to wait for teardown here?
        // Session has now been dropped, on success or failure. A TEARDOWN should
        // be pending if necessary. session_group.await_teardown() will wait for it.
        //if let Err(e) = session_group.await_teardown().await {
        //    log::error!("TEARDOWN failed: {}", e);
        //}

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

    async fn copy<'a, M: Mp4>(
        mp4: &'a mut M,
        duration: Option<u64>,
        frame_queue: Arc<Mutex<VecDeque<VideoFrame>>>,
    ) -> Result<(), Error> {
        let recording_window = match duration {
            Some(secs) => Some(Duration::new(secs, 0)),
            None => None,
        };
        let recording_start_time = Instant::now();
        let mut first_frame_found = false;

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

            if frame.kind == VideoFrameKind::IFrame {
                first_frame_found = true;
                if let Err(_e) = mp4.finish_fragment().await {
                    // This will be executed when livestream ends.
                    // This is a no op for recording an .mp4 file
                    // log::error!(".mp4 finish failed: {}", e);
                    break;
                }
            }

            if first_frame_found {
                //FIXME: we already determined whether the frame was an i-frame or not. Keep that in a vec to avoid recomputing?
                let frame_timestamp: u64 = frame
                    .timestamp
                    .duration_since(recording_start_time)
                    .as_micros()
                    .try_into()
                    .unwrap();
                mp4.video(
                    &frame.data,
                    frame_timestamp / 10,
                    frame.kind == VideoFrameKind::IFrame,
                )
                .await
                .with_context(|| format!("Error processing video frame"))?;
            }
            drop(queue);

            if let Some(window) = recording_window {
                if frame.timestamp.duration_since(recording_start_time) > window {
                    log::info!("Stopping the recording.");
                    break;
                }
            }
        }

        Ok(())
    }
}

impl Camera for RaspberryPiCamera {
    fn is_there_motion(&mut self) -> io::Result<bool> {
        self.motion_detection.handle_motion_event()
    }

    fn record_motion_video(&self, info: &VideoInfo) -> io::Result<()> {
        let rt = Runtime::new()?;

        let future = Self::write_mp4(
            self.video_dir.clone() + "/" + &info.filename,
            20,
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
                            //FIXME: hardcoded
            buf.put_u16(1920); // width
            buf.put_u16(1080); // height
            buf.put_u32(0x0048); // horizontal resolution
            buf.put_u32(0x0048); // vertical resolution
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
        //FIXME: hardcoded
        let width = (1920u32) << 16;
        let height = (1080u32) << 16;

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
