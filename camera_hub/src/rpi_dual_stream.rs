//! Code to implement dual streaming (such that, we stream the raw frames and concurrently convert them to H.264)
//! Assumes the cameras supports YUV420 codec and has ffmpeg and libcamera installed.
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

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::{
    io::{BufReader, Read, Write},
    process::{Command, Stdio},
    thread,
    time::{Duration, SystemTime},
};

use anyhow::{anyhow, Error};
use bytes::BytesMut;

pub const WIDTH: u32 = 1920; //TODO: for YUV420 to work properly with this code, this must be divisible by 64. Consider using padding for other resolution support in the future (if need be)

pub const HEIGHT: u32 = 1080;
pub const FRAMERATE: u32 = 30;

/// For 8-bit yuv420p, frame size = width * height * 3/2 bytes.
pub const FRAME_SIZE_8BIT: usize = (WIDTH as usize * HEIGHT as usize * 3) / 2;

static H264_FRAME_COUNTER: AtomicU64 = AtomicU64::new(0);
static LAST_PROCESSED_H264_SEQ: AtomicU64 = AtomicU64::new(0);

static RAW_FRAME_COUNTER: AtomicU64 = AtomicU64::new(0);
static LAST_PROCESSED_RAW_SEQ: AtomicU64 = AtomicU64::new(0);

pub struct H264RingBuffer {
    inner: Mutex<VecDeque<H264Frame>>,
    capacity: usize,
}

impl H264RingBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
        }
    }

    /// Push a new frame. If the buffer is full, drop the oldest frame.
    pub fn push(&self, frame: H264Frame) {
        let mut queue = self.inner.lock().unwrap();
        if queue.len() >= self.capacity {
            if let Some(old) = queue.pop_front() {
                debug!(
                    "H264RingBuffer: Dropping oldest frame with seq {} to make room for new frame seq {}.",
                    old.seq,
                    frame.seq
                );
            }
        }
        queue.push_back(frame);
    }

    //TODO: Make this exit gracefully when force shutting down...
    //TODO: If we decide to use multiple ffmpeg workers in the future, put a lock on this
    pub fn acquire_frame(&self) -> Option<H264Frame> {
        loop {
            let mut queue = self.inner.lock().unwrap();
            if let Some(frame) = queue.front() {
                let last_proc = LAST_PROCESSED_H264_SEQ.load(Ordering::SeqCst);
                if frame.seq > last_proc {
                    // The earliest frame is newer than the last processed.
                    let frame = queue.pop_front();
                    if let Some(frame) = frame {
                        LAST_PROCESSED_H264_SEQ.store(frame.seq, Ordering::SeqCst);
                        return Some(frame);
                    }
                } else {
                    // This frame is outdated, so drop it.
                    queue.pop_front();
                }
            }
            drop(queue);
            std::thread::sleep(Duration::from_millis(10)); //TODO: We could replace busy waiting
        }
    }
}

/// A simple generic ring buffer.
/// TODO: Combine H264 and the generic ring buffer into each other
pub struct RingBuffer<T> {
    inner: Mutex<VecDeque<T>>,
    capacity: usize,
}

impl<T> RingBuffer<T> {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
        }
    }

    /// Push an item into the buffer.
    /// If the buffer is full, drop the oldest element.
    pub fn push(&self, item: T) {
        let mut queue = self.inner.lock().unwrap();
        if queue.len() >= self.capacity {
            if let Some(_old) = queue.pop_front() {
                debug!("RingBuffer: Dropping an old item to make room.");
            }
        }
        queue.push_back(item);
    }

    /// Pop the oldest item from the buffer.
    pub fn pop(&self) -> Option<T> {
        let mut queue = self.inner.lock().unwrap();
        queue.pop_front()
    }

    /// Block until an item is available and return it.
    pub fn acquire(&self) -> T {
        loop {
            if let Some(item) = self.pop() {
                return item;
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}

/// Represents a single raw YUV420 frame captured from libcamera.
#[derive(Clone)]
pub struct RawFrame {
    pub data: Vec<u8>,
    pub seq: u64,
    pub timestamp: SystemTime,
}

/// Represents a complete H.264 output from ffmpeg
#[derive(Clone)]
pub struct H264Frame {
    pub data: Vec<u8>,
    pub seq: u64,
}

/// Provides two channels: one for raw YUV420 frames from libcamera‑vid, one for H.264 frames converted by FFmpeg.
pub struct SharedCameraStream {
    pub raw_buffer: Arc<RingBuffer<RawFrame>>,
    pub h264_buffer: Arc<H264RingBuffer>,
}

impl SharedCameraStream {
    pub fn start() -> Result<Self, Error> {
        const RAW_BUFFER_CAPACITY: usize = 50;
        const FFMPEG_INPUT_CAPACITY: usize = 50;
        const H264_RING_CAPACITY: usize = 50;

        // Create ring buffers for raw frames and for ffmpeg input.
        let raw_buffer = Arc::new(RingBuffer::<RawFrame>::new(RAW_BUFFER_CAPACITY));
        let ffmpeg_input_buffer = Arc::new(RingBuffer::<RawFrame>::new(FFMPEG_INPUT_CAPACITY));

        // Create the ring buffer for H264 frames.
        let h264_buffer = Arc::new(H264RingBuffer::new(H264_RING_CAPACITY));

        // Spawn libcamera‑vid with output directed to stdout (to get rid of TCP dependency for reduced complexity)
        let libcamera_cmd = format!(
            "libcamera-vid -t 0 -n --width {} --height {} --framerate {} --codec yuv420 -o -",
            WIDTH, HEIGHT, FRAMERATE
        );
        let mut libcamera_child = Command::new("sh")
            .arg("-c")
            .arg(libcamera_cmd)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let stdout = libcamera_child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("Failed to capture stdout from libcamera-vid"))?;
        let mut reader = BufReader::new(stdout);

        // We have separation of the initial frame and the ending frames in case we need to move to a different implementation at some point

        let mut probe_buffer = Vec::new();
        let start_probe = SystemTime::now();
        while probe_buffer.len() < FRAME_SIZE_8BIT {
            let mut chunk = vec![0u8; 8192];
            match reader.read(&mut chunk) {
                Ok(n) => {
                    probe_buffer.extend_from_slice(&chunk[..n]);
                }
                Err(e) => {
                    eprintln!("Error during probing: {:?}", e);
                    break;
                }
            }
            if start_probe.elapsed().unwrap() > Duration::from_millis(500) {
                break;
            }
        }

        // Create a combined buffer starting with the already-read probe data
        let mut combined_buffer = probe_buffer;
        // Spawn a thread that will continuously read full frames from libcamera-vid's stdout
        {
            let raw_buffer = Arc::clone(&raw_buffer);
            let mut reader = reader;
            thread::spawn(move || {
                loop {
                    // Ensure we have a full frame.
                    while combined_buffer.len() < FRAME_SIZE_8BIT {
                        let mut chunk = vec![0u8; 8192];
                        match reader.read(&mut chunk) {
                            Ok(n) => combined_buffer.extend_from_slice(&chunk[..n]),
                            Err(e) => {
                                eprintln!("Error reading additional data: {:?}", e);
                                return;
                            }
                        }
                    }
                    // Extract one full frame.
                    let frame_data = combined_buffer
                        .drain(..FRAME_SIZE_8BIT)
                        .collect::<Vec<u8>>();
                    let raw_frame = RawFrame {
                        data: frame_data,
                        seq: RAW_FRAME_COUNTER.fetch_add(1, Ordering::SeqCst),
                        timestamp: SystemTime::now(),
                    };
                    raw_buffer.push(raw_frame);
                }
            });
        }

        // Spawn a ffmpeg process for H.264 conversion using the Raspberry Pi hardware GPU (for offloading CPU)
        // This uses a 4 M/s bit rate, YUV420 pixel format from raw video
        let ffmpeg_cmd = format!(
            "ffmpeg -hide_banner -loglevel error -y -f rawvideo -pix_fmt yuv420p -s {}x{} -r {} -i pipe:0 -c:v h264_v4l2m2m -b:v 4M -pix_fmt yuv420p -f h264 pipe:1",
            WIDTH, HEIGHT, FRAMERATE
        );

        let mut ffmpeg_child = Command::new("sh")
            .arg("-c")
            .arg(ffmpeg_cmd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow!("Failed to spawn ffmpeg: {:?}", e))?;
        let mut ffmpeg_stdin = ffmpeg_child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("Failed to open ffmpeg stdin"))?;
        let ffmpeg_stdout = ffmpeg_child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("Failed to open ffmpeg stdout"))?;

        // Spawn a thread to feed ffmpeg_input_buffer from raw_buffer.
        {
            let raw_buffer = Arc::clone(&raw_buffer);
            let ffmpeg_input_buffer = Arc::clone(&ffmpeg_input_buffer);
            thread::spawn(move || {
                loop {
                    // Enforce ordering for raw frames similar to our H264 ordering...
                    let raw_frame = loop {
                        if let Some(frame) = raw_buffer.pop() {
                            let last_proc = LAST_PROCESSED_RAW_SEQ.load(Ordering::SeqCst);
                            if frame.seq > last_proc {
                                LAST_PROCESSED_RAW_SEQ.store(frame.seq, Ordering::SeqCst);
                                break frame;
                            } else {
                                // This frame is outdated; skip it.
                                continue;
                            }
                        }
                        thread::sleep(Duration::from_millis(10));
                    };
                    // Send the frame's data to the ffmpeg input buffer.
                    ffmpeg_input_buffer.push(raw_frame);
                }
            });
        }
        {
            let ffmpeg_input_buffer = Arc::clone(&ffmpeg_input_buffer);
            thread::spawn(move || {
                let mut last_written_seq = None;
                loop {
                    let raw_frame = ffmpeg_input_buffer.acquire();
                    // Verify that the current frame's sequence is greater than the last.
                    if let Some(last_seq) = last_written_seq {
                        if raw_frame.seq <= last_seq {
                            debug!(
                        "Out-of-order raw frame detected: expected a frame with seq greater than {} but got {}.",
                        last_seq,
                        raw_frame.seq
                    );
                            // Optionally, skip this frame or handle the error.
                            continue;
                        }
                    }
                    if let Err(e) = ffmpeg_stdin.write_all(&raw_frame.data) {
                        eprintln!("Error writing to ffmpeg stdin: {:?}", e);
                        break;
                    }
                    last_written_seq = Some(raw_frame.seq);
                }
            });
        }

        // Spawn a thread to read ffmpeg's stdout and extract H.264 frames.
        {
            let h264_buffer_clone = Arc::clone(&h264_buffer);
            thread::spawn(move || {
                let mut reader = BufReader::new(ffmpeg_stdout);
                let mut buffer = BytesMut::with_capacity(1024 * 1024);
                loop {
                    let mut temp_buf = [0u8; 8192];
                    match reader.read(&mut temp_buf) {
                        Ok(0) => {
                            eprintln!("ffmpeg stdout closed.");
                            break;
                        }
                        Ok(n) => {
                            buffer.extend_from_slice(&temp_buf[..n]);
                            while let Some(nal_unit) = Self::extract_h264_frame(&mut buffer) {
                                let h264_frame = H264Frame {
                                    data: nal_unit,
                                    seq: H264_FRAME_COUNTER.fetch_add(1, Ordering::SeqCst),
                                };

                                h264_buffer_clone.push(h264_frame);
                            }
                        }
                        Err(e) => {
                            eprintln!("Error reading ffmpeg stdout: {:?}", e);
                            break;
                        }
                    }
                }
            });
        }

        Ok(SharedCameraStream {
            raw_buffer,
            h264_buffer,
        })
    }

    /// Extract a complete H.264 NAL unit from the buffer.
    fn extract_h264_frame(buffer: &mut BytesMut) -> Option<Vec<u8>> {
        let start_code = [0x00, 0x00, 0x00, 0x01];
        let alt_start_code = [0x00, 0x00, 0x01];

        let start = if let Some(pos) = buffer.windows(4).position(|w| w == start_code) {
            pos
        } else if let Some(pos) = buffer.windows(3).position(|w| w == alt_start_code) {
            pos
        } else {
            return None;
        };

        let start_code_len = if buffer[start..].starts_with(&start_code) {
            4
        } else {
            3
        };
        let next_search = start + start_code_len;
        let next = if let Some(pos) = buffer[next_search..]
            .windows(4)
            .position(|w| w == start_code)
        {
            next_search + pos
        } else if let Some(pos) = buffer[next_search..]
            .windows(3)
            .position(|w| w == alt_start_code)
        {
            next_search + pos
        } else {
            return None;
        };

        let nal_unit = buffer.split_to(next);
        Some(nal_unit.to_vec())
    }
}
