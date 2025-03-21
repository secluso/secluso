//! Code to implement dual streaming (such that, we stream the raw frames and H.264 frames concurrently from rpicam-vid)
//! Assumes the cameras has the rpicam-apps fork built and installed.
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
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::Instant;
use std::{
    io::{BufReader, Read, Write},
    process::{Command, Stdio},
    thread,
    time::{Duration, SystemTime},
};

use crate::raspberry_pi::rpi_camera::{VideoFrame, VideoFrameKind};
use anyhow::anyhow;
use bytes::BytesMut;
use crossbeam_channel::Sender;

/// Represents a single raw YUV420 frame captured from rpicam.
#[derive(Clone)]
pub struct RawFrame {
    pub data: Vec<u8>,
    pub timestamp: SystemTime,
}

/// Provides two channels: one for raw YUV420 frames from rpicam‑vid (for motion detection), one for H.264 frames converted by rpicam-vid.
pub fn start(
    width: usize,
    height: usize,
    total_frame_rate: usize,
    motion_latest_frame: Arc<Mutex<Option<RawFrame>>>,
    frame_queue: Arc<Mutex<VecDeque<VideoFrame>>>,
    ps_tx: Sender<VideoFrame>,
    motion_fps: u8,
) -> Result<(), Box<dyn std::error::Error>> {
    // For 8-bit yuv420p, frame size = width * height * 3/2 bytes.
    let frame_size: usize = (width * height * 3) / 2;

    // Spawn rpicam‑vid with output directed to stdout (to get rid of TCP dependency for reduced complexity)
    let rpicam_cmd = format!(
        "rpicam-vid -t 0 -n --width {} --height {} --framerate {} --codec h264 -o -",
        width, height, total_frame_rate
    );
    let mut rpicam_child = Command::new("sh")
        .arg("-c")
        .arg(rpicam_cmd)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let rpicam_stdout = rpicam_child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("Failed to capture stdout from rpicam-vid"))?;

    // Spawn a thread to read rpicam's stdout and extract H.264 frames.
    {
        thread::spawn(move || {
            let mut reader = BufReader::new(rpicam_stdout);
            let mut buffer = BytesMut::with_capacity(1024 * 1024);
            let mut sps_sent = false;
            let mut pps_sent = false;
            loop {
                let mut temp_buf = [0u8; 8192];
                match reader.read(&mut temp_buf) {
                    Ok(0) => {
                        eprintln!("rpicam stdout closed.");
                        break;
                    }
                    Ok(n) => {
                        buffer.extend_from_slice(&temp_buf[..n]);
                        match extract_h264_frame(&mut buffer) {
                            Ok(h264_frame2) => {
                                if let Some(mut frame) = h264_frame2 {
                                    // Update the frame timestamp on extraction.
                                    frame.timestamp = Instant::now();

                                    debug!(
                                        "Extracted frame kind: {:?}, size: {} bytes",
                                        frame.kind,
                                        frame.data.len()
                                    );

                                    if !sps_sent && frame.kind == VideoFrameKind::Sps {
                                        let _ = ps_tx.send(frame.clone());
                                        sps_sent = true;
                                    }
                                    if !pps_sent && frame.kind == VideoFrameKind::Pps {
                                        let _ = ps_tx.send(frame.clone());
                                        pps_sent = true;
                                    }

                                    add_frame_and_drop_old(Arc::clone(&frame_queue), frame);
                                }
                            }
                            Err(e) => {
                                println!("Got error {:?}", e);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Error reading rpicam stdout: {:?}", e);
                        break;
                    }
                }
            }
        });
    }

    // Spawn a thread that will continuously read full frames from a UNIX domain socket in the modified rpicam-vid
    {
        thread::spawn(move || {
            let stream_attempt: Option<UnixStream> = connect_to_socket();
            if stream_attempt.is_none() {
                panic!("Was unable to connect to the rpicam-vid socket. Are you using the built rpicam-apps privastead fork?");
            }

            let mut stream = stream_attempt.unwrap(); // Unwrap will work since we checked is_none()

            // Write the motion_fps we want the output to synchronize to for maximum efficiency.
            if let Err(e) = stream.write(&[motion_fps]) {
                panic!("Failed to write Motion FPS to rpicam-vid: {:?}", e);
            }

            // Continuously read in frames from the secondary stream
            loop {
                let mut buffer = vec![0u8; frame_size];

                match stream.read_exact(&mut buffer) {
                    Ok(_) => {
                        let raw_frame = RawFrame {
                            data: buffer,
                            timestamp: SystemTime::now(),
                        };

                        {
                            let mut lock = motion_latest_frame.lock().unwrap();
                            *lock = Some(raw_frame);
                        }
                    }
                    Err(e) => {
                        panic!(
                            "Error reading from UNIX domain socket from secondary stream: {:?}",
                            e
                        );
                    }
                }
            }
        });

        return Ok(());
    }
}

/// Connect to the secondary lib camera stream (UNIX domain socket)
/// https://man7.org/linux/man-pages/man7/unix.7.html
fn connect_to_socket() -> Option<UnixStream> {
    for _ in 0..30 {
        if let Ok(stream) = UnixStream::connect("/tmp/rpi_raw_frame_socket") {
            return Some(stream); // Return immediately on success
        }
        sleep(Duration::from_secs(1)); // Wait before retrying
    }

    None // If all attempts fail, we return None.
}

fn add_frame_and_drop_old(frame_queue: Arc<Mutex<VecDeque<VideoFrame>>>, frame: VideoFrame) {
    let time_window = Duration::new(5, 0);
    let mut queue = frame_queue.lock().unwrap();
    queue.push_back(frame.clone());

    // Remove frames older than the time window.
    while let Some(front) = queue.front() {
        if Instant::now().duration_since(front.timestamp) > time_window {
            queue.pop_front();
        } else {
            break;
        }
    }
}

/// A modified H264 extraction frame method when I had issues working with the old ip.rs one
fn extract_h264_frame(buffer: &mut BytesMut) -> anyhow::Result<Option<VideoFrame>> {
    const MAX_NAL_UNIT_SIZE: usize = 2 * 1024 * 1024; // 2 MB maximum

    // Instead of discarding data, require the buffer to begin with a valid start code.
    if !buffer.starts_with(&[0, 0, 0, 1]) && !buffer.starts_with(&[0, 0, 1]) {
        println!(
            "Buffer not aligned (head: {:02x?}), waiting for more data.",
            &buffer[..std::cmp::min(buffer.len(), 16)]
        );
        return Ok(None);
    }

    // Determine the start code length.
    let start_code_len = if buffer.starts_with(&[0, 0, 0, 1]) {
        4
    } else {
        3
    };

    // Ensure we have at least one byte after the start code (for the NAL header).
    if buffer.len() < start_code_len + 1 {
        return Ok(None);
    }

    // Look for the next start code in the remaining data.
    let search_start = start_code_len;
    let next_start_opt = if let Some(pos) = buffer[search_start..]
        .windows(4)
        .position(|w| w == [0, 0, 0, 1])
    {
        Some(search_start + pos)
    } else if let Some(pos) = buffer[search_start..]
        .windows(3)
        .position(|w| w == [0, 0, 1])
    {
        Some(search_start + pos)
    } else {
        // No subsequent start code found; wait for more data.
        return Ok(None);
    };

    // The bytes from the beginning up to the next start code form one NAL unit.
    let nal_end = next_start_opt.unwrap();
    let nal_unit = buffer.split_to(nal_end);

    // --- Integrity Checks ---
    if nal_unit.len() < start_code_len + 1 {
        return Err(anyhow::anyhow!(
            "Extracted NAL unit is too short: {} bytes",
            nal_unit.len()
        ));
    }
    if nal_unit.len() > MAX_NAL_UNIT_SIZE {
        return Err(anyhow::anyhow!(
            "Extracted NAL unit exceeds maximum allowed size: {} bytes",
            nal_unit.len()
        ));
    }

    let expected_start_code: &[u8] = if start_code_len == 4 {
        &[0, 0, 0, 1]
    } else {
        &[0, 0, 1]
    };

    if !nal_unit.starts_with(expected_start_code) {
        // Instead of discarding, we now report an error.
        return Err(anyhow::anyhow!(
            "NAL unit does not start with a valid start code: {:02x?}",
            &nal_unit[..std::cmp::min(nal_unit.len(), 16)]
        ));
    }

    // Extract the NAL header (first byte after the start code) and determine the NAL type.
    let nal_header = nal_unit[start_code_len];
    let nal_type = nal_header & 0x1F;
    if nal_type > 31 {
        return Err(anyhow::anyhow!("Invalid NAL type: {}", nal_type));
    }
    if nal_unit.len() <= start_code_len + 1 {
        return Err(anyhow::anyhow!("NAL unit payload is empty"));
    }

    let kind = match nal_type {
        7 => VideoFrameKind::Sps,
        8 => VideoFrameKind::Pps,
        5 => VideoFrameKind::IFrame,
        1 => VideoFrameKind::RFrame,
        _ => VideoFrameKind::RFrame, // Extend as needed.
    };

    Ok(Some(VideoFrame::new(nal_unit.to_vec(), kind)))
}
