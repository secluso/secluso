//! Code to implement dual streaming (such that, we stream the raw frames and H.264 frames concurrently from rpicam-vid)
//! Assumes the cameras has the rpicam-apps fork built and installed.
//!
//! SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::VecDeque;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::{SystemTime};
use std::{
    io::{BufReader, Read, Write},
    process::{Command, Stdio},
    thread,
    time::Duration,
};
use bytes::Buf;

use crate::mp4::mp4_camera::{Frame, FrameKind};
use anyhow::anyhow;
use bytes::BytesMut;
use crossbeam_channel::Sender;
use secluso_motion_ai::frame::RawFrame;
use secluso_motion_ai::logic::pipeline::PipelineController;

/// Provides two channels: one for raw YUV420 frames from rpicam‑vid (for motion detection), one for H.264 frames converted by rpicam-vid.
#[allow(clippy::too_many_arguments)]
pub fn start(
    width: usize,
    height: usize,
    total_frame_rate: usize,
    i_frame_interval: usize,
    pipeline_controller: Arc<Mutex<PipelineController>>,
    frame_queue: Arc<Mutex<VecDeque<Frame>>>,
    ps_tx: Sender<Frame>,
    motion_fps: u8,
) -> Result<(), Box<dyn std::error::Error>> {
    // For 8-bit yuv420p, frame size = width * height * 3/2 bytes.
    // However, we need to take into account how the width is padded to 64-bytes.
    // This is for a row-aligned format from V4L2 for DMA transfer alignment.
    let yuv_width = width.div_ceil(64) * 64;
    let yuv_height = height;
    let yuv_frame_size = yuv_width * yuv_height * 3 / 2;

    // Spawn rpicam‑vid with output directed to stdout (to get rid of TCP dependency for reduced complexity)
    let rpicam_cmd = format!(
        "rpicam-vid --awb tungsten -t 0 -n --width {} --height {} --framerate {} --codec h264 --intra {} -o -",
        width, height, total_frame_rate, i_frame_interval
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
                                    frame.timestamp = SystemTime::now();

                                    if !sps_sent && frame.kind == FrameKind::Sps {
                                        let _ = ps_tx.send(frame.clone());
                                        sps_sent = true;
                                    }
                                    if !pps_sent && frame.kind == FrameKind::Pps {
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
                panic!("Was unable to connect to the rpicam-vid socket. Are you using the built rpicam-apps secluso fork?");
            }

            let mut stream = stream_attempt.unwrap(); // Unwrap will work since we checked is_none()

            // Write the motion_fps we want the output to synchronize to for maximum efficiency.
            if let Err(e) = stream.write(&[motion_fps]) {
                panic!("Failed to write Motion FPS to rpicam-vid: {:?}", e);
            }

            // Continuously read in frames from the secondary stream
            loop {
                let mut buffer = vec![0u8; yuv_frame_size];

                match stream.read_exact(&mut buffer) {
                    Ok(_) => {
                        let raw_frame = RawFrame::create_from_buffer(buffer, width, height);
                        {
                            let mut lock = pipeline_controller.lock().unwrap();
                            lock.push_frame(raw_frame);
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

        Ok(())
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

fn add_frame_and_drop_old(frame_queue: Arc<Mutex<VecDeque<Frame>>>, frame: Frame) {
    let time_window = Duration::new(5, 0);
    let mut queue = frame_queue.lock().unwrap();
    queue.push_back(frame.clone());

    // Remove frames older than the time window.
    while let Some(front) = queue.front() {
        if SystemTime::now()
            .duration_since(front.timestamp)
            .unwrap_or_default()
            > time_window
        {
            queue.pop_front();
        } else {
            break;
        }
    }
}

/// A modified H264 extraction frame method when I had issues working with the old ip.rs one
fn extract_h264_frame(buffer: &mut BytesMut) -> anyhow::Result<Option<Frame>> {
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
        7 => FrameKind::Sps,
        8 => FrameKind::Pps,
        5 => FrameKind::IFrame,
        1 => FrameKind::RFrame,
        _ => FrameKind::RFrame, // Extend as needed.
    };

    Ok(Some(Frame::new(nal_unit.to_vec(), kind)))
}

fn adts_frame_len(header: &[u8]) -> Option<usize> {
    if header.len() < 7 { return None; }
    // syncword 0xFFF
    if header[0] != 0xFF || (header[1] & 0xF0) != 0xF0 { return None; }
    let protection_absent = header[1] & 0x01;
    let hdr_len = if protection_absent == 1 { 7 } else { 9 };

    let frame_length = (((header[3] & 0x03) as usize) << 11)
        | ((header[4] as usize) << 3)
        | (((header[5] & 0xE0) as usize) >> 5);

    if frame_length < hdr_len { return None; }
    Some(frame_length)
}

fn strip_adts(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < 7 { return None; }
    if frame[0] != 0xFF || (frame[1] & 0xF0) != 0xF0 { return None; }
    let protection_absent = frame[1] & 0x01;
    let hdr_len = if protection_absent == 1 { 7 } else { 9 };
    if frame.len() < hdr_len { return None; }
    Some(&frame[hdr_len..])
}

pub fn start_audio(
    frame_queue: Arc<Mutex<VecDeque<Frame>>>,
) -> Result<(), Box<dyn std::error::Error>> {

    let cmd = "\
        arecord -D plughw:0,0 -f S16_LE -r 48000 -c 1 -t raw | \
        sox -t raw -b 16 -e signed-integer -r 48000 -c 1 - \
            -t raw -b 16 -e signed-integer -r 48000 -c 1 - \
            highpass 100 lowpass 7000 gain 20 | \
        fdkaac --raw --raw-channels 1 --raw-rate 48000 \
                --bitrate 96k --transport-format 2 -o - -";

    let mut child = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("Failed to capture stdout"))?;

    // Spawn a thread to read arecord|sox's stdout and extract audio frames.
    {
        thread::spawn(move || {
            let mut r = BufReader::new(stdout);
            let mut buf = BytesMut::with_capacity(64 * 1024);
            let mut tmp = [0u8; 4096];

            loop {
                match r.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => {
                        buf.extend_from_slice(&tmp[..n]);

                        loop {
                            if buf.len() < 7 { break; }
                            let len = match adts_frame_len(&buf[..7]) {
                                Some(l) => l,
                                None => {
                                    // resync: drop 1 byte
                                    buf.advance(1);
                                    continue;
                                }
                            };
                            if buf.len() < len { break; }

                            let adts = buf.split_to(len).to_vec();
                            if let Some(aac_au) = strip_adts(&adts) {
                                let frame = Frame {
                                    data: aac_au.to_vec(),
                                    kind: FrameKind::Audio,
                                    timestamp: SystemTime::now(),
                                };
                                add_frame_and_drop_old(Arc::clone(&frame_queue), frame);
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
        });
    }

    Ok(())
}