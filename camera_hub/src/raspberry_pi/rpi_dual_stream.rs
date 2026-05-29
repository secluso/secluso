//! Code to implement dual streaming (such that, we stream the raw frames and H.264 frames concurrently from rpicam-vid)
//! Assumes the cameras has the rpicam-apps fork built and installed.
//!
//! SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::VecDeque;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::SystemTime;
use std::{
    io::{BufReader, Read, Write},
    process::{Child, ChildStdout, Command, Stdio},
    thread,
    time::Duration,
};

use crate::raspberry_pi::rpi_camera::{
    Frame, FrameKind, OPUS_BITRATE_BPS, OPUS_COMPLEXITY, OPUS_FRAME_SAMPLES,
};
use anyhow::anyhow;
use bytes::BytesMut;
use crossbeam_channel::Sender;
use opusic_c::{Application, Bitrate, Channels, Encoder, Signal};
use secluso_motion_ai::frame::RawFrame;
use secluso_motion_ai::logic::pipeline::PipelineController;

const AUDIO_PROBE_PACKETS: usize = 50;
const AUDIO_SIGNAL_RMS_THRESHOLD: f64 = 8.0;
const AUDIO_SIGNAL_PEAK_THRESHOLD: i16 = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AudioCaptureMode {
    I2s32StereoLeft,
    Mono16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AudioCaptureCandidate {
    device: String,
    mode: AudioCaptureMode,
    forced: bool,
}

#[derive(Clone, Copy, Debug)]
enum I2sDecodeMode {
    LeftShift16,
    LeftShift8,
    RightShift16,
    RightShift8,
}

#[derive(Clone, Copy, Debug)]
struct AudioProbeStats {
    rms: f64,
    peak: i16,
}

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

pub fn start_audio(
    frame_queue: Arc<Mutex<VecDeque<Frame>>>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Spawn a thread to continuously
    // (1) look for a usable ALSA capture device &
    // (2) encode one 20 ms Opus packet at a time from whichever source is available.
    thread::spawn(move || loop {
        let candidates = audio_device_candidates();
        let mut used_device = false;

        for candidate in candidates {
            match spawn_arecord(&candidate) {
                Ok((mut child, stdout)) => {
                    eprintln!(
                        "Using audio input device: {} ({:?}, forced={})",
                        candidate.device, candidate.mode, candidate.forced
                    );
                    used_device = encode_audio_stream(stdout, &candidate, Arc::clone(&frame_queue));
                    let _ = child.wait();

                    if used_device {
                        eprintln!(
                            "Audio input device ended: {}. Retrying discovery.",
                            candidate.device
                        );
                        break;
                    }

                    eprintln!(
                        "Audio input device produced no audio: {}. Trying next candidate.",
                        candidate.device
                    );
                }
                Err(err) => {
                    eprintln!(
                        "Failed to start audio input device {} ({:?}): {:?}",
                        candidate.device, candidate.mode, err
                    );
                }
            }
        }

        if !used_device {
            eprintln!("No usable audio input device found. Retrying in 5 seconds.");
            thread::sleep(Duration::from_secs(5));
        } else {
            thread::sleep(Duration::from_secs(1));
        }
    });

    Ok(())
}

fn audio_device_candidates() -> Vec<AudioCaptureCandidate> {
    let mut devices = Vec::new();

    if let Ok(device) = std::env::var("SECLUSO_AUDIO_DEVICE") {
        let device = device.trim();
        if !device.is_empty() {
            eprintln!(
                "SECLUSO_AUDIO_DEVICE is set. Forcing audio capture attempts on {}.",
                device
            );
            devices.push(AudioCaptureCandidate {
                device: device.to_string(),
                mode: AudioCaptureMode::I2s32StereoLeft,
                forced: true,
            });
            devices.push(AudioCaptureCandidate {
                device: device.to_string(),
                mode: AudioCaptureMode::Mono16,
                forced: true,
            });
            eprintln!(
                "Audio candidate list: {} ({:?}, forced), {} ({:?}, forced).",
                device,
                AudioCaptureMode::I2s32StereoLeft,
                device,
                AudioCaptureMode::Mono16
            );
            return devices;
        }
    }

    devices.push(AudioCaptureCandidate {
        device: "plughw:ICS43432Mic,0".to_string(),
        mode: AudioCaptureMode::I2s32StereoLeft,
        forced: false,
    });
    // We prioritize the HAT capture device first because that is our default config
    eprintln!(
        "Audio candidate list starts with HAT device {} ({:?}).",
        devices[0].device, devices[0].mode
    );

    for device in detect_usb_capture_devices() {
        let candidate = AudioCaptureCandidate {
            device,
            mode: AudioCaptureMode::Mono16,
            forced: false,
        };
        if !devices.iter().any(|existing| existing == &candidate) {
            eprintln!(
                "Discovered USB audio candidate {} ({:?}).",
                candidate.device, candidate.mode
            );
            devices.push(candidate);
        }
    }

    eprintln!("Final audio candidate count: {}.", devices.len());
    devices
}

fn detect_usb_capture_devices() -> Vec<String> {
    let output = match Command::new("arecord")
        .arg("-l")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
    {
        Ok(output) => output,
        Err(err) => {
            eprintln!("Failed to enumerate ALSA capture devices: {:?}", err);
            return Vec::new();
        }
    };

    let listing = String::from_utf8_lossy(&output.stdout);
    let mut devices = Vec::new();

    for line in listing.lines() {
        let lower = line.to_ascii_lowercase();
        // Catch the class-compliant USB microphone devices that have been tested (and not unrelated ALSA hardware)
        if !lower.contains("usb") && !lower.contains("c-media") {
            continue;
        }

        if let Some((card, device)) = parse_arecord_card_and_device(line) {
            eprintln!("Matched USB ALSA capture line: {}", line.trim());
            devices.push(format!("plughw:{},{}", card, device));
        }
    }

    if devices.is_empty() {
        eprintln!("No USB ALSA capture devices matched arecord -l output.");
    }

    devices
}

fn parse_arecord_card_and_device(line: &str) -> Option<(u32, u32)> {
    let card_start = line.find("card ")? + "card ".len();
    let card_end = line[card_start..].find(':')? + card_start;
    let device_marker = ", device ";
    let device_start = line.find(device_marker)? + device_marker.len();
    let device_end = line[device_start..].find(':')? + device_start;

    let card = line[card_start..card_end].trim().parse().ok()?;
    let device = line[device_start..device_end].trim().parse().ok()?;

    Some((card, device))
}

fn spawn_arecord(
    candidate: &AudioCaptureCandidate,
) -> Result<(Child, ChildStdout), Box<dyn std::error::Error>> {
    let args: &[&str] = match candidate.mode {
        AudioCaptureMode::I2s32StereoLeft => &[
            "-D",
            &candidate.device,
            "-f",
            "S32_LE",
            "-r",
            "48000",
            "-c",
            "2",
            "-t",
            "raw",
        ],
        AudioCaptureMode::Mono16 => &[
            "-D",
            &candidate.device,
            "-f",
            "S16_LE",
            "-r",
            "48000",
            "-c",
            "1",
            "-t",
            "raw",
        ],
    };

    eprintln!(
        "Launching arecord for {} with mode {:?}: arecord {}",
        candidate.device,
        candidate.mode,
        args.join(" ")
    );

    let mut child = Command::new("arecord")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("Failed to capture stdout"))?;

    Ok((child, stdout))
}

fn encode_audio_stream(
    stdout: ChildStdout,
    candidate: &AudioCaptureCandidate,
    frame_queue: Arc<Mutex<VecDeque<Frame>>>,
) -> bool {
    let mut r = BufReader::new(stdout);
    let mut encoder = match Encoder::new(
        Channels::Mono,
        opusic_c::SampleRate::Hz48000,
        Application::Audio,
    ) {
        Ok(encoder) => encoder,
        Err(err) => {
            eprintln!("Failed to initialize Opus encoder: {:?}", err);
            return false;
        }
    };
    if let Err(err) = encoder.set_bitrate(Bitrate::Value(OPUS_BITRATE_BPS)) {
        eprintln!("Failed to set Opus bitrate: {:?}", err);
        return false;
    }
    if let Err(err) = encoder.set_vbr(true) {
        eprintln!("Failed to enable Opus VBR: {:?}", err);
        return false;
    }
    if let Err(err) = encoder.set_complexity(OPUS_COMPLEXITY) {
        eprintln!("Failed to set Opus complexity: {:?}", err);
        return false;
    }
    if let Err(err) = encoder.set_signal(Signal::Voice) {
        eprintln!("Failed to set Opus signal mode: {:?}", err);
        return false;
    }

    let bytes_per_frame = match candidate.mode {
        AudioCaptureMode::I2s32StereoLeft => (OPUS_FRAME_SAMPLES as usize) * 8,
        AudioCaptureMode::Mono16 => (OPUS_FRAME_SAMPLES as usize) * 2,
    };
    eprintln!(
        "Audio encoder configured for {}: opus_frame_samples={} bytes_per_capture_frame={} bitrate_bps={} complexity={}.",
        candidate.device,
        OPUS_FRAME_SAMPLES,
        bytes_per_frame,
        OPUS_BITRATE_BPS,
        OPUS_COMPLEXITY
    );
    let mut pcm_bytes = vec![0u8; bytes_per_frame];
    let mut pcm_samples = vec![0u16; OPUS_FRAME_SAMPLES as usize];
    let mut opus_packet = vec![0u8; 1_500];
    let mut encoded_any = false;
    let mut probe_raw = Vec::with_capacity(bytes_per_frame * AUDIO_PROBE_PACKETS);

    // We collect an initial probe window before committing to this device (basically a sanity check)
    // That gives us enough PCM to both detect obvious silence and, for I2S microphones, infer which slot/shift interpretation contains the live samples.
    for _ in 0..AUDIO_PROBE_PACKETS {
        if r.read_exact(&mut pcm_bytes).is_err() {
            break;
        }
        probe_raw.extend_from_slice(&pcm_bytes);
    }

    if probe_raw.is_empty() {
        eprintln!(
            "Audio probe failed: device {} opened but no PCM bytes arrived.",
            candidate.device
        );
        return false;
    }

    let i2s_decode_mode = match candidate.mode {
        AudioCaptureMode::I2s32StereoLeft => {
            let mut best_mode = I2sDecodeMode::LeftShift16;
            let mut best_stats = AudioProbeStats { rms: 0.0, peak: 0 };

            // The I2S microphone has not always presented its usable 16-bit audio samples in the same byte position / slot arrangement across our boards and overlays.
            // Thus, we score a few plausible interpretations and keep whichever one produces the strongest signal.
            for mode in [
                I2sDecodeMode::LeftShift16,
                I2sDecodeMode::LeftShift8,
                I2sDecodeMode::RightShift16,
                I2sDecodeMode::RightShift8,
            ] {
                let stats = probe_i2s_mode(&probe_raw, mode);
                if stats.rms > best_stats.rms
                    || (stats.rms == best_stats.rms && stats.peak > best_stats.peak)
                {
                    best_mode = mode;
                    best_stats = stats;
                }
            }

            eprintln!(
                "Audio probe for {} picked {:?} with rms={:.2} peak={}.",
                candidate.device, best_mode, best_stats.rms, best_stats.peak
            );
            Some(best_mode)
        }
        AudioCaptureMode::Mono16 => {
            let stats = probe_mono16(&probe_raw);
            eprintln!(
                "Audio probe for {} mono16 rms={:.2} peak={}.",
                candidate.device, stats.rms, stats.peak
            );
            None
        }
    };

    let probe_stats = match candidate.mode {
        AudioCaptureMode::I2s32StereoLeft => probe_i2s_mode(
            &probe_raw,
            i2s_decode_mode.expect("i2s decode mode must be selected"),
        ),
        AudioCaptureMode::Mono16 => probe_mono16(&probe_raw),
    };
    let signal_present = probe_stats.rms >= AUDIO_SIGNAL_RMS_THRESHOLD
        || probe_stats.peak >= AUDIO_SIGNAL_PEAK_THRESHOLD;
    eprintln!(
        "Audio signal status for {}: pcm_bytes={} signal_present={} rms={:.2} peak={} thresholds(rms>={:.2}, peak>={}).",
        candidate.device,
        probe_raw.len(),
        signal_present,
        probe_stats.rms,
        probe_stats.peak,
        AUDIO_SIGNAL_RMS_THRESHOLD,
        AUDIO_SIGNAL_PEAK_THRESHOLD
    );

    if !signal_present && !candidate.forced {
        // For auto-discovered devices, a silent probe means we should probably go to the next candidate on the list
        // Allows us to skip a dead/default ALSA source and keep searching for a live microphone.
        eprintln!(
            "Audio probe saw no meaningful signal on {}. Trying another candidate.",
            candidate.device
        );
        return false;
    }

    eprintln!(
        "Beginning steady-state audio encode for {} using mode {:?} and decode {:?}.",
        candidate.device, candidate.mode, i2s_decode_mode
    );
    let start_time = SystemTime::now();
    let mut packets_encoded = 0usize;
    let mut audio_bytes_encoded = 0usize;

    for frame in probe_raw.chunks_exact(bytes_per_frame) {
        fill_pcm_samples(frame, candidate.mode, i2s_decode_mode, &mut pcm_samples);
        if let Some(encoded_len) =
            encode_packet(&mut encoder, &pcm_samples, &mut opus_packet, &frame_queue)
        {
            encoded_any = true;
            packets_encoded += 1;
            audio_bytes_encoded += encoded_len;
        }
    }

    loop {
        if r.read_exact(&mut pcm_bytes).is_err() {
            break;
        }

        fill_pcm_samples(
            &pcm_bytes,
            candidate.mode,
            i2s_decode_mode,
            &mut pcm_samples,
        );

        if let Some(encoded_len) =
            encode_packet(&mut encoder, &pcm_samples, &mut opus_packet, &frame_queue)
        {
            encoded_any = true;
            packets_encoded += 1;
            audio_bytes_encoded += encoded_len;
            if packets_encoded % 250 == 0 {
                let elapsed = start_time.elapsed().unwrap_or_default();
                eprintln!(
                    "Audio encode progress for {}: packets={} opus_bytes={} elapsed_ms={}.",
                    candidate.device,
                    packets_encoded,
                    audio_bytes_encoded,
                    elapsed.as_millis()
                );
            }
        }
    }

    let elapsed = start_time.elapsed().unwrap_or_default();
    eprintln!(
        "Audio encode loop finished for {}: encoded_any={} packets={} opus_bytes={} elapsed_ms={}.",
        candidate.device,
        encoded_any,
        packets_encoded,
        audio_bytes_encoded,
        elapsed.as_millis()
    );

    encoded_any
}

fn encode_packet(
    encoder: &mut Encoder,
    pcm_samples: &[u16],
    opus_packet: &mut [u8],
    frame_queue: &Arc<Mutex<VecDeque<Frame>>>,
) -> Option<usize> {
    match encoder.encode_to_slice(pcm_samples, opus_packet) {
        Ok(encoded_len) if encoded_len > 0 => {
            let frame = Frame {
                data: opus_packet[..encoded_len].to_vec(),
                kind: FrameKind::Audio,
                timestamp: SystemTime::now(),
            };
            add_frame_and_drop_old(Arc::clone(frame_queue), frame);
            Some(encoded_len)
        }
        Ok(_) => None,
        Err(err) => {
            eprintln!("Failed to encode Opus audio: {:?}", err);
            None
        }
    }
}

fn fill_pcm_samples(
    bytes: &[u8],
    mode: AudioCaptureMode,
    i2s_decode_mode: Option<I2sDecodeMode>,
    pcm_samples: &mut [u16],
) {
    match mode {
        AudioCaptureMode::I2s32StereoLeft => {
            let decode_mode = i2s_decode_mode.expect("i2s decode mode must be selected");
            for (dst, frame) in pcm_samples.iter_mut().zip(bytes.chunks_exact(8)) {
                *dst = decode_i2s_sample(frame, decode_mode);
            }
        }
        AudioCaptureMode::Mono16 => {
            for (dst, chunk) in pcm_samples.iter_mut().zip(bytes.chunks_exact(2)) {
                *dst = u16::from_le_bytes([chunk[0], chunk[1]]);
            }
        }
    }
}

fn probe_mono16(bytes: &[u8]) -> AudioProbeStats {
    let samples = bytes
        .chunks_exact(2)
        .map(|chunk| i16::from_le_bytes([chunk[0], chunk[1]]));
    compute_probe_stats(samples)
}

fn probe_i2s_mode(bytes: &[u8], mode: I2sDecodeMode) -> AudioProbeStats {
    let samples = bytes
        .chunks_exact(8)
        .map(|frame| i16::from_ne_bytes(decode_i2s_sample(frame, mode).to_ne_bytes()));
    compute_probe_stats(samples)
}

fn compute_probe_stats(samples: impl Iterator<Item = i16>) -> AudioProbeStats {
    let mut sum_sq = 0.0f64;
    let mut count = 0usize;
    let mut peak = 0i16;

    for sample in samples {
        let abs = sample.saturating_abs();
        if abs > peak {
            peak = abs;
        }
        let sample_f = f64::from(sample);
        sum_sq += sample_f * sample_f;
        count += 1;
    }

    let rms = if count == 0 {
        0.0
    } else {
        (sum_sq / count as f64).sqrt()
    };

    AudioProbeStats { rms, peak }
}

fn decode_i2s_sample(frame: &[u8], mode: I2sDecodeMode) -> u16 {
    let left = i32::from_le_bytes([frame[0], frame[1], frame[2], frame[3]]);
    let right = i32::from_le_bytes([frame[4], frame[5], frame[6], frame[7]]);
    let sample_i16 = match mode {
        I2sDecodeMode::LeftShift16 => (left >> 16) as i16,
        I2sDecodeMode::LeftShift8 => (left >> 8) as i16,
        I2sDecodeMode::RightShift16 => (right >> 16) as i16,
        I2sDecodeMode::RightShift8 => (right >> 8) as i16,
    };
    sample_i16 as u16
}
