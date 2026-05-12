//! Code to manage the Raspberry Pi Camera
//!
//! SPDX-License-Identifier: GPL-3.0-or-later

use std::time::{Instant, SystemTime, UNIX_EPOCH};
use std::{
    collections::VecDeque,
    io,
    process::Command,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use crate::motion::MotionResult;
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
use anyhow::Error;
use bytes::{BufMut, BytesMut};
use crossbeam_channel::unbounded;
use image::RgbImage;
use secluso_client_lib::thumbnail_meta_info::GeneralDetectionType;
use secluso_motion_ai::logic::pipeline::PipelineController;
use secluso_motion_ai::ml::models::DetectionType;
use secluso_motion_ai::pipeline;
use tokio::runtime::Runtime;

const TOTAL_FRAME_RATE: usize = 10;
const I_FRAME_INTERVAL: usize = TOTAL_FRAME_RATE; // 1-second fragments

//These are for our local SPS/PPS channel
#[derive(PartialEq, Debug, Clone)]
pub enum FrameKind {
    RFrame,
    IFrame,
    Sps,
    Pps,
    Audio,
}

#[derive(Debug, Clone)]
pub struct Frame {
    pub data: Vec<u8>,
    pub kind: FrameKind,
    pub timestamp: SystemTime,
}

impl Frame {
    pub fn new(data: Vec<u8>, kind: FrameKind) -> Self {
        Self {
            data,
            kind,
            timestamp: SystemTime::now(),
        }
    }
}

#[derive(Clone)]
pub struct CameraResolution {
    width: usize,
    height: usize,
}

/// RaspberryPiCamera uses the shared stream for both motion detection (via raw YUV420 frames) and recording/livestreaming (via H.264).
pub struct RaspberryPiCamera {
    name: String,
    state_dir: String,
    video_dir: String,
    thumbnail_dir: String,
    frame_queue: Arc<Mutex<VecDeque<Frame>>>,
    sps_frame: Frame,
    pps_frame: Frame,
    motion_detection: Arc<Mutex<PipelineController>>,
    resolution: CameraResolution,
}

impl RaspberryPiCamera {
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

        Self {
            name,
            state_dir,
            video_dir,
            thumbnail_dir,
            frame_queue,
            sps_frame,
            pps_frame,
            motion_detection,
            resolution,
        }
    }

    // The modified copy function now takes an optional raw_writer.
    // For every frame sent to the MP4 writer, we also write the raw frame data.
    async fn copy<M: Mp4>(
        mp4: &mut M,
        duration: Option<u64>,
        frame_queue: Arc<Mutex<VecDeque<Frame>>>,
    ) -> Result<(), Error> {
        let recording_window = duration.map(|secs| Duration::new(secs, 0));
        let recording_start_time = Instant::now();

        let mut started = false; // started first fragment after first IDR
        let mut samples_in_fragment = 0u32; // count samples in the current fragment
        let mut video_frame_count: u64 = 0;
        let ticks_per_video_frame: u64 = 90_000 / TOTAL_FRAME_RATE as u64;

        let mut audio_sample_count: u64 = 0;

        loop {
            let frame = {
                let mut queue = frame_queue.lock().unwrap();
                match queue.pop_front() {
                    Some(f) => f,
                    None => {
                        drop(queue);
                        thread::sleep(Duration::from_millis(100));
                        continue;
                    }
                }
            };

            // Open the very first fragment on the first IDR
            if !started && frame.kind == FrameKind::IFrame {
                started = true;
                samples_in_fragment = 0;
            }
            // On later IDR, close the previous fragment if it has samples.
            else if started && frame.kind == FrameKind::IFrame && samples_in_fragment > 0 {
                mp4.finish_fragment().await?;
                samples_in_fragment = 0;
            }

            if started {
                if frame.kind == FrameKind::Audio {
                    let ts_audio = audio_sample_count; // 48k timescale
                    mp4.audio(&frame.data, ts_audio).await?;
                    audio_sample_count += 1024; // AAC-LC fixed
                    continue;
                } else {
                    let ts = video_frame_count * ticks_per_video_frame;
                    let avcc = Self::annexb_to_avcc_frame(
                        &frame.data,
                        /*strip_aud*/ true,
                        /*strip_ps*/ true,
                    );

                    // Prepend per-frame SEI carrying capture time
                    let sei = Self::make_sei_unreg_avcc(
                        frame
                            .timestamp
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as u64,
                    );
                    let mut sample = Vec::with_capacity(sei.len() + avcc.len());
                    sample.extend_from_slice(&sei);
                    sample.extend_from_slice(&avcc);

                    mp4.video(&sample, ts, frame.kind == FrameKind::IFrame)
                        .await?;

                    video_frame_count += 1;
                    samples_in_fragment += 1;
                }
            }

            if let Some(window) = recording_window {
                if Instant::now().duration_since(recording_start_time) > window {
                    break;
                }
            }
        }

        // Flush the last fragment if it has samples.
        if started && samples_in_fragment > 0 {
            mp4.finish_fragment().await?;
        }
        Ok(())
    }

    /// Writes a motion detection .mp4
    async fn write_mp4(
        filename: String,
        duration: u64,
        frame_queue: Arc<Mutex<VecDeque<Frame>>>,
        sps_frame: Frame,
        pps_frame: Frame,
        resolution: CameraResolution,
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
                sps_bytes, pps_bytes, resolution,
            ),
            RpiCameraAudioParameters::new(),
            file,
        )
            .await?;

        // Process the rest of the frames, writing both to the MP4 writer and to the raw file.
        Self::copy(&mut mp4, Some(duration), frame_queue).await?;
        mp4.finish().await?;

        Ok(())
    }

    fn make_sei_unreg_avcc(epoch_ms: u64) -> Vec<u8> {
        const NAL_TYPE_SEI: u8 = 6;
        const PAYLOAD_TYPE_UNREG: u8 = 5;

        // 16-byte UUID
        const UUID: &[u8; 16] = b"SECLUSO_LATENCY_";

        // Build raw RBSP (before EPB insertion)
        // payload = UUID(16) + timestamp(8, big-endian)
        let mut payload = Vec::with_capacity(24);
        payload.extend_from_slice(UUID);
        payload.extend_from_slice(&epoch_ms.to_be_bytes()); // 8B BE

        // payloadType (5) using 255-extension coding
        // payloadSize (24) using 255-extension coding
        let mut rbsp = Vec::with_capacity(1 + 1 + payload.len() + 1);
        rbsp.push(PAYLOAD_TYPE_UNREG);

        let mut size = payload.len() as u32; // must be 24
        while size >= 255 {
            rbsp.push(255);
            size -= 255;
        }
        rbsp.push(size as u8);

        rbsp.extend_from_slice(&payload);

        // rbsp_trailing_bits: 1 bit '1' then pad with zeros to byte boundary
        rbsp.push(0x80);

        // Emulation-prevention bytes
        // Scan rbsp and after any 0x00 0x00 {00..03} pattern, insert 0x03 before that
        let mut rbsp_epb = Vec::with_capacity(rbsp.len() + 8);
        let mut zero_run = 0usize;
        for &b in &rbsp {
            if zero_run >= 2 && b <= 0x03 {
                rbsp_epb.push(0x03);
                zero_run = 0; // reset after insertion
            }
            rbsp_epb.push(b);
            if b == 0x00 {
                zero_run += 1
            } else {
                zero_run = 0
            }
        }

        // Assemble the NAL (header + rbsp_epb)
        // forbidden_zero_bit=0, nal_ref_idc=0, nal_unit_type=6 (SEI)
        let mut nal = Vec::with_capacity(1 + rbsp_epb.len());
        nal.push(0x00 | NAL_TYPE_SEI);
        nal.extend_from_slice(&rbsp_epb);

        // AVCC length-prefixed output
        let mut out = Vec::with_capacity(4 + nal.len());
        out.extend_from_slice(&(nal.len() as u32).to_be_bytes());
        out.extend_from_slice(&nal);
        out
    }

    /// Streams fmp4 video.
    async fn write_fmp4(
        livestream_writer: LivestreamWriter,
        frame_queue: Arc<Mutex<VecDeque<Frame>>>,
        sps_frame: Frame,
        pps_frame: Frame,
        resolution: CameraResolution,
    ) -> Result<(), Error> {
        // Detect 3/4-byte AnnexB start codes
        fn start_code_len(b: &[u8]) -> usize {
            if b.starts_with(&[0, 0, 0, 1]) {
                4
            } else if b.starts_with(&[0, 0, 1]) {
                3
            } else {
                0
            }
        }
        let sps_off = start_code_len(&sps_frame.data);
        let pps_off = start_code_len(&pps_frame.data);

        let sps = if sps_off > 0 {
            &sps_frame.data[sps_off..]
        } else {
            &sps_frame.data[..]
        };
        let pps = if pps_off > 0 {
            &pps_frame.data[pps_off..]
        } else {
            &pps_frame.data[..]
        };

        // sanity
        if sps.is_empty() || (sps[0] & 0x1F) != 7 {
            return Err(anyhow::anyhow!(
                "Bad SPS NAL: first byte={:#04x}",
                sps.get(0).cloned().unwrap_or(0)
            ));
        }
        if pps.is_empty() || (pps[0] & 0x1F) != 8 {
            return Err(anyhow::anyhow!(
                "Bad PPS NAL: first byte={:#04x}",
                pps.get(0).cloned().unwrap_or(0)
            ));
        }

        let mut fmp4 = Fmp4Writer::new(
            RpiCameraVideoParameters::new(sps.to_vec(), pps.to_vec(), resolution),
            RpiCameraAudioParameters::new(),
            livestream_writer,
        )
            .await?;
        fmp4.finish_header(None).await?;

        Self::copy(&mut fmp4, None, frame_queue).await?;

        Ok(())
    }

    // Required for MP4 muxing. Frames from rpicam-vid are in AnnexB, and we need Avcc for our muxer. FFmpeg did not have this output.
    fn annexb_to_avcc_frame(frame: &[u8], strip_aud: bool, strip_ps: bool) -> Vec<u8> {
        // Detect start codes 0x000001 or 0x00000001
        fn is_start_code(buf: &[u8], i: usize) -> Option<usize> {
            if i + 3 <= buf.len() && &buf[i..i + 3] == [0, 0, 1] {
                return Some(3);
            }
            if i + 4 <= buf.len() && &buf[i..i + 4] == [0, 0, 0, 1] {
                return Some(4);
            }
            None
        }

        // Collect payload spans of every NAL
        let mut nal_spans: Vec<(usize, usize)> = Vec::new();
        let mut i = 0usize;
        let mut open_at: Option<usize> = None;

        while i < frame.len() {
            if let Some(sc) = is_start_code(frame, i) {
                if let Some(s) = open_at {
                    // close previous NAL at start of this start code
                    let end = i;
                    if end > s {
                        nal_spans.push((s, end));
                    }
                }
                open_at = Some(i + sc);
                i += sc;
            } else {
                i += 1;
            }
        }
        if let Some(s) = open_at {
            if frame.len() > s {
                nal_spans.push((s, frame.len()));
            }
        }
        if nal_spans.is_empty() {
            // No start codes: whole buffer is a single NAL
            nal_spans.push((0, frame.len()));
        }

        // Build AVCC: [len][NAL] [len][NAL] …
        let mut out = Vec::with_capacity(frame.len() + nal_spans.len() * 4);
        for (s, e) in nal_spans {
            let nal = &frame[s..e];
            if nal.is_empty() {
                continue;
            }
            let nal_type = nal[0] & 0x1F; // H.264 NAL type

            // Optional stripping: AUD (9) and SPS/PPS (7/8) — SPS/PPS already in avcC
            if strip_aud && nal_type == 9 {
                continue;
            }
            if strip_ps && (nal_type == 7 || nal_type == 8) {
                continue;
            }

            let len = (nal.len() as u32).to_be_bytes();
            out.extend_from_slice(&len);
            out.extend_from_slice(nal);
        }
        out
    }

    pub fn fetch_resolution() -> Option<CameraResolution> {
        debug!("Attempting to fetch the type of sensor attached to the Raspberry Pi");

        // Hard coded width x height based on the Camera Module connected to the Raspberry Pi.
        // Camera Module V1 (OV5647): 1296 x 972 (60% of 1080p)
        // Camera Module V2 (IMX219): 1640 x 1232 (97% of 1080p)
        // Even though these support 1080p directly, if we were to use that, the sides would be cropped out due to the aspect ratio of the sensor.
        const CAMERA_RESOLUTION_V1: (usize, usize) = (1296, 972);
        const CAMERA_RESOLUTION_V2: (usize, usize) = (1640, 1232);

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
        } else {
            None
        }
    }
}

impl Camera for RaspberryPiCamera {
    /// When Ok, there's motion
    fn is_there_motion(&mut self) -> Result<MotionResult, Error> {
        if let Some(pipeline_result) = self.motion_detection.lock().unwrap().motion_recently()? {
            if pipeline_result.motion {
                let frame = pipeline_result.thumbnail;
                let data = frame.rgb_data.unwrap().to_vec();
                let img = RgbImage::from_raw(frame.width as u32, frame.height as u32, data)
                    .expect("Failed to convert RGB data into RgbImage");

                // TODO: We have to manually map these until we connect the IP camera to motion_ai
                let mut detections: Vec<GeneralDetectionType> = Vec::new();
                for detection in pipeline_result.detections {
                    if detection == DetectionType::Animal {
                        detections.push(GeneralDetectionType::Pet);
                    } else if detection == DetectionType::Human {
                        detections.push(GeneralDetectionType::Human);
                    } else if detection == DetectionType::Car {
                        detections.push(GeneralDetectionType::Car);
                    }
                }

                return Ok(MotionResult {
                    motion: true,
                    detections,
                    thumbnail: Some(img as RgbImage),
                });
            }
        }
        Ok(MotionResult {
            motion: false,
            thumbnail: None,
            detections: vec![],
        })
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
            self.resolution.clone()
        );

        rt.block_on(future).unwrap();
        Ok(())
    }

    fn launch_livestream(&self, livestream_writer: LivestreamWriter) -> io::Result<()> {
        // We don't need old frames for the live session
        {
            let mut queue = self.frame_queue.lock().unwrap();
            queue.clear();
        }

        let frame_queue_clone = Arc::clone(&self.frame_queue);
        let sps_frame_clone = self.sps_frame.clone();
        let pps_frame_clone = self.pps_frame.clone();
        let resolution_clone = self.resolution.clone();

        thread::spawn(move || {
            let rt = Runtime::new().unwrap();
            let future = Self::write_fmp4(
                livestream_writer,
                frame_queue_clone,
                sps_frame_clone,
                pps_frame_clone,
                resolution_clone
            );
            if let Err(e) = rt.block_on(future) {
                eprintln!("[Livestream] write_fmp4 error: {e:?}");
            }
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

    fn get_thumbnail_dir(&self) -> String {
        self.thumbnail_dir.clone()
    }
}

struct RpiCameraVideoParameters {
    sps: Vec<u8>,
    pps: Vec<u8>,
    dimensions: CameraResolution,
}

impl RpiCameraVideoParameters {
    pub fn new(sps: Vec<u8>, pps: Vec<u8>, dimensions: CameraResolution) -> Self {
        Self { sps, pps, dimensions }
    }
}

impl CodecParameters for RpiCameraVideoParameters {
    fn write_codec_box(&self, buf: &mut BytesMut) -> Result<(), Error> {
        write_box!(buf, b"avc1", {
            // VisualSampleEntry per ISO/IEC 14496-12
            // 6 bytes reserved
            buf.put_u8(0);
            buf.put_u8(0);
            buf.put_u8(0);
            buf.put_u8(0);
            buf.put_u8(0);
            buf.put_u8(0);
            // data_reference_index
            buf.put_u16(1);

            // pre_defined, reserved
            buf.put_u16(0); // pre_defined
            buf.put_u16(0); // reserved
                            // pre_defined[3]
            buf.put_u32(0);
            buf.put_u32(0);
            buf.put_u32(0);

            // width/height
            buf.put_u16(self.dimensions.width as u16);
            buf.put_u16(self.dimensions.height as u16);

            // horiz/vert resolution (72 dpi in 16.16 fixed)
            buf.put_u32(0x0048_0000);
            buf.put_u32(0x0048_0000);

            // reserved
            buf.put_u32(0);

            // frame_count
            buf.put_u16(1);

            // compressorname: Pascal string padded to 32 bytes
            let name = b"Secluso H.264";
            let n = name.len().min(31) as u8;
            buf.put_u8(n);
            buf.extend_from_slice(&name[..n as usize]);
            for _ in (n as usize + 1)..32 {
                buf.put_u8(0);
            }

            // depth and pre_defined (-1)
            buf.put_u16(0x0018);
            buf.put_i16(-1);

            write_box!(buf, b"avcC", {
                // Expect SPS/PPS without start-codes
                debug_assert!(!self.sps.is_empty() && (self.sps[0] & 0x1F) == 7);
                debug_assert!(!self.pps.is_empty() && (self.pps[0] & 0x1F) == 8);

                buf.put_u8(1); // configurationVersion
                buf.put_u8(self.sps[1]); // AVCProfileIndication
                buf.put_u8(self.sps[2]); // profile_compatibility
                buf.put_u8(self.sps[3]); // AVCLevelIndication

                // lengthSizeMinusOne=3 → 4-byte NAL length
                buf.put_u8(0b1111_1100 | 0b11);

                // numOfSequenceParameterSets=1
                buf.put_u8(0b1110_0000 | 1);

                // SPS
                buf.put_u16(self.sps.len() as u16);
                buf.extend_from_slice(&self.sps);

                // PPS count = 1
                buf.put_u8(1);
                buf.put_u16(self.pps.len() as u16);
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
        ((self.dimensions.width as u32) << 16, (self.dimensions.height as u32) << 16)
    }
}

struct RpiCameraAudioParameters {
    sample_rate: u32, // 48000
    channels: u16,    // 1
    asc: [u8; 2],     // AudioSpecificConfig
}

impl RpiCameraAudioParameters {
    fn new() -> Self {
        Self {
            sample_rate: 48_000,
            channels: 1,
            asc: [0x11, 0x88], // AAC-LC, 48kHz (idx=3), mono (1)
        }
    }
}

impl CodecParameters for RpiCameraAudioParameters {
    fn write_codec_box(&self, buf: &mut BytesMut) -> Result<(), Error> {
        write_box!(buf, b"mp4a", {
            // 6 reserved bytes
            buf.put_u8(0);
            buf.put_u8(0);
            buf.put_u8(0);
            buf.put_u8(0);
            buf.put_u8(0);
            buf.put_u8(0);

            // data_reference_index
            buf.put_u16(1);

            // AudioSampleEntry
            buf.put_u16(0); // version
            buf.put_u16(0); // revision
            buf.put_u32(0); // vendor

            buf.put_u16(self.channels); // channelcount
            buf.put_u16(16); // samplesize
            buf.put_u16(0); // compressionid
            buf.put_u16(0); // packetsize
            buf.put_u32(self.sample_rate << 16); // samplerate 16.16

            // ES Descriptor box
            write_box!(buf, b"esds", {
                // FullBox: version(1) + flags(3)
                buf.put_u32(0);

                let asc = &self.asc;

                // Build the descriptor payload in a temp vec, then write with size.
                let mut d = Vec::new();

                // ES_Descriptor
                d.push(0x03);
                let mut es_payload = Vec::new();
                es_payload.extend_from_slice(&0x0002u16.to_be_bytes()); // ES_ID
                es_payload.push(0x00); // flags

                // DecoderConfigDescriptor (tag 0x04) ---
                let mut dec_payload = Vec::new();
                dec_payload.push(0x40); // objectTypeIndication = MPEG-4 Audio
                dec_payload.push(0x15); // streamType=5 (AudioStream) <<2 | 1 reserved
                dec_payload.extend_from_slice(&[0x00, 0x00, 0x00]); // bufferSizeDB (unknown)
                dec_payload.extend_from_slice(&0u32.to_be_bytes()); // maxBitrate
                dec_payload.extend_from_slice(&0u32.to_be_bytes()); // avgBitrate

                // DecoderSpecificInfo (tag 0x05) inside DecoderConfigDescriptor
                dec_payload.push(0x05);
                dec_payload.push(asc.len() as u8);
                dec_payload.extend_from_slice(asc);

                // Write DecoderConfigDescriptor: tag + length + payload
                es_payload.push(0x04);
                es_payload.extend_from_slice(&write_desc_len(dec_payload.len()));
                es_payload.extend_from_slice(&dec_payload);

                // SLConfigDescriptor (tag 0x06) is a sibling of 0x04 inside ES_Descriptor
                es_payload.push(0x06);
                es_payload.push(0x01);
                es_payload.push(0x02);

                // Write length for ES_Descriptor
                d.extend_from_slice(&write_desc_len(es_payload.len()));
                d.extend_from_slice(&es_payload);

                buf.extend_from_slice(&d);
            });
        });

        Ok(())
    }

    fn get_clock_rate(&self) -> u32 {
        self.sample_rate
    }

    fn get_dimensions(&self) -> (u32, u32) {
        (0, 0)
    }
}

// Size encoding: 7-bit continuation
fn write_desc_len(mut len: usize) -> Vec<u8> {
    // Up to 4 bytes
    let mut out = vec![0u8; 4];
    for i in (0..4).rev() {
        out[i] = (len & 0x7F) as u8;
        len >>= 7;
    }
    // Set continuation bit on first 3
    out[0] |= 0x80;
    out[1] |= 0x80;
    out[2] |= 0x80;

    // Trim leading 0x80 chunks if possible
    while out.len() > 1 && out[0] == 0x80 && (out[1] & 0x80) != 0 {
        out.remove(0);
    }
    // If needed, also trim if the very first byte is 0
    while out.len() > 1 && out[0] == 0 {
        out.remove(0);
    }
    out
}
