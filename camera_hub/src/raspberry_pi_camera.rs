//! Code to interface with Raspberry Pi Camera using libcamera.
//!
//! Copyright (C) 2024  Ardalan Amiri Sani
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

use crate::delivery_monitor::VideoInfo;
use crate::livestream::LivestreamWriter;
use crate::traits::{CodecParameters, Mp4, Camera};
use crate::write_box;
use crate::mp4::Mp4Writer;
use crate::fmp4::Fmp4Writer;
use std::io;
use std::process::Command;
use std::process::Stdio;
use std::thread;
use std::sync::Arc;
use std::collections::VecDeque;
use std::sync::{Mutex, mpsc::{self, Sender}};
use anyhow::{anyhow, Context, Error};
use tokio::io::{AsyncReadExt};
use tokio::net::TcpStream;
use tokio::runtime::Runtime;
use bytes::{BufMut, BytesMut};
use std::time::{SystemTime, Duration};

#[derive(PartialEq, Debug, Clone)]
enum VideoFrameKind {
    RFrame, // Regular frame (not an I-Frame)
    IFrame,
    Sps,
    Pps,
}

#[derive(Debug, Clone)]
struct VideoFrame {
    pub data: Vec<u8>,
    pub kind: VideoFrameKind,
    timestamp: SystemTime, // timestamp used to manage frames in the queue
}

impl VideoFrame {
    pub fn new(data: Vec<u8>, kind: VideoFrameKind) -> Self {
        Self {
            data,
            kind,
            timestamp: SystemTime::now(),
        }
    }
}

pub struct RaspberryPiCamera {
    name: String,
    state_dir: String,
    video_dir: String,
    frame_queue: Arc<Mutex<VecDeque<VideoFrame>>>,
    sps_frame: VideoFrame,
    pps_frame: VideoFrame,
}

impl RaspberryPiCamera {
    pub fn new(
        name: String,
        state_dir: String,
        video_dir: String,
        _motion_fps: u64,
    ) -> Self {
        let frame_queue: Arc<Mutex<VecDeque<VideoFrame>>> = Arc::new(Mutex::new(VecDeque::new()));
        let frame_queue_clone = Arc::clone(&frame_queue);
        let (ps_tx, ps_rx) = mpsc::channel::<VideoFrame>();

        thread::spawn(move || {
            let rt = Runtime::new().unwrap();
            let future = Self::start_camera_stream(frame_queue_clone, ps_tx);
            rt.block_on(future).unwrap();
        });

        let sps_frame = ps_rx.recv().unwrap();
        assert!(sps_frame.kind == VideoFrameKind::Sps);
        let pps_frame = ps_rx.recv().unwrap();
        assert!(pps_frame.kind == VideoFrameKind::Pps);

        Self {
            name,
            state_dir,
            video_dir,
            frame_queue,
            sps_frame,
            pps_frame,
        }
    }

    async fn start_camera_stream(
        frame_queue: Arc<Mutex<VecDeque<VideoFrame>>>,
        ps_tx: Sender<VideoFrame>,
    ) -> Result<(), Error> {
        let _ = Self::start_camera_stream_attempt(
            Arc::clone(&frame_queue),
            Some(ps_tx),
        ).await?;

        loop {
            println!("Camera stream stopped or didn't start. Will try to restart soon.");
            thread::sleep(Duration::from_secs(5));

            let _ = Self::start_camera_stream_attempt(
                Arc::clone(&frame_queue),
                None,
            ).await?;
        }
    }
    
    async fn start_camera_stream_attempt(
        frame_queue: Arc<Mutex<VecDeque<VideoFrame>>>,
        ps_tx: Option<Sender<VideoFrame>>,
    ) -> Result<(), Error> {
        let _ = Command::new("sh")
        .arg("-c")
        .arg("~/libcamera-apps/build/libcamera-vid -t 0 --width 1296 --height 972 --framerate 10 --inline --listen --codec h264 -o tcp://0.0.0.0:8888")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
        
        Self::stream_loop(frame_queue, ps_tx).await?;
        println!("Read frame thread exiting.");

        Ok(())
    }

    fn add_frame_and_drop_old(
        frame_queue: Arc<Mutex<VecDeque<VideoFrame>>>,
        frame: VideoFrame,
    ) {
        let time_window = Duration::new(5, 0); // We want to record 5 seconds of frames prior to detection of motion
        let mut queue = frame_queue.lock().unwrap();
        queue.push_back(frame);

        // Remove old entries
        let now = SystemTime::now();
        while let Some(front) = queue.front() {
            if now.duration_since(front.timestamp).unwrap_or_default() > time_window {
                queue.pop_front();
            } else {
                break;
            }
        }
    }

    async fn stream_loop(
        frame_queue: Arc<Mutex<VecDeque<VideoFrame>>>,
        ps_tx: Option<Sender<VideoFrame>>,
    ) -> Result<(), Error> {
        let mut frame_stream = Self::connect_tcp_stream("127.0.0.1:8888".to_string()).await.ok_or_else(|| anyhow!("Could not start frame stream"))?;

        let mut frame_buffer = BytesMut::with_capacity(1024 * 1024); // 1 MB buffer

        let mut sps_sent = false;
        let mut pps_sent = false;

        loop {
            //FIXME: 4k is enough?
            let mut frame_buf = vec![0; 4096]; // 4 KB buffer for each read

            tokio::select! {
                result = frame_stream.read(&mut frame_buf) => {
                    if let Ok(bytes_read) = result {
                        if bytes_read == 0 {
                            println!("No bytes read.");
                            continue;
                        }        
                        frame_buffer.extend_from_slice(&frame_buf[..bytes_read]);

                        // Parse H.264 frames from the buffer
                        while let Some(frame) = Self::extract_h264_frame(&mut frame_buffer) {
  
                            if let Some(ref tx) = ps_tx {
                                if !sps_sent && frame.kind == VideoFrameKind::Sps {
                                    tx.send(frame.clone())?;
                                    sps_sent = true;
                                }

                                if !pps_sent && frame.kind == VideoFrameKind::Pps {
                                    tx.send(frame.clone())?;
                                    pps_sent = true;
                                }
                            }

                            Self::add_frame_and_drop_old(Arc::clone(&frame_queue), frame);
                        }
                    } else {
                        println!("Stream closed.");
                        continue;
                    }
                },
            }
        }
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
            // Removing the 4-byte length prefix
            RpiCameraVideoParameters::new(sps_frame.data[4..].to_vec(), pps_frame.data[4..].to_vec()),
            RpiCameraAudioParameters::default(),
            file,
        )
        .await?;
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
            RpiCameraVideoParameters::new(sps_frame.data[4..].to_vec(), pps_frame.data[4..].to_vec()),
            RpiCameraAudioParameters::default(),
            livestream_writer,
        )
        .await?;
        fmp4.finish_header().await?;
        Self::copy(&mut fmp4, None, frame_queue).await?;

        Ok(())
    }

    /// Extracts a single H.264 frame from the buffer if available.
    /// Removes the frame and returns it.
    /// Also checks for i-frames, SPS, and PPS and return them if available.
    /// Returns (is_there_any_frame, Option<frame>, is_i_frame, Option<SPS>, Option<PPS>)
    fn extract_h264_frame(
        buffer: &mut BytesMut,
    ) -> Option<VideoFrame> {
        //FIXME: use find_start instead to remove redundant code.
        // Look for the start code `0x00000001` or `0x000001`
        let start_code = &[0x00, 0x00, 0x00, 0x01];
        let short_start_code = &[0x00, 0x00, 0x01];

        // Search for the first start code
        let start = if let Some(pos) = Self::find_start_code(buffer, start_code) {
            pos + start_code.len()
        } else if let Some(pos) = Self::find_start_code(buffer, short_start_code) {
            pos + short_start_code.len()
        } else {
            return None; // Not enough data for a frame
        };

        // Search for the next start code after the first
        let end = if let Some(pos) = Self::find_start_code(&buffer[start..], start_code) {
            start + pos
        } else if let Some(pos) = Self::find_start_code(&buffer[start..], short_start_code) {
            start + pos
        } else {
            return None; // Full frame not yet available
        };

        // Extract the frame
        let frame = buffer.split_to(end).split_off(start).to_vec();

        // Parse the NAL unit type (first byte after the start code)
        if frame.len() > 0 {
            let nal_unit_type = frame[0] & 0x1F;
            let mut prefixed_frame: Vec<u8> = vec![];
            Self::append_length_prefixed_nal(&mut prefixed_frame, &frame);

            match nal_unit_type {
                7 => {
                    // SPS
                    return Some(VideoFrame::new(prefixed_frame, VideoFrameKind::Sps));
                    //return (true, None, false, Some(frame[start..].to_vec()), None);
                },
                8 => {
                    // PPS
                    return Some(VideoFrame::new(prefixed_frame, VideoFrameKind::Pps));
                    //return (true, None, false, None, Some(frame[start..].to_vec()));
                },
                5 => {
                    // i_frame
                    return Some(VideoFrame::new(prefixed_frame, VideoFrameKind::IFrame));
                    //return (true, Some(frame), true, None, None);
                },
                1 => {
                    // regular frame
                    return Some(VideoFrame::new(prefixed_frame, VideoFrameKind::RFrame));
                    //return (true, Some(frame), true, None, None);
                },
                h => {
                    // Other NAL types including regular frames
                    println!("Unsupported frame (NAL: {h})");
                }
            }
        }

        None
    }

    fn append_length_prefixed_nal(output: &mut Vec<u8>, nal: &[u8]) {
        let nal_length = nal.len() as u32;
        output.extend_from_slice(&nal_length.to_be_bytes()); // 4-byte big-endian length prefix
        output.extend_from_slice(nal); // Append the NAL unit itself
    }

    /*
    fn find_start(buffer: &[u8]) -> Option<usize> {
        // Look for the start code `0x00000001` or `0x000001`
        let start_code = &[0x00, 0x00, 0x00, 0x01];
        let short_start_code = &[0x00, 0x00, 0x01];

        if let Some(pos) = Self::find_start_code(buffer, start_code) {
            return Some(pos + start_code.len());
        } else if let Some(pos) = Self::find_start_code(buffer, short_start_code) {
            return Some(pos + short_start_code.len());
        } else {
            return None;
        };
    }
    */

    /// Finds the position of a start code in the buffer.
    fn find_start_code(buffer: &[u8], start_code: &[u8]) -> Option<usize> {
        buffer.windows(start_code.len()).position(|window| window == start_code)
    }

    async fn connect_tcp_stream(addr: String) -> Option<TcpStream> {
        for _ in 1..10 {
            println!("Try to connect to {:?}", addr.clone());
            match TcpStream::connect(addr.clone()).await {
                Ok(stream) => {
                    return Some(stream);
                }
                Err(_) => {}
            }

            thread::sleep(Duration::from_secs(1));
        };

        return None;
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
        let recording_start_time = SystemTime::now();
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
                let frame_timestamp: u64 = frame.timestamp.duration_since(recording_start_time).unwrap_or_default().as_micros().try_into().unwrap();
                mp4.video(&frame.data, frame_timestamp / 10, frame.kind == VideoFrameKind::IFrame).await.with_context(
                || format!("Error processing video frame"))?;
            }
            drop(queue);

            if let Some(window) = recording_window {   
                if frame.timestamp.duration_since(recording_start_time).unwrap_or_default() > window {
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
        //TODO
        Ok(true)
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
}

struct RpiCameraVideoParameters {
    sps: Vec<u8>,
    pps: Vec<u8>,
}

impl RpiCameraVideoParameters {
    pub fn new(sps: Vec<u8>, pps: Vec<u8>) -> Self {
        Self {
            sps,
            pps,
        }
    }
}

impl CodecParameters for RpiCameraVideoParameters {
    fn write_codec_box(&self, buf: &mut BytesMut)-> Result<(), Error> {
        write_box!(buf, b"avc1", {
            buf.put_u32(0); // predefined & reserved
            buf.put_u32(1); // data reference index
            buf.put_u32(0); // reserved
            buf.put_u64(0); // reserved
            buf.put_u32(0); // reserved
            //FIXME: hardcoded
            buf.put_u16(640); // width
            buf.put_u16(480); // height
            buf.put_u32(0x0048); // horizontal resolution
            buf.put_u32(0x0048); // vertical resolution
            buf.put_u32(0); // reserved
            buf.put_u16(1); // frame count
            for _ in 0..32 { // compressor name
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
        let width = (640 as u32) << 16;
        let height = (480 as u32) << 16;

        (width, height)
    }
}

// Not used for now.
#[derive(Default)]
struct RpiCameraAudioParameters { }

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