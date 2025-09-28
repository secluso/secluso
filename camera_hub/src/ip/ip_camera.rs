//! Code to interface with IP cameras.
//! Assumes the camera supports RTSP
//!
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Uses some code from the Retina example MP4 writer (https://github.com/scottlamb/retina).
//! MIT License.
//!
// Copyright (C) 2021 Scott Lamb <slamb@slamb.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Proof-of-concept `.mp4` writer.
//!
//! This writes media data (`mdat`) to a stream, buffering parameters for a
//! `moov` atom at the end. This avoids the need to buffer the media data
//! (`mdat`) first or reserved a fixed size for the `moov`, but it will slow
//! playback, particularly when serving `.mp4` files remotely.
//!
//! For a more high-quality implementation, see [Moonfire NVR](https://github.com/scottlamb/moonfire-nvr).
//! It's better tested, places the `moov` atom at the start, can do HTTP range
//! serving for arbitrary time ranges, and supports standard and fragmented
//! `.mp4` files.
//!
//! See the BMFF spec, ISO/IEC 14496-12:2015:
//! https://github.com/scottlamb/moonfire-nvr/wiki/Standards-and-specifications
//! https://standards.iso.org/ittf/PubliclyAvailableStandards/c068960_ISO_IEC_14496-12_2015.zip

use crate::delivery_monitor::VideoInfo;
use crate::fmp4::Fmp4Writer;
use crate::livestream::LivestreamWriter;
use crate::motion::MotionResult;
use crate::mp4::Mp4Writer;
use crate::traits::{Camera, CodecParameters, Mp4};
use std::fs;
use std::io;
use std::io::Write;
use std::thread;
use tokio::runtime::Runtime;

use anyhow::{anyhow, bail, Context, Error};
use bytes::BytesMut;
use futures::StreamExt;
use retina::{
    client::SetupOptions,
    codec::{AudioParameters, CodecItem, ParametersRef, VideoParameters},
};
use url::Url;

use std::convert::TryFrom;
use std::num::NonZeroU32;
use std::sync::Arc;

use crate::ip::ip_motion_detection::MotionDetection;
use crate::{STATE_DIR_GENERAL, THUMBNAIL_DIR_GENERAL, VIDEO_DIR_GENERAL};
use rpassword::read_password;
use std::collections::VecDeque;
use std::process::exit;
use std::sync::{
    mpsc::{self, Sender},
    Mutex,
};
use std::time::{Duration, SystemTime};

pub struct IpCamera {
    name: String,
    state_dir: String,
    video_dir: String,
    thumbnail_dir: String,
    frame_queue: Arc<Mutex<VecDeque<Frame>>>,
    video_params: VideoParameters,
    audio_params: AudioParameters,
    motion_detection: MotionDetection,
}

struct Frame {
    frame: Vec<u8>,
    frame_timestamp: u64,  // timestamp sent by the camera
    timestamp: SystemTime, // timestamp used to manage frames in the queue
    is_video: bool,
    is_random_access_point: bool,
}

#[derive(Debug, Deserialize)]
struct Config {
    cameras: Vec<CameraConfig>,
}

#[derive(Debug, Deserialize)]
struct CameraConfig {
    name: String,
    motion_fps: u64,
    ip: String,
    rtsp_port: u16,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
}

impl IpCamera {
    #[allow(clippy::too_many_arguments)]
    fn new(
        name: String,
        ip: String,
        rtsp_port: u16,
        username: String,
        password: String,
        state_dir: String,
        video_dir: String,
        thumbnail_dir: String,
        motion_fps: u64,
    ) -> io::Result<Self> {
        let frame_queue: Arc<Mutex<VecDeque<Frame>>> = Arc::new(Mutex::new(VecDeque::new()));
        let frame_queue_clone = Arc::clone(&frame_queue);
        let (video_params_tx, video_params_rx) = mpsc::channel::<VideoParameters>();
        let (audio_params_tx, audio_params_rx) = mpsc::channel::<AudioParameters>();

        let ip_clone = ip.clone();
        let username_clone = username.clone();
        let password_clone = password.clone();
        thread::spawn(move || {
            let rt = Runtime::new().unwrap();

            let future = Self::start_camera_stream(
                username_clone,
                password_clone,
                format!("rtsp://{}:{}", ip_clone, rtsp_port),
                frame_queue_clone,
                video_params_tx,
                audio_params_tx,
            );

            rt.block_on(future).unwrap();
        });

        let video_params_prior = video_params_rx.recv();
        match video_params_prior {
            Ok(_) => {}
            Err(e) => {
                println!(
                    "[{}] You most likely entered invalid credentials",
                    name.clone()
                );
                debug!("{}", e);
                exit(1);
            }
        }

        let video_params = video_params_prior.unwrap();
        let audio_params = audio_params_rx.recv().unwrap();

        fs::create_dir_all(state_dir.clone()).unwrap();
        fs::create_dir_all(video_dir.clone()).unwrap();
        fs::create_dir_all(thumbnail_dir.clone()).unwrap();

        let motion_detection = MotionDetection::new(ip, username, password, motion_fps).unwrap();

        Ok(Self {
            name,
            state_dir,
            video_dir,
            thumbnail_dir,
            frame_queue,
            video_params,
            audio_params,
            motion_detection,
        })
    }

    /// Parses cameras.yaml file and returns a list of all cameras.
    pub fn get_all_cameras_info() -> io::Result<Vec<Box<dyn Camera + Send>>> {
        // Retrieve the cameras.yaml file. If it doesn't exist, print an error message for the user.
        let content = match fs::read_to_string("cameras.yaml") {
            Ok(c) => c,

            Err(_error) => {
                println!("Error retrieving cameras.yaml file, see the example_cameras.yaml for an example configuration.");
                exit(1);
            }
        };

        // Load the yml file in for analysis
        let cfg: Config = serde_yaml2::from_str(&content).map_err(io::Error::other)?;

        let mut camera_list: Vec<Box<dyn Camera + Send>> = Vec::new();

        // Iterate through every camera in the cameras.yaml file, accumulating structs representing their data
        for c in cfg.cameras {
            let mut camera_username = c.username.unwrap_or_default();
            let mut camera_password = c.password.unwrap_or_default();

            if camera_username.is_empty() {
                camera_username = Self::ask_user(format!(
                    "Enter the username for the IP camera {:?}: ",
                    c.name
                ))
                .unwrap();
            }

            if camera_password.is_empty() {
                camera_password = Self::ask_user_password(format!(
                    "Enter the password for the IP camera {:?}: ",
                    c.name
                ))
                .unwrap();
            }

            let ip_camera_result = IpCamera::new(
                c.name.clone(),
                c.ip,
                c.rtsp_port,
                camera_username,
                camera_password,
                format!(
                    "{}/{}",
                    STATE_DIR_GENERAL,
                    c.name.replace(" ", "_").to_lowercase()
                ),
                format!(
                    "{}/{}",
                    VIDEO_DIR_GENERAL,
                    c.name.replace(" ", "_").to_lowercase()
                ),
                format!(
                    "{}/{}",
                    THUMBNAIL_DIR_GENERAL,
                    c.name.replace(" ", "_").to_lowercase()
                ),
                c.motion_fps,
            );

            match ip_camera_result {
                Ok(camera) => {
                    camera_list.push(Box::new(camera));
                }
                Err(err) => {
                    panic!("Failed to initialize the IP camera object. Consider resetting the camera. (Error: {err})");
                }
            }
        }

        Ok(camera_list)
    }

    fn ask_user(prompt: String) -> io::Result<String> {
        print!("{prompt}");
        // Make sure the prompt is displayed before reading input
        io::stdout().flush()?;

        let mut user_input = String::new();
        io::stdin().read_line(&mut user_input)?;
        // Trim the input to remove any extra whitespace or newline characters
        Ok(user_input.trim().to_string())
    }

    fn ask_user_password(prompt: String) -> io::Result<String> {
        print!("{prompt}");
        // Make sure the prompt is displayed before reading input
        io::stdout().flush()?;

        let password = read_password()?;
        // Trim the input to remove any extra whitespace or newline characters
        Ok(password.trim().to_string())
    }

    fn add_frame_and_drop_old(frame_queue: Arc<Mutex<VecDeque<Frame>>>, frame: Frame) {
        // We want to record 5 seconds of frames at any given time.
        let time_window = Duration::new(5, 0);
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

    /// Copies packets from the IP camera session to the frame queue
    async fn stream_loop(
        session: &mut retina::client::Demuxed,
        frame_queue: Arc<Mutex<VecDeque<Frame>>>,
    ) -> Result<(), Error> {
        loop {
            tokio::select! {
                pkt = session.next() => {
                    match pkt.ok_or_else(|| anyhow!("EOF"))?? {
                        CodecItem::VideoFrame(f) => {
                            let frame = Frame {
                                frame: f.data().to_vec(),
                                frame_timestamp: f.timestamp().timestamp().try_into().unwrap(),
                                timestamp: SystemTime::now(),
                                is_video: true,
                                is_random_access_point: f.is_random_access_point(),
                            };

                            let frame_queue_clone = Arc::clone(&frame_queue);
                            Self::add_frame_and_drop_old(frame_queue_clone, frame);
                        },
                        CodecItem::AudioFrame(f) => {
                            let frame = Frame {
                                frame: f.data().to_vec(),
                                frame_timestamp: f.timestamp().timestamp().try_into().unwrap(),
                                timestamp: SystemTime::now(),
                                is_video: false,
                                is_random_access_point: false,
                            };

                            let frame_queue_clone = Arc::clone(&frame_queue);
                            Self::add_frame_and_drop_old(frame_queue_clone, frame);
                        },
                        CodecItem::Rtcp(rtcp) => {
                            if let (Some(_t), Some(Ok(Some(_sr)))) = (rtcp.rtp_timestamp(), rtcp.pkts().next().map(retina::rtcp::PacketRef::as_sender_report)) {
                            }
                        },
                        _ => continue,
                    };
                },
            }
        }
    }

    /// Streams frames from the IP camera.
    async fn start_camera_stream_attempt(
        username: String,
        password: String,
        url: String,
        frame_queue: Arc<Mutex<VecDeque<Frame>>>,
        video_params_tx: Option<Sender<VideoParameters>>,
        audio_params_tx: Option<Sender<AudioParameters>>,
    ) -> Result<(), Error> {
        let (session, video_params, audio_params) =
            Self::get_stream(username, password, url).await?;

        let mut session = session
            .play(
                retina::client::PlayOptions::default()
                    .initial_timestamp(retina::client::InitialTimestampPolicy::Default)
                    .enforce_timestamps_with_max_jump_secs(NonZeroU32::new(10).unwrap())
                    .unknown_rtcp_ssrc(retina::client::UnknownRtcpSsrcPolicy::Default),
            )
            .await?
            .demuxed()?;

        if let Some(vtx) = video_params_tx {
            let _ = vtx.send(video_params);
        }
        if let Some(atx) = audio_params_tx {
            let _ = atx.send(audio_params);
        }

        Self::stream_loop(&mut session, frame_queue).await?;

        // FIXME: do we need to wait for teardown here?

        Ok(())
    }

    /// Start the camera stream in a loop
    async fn start_camera_stream(
        username: String,
        password: String,
        url: String,
        frame_queue: Arc<Mutex<VecDeque<Frame>>>,
        video_params_tx: Sender<VideoParameters>,
        audio_params_tx: Sender<AudioParameters>,
    ) -> Result<(), Error> {
        Self::start_camera_stream_attempt(
            username.clone(),
            password.clone(),
            url.clone(),
            Arc::clone(&frame_queue),
            Some(video_params_tx),
            Some(audio_params_tx),
        )
        .await?;

        loop {
            println!("IP camera stream stopped or didn't start. Will try to restart soon.");
            thread::sleep(Duration::from_secs(5));

            Self::start_camera_stream_attempt(
                username.clone(),
                password.clone(),
                url.clone(),
                Arc::clone(&frame_queue),
                None,
                None,
            )
            .await?;
        }
    }

    /// Writes the `.mp4`, including trying to finish or clean up the file.
    async fn write_mp4(
        filename: String,
        duration: u64,
        frame_queue: Arc<Mutex<VecDeque<Frame>>>,
        video_params: VideoParameters,
        audio_params: AudioParameters,
    ) -> Result<(), Error> {
        let out = tokio::fs::File::create(&filename).await?;
        let mut mp4 = Mp4Writer::new(
            IpCameraVideoParameters::new(video_params),
            IpCameraAudioParameters::new(audio_params),
            out,
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
        frame_queue: Arc<Mutex<VecDeque<Frame>>>,
        video_params: VideoParameters,
        audio_params: AudioParameters,
    ) -> Result<(), Error> {
        let mut fmp4 = Fmp4Writer::new(
            IpCameraVideoParameters::new(video_params),
            IpCameraAudioParameters::new(audio_params),
            livestream_writer,
        )
        .await?;
        fmp4.finish_header().await?;
        Self::copy(&mut fmp4, None, frame_queue).await?;

        // FIXME: do we need to wait for teardown here?

        Ok(())
    }

    /// Copies packets from `session` to `mp4` without handling any cleanup on error.
    async fn copy<M: Mp4>(
        mp4: &mut M,
        duration: Option<u64>,
        frame_queue: Arc<Mutex<VecDeque<Frame>>>,
    ) -> Result<(), Error> {
        let recording_window = duration.map(|secs| Duration::new(secs, 0));
        let recording_start_time = SystemTime::now();
        let mut first_frame_found = false;

        loop {
            let frame = {
                let mut queue = frame_queue.lock().unwrap();
                match queue.pop_front() {
                    Some(f) => f,
                    None => {
                        // guard is dropped at the end of this block
                        drop(queue);
                        thread::sleep(Duration::from_secs(1));
                        continue;
                    }
                }
            };

            if frame.is_video {
                if frame.is_random_access_point {
                    first_frame_found = true;
                    if let Err(_e) = mp4.finish_fragment().await {
                        // This will be executed when livestream ends.
                        // This is a no op for recording an .mp4 file
                        // log::error!(".mp4 finish failed: {}", e);
                        break;
                    }
                }

                if first_frame_found {
                    mp4.video(
                        &frame.frame,
                        frame.frame_timestamp,
                        frame.is_random_access_point,
                    )
                    .await
                    .with_context(|| "Error processing video frame")?;
                }
            } else {
                // audio
                if first_frame_found {
                    mp4.audio(&frame.frame, frame.frame_timestamp)
                        .await
                        .with_context(|| "Error processing audio frame")?;
                }
            }

            if let Some(window) = recording_window {
                if frame
                    .timestamp
                    .duration_since(recording_start_time)
                    .unwrap_or_default()
                    > window
                {
                    log::info!("Stopping the recording.");
                    break;
                }
            }
        }
        Ok(())
    }

    /// Record an mp4 video file from the IP camera
    /// username: username of the IP camera
    /// passwword: password of the IP camera
    /// url: RTSP url of the IP camera
    /// filename: the name of the mp4 file to be used
    /// duration: the duration of the video, in seconds.
    async fn get_stream(
        username: String,
        password: String,
        url: String,
    ) -> Result<
        (
            retina::client::Session<retina::client::Described>,
            VideoParameters,
            AudioParameters,
        ),
        Error,
    > {
        let creds = retina::client::Credentials { username, password };
        let session_group = Arc::new(retina::client::SessionGroup::default());
        let url_parsed = Url::parse(&url)?;
        let mut session = retina::client::Session::describe(
            url_parsed,
            retina::client::SessionOptions::default()
                .creds(Some(creds))
                .session_group(session_group.clone())
                .teardown(retina::client::TeardownPolicy::Auto),
        )
        .await?;
        let video_stream_i = {
            let s = session.streams().iter().position(|s| {
                if s.media() == "video" {
                    if s.encoding_name() == "h264" || s.encoding_name() == "jpeg" {
                        log::info!("Starting to record using h264 video stream");
                        return true;
                    }
                    log::info!(
                        "Ignoring {} video stream because it's unsupported",
                        s.encoding_name(),
                    );
                }
                false
            });
            if s.is_none() {
                log::info!("No suitable video stream found");
            }
            s
        };
        if let Some(i) = video_stream_i {
            session
                .setup(
                    i,
                    SetupOptions::default().transport(retina::client::Transport::default()),
                )
                .await?;
        }
        let audio_stream = {
            let s = session
                .streams()
                .iter()
                .enumerate()
                .find_map(|(i, s)| match s.parameters() {
                    // Only consider audio streams that can produce a .mp4 sample
                    // entry.
                    Some(retina::codec::ParametersRef::Audio(a)) if a.mp4_sample_entry().build().is_ok() => {
                        log::info!("Using {} audio stream (rfc 6381 codec {})", s.encoding_name(), a.rfc6381_codec().unwrap());
                        Some((i, Box::new(a.clone())))
                    }
                    _ if s.media() == "audio" => {
                        log::info!("Ignoring {} audio stream because it can't be placed into a .mp4 file without transcoding", s.encoding_name());
                        None
                    }
                    _ => None,
                });
            if s.is_none() {
                log::info!("No suitable audio stream found");
            }
            s
        };
        if let Some((i, _)) = audio_stream {
            session
                .setup(
                    i,
                    SetupOptions::default().transport(retina::client::Transport::default()),
                )
                .await?;
        }
        if video_stream_i.is_none() && audio_stream.is_none() {
            bail!("Exiting because no video or audio stream was selected; see info log messages above");
        }

        //FIXME: what if there are multiple streams?
        //The frame will have the stream ID: e.g., let stream = &session.streams()[f.stream_id()];
        let video_stream = &session.streams()[video_stream_i.unwrap()];
        let video_params = match video_stream.parameters() {
            Some(ParametersRef::Video(params)) => params.clone(),
            _ => {
                bail!("Exiting because no video parameters were found");
            }
        };

        let audio_params = audio_stream.map(|(_i, p)| p).unwrap();

        Ok((session, video_params, *audio_params))
    }
}

impl Camera for IpCamera {
    fn record_motion_video(&self, info: &VideoInfo, duration: u64) -> io::Result<()> {
        let rt = Runtime::new()?;

        // FIXME: use a temp name for recording and then rename at the end?
        // If not, we might end up with half-recorded videos on crash, factory reset, etc.
        // This might be okay though.
        let future = Self::write_mp4(
            self.video_dir.clone() + "/" + &info.filename,
            duration,
            Arc::clone(&self.frame_queue),
            self.video_params.clone(),
            self.audio_params.clone(),
        );

        rt.block_on(future).unwrap();
        Ok(())
    }

    fn launch_livestream(&self, livestream_writer: LivestreamWriter) -> io::Result<()> {
        // Drop all the frames from the queue since we won't need them for livestreaming
        let mut queue = self.frame_queue.lock().unwrap();
        queue.clear();
        drop(queue);

        let frame_queue = Arc::clone(&self.frame_queue);
        let video_params = self.video_params.clone();
        let audio_params = self.audio_params.clone();
        thread::spawn(move || {
            let rt = Runtime::new().unwrap();

            let future =
                Self::write_fmp4(livestream_writer, frame_queue, video_params, audio_params);

            rt.block_on(future).unwrap();
        });

        Ok(())
    }

    fn is_there_motion(&mut self) -> Result<MotionResult, Error> {
        self.motion_detection.handle_motion_event()
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

struct IpCameraVideoParameters {
    parameters: VideoParameters,
}

impl IpCameraVideoParameters {
    pub fn new(parameters: VideoParameters) -> Self {
        Self { parameters }
    }
}

impl CodecParameters for IpCameraVideoParameters {
    fn write_codec_box(&self, buf: &mut BytesMut) -> Result<(), Error> {
        let e = self
            .parameters
            .mp4_sample_entry()
            .build()
            .map_err(|e| {
                anyhow!(
                    "unable to produce VisualSampleEntry for {} stream: {}",
                    self.parameters.rfc6381_codec(),
                    e,
                )
            })
            .unwrap();
        buf.extend_from_slice(&e);

        Ok(())
    }

    // Not used
    fn get_clock_rate(&self) -> u32 {
        0
    }

    fn get_dimensions(&self) -> (u32, u32) {
        let dims = self.parameters.pixel_dimensions();
        let width = u32::from(u16::try_from(dims.0).unwrap()) << 16;
        let height = u32::from(u16::try_from(dims.1).unwrap()) << 16;

        (width, height)
    }
}

struct IpCameraAudioParameters {
    parameters: AudioParameters,
}

impl IpCameraAudioParameters {
    pub fn new(parameters: AudioParameters) -> Self {
        Self { parameters }
    }
}

impl CodecParameters for IpCameraAudioParameters {
    fn write_codec_box(&self, buf: &mut BytesMut) -> Result<(), Error> {
        buf.extend_from_slice(
            &self
                .parameters
                .mp4_sample_entry()
                .build()
                .expect("all added streams have sample entries"),
        );

        Ok(())
    }

    fn get_clock_rate(&self) -> u32 {
        self.parameters.clock_rate()
    }

    // Not applicable to audio
    fn get_dimensions(&self) -> (u32, u32) {
        (0, 0)
    }
}
