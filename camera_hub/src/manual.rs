//! Minimal manual camera backend used for local development.
//!
//! SPDX-License-Identifier: GPL-3.0-or-later

use crate::delivery_monitor::VideoInfo;
use crate::livestream::LivestreamWriter;
use crate::motion::MotionResult;
use crate::traits::Camera;
use anyhow::{anyhow, Error};
use image::RgbImage;
use secluso_client_lib::thumbnail_meta_info::GeneralDetectionType;
use std::fs;
use std::io::{self, BufRead, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread;
use tokio::io::AsyncWriteExt;
use tokio::runtime::Runtime;

struct PendingManualMotion {
    video_path: PathBuf,
    thumbnail_path: Option<PathBuf>,
}

pub struct ManualCamera {
    name: String,
    state_dir: String,
    video_dir: String,
    thumbnail_dir: String,
    command_rx: Receiver<PendingManualMotion>,
    pending_motion: Arc<Mutex<Option<PendingManualMotion>>>,
    livestream_command: Arc<Mutex<Option<String>>>,
}

impl ManualCamera {
    pub fn new(
        name: String,
        state_dir: String,
        video_dir: String,
        thumbnail_dir: String,
    ) -> io::Result<Self> {
        fs::create_dir_all(&state_dir)?;
        fs::create_dir_all(&video_dir)?;
        fs::create_dir_all(&thumbnail_dir)?;

        let (command_tx, command_rx) = mpsc::channel::<PendingManualMotion>();
        let livestream_command = Arc::new(Mutex::new(None));
        Self::spawn_command_reader(command_tx, Arc::clone(&livestream_command));

        Ok(Self {
            name,
            state_dir,
            video_dir,
            thumbnail_dir,
            command_rx,
            pending_motion: Arc::new(Mutex::new(None)),
            livestream_command,
        })
    }

    fn spawn_command_reader(
        command_tx: mpsc::Sender<PendingManualMotion>,
        livestream_command: Arc<Mutex<Option<String>>>,
    ) {
        println!("Manual camera mode ready.");
        println!("Type: motion \"/path/to/video.mp4\" [\"/path/to/thumbnail.png\"]");
        println!("Type: livestream webcam");
        println!("Type: livestream off");
        println!("Type: help");

        thread::spawn(move || {
            let stdin = io::stdin();
            for line in stdin.lock().lines() {
                match line {
                    Ok(line) => {
                        match Self::handle_control_command(&line, &livestream_command) {
                            Ok(true) => continue,
                            Ok(false) => {}
                            Err(error) => {
                                println!("{error}");
                                continue;
                            }
                        }

                        match Self::parse_command(&line) {
                            Ok(Some(command)) => {
                                if command_tx.send(command).is_err() {
                                    break;
                                }
                            }
                            Ok(None) => {}
                            Err(error) => {
                                println!("{error}");
                            }
                        }
                    }
                    Err(error) => {
                        println!("Failed to read manual camera command: {error}");
                        break;
                    }
                }
            }
        });
    }

    fn parse_command(line: &str) -> Result<Option<PendingManualMotion>, String> {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }

        let tokens = Self::parse_tokens(trimmed)?;
        if tokens.is_empty() {
            return Ok(None);
        }

        match tokens[0].as_str() {
            "help" => {
                println!("Manual camera commands:");
                println!("  motion \"/path/to/video.mp4\" [\"/path/to/thumbnail.png\"]");
                println!("  livestream webcam");
                println!("  livestream off");
                Ok(None)
            }
            "motion" => {
                if tokens.len() < 2 || tokens.len() > 3 {
                    return Err(
                        "Usage: motion \"/path/to/video.mp4\" [\"/path/to/thumbnail.png\"]"
                            .to_string(),
                    );
                }

                let video_path = PathBuf::from(&tokens[1]);
                if !video_path.exists() {
                    return Err(format!(
                        "Video file does not exist: {}",
                        video_path.display()
                    ));
                }

                let thumbnail_path = if let Some(thumbnail_token) = tokens.get(2) {
                    let path = PathBuf::from(thumbnail_token);
                    if !path.exists() {
                        return Err(format!("Thumbnail file does not exist: {}", path.display()));
                    }

                    Some(path)
                } else {
                    None
                };

                Ok(Some(PendingManualMotion {
                    video_path,
                    thumbnail_path,
                }))
            }
            _ => Err("Unknown command. Type: help".to_string()),
        }
    }

    fn parse_tokens(line: &str) -> Result<Vec<String>, String> {
        let mut tokens = Vec::new();
        let mut current = String::new();
        let mut in_quotes = false;
        let mut escape_next = false;

        for ch in line.chars() {
            if escape_next {
                current.push(ch);
                escape_next = false;
                continue;
            }

            match ch {
                '\\' => {
                    escape_next = true;
                }
                '"' => {
                    in_quotes = !in_quotes;
                }
                ch if ch.is_whitespace() && !in_quotes => {
                    if !current.is_empty() {
                        tokens.push(current.clone());
                        current.clear();
                    }
                }
                _ => current.push(ch),
            }
        }

        if escape_next {
            current.push('\\');
        }

        if in_quotes {
            return Err("Unterminated quote in command.".to_string());
        }

        if !current.is_empty() {
            tokens.push(current);
        }

        Ok(tokens)
    }

    fn load_thumbnail(thumbnail_path: Option<&Path>) -> Result<Option<RgbImage>, Error> {
        let Some(path) = thumbnail_path else {
            return Ok(None);
        };

        let image = image::open(path)
            .map_err(|error| anyhow!("Failed to load thumbnail {}: {error}", path.display()))?;
        Ok(Some(image.into_rgb8()))
    }

    fn handle_control_command(
        line: &str,
        livestream_command: &Arc<Mutex<Option<String>>>,
    ) -> Result<bool, String> {
        let tokens = Self::parse_tokens(line)?;
        if tokens.is_empty() {
            return Ok(false);
        }

        match tokens[0].as_str() {
            "livestream" => {
                if tokens.len() == 2 && tokens[1] == "webcam" {
                    let default_command = std::env::var("SECLUSO_MANUAL_LIVESTREAM_CMD")
                        .unwrap_or_else(|_| Self::default_webcam_command());
                    *livestream_command.lock().unwrap() = Some(default_command);
                    println!("Manual livestream source enabled.");
                    return Ok(true);
                }

                if tokens.len() == 2 && tokens[1] == "off" {
                    *livestream_command.lock().unwrap() = None;
                    println!("Manual livestream source disabled.");
                    return Ok(true);
                }

                return Err("Usage: livestream webcam | livestream off".to_string());
            }
            _ => Ok(false),
        }
    }

    fn default_webcam_command() -> String {
        let device = std::env::var("SECLUSO_MANUAL_WEBCAM_DEVICE")
            .unwrap_or_else(|_| "FaceTime HD Camera".to_string());
        let frame_rate =
            std::env::var("SECLUSO_MANUAL_WEBCAM_FPS").unwrap_or_else(|_| "30".to_string());
        let video_size =
            std::env::var("SECLUSO_MANUAL_WEBCAM_SIZE").unwrap_or_else(|_| "640x480".to_string());
        let input_pixel_format = std::env::var("SECLUSO_MANUAL_WEBCAM_PIXEL_FORMAT")
            .unwrap_or_else(|_| "nv12".to_string());

        format!(
            "ffmpeg -hide_banner -loglevel error -f avfoundation -framerate {frame_rate} -video_size {video_size} -pixel_format {input_pixel_format} -i \"{device}:none\" -an -c:v libx264 -preset ultrafast -tune zerolatency -pix_fmt yuv420p -g {frame_rate} -movflags +empty_moov+default_base_moof+frag_keyframe -f mp4 pipe:1"
        )
    }

    fn copy_stdout_to_livestream(
        mut stdout: impl Read,
        mut livestream_writer: LivestreamWriter,
    ) -> io::Result<()> {
        let mut read_buffer = [0u8; 64 * 1024];
        let mut box_buffer = Vec::<u8>::new();
        let mut pending_chunk = Vec::<u8>::new();
        let rt = Runtime::new()?;

        loop {
            let bytes_read = stdout.read(&mut read_buffer)?;
            if bytes_read == 0 {
                break;
            }

            box_buffer.extend_from_slice(&read_buffer[..bytes_read]);

            while let Some((box_type, box_bytes)) = Self::take_next_mp4_box(&mut box_buffer)? {
                pending_chunk.extend_from_slice(&box_bytes);

                if box_type == *b"moov" || box_type == *b"mdat" {
                    rt.block_on(async {
                        livestream_writer.write_all(&pending_chunk).await?;
                        livestream_writer.flush().await
                    })?;
                    pending_chunk.clear();
                }
            }
        }

        if !pending_chunk.is_empty() {
            rt.block_on(async {
                livestream_writer.write_all(&pending_chunk).await?;
                livestream_writer.flush().await
            })?;
        }

        Ok(())
    }

    fn take_next_mp4_box(buffer: &mut Vec<u8>) -> io::Result<Option<([u8; 4], Vec<u8>)>> {
        if buffer.len() < 8 {
            return Ok(None);
        }

        let size = u32::from_be_bytes(buffer[0..4].try_into().unwrap());
        let box_type: [u8; 4] = buffer[4..8].try_into().unwrap();

        let (box_len, header_len) = if size == 1 {
            if buffer.len() < 16 {
                return Ok(None);
            }

            let largesize = u64::from_be_bytes(buffer[8..16].try_into().unwrap());
            let box_len = usize::try_from(largesize)
                .map_err(|_| io::Error::other("Fragmented MP4 box is too large."))?;
            (box_len, 16usize)
        } else if size == 0 {
            return Err(io::Error::other(
                "Fragmented MP4 stream used a box with size 0.",
            ));
        } else {
            (size as usize, 8usize)
        };

        if box_len < header_len {
            return Err(io::Error::other("Fragmented MP4 box was malformed."));
        }

        if buffer.len() < box_len {
            return Ok(None);
        }

        let box_bytes: Vec<u8> = buffer.drain(0..box_len).collect();
        Ok(Some((box_type, box_bytes)))
    }
}

impl Camera for ManualCamera {
    fn is_there_motion(&mut self) -> Result<MotionResult, Error> {
        match self.command_rx.try_recv() {
            Ok(pending_motion) => {
                let thumbnail = Self::load_thumbnail(pending_motion.thumbnail_path.as_deref())?;
                *self.pending_motion.lock().unwrap() = Some(pending_motion);

                Ok(MotionResult {
                    motion: true,
                    detections: Vec::<GeneralDetectionType>::new(),
                    thumbnail,
                })
            }
            Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => Ok(MotionResult {
                motion: false,
                detections: Vec::<GeneralDetectionType>::new(),
                thumbnail: None,
            }),
        }
    }

    fn record_motion_video(&self, info: &VideoInfo, _duration: u64) -> io::Result<()> {
        let pending_motion = self.pending_motion.lock().unwrap().take();
        let Some(pending_motion) = pending_motion else {
            return Err(io::Error::other(
                "No pending manual motion video is available to upload.",
            ));
        };

        let output_path = Path::new(&self.video_dir).join(&info.filename);
        fs::copy(&pending_motion.video_path, output_path)?;
        Ok(())
    }

    fn launch_livestream(&self, livestream_writer: LivestreamWriter) -> io::Result<()> {
        let livestream_command = self.livestream_command.lock().unwrap().clone();
        let Some(livestream_command) = livestream_command else {
            info!("Manual camera mode ignored a livestream request because no livestream source is enabled.");
            return Ok(());
        };

        println!("[Manual livestream] starting webcam source...");

        thread::spawn(move || {
            let mut child = match Command::new("/bin/sh")
                .arg("-lc")
                .arg(&livestream_command)
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
            {
                Ok(child) => child,
                Err(error) => {
                    eprintln!("[Manual livestream] failed to start source command: {error}");
                    return;
                }
            };

            let stdout = match child.stdout.take() {
                Some(stdout) => stdout,
                None => {
                    eprintln!("[Manual livestream] source command did not expose stdout.");
                    let _ = child.kill();
                    let _ = child.wait();
                    return;
                }
            };

            if let Err(error) = Self::copy_stdout_to_livestream(stdout, livestream_writer) {
                eprintln!("[Manual livestream] failed while forwarding webcam stream: {error}");
            }

            let _ = child.kill();
            let _ = child.wait();
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
