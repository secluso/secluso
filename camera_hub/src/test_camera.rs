//! Test camera with dummy data
//!
//! SPDX-License-Identifier: GPL-3.0-or-later

use std::fs::File;
use std::io::{self, Write};
use rand::Rng;
use anyhow::{Error};
use crate::motion::MotionResult;
use crate::livestream::LivestreamWriter;
use crate::VideoInfo;
use crate::Camera;
use tokio::time::{sleep, Duration};
use std::thread;
use tokio::io::AsyncWriteExt;
use tokio::runtime::Runtime;
use image::RgbImage;

pub struct TestCamera {
    pub name: String,
    pub state_dir: String,
    pub video_dir: String,
    pub thumbnail_dir: String,
    pub counter: u8,
}

impl Camera for TestCamera {
    fn record_motion_video(&self, info: &VideoInfo, _duration: u64) -> io::Result<()> {
        let mut file = File::create(self.video_dir.clone() + "/" + &info.filename)?;

        let mut rng = rand::rng();
        let data: Vec<u8> = (0..1024).map(|_| rng.random()).collect();

        file.write_all(&data)?;

        Ok(())
    }

    fn launch_livestream(&self, mut livestream_writer: LivestreamWriter) -> io::Result<()> {
        thread::spawn(move || {
            let rt = Runtime::new().unwrap();

            rt.block_on(async move {
                loop {
                    let buffer = vec![0u8; 1024];

                    if livestream_writer.write_all(&buffer).await.is_err() {
                        break;
                    }

                    if livestream_writer.flush().await.is_err() {
                        break;
                    }

                    sleep(Duration::from_secs(1)).await;
                }
            });
        });

        Ok(())
    }

    fn is_there_motion(&mut self) -> Result<MotionResult, Error> {
        if self.counter != 0 {
            self.counter -= 1;
            return Ok(MotionResult {
                motion: false,
                detections: vec![],
                thumbnail: None,
            })
        }
        //create dummy thumbnail
        let width = 256;
        let height = 256;

        // 3 bytes per pixel (RGB)
        let mut data = vec![0u8; (width * height * 3) as usize];

        // Fill with dummy pattern
        for i in 0..data.len() {
            data[i] = (i % 256) as u8;
        }

        let img = RgbImage::from_raw(width, height, data)
            .expect("Buffer size mismatch");

        Ok(MotionResult {
            motion: true,
            detections: vec![],
            thumbnail: Some(img),
        })
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
