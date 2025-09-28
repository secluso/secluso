//! Secluso camera traits.
//!
//! SPDX-License-Identifier: GPL-3.0-or-later

use crate::delivery_monitor::VideoInfo;
use crate::livestream::LivestreamWriter;
use crate::motion::MotionResult;
use anyhow::Error;
use bytes::BytesMut;
use std::io;

pub trait CodecParameters {
    fn write_codec_box(&self, buf: &mut BytesMut) -> Result<(), Error>;
    fn get_clock_rate(&self) -> u32;
    fn get_dimensions(&self) -> (u32, u32);
}

pub trait Mp4 {
    async fn video(
        &mut self,
        frame: &[u8],
        frame_timestamp: u64,
        is_random_access_point: bool,
    ) -> Result<(), Error>;
    #[allow(dead_code)]
    async fn audio(&mut self, frame: &[u8], frame_timestamp: u64) -> Result<(), Error>;
    async fn finish_fragment(&mut self) -> Result<(), Error>;
}

pub trait Camera {
    fn is_there_motion(&mut self) -> Result<MotionResult, Error>;
    fn record_motion_video(&self, info: &VideoInfo, duration: u64) -> io::Result<()>;
    fn launch_livestream(&self, livestream_writer: LivestreamWriter) -> io::Result<()>;
    fn get_name(&self) -> String;
    fn get_state_dir(&self) -> String;
    fn get_video_dir(&self) -> String;
    fn get_thumbnail_dir(&self) -> String;
}
