//! Privastead camera traits.
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
    fn is_there_motion(&mut self) -> io::Result<bool>;
    fn record_motion_video(&self, info: &VideoInfo) -> io::Result<()>;
    fn launch_livestream(&self, livestream_writer: LivestreamWriter) -> io::Result<()>;
    fn get_name(&self) -> String;
    fn get_state_dir(&self) -> String;
    fn get_video_dir(&self) -> String;
}
