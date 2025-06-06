//! Privastead fMP4 Writer, used for livestreaming.
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

use crate::mp4::{Mp4WriterCore, TrakTrackerCore};
use crate::traits::{CodecParameters, Mp4};
use crate::write_box;
use anyhow::{anyhow, Error};
use bytes::{BufMut, BytesMut};

use cfg_if::cfg_if;
use std::convert::TryFrom;
use tokio::io::{AsyncWrite, AsyncWriteExt};

/// Tracks the parts of a `trak` atom which are common between video and audio samples.
#[derive(Default)]
struct TrakTracker {
    core: TrakTrackerCore,
    samples_durations_sizes: Vec<(u32, u32)>,
    fragment_start_time: u64,
    last_timestamp: u64,
}

impl TrakTracker {
    fn add_sample(&mut self, size: u32, timestamp: u64) -> Result<(), Error> {
        self.core.samples += 1;

        let duration: u32 = if self.last_timestamp == 0 {
            0
        } else {
            timestamp
                .checked_sub(self.last_timestamp)
                .unwrap()
                .try_into()
                .unwrap()
        };
        self.last_timestamp = timestamp;
        self.core.tot_duration += u64::from(duration);

        self.samples_durations_sizes.push((duration, size));
        Ok(())
    }

    fn write_fragment(&self, buf: &mut BytesMut) -> Result<(), Error> {
        write_box!(buf, b"tfdt", {
            buf.put_u32(1 << 24); // version, flags
            buf.put_u64(self.fragment_start_time); // base media decode time
        });
        write_box!(buf, b"trun", {
            buf.put_u32(1 << 24 | 0x100 | 0x200); // version, flags (sample duration, sample size)
            buf.put_u32(self.core.samples); // sample count

            for (duration, size) in &self.samples_durations_sizes {
                buf.put_u32(*duration);
                buf.put_u32(*size);
            }
        });
        Ok(())
    }

    fn clean(&mut self) {
        self.core.samples = 0;
        self.core.chunks.clear();
        self.core.sizes.clear();
        self.core.durations.clear();
        self.samples_durations_sizes.clear();
        self.fragment_start_time = self.core.tot_duration;
    }
}

/// Writes fragmented `.mp4` data to a sink.
pub struct Fmp4Writer<W: AsyncWrite + Unpin, V: CodecParameters, A: CodecParameters> {
    core: Mp4WriterCore<W, V, A>,
    video_trak: TrakTracker,
    audio_trak: TrakTracker,

    /// Buffers for fragment data
    fbuf_video: Vec<u8>,
    fbuf_audio: Vec<u8>,
}

impl<W: AsyncWrite + Unpin, V: CodecParameters, A: CodecParameters> Fmp4Writer<W, V, A> {
    pub async fn new(video_params: V, audio_params: A, mut inner: W) -> Result<Self, Error> {
        let mut buf = BytesMut::new();
        write_box!(&mut buf, b"ftyp", {
            buf.extend_from_slice(&[
                b'i', b's', b'o', b'm', // major_brand
                0, 0, 0, 0, // minor_version
                b'i', b's', b'o', b'm', // compatible_brands[0]
            ]);
        });

        let mdat_start = 0;
        inner.write_all(&buf).await?;
        Ok(Fmp4Writer {
            core: Mp4WriterCore::new(video_params, audio_params, inner, mdat_start).await,
            video_trak: TrakTracker::default(),
            audio_trak: TrakTracker::default(),
            fbuf_video: Vec::new(),
            fbuf_audio: Vec::new(),
        })
    }

    pub async fn finish_header(&mut self) -> Result<(), Error> {
        let mut buf = BytesMut::with_capacity(
            1024 + self.video_trak.core.size_estimate()
                + self.audio_trak.core.size_estimate()
                + 4 * self.core.video_sync_sample_nums.len(),
        );
        write_box!(&mut buf, b"moov", {
            write_box!(&mut buf, b"mvhd", {
                buf.put_u32(1 << 24); // version
                buf.put_u64(0); // creation_time
                buf.put_u64(0); // modification_time
                buf.put_u32(90000); // timescale
                buf.put_u64(self.video_trak.core.tot_duration);
                buf.put_u32(0x00010000); // rate
                buf.put_u16(0x0100); // volume
                buf.put_u16(0); // reserved
                buf.put_u64(0); // reserved
                for v in &[0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000] {
                    buf.put_u32(*v); // matrix
                }
                for _ in 0..6 {
                    buf.put_u32(0); // pre_defined
                }
                buf.put_u32(2); // next_track_id
            });
            self.core
                .write_video_trak(&mut buf, &self.video_trak.core)?;
            // disable audio for Raspberry Pi for now
            cfg_if! {
                if #[cfg(feature = "ip")] {
                    self.core
                        .write_audio_trak(&mut buf, &self.audio_trak.core)?;
                }
            }
            write_box!(&mut buf, b"mvex", {
                write_box!(&mut buf, b"trex", {
                    buf.put_u32(1 << 24); // version, flags
                    buf.put_u32(1); // track id
                    buf.put_u32(1); // default sample description index
                    buf.put_u32(0); // default sample duration
                    buf.put_u32(0); // default sample size
                    buf.put_u32(0); // default sample flags
                });
                // disable audio for Raspberry Pi for now
                cfg_if! {
                    if #[cfg(feature = "ip")] {
                        write_box!(&mut buf, b"trex", {
                            buf.put_u32(1 << 24); // version, flags
                            buf.put_u32(2); // track id
                            buf.put_u32(1); // default sample description index
                            buf.put_u32(0); // default sample duration
                            buf.put_u32(0); // default sample size
                            buf.put_u32(0); // default sample flags
                        });
                    }
                }
            });
        });
        self.core.inner.write_all(&buf).await?;

        Ok(())
    }

    fn write_video_fragment(&self, buf: &mut BytesMut) -> Result<(), Error> {
        write_box!(buf, b"traf", {
            write_box!(buf, b"tfhd", {
                buf.put_u32(1 << 24); // version, flags
                buf.put_u32(1); // track_id
            });

            self.video_trak.write_fragment(buf)?;
        });
        Ok(())
    }

    fn write_audio_fragment(&self, buf: &mut BytesMut) -> Result<(), Error> {
        write_box!(buf, b"traf", {
            write_box!(buf, b"tfhd", {
                buf.put_u32(1 << 24);
                buf.put_u32(2); // track_id
            });

            self.audio_trak.write_fragment(buf)?;
        });
        Ok(())
    }
}

impl<W: AsyncWrite + Unpin, V: CodecParameters, A: CodecParameters> Mp4 for Fmp4Writer<W, V, A> {
    async fn video(
        &mut self,
        frame: &[u8],
        frame_timestamp: u64,
        is_random_access_point: bool,
    ) -> Result<(), Error> {
        let size = u32::try_from(frame.len())?;
        self.video_trak.add_sample(size, frame_timestamp)?;
        self.core.mdat_pos = self
            .core
            .mdat_pos
            .checked_add(size)
            .ok_or_else(|| anyhow!("mdat_pos overflow"))?;
        if is_random_access_point {
            self.core
                .video_sync_sample_nums
                .push(self.video_trak.core.samples);
        }
        self.fbuf_video.append(&mut frame.to_vec());
        Ok(())
    }

    async fn audio(&mut self, frame: &[u8], frame_timestamp: u64) -> Result<(), Error> {
        let size = u32::try_from(frame.len())?;
        self.audio_trak.add_sample(size, frame_timestamp)?;
        self.core.mdat_pos = self
            .core
            .mdat_pos
            .checked_add(size)
            .ok_or_else(|| anyhow!("mdat_pos overflow"))?;
        self.fbuf_audio.append(&mut frame.to_vec());
        Ok(())
    }

    async fn finish_fragment(&mut self) -> Result<(), Error> {
        self.video_trak.core.finish();
        self.audio_trak.core.finish();
        let mut buf = BytesMut::with_capacity(
            1024 + self.video_trak.core.size_estimate()
                + self.audio_trak.core.size_estimate()
                + 4 * self.core.video_sync_sample_nums.len(),
        );
        write_box!(&mut buf, b"moof", {
            write_box!(&mut buf, b"mfhd", {
                buf.put_u32(1 << 24); // version, flags
                buf.put_u32(1); // sequence number
            });
            if self.video_trak.core.samples > 0 {
                self.write_video_fragment(&mut buf)?;
            }
            if self.audio_trak.core.samples > 0 {
                self.write_audio_fragment(&mut buf)?;
            }
        });

        buf.extend_from_slice(
            &u32::try_from(self.fbuf_video.len() + self.fbuf_audio.len() + 8)?.to_be_bytes()[..],
        );
        buf.extend_from_slice(&b"mdat"[..]);

        self.core.inner.write_all(&buf).await?;
        self.core.inner.write_all(&self.fbuf_video).await?;
        self.core.inner.write_all(&self.fbuf_audio).await?;
        self.core.inner.flush().await?;

        self.video_trak.clean();
        self.audio_trak.clean();
        self.fbuf_video.clear();
        self.fbuf_audio.clear();

        Ok(())
    }
}
