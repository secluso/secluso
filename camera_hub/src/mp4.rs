//! Privastead MP4 Writer.
//! FIXME: shares a lot of code with fmp4.rs
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

//! Based on Retina example MP4 writer (https://github.com/scottlamb/retina).
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

use crate::traits::{CodecParameters, Mp4};
use anyhow::{anyhow, Error};
use bytes::{BufMut, BytesMut};

use std::convert::TryFrom;
use std::io::SeekFrom;
use tokio::io::{AsyncSeek, AsyncSeekExt, AsyncWrite, AsyncWriteExt};

/// Writes a box length for everything appended in the supplied scope.
#[macro_export]
macro_rules! write_box {
    ($buf:expr, $fourcc:expr, $b:block) => {{
        let _: &mut BytesMut = $buf; // type-check.
        let pos_start = ($buf as &BytesMut).len();
        let fourcc: &[u8; 4] = $fourcc;
        $buf.extend_from_slice(&[0, 0, 0, 0, fourcc[0], fourcc[1], fourcc[2], fourcc[3]]);
        let r = {
            $b;
        };
        let pos_end = ($buf as &BytesMut).len();
        let len = pos_end.checked_sub(pos_start).unwrap();
        $buf[pos_start..pos_start + 4].copy_from_slice(&u32::try_from(len)?.to_be_bytes()[..]);
        r
    }};
}

/// A chunk: a group of samples that have consecutive byte positions and same sample description.
pub struct Chunk {
    first_sample_number: u32, // 1-based index
    byte_pos: u32,            // starting byte of first sample
    sample_description_index: u32,
}

/// Tracks the parts of a `trak` atom which are common between video and audio samples.
#[derive(Default)]
pub struct TrakTrackerCore {
    pub samples: u32,
    pub chunks: Vec<Chunk>,
    pub sizes: Vec<u32>,

    /// The durations of samples in a run-length encoding form: (number of samples, duration).
    /// This lags one sample behind calls to `add_sample` because each sample's duration
    /// is calculated using the PTS of the following sample.
    pub durations: Vec<(u32, u32)>,
    pub last_pts: Option<u64>,
    pub tot_duration: u64,
}

impl TrakTrackerCore {
    pub fn finish(&mut self) {
        if self.last_pts.is_some() {
            self.durations.push((1, 0));
        }
    }

    /// Estimates the sum of the variable-sized portions of the data.
    pub fn size_estimate(&self) -> usize {
        (self.durations.len() * 8) + // stts
        (self.chunks.len() * 12) +   // stsc
        (self.sizes.len() * 4) +     // stsz
        (self.chunks.len() * 4) // stco
    }

    pub fn write_common_stbl_parts(&self, buf: &mut BytesMut) -> Result<(), Error> {
        // TODO: add an edit list so the video and audio tracks are in sync.
        write_box!(buf, b"stts", {
            buf.put_u32(0);
            buf.put_u32(u32::try_from(self.durations.len())?);
            for (samples, duration) in &self.durations {
                buf.put_u32(*samples);
                buf.put_u32(*duration);
            }
        });
        write_box!(buf, b"stsc", {
            buf.put_u32(0); // version
            buf.put_u32(u32::try_from(self.chunks.len())?);
            let mut prev_sample_number = 1;
            let mut chunk_number = 1;
            if !self.chunks.is_empty() {
                for c in &self.chunks[1..] {
                    buf.put_u32(chunk_number);
                    buf.put_u32(c.first_sample_number - prev_sample_number);
                    buf.put_u32(c.sample_description_index);
                    prev_sample_number = c.first_sample_number;
                    chunk_number += 1;
                }
                buf.put_u32(chunk_number);
                buf.put_u32(self.samples + 1 - prev_sample_number);
                buf.put_u32(1); // sample_description_index
            }
        });
        write_box!(buf, b"stsz", {
            buf.put_u32(0); // version
            buf.put_u32(0); // sample_size
            buf.put_u32(u32::try_from(self.sizes.len())?);
            for s in &self.sizes {
                buf.put_u32(*s);
            }
        });
        write_box!(buf, b"stco", {
            buf.put_u32(0); // version
            buf.put_u32(u32::try_from(self.chunks.len())?); // entry_count
            for c in &self.chunks {
                buf.put_u32(c.byte_pos);
            }
        });
        Ok(())
    }
}

#[derive(Default)]
struct TrakTracker {
    core: TrakTrackerCore,
    next_pos: Option<u32>,
}

impl TrakTracker {
    fn add_sample(
        &mut self,
        sample_description_index: u32,
        byte_pos: u32,
        size: u32,
        timestamp: u64,
    ) -> Result<(), Error> {
        self.core.samples += 1;
        if self.next_pos != Some(byte_pos)
            || self.core.chunks.last().map(|c| c.sample_description_index)
                != Some(sample_description_index)
        {
            self.core.chunks.push(Chunk {
                first_sample_number: self.core.samples,
                byte_pos,
                sample_description_index,
            });
        }
        self.core.sizes.push(size);
        self.next_pos = Some(byte_pos + size);
        if let Some(last_pts) = self.core.last_pts.replace(timestamp) {
            let duration = match timestamp.checked_sub(last_pts) {
                Some(c) => c,
                None => {
                    println!("checked_sub returned None!");
                    0
                }
            };
            self.core.tot_duration += duration;
            let duration = u32::try_from(duration)?;
            match self.core.durations.last_mut() {
                Some((s, d)) if *d == duration => *s += 1,
                _ => self.core.durations.push((1, duration)),
            }
        }
        Ok(())
    }
}

pub struct Mp4WriterCore<W: AsyncWrite + Unpin, V: CodecParameters, A: CodecParameters> {
    pub mdat_pos: u32,
    pub video_params: V,
    pub audio_params: A,

    /// The (1-indexed) video sample (frame) number of each sync sample (random access point).
    pub video_sync_sample_nums: Vec<u32>,
    pub inner: W,
}

impl<W: AsyncWrite + Unpin, V: CodecParameters, A: CodecParameters> Mp4WriterCore<W, V, A> {
    pub async fn new(video_params: V, audio_params: A, inner: W, mdat_pos: u32) -> Self {
        Mp4WriterCore {
            inner,
            video_params,
            audio_params,
            video_sync_sample_nums: Vec::new(),
            mdat_pos,
        }
    }

    pub fn write_video_trak(
        &self,
        buf: &mut BytesMut,
        video_trak_core: &TrakTrackerCore,
    ) -> Result<(), Error> {
        write_box!(buf, b"trak", {
            write_box!(buf, b"tkhd", {
                buf.put_u32((1 << 24) | 7); // version, flags
                buf.put_u64(0); // creation_time
                buf.put_u64(0); // modification_time
                buf.put_u32(1); // track_id
                buf.put_u32(0); // reserved
                buf.put_u64(video_trak_core.tot_duration);
                buf.put_u64(0); // reserved
                buf.put_u16(0); // layer
                buf.put_u16(0); // alternate_group
                buf.put_u16(0); // volume
                buf.put_u16(0); // reserved
                for v in &[0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000] {
                    buf.put_u32(*v); // matrix
                }
                let (width, height) = self.video_params.get_dimensions();
                buf.put_u32(width);
                buf.put_u32(height);
            });
            write_box!(buf, b"mdia", {
                write_box!(buf, b"mdhd", {
                    buf.put_u32(1 << 24); // version
                    buf.put_u64(0); // creation_time
                    buf.put_u64(0); // modification_time
                    buf.put_u32(90000); // timebase
                    buf.put_u64(video_trak_core.tot_duration);
                    buf.put_u32(0x55c40000); // language=und + pre-defined
                });
                write_box!(buf, b"hdlr", {
                    buf.extend_from_slice(&[
                        0x00, 0x00, 0x00, 0x00, // version + flags
                        0x00, 0x00, 0x00, 0x00, // pre_defined
                        b'v', b'i', b'd', b'e', // handler = vide
                        0x00, 0x00, 0x00, 0x00, // reserved[0]
                        0x00, 0x00, 0x00, 0x00, // reserved[1]
                        0x00, 0x00, 0x00, 0x00, // reserved[2]
                        0x00, // name, zero-terminated (empty)
                    ]);
                });
                write_box!(buf, b"minf", {
                    write_box!(buf, b"vmhd", {
                        buf.put_u32(1);
                        buf.put_u64(0);
                    });
                    write_box!(buf, b"dinf", {
                        write_box!(buf, b"dref", {
                            buf.put_u32(0);
                            buf.put_u32(1); // entry_count
                            write_box!(buf, b"url ", {
                                buf.put_u32(1); // version, flags=self-contained
                            });
                        });
                    });
                    write_box!(buf, b"stbl", {
                        write_box!(buf, b"stsd", {
                            buf.put_u32(0); // version
                            buf.put_u32(1); // entry_count
                            self.video_params.write_codec_box(buf)?;
                        });
                        video_trak_core.write_common_stbl_parts(buf)?;
                        write_box!(buf, b"stss", {
                            buf.put_u32(0); // version
                            buf.put_u32(u32::try_from(self.video_sync_sample_nums.len())?);
                            for n in &self.video_sync_sample_nums {
                                buf.put_u32(*n);
                            }
                        });
                    });
                });
            });
        });
        Ok(())
    }

    pub fn write_audio_trak(
        &self,
        buf: &mut BytesMut,
        audio_trak_core: &TrakTrackerCore,
    ) -> Result<(), Error> {
        write_box!(buf, b"trak", {
            write_box!(buf, b"tkhd", {
                buf.put_u32((1 << 24) | 7); // version, flags
                buf.put_u64(0); // creation_time
                buf.put_u64(0); // modification_time
                buf.put_u32(2); // track_id
                buf.put_u32(0); // reserved
                buf.put_u64(audio_trak_core.tot_duration);
                buf.put_u64(0); // reserved
                buf.put_u16(0); // layer
                buf.put_u16(0); // alternate_group
                buf.put_u16(0); // volume
                buf.put_u16(0); // reserved
                for v in &[0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000] {
                    buf.put_u32(*v); // matrix
                }
                buf.put_u32(0); // width
                buf.put_u32(0); // height
            });
            write_box!(buf, b"mdia", {
                write_box!(buf, b"mdhd", {
                    buf.put_u32(1 << 24); // version
                    buf.put_u64(0); // creation_time
                    buf.put_u64(0); // modification_time
                    buf.put_u32(self.audio_params.get_clock_rate());
                    buf.put_u64(audio_trak_core.tot_duration);
                    buf.put_u32(0x55c40000); // language=und + pre-defined
                });
                write_box!(buf, b"hdlr", {
                    buf.extend_from_slice(&[
                        0x00, 0x00, 0x00, 0x00, // version + flags
                        0x00, 0x00, 0x00, 0x00, // pre_defined
                        b's', b'o', b'u', b'n', // handler = soun
                        0x00, 0x00, 0x00, 0x00, // reserved[0]
                        0x00, 0x00, 0x00, 0x00, // reserved[1]
                        0x00, 0x00, 0x00, 0x00, // reserved[2]
                        0x00, // name, zero-terminated (empty)
                    ]);
                });
                write_box!(buf, b"minf", {
                    write_box!(buf, b"smhd", {
                        buf.extend_from_slice(&[
                            0x00, 0x00, 0x00, 0x00, // version + flags
                            0x00, 0x00, // balance
                            0x00, 0x00, // reserved
                        ]);
                    });
                    write_box!(buf, b"dinf", {
                        write_box!(buf, b"dref", {
                            buf.put_u32(0);
                            buf.put_u32(1); // entry_count
                            write_box!(buf, b"url ", {
                                buf.put_u32(1); // version, flags=self-contained
                            });
                        });
                    });
                    write_box!(buf, b"stbl", {
                        write_box!(buf, b"stsd", {
                            buf.put_u32(0); // version
                            buf.put_u32(1); // entry_count
                            self.audio_params.write_codec_box(buf)?;
                        });
                        audio_trak_core.write_common_stbl_parts(buf)?;

                        // AAC requires two samples (really, each is a set of 960 or 1024 samples)
                        // to decode accurately. See
                        // https://developer.apple.com/library/archive/documentation/QuickTime/QTFF/QTFFAppenG/QTFFAppenG.html .
                        write_box!(buf, b"sgpd", {
                            // BMFF section 8.9.3: SampleGroupDescriptionBox
                            buf.put_u32(0); // version
                            buf.extend_from_slice(b"roll"); // grouping type
                            buf.put_u32(1); // entry_count
                                            // BMFF section 10.1: AudioRollRecoveryEntry
                            buf.put_i16(-1); // roll_distance
                        });
                        write_box!(buf, b"sbgp", {
                            // BMFF section 8.9.2: SampleToGroupBox
                            buf.put_u32(0); // version
                            buf.extend_from_slice(b"roll"); // grouping type
                            buf.put_u32(1); // entry_count
                            buf.put_u32(audio_trak_core.samples);
                            buf.put_u32(1); // group_description_index
                        });
                    });
                });
            });
        });
        Ok(())
    }
}

/// Writes `.mp4` data to a sink.
pub struct Mp4Writer<
    W: AsyncWrite + AsyncSeek + Send + Unpin,
    V: CodecParameters,
    A: CodecParameters,
> {
    core: Mp4WriterCore<W, V, A>,
    mdat_start: u32,
    video_trak: TrakTracker,
    audio_trak: TrakTracker,
}

impl<W: AsyncWrite + AsyncSeek + Send + Unpin, V: CodecParameters, A: CodecParameters>
    Mp4Writer<W, V, A>
{
    pub async fn new(video_params: V, audio_params: A, mut inner: W) -> Result<Self, Error> {
        let mut buf = BytesMut::new();
        write_box!(&mut buf, b"ftyp", {
            buf.extend_from_slice(&[
                b'i', b's', b'o', b'm', // major_brand
                0, 0, 0, 0, // minor_version
                b'i', b's', b'o', b'm', // compatible_brands[0]
            ]);
        });
        buf.extend_from_slice(&b"\0\0\0\0mdat"[..]);
        let mdat_start = u32::try_from(buf.len())?;
        inner.write_all(&buf).await?;
        Ok(Mp4Writer {
            core: Mp4WriterCore::new(video_params, audio_params, inner, mdat_start).await,
            mdat_start,
            video_trak: TrakTracker::default(),
            audio_trak: TrakTracker::default(),
        })
    }

    pub async fn finish(mut self) -> Result<(), Error> {
        self.video_trak.core.finish();
        self.audio_trak.core.finish();
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
            if self.video_trak.core.samples > 0 {
                self.core
                    .write_video_trak(&mut buf, &self.video_trak.core)?;
            }
            if self.audio_trak.core.samples > 0 {
                self.core
                    .write_audio_trak(&mut buf, &self.audio_trak.core)?;
            }
        });
        self.core.inner.write_all(&buf).await?;
        self.core
            .inner
            .seek(SeekFrom::Start(u64::from(self.mdat_start - 8)))
            .await?;
        self.core
            .inner
            .write_all(&(self.core.mdat_pos + 8 - self.mdat_start).to_be_bytes()[..])
            .await?;
        Ok(())
    }
}

impl<W: AsyncWrite + AsyncSeek + Send + Unpin, V: CodecParameters, A: CodecParameters> Mp4
    for Mp4Writer<W, V, A>
{
    async fn video(
        &mut self,
        frame: &[u8],
        frame_timestamp: u64,
        is_random_access_point: bool,
    ) -> Result<(), Error> {
        let size = u32::try_from(frame.len())?;
        self.video_trak.add_sample(
            /* sample_description_index */ 1,
            self.core.mdat_pos,
            size,
            frame_timestamp,
        )?;
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
        self.core.inner.write_all(frame).await?;
        Ok(())
    }

    async fn audio(&mut self, frame: &[u8], frame_timestamp: u64) -> Result<(), Error> {
        let size = u32::try_from(frame.len())?;
        self.audio_trak.add_sample(
            /* sample_description_index */ 1,
            self.core.mdat_pos,
            size,
            frame_timestamp,
        )?;
        self.core.mdat_pos = self
            .core
            .mdat_pos
            .checked_add(size)
            .ok_or_else(|| anyhow!("mdat_pos overflow"))?;
        self.core.inner.write_all(frame).await?;
        Ok(())
    }

    /// No op
    async fn finish_fragment(&mut self) -> Result<(), Error> {
        Ok(())
    }
}
