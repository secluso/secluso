//! Privastead fMP4 Writer, used for livestreaming.
//! FIXME: shares a lot of code with mp4.rs
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

use anyhow::{anyhow, bail, Context, Error};
use bytes::{Buf, BufMut, BytesMut};
use futures::StreamExt;
use retina::{
    client::SetupOptions,
    codec::{AudioParameters, CodecItem, ParametersRef, VideoParameters},
};
use url::Url;

use std::convert::TryFrom;
use std::num::NonZeroU32;
use std::sync::Arc;
use tokio::io::{AsyncWrite, AsyncWriteExt};

/// Writes a box length for everything appended in the supplied scope.
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

/// Writes `.mp4` data to a sink.
/// See module-level documentation for details.
pub struct Fmp4Writer<W: AsyncWrite + Unpin> {
    mdat_pos: u32,
    video_params: Option<Box<VideoParameters>>,

    audio_params: Option<Box<AudioParameters>>,
    allow_loss: bool,

    /// The (1-indexed) video sample (frame) number of each sync sample (random access point).
    video_sync_sample_nums: Vec<u32>,

    video_trak: TrakTracker,
    audio_trak: TrakTracker,
    inner: W,

    /// Buffers for fragment data
    fbuf_video: Vec<u8>,
    fbuf_audio: Vec<u8>,
}

/// A chunk: a group of samples that have consecutive byte positions and same sample description.
struct Chunk {
    first_sample_number: u32, // 1-based index
    byte_pos: u32,            // starting byte of first sample
    sample_description_index: u32,
}

/// Tracks the parts of a `trak` atom which are common between video and audio samples.
#[derive(Default)]
struct TrakTracker {
    samples: u32,
    chunks: Vec<Chunk>,
    sizes: Vec<u32>,

    /// The durations of samples in a run-length encoding form: (number of samples, duration).
    /// This lags one sample behind calls to `add_sample` because each sample's duration
    /// is calculated using the PTS of the following sample.
    durations: Vec<(u32, u32)>,
    last_pts: Option<i64>,
    tot_duration: u64,
    samples_durations_sizes: Vec<(u32, u32)>,
    fragment_start_time: u64,
    last_timestamp: i64,
}

impl TrakTracker {
    fn add_sample(
        &mut self,
        size: u32,
        timestamp: retina::Timestamp,
        loss: u16,
        allow_loss: bool,
    ) -> Result<(), Error> {
        if self.samples > 0 && loss > 0 && !allow_loss {
            bail!("Lost {} RTP packets mid-stream", loss);
        }
        self.samples += 1;

        let duration: u32 = if self.last_timestamp == 0 {
            0
        } else {
            timestamp
                .timestamp()
                .checked_sub(self.last_timestamp)
                .unwrap()
                .try_into()
                .unwrap()
        };
        self.last_timestamp = timestamp.timestamp();
        self.tot_duration += u64::from(duration);

        self.samples_durations_sizes.push((duration, size));
        Ok(())
    }

    fn finish(&mut self) {
        if self.last_pts.is_some() {
            self.durations.push((1, 0));
        }
    }

    /// Estimates the sum of the variable-sized portions of the data.
    fn size_estimate(&self) -> usize {
        (self.durations.len() * 8) + // stts
        (self.chunks.len() * 12) +   // stsc
        (self.sizes.len() * 4) +     // stsz
        (self.chunks.len() * 4) // stco
    }

    fn write_common_stbl_parts(&self, buf: &mut BytesMut) -> Result<(), Error> {
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

    fn write_fragment(&self, buf: &mut BytesMut) -> Result<(), Error> {
        write_box!(buf, b"tfdt", {
            buf.put_u32(1 << 24); // version, flags
            buf.put_u64(self.fragment_start_time); // base media decode time
        });
        write_box!(buf, b"trun", {
            buf.put_u32(1 << 24 | 0x100 | 0x200); // version, flags (sample duration, sample size)
            buf.put_u32(self.samples); // sample count

            for (duration, size) in &self.samples_durations_sizes {
                buf.put_u32(*duration);
                buf.put_u32(*size);
            }
        });
        Ok(())
    }

    fn clean(&mut self) {
        self.samples = 0;
        self.chunks.clear();
        self.sizes.clear();
        self.durations.clear();
        self.samples_durations_sizes.clear();
        self.fragment_start_time = self.tot_duration;
    }
}

impl<W: AsyncWrite + Unpin> Fmp4Writer<W> {
    pub async fn new(
        video_params: Option<Box<VideoParameters>>,
        audio_params: Option<Box<AudioParameters>>,
        allow_loss: bool,
        mut inner: W,
    ) -> Result<Self, Error> {
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
            inner,
            video_params,
            audio_params,
            allow_loss,
            video_trak: TrakTracker::default(),
            audio_trak: TrakTracker::default(),
            video_sync_sample_nums: Vec::new(),
            mdat_pos: mdat_start,
            fbuf_video: Vec::new(),
            fbuf_audio: Vec::new(),
        })
    }

    pub async fn finish_header(&mut self) -> Result<(), Error> {
        let mut buf = BytesMut::with_capacity(
            1024 + self.video_trak.size_estimate()
                + self.audio_trak.size_estimate()
                + 4 * self.video_sync_sample_nums.len(),
        );
        write_box!(&mut buf, b"moov", {
            write_box!(&mut buf, b"mvhd", {
                buf.put_u32(1 << 24); // version
                buf.put_u64(0); // creation_time
                buf.put_u64(0); // modification_time
                buf.put_u32(90000); // timescale
                buf.put_u64(self.video_trak.tot_duration);
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
            self.write_video_trak(&mut buf, self.video_params.as_ref().unwrap())?;
            self.write_audio_trak(&mut buf, self.audio_params.as_ref().unwrap())?;
            write_box!(&mut buf, b"mvex", {
                write_box!(&mut buf, b"trex", {
                    buf.put_u32(1 << 24); // version, flags
                    buf.put_u32(1); // track id
                    buf.put_u32(1); // default sample description index
                    buf.put_u32(0); // default sample duration
                    buf.put_u32(0); // default sample size
                    buf.put_u32(0); // default sample flags
                });
                write_box!(&mut buf, b"trex", {
                    buf.put_u32(1 << 24); // version, flags
                    buf.put_u32(2); // track id
                    buf.put_u32(1); // default sample description index
                    buf.put_u32(0); // default sample duration
                    buf.put_u32(0); // default sample size
                    buf.put_u32(0); // default sample flags
                });
            });
        });
        self.inner.write_all(&buf).await?;

        Ok(())
    }

    fn write_video_trak(
        &self,
        buf: &mut BytesMut,
        parameters: &VideoParameters,
    ) -> Result<(), Error> {
        write_box!(buf, b"trak", {
            write_box!(buf, b"tkhd", {
                buf.put_u32((1 << 24) | 7); // version, flags
                buf.put_u64(0); // creation_time
                buf.put_u64(0); // modification_time
                buf.put_u32(1); // track_id
                buf.put_u32(0); // reserved
                buf.put_u64(self.video_trak.tot_duration);
                buf.put_u64(0); // reserved
                buf.put_u16(0); // layer
                buf.put_u16(0); // alternate_group
                buf.put_u16(0); // volume
                buf.put_u16(0); // reserved
                for v in &[0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000] {
                    buf.put_u32(*v); // matrix
                }

                let dims = parameters.pixel_dimensions();
                let width = u32::from(u16::try_from(dims.0)?) << 16;
                let height = u32::from(u16::try_from(dims.1)?) << 16;
                buf.put_u32(width);
                buf.put_u32(height);
            });
            write_box!(buf, b"mdia", {
                write_box!(buf, b"mdhd", {
                    buf.put_u32(1 << 24); // version
                    buf.put_u64(0); // creation_time
                    buf.put_u64(0); // modification_time
                    buf.put_u32(90000); // timebase
                    buf.put_u64(self.video_trak.tot_duration);
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
                                            //buf.put_u32(u32::try_from(parameters.len())?); // entry_count
                            buf.put_u32(1); // entry_count
                            let e = parameters.mp4_sample_entry().build().map_err(|e| {
                                anyhow!(
                                    "unable to produce VisualSampleEntry for {} stream: {}",
                                    parameters.rfc6381_codec(),
                                    e,
                                )
                            })?;
                            buf.extend_from_slice(&e);
                        });
                        self.video_trak.write_common_stbl_parts(buf)?;
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

    fn write_audio_trak(
        &self,
        buf: &mut BytesMut,
        parameters: &AudioParameters,
    ) -> Result<(), Error> {
        write_box!(buf, b"trak", {
            write_box!(buf, b"tkhd", {
                buf.put_u32((1 << 24) | 3); // version, flags
                buf.put_u64(0); // creation_time
                buf.put_u64(0); // modification_time
                buf.put_u32(2); // track_id
                buf.put_u32(0); // reserved
                buf.put_u64(self.audio_trak.tot_duration);
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
                    buf.put_u32(parameters.clock_rate());
                    buf.put_u64(self.audio_trak.tot_duration);
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
                            buf.extend_from_slice(
                                &parameters
                                    .mp4_sample_entry()
                                    .build()
                                    .expect("all added streams have sample entries"),
                            );
                        });
                        self.audio_trak.write_common_stbl_parts(buf)?;

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
                            buf.put_u32(self.audio_trak.samples);
                            buf.put_u32(1); // group_description_index
                        });
                    });
                });
            });
        });
        Ok(())
    }

    pub async fn finish_fragment(&mut self) -> Result<(), Error> {
        self.video_trak.finish();
        self.audio_trak.finish();
        let mut buf = BytesMut::with_capacity(
            1024 + self.video_trak.size_estimate()
                + self.audio_trak.size_estimate()
                + 4 * self.video_sync_sample_nums.len(),
        );
        write_box!(&mut buf, b"moof", {
            write_box!(&mut buf, b"mfhd", {
                buf.put_u32(1 << 24); // version, flags
                buf.put_u32(1); // sequence number
            });
            if self.video_trak.samples > 0 {
                self.write_video_fragment(&mut buf)?;
            }
            if self.audio_trak.samples > 0 {
                self.write_audio_fragment(&mut buf)?;
            }
        });

        buf.extend_from_slice(
            &u32::try_from(self.fbuf_video.len() + self.fbuf_audio.len() + 8)?.to_be_bytes()[..],
        );
        buf.extend_from_slice(&b"mdat"[..]);

        self.inner.write_all(&buf).await?;
        self.inner.write_all(&self.fbuf_video).await?;
        self.inner.write_all(&self.fbuf_audio).await?;

        self.video_trak.clean();
        self.audio_trak.clean();
        self.fbuf_video.clear();
        self.fbuf_audio.clear();

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

    async fn video(&mut self, frame: retina::codec::VideoFrame) -> Result<(), Error> {
        let size = u32::try_from(frame.data().remaining())?;
        self.video_trak
            .add_sample(size, frame.timestamp(), frame.loss(), self.allow_loss)?;
        self.mdat_pos = self
            .mdat_pos
            .checked_add(size)
            .ok_or_else(|| anyhow!("mdat_pos overflow"))?;
        if frame.is_random_access_point() {
            self.video_sync_sample_nums.push(self.video_trak.samples);
        }
        self.fbuf_video.append(&mut frame.data().to_vec());
        Ok(())
    }

    async fn audio(&mut self, frame: retina::codec::AudioFrame) -> Result<(), Error> {
        let size = u32::try_from(frame.data().remaining())?;
        self.audio_trak
            .add_sample(size, frame.timestamp(), frame.loss(), self.allow_loss)?;
        self.mdat_pos = self
            .mdat_pos
            .checked_add(size)
            .ok_or_else(|| anyhow!("mdat_pos overflow"))?;
        self.fbuf_audio.append(&mut frame.data().to_vec());
        Ok(())
    }
}

/// Copies packets from `session` to `mp4` without handling any cleanup on error.
async fn copy<'a, W: AsyncWrite + Unpin>(
    session: &'a mut retina::client::Demuxed,
    mp4: &'a mut Fmp4Writer<W>,
) -> Result<(), Error> {
    loop {
        tokio::select! {
            pkt = session.next() => {
                match pkt.ok_or_else(|| anyhow!("EOF"))?? {
                    CodecItem::VideoFrame(f) => {
                        if f.is_random_access_point() {
                            if let Err(_e) = mp4.finish_fragment().await {
                                // This will be executed when livestream ends.
                                // log::error!(".mp4 finish failed: {}", e);
                                break;
                            }
                        }
                        let start_ctx = *f.start_ctx();
                        mp4.video(f).await.with_context(
                            || format!("Error processing video frame starting with {start_ctx}"))?;
                    },
                    CodecItem::AudioFrame(f) => {
                        let ctx = *f.ctx();
                        mp4.audio(f).await.with_context(
                            || format!("Error processing audio frame, {ctx}"))?;
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
    Ok(())
}

/// Writes the `.mp4`, including trying to finish or clean up the file.
async fn write_mp4<W: AsyncWrite + Unpin>(
    session: retina::client::Session<retina::client::Described>,
    video_params: Option<Box<VideoParameters>>,
    audio_params: Option<Box<AudioParameters>>,
    writer: W,
) -> Result<(), Error> {
    let mut session = session
        .play(
            retina::client::PlayOptions::default()
                .initial_timestamp(retina::client::InitialTimestampPolicy::Default)
                .enforce_timestamps_with_max_jump_secs(NonZeroU32::new(10).unwrap())
                .unknown_rtcp_ssrc(retina::client::UnknownRtcpSsrcPolicy::Default),
        )
        .await?
        .demuxed()?;

    // Set allow_loss to false since we're using TCP.
    let mut mp4 = Fmp4Writer::new(video_params, audio_params, false, writer).await?;
    mp4.finish_header().await?;
    copy(&mut session, &mut mp4).await?;

    Ok(())
}

/// Record an mp4 video file from the IP camera
/// username: username of the IP camera
/// passwword: password of the IP camera
/// url: RTSP url of the IP camera
/// filename: the name of the mp4 file to be used
/// duration: the duration of the video, in seconds.
pub async fn record<W: AsyncWrite + Unpin>(
    username: String,
    password: String,
    url: String,
    writer: W,
) -> Result<(), Error> {
    let creds = retina::client::Credentials { username, password };
    let session_group = Arc::new(retina::client::SessionGroup::default());
    let url_parsed = Url::parse(&url)?;
    let mut session = retina::client::Session::describe(
        url_parsed,
        retina::client::SessionOptions::default()
            .creds(Some(creds))
            .session_group(session_group.clone())
            .user_agent("Retina mp4 example".to_owned())
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
        Some(ParametersRef::Video(params)) => Some(Box::new(params.clone())),
        _ => {
            bail!("Exiting because no video parameters were found");
        }
    };

    let result = write_mp4(session, video_params, audio_stream.map(|(_i, p)| p), writer).await;
    if result.is_err() {
        log::info!(
            "writing MP4 failed; \
                    details will be logged with `Fatal:` after RTSP session teardown"
        );
    }

    // Session has now been dropped, on success or failure. A TEARDOWN should
    // be pending if necessary. session_group.await_teardown() will wait for it.
    if let Err(e) = session_group.await_teardown().await {
        log::error!("TEARDOWN failed: {}", e);
    }
    result
}
