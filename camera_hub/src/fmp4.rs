//! Secluso fMP4 Writer, used for livestreaming.
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

use crate::mp4::{Mp4WriterCore, TrakTrackerCore};
use crate::traits::{CodecParameters, Mp4};
use crate::write_box;
use anyhow::{anyhow, Error};
use bytes::{BufMut, BytesMut};

use std::convert::TryFrom;
use tokio::io::{AsyncWrite, AsyncWriteExt};

mod fmp4_flags {
    /// Ensure the 6 MSB reserved bits are set to 1 as some players expect.
    #[inline]
    pub const fn with_reserved(bits: u32) -> u32 {
        (bits & 0x03FF_FFFF) | 0xFC00_0000
    }

    // Common flag payloads (without reserved):
    // Non-sync (inter-frame): 0x0001_0000  (sample_is_non_sync_sample = 1)
    // RAP/keyframe (IDR):     0x0200_0000  (sample_depends_on = 2, does not depend on others)
    pub const NON_SYNC_BASE: u32 = 0x0001_0000;
    pub const RAP_BASE: u32 = 0x0200_0000;

    pub const NON_SYNC: u32 = with_reserved(NON_SYNC_BASE);
    pub const RAP: u32 = with_reserved(RAP_BASE);
}

#[derive(Default)]
struct TrakTracker {
    core: TrakTrackerCore,
    samples_durations_sizes: Vec<(u32, u32)>,
    fragment_start_time: u64,
    last_timestamp: u64,
    first_sample_is_rap: bool,
    default_frame_ticks: u32,
}

impl TrakTracker {
    fn with_default_ticks(default_ticks: u32) -> Self {
        Self {
            core: TrakTrackerCore::default(),
            samples_durations_sizes: Vec::new(),
            fragment_start_time: 0,
            last_timestamp: 0,
            first_sample_is_rap: false,
            default_frame_ticks: default_ticks,
        }
    }

    fn add_sample(&mut self, size: u32, timestamp: u64, is_rap: bool) -> Result<(), Error> {
        self.core.samples += 1;

        // iOS is strict about a zero first-sample duration
        let duration: u32 = if self.last_timestamp == 0 {
            // exampl: 90_000 / 10 = 9000 ticks @ 10 fps
            self.default_frame_ticks.max(1)
        } else {
            (timestamp - self.last_timestamp).try_into().unwrap()
        };

        self.last_timestamp = timestamp;
        self.core.tot_duration = self
            .core
            .tot_duration
            .checked_add(u64::from(duration))
            .unwrap();

        if self.core.samples == 1 {
            self.first_sample_is_rap = is_rap;
        }

        self.samples_durations_sizes.push((duration, size));
        Ok(())
    }

    // Writes tfdt + trun. Returns the moof-relative byte position of the i32 data_offset.
    fn write_fragment(&self, buf: &mut BytesMut) -> Result<Option<usize>, Error> {
        write_box!(buf, b"tfdt", {
            buf.put_u32(1 << 24); // version=1, flags=0
            buf.put_u64(self.fragment_start_time);
        });

        let data_offset_pos: Option<usize>;

        const TRUN_DATA_OFFSET: u32 = 0x000001;
        const TRUN_FIRST_SAMPLE_FL: u32 = 0x000004;
        const TRUN_SAMPLE_DURATION: u32 = 0x000100;
        const TRUN_SAMPLE_SIZE: u32 = 0x000200;

        write_box!(buf, b"trun", {
            let flags =
                TRUN_DATA_OFFSET | TRUN_FIRST_SAMPLE_FL | TRUN_SAMPLE_DURATION | TRUN_SAMPLE_SIZE;
            buf.put_u32(flags);
            buf.put_u32(self.core.samples);

            // data_offset placeholder
            data_offset_pos = Some(buf.len());
            buf.put_i32(0);

            // first_sample_flags
            let first_flags = if self.first_sample_is_rap {
                fmp4_flags::RAP
            } else {
                fmp4_flags::NON_SYNC
            };
            buf.put_u32(first_flags);

            // per-sample fields
            for (dur, sz) in &self.samples_durations_sizes {
                buf.put_u32(*dur);
                buf.put_u32(*sz);
            }
        });

        Ok(data_offset_pos)
    }

    fn clean(&mut self) {
        self.core.samples = 0;
        self.core.chunks.clear();
        self.core.sizes.clear();
        self.core.durations.clear();
        self.samples_durations_sizes.clear();
        self.fragment_start_time = self.core.tot_duration;
        self.first_sample_is_rap = false;
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

    seq_no: u32,
}

impl<W: AsyncWrite + Unpin, V: CodecParameters, A: CodecParameters> Fmp4Writer<W, V, A> {
    pub async fn new(video_params: V, audio_params: A, mut inner: W) -> Result<Self, Error> {
        let mut buf = BytesMut::new();
        write_box!(&mut buf, b"ftyp", {
            buf.extend_from_slice(b"isom"); // major_brand
            buf.extend_from_slice(&0x00000200u32.to_be_bytes()); // minor_version
            buf.extend_from_slice(b"isom"); // compat[0]
            buf.extend_from_slice(b"iso6"); // compat[1]
            buf.extend_from_slice(b"avc1"); // compat[2]
            buf.extend_from_slice(b"mp41"); // compat[3]
        });

        inner.write_all(&buf).await?;

        // 90 kHz timescale. We assume a constant 10 FPS based on rpi_camera/rpi_dual_stream. TODO: I'm not sure of what to put IP camera FPS.
        let fps: u32 = 10;
        let default_video_ticks: u32 = (90_000u32 / fps).max(1);

        Ok(Fmp4Writer {
            core: Mp4WriterCore::new(video_params, audio_params, inner, 0).await,
            video_trak: TrakTracker::with_default_ticks(default_video_ticks),
            audio_trak: TrakTracker::with_default_ticks(0),
            fbuf_video: Vec::new(),
            fbuf_audio: Vec::new(),
            seq_no: 1,
        })
    }

    pub async fn finish_header(&mut self, total_duration_90k: Option<u64>) -> Result<(), Error> {
        let mut buf = BytesMut::with_capacity(
            1024 + self.video_trak.core.size_estimate()
                + self.audio_trak.core.size_estimate()
                + 4 * self.core.video_sync_sample_nums.len(),
        );

        write_box!(&mut buf, b"moov", {
            write_box!(&mut buf, b"mvhd", {
                buf.put_u32(1 << 24); // version=1
                buf.put_u64(0); // creation_time
                buf.put_u64(0); // modification_time
                buf.put_u32(90000); // timescale
                buf.put_u64(self.video_trak.core.tot_duration); // 0 at init is fine
                buf.put_u32(0x00010000); // rate
                buf.put_u16(0x0100); // volume
                buf.put_u16(0); // reserved
                buf.put_u64(0); // reserved
                for v in &[0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000] {
                    buf.put_u32(*v); // matrix
                }
                for _ in 0..6 {
                    buf.put_u32(0);
                } // pre_defined
                buf.put_u32(2); // next_track_id
            });

            self.core
                .write_video_trak(&mut buf, &self.video_trak.core)?;
            // FIXME: disabling this for now as it breaks our livestreaming.
            //self.core.write_audio_trak(&mut buf, &self.audio_trak.core)?;

            write_box!(&mut buf, b"mvex", {
                write_box!(&mut buf, b"mehd", {
                    buf.put_u32(1 << 24); // version=1, flags=0
                                          // 0 is open-ended/unspecified duration
                    let dur = total_duration_90k.unwrap_or(0);
                    buf.put_u64(dur);
                });

                // trex for video
                write_box!(&mut buf, b"trex", {
                    buf.put_u32(1 << 24); // version, flags
                    buf.put_u32(1); // track id (video)
                    buf.put_u32(1); // default sample description index
                    buf.put_u32(0); // default sample duration (0 is use trun)
                    buf.put_u32(0); // default sample size (0 is use trun)
                                    // default sample flags
                    buf.put_u32(fmp4_flags::with_reserved(0x0001_0000));
                });

                // trex for audio
                // FIXME: disabling this for now as it breaks our livestreaming.
                /*
                write_box!(&mut buf, b"trex", {
                    buf.put_u32(1 << 24);
                    buf.put_u32(2);
                    buf.put_u32(1);
                    buf.put_u32(0);
                    buf.put_u32(0);
                    buf.put_u32(fmp4_flags::with_reserved(0x0001_0000));
                });
                */
            });
        });

        self.core.inner.write_all(&buf).await?;
        Ok(())
    }

    fn write_video_fragment(&self, buf: &mut BytesMut) -> Result<Option<usize>, Error> {
        let trun_off: Option<usize>;
        write_box!(buf, b"traf", {
            write_box!(buf, b"tfhd", {
                buf.put_u32(0x020000); // default-base-is-moof
                buf.put_u32(1); // video track_id
            });
            // write tfdt + trun *inside* traf
            trun_off = self.video_trak.write_fragment(buf)?;
        });
        Ok(trun_off)
    }

    fn write_audio_fragment(&self, buf: &mut BytesMut) -> Result<Option<usize>, Error> {
        let trun_off: Option<usize>;
        write_box!(buf, b"traf", {
            write_box!(buf, b"tfhd", {
                buf.put_u32(0x020000); // default-base-is-moof
                buf.put_u32(2); // audio track_id
            });
            trun_off = self.audio_trak.write_fragment(buf)?;
        });
        Ok(trun_off)
    }
}

impl<W: AsyncWrite + Unpin, V: CodecParameters, A: CodecParameters> Mp4 for Fmp4Writer<W, V, A> {
    async fn video(&mut self, frame: &[u8], ts: u64, is_rap: bool) -> Result<(), Error> {
        let size = u32::try_from(frame.len())?;
        self.video_trak.add_sample(size, ts, is_rap)?;
        self.core.mdat_pos = self
            .core
            .mdat_pos
            .checked_add(size)
            .ok_or_else(|| anyhow!("mdat_pos overflow"))?;
        self.fbuf_video.extend_from_slice(frame);
        Ok(())
    }

    async fn audio(&mut self, frame: &[u8], ts: u64) -> Result<(), Error> {
        let size = u32::try_from(frame.len())?;
        self.audio_trak.add_sample(size, ts, false)?;
        self.core.mdat_pos = self
            .core
            .mdat_pos
            .checked_add(size)
            .ok_or_else(|| anyhow!("mdat_pos overflow"))?;
        self.fbuf_audio.extend_from_slice(frame);
        Ok(())
    }

    async fn finish_fragment(&mut self) -> Result<(), Error> {
        self.video_trak.core.finish();
        self.audio_trak.core.finish();

        // Nothing to flush if there's no payload
        if self.fbuf_video.is_empty() && self.fbuf_audio.is_empty() {
            self.video_trak.clean();
            self.audio_trak.clean();
            return Ok(());
        }

        let mut moof = BytesMut::with_capacity(
            1024 + self.video_trak.core.size_estimate()
                + self.audio_trak.core.size_estimate()
                + 4 * self.core.video_sync_sample_nums.len(),
        );

        let mut v_off: Option<usize> = None;
        let mut a_off: Option<usize> = None;

        write_box!(&mut moof, b"moof", {
            write_box!(&mut moof, b"mfhd", {
                moof.put_u32(0);
                moof.put_u32(self.seq_no);
            });

            if self.video_trak.core.samples > 0 {
                v_off = self.write_video_fragment(&mut moof)?;
            }
            if self.audio_trak.core.samples > 0 {
                a_off = self.write_audio_fragment(&mut moof)?;
            }
        });

        // Patch trun data_offsets relative to start-of-moof
        let base = (moof.len() as i32) + 8;
        if let Some(pos) = v_off {
            let off = base; // video starts right after mdat header
            moof[pos + 0] = ((off >> 24) & 0xFF) as u8;
            moof[pos + 1] = ((off >> 16) & 0xFF) as u8;
            moof[pos + 2] = ((off >> 8) & 0xFF) as u8;
            moof[pos + 3] = ((off >> 0) & 0xFF) as u8;
        }
        if let Some(pos) = a_off {
            let off = base + (self.fbuf_video.len() as i32); // audio follows video bytes
            moof[pos + 0] = ((off >> 24) & 0xFF) as u8;
            moof[pos + 1] = ((off >> 16) & 0xFF) as u8;
            moof[pos + 2] = ((off >> 8) & 0xFF) as u8;
            moof[pos + 3] = ((off >> 0) & 0xFF) as u8;
        }

        // Write moof + mdat + payload
        self.core.inner.write_all(&moof).await?;

        let mdat_payload_len = self.fbuf_video.len() + self.fbuf_audio.len();
        let mdat_size: u32 = (mdat_payload_len + 8).try_into()?;

        let mut mdat = BytesMut::with_capacity(8);
        mdat.extend_from_slice(&mdat_size.to_be_bytes());
        mdat.extend_from_slice(b"mdat");

        self.core.inner.write_all(&mdat).await?;
        if !self.fbuf_video.is_empty() {
            self.core.inner.write_all(&self.fbuf_video).await?;
        }
        if !self.fbuf_audio.is_empty() {
            self.core.inner.write_all(&self.fbuf_audio).await?;
        }
        self.core.inner.flush().await?;

        // Next fragment + cleanup
        self.seq_no = self.seq_no.wrapping_add(1);
        self.video_trak.clean();
        self.audio_trak.clean();
        self.fbuf_video.clear();
        self.fbuf_audio.clear();
        Ok(())
    }
}
