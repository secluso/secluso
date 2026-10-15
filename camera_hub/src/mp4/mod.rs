//! Mp4 camera backend.
//!
//! SPDX-License-Identifier: GPL-3.0-or-later

// The shared Mp4Camera backend is only used by the platforms that feed it frames.
// The IP camera has its own backend in ip/, so leave it out of that build.
#[cfg(any(feature = "raspberry", feature = "android"))]
pub(crate) mod mp4_camera;
pub(crate) mod mp4;
pub(crate) mod fmp4;
