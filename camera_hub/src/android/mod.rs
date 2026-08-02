//! Android camera backend.
//!
//! SPDX-License-Identifier: GPL-3.0-or-later

pub(crate) mod android_camera;
pub(crate) mod android_dual_stream;

#[cfg(miri)]
pub(crate) mod mock_ndk_sys;
