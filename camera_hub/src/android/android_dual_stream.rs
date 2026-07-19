//! Android dual stream bridge.
//!
//! SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::VecDeque;
use std::os::raw::c_int;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use crossbeam_channel::Sender;

use crate::mp4::mp4_camera::{Frame, FrameKind};

pub const ANDROID_CAMERA_FACING_BACK: i32 = 0;
pub const ANDROID_CAMERA_FACING_FRONT: i32 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AndroidCameraResolution {
    pub width: usize,
    pub height: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AndroidCameraFrameRateRange {
    pub min: i32,
    pub max: i32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AndroidCameraSpec {
    pub facing: i32,
    pub resolutions: Vec<AndroidCameraResolution>,
    pub frame_rate_ranges: Vec<AndroidCameraFrameRateRange>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AndroidCameraSettings {
    pub facing: i32,
    pub width: usize,
    pub height: usize,
    pub frame_rate_range: AndroidCameraFrameRateRange,
}

impl Default for AndroidCameraSettings {
    fn default() -> Self {
        Self {
            facing: ANDROID_CAMERA_FACING_BACK,
            width: 1280,
            height: 720,
            frame_rate_range: AndroidCameraFrameRateRange { min: 10, max: 10 },
        }
    }
}

pub fn get_available_specs() -> anyhow::Result<Vec<AndroidCameraSpec>> {
    ndk::available_camera_specs()
        .map_err(|e| anyhow::anyhow!("failed to get Android camera specs: {e}"))
}

struct AndroidStreamState {
    frame_queue: Arc<Mutex<VecDeque<Frame>>>,
    ps_tx: Sender<Frame>,
}

pub struct AndroidStreamHandle {
    _native: ndk::NativeCamera,
    _state: Arc<AndroidStreamState>,
}

#[allow(clippy::too_many_arguments)]
pub fn start(
    facing: i32,
    width: usize,
    height: usize,
    frame_rate_range: AndroidCameraFrameRateRange,
    i_frame_interval: usize,
    bitrate: usize,
    //FIXME
    //pipeline_controller: Arc<Mutex<PipelineController>>,
    frame_queue: Arc<Mutex<VecDeque<Frame>>>,
    ps_tx: Sender<Frame>,
    motion_fps: u8,
) -> anyhow::Result<AndroidStreamHandle> {
    let state = Arc::new(AndroidStreamState {
        frame_queue,
        ps_tx,
    });

    if facing != ANDROID_CAMERA_FACING_BACK && facing != ANDROID_CAMERA_FACING_FRONT {
        return Err(anyhow::anyhow!("unsupported Android camera facing: {facing}"));
    }

    let width = c_int::try_from(width)
        .map_err(|_| anyhow::anyhow!("Invalid width"))?;
    let height = c_int::try_from(height)
        .map_err(|_| anyhow::anyhow!("Invalid height"))?;
    if frame_rate_range.min <= 0
        || frame_rate_range.max <= 0
        || frame_rate_range.min > frame_rate_range.max
    {
        return Err(anyhow::anyhow!("Invalid frame rate range"));
    }
    let bitrate = c_int::try_from(bitrate)
        .map_err(|_| anyhow::anyhow!("Invalid bitrate"))?;
    let i_frame_interval = c_int::try_from(i_frame_interval)
        .map_err(|_| anyhow::anyhow!("In valid keyframe interval"))?;

    let config = ndk::CameraConfig {
        facing,
        width,
        height,
        fps_min: frame_rate_range.min,
        fps_max: frame_rate_range.max,
        bitrate,
        i_frame_interval,
        motion_fps: c_int::from(motion_fps),
    };

    let callbacks = ndk::CameraCallbacks {
        state: Arc::clone(&state),
        on_h264,
        on_aac,
        on_raw_i420,
        on_error,
    };

    let native = ndk::NativeCamera::start(config, callbacks)
        .map_err(|e| anyhow::anyhow!("failed to start Android native camera: {e}"))?;

    Ok(AndroidStreamHandle {
        _native: native,
        _state: state,
    })
}

fn on_h264(
    state: &AndroidStreamState,
    data: &[u8],
    kind: FrameKind,
) {
    if data.is_empty() {
        return;
    }

    let frame = Frame {
        data: data.to_vec(),
        kind,
        timestamp: SystemTime::now(),
    };

    if frame.kind == FrameKind::Sps || frame.kind == FrameKind::Pps {
        let _ = state.ps_tx.send(frame.clone());
    }
    add_frame_and_drop_old(Arc::clone(&state.frame_queue), frame);
}

fn on_aac(
    state: &AndroidStreamState,
    data: &[u8]
) {
    if data.is_empty() {
        return;
    }

    let frame = Frame {
        data: data.to_vec(),
        kind: FrameKind::Audio,
        timestamp: SystemTime::now(),
    };

    add_frame_and_drop_old(Arc::clone(&state.frame_queue), frame);
}

fn on_raw_i420(
    _state: &AndroidStreamState,
    data: &[u8],
    width: usize,
    height: usize,
) {
    if data.is_empty() || width == 0 || height == 0 {
        return;
    }

    let expected = width * height * 3 / 2;
    if data.len() < expected {
        return;
    }

    //FIXME
    /*
    let buffer = data[..expected].to_vec();
    let raw_frame = RawFrame::create_from_buffer(buffer, width, height);
    if let Ok(mut lock) = state.pipeline_controller.lock() {
        lock.push_frame(raw_frame);
    }
    */
}

fn on_error(message: &str) {
    error!("[AndroidCamera] {message}");
}

//FIXME: copied from rpi_dual_stream.rs
fn add_frame_and_drop_old(frame_queue: Arc<Mutex<VecDeque<Frame>>>, frame: Frame) {
    let time_window = Duration::new(5, 0);
    let mut queue = frame_queue.lock().unwrap();
    queue.push_back(frame);

    // Remove frames older than the time window.
    while let Some(front) = queue.front() {
        if SystemTime::now()
            .duration_since(front.timestamp)
            .unwrap_or_default()
            > time_window
        {
            queue.pop_front();
        } else {
            break;
        }
    }
}

mod ndk {
    use std::collections::BTreeSet;
    use std::ffi::CString;
    use std::os::raw::{c_char, c_int, c_void};
    use std::ptr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Condvar, Mutex};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};

    use ndk_sys as sys;

    use super::{
        AndroidCameraFrameRateRange, AndroidCameraResolution, AndroidCameraSpec,
        ANDROID_CAMERA_FACING_BACK, ANDROID_CAMERA_FACING_FRONT,
    };

    const CAMERA_OK: sys::camera_status_t = sys::camera_status_t(0);
    const MEDIA_OK: sys::media_status_t = sys::media_status_t(0);
    const AIMAGE_FORMAT_IMPLEMENTATION_DEFINED: c_int = 0x22;
    const AIMAGE_FORMAT_YUV_420_888: c_int = 0x23;
    const K_FACING_FRONT: c_int = 1;
    const K_COLOR_FORMAT_SURFACE: c_int = 0x7F000789;
    const K_AUDIO_SAMPLE_RATE: c_int = 48_000;
    const K_AUDIO_CHANNEL_COUNT: c_int = 1;
    const K_AUDIO_BITRATE: c_int = 96_000;
    const K_AUDIO_SAMPLES_PER_ACCESS_UNIT: usize = 1024;
    const K_AUDIO_BYTES_PER_SAMPLE: usize = std::mem::size_of::<i16>();
    const K_AAC_OBJECT_LC: c_int = 2;

    #[derive(Clone, Copy)]
    pub(super) struct CameraConfig {
        pub facing: c_int,
        pub width: c_int,
        pub height: c_int,
        pub fps_min: c_int,
        pub fps_max: c_int,
        pub bitrate: c_int,
        pub i_frame_interval: c_int,
        pub motion_fps: c_int,
    }

    #[derive(Clone)]
    pub(super) struct CameraCallbacks {
        pub state: Arc<super::AndroidStreamState>,
        pub on_h264: fn(&super::AndroidStreamState, &[u8], super::FrameKind),
        pub on_aac: fn(&super::AndroidStreamState, &[u8]),
        pub on_raw_i420: fn(&super::AndroidStreamState, &[u8], usize, usize),
        pub on_error: fn(&str),
    }

    pub(super) struct NativeCamera {
        bridge: Box<CameraBridge>,
    }

    pub(super) fn available_camera_specs() -> Result<Vec<AndroidCameraSpec>, String> {
        let manager = unsafe {
            // SAFETY
            // None.
            sys::ACameraManager_create()
        };
        if manager.is_null() {
            return Err("ACameraManager_create failed".to_string());
        }

        let result = unsafe {
            // SAFETY
            // 1. manager is a live ACameraManager.
            read_camera_specs(manager)
        };

        unsafe {
            // SAFETY
            // 1. manager is live and no longer used after this call.
            sys::ACameraManager_delete(manager);
        }

        result
    }

    /// # Safety
    /// 1. manager must be a live ACameraManager.
    unsafe fn read_camera_specs(
        manager: *mut sys::ACameraManager,
    ) -> Result<Vec<AndroidCameraSpec>, String> {
        if manager.is_null() {
            return Err("ACameraManager was null".to_string());
        }

        let mut ids: *mut sys::ACameraIdList = ptr::null_mut();

        // SAFETY
        // 1. manager is live.
        // 2. ids is writable.
        if unsafe { sys::ACameraManager_getCameraIdList(manager, &mut ids) } != CAMERA_OK || ids.is_null() {
            return Err("ACameraManager_getCameraIdList failed".to_string());
        }

        // SAFETY
        // 1. ids is not null and points to the live camera-id list returned by the NDK.
        let id_list = unsafe { &*ids };
        let Ok(num_cameras) = usize::try_from(id_list.numCameras) else {
            // SAFETY
            // 1. ids is a live camera-id list returned by the NDK.
            unsafe { sys::ACameraManager_deleteCameraIdList(ids) };
            return Err("camera-id list reported a negative camera count".to_string());
        };

        if num_cameras > 0 && id_list.cameraIds.is_null() {
            // SAFETY
            // 1. ids is a live camera-id list returned by the NDK.
            unsafe { sys::ACameraManager_deleteCameraIdList(ids) };
            return Err("camera-id list contained a null cameraIds pointer".to_string());
        }

        let mut specs = Vec::new();
        for i in 0..num_cameras {
            // SAFETY
            // 1. cameraIds points to num_cameras entries.
            // 2. i < num_cameras.
            let id_ptr = unsafe { *id_list.cameraIds.add(i) };
            if id_ptr.is_null() {
                continue;
            }

            let mut metadata: *mut sys::ACameraMetadata = ptr::null_mut();

            // SAFETY
            // 1. manager is live.
            // 2. id_ptr comes from the live camera-id list.
            // 3. metadata is writable.
            let status =
                unsafe { sys::ACameraManager_getCameraCharacteristics(manager, id_ptr, &mut metadata) };
            if status != CAMERA_OK || metadata.is_null() {
                if !metadata.is_null() {
                    // SAFETY
                    // 1. metadata was returned by the NDK and not freed yet.
                    unsafe { sys::ACameraMetadata_free(metadata) };
                }
                continue;
            }

            // SAFETY
            // 1. metadata is live until it is freed below.
            let spec = unsafe { read_camera_spec(metadata) };

            // SAFETY
            // 1. metadata was returned by the NDK and not freed yet.
            unsafe { sys::ACameraMetadata_free(metadata) };

            if let Some(spec) = spec {
                // Avoid duplicate cameras.
                if !specs
                    .iter()
                    .any(|existing: &AndroidCameraSpec| existing.facing == spec.facing)
                {
                    specs.push(spec);
                }
            }
        }

        // SAFETY
        // 1. ids is a live camera-id list returned by the NDK.
        unsafe { sys::ACameraManager_deleteCameraIdList(ids) };

        Ok(specs)
    }

    /// # Safety
    /// 1. metadata must be a live ACameraMetadata.
    unsafe fn read_camera_spec(metadata: *mut sys::ACameraMetadata) -> Option<AndroidCameraSpec> {
        if metadata.is_null() {
            return None;
        }

        // SAFETY
        // 1. metadata is live.
        let facing = unsafe { read_camera_facing(metadata) }?;

        // SAFETY
        // 1. metadata is live.
        let resolutions = unsafe { read_camera_resolutions(metadata) };

        // SAFETY
        // 1. metadata is live.
        let frame_rate_ranges = unsafe { read_frame_rate_ranges(metadata) };

        Some(AndroidCameraSpec {
            facing,
            resolutions,
            frame_rate_ranges,
        })
    }

    /// # Safety
    /// 1. metadata must be a live ACameraMetadata.
    unsafe fn read_camera_facing(metadata: *mut sys::ACameraMetadata) -> Option<i32> {
        if metadata.is_null() {
            return None;
        }

        let mut entry = std::mem::MaybeUninit::<sys::ACameraMetadata_const_entry>::uninit();

        // SAFETY
        // 1. metadata is live.
        // 2. entry is writable.
        if unsafe { sys::ACameraMetadata_getConstEntry(
            metadata,
            sys::acamera_metadata_tag::ACAMERA_LENS_FACING.0,
            entry.as_mut_ptr(),
        ) } != CAMERA_OK
        {
            return None;
        }

        // SAFETY
        // 1. The successful NDK call initialized entry.
        let entry = unsafe { entry.assume_init() };
        if entry.count == 0 {
            return None;
        }

        // SAFETY
        // 1. ACAMERA_LENS_FACING metadata contains u8 data.
        // 2. entry came from a successful metadata lookup and count is non-zero.
        let facing = unsafe { camera_metadata_u8(&entry) }?;

        if facing
            == sys::acamera_metadata_enum_acamera_lens_facing::ACAMERA_LENS_FACING_FRONT.0 as u8
        {
            Some(ANDROID_CAMERA_FACING_FRONT)
        } else if facing
            == sys::acamera_metadata_enum_acamera_lens_facing::ACAMERA_LENS_FACING_BACK.0 as u8
        {
            Some(ANDROID_CAMERA_FACING_BACK)
        } else {
            None
        }
    }

    /// # Safety
    /// 1. metadata must be a live ACameraMetadata.
    unsafe fn read_camera_resolutions(
        metadata: *mut sys::ACameraMetadata,
    ) -> Vec<AndroidCameraResolution> {
        if metadata.is_null() {
            return default_resolutions();
        }

        let mut entry = std::mem::MaybeUninit::<sys::ACameraMetadata_const_entry>::uninit();

        // SAFETY
        // 1. metadata is live.
        // 2. entry is writable.
        if unsafe { sys::ACameraMetadata_getConstEntry(
            metadata,
            sys::acamera_metadata_tag::ACAMERA_SCALER_AVAILABLE_STREAM_CONFIGURATIONS.0,
            entry.as_mut_ptr(),
        ) } != CAMERA_OK
        {
            return default_resolutions();
        }

        // SAFETY
        // 1. The successful NDK call initialized entry.
        let entry = unsafe { entry.assume_init() };
        if entry.count < 4 {
            return default_resolutions();
        }

        // SAFETY
        // 1. ACAMERA_SCALER_AVAILABLE_STREAM_CONFIGURATIONS contains i32 data.
        // 2. entry came from a successful metadata lookup.
        let Some(values) = (unsafe { camera_metadata_i32_vec(&entry) }) else {
            return default_resolutions();
        };

        let mut yuv_resolutions = BTreeSet::new();
        let mut encoder_surface_resolutions = BTreeSet::new();
        for chunk in values.chunks_exact(4) {
            let format = chunk[0];
            let Ok(width) = usize::try_from(chunk[1]) else {
                continue;
            };
            let Ok(height) = usize::try_from(chunk[2]) else {
                continue;
            };

            // input/output flag
            let input = chunk[3] != 0;

            if input {
                continue;
            }

            match format {
                AIMAGE_FORMAT_YUV_420_888 => {
                    yuv_resolutions.insert((width, height));
                }
                AIMAGE_FORMAT_IMPLEMENTATION_DEFINED => {
                    encoder_surface_resolutions.insert((width, height));
                }
                _ => {}
            }
        }

        // The capture session sends the same camera stream to a YUV reader and
        // the MediaCodec input surface. Only advertise dimensions supported by
        // both output types.
        let mut resolutions: Vec<_> = yuv_resolutions
            .intersection(&encoder_surface_resolutions)
            .map(|&(width, height)| AndroidCameraResolution { width, height })
            .collect();

        resolutions.sort_by(|a, b| {
            let area_a = a.width.saturating_mul(a.height);
            let area_b = b.width.saturating_mul(b.height);
            area_b
                .cmp(&area_a)
                .then_with(|| b.width.cmp(&a.width))
                .then_with(|| b.height.cmp(&a.height))
        });

        if resolutions.is_empty() {
            default_resolutions()
        } else {
            resolutions
        }
    }

    /// # Safety
    /// 1. metadata must be a live ACameraMetadata.
    unsafe fn read_frame_rate_ranges(
        metadata: *mut sys::ACameraMetadata,
    ) -> Vec<AndroidCameraFrameRateRange> {
        if metadata.is_null() {
            return default_frame_rate_ranges();
        }

        let mut entry = std::mem::MaybeUninit::<sys::ACameraMetadata_const_entry>::uninit();

        // SAFETY
        // 1. metadata is live.
        // 2. entry is writable.
        if unsafe { sys::ACameraMetadata_getConstEntry(
            metadata,
            sys::acamera_metadata_tag::ACAMERA_CONTROL_AE_AVAILABLE_TARGET_FPS_RANGES.0,
            entry.as_mut_ptr(),
        ) } != CAMERA_OK
        {
            return default_frame_rate_ranges();
        }

        // SAFETY
        // 1. The successful NDK call initialized entry.
        let entry = unsafe { entry.assume_init() };
        if entry.count < 2 {
            return default_frame_rate_ranges();
        }

        // SAFETY
        // 1. ACAMERA_CONTROL_AE_AVAILABLE_TARGET_FPS_RANGES contains i32 data.
        // 2. entry came from a successful metadata lookup.
        let Some(values) = (unsafe { camera_metadata_i32_vec(&entry) }) else {
            return default_frame_rate_ranges();
        };

        let mut ranges = Vec::new();
        for chunk in values.chunks_exact(2) {
            let min = chunk[0];
            let max = chunk[1];
            if min <= 0 {
                continue;
            }
            ranges.push(AndroidCameraFrameRateRange { min, max });
        }

        ranges.sort_by(|a, b| a.max.cmp(&b.max).then_with(|| a.min.cmp(&b.min)));
        ranges.dedup();

        if ranges.is_empty() {
            default_frame_rate_ranges()
        } else {
            ranges
        }
    }

    fn default_resolutions() -> Vec<AndroidCameraResolution> {
        vec![AndroidCameraResolution {
            width: 1280,
            height: 720,
        }]
    }

    fn default_frame_rate_ranges() -> Vec<AndroidCameraFrameRateRange> {
        vec![AndroidCameraFrameRateRange { min: 10, max: 10 }]
    }

    // SAFETY
    // 1. Native callbacks access only the shared callback state through shared references.
    // 2. The callback state remains live until native callback sources are closed and callbacks finish.
    // 3. Workers stop before native handles are freed.
    unsafe impl Send for NativeCamera {}

    impl NativeCamera {
        pub(super) fn start(config: CameraConfig, callbacks: CameraCallbacks) -> Result<Self, String> {
            let mut bridge = Box::new(CameraBridge::new(config, callbacks));
            unsafe {
                // SAFETY
                // 1. bridge.callback_state allocation remains live while callbacks are registered.
                if let Err(err) = bridge.start() {
                    // SAFETY
                    // 1. Native handles, if not null, are live.
                    // 2. Registered callbacks still point to bridge.callback_state until callbacks finish.
                    bridge.stop();
                    return Err(err);
                }
            }
            Ok(Self { bridge })
        }
    }

    impl Drop for NativeCamera {
        fn drop(&mut self) {
            // SAFETY
            // 1. Native handles, if not null, are live.
            // 2. Registered callbacks still point to the bridge callback state until callbacks finish.
            unsafe {
                self.bridge.stop();
            }
        }
    }

    struct CameraBridge {
        config: CameraConfig,
        callbacks: CameraCallbacks,
        running: Arc<AtomicBool>,
        callback_state: Arc<CameraCallbackState>,
        audio_enabled: bool,
        audio_encoder_started: bool,
        camera_id: Option<CString>,
        encoder_thread: Option<JoinHandle<()>>,
        audio_thread: Option<JoinHandle<()>>,
        manager: *mut sys::ACameraManager,
        device: *mut sys::ACameraDevice,
        session: *mut sys::ACameraCaptureSession,
        capture_request: *mut sys::ACaptureRequest,
        outputs: *mut sys::ACaptureSessionOutputContainer,
        encoder_output: *mut sys::ACaptureSessionOutput,
        raw_output: *mut sys::ACaptureSessionOutput,
        encoder_target: *mut sys::ACameraOutputTarget,
        raw_target: *mut sys::ACameraOutputTarget,
        reader: *mut sys::AImageReader,
        raw_window: *mut sys::ANativeWindow,
        encoder: *mut sys::AMediaCodec,
        encoder_window: *mut sys::ANativeWindow,
        audio_encoder: *mut sys::AMediaCodec,
        audio_stream: *mut sys::AAudioStream,
    }

    struct CameraCallbackState {
        config: CameraConfig,
        callbacks: CameraCallbacks,
        running: Arc<AtomicBool>,
        activity: Mutex<CallbackActivity>,
        activity_changed: Condvar,
        session_closed: Mutex<bool>,
        session_state_changed: Condvar,
        image_mutex: Mutex<()>,
        last_raw_emit: Mutex<Option<Instant>>,
    }

    struct CallbackActivity {
        stopping: bool,
        active: usize,
    }

    struct CallbackGuard<'a> {
        state: &'a CameraCallbackState,
        enabled: bool,
    }

    struct VideoEncoderThreadState {
        running: Arc<AtomicBool>,
        callbacks: CameraCallbacks,
        encoder: *mut sys::AMediaCodec,
    }

    struct AudioThreadState {
        running: Arc<AtomicBool>,
        callbacks: CameraCallbacks,
        audio_encoder: *mut sys::AMediaCodec,
        audio_stream: *mut sys::AAudioStream,
    }

    // SAFETY
    // 1. This state is moved into exactly one video encoder worker thread.
    // 2. The raw encoder handle remains live until
    // CameraBridge::stop sets running = false, joins the worker, and only then
    // deletes the codec.
    unsafe impl Send for VideoEncoderThreadState {}

    // SAFETY
    // 1. This state is moved into exactly one audio worker thread.
    // 2. The raw audio stream and audio encoder handles remain live until
    // CameraBridge::stop sets running = false, requests stream stop,
    // joins the worker, and only then closes/deletes the audio resources.
    unsafe impl Send for AudioThreadState {}

    impl CameraBridge {
        fn new(config: CameraConfig, callbacks: CameraCallbacks) -> Self {
            let running = Arc::new(AtomicBool::new(false));
            let callback_state = Arc::new(CameraCallbackState {
                config,
                callbacks: callbacks.clone(),
                running: Arc::clone(&running),
                activity: Mutex::new(CallbackActivity {
                    stopping: false,
                    active: 0,
                }),
                activity_changed: Condvar::new(),
                session_closed: Mutex::new(false),
                session_state_changed: Condvar::new(),
                image_mutex: Mutex::new(()),
                last_raw_emit: Mutex::new(None),
            });

            Self {
                config,
                callbacks,
                running,
                callback_state,
                audio_enabled: false,
                audio_encoder_started: false,
                camera_id: None,
                encoder_thread: None,
                audio_thread: None,
                manager: ptr::null_mut(),
                device: ptr::null_mut(),
                session: ptr::null_mut(),
                capture_request: ptr::null_mut(),
                outputs: ptr::null_mut(),
                encoder_output: ptr::null_mut(),
                raw_output: ptr::null_mut(),
                encoder_target: ptr::null_mut(),
                raw_target: ptr::null_mut(),
                reader: ptr::null_mut(),
                raw_window: ptr::null_mut(),
                encoder: ptr::null_mut(),
                encoder_window: ptr::null_mut(),
                audio_encoder: ptr::null_mut(),
                audio_stream: ptr::null_mut(),
            }
        }

        /// # Safety
        /// 1. self.callback_state allocation must remain live while native callbacks are registered.
        unsafe fn start(&mut self) -> Result<(), String> {
            if self.running.load(Ordering::SeqCst) || !self.manager.is_null() {
                return self.fail("Android camera already started");
            }

            // SAFETY
            // None.
            self.manager = unsafe { sys::ACameraManager_create() };
            if self.manager.is_null() {
                return self.fail("ACameraManager_create failed");
            }

            // SAFETY
            // 1. self.manager is a live ACameraManager.
            unsafe { self.select_camera() }?;
            // SAFETY
            // 1. self.callback_state allocation stays live while the listener is installed.
            unsafe { self.create_reader() }?;
            // SAFETY
            // None.
            unsafe { self.create_encoder() }?;
            // SAFETY
            // create_audio_encoder: None.
            // create_audio_recorder: None.
            self.audio_enabled = unsafe { self.create_audio_encoder() }.is_ok() && unsafe { self.create_audio_recorder() }.is_ok();
            if !self.audio_enabled {
                log::warn!("Android audio disabled; continuing with video-only camera startup");
                // SAFETY
                // 1. Audio handles, if not null, are live.
                // 2. No audio worker has been spawned yet.
                unsafe { self.release_audio_resources() };
            }
            // SAFETY
            // 1. self.manager is live.
            // 2. self.callback_state allocation stays live while callbacks are registered.
            unsafe { self.open_camera() }?;
            // SAFETY
            // 1. device, encoder_window, and raw_window are live.
            unsafe { self.create_capture_session() }?;

            self.running.store(true, Ordering::SeqCst);

            let encoder_state = VideoEncoderThreadState {
                running: Arc::clone(&self.running),
                callbacks: self.callbacks.clone(),
                encoder: self.encoder,
            };

            self.encoder_thread = Some(thread::spawn(move || {
                encoder_state.drain_encoder();
            }));

            if self.audio_enabled {
                // SAFETY
                // 1. self.audio_stream is live.
                if unsafe { sys::AAudioStream_requestStart(self.audio_stream) } != sys::AAUDIO_OK {
                    log::warn!("AAudioStream_requestStart failed; continuing without audio");
                    // SAFETY
                    // 1. Audio handles, if not null, are live.
                    // 2. No audio worker has been spawned yet.
                    unsafe { self.release_audio_resources() };
                } else {
                    let audio_state = AudioThreadState {
                        running: Arc::clone(&self.running),
                        callbacks: self.callbacks.clone(),
                        audio_encoder: self.audio_encoder,
                        audio_stream: self.audio_stream,
                    };

                    self.audio_thread = Some(thread::spawn(move || {
                        audio_state.drain_audio();
                    }));
                }
            }

            Ok(())
        }

        /// # Safety
        /// 1. Native handles, if not null, must be live.
        /// 2. Registered callbacks must still point to self.callback_state until callbacks finish.
        unsafe fn stop(&mut self) {
            self.callback_state.stop_callbacks();
            let was_running = self.running.swap(false, Ordering::SeqCst);
            let had_session = !self.session.is_null();

            if !self.session.is_null() {
                // SAFETY
                // 1. self.session is a live capture session.
                let _ = unsafe { sys::ACameraCaptureSession_stopRepeating(self.session) };
                // SAFETY
                // 1. self.session is a live capture session.
                let _ = unsafe { sys::ACameraCaptureSession_abortCaptures(self.session) };
                // SAFETY
                // 1. self.session is a live capture session.
                unsafe { sys::ACameraCaptureSession_close(self.session) };
            }

            if !self.audio_stream.is_null() {
                // SAFETY
                // 1. self.audio_stream is live.
                let _ = unsafe { sys::AAudioStream_requestStop(self.audio_stream) };
            }

            if let Some(handle) = self.encoder_thread.take() {
                let _ = handle.join();
            }
            if let Some(handle) = self.audio_thread.take() {
                let _ = handle.join();
            }

            if had_session {
                self.callback_state.wait_for_session_closed();
                self.callback_state.wait_for_callbacks();
                self.session = ptr::null_mut();
            }

            if !self.encoder.is_null() {
                // SAFETY
                // 1. self.encoder is live and the worker is joined.
                let _ = unsafe { sys::AMediaCodec_stop(self.encoder) };
                // SAFETY
                // 1. self.encoder is live.
                unsafe { sys::AMediaCodec_delete(self.encoder) };
                self.encoder = ptr::null_mut();
            }

            // SAFETY
            // 1. Audio handles, if not null, are live.
            // 2. Audio worker has been joined.
            unsafe { self.release_audio_resources() };

            if !self.capture_request.is_null() {
                // SAFETY
                // 1. self.capture_request is live.
                unsafe { sys::ACaptureRequest_free(self.capture_request) };
                self.capture_request = ptr::null_mut();
            }
            if !self.encoder_target.is_null() {
                // SAFETY
                // 1. self.encoder_target is live.
                unsafe { sys::ACameraOutputTarget_free(self.encoder_target) };
                self.encoder_target = ptr::null_mut();
            }
            if !self.raw_target.is_null() {
                // SAFETY
                // 1. self.raw_target is live.
                unsafe { sys::ACameraOutputTarget_free(self.raw_target) };
                self.raw_target = ptr::null_mut();
            }
            if !self.outputs.is_null() {
                // SAFETY
                // 1. self.outputs is live.
                unsafe { sys::ACaptureSessionOutputContainer_free(self.outputs) };
                self.outputs = ptr::null_mut();
            }
            if !self.encoder_output.is_null() {
                // SAFETY
                // 1. self.encoder_output is live.
                unsafe { sys::ACaptureSessionOutput_free(self.encoder_output) };
                self.encoder_output = ptr::null_mut();
            }
            if !self.raw_output.is_null() {
                // SAFETY
                // 1. self.raw_output is live.
                unsafe { sys::ACaptureSessionOutput_free(self.raw_output) };
                self.raw_output = ptr::null_mut();
            }
            if !self.encoder_window.is_null() {
                // SAFETY
                // 1. self.encoder_window is live.
                unsafe { sys::ANativeWindow_release(self.encoder_window) };
                self.encoder_window = ptr::null_mut();
            }
            self.callback_state.wait_for_callbacks();

            if !self.reader.is_null() {
                let _guard = self.callback_state.image_mutex.lock().unwrap();
                // SAFETY
                // 1. All enabled image callbacks have finished.
                // 2. self.reader is live.
                unsafe { sys::AImageReader_setImageListener(self.reader, ptr::null_mut()) };
                // SAFETY
                // 1. The listener is cleared and all enabled image callbacks have finished.
                // 2. self.reader is live.
                unsafe { sys::AImageReader_delete(self.reader) };
                self.reader = ptr::null_mut();
                self.raw_window = ptr::null_mut();
            }
            if !self.device.is_null() {
                // SAFETY
                // 1. self.device is live.
                unsafe { sys::ACameraDevice_close(self.device) };
                self.device = ptr::null_mut();
            }
            if !self.manager.is_null() {
                // SAFETY
                // 1. self.manager is live.
                unsafe { sys::ACameraManager_delete(self.manager) };
                self.manager = ptr::null_mut();
            }

            self.callback_state.wait_for_callbacks();

            if was_running {
                log::info!("Android camera stopped");
            }
        }

        fn fail<T>(&self, message: &str) -> Result<T, String> {
            log::error!("{message}");
            (self.callbacks.on_error)(message);
            Err(message.to_string())
        }

        /// # Safety
        /// 1. self.manager must be a live ACameraManager.
        unsafe fn select_camera(&mut self) -> Result<(), String> {
            if self.manager.is_null() {
                return self.fail("ACameraManager not created");
            }

            let mut ids: *mut sys::ACameraIdList = ptr::null_mut();
            // SAFETY
            // 1. self.manager is live.
            // 2. ids is writable.
            if unsafe { sys::ACameraManager_getCameraIdList(self.manager, &mut ids) } != CAMERA_OK || ids.is_null() {
                return self.fail("ACameraManager_getCameraIdList failed");
            }

            let wanted = if self.config.facing == K_FACING_FRONT {
                sys::acamera_metadata_enum_acamera_lens_facing::ACAMERA_LENS_FACING_FRONT.0 as u8
            } else {
                sys::acamera_metadata_enum_acamera_lens_facing::ACAMERA_LENS_FACING_BACK.0 as u8
            };

            // SAFETY
            // 1. The NDK call that returned ids succeeded.
            // 2. ids is not null.
            let id_list = unsafe { &*ids };
            for i in 0..id_list.numCameras {
                // SAFETY
                // 1. ids is a live camera-id list and i < numCameras.
                // 2. cameraIds points to numCameras entries.
                let id_ptr = unsafe { *id_list.cameraIds.add(i as usize) };
                let mut metadata: *mut sys::ACameraMetadata = ptr::null_mut();
                // SAFETY
                // 1. self.manager is live and id_ptr comes from the live id list.
                // 2. metadata is writable.
                if unsafe { sys::ACameraManager_getCameraCharacteristics(self.manager, id_ptr, &mut metadata) } != CAMERA_OK {
                    continue;
                }

                let mut entry = std::mem::MaybeUninit::<sys::ACameraMetadata_const_entry>::uninit();

                // SAFETY
                // 1. metadata is live for this camera.
                // 2. entry is writable.
                let matched = if unsafe { sys::ACameraMetadata_getConstEntry(
                    metadata,
                    sys::acamera_metadata_tag::ACAMERA_LENS_FACING.0,
                    entry.as_mut_ptr(),
                ) } == CAMERA_OK {
                    // SAFETY
                    // 1. The NDK call that returned entry succeeded and hence it is initialized.
                    let entry = unsafe { entry.assume_init() };

                    // SAFETY
                    // 1. entry.data is the u8 pointer variant.
                    // 2. entry.count > 0 and entry.data came from a successful metadata lookup.
                    entry.count > 0
                        && unsafe { camera_metadata_u8(&entry) }
                            .map(|facing| facing == wanted)
                            .unwrap_or(false)
                } else {
                    false
                };

                // SAFETY
                // 1. metadata was returned by the NDK and not freed yet.
                unsafe { sys::ACameraMetadata_free(metadata) };

                if matched {
                    // SAFETY
                    // 1. id_ptr comes from the live NDK list as a NUL-terminated string.
                    self.camera_id = Some(unsafe { cstr_ptr_to_cstring(id_ptr) }?);
                    break;
                }
            }

            // SAFETY
            // 1. ids was returned by the NDK and not freed yet.
            unsafe { sys::ACameraManager_deleteCameraIdList(ids) };

            if self.camera_id.is_none() {
                return self.fail("no matching Android camera found");
            }
            Ok(())
        }

        /// # Safety
        /// 1. self.callback_state allocation must remain live while the listener is installed.
        unsafe fn create_reader(&mut self) -> Result<(), String> {
            if !self.reader.is_null() || !self.raw_window.is_null() {
                return self.fail("AImageReader already created");
            }

            // SAFETY
            // 1. self.reader is writable.
            let status = unsafe { sys::AImageReader_new(
                self.config.width,
                self.config.height,
                AIMAGE_FORMAT_YUV_420_888,
                4, // max number of images that we'll want to access simultaneously
                &mut self.reader,
            ) };
            if status != MEDIA_OK || self.reader.is_null() {
                return self.fail("AImageReader_new(YUV_420_888) failed");
            }

            let mut listener = sys::AImageReader_ImageListener {
                context: Arc::as_ptr(&self.callback_state) as *mut c_void,
                onImageAvailable: Some(CameraCallbackState::on_image_available),
            };
            // SAFETY
            // 1. self.reader is live.
            // 2. listener context points to the live self.callback_state allocation.
            let status = unsafe { sys::AImageReader_setImageListener(self.reader, &mut listener) };
            if status != MEDIA_OK {
                return self.fail("AImageReader_setImageListener failed");
            }

            // SAFETY
            // 1. self.reader is live.
            // 2. self.raw_window is writable.
            let status = unsafe { sys::AImageReader_getWindow(self.reader, &mut self.raw_window) };
            if status != MEDIA_OK || self.raw_window.is_null() {
                return self.fail("AImageReader_getWindow failed");
            }
            Ok(())
        }

        /// # Safety
        /// None.
        unsafe fn create_encoder(&mut self) -> Result<(), String> {
            if !self.encoder.is_null() || !self.encoder_window.is_null() {
                return self.fail("video encoder already created");
            }

            let video_avc = CString::new("video/avc").unwrap();
            // SAFETY
            // 1. video_avc is a valid C string for this call.
            self.encoder = unsafe { sys::AMediaCodec_createEncoderByType(video_avc.as_ptr()) };
            if self.encoder.is_null() {
                return self.fail("AMediaCodec_createEncoderByType(video/avc) failed");
            }

            // SAFETY
            // None.
            let format = unsafe { sys::AMediaFormat_new() };
            if format.is_null() {
                return self.fail("AMediaFormat_new video failed");
            }

            // SAFETY
            // 1. format is live.
            // 2. video_avc is a valid C string for this call.
            unsafe { sys::AMediaFormat_setString(format, sys::AMEDIAFORMAT_KEY_MIME, video_avc.as_ptr()) };
            // SAFETY
            // 1. format is live.
            unsafe { sys::AMediaFormat_setInt32(format, sys::AMEDIAFORMAT_KEY_WIDTH, self.config.width) };
            // SAFETY
            // 1. format is live.
            unsafe { sys::AMediaFormat_setInt32(format, sys::AMEDIAFORMAT_KEY_HEIGHT, self.config.height) };
            // SAFETY
            // 1. format is live.
            unsafe { sys::AMediaFormat_setInt32(format, sys::AMEDIAFORMAT_KEY_BIT_RATE, self.config.bitrate) };
            // SAFETY
            // 1. format is live.
            unsafe { sys::AMediaFormat_setInt32(format, sys::AMEDIAFORMAT_KEY_FRAME_RATE, self.config.fps_max) };
            // SAFETY
            // 1. format is live.
            unsafe { sys::AMediaFormat_setInt32(format, sys::AMEDIAFORMAT_KEY_I_FRAME_INTERVAL, self.config.i_frame_interval) };
            // SAFETY
            // 1. format is live.
            unsafe { sys::AMediaFormat_setInt32(format, sys::AMEDIAFORMAT_KEY_COLOR_FORMAT, K_COLOR_FORMAT_SURFACE) };

            // SAFETY
            // 1. self.encoder and format are live.
            // 2. null surface and crypto are allowed here.
            let status = unsafe { sys::AMediaCodec_configure(
                self.encoder,
                format,
                ptr::null_mut(),
                ptr::null_mut(),
                sys::AMEDIACODEC_CONFIGURE_FLAG_ENCODE as u32,
            ) };
            // SAFETY
            // 1. format was created by the NDK and is no longer used.
            unsafe { sys::AMediaFormat_delete(format) };
            if status != MEDIA_OK {
                return self.fail("AMediaCodec_configure video encoder failed");
            }

            // SAFETY
            // 1. self.encoder is configured.
            // 2. self.encoder_window is writable.
            let status = unsafe { sys::AMediaCodec_createInputSurface(self.encoder, &mut self.encoder_window) };
            if status != MEDIA_OK || self.encoder_window.is_null() {
                return self.fail("AMediaCodec_createInputSurface failed");
            }

            // SAFETY
            // 1. self.encoder is configured and not yet started.
            if unsafe { sys::AMediaCodec_start(self.encoder) } != MEDIA_OK {
                return self.fail("AMediaCodec_start video failed");
            }
            Ok(())
        }

        /// # Safety
        /// None.
        unsafe fn create_audio_encoder(&mut self) -> Result<(), String> {
            if !self.audio_encoder.is_null() {
                return Err("audio encoder already created".to_string());
            }

            let audio_aac = CString::new("audio/mp4a-latm").unwrap();
            // SAFETY
            // 1. audio_aac is a valid C string for this call.
            self.audio_encoder = unsafe { sys::AMediaCodec_createEncoderByType(audio_aac.as_ptr()) };
            if self.audio_encoder.is_null() {
                return Err("AMediaCodec_createEncoderByType(audio/mp4a-latm) failed".to_string());
            }

            // SAFETY
            // None.
            let format = unsafe { sys::AMediaFormat_new() };
            if format.is_null() {
                return Err("AMediaFormat_new audio failed".to_string());
            }

            // SAFETY
            // 1. format is live.
            // 2. audio_aac is a valid C string for this call.
            unsafe { sys::AMediaFormat_setString(format, sys::AMEDIAFORMAT_KEY_MIME, audio_aac.as_ptr()) };
            // SAFETY
            // 1. format is live.
            unsafe { sys::AMediaFormat_setInt32(format, sys::AMEDIAFORMAT_KEY_SAMPLE_RATE, K_AUDIO_SAMPLE_RATE) };
            // SAFETY
            // 1. format is live.
            unsafe { sys::AMediaFormat_setInt32(format, sys::AMEDIAFORMAT_KEY_CHANNEL_COUNT, K_AUDIO_CHANNEL_COUNT) };
            // SAFETY
            // 1. format is live.
            unsafe { sys::AMediaFormat_setInt32(format, sys::AMEDIAFORMAT_KEY_BIT_RATE, K_AUDIO_BITRATE) };
            // SAFETY
            // 1. format is live.
            unsafe { sys::AMediaFormat_setInt32(format, sys::AMEDIAFORMAT_KEY_AAC_PROFILE, K_AAC_OBJECT_LC) };

            // SAFETY
            // 1. self.audio_encoder and format are live.
            // 2. null surface and crypto are allowed here.
            let status = unsafe { sys::AMediaCodec_configure(
                self.audio_encoder,
                format,
                ptr::null_mut(),
                ptr::null_mut(),
                sys::AMEDIACODEC_CONFIGURE_FLAG_ENCODE as u32,
            ) };
            // SAFETY
            // 1. format was created by the NDK and is no longer used.
            unsafe { sys::AMediaFormat_delete(format) };
            if status != MEDIA_OK {
                return Err("AMediaCodec_configure audio encoder failed".to_string());
            }

            // SAFETY
            // 1. self.audio_encoder is configured and not yet started.
            if unsafe { sys::AMediaCodec_start(self.audio_encoder) } != MEDIA_OK {
                return Err("AMediaCodec_start audio encoder failed".to_string());
            }

            self.audio_encoder_started = true;
            Ok(())
        }

        /// # Safety
        /// None.
        unsafe fn create_audio_recorder(&mut self) -> Result<(), String> {
            if !self.audio_stream.is_null() {
                return Err("audio stream already opened".to_string());
            }

            let mut builder: *mut sys::AAudioStreamBuilder = ptr::null_mut();
            // SAFETY
            // 1. builder is writable.
            if unsafe { sys::AAudio_createStreamBuilder(&mut builder) } != sys::AAUDIO_OK || builder.is_null() {
                return Err("AAudio_createStreamBuilder failed".to_string());
            }

            // SAFETY
            // 1. builder is live.
            unsafe { sys::AAudioStreamBuilder_setDirection(builder, sys::AAUDIO_DIRECTION_INPUT as i32) };
            // SAFETY
            // 1. builder is live.
            unsafe { sys::AAudioStreamBuilder_setSampleRate(builder, K_AUDIO_SAMPLE_RATE) };
            // SAFETY
            // 1. builder is live.
            unsafe { sys::AAudioStreamBuilder_setChannelCount(builder, K_AUDIO_CHANNEL_COUNT) };
            // SAFETY
            // 1. builder is live.
            unsafe { sys::AAudioStreamBuilder_setFormat(builder, sys::AAUDIO_FORMAT_PCM_I16) };
            // SAFETY
            // 1. builder is live.
            unsafe { sys::AAudioStreamBuilder_setPerformanceMode(builder, sys::AAUDIO_PERFORMANCE_MODE_NONE as i32) };
            // SAFETY
            // 1. builder is live.
            unsafe { sys::AAudioStreamBuilder_setSharingMode(builder, sys::AAUDIO_SHARING_MODE_SHARED as i32) };

            // SAFETY
            // 1. builder is live.
            // 2. self.audio_stream is writable.
            let result = unsafe { sys::AAudioStreamBuilder_openStream(builder, &mut self.audio_stream) };
            // SAFETY
            // 1. builder was returned by the NDK and is no longer used.
            unsafe { sys::AAudioStreamBuilder_delete(builder) };

            if result != sys::AAUDIO_OK || self.audio_stream.is_null() {
                return Err("AAudioStreamBuilder_openStream failed; check RECORD_AUDIO permission".to_string());
            }
            Ok(())
        }

        /// # Safety
        /// 1. Audio handles, if not null, must be live.
        /// 2. No audio worker may be using them.
        unsafe fn release_audio_resources(&mut self) {
            self.audio_enabled = false;
            if !self.audio_encoder.is_null() {
                if self.audio_encoder_started {
                    // SAFETY
                    // 1. self.audio_encoder is live and started.
                    let _ = unsafe { sys::AMediaCodec_stop(self.audio_encoder) };
                }
                // SAFETY
                // 1. self.audio_encoder is live.
                unsafe { sys::AMediaCodec_delete(self.audio_encoder) };
                self.audio_encoder = ptr::null_mut();
            }
            self.audio_encoder_started = false;

            if !self.audio_stream.is_null() {
                // SAFETY
                // 1. self.audio_stream is live.
                unsafe { sys::AAudioStream_close(self.audio_stream) };
                self.audio_stream = ptr::null_mut();
            }
        }

        /// # Safety
        /// 1. self.manager must be live.
        /// 2. self.callback_state allocation must remain live while callbacks are registered.
        unsafe fn open_camera(&mut self) -> Result<(), String> {
            if self.manager.is_null() {
                return self.fail("ACameraManager not created");
            }
            if !self.device.is_null() {
                return self.fail("camera device already open");
            }

            let mut callbacks = sys::ACameraDevice_StateCallbacks {
                context: Arc::as_ptr(&self.callback_state) as *mut c_void,
                onDisconnected: Some(CameraCallbackState::on_camera_disconnected),
                onError: Some(CameraCallbackState::on_camera_error),
            };

            let Some(camera_id) = self.camera_id.as_ref() else {
                return self.fail("camera id not selected");
            };
            // SAFETY
            // 1. self.manager is live.
            // 2. camera_id is a valid C string.
            // 3. self.device is writable.
            // 4. callbacks context points to the live self.callback_state allocation.
            let status = unsafe { sys::ACameraManager_openCamera(
                self.manager,
                camera_id.as_ptr(),
                &mut callbacks,
                &mut self.device,
            ) };
            if status != CAMERA_OK || self.device.is_null() {
                return self.fail("ACameraManager_openCamera failed");
            }
            Ok(())
        }

        /// # Safety
        /// 1. device, encoder_window, and raw_window must be live.
        unsafe fn create_capture_session(&mut self) -> Result<(), String> {
            if self.device.is_null() || self.encoder_window.is_null() || self.raw_window.is_null() {
                return self.fail("capture session prerequisites missing");
            }
            if !self.session.is_null()
                || !self.capture_request.is_null()
                || !self.outputs.is_null()
                || !self.encoder_output.is_null()
                || !self.raw_output.is_null()
                || !self.encoder_target.is_null()
                || !self.raw_target.is_null()
            {
                return self.fail("capture session already created");
            }

            // SAFETY
            // 1. self.outputs is writable.
            if unsafe { sys::ACaptureSessionOutputContainer_create(&mut self.outputs) } != CAMERA_OK {
                return self.fail("ACaptureSessionOutputContainer_create failed");
            }
            // SAFETY
            // 1. self.encoder_window and self.raw_window are live.
            // 2. output pointers are writable.
            if unsafe { sys::ACaptureSessionOutput_create(self.encoder_window, &mut self.encoder_output) } != CAMERA_OK
                || unsafe { sys::ACaptureSessionOutput_create(self.raw_window, &mut self.raw_output) } != CAMERA_OK
            {
                return self.fail("ACaptureSessionOutput_create failed");
            }
            // SAFETY
            // 1. self.outputs and both outputs are live.
            if unsafe { sys::ACaptureSessionOutputContainer_add(self.outputs, self.encoder_output) } != CAMERA_OK
                || unsafe { sys::ACaptureSessionOutputContainer_add(self.outputs, self.raw_output) } != CAMERA_OK
            {
                return self.fail("ACaptureSessionOutputContainer_add failed");
            }

            // SAFETY
            // 1. self.device is live.
            // 2. self.capture_request is writable.
            if unsafe { sys::ACameraDevice_createCaptureRequest(
                self.device,
                sys::ACameraDevice_request_template(3),
                &mut self.capture_request,
            ) } != CAMERA_OK
            {
                return self.fail("ACameraDevice_createCaptureRequest failed");
            }

            // SAFETY
            // 1. self.encoder_window and self.raw_window are live.
            // 2. target pointers are writable.
            if unsafe { sys::ACameraOutputTarget_create(self.encoder_window, &mut self.encoder_target) } != CAMERA_OK
                || unsafe { sys::ACameraOutputTarget_create(self.raw_window, &mut self.raw_target) } != CAMERA_OK
            {
                return self.fail("ACameraOutputTarget_create failed");
            }
            // SAFETY
            // 1. self.capture_request and both targets are live.
            if unsafe { sys::ACaptureRequest_addTarget(self.capture_request, self.encoder_target) } != CAMERA_OK
                || unsafe { sys::ACaptureRequest_addTarget(self.capture_request, self.raw_target) } != CAMERA_OK
            {
                return self.fail("ACaptureRequest_addTarget failed");
            }

            let fps_range = [self.config.fps_min, self.config.fps_max];
            // SAFETY
            // 1. self.capture_request is live.
            // 2. fps_range.as_ptr() is valid for this call.
            let status = unsafe { sys::ACaptureRequest_setEntry_i32(
                self.capture_request,
                sys::acamera_metadata_tag::ACAMERA_CONTROL_AE_TARGET_FPS_RANGE.0,
                fps_range.len() as u32,
                fps_range.as_ptr(),
            ) };
            if status != CAMERA_OK {
                return self.fail("ACaptureRequest_setEntry_i32 fps range failed");
            }

            *self.callback_state.session_closed.lock().unwrap() = false;

            let mut session_callbacks = sys::ACameraCaptureSession_stateCallbacks {
                context: Arc::as_ptr(&self.callback_state) as *mut c_void,
                onClosed: Some(CameraCallbackState::on_session_closed),
                onReady: None,
                onActive: None,
            };

            // SAFETY
            // 1. self.device and self.outputs are live.
            // 2. callbacks is valid for this call.
            // 3. self.session is writable.
            if unsafe { sys::ACameraDevice_createCaptureSession(
                self.device,
                self.outputs,
                &mut session_callbacks,
                &mut self.session,
            ) } != CAMERA_OK
            {
                return self.fail("ACameraDevice_createCaptureSession failed");
            }

            let mut request = self.capture_request;
            // SAFETY
            // 1. self.session and request are live.
            if unsafe { sys::ACameraCaptureSession_setRepeatingRequest(
                self.session,
                ptr::null_mut(),
                1,
                &mut request,
                ptr::null_mut(),
            ) } != CAMERA_OK
            {
                return self.fail("ACameraCaptureSession_setRepeatingRequest failed");
            }

            Ok(())
        }
    }

    impl CameraCallbackState {
        fn begin_callback(&self) -> CallbackGuard<'_> {
            let mut activity = self.activity.lock().unwrap();
            activity.active += 1;
            let enabled = !activity.stopping;
            CallbackGuard {
                state: self,
                enabled,
            }
        }

        fn stop_callbacks(&self) {
            let mut activity = self.activity.lock().unwrap();
            activity.stopping = true;
        }

        fn wait_for_callbacks(&self) {
            let mut activity = self.activity.lock().unwrap();
            while activity.active != 0 {
                activity = self.activity_changed.wait(activity).unwrap();
            }
        }

        fn wait_for_session_closed(&self) {
            let mut session_closed = self.session_closed.lock().unwrap();
            while !*session_closed {
                session_closed = self
                    .session_state_changed
                    .wait(session_closed)
                    .unwrap();
            }
        }

        fn fail<T>(&self, message: &str) -> Result<T, String> {
            log::error!("{message}");
            (self.callbacks.on_error)(message);
            Err(message.to_string())
        }

        /// # Safety
        /// 1. If not null, context must point to the live CameraCallbackState registered with the NDK.
        unsafe extern "C" fn on_session_closed(
            context: *mut c_void,
            _session: *mut sys::ACameraCaptureSession,
        ) {
            // SAFETY
            // 1. If not null, context points to the live CameraCallbackState registered with the NDK.
            if let Some(this) = unsafe { (context as *const Self).as_ref() } {
                let _callback = this.begin_callback();
                *this.session_closed.lock().unwrap() = true;
                this.session_state_changed.notify_all();
            }
        }

        /// # Safety
        /// 1. If not null, context must point to the live CameraCallbackState registered with the NDK.
        unsafe extern "C" fn on_camera_disconnected(context: *mut c_void, _device: *mut sys::ACameraDevice) {
            // SAFETY
            // 1. If not null, context points to the live CameraCallbackState registered with the NDK.
            if let Some(this) = unsafe { (context as *const Self).as_ref() } {
                let callback = this.begin_callback();
                if !callback.enabled {
                    return;
                }
                let _ = this.fail::<()>("camera disconnected");
            }
        }

        /// # Safety
        /// 1. If not null, context must point to the live CameraCallbackState registered with the NDK.
        unsafe extern "C" fn on_camera_error(
            context: *mut c_void,
            _device: *mut sys::ACameraDevice,
            error: c_int,
        ) {
            // SAFETY
            // 1. If not null, context points to the live CameraCallbackState registered with the NDK.
            if let Some(this) = unsafe { (context as *const Self).as_ref() } {
                let callback = this.begin_callback();
                if !callback.enabled {
                    return;
                }
                let message = format!("camera device error: {error}");
                let _ = this.fail::<()>(&message);
            }
        }

        /// # Safety
        /// 1. If not null, context must point to the live CameraCallbackState registered with the NDK.
        /// 2. If callback processing is enabled, reader must remain live until the callback finishes.
        unsafe extern "C" fn on_image_available(context: *mut c_void, reader: *mut sys::AImageReader) {
            if reader.is_null() {
                return;
            }

            // SAFETY
            // 1. If not null, context points to the live CameraCallbackState registered with the NDK.
            if let Some(this) = unsafe { (context as *const Self).as_ref() } {
                let callback = this.begin_callback();
                if !callback.enabled {
                    return;
                }
                // SAFETY
                // 1. reader remains live until the enabled callback finishes.
                unsafe { this.handle_image_available(reader) };
            }
        }

        /// # Safety
        /// 1. reader must remain live until the function returns.
        unsafe fn handle_image_available(&self, reader: *mut sys::AImageReader) {
            if reader.is_null() {
                return;
            }

            let _guard = self.image_mutex.lock().unwrap();
            if !self.running.load(Ordering::SeqCst) {
                return;
            }

            let mut image: *mut sys::AImage = ptr::null_mut();
            // SAFETY
            // 1. reader remains live until this enabled callback finishes.
            // 2. image is writable.
            if unsafe { sys::AImageReader_acquireLatestImage(reader, &mut image) } != MEDIA_OK || image.is_null() {
                return;
            }

            if !self.should_emit_raw_frame() {
                // SAFETY
                // 1. image was returned by the NDK and not deleted yet.
                unsafe { sys::AImage_delete(image) };
                return;
            }

            let mut y = ptr::null_mut();
            let mut u = ptr::null_mut();
            let mut v = ptr::null_mut();
            let mut y_len = 0;
            let mut u_len = 0;
            let mut v_len = 0;
            let mut y_row = 0;
            let mut u_row = 0;
            let mut v_row = 0;
            let mut y_pix = 0;
            let mut u_pix = 0;
            let mut v_pix = 0;

            // SAFETY
            // 1. image is live.
            // 2. Plane outputs are writable.
            let ok = unsafe { sys::AImage_getPlaneData(image, 0, &mut y, &mut y_len) } == MEDIA_OK
                && unsafe { sys::AImage_getPlaneData(image, 1, &mut u, &mut u_len) } == MEDIA_OK
                && unsafe { sys::AImage_getPlaneData(image, 2, &mut v, &mut v_len) } == MEDIA_OK
                && unsafe { sys::AImage_getPlaneRowStride(image, 0, &mut y_row) } == MEDIA_OK
                && unsafe { sys::AImage_getPlaneRowStride(image, 1, &mut u_row) } == MEDIA_OK
                && unsafe { sys::AImage_getPlaneRowStride(image, 2, &mut v_row) } == MEDIA_OK
                && unsafe { sys::AImage_getPlanePixelStride(image, 0, &mut y_pix) } == MEDIA_OK
                && unsafe { sys::AImage_getPlanePixelStride(image, 1, &mut u_pix) } == MEDIA_OK
                && unsafe { sys::AImage_getPlanePixelStride(image, 2, &mut v_pix) } == MEDIA_OK;

            if ok && !y.is_null() && !u.is_null() && !v.is_null() {
                let expected = (self.config.width * self.config.height * 3 / 2) as usize;
                let mut i420 = vec![0u8; expected];
                // SAFETY
                // 1. Plane pointers and lengths come from the live NDK image.
                unsafe { copy_yuv420_to_i420(
                    &mut i420,
                    self.config.width,
                    self.config.height,
                    Plane { ptr: y, len: y_len, row_stride: y_row, pixel_stride: y_pix },
                    Plane { ptr: u, len: u_len, row_stride: u_row, pixel_stride: u_pix },
                    Plane { ptr: v, len: v_len, row_stride: v_row, pixel_stride: v_pix },
                ) };
                (self.callbacks.on_raw_i420)(
                    self.callbacks.state.as_ref(),
                    &i420,
                    self.config.width as usize,
                    self.config.height as usize,
                );
            }

            // SAFETY
            // 1. image was returned by the NDK and not deleted yet.
            unsafe { sys::AImage_delete(image) };
        }

        fn should_emit_raw_frame(&self) -> bool {
            if self.config.motion_fps <= 0 {
                return false;
            }

            let now = Instant::now();
            let interval = Duration::from_nanos(1_000_000_000u64 / self.config.motion_fps as u64);
            let mut last_raw_emit = self.last_raw_emit.lock().unwrap();
            if matches!(*last_raw_emit, Some(last) if now.duration_since(last) < interval) {
                return false;
            }

            *last_raw_emit = Some(now);
            true
        }
    }

    impl Drop for CallbackGuard<'_> {
        fn drop(&mut self) {
            let mut activity = self.state.activity.lock().unwrap();
            activity.active -= 1;
            if activity.active == 0 {
                self.state.activity_changed.notify_all();
            }
        }
    }

    impl VideoEncoderThreadState {
        fn drain_encoder(&self) {
            // SAFETY
            // 1. self.encoder remains live while running is true.
            // 2. This worker has exclusive access to encoder output buffers.
            unsafe {
                self.drain_encoder_unsafe();
            }
        }

        /// # Safety
        /// 1. self.encoder must remain live while running is true.
        /// 2. This worker must have exclusive access to encoder output buffers.
        unsafe fn drain_encoder_unsafe(&self) {
            while self.running.load(Ordering::SeqCst) {
                let mut info = std::mem::MaybeUninit::<sys::AMediaCodecBufferInfo>::uninit();
                // SAFETY
                // 1. self.encoder is live.
                // 2. info is writable.
                let index = unsafe { sys::AMediaCodec_dequeueOutputBuffer(self.encoder, info.as_mut_ptr(), 10_000) };
                if index == sys::AMEDIACODEC_INFO_TRY_AGAIN_LATER as isize {
                    continue;
                }
                if index == sys::AMEDIACODEC_INFO_OUTPUT_FORMAT_CHANGED as isize {
                    // SAFETY
                    // 1. self.encoder is live.
                    unsafe { self.emit_codec_config_from_output_format() };
                    continue;
                }
                if index < 0 {
                    continue;
                }

                // SAFETY
                // 1. The FFI call that returned info succeeded and hence info is initialized.
                let info = unsafe { info.assume_init() };

                let mut _out_size = 0usize;
                // SAFETY
                // 1. self.encoder is live and index came from dequeue.
                // 2. _out_size is writable.
                let out = unsafe { sys::AMediaCodec_getOutputBuffer(self.encoder, index as usize, &mut _out_size) };
                if !out.is_null() && info.size > 0 {
                    let size = info.size as usize;
                    // SAFETY
                    // 1. out is not null and index remains dequeued.
                    // 2. info.size is valid; info.offset and _out_size are invalid through Android API 35 and ignored:
                    //    https://developer.android.com/ndk/reference/group/media#amediacodec_dequeueoutputbuffer
                    //    https://developer.android.com/ndk/reference/group/media#amediacodec_getoutputbuffer
                    let bytes = unsafe { std::slice::from_raw_parts(out, size) };
                    self.emit_annexb(bytes);
                }
                // SAFETY
                // 1. index came from dequeue.
                unsafe { sys::AMediaCodec_releaseOutputBuffer(self.encoder, index as usize, false) };
            }
        }

        fn emit_annexb(&self, data: &[u8]) {
            if data.len() < 5 {
                return;
            }
            if starts_with_start_code(data) {
                self.split_and_emit_start_coded(data);
            } else {
                self.split_and_emit_length_prefixed(data);
            }
        }

        fn split_and_emit_length_prefixed(&self, data: &[u8]) {
            let mut pos = 0usize;
            while pos + 4 <= data.len() {
                let nal_len = u32::from_be_bytes([
                    data[pos],
                    data[pos + 1],
                    data[pos + 2],
                    data[pos + 3],
                ]) as usize;
                pos += 4;
                if nal_len == 0 || pos + nal_len > data.len() {
                    return;
                }

                let mut out = Vec::with_capacity(nal_len + 4);
                out.extend_from_slice(&[0, 0, 0, 1]);
                out.extend_from_slice(&data[pos..pos + nal_len]);
                self.emit_one_nal(&out);
                pos += nal_len;
            }
        }

        fn split_and_emit_start_coded(&self, data: &[u8]) {
            let mut start = 0usize;
            while start < data.len() {
                let next = find_next_start_code(data, start + 4);
                let end = next.unwrap_or(data.len());
                if end > start {
                    self.emit_one_nal(&data[start..end]);
                }
                match next {
                    Some(next) => start = next,
                    None => break,
                }
            }
        }

        fn emit_one_nal(&self, data: &[u8]) {
            if data.len() < 5 {
                return;
            }

            let offset = if data.starts_with(&[0, 0, 0, 1]) {
                4
            } else if data.starts_with(&[0, 0, 1]) {
                3
            } else {
                0
            };
            if offset >= data.len() {
                return;
            }

            let kind = match data[offset] & 0x1F {
                7 => super::FrameKind::Sps,
                8 => super::FrameKind::Pps,
                5 => super::FrameKind::IFrame,
                _ => super::FrameKind::RFrame,
            };

            (self.callbacks.on_h264)(self.callbacks.state.as_ref(), data, kind);
        }

        /// # Safety
        /// 1. self.encoder must be live.
        unsafe fn emit_codec_config_from_output_format(&self) {
            // SAFETY
            // 1. self.encoder is live.
            let format = unsafe { sys::AMediaCodec_getOutputFormat(self.encoder) };
            if format.is_null() {
                log::error!("AMediaCodec_getOutputFormat returned null");
                return;
            }

            // SAFETY
            // 1. format is live for this lookup.
            unsafe { self.emit_codec_config_buffer_from_format(format, "csd-0") };
            // SAFETY
            // 1. format is live for this lookup.
            unsafe { self.emit_codec_config_buffer_from_format(format, "csd-1") };

            // SAFETY
            // 1. format was returned by the NDK and is no longer used.
            unsafe { sys::AMediaFormat_delete(format) };
        }

        /// # Safety
        /// 1. format must be live for the duration of the call.
        unsafe fn emit_codec_config_buffer_from_format(&self, format: *mut sys::AMediaFormat, key: &str) {
            let key = CString::new(key).unwrap();
            let mut buffer: *mut c_void = ptr::null_mut();
            let mut buffer_size = 0usize;

            // SAFETY
            // 1. format is live and key is a valid C string.
            // 2. buffer outputs are writable.
            if unsafe { sys::AMediaFormat_getBuffer(format, key.as_ptr(), &mut buffer, &mut buffer_size) }
                && !buffer.is_null()
                && buffer_size > 0
            {
                // SAFETY
                // 1. buffer is not null.
                // 2. buffer_size came from the NDK.
                let data = unsafe { std::slice::from_raw_parts(buffer.cast::<u8>(), buffer_size) };
                self.emit_codec_config_buffer(data);
            } else {
                log::error!("Encoder output format missing {}", key.to_string_lossy());
            }
        }

        fn emit_codec_config_buffer(&self, data: &[u8]) {
            if data.is_empty() {
                return;
            }

            if starts_with_start_code(data) {
                self.split_and_emit_start_coded(data);
                return;
            }

            let nal_type = data[0] & 0x1F;
            if nal_type == 7 || nal_type == 8 {
                let mut out = Vec::with_capacity(data.len() + 4);
                out.extend_from_slice(&[0, 0, 0, 1]);
                out.extend_from_slice(data);
                self.emit_one_nal(&out);
                return;
            }

            self.split_and_emit_length_prefixed(data);
        }
    }

    impl AudioThreadState {
        fn drain_audio(&self) {
            // SAFETY
            // 1. audio_stream and audio_encoder remain live while running.
            // 2. This worker has exclusive access to audio codec buffers.
            unsafe {
                self.drain_audio_unsafe();
            }
        }

        /// # Safety
        /// 1. audio_stream and audio_encoder must remain live while running.
        /// 2. This worker must have exclusive access to audio codec buffers.
        unsafe fn drain_audio_unsafe(&self) {
            let mut samples = vec![0i16; K_AUDIO_SAMPLES_PER_ACCESS_UNIT * K_AUDIO_CHANNEL_COUNT as usize];
            let mut filled_frames = 0usize;
            let mut submitted_frames = 0i64;

            while self.running.load(Ordering::SeqCst) {
                let frames_needed = K_AUDIO_SAMPLES_PER_ACCESS_UNIT - filled_frames;
                let offset = filled_frames
                    .checked_mul(K_AUDIO_CHANNEL_COUNT as usize)
                    .expect("audio sample offset overflow");

                let dst = samples[offset..].as_mut_ptr();

                // SAFETY
                // 1. self.audio_stream is live.
                // 2. dst has space for frames_needed audio frames.
                let frames_read = unsafe { sys::AAudioStream_read(
                    self.audio_stream,
                    dst.cast(),
                    frames_needed as i32,
                    100_000_000,
                ) };

                if frames_read == sys::AAUDIO_ERROR_DISCONNECTED {
                    log::warn!("AAudioStream_read disconnected; stopping audio capture");
                    break;
                }
                if frames_read < 0 {
                    continue;
                }
                if frames_read == 0 {
                    // SAFETY
                    // 1. self.audio_encoder is live.
                    // 2. This worker has exclusive access to audio output buffers.
                    unsafe { self.drain_audio_encoder(false) };
                    continue;
                }

                filled_frames += frames_read as usize;
                if filled_frames < K_AUDIO_SAMPLES_PER_ACCESS_UNIT {
                    continue;
                }

                let byte_count = K_AUDIO_SAMPLES_PER_ACCESS_UNIT
                    * K_AUDIO_CHANNEL_COUNT as usize
                    * K_AUDIO_BYTES_PER_SAMPLE;
                let pts_us = submitted_frames * 1_000_000 / K_AUDIO_SAMPLE_RATE as i64;
                // SAFETY
                // 1. samples.as_ptr() is valid for byte_count bytes during this call.
                let audio_bytes = unsafe { std::slice::from_raw_parts(samples.as_ptr().cast::<u8>(), byte_count) };

                // SAFETY
                // 1. self.audio_encoder is live.
                // 2. This worker has exclusive access to audio input buffers.
                if !unsafe { self.queue_audio_input(audio_bytes, pts_us) } {
                    break;
                }

                submitted_frames += K_AUDIO_SAMPLES_PER_ACCESS_UNIT as i64;
                filled_frames = 0;

                // SAFETY
                // 1. self.audio_encoder is live.
                // 2. This worker has exclusive access to audio output buffers.
                unsafe { self.drain_audio_encoder(false) };
            }

            // SAFETY
            // 1. self.audio_encoder is live for final drain.
            // 2. This worker has exclusive access to audio output buffers.
            unsafe { self.drain_audio_encoder(true) };
        }

        /// # Safety
        /// 1. audio_encoder must be live.
        /// 2. This worker must have exclusive access to audio input buffers.
        unsafe fn queue_audio_input(&self, data: &[u8], pts_us: i64) -> bool {
            let len = data.len();

            for _ in 0..5 {
                if !self.running.load(Ordering::SeqCst) {
                    return false;
                }

                // SAFETY
                // 1. self.audio_encoder is live.
                let index = unsafe { sys::AMediaCodec_dequeueInputBuffer(self.audio_encoder, 10_000) };
                if index == sys::AMEDIACODEC_INFO_TRY_AGAIN_LATER as isize {
                    // SAFETY
                    // 1. self.audio_encoder is live.
                    // 2. This worker has exclusive access to audio output buffers.
                    unsafe { self.drain_audio_encoder(false) };
                    continue;
                }
                if index < 0 {
                    continue;
                }

                let mut capacity = 0usize;
                // SAFETY
                // 1. index came from dequeue.
                // 2. capacity is writable.
                let input = unsafe { sys::AMediaCodec_getInputBuffer(self.audio_encoder, index as usize, &mut capacity) };
                if input.is_null() || capacity < len {
                    // SAFETY
                    // 1. index came from dequeue.
                    let _ = unsafe { sys::AMediaCodec_queueInputBuffer(self.audio_encoder, index as usize, 0, 0, pts_us as u64, 0) };
                    return false;
                }

                // SAFETY
                // 1. input is not null.
                // 2. capacity came from the codec.
                let input = unsafe { std::slice::from_raw_parts_mut(input, capacity) };

                input[..len].copy_from_slice(data);
                
                // SAFETY
                // 1. index came from dequeue.
                // 2. len was checked against capacity.
                return unsafe { sys::AMediaCodec_queueInputBuffer(self.audio_encoder, index as usize, 0, len, pts_us as u64, 0) }
                    == MEDIA_OK;
            }

            false
        }

        /// # Safety
        /// 1. audio_encoder, if not null, must be live.
        /// 2. This worker must have exclusive access to audio output buffers.
        unsafe fn drain_audio_encoder(&self, wait: bool) {
            if self.audio_encoder.is_null() {
                return;
            }

            while self.running.load(Ordering::SeqCst) || wait {
                let mut info = std::mem::MaybeUninit::<sys::AMediaCodecBufferInfo>::uninit();
                // SAFETY
                // 1. self.audio_encoder is live.
                // 2. info is writable.
                let index = unsafe { sys::AMediaCodec_dequeueOutputBuffer(
                    self.audio_encoder,
                    info.as_mut_ptr(),
                    if wait { 10_000 } else { 0 },
                ) };
                if index == sys::AMEDIACODEC_INFO_TRY_AGAIN_LATER as isize {
                    break;
                }
                if index == sys::AMEDIACODEC_INFO_OUTPUT_FORMAT_CHANGED as isize || index < 0 {
                    continue;
                }

                // SAFETY
                // 1. The FFI call that returned info succeeded and hence it is initialized.
                let info = unsafe { info.assume_init() };

                let mut _out_size = 0usize;
                // SAFETY
                // 1. index came from dequeue.
                // 2. _out_size is writable.
                let out = unsafe { sys::AMediaCodec_getOutputBuffer(self.audio_encoder, index as usize, &mut _out_size) };
                let codec_config = (info.flags & sys::AMEDIACODEC_BUFFER_FLAG_CODEC_CONFIG) != 0;
                if !codec_config && !out.is_null() && info.size > 0 {
                    let size = info.size as usize;
                    // SAFETY
                    // 1. out is not null and index remains dequeued.
                    // 2. info.size is valid; info.offset and _out_size are invalid through Android API 35 and ignored:
                    //    https://developer.android.com/ndk/reference/group/media#amediacodec_dequeueoutputbuffer
                    //    https://developer.android.com/ndk/reference/group/media#amediacodec_getoutputbuffer
                    let data = unsafe { std::slice::from_raw_parts(out, size) };
                    (self.callbacks.on_aac)(self.callbacks.state.as_ref(), data);
                }
                // SAFETY
                // 1. index came from dequeue.
                unsafe { sys::AMediaCodec_releaseOutputBuffer(self.audio_encoder, index as usize, false) };

                if (info.flags & sys::AMEDIACODEC_BUFFER_FLAG_END_OF_STREAM) != 0 {
                    break;
                }
            }
        }
    }

    struct Plane {
        ptr: *const u8,
        len: c_int,
        row_stride: c_int,
        pixel_stride: c_int,
    }

    fn starts_with_start_code(data: &[u8]) -> bool {
        data.starts_with(&[0, 0, 0, 1]) || data.starts_with(&[0, 0, 1])
    }

    fn find_next_start_code(data: &[u8], from: usize) -> Option<usize> {
        let mut i = from;
        while i + 3 < data.len() {
            if data[i] == 0
                && data[i + 1] == 0
                && (data[i + 2] == 1 || (i + 3 < data.len() && data[i + 2] == 0 && data[i + 3] == 1))
            {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    /// # Safety
    /// 1. Plane pointers must be valid for their lengths.
    unsafe fn copy_yuv420_to_i420(
        dst: &mut [u8],
        width: c_int,
        height: c_int,
        y: Plane,
        u: Plane,
        v: Plane,
    ) {
        let Ok(width) = usize::try_from(width) else {
            return;
        };
        let Ok(height) = usize::try_from(height) else {
            return;
        };

        let Ok(y_len) = usize::try_from(y.len) else {
            return;
        };
        let Ok(u_len) = usize::try_from(u.len) else {
            return;
        };
        let Ok(v_len) = usize::try_from(v.len) else {
            return;
        };

        let Ok(y_row_stride) = usize::try_from(y.row_stride) else {
            return;
        };
        let Ok(u_row_stride) = usize::try_from(u.row_stride) else {
            return;
        };
        let Ok(v_row_stride) = usize::try_from(v.row_stride) else {
            return;
        };

        let Ok(u_pixel_stride) = usize::try_from(u.pixel_stride) else {
            return;
        };
        let Ok(v_pixel_stride) = usize::try_from(v.pixel_stride) else {
            return;
        };

        if y.ptr.is_null() || u.ptr.is_null() || v.ptr.is_null() {
            return;
        }

        if u_pixel_stride == 0 || v_pixel_stride == 0 {
            return;
        }

        // SAFETY
        // 1. y.ptr is not null and valid for y_len bytes.
        let y_src = unsafe { std::slice::from_raw_parts(y.ptr, y_len) };

        // SAFETY
        // 1. u.ptr is not null and valid for u_len bytes.
        let u_src = unsafe { std::slice::from_raw_parts(u.ptr, u_len) };

        // SAFETY
        // 1. v.ptr is not null and valid for v_len bytes.
        let v_src = unsafe { std::slice::from_raw_parts(v.ptr, v_len) };

        let Some(y_size) = width.checked_mul(height) else {
            return;
        };

        let uv_width = width / 2;
        let uv_height = height / 2;

        let Some(uv_size) = uv_width.checked_mul(uv_height) else {
            return;
        };

        let Some(required_len) = y_size.checked_add(uv_size.saturating_mul(2)) else {
            return;
        };

        if dst.len() < required_len {
            return;
        }

        let (dst_y, rest) = dst.split_at_mut(y_size);
        let (dst_u, dst_v) = rest.split_at_mut(uv_size);

        for row in 0..height {
            let Some(src_offset) = row.checked_mul(y_row_stride) else {
                continue;
            };
            let Some(src_end) = src_offset.checked_add(width) else {
                continue;
            };
            let Some(dst_offset) = row.checked_mul(width) else {
                continue;
            };
            let Some(dst_end) = dst_offset.checked_add(width) else {
                continue;
            };

            let Some(src_row) = y_src.get(src_offset..src_end) else {
                continue;
            };
            let Some(dst_row) = dst_y.get_mut(dst_offset..dst_end) else {
                continue;
            };

            dst_row.copy_from_slice(src_row);
        }

        for row in 0..uv_height {
            for col in 0..uv_width {
                let Some(dst_offset) = row
                    .checked_mul(uv_width)
                    .and_then(|offset| offset.checked_add(col))
                else {
                    continue;
                };

                let Some(u_offset) = row
                    .checked_mul(u_row_stride)
                    .and_then(|offset| col.checked_mul(u_pixel_stride).and_then(|col_offset| offset.checked_add(col_offset)))
                else {
                    continue;
                };

                let Some(v_offset) = row
                    .checked_mul(v_row_stride)
                    .and_then(|offset| col.checked_mul(v_pixel_stride).and_then(|col_offset| offset.checked_add(col_offset)))
                else {
                    continue;
                };

                if let Some(&sample) = u_src.get(u_offset) {
                    dst_u[dst_offset] = sample;
                }

                if let Some(&sample) = v_src.get(v_offset) {
                    dst_v[dst_offset] = sample;
                }
            }
        }
    }

    /// # Safety
    /// 1. entry.data must contain i32 data.
    /// 2. If entry.count > 0, entry.data must be valid for entry.count i32 values and must be live.
    unsafe fn camera_metadata_i32_vec(
        entry: &sys::ACameraMetadata_const_entry,
    ) -> Option<Vec<i32>> {
        let len = usize::try_from(entry.count).ok()?;
        if len == 0 {
            return Some(Vec::new());
        }

        // SAFETY
        // 1. entry.data is an i32 pointer.
        let data = unsafe { *(&entry.data as *const _ as *const *const i32) };
        if data.is_null() {
            return None;
        }

        // SAFETY
        // 1. data is not null and is valid for len i32 values.
        Some(unsafe { std::slice::from_raw_parts(data, len) }.to_vec())
    }

    /// # Safety
    /// 1. entry.data must contain u8 data.
    /// 2. If entry.count > 0, entry.data must be valid and live.
    unsafe fn camera_metadata_u8(entry: &sys::ACameraMetadata_const_entry) -> Option<u8> {
        if entry.count == 0 {
            return None;
        }

        // SAFETY
        // 1. entry.data is a u8 pointer.
        let data = unsafe { *(&entry.data as *const _ as *const *const u8) };
        if data.is_null() {
            None
        } else {
            // SAFETY
            // 1. data points to at least one valid u8.
            Some(unsafe { *data })
        }
    }

    /// # Safety
    /// 1. If not null, ptr must point to a valid NUL-terminated C string.
    unsafe fn cstr_ptr_to_cstring(ptr: *const c_char) -> Result<CString, String> {
        if ptr.is_null() {
            return Err("camera id pointer was null".to_string());
        }
        // SAFETY
        // 1. ptr is not null and points to a valid C string.
        Ok(unsafe { std::ffi::CStr::from_ptr(ptr) }.to_owned())
    }
}
