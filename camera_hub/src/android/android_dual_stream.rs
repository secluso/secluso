//! Android dual stream bridge.
//!
//! SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::VecDeque;
use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_uchar, c_void};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use crossbeam_channel::Sender;

use crate::android::android_camera::{Frame, FrameKind};

pub const ANDROID_CAMERA_FACING_BACK: i32 = 0;
//pub const ANDROID_CAMERA_FACING_FRONT: i32 = 1;

struct AndroidStreamState {
    frame_queue: Arc<Mutex<VecDeque<Frame>>>,
    ps_tx: Sender<Frame>,
}

pub struct AndroidStreamHandle {
    _native: ndk::NativeCamera,
    _state: Box<AndroidStreamState>,
}

#[allow(clippy::too_many_arguments)]
pub fn start(
    facing: i32,
    width: usize,
    height: usize,
    total_frame_rate: usize,
    i_frame_interval: usize,
    bitrate: usize,
    //FIXME
    //pipeline_controller: Arc<Mutex<PipelineController>>,
    frame_queue: Arc<Mutex<VecDeque<Frame>>>,
    ps_tx: Sender<Frame>,
    motion_fps: u8,
) -> anyhow::Result<AndroidStreamHandle> {
    let mut state = Box::new(AndroidStreamState {
        frame_queue,
        ps_tx,
    });

    let config = ndk::CameraConfig {
        facing,
        width: width as c_int,
        height: height as c_int,
        fps: total_frame_rate as c_int,
        bitrate: bitrate as c_int,
        i_frame_interval: i_frame_interval as c_int,
        motion_fps: motion_fps as c_int,
    };

    let callbacks = ndk::CameraCallbacks {
        user_data: (&mut *state as *mut AndroidStreamState).cast(),
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

extern "C" fn on_h264(
    user_data: *mut c_void,
    data: *const c_uchar,
    len: usize,
    kind: c_int,
) {
    if user_data.is_null() || data.is_null() || len == 0 {
        return;
    }

    let state = unsafe { &*(user_data.cast::<AndroidStreamState>()) };
    let bytes = unsafe { std::slice::from_raw_parts(data, len) }.to_vec();
    let frame_kind = match kind {
        7 => FrameKind::Sps,
        8 => FrameKind::Pps,
        5 => FrameKind::IFrame,
        _ => FrameKind::RFrame,
    };

    let frame = Frame {
        data: bytes,
        kind: frame_kind,
        timestamp: SystemTime::now(),
    };

    if frame.kind == FrameKind::Sps || frame.kind == FrameKind::Pps {
        let _ = state.ps_tx.send(frame.clone());
    }
    add_frame_and_drop_old(Arc::clone(&state.frame_queue), frame);
}

extern "C" fn on_aac(user_data: *mut c_void, data: *const c_uchar, len: usize) {
    if user_data.is_null() || data.is_null() || len == 0 {
        return;
    }

    let state = unsafe { &*(user_data.cast::<AndroidStreamState>()) };
    let bytes = unsafe { std::slice::from_raw_parts(data, len) }.to_vec();
    let frame = Frame {
        data: bytes,
        kind: FrameKind::Audio,
        timestamp: SystemTime::now(),
    };

    add_frame_and_drop_old(Arc::clone(&state.frame_queue), frame);
}

extern "C" fn on_raw_i420(
    user_data: *mut c_void,
    data: *const c_uchar,
    len: usize,
    width: c_int,
    height: c_int,
) {
    if user_data.is_null() || data.is_null() || len == 0 || width <= 0 || height <= 0 {
        return;
    }

    let expected = width as usize * height as usize * 3 / 2;
    if len < expected {
        return;
    }

    //FIXME
    /*
    let state = unsafe { &*(user_data.cast::<AndroidStreamState>()) };
    let buffer = unsafe { std::slice::from_raw_parts(data, expected) }.to_vec();
    let raw_frame = RawFrame::create_from_buffer(buffer, width as usize, height as usize);
    if let Ok(mut lock) = state.pipeline_controller.lock() {
        lock.push_frame(raw_frame);
    }
    */
}

extern "C" fn on_error(_user_data: *mut c_void, message: *const c_char) {
    if message.is_null() {
        eprintln!("[AndroidCamera] unknown native camera error");
        return;
    }
    let msg = unsafe { CStr::from_ptr(message) }.to_string_lossy();
    error!("[AndroidCamera] {msg}");
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

// native layer
mod ndk {
    use std::ffi::CString;
    use std::os::raw::{c_char, c_int, c_uchar, c_void};
    use std::ptr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};

    use ndk_sys as sys;

    const CAMERA_OK: sys::camera_status_t = sys::camera_status_t(0);
    const MEDIA_OK: sys::media_status_t = sys::media_status_t(0);
    const AIMAGE_FORMAT_YUV_420_888: c_int = 0x23;
    const K_FACING_FRONT: c_int = 1;
    const K_COLOR_FORMAT_SURFACE: c_int = 0x7F000789;
    const K_AUDIO_SAMPLE_RATE: c_int = 48_000;
    const K_AUDIO_CHANNEL_COUNT: c_int = 1;
    const K_AUDIO_BITRATE: c_int = 96_000;
    const K_AUDIO_SAMPLES_PER_ACCESS_UNIT: usize = 1024;
    const K_AUDIO_BYTES_PER_SAMPLE: usize = std::mem::size_of::<i16>();
    const K_AAC_OBJECT_LC: c_int = 2;

    pub(super) struct CameraConfig {
        pub facing: c_int,
        pub width: c_int,
        pub height: c_int,
        pub fps: c_int,
        pub bitrate: c_int,
        pub i_frame_interval: c_int,
        pub motion_fps: c_int,
    }

    #[derive(Clone, Copy)]
    pub(super) struct CameraCallbacks {
        pub user_data: *mut c_void,
        pub on_h264: extern "C" fn(*mut c_void, *const c_uchar, usize, c_int),
        pub on_aac: extern "C" fn(*mut c_void, *const c_uchar, usize),
        pub on_raw_i420: extern "C" fn(*mut c_void, *const c_uchar, usize, c_int, c_int),
        pub on_error: extern "C" fn(*mut c_void, *const c_char),
    }

    pub(super) struct NativeCamera {
        bridge: Box<CameraBridge>,
    }

    unsafe impl Send for NativeCamera {}

    impl NativeCamera {
        pub(super) fn start(config: CameraConfig, callbacks: CameraCallbacks) -> Result<Self, String> {
            let mut bridge = Box::new(CameraBridge::new(config, callbacks));
            unsafe {
                if let Err(err) = bridge.start() {
                    bridge.stop();
                    return Err(err);
                }
            }
            Ok(Self { bridge })
        }
    }

    impl Drop for NativeCamera {
        fn drop(&mut self) {
            unsafe {
                self.bridge.stop();
            }
        }
    }

    struct CameraBridge {
        config: CameraConfig,
        callbacks: CameraCallbacks,
        running: Arc<AtomicBool>,
        audio_enabled: bool,
        audio_encoder_started: bool,
        camera_id: Option<CString>,
        encoder_thread: Option<JoinHandle<()>>,
        audio_thread: Option<JoinHandle<()>>,
        image_mutex: Mutex<()>,
        last_raw_emit: Mutex<Option<Instant>>,
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

    struct ThreadState {
        running: Arc<AtomicBool>,
        callbacks: CameraCallbacks,
        encoder: *mut sys::AMediaCodec,
        audio_encoder: *mut sys::AMediaCodec,
        audio_stream: *mut sys::AAudioStream,
    }

    unsafe impl Send for ThreadState {}
    unsafe impl Sync for ThreadState {}

    impl CameraBridge {
        fn new(config: CameraConfig, callbacks: CameraCallbacks) -> Self {
            Self {
                config,
                callbacks,
                running: Arc::new(AtomicBool::new(false)),
                audio_enabled: false,
                audio_encoder_started: false,
                camera_id: None,
                encoder_thread: None,
                audio_thread: None,
                image_mutex: Mutex::new(()),
                last_raw_emit: Mutex::new(None),
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

        unsafe fn start(&mut self) -> Result<(), String> {
            self.manager = sys::ACameraManager_create();
            if self.manager.is_null() {
                return self.fail("ACameraManager_create failed");
            }

            self.select_camera()?;
            self.create_reader()?;
            self.create_encoder()?;
            self.audio_enabled = self.create_audio_encoder().is_ok() && self.create_audio_recorder().is_ok();
            if !self.audio_enabled {
                log::warn!("Android audio disabled; continuing with video-only camera startup");
                self.release_audio_resources();
            }
            self.open_camera()?;
            self.create_capture_session()?;

            self.running.store(true, Ordering::SeqCst);

            let thread_state = Arc::new(ThreadState {
                running: Arc::clone(&self.running),
                callbacks: self.callbacks,
                encoder: self.encoder,
                audio_encoder: self.audio_encoder,
                audio_stream: self.audio_stream,
            });

            let encoder_state = Arc::clone(&thread_state);
            self.encoder_thread = Some(thread::spawn(move || {
                encoder_state.drain_encoder();
            }));

            if self.audio_enabled {
                if sys::AAudioStream_requestStart(self.audio_stream) != sys::AAUDIO_OK {
                    log::warn!("AAudioStream_requestStart failed; continuing without audio");
                    self.release_audio_resources();
                } else {
                    let audio_state = Arc::clone(&thread_state);
                    self.audio_thread = Some(thread::spawn(move || {
                        audio_state.drain_audio();
                    }));
                }
            }

            Ok(())
        }

        unsafe fn stop(&mut self) {
            let was_running = self.running.swap(false, Ordering::SeqCst);

            if !self.session.is_null() {
                let _ = sys::ACameraCaptureSession_stopRepeating(self.session);
                let _ = sys::ACameraCaptureSession_abortCaptures(self.session);
                sys::ACameraCaptureSession_close(self.session);
                self.session = ptr::null_mut();
            }

            if !self.audio_stream.is_null() {
                let _ = sys::AAudioStream_requestStop(self.audio_stream);
            }

            if let Some(handle) = self.encoder_thread.take() {
                let _ = handle.join();
            }
            if let Some(handle) = self.audio_thread.take() {
                let _ = handle.join();
            }

            if !self.encoder.is_null() {
                let _ = sys::AMediaCodec_stop(self.encoder);
                sys::AMediaCodec_delete(self.encoder);
                self.encoder = ptr::null_mut();
            }

            self.release_audio_resources();

            if !self.capture_request.is_null() {
                sys::ACaptureRequest_free(self.capture_request);
                self.capture_request = ptr::null_mut();
            }
            if !self.encoder_target.is_null() {
                sys::ACameraOutputTarget_free(self.encoder_target);
                self.encoder_target = ptr::null_mut();
            }
            if !self.raw_target.is_null() {
                sys::ACameraOutputTarget_free(self.raw_target);
                self.raw_target = ptr::null_mut();
            }
            if !self.outputs.is_null() {
                sys::ACaptureSessionOutputContainer_free(self.outputs);
                self.outputs = ptr::null_mut();
            }
            if !self.encoder_output.is_null() {
                sys::ACaptureSessionOutput_free(self.encoder_output);
                self.encoder_output = ptr::null_mut();
            }
            if !self.raw_output.is_null() {
                sys::ACaptureSessionOutput_free(self.raw_output);
                self.raw_output = ptr::null_mut();
            }
            if !self.encoder_window.is_null() {
                sys::ANativeWindow_release(self.encoder_window);
                self.encoder_window = ptr::null_mut();
            }
            if !self.reader.is_null() {
                let _guard = self.image_mutex.lock().unwrap();
                sys::AImageReader_setImageListener(self.reader, ptr::null_mut());
                sys::AImageReader_delete(self.reader);
                self.reader = ptr::null_mut();
                self.raw_window = ptr::null_mut();
            }
            if !self.device.is_null() {
                sys::ACameraDevice_close(self.device);
                self.device = ptr::null_mut();
            }
            if !self.manager.is_null() {
                sys::ACameraManager_delete(self.manager);
                self.manager = ptr::null_mut();
            }

            if was_running {
                log::info!("Android camera stopped");
            }
        }

        fn fail<T>(&self, message: &str) -> Result<T, String> {
            log::error!("{message}");
            if let Ok(c_message) = CString::new(message) {
                (self.callbacks.on_error)(self.callbacks.user_data, c_message.as_ptr());
            }
            Err(message.to_string())
        }

        unsafe fn select_camera(&mut self) -> Result<(), String> {
            let mut ids: *mut sys::ACameraIdList = ptr::null_mut();
            if sys::ACameraManager_getCameraIdList(self.manager, &mut ids) != CAMERA_OK || ids.is_null() {
                return self.fail("ACameraManager_getCameraIdList failed");
            }

            let wanted = if self.config.facing == K_FACING_FRONT {
                sys::acamera_metadata_enum_acamera_lens_facing::ACAMERA_LENS_FACING_FRONT.0 as u8
            } else {
                sys::acamera_metadata_enum_acamera_lens_facing::ACAMERA_LENS_FACING_BACK.0 as u8
            };

            let id_list = &*ids;
            for i in 0..id_list.numCameras {
                let id_ptr = *id_list.cameraIds.add(i as usize);
                let mut metadata: *mut sys::ACameraMetadata = ptr::null_mut();
                if sys::ACameraManager_getCameraCharacteristics(self.manager, id_ptr, &mut metadata) != CAMERA_OK {
                    continue;
                }

                let mut entry = std::mem::zeroed::<sys::ACameraMetadata_const_entry>();
                let matched = sys::ACameraMetadata_getConstEntry(
                    metadata,
                    sys::acamera_metadata_tag::ACAMERA_LENS_FACING.0,
                    &mut entry,
                ) == CAMERA_OK
                    && entry.count > 0
                    && camera_metadata_u8(&entry)
                        .map(|facing| facing == wanted)
                        .unwrap_or(false);

                sys::ACameraMetadata_free(metadata);

                if matched {
                    self.camera_id = Some(cstr_ptr_to_cstring(id_ptr)?);
                    break;
                }
            }

            sys::ACameraManager_deleteCameraIdList(ids);

            if self.camera_id.is_none() {
                return self.fail("no matching Android camera found");
            }
            Ok(())
        }

        unsafe fn create_reader(&mut self) -> Result<(), String> {
            let status = sys::AImageReader_new(
                self.config.width,
                self.config.height,
                AIMAGE_FORMAT_YUV_420_888,
                4,
                &mut self.reader,
            );
            if status != MEDIA_OK || self.reader.is_null() {
                return self.fail("AImageReader_new(YUV_420_888) failed");
            }

            let mut listener = sys::AImageReader_ImageListener {
                context: self as *mut Self as *mut c_void,
                onImageAvailable: Some(Self::on_image_available),
            };
            let status = sys::AImageReader_setImageListener(self.reader, &mut listener);
            if status != MEDIA_OK {
                return self.fail("AImageReader_setImageListener failed");
            }

            let status = sys::AImageReader_getWindow(self.reader, &mut self.raw_window);
            if status != MEDIA_OK || self.raw_window.is_null() {
                return self.fail("AImageReader_getWindow failed");
            }
            Ok(())
        }

        unsafe fn create_encoder(&mut self) -> Result<(), String> {
            let video_avc = CString::new("video/avc").unwrap();
            self.encoder = sys::AMediaCodec_createEncoderByType(video_avc.as_ptr());
            if self.encoder.is_null() {
                return self.fail("AMediaCodec_createEncoderByType(video/avc) failed");
            }

            let format = sys::AMediaFormat_new();
            if format.is_null() {
                return self.fail("AMediaFormat_new video failed");
            }

            set_format_string(format, sys::AMEDIAFORMAT_KEY_MIME, &video_avc);
            sys::AMediaFormat_setInt32(format, sys::AMEDIAFORMAT_KEY_WIDTH, self.config.width);
            sys::AMediaFormat_setInt32(format, sys::AMEDIAFORMAT_KEY_HEIGHT, self.config.height);
            sys::AMediaFormat_setInt32(format, sys::AMEDIAFORMAT_KEY_BIT_RATE, self.config.bitrate);
            sys::AMediaFormat_setInt32(format, sys::AMEDIAFORMAT_KEY_FRAME_RATE, self.config.fps);
            sys::AMediaFormat_setInt32(format, sys::AMEDIAFORMAT_KEY_I_FRAME_INTERVAL, self.config.i_frame_interval);
            sys::AMediaFormat_setInt32(format, sys::AMEDIAFORMAT_KEY_COLOR_FORMAT, K_COLOR_FORMAT_SURFACE);

            let status = sys::AMediaCodec_configure(
                self.encoder,
                format,
                ptr::null_mut(),
                ptr::null_mut(),
                sys::AMEDIACODEC_CONFIGURE_FLAG_ENCODE as u32,
            );
            sys::AMediaFormat_delete(format);
            if status != MEDIA_OK {
                return self.fail("AMediaCodec_configure video encoder failed");
            }

            let status = sys::AMediaCodec_createInputSurface(self.encoder, &mut self.encoder_window);
            if status != MEDIA_OK || self.encoder_window.is_null() {
                return self.fail("AMediaCodec_createInputSurface failed");
            }

            if sys::AMediaCodec_start(self.encoder) != MEDIA_OK {
                return self.fail("AMediaCodec_start video failed");
            }
            Ok(())
        }

        unsafe fn create_audio_encoder(&mut self) -> Result<(), String> {
            let audio_aac = CString::new("audio/mp4a-latm").unwrap();
            self.audio_encoder = sys::AMediaCodec_createEncoderByType(audio_aac.as_ptr());
            if self.audio_encoder.is_null() {
                return Err("AMediaCodec_createEncoderByType(audio/mp4a-latm) failed".to_string());
            }

            let format = sys::AMediaFormat_new();
            if format.is_null() {
                return Err("AMediaFormat_new audio failed".to_string());
            }

            set_format_string(format, sys::AMEDIAFORMAT_KEY_MIME, &audio_aac);
            sys::AMediaFormat_setInt32(format, sys::AMEDIAFORMAT_KEY_SAMPLE_RATE, K_AUDIO_SAMPLE_RATE);
            sys::AMediaFormat_setInt32(format, sys::AMEDIAFORMAT_KEY_CHANNEL_COUNT, K_AUDIO_CHANNEL_COUNT);
            sys::AMediaFormat_setInt32(format, sys::AMEDIAFORMAT_KEY_BIT_RATE, K_AUDIO_BITRATE);
            sys::AMediaFormat_setInt32(format, sys::AMEDIAFORMAT_KEY_AAC_PROFILE, K_AAC_OBJECT_LC);

            let status = sys::AMediaCodec_configure(
                self.audio_encoder,
                format,
                ptr::null_mut(),
                ptr::null_mut(),
                sys::AMEDIACODEC_CONFIGURE_FLAG_ENCODE as u32,
            );
            sys::AMediaFormat_delete(format);
            if status != MEDIA_OK {
                return Err("AMediaCodec_configure audio encoder failed".to_string());
            }

            if sys::AMediaCodec_start(self.audio_encoder) != MEDIA_OK {
                return Err("AMediaCodec_start audio encoder failed".to_string());
            }

            self.audio_encoder_started = true;
            Ok(())
        }

        unsafe fn create_audio_recorder(&mut self) -> Result<(), String> {
            let mut builder: *mut sys::AAudioStreamBuilder = ptr::null_mut();
            if sys::AAudio_createStreamBuilder(&mut builder) != sys::AAUDIO_OK || builder.is_null() {
                return Err("AAudio_createStreamBuilder failed".to_string());
            }

            sys::AAudioStreamBuilder_setDirection(builder, sys::AAUDIO_DIRECTION_INPUT as i32);
            sys::AAudioStreamBuilder_setSampleRate(builder, K_AUDIO_SAMPLE_RATE);
            sys::AAudioStreamBuilder_setChannelCount(builder, K_AUDIO_CHANNEL_COUNT);
            sys::AAudioStreamBuilder_setFormat(builder, sys::AAUDIO_FORMAT_PCM_I16);
            sys::AAudioStreamBuilder_setPerformanceMode(builder, sys::AAUDIO_PERFORMANCE_MODE_NONE as i32);
            sys::AAudioStreamBuilder_setSharingMode(builder, sys::AAUDIO_SHARING_MODE_SHARED as i32);

            let result = sys::AAudioStreamBuilder_openStream(builder, &mut self.audio_stream);
            sys::AAudioStreamBuilder_delete(builder);

            if result != sys::AAUDIO_OK || self.audio_stream.is_null() {
                return Err("AAudioStreamBuilder_openStream failed; check RECORD_AUDIO permission".to_string());
            }
            Ok(())
        }

        unsafe fn release_audio_resources(&mut self) {
            self.audio_enabled = false;
            if !self.audio_encoder.is_null() {
                if self.audio_encoder_started {
                    let _ = sys::AMediaCodec_stop(self.audio_encoder);
                }
                sys::AMediaCodec_delete(self.audio_encoder);
                self.audio_encoder = ptr::null_mut();
            }
            self.audio_encoder_started = false;

            if !self.audio_stream.is_null() {
                sys::AAudioStream_close(self.audio_stream);
                self.audio_stream = ptr::null_mut();
            }
        }

        unsafe fn open_camera(&mut self) -> Result<(), String> {
            let mut callbacks = sys::ACameraDevice_StateCallbacks {
                context: self as *mut Self as *mut c_void,
                onDisconnected: Some(Self::on_camera_disconnected),
                onError: Some(Self::on_camera_error),
            };

            let camera_id = self.camera_id.as_ref().expect("camera id selected");
            let status = sys::ACameraManager_openCamera(
                self.manager,
                camera_id.as_ptr(),
                &mut callbacks,
                &mut self.device,
            );
            if status != CAMERA_OK || self.device.is_null() {
                return self.fail("ACameraManager_openCamera failed");
            }
            Ok(())
        }

        unsafe fn create_capture_session(&mut self) -> Result<(), String> {
            if sys::ACaptureSessionOutputContainer_create(&mut self.outputs) != CAMERA_OK {
                return self.fail("ACaptureSessionOutputContainer_create failed");
            }
            if sys::ACaptureSessionOutput_create(self.encoder_window, &mut self.encoder_output) != CAMERA_OK
                || sys::ACaptureSessionOutput_create(self.raw_window, &mut self.raw_output) != CAMERA_OK
            {
                return self.fail("ACaptureSessionOutput_create failed");
            }
            if sys::ACaptureSessionOutputContainer_add(self.outputs, self.encoder_output) != CAMERA_OK
                || sys::ACaptureSessionOutputContainer_add(self.outputs, self.raw_output) != CAMERA_OK
            {
                return self.fail("ACaptureSessionOutputContainer_add failed");
            }

            if sys::ACameraDevice_createCaptureRequest(
                self.device,
                sys::ACameraDevice_request_template(3),
                &mut self.capture_request,
            ) != CAMERA_OK
            {
                return self.fail("ACameraDevice_createCaptureRequest failed");
            }

            if sys::ACameraOutputTarget_create(self.encoder_window, &mut self.encoder_target) != CAMERA_OK
                || sys::ACameraOutputTarget_create(self.raw_window, &mut self.raw_target) != CAMERA_OK
            {
                return self.fail("ACameraOutputTarget_create failed");
            }
            if sys::ACaptureRequest_addTarget(self.capture_request, self.encoder_target) != CAMERA_OK
                || sys::ACaptureRequest_addTarget(self.capture_request, self.raw_target) != CAMERA_OK
            {
                return self.fail("ACaptureRequest_addTarget failed");
            }

            let fps_range = [self.config.fps, self.config.fps];
            let status = sys::ACaptureRequest_setEntry_i32(
                self.capture_request,
                sys::acamera_metadata_tag::ACAMERA_CONTROL_AE_TARGET_FPS_RANGE.0,
                fps_range.len() as u32,
                fps_range.as_ptr(),
            );
            if status != CAMERA_OK {
                return self.fail("ACaptureRequest_setEntry_i32 fps range failed");
            }

            let mut session_callbacks = sys::ACameraCaptureSession_stateCallbacks {
                context: self as *mut Self as *mut c_void,
                onClosed: None,
                onReady: None,
                onActive: None,
            };

            if sys::ACameraDevice_createCaptureSession(
                self.device,
                self.outputs,
                &mut session_callbacks,
                &mut self.session,
            ) != CAMERA_OK
            {
                return self.fail("ACameraDevice_createCaptureSession failed");
            }

            let mut request = self.capture_request;
            if sys::ACameraCaptureSession_setRepeatingRequest(
                self.session,
                ptr::null_mut(),
                1,
                &mut request,
                ptr::null_mut(),
            ) != CAMERA_OK
            {
                return self.fail("ACameraCaptureSession_setRepeatingRequest failed");
            }

            Ok(())
        }

        unsafe extern "C" fn on_camera_disconnected(context: *mut c_void, _device: *mut sys::ACameraDevice) {
            if let Some(this) = (context as *mut Self).as_mut() {
                let _ = this.fail::<()>("camera disconnected");
            }
        }

        unsafe extern "C" fn on_camera_error(
            context: *mut c_void,
            _device: *mut sys::ACameraDevice,
            error: c_int,
        ) {
            if let Some(this) = (context as *mut Self).as_mut() {
                let message = format!("camera device error: {error}");
                let _ = this.fail::<()>(&message);
            }
        }

        unsafe extern "C" fn on_image_available(context: *mut c_void, reader: *mut sys::AImageReader) {
            if let Some(this) = (context as *mut Self).as_mut() {
                this.handle_image_available(reader);
            }
        }

        unsafe fn handle_image_available(&mut self, reader: *mut sys::AImageReader) {
            let _guard = self.image_mutex.lock().unwrap();
            if !self.running.load(Ordering::SeqCst) {
                return;
            }

            let mut image: *mut sys::AImage = ptr::null_mut();
            if sys::AImageReader_acquireLatestImage(reader, &mut image) != MEDIA_OK || image.is_null() {
                return;
            }

            if !self.should_emit_raw_frame() {
                sys::AImage_delete(image);
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

            let ok = sys::AImage_getPlaneData(image, 0, &mut y, &mut y_len) == MEDIA_OK
                && sys::AImage_getPlaneData(image, 1, &mut u, &mut u_len) == MEDIA_OK
                && sys::AImage_getPlaneData(image, 2, &mut v, &mut v_len) == MEDIA_OK
                && sys::AImage_getPlaneRowStride(image, 0, &mut y_row) == MEDIA_OK
                && sys::AImage_getPlaneRowStride(image, 1, &mut u_row) == MEDIA_OK
                && sys::AImage_getPlaneRowStride(image, 2, &mut v_row) == MEDIA_OK
                && sys::AImage_getPlanePixelStride(image, 0, &mut y_pix) == MEDIA_OK
                && sys::AImage_getPlanePixelStride(image, 1, &mut u_pix) == MEDIA_OK
                && sys::AImage_getPlanePixelStride(image, 2, &mut v_pix) == MEDIA_OK;

            if ok && !y.is_null() && !u.is_null() && !v.is_null() {
                let expected = (self.config.width * self.config.height * 3 / 2) as usize;
                let mut i420 = vec![0u8; expected];
                copy_yuv420_to_i420(
                    &mut i420,
                    self.config.width,
                    self.config.height,
                    Plane { ptr: y, len: y_len, row_stride: y_row, pixel_stride: y_pix },
                    Plane { ptr: u, len: u_len, row_stride: u_row, pixel_stride: u_pix },
                    Plane { ptr: v, len: v_len, row_stride: v_row, pixel_stride: v_pix },
                );
                (self.callbacks.on_raw_i420)(
                    self.callbacks.user_data,
                    i420.as_ptr(),
                    i420.len(),
                    self.config.width,
                    self.config.height,
                );
            }

            sys::AImage_delete(image);
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

    impl ThreadState {
        fn drain_encoder(&self) {
            unsafe {
                self.drain_encoder_unsafe();
            }
        }

        unsafe fn drain_encoder_unsafe(&self) {
            while self.running.load(Ordering::SeqCst) {
                let mut info = std::mem::zeroed::<sys::AMediaCodecBufferInfo>();
                let index = sys::AMediaCodec_dequeueOutputBuffer(self.encoder, &mut info, 10_000);
                if index == sys::AMEDIACODEC_INFO_TRY_AGAIN_LATER as isize {
                    continue;
                }
                if index == sys::AMEDIACODEC_INFO_OUTPUT_FORMAT_CHANGED as isize {
                    self.emit_codec_config_from_output_format();
                    continue;
                }
                if index < 0 {
                    continue;
                }

                let mut out_size = 0usize;
                let out = sys::AMediaCodec_getOutputBuffer(self.encoder, index as usize, &mut out_size);
                if !out.is_null() && info.size > 0 {
                    let offset = info.offset.max(0) as usize;
                    let size = info.size as usize;
                    if offset + size <= out_size {
                        let bytes = std::slice::from_raw_parts(out.add(offset), size);
                        self.emit_annexb(bytes);
                    }
                }
                sys::AMediaCodec_releaseOutputBuffer(self.encoder, index as usize, false);
            }
        }

        fn drain_audio(&self) {
            unsafe {
                self.drain_audio_unsafe();
            }
        }

        unsafe fn drain_audio_unsafe(&self) {
            let mut samples = vec![0i16; K_AUDIO_SAMPLES_PER_ACCESS_UNIT * K_AUDIO_CHANNEL_COUNT as usize];
            let mut filled_frames = 0usize;
            let mut submitted_frames = 0i64;

            while self.running.load(Ordering::SeqCst) {
                let frames_needed = K_AUDIO_SAMPLES_PER_ACCESS_UNIT - filled_frames;
                let dst = samples.as_mut_ptr().add(filled_frames * K_AUDIO_CHANNEL_COUNT as usize);
                let frames_read = sys::AAudioStream_read(
                    self.audio_stream,
                    dst.cast(),
                    frames_needed as i32,
                    100_000_000,
                );

                if frames_read == sys::AAUDIO_ERROR_DISCONNECTED {
                    log::warn!("AAudioStream_read disconnected; stopping audio capture");
                    break;
                }
                if frames_read < 0 {
                    continue;
                }
                if frames_read == 0 {
                    self.drain_audio_encoder(false);
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
                if !self.queue_audio_input(samples.as_ptr().cast(), byte_count, pts_us) {
                    break;
                }
                submitted_frames += K_AUDIO_SAMPLES_PER_ACCESS_UNIT as i64;
                filled_frames = 0;

                self.drain_audio_encoder(false);
            }

            self.drain_audio_encoder(true);
        }

        unsafe fn queue_audio_input(&self, data: *const u8, len: usize, pts_us: i64) -> bool {
            for _ in 0..5 {
                if !self.running.load(Ordering::SeqCst) {
                    return false;
                }

                let index = sys::AMediaCodec_dequeueInputBuffer(self.audio_encoder, 10_000);
                if index == sys::AMEDIACODEC_INFO_TRY_AGAIN_LATER as isize {
                    self.drain_audio_encoder(false);
                    continue;
                }
                if index < 0 {
                    continue;
                }

                let mut capacity = 0usize;
                let input = sys::AMediaCodec_getInputBuffer(self.audio_encoder, index as usize, &mut capacity);
                if input.is_null() || capacity < len {
                    let _ = sys::AMediaCodec_queueInputBuffer(self.audio_encoder, index as usize, 0, 0, pts_us as u64, 0);
                    return false;
                }

                ptr::copy_nonoverlapping(data, input, len);
                return sys::AMediaCodec_queueInputBuffer(self.audio_encoder, index as usize, 0, len, pts_us as u64, 0)
                    == MEDIA_OK;
            }

            false
        }

        unsafe fn drain_audio_encoder(&self, wait: bool) {
            if self.audio_encoder.is_null() {
                return;
            }

            while self.running.load(Ordering::SeqCst) || wait {
                let mut info = std::mem::zeroed::<sys::AMediaCodecBufferInfo>();
                let index = sys::AMediaCodec_dequeueOutputBuffer(
                    self.audio_encoder,
                    &mut info,
                    if wait { 10_000 } else { 0 },
                );
                if index == sys::AMEDIACODEC_INFO_TRY_AGAIN_LATER as isize {
                    break;
                }
                if index == sys::AMEDIACODEC_INFO_OUTPUT_FORMAT_CHANGED as isize || index < 0 {
                    continue;
                }

                let mut out_size = 0usize;
                let out = sys::AMediaCodec_getOutputBuffer(self.audio_encoder, index as usize, &mut out_size);
                let codec_config = (info.flags & sys::AMEDIACODEC_BUFFER_FLAG_CODEC_CONFIG) != 0;
                if !codec_config && !out.is_null() && info.size > 0 {
                    let offset = info.offset.max(0) as usize;
                    let size = info.size as usize;
                    if offset + size <= out_size {
                        (self.callbacks.on_aac)(self.callbacks.user_data, out.add(offset), size);
                    }
                }
                sys::AMediaCodec_releaseOutputBuffer(self.audio_encoder, index as usize, false);

                if (info.flags & sys::AMEDIACODEC_BUFFER_FLAG_END_OF_STREAM) != 0 {
                    break;
                }
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

            let kind = (data[offset] & 0x1F) as c_int;
            (self.callbacks.on_h264)(self.callbacks.user_data, data.as_ptr(), data.len(), kind);
        }

        unsafe fn emit_codec_config_from_output_format(&self) {
            let format = sys::AMediaCodec_getOutputFormat(self.encoder);
            if format.is_null() {
                log::error!("AMediaCodec_getOutputFormat returned null");
                return;
            }

            self.emit_codec_config_buffer_from_format(format, "csd-0");
            self.emit_codec_config_buffer_from_format(format, "csd-1");

            sys::AMediaFormat_delete(format);
        }

        unsafe fn emit_codec_config_buffer_from_format(&self, format: *mut sys::AMediaFormat, key: &str) {
            let key = CString::new(key).unwrap();
            let mut buffer: *mut c_void = ptr::null_mut();
            let mut buffer_size = 0usize;

            if sys::AMediaFormat_getBuffer(format, key.as_ptr(), &mut buffer, &mut buffer_size)
                && !buffer.is_null()
                && buffer_size > 0
            {
                let data = std::slice::from_raw_parts(buffer.cast::<u8>(), buffer_size);
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

    unsafe fn copy_yuv420_to_i420(
        dst: &mut [u8],
        width: c_int,
        height: c_int,
        y: Plane,
        u: Plane,
        v: Plane,
    ) {
        let width = width as usize;
        let height = height as usize;
        let y_size = width * height;
        let uv_width = width / 2;
        let uv_height = height / 2;
        let uv_size = uv_width * uv_height;

        if dst.len() < y_size + uv_size * 2 {
            return;
        }

        let (dst_y, rest) = dst.split_at_mut(y_size);
        let (dst_u, dst_v) = rest.split_at_mut(uv_size);

        for row in 0..height {
            let src_offset = row * y.row_stride as usize;
            if src_offset + width <= y.len as usize {
                ptr::copy_nonoverlapping(y.ptr.add(src_offset), dst_y.as_mut_ptr().add(row * width), width);
            }
        }

        for row in 0..uv_height {
            for col in 0..uv_width {
                let u_offset = row * u.row_stride as usize + col * u.pixel_stride as usize;
                let v_offset = row * v.row_stride as usize + col * v.pixel_stride as usize;
                let dst_offset = row * uv_width + col;
                if u_offset < u.len as usize {
                    dst_u[dst_offset] = *u.ptr.add(u_offset);
                }
                if v_offset < v.len as usize {
                    dst_v[dst_offset] = *v.ptr.add(v_offset);
                }
            }
        }
    }

    unsafe fn camera_metadata_u8(entry: &sys::ACameraMetadata_const_entry) -> Option<u8> {
        let data = *(&entry.data as *const _ as *const *const u8);
        if data.is_null() {
            None
        } else {
            Some(*data)
        }
    }

    unsafe fn cstr_ptr_to_cstring(ptr: *const c_char) -> Result<CString, String> {
        if ptr.is_null() {
            return Err("camera id pointer was null".to_string());
        }
        Ok(std::ffi::CStr::from_ptr(ptr).to_owned())
    }

    unsafe fn set_format_string(format: *mut sys::AMediaFormat, key: *const c_char, value: &CString) {
        sys::AMediaFormat_setString(format, key, value.as_ptr());
    }
}
