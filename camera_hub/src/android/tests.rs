/// Miri tests for the unsafe code in android_dual_stream.rs needed to interact with Android NDK.
/// These tests use the mock NDK.
///
/// SPDX-License-Identifier: GPL-3.0-or-later

/// Note: Make sure to use --test-threads=1. Some callback tests use
/// global counters.

use std::collections::VecDeque;
use std::ffi::CString;
use std::os::raw::{c_int, c_void};
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};

use crossbeam_channel::unbounded;

use super::*;

static H264_CALLBACKS: AtomicUsize = AtomicUsize::new(0);
static AAC_CALLBACKS: AtomicUsize = AtomicUsize::new(0);
static RAW_CALLBACKS: AtomicUsize = AtomicUsize::new(0);
static ERROR_CALLBACKS: AtomicUsize = AtomicUsize::new(0);
static VIDEO_RUNNING: OnceLock<Mutex<Option<Arc<AtomicBool>>>> = OnceLock::new();

fn test_state() -> Arc<super::super::AndroidStreamState> {
    let (ps_tx, _ps_rx) = unbounded();
    Arc::new(super::super::AndroidStreamState {
        frame_queue: Arc::new(Mutex::new(VecDeque::new())),
        ps_tx,
    })
}

fn test_h264_callback(
    _state: &super::super::AndroidStreamState,
    _data: &[u8],
    _kind: super::super::FrameKind,
) {
    H264_CALLBACKS.fetch_add(1, Ordering::SeqCst);
    if let Some(running) = VIDEO_RUNNING
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap()
        .as_ref()
    {
        running.store(false, Ordering::SeqCst);
    }
}

fn test_aac_callback(_state: &super::super::AndroidStreamState, _data: &[u8]) {
    AAC_CALLBACKS.fetch_add(1, Ordering::SeqCst);
}

fn test_raw_callback(
    _state: &super::super::AndroidStreamState,
    _data: &[u8],
    _width: usize,
    _height: usize,
) {
    RAW_CALLBACKS.fetch_add(1, Ordering::SeqCst);
}

fn test_error_callback(_message: &str) {
    ERROR_CALLBACKS.fetch_add(1, Ordering::SeqCst);
}

fn test_callbacks() -> CameraCallbacks {
    CameraCallbacks {
        state: test_state(),
        on_h264: test_h264_callback,
        on_aac: test_aac_callback,
        on_raw_i420: test_raw_callback,
        on_error: test_error_callback,
    }
}

fn test_config() -> CameraConfig {
    CameraConfig {
        facing: ANDROID_CAMERA_FACING_BACK,
        width: 1280,
        height: 720,
        raw_width: 4,
        raw_height: 4,
        fps_min: 10,
        fps_max: 10,
        bitrate: 2_000_000,
        i_frame_interval: 1,
        motion_fps: 10,
    }
}

fn plane(data: &[u8], row_stride: c_int, pixel_stride: c_int) -> Plane {
    Plane {
        ptr: data.as_ptr(),
        len: c_int::try_from(data.len()).unwrap(),
        row_stride,
        pixel_stride,
    }
}

fn mock_metadata() -> (*mut sys::ACameraManager, *mut sys::ACameraMetadata) {
    unsafe {
        let manager = sys::ACameraManager_create();
        let camera_id = CString::new("0").unwrap();
        let mut metadata = ptr::null_mut();
        assert_eq!(
            sys::ACameraManager_getCameraCharacteristics(
                manager,
                camera_id.as_ptr(),
                &mut metadata,
            ),
            CAMERA_OK,
        );
        assert!(!manager.is_null());
        assert!(!metadata.is_null());
        (manager, metadata)
    }
}

#[test]
/// The Y, U, and V planes may have padding between rows and samples.
/// This test checks that the unsafe plane slices stay in bounds and
/// produce packed I420.
fn copy_yuv420_to_i420_with_row_and_pixel_strides() {
    let y = [
        1, 2, 3, 4, 0, 0,
        5, 6, 7, 8, 0, 0,
        9, 10, 11, 12, 0, 0,
        13, 14, 15, 16, 0, 0,
    ];
    let u = [17, 0, 18, 0, 19, 0, 20, 0];
    let v = [21, 0, 22, 0, 23, 0, 24, 0];
    let mut output = [0; 24];

    unsafe {
        copy_yuv420_to_i420(
            &mut output,
            4,
            4,
            plane(&y, 6, 1),
            plane(&u, 4, 2),
            plane(&v, 4, 2),
        );
    }

    assert_eq!(
        output,
        [
            // Y plane
            1, 2, 3, 4,
            5, 6, 7, 8,
            9, 10, 11, 12,
            13, 14, 15, 16,

            // U plane
            17, 18, 19, 20,

            // V plane
            21, 22, 23, 24,
        ]
    );
}

#[test]
/// This tests that invalid dimensions, null pointers, and zero pixel
/// strides are rejected before constructing or indexing unsafe plane slices.
fn copy_yuv420_to_i420_rejects_invalid_plane_descriptions() {
    let data = [1u8; 16];
    let valid = plane(&data, 4, 1);
    let null = Plane {
        ptr: ptr::null(),
        len: 16,
        row_stride: 4,
        pixel_stride: 1,
    };
    let zero_stride = Plane { pixel_stride: 0, ..valid };
    let mut output = [9u8; 24];

    unsafe {
        copy_yuv420_to_i420(&mut output, 4, 4, null, valid, valid);
        copy_yuv420_to_i420(&mut output, 4, 4, valid, zero_stride, valid);
        copy_yuv420_to_i420(&mut output, -1, 4, valid, valid, valid);
    }

    assert_eq!(output, [9u8; 24]);
}

#[test]
/// This tests that a valid but short source allocation is not read beyond its
/// declared length. Rows which do not fit remain zero in the destination.
fn copy_yuv420_to_i420_does_not_read_short_planes() {
    let y = [1, 2, 3, 4];
    let u = [5];
    let v = [6];
    let mut output = [0u8; 24];

    unsafe {
        copy_yuv420_to_i420(
            &mut output,
            4,
            4,
            plane(&y, 4, 1),
            plane(&u, 2, 1),
            plane(&v, 2, 1),
        );
    }

    assert_eq!(
        output,
        [
            // Y plane
            1, 2, 3, 4,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0,

            // U plane
            5, 0, 0, 0,

            // V plane
            6, 0, 0, 0,
        ]
    );

}

#[test]
/// The metadata i32 helper creates a slice from an NDK union pointer.
/// This tests non-empty, empty, and null representations.
fn camera_metadata_i32_vec_handles_valid_empty_and_null_entries() {
    let values = [10, 20, 30, 40];
    let valid = sys::ACameraMetadata_const_entry {
        tag: 0,
        type_: 1,
        count: values.len() as u32,
        data: sys::ACameraMetadata_const_entry__bindgen_ty_1 {
            i32_: values.as_ptr(),
        },
    };
    let empty = sys::ACameraMetadata_const_entry { count: 0, ..valid };
    let null = sys::ACameraMetadata_const_entry {
        count: 1,
        data: sys::ACameraMetadata_const_entry__bindgen_ty_1 { i32_: ptr::null() },
        ..valid
    };

    unsafe {
        assert_eq!(camera_metadata_i32_vec(&valid), Some(values.to_vec()));
        assert_eq!(camera_metadata_i32_vec(&empty), Some(Vec::new()));
        assert_eq!(camera_metadata_i32_vec(&null), None);
    }
}

#[test]
/// The metadata u8 helper dereferences the pointer member of an NDK
/// metadata union. This tests valid, empty, and null representations.
fn camera_metadata_u8_handles_valid_empty_and_null_entries() {
    let value = 7u8;
    let valid = sys::ACameraMetadata_const_entry {
        tag: 0,
        type_: 0,
        count: 1,
        data: sys::ACameraMetadata_const_entry__bindgen_ty_1 { u8_: &value },
    };
    let empty = sys::ACameraMetadata_const_entry { count: 0, ..valid };
    let null = sys::ACameraMetadata_const_entry {
        data: sys::ACameraMetadata_const_entry__bindgen_ty_1 { u8_: ptr::null() },
        ..valid
    };

    unsafe {
        assert_eq!(camera_metadata_u8(&valid), Some(value));
        assert_eq!(camera_metadata_u8(&empty), None);
        assert_eq!(camera_metadata_u8(&null), None);
    }
}

#[test]
/// This tests copying a valid string and rejecting a null pointer.
fn cstr_ptr_to_cstring_copies_valid_input_and_rejects_null() {
    let camera_id = CString::new("camera-0").unwrap();

    unsafe {
        assert_eq!(cstr_ptr_to_cstring(camera_id.as_ptr()).unwrap(), camera_id);
        assert!(cstr_ptr_to_cstring(ptr::null()).is_err());
    }
}

#[test]
/// Capability discovery dereferences camera ID lists and metadata union
/// pointers supplied by the NDK. This tests the success path.
fn read_camera_capabilities_successfully() {
    let preview = ResolutionBound {
        max_long_side: 1920,
        max_short_side: 1080,
    };

    let capabilities = unsafe { read_camera_capabilities(preview) }.unwrap();

    assert_eq!(capabilities.len(), 1);
    assert_eq!(capabilities[0].spec.facing, ANDROID_CAMERA_FACING_BACK);
    assert_eq!(
        capabilities[0].spec.resolutions,
        vec![AndroidCameraResolution { width: 1280, height: 720 }],
    );
    assert_eq!(
        capabilities[0].detection_resolutions,
        vec![AndroidCameraResolution { width: 640, height: 480 }],
    );
}

#[test]
/// This tests that metadata readers reject null handles.
fn camera_metadata_readers_reject_null_handles() {
    let preview = ResolutionBound {
        max_long_side: 1920,
        max_short_side: 1080,
    };

    unsafe {
        assert!(read_camera_spec(ptr::null_mut(), preview).is_none());
        assert!(read_camera_facing(ptr::null_mut()).is_none());
        assert_eq!(
            read_camera_resolutions(ptr::null_mut(), preview),
            (Vec::new(), Vec::new()),
        );
        assert_eq!(read_frame_rate_ranges(ptr::null_mut()), default_frame_rate_ranges());
    }
}

#[test]
/// This tests the success path of metadata readers.
fn camera_metadata_readers_parse_metadata() {
    let preview = ResolutionBound {
        max_long_side: 1920,
        max_short_side: 1080,
    };
    let (manager, metadata) = mock_metadata();

    unsafe {
        assert_eq!(read_camera_facing(metadata), Some(ANDROID_CAMERA_FACING_BACK));
        assert_eq!(
            read_camera_resolutions(metadata, preview),
            (
                vec![AndroidCameraResolution { width: 1280, height: 720 }],
                vec![AndroidCameraResolution { width: 640, height: 480 }],
            ),
        );
        assert_eq!(
            read_frame_rate_ranges(metadata),
            vec![
                AndroidCameraFrameRateRange { min: 10, max: 10 },
                AndroidCameraFrameRateRange { min: 15, max: 30 },
            ],
        );
        sys::ACameraMetadata_free(metadata);
        sys::ACameraManager_delete(manager);
    }
}

#[test]
/// This tests moving the NativeCamera to another thread (which exercises
/// the NativeCamera's unsafe Send trait).
fn native_camera_start_move_and_drop_uses_valid_handle_lifetimes() {
    let preview = ResolutionBound {
        max_long_side: 1920,
        max_short_side: 1080,
    };
    available_camera_specs(preview).unwrap();

    let camera = NativeCamera::start(test_config(), test_callbacks()).unwrap();
    std::thread::spawn(move || drop(camera)).join().unwrap();
}

#[test]
/// Native callbacks receive an opaque context pointer. This tests valid and null
/// contexts passed to these callbacks.
fn native_callbacks_validate_context_and_image_lifetimes() {
    ERROR_CALLBACKS.store(0, Ordering::SeqCst);
    RAW_CALLBACKS.store(0, Ordering::SeqCst);
    let bridge = CameraBridge::new(test_config(), test_callbacks());
    bridge.running.store(true, Ordering::SeqCst);
    let context = Arc::as_ptr(&bridge.callback_state) as *mut c_void;

    let mut reader = ptr::null_mut();
    unsafe {
        assert_eq!(sys::AImageReader_new(4, 4, AIMAGE_FORMAT_YUV_420_888, 4, &mut reader), MEDIA_OK);
        CameraCallbackState::on_session_closed(context, ptr::null_mut());
        CameraCallbackState::on_camera_disconnected(context, ptr::null_mut());
        CameraCallbackState::on_camera_error(context, ptr::null_mut(), 1);
        CameraCallbackState::on_image_available(context, reader);

        CameraCallbackState::on_session_closed(ptr::null_mut(), ptr::null_mut());
        CameraCallbackState::on_camera_disconnected(ptr::null_mut(), ptr::null_mut());
        CameraCallbackState::on_camera_error(ptr::null_mut(), ptr::null_mut(), 1);
        CameraCallbackState::on_image_available(ptr::null_mut(), reader);
        
        CameraCallbackState::on_image_available(context, ptr::null_mut());
        bridge.callback_state.handle_image_available(ptr::null_mut());
        sys::AImageReader_delete(reader);
    }

    assert!(*bridge.callback_state.session_closed.lock().unwrap());
    assert_eq!(ERROR_CALLBACKS.load(Ordering::SeqCst), 2);
    assert_eq!(RAW_CALLBACKS.load(Ordering::SeqCst), 1);
}

#[test]
/// A dequeued video buffer becomes an unsafe Rust slice until it is
/// released. This tests that one mock Annex-B buffer is consumed while live.
fn video_encoder_drain_uses_live_output_buffer() {
    H264_CALLBACKS.store(0, Ordering::SeqCst);
    let running = Arc::new(AtomicBool::new(true));
    *VIDEO_RUNNING.get_or_init(|| Mutex::new(None)).lock().unwrap() =
        Some(Arc::clone(&running));

    let mime = CString::new("video/avc").unwrap();
    let codec = unsafe { sys::AMediaCodec_createEncoderByType(mime.as_ptr()) };

    assert!(unsafe { sys::miri_set_codec_output(codec, &[0, 0, 0, 1, 0x67, 1], 0) });
    let state = VideoEncoderThreadState {
        running,
        callbacks: test_callbacks(),
        encoder: codec,
    };

    unsafe {
        state.drain_encoder_unsafe();
        sys::AMediaCodec_delete(codec);
    }
    *VIDEO_RUNNING.get().unwrap().lock().unwrap() = None;

    assert_eq!(H264_CALLBACKS.load(Ordering::SeqCst), 1);
}

#[test]
/// Codec-specific format data is returned as a raw pointer and length.
/// This tests conversion of that live buffer into an H.264 callback slice.
fn codec_config_reader_uses_live_format_buffer() {
    H264_CALLBACKS.store(0, Ordering::SeqCst);
    let format = unsafe { sys::AMediaFormat_new() };

    assert!(unsafe { sys::miri_set_format_buffer(format, &[0x67, 1, 2, 3]) });
    let state = VideoEncoderThreadState {
        running: Arc::new(AtomicBool::new(false)),
        callbacks: test_callbacks(),
        encoder: ptr::null_mut(),
    };

    unsafe {
        state.emit_codec_config_buffer_from_format(format, "csd-0");
        sys::AMediaFormat_delete(format);
    }

    assert_eq!(H264_CALLBACKS.load(Ordering::SeqCst), 1);
}

#[test]
/// Retrieving a codec output format transfers ownership of a raw format
/// handle to Rust. This tests that the format is queried and released once.
fn codec_output_format_handle_is_released_after_use() {
    let mime = CString::new("video/avc").unwrap();
    let codec = unsafe { sys::AMediaCodec_createEncoderByType(mime.as_ptr()) };
    let state = VideoEncoderThreadState {
        running: Arc::new(AtomicBool::new(false)),
        callbacks: test_callbacks(),
        encoder: codec,
    };

    unsafe {
        state.emit_codec_config_from_output_format();
        sys::AMediaCodec_delete(codec);
    }
}

#[test]
/// Audio input is copied into a mutable raw codec buffer. This tests
/// a fitting access unit and rejection when the codec capacity is insufficient.
fn audio_input_queue_uses_live_mutable_codec_buffer() {
    let mime = CString::new("audio/mp4a-latm").unwrap();
    let codec = unsafe { sys::AMediaCodec_createEncoderByType(mime.as_ptr()) };
    let state = AudioThreadState {
        running: Arc::new(AtomicBool::new(true)),
        callbacks: test_callbacks(),
        audio_encoder: codec,
        audio_stream: ptr::null_mut(),
    };

    unsafe {
        assert!(state.queue_audio_input(&[1, 2, 3, 4], 0));
        assert!(!state.queue_audio_input(&vec![0; 4097], 1));
        sys::AMediaCodec_delete(codec);
    }
}

#[test]
/// Audio output is exposed as a raw codec pointer and length. This tests that
/// one live buffer is delivered before end-of-stream cleanup.
fn audio_encoder_drain_uses_live_output_buffer() {
    AAC_CALLBACKS.store(0, Ordering::SeqCst);
    let mime = CString::new("audio/mp4a-latm").unwrap();
    let codec = unsafe { sys::AMediaCodec_createEncoderByType(mime.as_ptr()) };

    assert!(unsafe {
        sys::miri_set_codec_output(
            codec,
            &[1, 2, 3, 4],
            sys::AMEDIACODEC_BUFFER_FLAG_END_OF_STREAM,
        )
    });
    let state = AudioThreadState {
        running: Arc::new(AtomicBool::new(false)),
        callbacks: test_callbacks(),
        audio_encoder: codec,
        audio_stream: ptr::null_mut(),
    };

    unsafe {
        state.drain_audio_encoder(true);
        sys::AMediaCodec_delete(codec);
    }

    assert_eq!(AAC_CALLBACKS.load(Ordering::SeqCst), 1);
}

#[test]
/// This tests reading audio PCM samples and queueing them into a mock audio codec.
fn audio_worker_uses_live_stream_and_codec_buffers() {
    let mut builder = ptr::null_mut();
    let mut stream = ptr::null_mut();
    let mime = CString::new("audio/mp4a-latm").unwrap();

    unsafe {
        assert_eq!(sys::AAudio_createStreamBuilder(&mut builder), sys::AAUDIO_OK);
        assert_eq!(sys::AAudioStreamBuilder_openStream(builder, &mut stream), sys::AAUDIO_OK);
        assert_eq!(sys::AAudioStreamBuilder_delete(builder), sys::AAUDIO_OK);
        let codec = sys::AMediaCodec_createEncoderByType(mime.as_ptr());
        let state = AudioThreadState {
            running: Arc::new(AtomicBool::new(true)),
            callbacks: test_callbacks(),
            audio_encoder: codec,
            audio_stream: stream,
        };
        state.drain_audio_unsafe();
        sys::AMediaCodec_delete(codec);
        assert_eq!(sys::AAudioStream_close(stream), sys::AAUDIO_OK);
    }
}
