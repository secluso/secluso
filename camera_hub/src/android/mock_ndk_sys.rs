//! Minimal mock Android NDK for Miri tests.
//!
//! This is not an Android emulator. It provides only the API subset used in
//! android_dual_stream.rs.
//! The mock uses Box allocations so Miri can track handle lifetimes and
//! pointer accesses.
//!
//! SPDX-License-Identifier: GPL-3.0-or-later

#![allow(non_camel_case_types, non_snake_case)]

use std::ffi::{c_char, c_void, CString};
use std::ptr;

#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct camera_status_t(pub i32);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct media_status_t(pub i32);

const CAMERA_OK: camera_status_t = camera_status_t(0);
const MEDIA_OK: media_status_t = media_status_t(0);

pub const AAUDIO_OK: i32 = 0;
pub const AAUDIO_ERROR_DISCONNECTED: i32 = -899;
pub const AAUDIO_DIRECTION_INPUT: u32 = 1;
pub const AAUDIO_FORMAT_PCM_I16: i32 = 1;
pub const AAUDIO_SHARING_MODE_SHARED: u32 = 1;
pub const AAUDIO_PERFORMANCE_MODE_NONE: u32 = 10;

pub const AMEDIACODEC_BUFFER_FLAG_CODEC_CONFIG: u32 = 2;
pub const AMEDIACODEC_BUFFER_FLAG_END_OF_STREAM: u32 = 4;
pub const AMEDIACODEC_CONFIGURE_FLAG_ENCODE: i32 = 1;
pub const AMEDIACODEC_INFO_OUTPUT_FORMAT_CHANGED: i32 = -2;
pub const AMEDIACODEC_INFO_TRY_AGAIN_LATER: i32 = -1;

macro_rules! media_key {
    ($name:ident, $value:literal) => {
        pub static mut $name: *const c_char = concat!($value, "\0").as_ptr().cast();
    };
}

media_key!(AMEDIAFORMAT_KEY_AAC_PROFILE, "aac-profile");
media_key!(AMEDIAFORMAT_KEY_BIT_RATE, "bitrate");
media_key!(AMEDIAFORMAT_KEY_CHANNEL_COUNT, "channel-count");
media_key!(AMEDIAFORMAT_KEY_COLOR_FORMAT, "color-format");
media_key!(AMEDIAFORMAT_KEY_FRAME_RATE, "frame-rate");
media_key!(AMEDIAFORMAT_KEY_HEIGHT, "height");
media_key!(AMEDIAFORMAT_KEY_I_FRAME_INTERVAL, "i-frame-interval");
media_key!(AMEDIAFORMAT_KEY_MIME, "mime");
media_key!(AMEDIAFORMAT_KEY_SAMPLE_RATE, "sample-rate");
media_key!(AMEDIAFORMAT_KEY_WIDTH, "width");

pub mod acamera_metadata_tag {
    #[repr(transparent)]
    #[derive(Clone, Copy)]
    pub struct Tag(pub u32);

    pub const ACAMERA_LENS_FACING: Tag = Tag(1);
    pub const ACAMERA_SCALER_AVAILABLE_STREAM_CONFIGURATIONS: Tag = Tag(2);
    pub const ACAMERA_CONTROL_AE_AVAILABLE_TARGET_FPS_RANGES: Tag = Tag(3);
    pub const ACAMERA_CONTROL_AE_TARGET_FPS_RANGE: Tag = Tag(4);
}

pub mod acamera_metadata_enum_acamera_lens_facing {
    #[repr(transparent)]
    #[derive(Clone, Copy)]
    pub struct Facing(pub u32);

    pub const ACAMERA_LENS_FACING_FRONT: Facing = Facing(0);
    pub const ACAMERA_LENS_FACING_BACK: Facing = Facing(1);
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union ACameraMetadata_const_entry__bindgen_ty_1 {
    pub u8_: *const u8,
    pub i32_: *const i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ACameraMetadata_const_entry {
    pub tag: u32,
    pub type_: u8,
    pub count: u32,
    pub data: ACameraMetadata_const_entry__bindgen_ty_1,
}

#[derive(Default)]
pub struct ACameraManager {
    _private: u8,
}

pub struct ACameraMetadata {
    facing: [u8; 1],
    stream_configurations: Vec<i32>,
    frame_rates: Vec<i32>,
}

impl ACameraMetadata {
    fn back_camera() -> Self {
        Self {
            facing: [acamera_metadata_enum_acamera_lens_facing::ACAMERA_LENS_FACING_BACK.0 as u8],
            stream_configurations: vec![
                // format, width, height, input/output for encoded stream
                0x22, 1280, 720, 0,
                // format, width, height, input/output for raw frames
                0x23, 640, 480, 0
            ],
            frame_rates: vec![10, 10, 15, 30],
        }
    }
}

pub struct ACameraIdList {
    pub numCameras: i32,
    pub cameraIds: *mut *const c_char,
    #[allow(dead_code)]
    ids: Vec<CString>,
    #[allow(dead_code)]
    pointers: Vec<*const c_char>,
}

#[derive(Default)]
pub struct ACameraDevice { _private: u8 }
pub struct ACaptureRequest { _private: u8 }
pub struct ACaptureSessionOutputContainer { _private: u8 }
pub struct ACaptureSessionOutput { _private: u8 }
pub struct ACameraOutputTarget { _private: u8 }

pub type ACameraCaptureSession_closed =
    Option<unsafe extern "C" fn(*mut c_void, *mut ACameraCaptureSession)>;
pub type ACameraCaptureSession_ready =
    Option<unsafe extern "C" fn(*mut c_void, *mut ACameraCaptureSession)>;
pub type ACameraCaptureSession_active =
    Option<unsafe extern "C" fn(*mut c_void, *mut ACameraCaptureSession)>;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ACameraCaptureSession_stateCallbacks {
    pub context: *mut c_void,
    pub onClosed: ACameraCaptureSession_closed,
    pub onReady: ACameraCaptureSession_ready,
    pub onActive: ACameraCaptureSession_active,
}

pub struct ACameraCaptureSession {
    callbacks: ACameraCaptureSession_stateCallbacks,
}

pub type ACameraDevice_disconnected =
    Option<unsafe extern "C" fn(*mut c_void, *mut ACameraDevice)>;
pub type ACameraDevice_error =
    Option<unsafe extern "C" fn(*mut c_void, *mut ACameraDevice, i32)>;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ACameraDevice_StateCallbacks {
    pub context: *mut c_void,
    pub onDisconnected: ACameraDevice_disconnected,
    pub onError: ACameraDevice_error,
}

#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct ACameraDevice_request_template(pub i32);

#[derive(Default)]
pub struct ANativeWindow { _private: u8 }

pub struct AImageReader {
    width: i32,
    height: i32,
    window: Box<ANativeWindow>,
    listener: Option<AImageReader_ImageListener>,
}

pub struct AImage {
    planes: [Vec<u8>; 3],
    row_strides: [i32; 3],
    pixel_strides: [i32; 3],
}

pub type AImageReader_ImageCallback =
    Option<unsafe extern "C" fn(*mut c_void, *mut AImageReader)>;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AImageReader_ImageListener {
    pub context: *mut c_void,
    pub onImageAvailable: AImageReader_ImageCallback,
}

pub struct AMediaCrypto;
pub struct AMediaFormat {
    codec_specific_data: Vec<u8>,
}

pub struct AMediaCodec {
    input: Vec<u8>,
    output: Vec<u8>,
    output_flags: u32,
    output_pending: bool,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AMediaCodecBufferInfo {
    pub offset: i32,
    pub size: i32,
    pub presentationTimeUs: i64,
    pub flags: u32,
}

#[derive(Default)]
pub struct AAudioStreamBuilder { _private: u8 }
pub struct AAudioStream {
    reads: usize,
}

unsafe fn boxed<T>(value: T) -> *mut T {
    Box::into_raw(Box::new(value))
}

unsafe fn delete_boxed<T>(value: *mut T) {
    if !value.is_null() {
        drop(unsafe { Box::from_raw(value) });
    }
}

pub unsafe fn ACameraManager_create() -> *mut ACameraManager {
    unsafe { boxed(ACameraManager::default()) }
}

pub unsafe fn ACameraManager_delete(manager: *mut ACameraManager) {
    unsafe { delete_boxed(manager) };
}

pub unsafe fn ACameraManager_getCameraIdList(
    _manager: *mut ACameraManager,
    out: *mut *mut ACameraIdList,
) -> camera_status_t {
    if out.is_null() {
        return camera_status_t(-1);
    }
    let ids = vec![CString::new("0").expect("static camera ID contains no NUL")];
    let mut pointers: Vec<_> = ids.iter().map(|id| id.as_ptr()).collect();
    let list = ACameraIdList {
        numCameras: pointers.len() as i32,
        cameraIds: pointers.as_mut_ptr(),
        ids,
        pointers,
    };
    unsafe { out.write(boxed(list)) };
    CAMERA_OK
}

pub unsafe fn ACameraManager_deleteCameraIdList(list: *mut ACameraIdList) {
    unsafe { delete_boxed(list) };
}

pub unsafe fn ACameraManager_getCameraCharacteristics(
    _manager: *mut ACameraManager,
    _camera_id: *const c_char,
    out: *mut *mut ACameraMetadata,
) -> camera_status_t {
    if out.is_null() {
        return camera_status_t(-1);
    }
    unsafe { out.write(boxed(ACameraMetadata::back_camera())) };
    CAMERA_OK
}

pub unsafe fn ACameraMetadata_free(metadata: *mut ACameraMetadata) {
    unsafe { delete_boxed(metadata) };
}

pub unsafe fn ACameraMetadata_getConstEntry(
    metadata: *const ACameraMetadata,
    tag: u32,
    out: *mut ACameraMetadata_const_entry,
) -> camera_status_t {
    let (Some(metadata), Some(out)) = (unsafe { metadata.as_ref() }, unsafe { out.as_mut() }) else {
        return camera_status_t(-1);
    };

    let (type_, count, data) = if tag == acamera_metadata_tag::ACAMERA_LENS_FACING.0 {
        (
            0,
            metadata.facing.len() as u32,
            ACameraMetadata_const_entry__bindgen_ty_1 { u8_: metadata.facing.as_ptr() },
        )
    } else if tag == acamera_metadata_tag::ACAMERA_SCALER_AVAILABLE_STREAM_CONFIGURATIONS.0 {
        (
            1,
            metadata.stream_configurations.len() as u32,
            ACameraMetadata_const_entry__bindgen_ty_1 {
                i32_: metadata.stream_configurations.as_ptr(),
            },
        )
    } else if tag == acamera_metadata_tag::ACAMERA_CONTROL_AE_AVAILABLE_TARGET_FPS_RANGES.0 {
        (
            1,
            metadata.frame_rates.len() as u32,
            ACameraMetadata_const_entry__bindgen_ty_1 { i32_: metadata.frame_rates.as_ptr() },
        )
    } else {
        return camera_status_t(-1);
    };

    *out = ACameraMetadata_const_entry { tag, type_, count, data };
    CAMERA_OK
}

pub unsafe fn ACameraManager_openCamera(
    _manager: *mut ACameraManager,
    _camera_id: *const c_char,
    _callbacks: *mut ACameraDevice_StateCallbacks,
    out: *mut *mut ACameraDevice,
) -> camera_status_t {
    if out.is_null() {
        return camera_status_t(-1);
    }
    unsafe { out.write(boxed(ACameraDevice::default())) };
    CAMERA_OK
}

pub unsafe fn ACameraDevice_close(device: *mut ACameraDevice) {
    unsafe { delete_boxed(device) };
}

macro_rules! simple_handle_create {
    ($function:ident, $handle:ty, ($($name:ident : $ty:ty),*), $out:ident) => {
        pub unsafe fn $function($($name: $ty,)* $out: *mut *mut $handle) -> camera_status_t {
            $(let _ = $name;)*
            if $out.is_null() {
                return camera_status_t(-1);
            }
            unsafe { $out.write(boxed(<$handle>::default())) };
            CAMERA_OK
        }
    };
}

macro_rules! simple_handle {
    ($name:ident) => {
        impl Default for $name {
            fn default() -> Self { Self { _private: 0 } }
        }
    };
}

simple_handle!(ACaptureRequest);
simple_handle!(ACaptureSessionOutputContainer);
simple_handle!(ACaptureSessionOutput);
simple_handle!(ACameraOutputTarget);

simple_handle_create!(ACaptureSessionOutputContainer_create, ACaptureSessionOutputContainer, (), out);
simple_handle_create!(ACaptureSessionOutput_create, ACaptureSessionOutput, (_window: *mut ANativeWindow), out);
simple_handle_create!(ACameraOutputTarget_create, ACameraOutputTarget, (_window: *mut ANativeWindow), out);

pub unsafe fn ACaptureSessionOutputContainer_add(
    _container: *mut ACaptureSessionOutputContainer,
    _output: *const ACaptureSessionOutput,
) -> camera_status_t {
    CAMERA_OK
}

pub unsafe fn ACameraDevice_createCaptureRequest(
    _device: *const ACameraDevice,
    _template: ACameraDevice_request_template,
    out: *mut *mut ACaptureRequest,
) -> camera_status_t {
    if out.is_null() { return camera_status_t(-1); }
    unsafe { out.write(boxed(ACaptureRequest::default())) };
    CAMERA_OK
}

pub unsafe fn ACaptureRequest_addTarget(
    _request: *mut ACaptureRequest,
    _target: *const ACameraOutputTarget,
) -> camera_status_t {
    CAMERA_OK
}

pub unsafe fn ACaptureRequest_setEntry_i32(
    _request: *mut ACaptureRequest,
    _tag: u32,
    _count: u32,
    _data: *const i32,
) -> camera_status_t {
    CAMERA_OK
}

pub unsafe fn ACameraDevice_createCaptureSession(
    _device: *mut ACameraDevice,
    _outputs: *const ACaptureSessionOutputContainer,
    callbacks: *const ACameraCaptureSession_stateCallbacks,
    out: *mut *mut ACameraCaptureSession,
) -> camera_status_t {
    if callbacks.is_null() || out.is_null() { return camera_status_t(-1); }
    let session = ACameraCaptureSession { callbacks: unsafe { *callbacks } };
    unsafe { out.write(boxed(session)) };
    CAMERA_OK
}

pub unsafe fn ACameraCaptureSession_setRepeatingRequest(
    _session: *mut ACameraCaptureSession,
    _callbacks: *mut c_void,
    _num_requests: i32,
    _requests: *mut *mut ACaptureRequest,
    _sequence_id: *mut i32,
) -> camera_status_t {
    CAMERA_OK
}

pub unsafe fn ACameraCaptureSession_stopRepeating(
    _session: *mut ACameraCaptureSession,
) -> camera_status_t { CAMERA_OK }

pub unsafe fn ACameraCaptureSession_abortCaptures(
    _session: *mut ACameraCaptureSession,
) -> camera_status_t { CAMERA_OK }

pub unsafe fn ACameraCaptureSession_close(session: *mut ACameraCaptureSession) {
    if let Some(session_ref) = unsafe { session.as_ref() } {
        if let Some(callback) = session_ref.callbacks.onClosed {
            unsafe { callback(session_ref.callbacks.context, session) };
        }
    }
    unsafe { delete_boxed(session) };
}

macro_rules! camera_delete {
    ($function:ident, $handle:ty) => {
        pub unsafe fn $function(value: *mut $handle) {
            unsafe { delete_boxed(value) };
        }
    };
}

camera_delete!(ACaptureRequest_free, ACaptureRequest);
camera_delete!(ACaptureSessionOutputContainer_free, ACaptureSessionOutputContainer);
camera_delete!(ACaptureSessionOutput_free, ACaptureSessionOutput);
camera_delete!(ACameraOutputTarget_free, ACameraOutputTarget);

pub unsafe fn AImageReader_new(
    width: i32,
    height: i32,
    _format: i32,
    _max_images: i32,
    out: *mut *mut AImageReader,
) -> media_status_t {
    if width <= 0 || height <= 0 || out.is_null() { return media_status_t(-1); }
    let reader = AImageReader {
        width,
        height,
        window: Box::new(ANativeWindow::default()),
        listener: None,
    };
    unsafe { out.write(boxed(reader)) };
    MEDIA_OK
}

pub unsafe fn AImageReader_setImageListener(
    reader: *mut AImageReader,
    listener: *mut AImageReader_ImageListener,
) -> media_status_t {
    let Some(reader) = (unsafe { reader.as_mut() }) else { return media_status_t(-1); };
    reader.listener = unsafe { listener.as_ref().copied() };
    MEDIA_OK
}

pub unsafe fn AImageReader_getWindow(
    reader: *mut AImageReader,
    out: *mut *mut ANativeWindow,
) -> media_status_t {
    let (Some(reader), Some(out)) = (unsafe { reader.as_mut() }, unsafe { out.as_mut() }) else {
        return media_status_t(-1);
    };
    *out = reader.window.as_mut();
    MEDIA_OK
}

pub unsafe fn AImageReader_delete(reader: *mut AImageReader) {
    unsafe { delete_boxed(reader) };
}

pub unsafe fn AImageReader_acquireLatestImage(
    reader: *mut AImageReader,
    out: *mut *mut AImage,
) -> media_status_t {
    let (Some(reader), Some(out)) = (unsafe { reader.as_ref() }, unsafe { out.as_mut() }) else {
        return media_status_t(-1);
    };
    let (Ok(width), Ok(height)) = (usize::try_from(reader.width), usize::try_from(reader.height)) else {
        return media_status_t(-1);
    };
    let (uv_width, uv_height) = (width / 2, height / 2);
    let image = AImage {
        planes: [
            vec![0; width.saturating_mul(height)],
            vec![0; uv_width.saturating_mul(uv_height)],
            vec![0; uv_width.saturating_mul(uv_height)],
        ],
        row_strides: [reader.width, reader.width / 2, reader.width / 2],
        pixel_strides: [1, 1, 1],
    };
    *out = unsafe { boxed(image) };
    MEDIA_OK
}

pub unsafe fn AImage_delete(image: *mut AImage) {
    unsafe { delete_boxed(image) };
}

pub unsafe fn AImage_getPlaneData(
    image: *const AImage,
    plane: i32,
    data: *mut *mut u8,
    len: *mut i32,
) -> media_status_t {
    let (Some(image), Ok(index), Some(data), Some(len)) = (
        unsafe { image.as_ref() }, usize::try_from(plane), unsafe { data.as_mut() }, unsafe { len.as_mut() },
    ) else { return media_status_t(-1); };
    let Some(buffer) = image.planes.get(index) else { return media_status_t(-1); };
    *data = buffer.as_ptr().cast_mut();
    *len = buffer.len() as i32;
    MEDIA_OK
}

pub unsafe fn AImage_getPlaneRowStride(
    image: *const AImage,
    plane: i32,
    out: *mut i32,
) -> media_status_t {
    let (Some(image), Ok(index), Some(out)) =
        (unsafe { image.as_ref() }, usize::try_from(plane), unsafe { out.as_mut() })
    else { return media_status_t(-1); };
    let Some(value) = image.row_strides.get(index) else { return media_status_t(-1); };
    *out = *value;
    MEDIA_OK
}

pub unsafe fn AImage_getPlanePixelStride(
    image: *const AImage,
    plane: i32,
    out: *mut i32,
) -> media_status_t {
    let (Some(image), Ok(index), Some(out)) =
        (unsafe { image.as_ref() }, usize::try_from(plane), unsafe { out.as_mut() })
    else { return media_status_t(-1); };
    let Some(value) = image.pixel_strides.get(index) else { return media_status_t(-1); };
    *out = *value;
    MEDIA_OK
}

pub unsafe fn AMediaFormat_new() -> *mut AMediaFormat {
    unsafe { boxed(AMediaFormat { codec_specific_data: Vec::new() }) }
}

pub unsafe fn AMediaFormat_delete(format: *mut AMediaFormat) -> media_status_t {
    unsafe { delete_boxed(format) };
    MEDIA_OK
}

#[allow(non_snake_case)]
pub unsafe fn AMediaCodec_setParameters(
    _codec: *mut AMediaCodec,
    _format: *mut AMediaFormat,
) -> media_status_t {
    MEDIA_OK
}

pub unsafe fn AMediaFormat_setString(
    _format: *mut AMediaFormat,
    _name: *const c_char,
    _value: *const c_char,
) {}

pub unsafe fn AMediaFormat_setInt32(
    _format: *mut AMediaFormat,
    _name: *const c_char,
    _value: i32,
) {}

pub unsafe fn AMediaFormat_getBuffer(
    format: *mut AMediaFormat,
    _name: *const c_char,
    data: *mut *mut c_void,
    size: *mut usize,
) -> bool {
    let (Some(format), Some(data), Some(size)) =
        (unsafe { format.as_mut() }, unsafe { data.as_mut() }, unsafe { size.as_mut() })
    else { return false; };
    if format.codec_specific_data.is_empty() { return false; }
    *data = format.codec_specific_data.as_mut_ptr().cast();
    *size = format.codec_specific_data.len();
    true
}

pub unsafe fn miri_set_format_buffer(format: *mut AMediaFormat, data: &[u8]) -> bool {
    let Some(format) = (unsafe { format.as_mut() }) else { return false; };
    format.codec_specific_data.clear();
    format.codec_specific_data.extend_from_slice(data);
    true
}

pub unsafe fn AMediaCodec_createEncoderByType(_mime: *const c_char) -> *mut AMediaCodec {
    unsafe {
        boxed(AMediaCodec {
            input: vec![0; 4096],
            output: Vec::new(),
            output_flags: 0,
            output_pending: false,
        })
    }
}

pub unsafe fn miri_set_codec_output(codec: *mut AMediaCodec, data: &[u8], flags: u32) -> bool {
    let Some(codec) = (unsafe { codec.as_mut() }) else { return false; };
    codec.output.clear();
    codec.output.extend_from_slice(data);
    codec.output_flags = flags;
    codec.output_pending = true;
    true
}

pub unsafe fn AMediaCodec_delete(codec: *mut AMediaCodec) -> media_status_t {
    unsafe { delete_boxed(codec) };
    MEDIA_OK
}

pub unsafe fn AMediaCodec_configure(
    _codec: *mut AMediaCodec,
    _format: *const AMediaFormat,
    _surface: *mut ANativeWindow,
    _crypto: *mut AMediaCrypto,
    _flags: u32,
) -> media_status_t { MEDIA_OK }

pub unsafe fn AMediaCodec_start(_codec: *mut AMediaCodec) -> media_status_t { MEDIA_OK }
pub unsafe fn AMediaCodec_stop(_codec: *mut AMediaCodec) -> media_status_t { MEDIA_OK }

pub unsafe fn AMediaCodec_createInputSurface(
    _codec: *mut AMediaCodec,
    out: *mut *mut ANativeWindow,
) -> media_status_t {
    if out.is_null() { return media_status_t(-1); }
    unsafe { out.write(boxed(ANativeWindow::default())) };
    MEDIA_OK
}

pub unsafe fn ANativeWindow_release(window: *mut ANativeWindow) {
    unsafe { delete_boxed(window) };
}

pub unsafe fn AMediaCodec_dequeueInputBuffer(
    _codec: *mut AMediaCodec,
    _timeout_us: i64,
) -> isize { 0 }

pub unsafe fn AMediaCodec_getInputBuffer(
    codec: *mut AMediaCodec,
    _index: usize,
    size: *mut usize,
) -> *mut u8 {
    let (Some(codec), Some(size)) = (unsafe { codec.as_mut() }, unsafe { size.as_mut() }) else {
        return ptr::null_mut();
    };
    *size = codec.input.len();
    codec.input.as_mut_ptr()
}

pub unsafe fn AMediaCodec_queueInputBuffer(
    _codec: *mut AMediaCodec,
    _index: usize,
    _offset: i64,
    _size: usize,
    _time: u64,
    _flags: u32,
) -> media_status_t { MEDIA_OK }

pub unsafe fn AMediaCodec_dequeueOutputBuffer(
    codec: *mut AMediaCodec,
    info: *mut AMediaCodecBufferInfo,
    _timeout_us: i64,
) -> isize {
    let (Some(codec), Some(info)) = (unsafe { codec.as_ref() }, unsafe { info.as_mut() }) else {
        return AMEDIACODEC_INFO_TRY_AGAIN_LATER as isize;
    };
    if !codec.output_pending {
        std::thread::yield_now();
        return AMEDIACODEC_INFO_TRY_AGAIN_LATER as isize;
    }
    *info = AMediaCodecBufferInfo {
        offset: 0,
        size: codec.output.len() as i32,
        presentationTimeUs: 0,
        flags: codec.output_flags,
    };
    0
}

pub unsafe fn AMediaCodec_getOutputBuffer(
    codec: *mut AMediaCodec,
    _index: usize,
    size: *mut usize,
) -> *mut u8 {
    let (Some(codec), Some(size)) = (unsafe { codec.as_mut() }, unsafe { size.as_mut() }) else {
        return ptr::null_mut();
    };
    *size = codec.output.len();
    codec.output.as_mut_ptr()
}

pub unsafe fn AMediaCodec_releaseOutputBuffer(
    codec: *mut AMediaCodec,
    _index: usize,
    _render: bool,
) -> media_status_t {
    if let Some(codec) = unsafe { codec.as_mut() } {
        codec.output_pending = false;
    }
    MEDIA_OK
}

pub unsafe fn AMediaCodec_getOutputFormat(_codec: *mut AMediaCodec) -> *mut AMediaFormat {
    unsafe { AMediaFormat_new() }
}

pub unsafe fn AAudio_createStreamBuilder(out: *mut *mut AAudioStreamBuilder) -> i32 {
    if out.is_null() { return -1; }
    unsafe { out.write(boxed(AAudioStreamBuilder::default())) };
    AAUDIO_OK
}

pub unsafe fn AAudioStreamBuilder_setDirection(_builder: *mut AAudioStreamBuilder, _value: i32) {}
pub unsafe fn AAudioStreamBuilder_setSampleRate(_builder: *mut AAudioStreamBuilder, _value: i32) {}
pub unsafe fn AAudioStreamBuilder_setChannelCount(_builder: *mut AAudioStreamBuilder, _value: i32) {}
pub unsafe fn AAudioStreamBuilder_setFormat(_builder: *mut AAudioStreamBuilder, _value: i32) {}
pub unsafe fn AAudioStreamBuilder_setPerformanceMode(_builder: *mut AAudioStreamBuilder, _value: i32) {}
pub unsafe fn AAudioStreamBuilder_setSharingMode(_builder: *mut AAudioStreamBuilder, _value: i32) {}

pub unsafe fn AAudioStreamBuilder_openStream(
    _builder: *mut AAudioStreamBuilder,
    out: *mut *mut AAudioStream,
) -> i32 {
    if out.is_null() { return -1; }
    unsafe { out.write(boxed(AAudioStream { reads: 0 })) };
    AAUDIO_OK
}

pub unsafe fn AAudioStreamBuilder_delete(builder: *mut AAudioStreamBuilder) -> i32 {
    unsafe { delete_boxed(builder) };
    AAUDIO_OK
}

pub unsafe fn AAudioStream_requestStart(_stream: *mut AAudioStream) -> i32 { AAUDIO_OK }
pub unsafe fn AAudioStream_requestStop(_stream: *mut AAudioStream) -> i32 { AAUDIO_OK }

pub unsafe fn AAudioStream_read(
    stream: *mut AAudioStream,
    buffer: *mut c_void,
    frames: i32,
    _timeout_ns: i64,
) -> i32 {
    let Some(stream) = (unsafe { stream.as_mut() }) else { return -1; };
    if buffer.is_null() || frames < 0 { return -1; }
    if stream.reads > 0 {
        return AAUDIO_ERROR_DISCONNECTED;
    }
    stream.reads += 1;
    // android_dual_stream.rs configures the stream as mono PCM i16. (const K_AUDIO_CHANNEL_COUNT: c_int = 1;)
    unsafe { ptr::write_bytes(buffer.cast::<i16>(), 0, frames as usize) };
    frames
}

pub unsafe fn AAudioStream_close(stream: *mut AAudioStream) -> i32 {
    unsafe { delete_boxed(stream) };
    AAUDIO_OK
}
