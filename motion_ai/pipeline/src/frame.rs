use crate::logic::pipeline::RunId;
use crate::ml::models::DetectionType;
use crate::ml::models::{BoxInfo, DetectionResult};
use image::{GrayImage, Rgb, RgbImage};
use imageproc::drawing::draw_hollow_rect_mut;
use imageproc::rect::Rect;
use rayon::iter::IndexedParallelIterator;
use rayon::iter::ParallelIterator;
use rayon::slice::ParallelSliceMut;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::SystemTime;
use log::{debug, warn};
use once_cell::sync::Lazy;
use flume::{Receiver, Sender};
use std::{fs, path::PathBuf, thread};


#[cfg(feature = "mp4_player")]
use yuv::{
    YuvChromaSubsampling, YuvConversionMode, YuvError, YuvPlanarImageMut, YuvRange,
    YuvStandardMatrix, rgb_to_yuv420,
};

pub static SAVE_IMAGES: AtomicBool = AtomicBool::new(true);

/// Stores raw frame data in both YUV and RGB formats along with metadata.
/// Used as the fundamental image unit across the inference and telemetry pipeline.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RawFrame {
    #[serde(with = "serde_bytes_arc")]
    pub yuv_data: Arc<Vec<u8>>, // We use Arc to prevent copying the bytes every time we need to clone this.
    #[serde(with = "serde_bytes_arc_option")]
    pub rgb_data: Option<Arc<Vec<u8>>>, // We use Arc to prevent copying the bytes every time we need to clone this.
    pub timestamp: SystemTime,
    pub width: usize,
    pub height: usize,
    pub detection_result: Option<DetectionResult>,
    pub dma_aligned: bool,
}

/// Internal module to serialize/deserialize Arc<Vec<u8>> fields used in RawFrame.
/// This avoids redundant copying and enables efficient serialization.
mod serde_bytes_arc {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_bytes::{ByteBuf, Bytes};
    use std::sync::Arc;

    pub fn serialize<S>(data: &Arc<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Bytes::new(data).serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Arc<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let byte_buf = ByteBuf::deserialize(deserializer)?;
        Ok(Arc::new(byte_buf.into_vec()))
    }
}

mod serde_bytes_arc_option {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_bytes::{ByteBuf, Bytes};
    use std::sync::Arc;

    pub fn serialize<S>(data: &Option<Arc<Vec<u8>>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match data {
            Some(arc_vec) => Bytes::new(arc_vec).serialize(serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Arc<Vec<u8>>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt_bytes = Option::<ByteBuf>::deserialize(deserializer)?;
        Ok(opt_bytes.map(|b| Arc::new(b.into_vec())))
    }
}

enum SaveJob {
    Rgb { img: image::RgbImage, path: PathBuf },
    Gray { img: image::GrayImage, path: PathBuf },
}

// BOUNDED queue to prevent unbounded memory growth under backpressure.
static TX: Lazy<Sender<SaveJob>> = Lazy::new(|| {
    let (tx, rx) = flume::bounded::<SaveJob>(256);
    thread::spawn(move || worker(rx));
    tx
});

fn worker(rx: Receiver<SaveJob>) {
    while let Ok(job) = rx.recv() {
        match job {
            SaveJob::Rgb { img, path } => {
                if let Some(parent) = path.parent() {
                    if let Err(e) = fs::create_dir_all(parent) {
                        warn!("create_dir_all({}): {}", parent.display(), e);
                        // still attempt save; will likely fail below
                    }
                }
                if let Err(e) = img.save(&path) {
                    warn!("image save failed {}: {}", path.display(), e);
                } else {
                    debug!("saved RGB {}", path.display());
                }
            }
            SaveJob::Gray { img, path } => {
                if let Some(parent) = path.parent() {
                    if let Err(e) = fs::create_dir_all(parent) {
                        warn!("create_dir_all({}): {}", parent.display(), e);
                    }
                }
                if let Err(e) = img.save(&path) {
                    warn!("gray save failed {}: {}", path.display(), e);
                } else {
                    debug!("saved GRAY {}", path.display());
                }
            }
        }
    }
}

// Non-blocking enqueue helpers; drop if queue is full (won’t stall hot path).
#[inline]
fn save_rgb_async(img: image::RgbImage, path: PathBuf) {
    if let Err(_e) = TX.try_send(SaveJob::Rgb { img, path }) {
        debug!("save queue full; dropped RGB save");
    }
}

#[inline]
fn save_gray_async_if_room(img: &image::GrayImage, path: PathBuf) {
    if !TX.is_full() {
        // one clone to transfer ownership to worker
        let _ = TX.try_send(SaveJob::Gray { img: img.clone(), path });
    } else {
        debug!("save queue full; dropped GRAY save");
    }
}


/// Core methods to manipulate, save, and convert raw image frames.
/// Includes support for saving annotated detections and converting YUV420p to RGB.
impl RawFrame {
    /// Saves the RGB buffer as a PNG file.
    /// If draw_bb is true and detection results exist, bounding boxes are rendered before saving.
    ///
    /// TODO: Allow resizing?
    pub fn save_png(
        &mut self,
        session_id: &str,
        run_id: &RunId,
        file_name: &str,
        draw_bb: bool,
    ) -> image::ImageResult<String> {
        if !SAVE_IMAGES.load(Ordering::Relaxed) {
            return Ok("".into());
        }

        if let None = self.rgb_data {
            self.yuv_to_rgb();
        }

        // Build RgbImage from raw RGB buffer
        let expected_len = self.width * self.height * 3;
        let buf = self
            .rgb_data
            .as_ref()
            .map(|v| v.as_slice())
            .ok_or_else(|| {
                image::ImageError::Parameter(image::error::ParameterError::from_kind(
                    image::error::ParameterErrorKind::Generic("Missing RGB buffer".into()),
                ))
            })?;

        if buf.len() != expected_len {
            return Err(image::ImageError::Parameter(
                image::error::ParameterError::from_kind(
                    image::error::ParameterErrorKind::DimensionMismatch,
                ),
            ));
        }

        // Length was checked above
        let mut img = RgbImage::from_raw(self.width as u32, self.height as u32, buf.to_vec())
            .ok_or_else(|| {
                image::ImageError::Parameter(image::error::ParameterError::from_kind(
                    image::error::ParameterErrorKind::DimensionMismatch,
                ))
            })?;

        // Resize to save space on SD card
        use image::imageops::FilterType;
        img = image::imageops::resize(&img, 416, 416, FilterType::CatmullRom);

        if draw_bb {
            if let Some(det) = &self.detection_result {
                img = self.draw_boxes(img, &det.results)
            }
        }

        // Encode as PNG under output/runs/<run>/frames
        let base = Path::new("output")
            .join("runs")
            .join(session_id)
            .join("frames");
        let path = base.join(format!("{}_{}.png", run_id.0, file_name));
        save_rgb_async(img, path.clone());

        Ok(path.to_string_lossy().into_owned())
    }

    /// Saves a grayscale image (e.g., background/motion masks) as a PNG under the run-specific path.
    pub fn save_gray_image(
        gray_image: &GrayImage,
        session_id: &str,
        run_id: &RunId,
        file_name: &str,
    ) -> image::ImageResult<String> {
        if !SAVE_IMAGES.load(Ordering::Relaxed) {
            return Ok("".into());
        }

        let base = Path::new("output")
            .join("runs")
            .join(session_id)
            .join("frames");

        let path = base.join(format!("{}_{}.png", run_id.0, file_name));
        save_gray_async_if_room(gray_image, path.clone());
        Ok(path.to_string_lossy().into_owned())
    }

    /// Maps a label ID to a color using a fixed color palette. Used for drawing bounding boxes.
    fn get_color_for_label(label: i32) -> [u8; 3] {
        let color_palette: [[u8; 3]; 5] = [
            [255, 0, 0],   // Red
            [0, 255, 0],   // Green
            [0, 0, 255],   // Blue
            [255, 255, 0], // Yellow
            [255, 0, 255], // Magenta
        ];

        color_palette[(label as usize) % color_palette.len()]
    }

    /// Draws bounding boxes onto an RGB image for detections that are not classified as 'Other'.
    fn draw_boxes(&self, mut img: RgbImage, boxes: &Vec<BoxInfo>) -> RgbImage {
        let len = boxes.len();
        debug!("Drawing {len} boxes");
        // TODO: Convert the labels to map into 1-6... e.g. we have 2 occurrences of 33, both should map to 1, then another occurrence of 34 which maps to 2. ordering not guaranteed
        for bbox in boxes {
            if bbox.det_type != DetectionType::Other {
                let color = Rgb(Self::get_color_for_label(bbox.label));

                let rect = Rect::at(bbox.x1 as i32, bbox.y1 as i32)
                    .of_size((bbox.x2 - bbox.x1) as u32, (bbox.y2 - bbox.y1) as u32);

                draw_hollow_rect_mut(&mut img, rect, color);
            }
        }

        img
    }

    /// Converts an RGB frame (from video_rs) into a RawFrame with internal YUV420 representation.
    /// Useful for testing or replay from RGB video input sources.
    #[cfg(feature = "mp4_player")]
    pub fn create_from_rgb(frame: video_rs::frame::Frame) -> Result<RawFrame, YuvError> {
        let actual_height = frame.shape()[0];
        let actual_width = frame.shape()[1];

        let mut planar_image = YuvPlanarImageMut::<u8>::alloc(
            actual_width as u32,
            actual_height as u32,
            YuvChromaSubsampling::Yuv420,
        );

        let slice = frame.as_slice().ok_or(YuvError::PointerOverflow)?;

        rgb_to_yuv420(
            &mut planar_image,
            slice,
            (actual_width * 3) as u32,
            YuvRange::Limited,
            YuvStandardMatrix::Bt601,
            YuvConversionMode::Balanced,
        )?;

        // Get the slices for Y, U, V planes
        let y_plane = planar_image.y_plane.borrow();
        let u_plane = planar_image.u_plane.borrow();
        let v_plane = planar_image.v_plane.borrow();

        let mut data = Vec::with_capacity(y_plane.len() + u_plane.len() + v_plane.len());

        data.extend_from_slice(y_plane);
        data.extend_from_slice(u_plane);
        data.extend_from_slice(v_plane);

        Ok(RawFrame {
            yuv_data: Arc::new(data),
            rgb_data: Some(Arc::new(slice.to_vec())),
            timestamp: SystemTime::now(),
            width: actual_width,
            height: actual_height,
            detection_result: None,
            dma_aligned: false,
        })
    }

    pub fn create_from_buffer(buffer: Vec<u8>, actual_width: usize, actual_height: usize) -> RawFrame {
        RawFrame {
            yuv_data: Arc::new(buffer),
            rgb_data: None,
            timestamp: SystemTime::now(),
            width: actual_width,
            height: actual_height,
            detection_result: None,
            dma_aligned: true,
        }
    }


    /**
    Tested with 1292x972 resized frames
    This method approximates of YUV -> RGB, average runtime: 17ms on Raspberry Pi Zero 2W
    Without approximation feature, runtime was 64ms for this method on average.
     **/    pub(crate) fn yuv_to_rgb(&mut self) {
        // For 8-bit yuv420p, frame size = width * height * 3/2 bytes.
        // However, we need to take into account how the width is padded to 64-bytes.
        // This is for a row-aligned format from V4L2 for DMA transfer alignment.
        let yuv_width = if self.dma_aligned {
            (self.width + 63) / 64 * 64
        } else {
            self.width
        };

        let yuv_height = self.height;
        let yuv_size = yuv_width * yuv_height * 3 / 2;

        let data = &self.yuv_data;
        if data.len() != yuv_size {
            panic!(
                "Raw data did not match expected YUV size for the camera resolution ({} versus {}).",
                data.len(),
                yuv_size
            );
        }

        // Split the raw data into Y, U, and V planes.
        let y_plane = &data[..yuv_width * yuv_height]; // The Y plane of YUV420 is the first W*H pixels
        let u_plane =
            &data[yuv_width * yuv_height..yuv_width * yuv_height + (yuv_width * yuv_height) / 4]; // The U plane is right after the Y plane, consisting of 1/4 W*H pixels.
        let v_plane = &data[yuv_width * yuv_height + (yuv_width * yuv_height) / 4..]; // The V plane is right after the U plane, consisting of 1/4 W*H pixels.

        // Allocate output buffer for RGB pixels.
        let mut rgb = vec![0u8; self.width * self.height * 3];

        // Split output buffer into rows.
        let mut rows: Vec<&mut [u8]> = rgb.chunks_mut(self.width * 3).collect();
        let block_width = self.width / 2;
        let uv_stride = yuv_width / 2;

        // Process rows in pairs in parallel.
        rows.as_mut_slice()
            .par_chunks_mut(2)
            .enumerate()
            .for_each(|(by, rows_pair)| {
                if rows_pair.len() == 2 {
                    // Safely obtain mutable references to the two rows.
                    let (row0, row1) = {
                        let (r0, r1) = rows_pair.split_at_mut(1);
                        (&mut r0[0], &mut r1[0])
                    };

                    // Calculate starting indices in the Y plane for the two rows.
                    let y0_offset = by * 2 * yuv_width;
                    let y1_offset = (by * 2 + 1) * yuv_width;

                    // Process each 2x2 pixel block.
                    for bx in 0..block_width {
                        let x0 = bx * 2;
                        let x1 = x0 + 1;
                        let uv_index = by * uv_stride + bx;

                        // Convert U, V to signed values.
                        let u = u_plane[uv_index] as i32 - 128;
                        let v = v_plane[uv_index] as i32 - 128;

                        // Use fixed-point arithmetic with scaling factor 256.
                        // Use pre-computed approximation multipliers for CPU speedup
                        //   1.402  -> 359   (1.402 * 256 ≈ 359)
                        //   0.3441 -> 88    (0.3441 * 256 ≈ 88)
                        //   0.7141 -> 183   (0.7141 * 256 ≈ 183)
                        //   1.772  -> 453   (1.772 * 256 ≈ 453)

                        let r_off = (359 * v) >> 8;
                        let g_off = (88 * u + 183 * v) >> 8;
                        let b_off = (453 * u) >> 8;

                        // Proceed to process the four pixels in the 2x2 block
                        // Row 0, pixel at x0.
                        let y_val = y_plane[y0_offset + x0] as i32;
                        let r = (y_val + r_off).clamp(0, 255) as u8;
                        let g = (y_val - g_off).clamp(0, 255) as u8;
                        let b = (y_val + b_off).clamp(0, 255) as u8;
                        let out_offset = x0 * 3;
                        row0[out_offset] = r;
                        row0[out_offset + 1] = g;
                        row0[out_offset + 2] = b;

                        // Row 0, pixel at x1.
                        let y_val = y_plane[y0_offset + x1] as i32;
                        let r = (y_val + r_off).clamp(0, 255) as u8;
                        let g = (y_val - g_off).clamp(0, 255) as u8;
                        let b = (y_val + b_off).clamp(0, 255) as u8;
                        let out_offset = x1 * 3;
                        row0[out_offset] = r;
                        row0[out_offset + 1] = g;
                        row0[out_offset + 2] = b;

                        // Row 1, pixel at x0.
                        let y_val = y_plane[y1_offset + x0] as i32;
                        let r = (y_val + r_off).clamp(0, 255) as u8;
                        let g = (y_val - g_off).clamp(0, 255) as u8;
                        let b = (y_val + b_off).clamp(0, 255) as u8;
                        let out_offset = x0 * 3;
                        row1[out_offset] = r;
                        row1[out_offset + 1] = g;
                        row1[out_offset + 2] = b;

                        // Row 1, pixel at x1.
                        let y_val = y_plane[y1_offset + x1] as i32;
                        let r = (y_val + r_off).clamp(0, 255) as u8;
                        let g = (y_val - g_off).clamp(0, 255) as u8;
                        let b = (y_val + b_off).clamp(0, 255) as u8;
                        let out_offset = x1 * 3;
                        row1[out_offset] = r;
                        row1[out_offset + 1] = g;
                        row1[out_offset + 2] = b;
                    }
                }
            });

        self.rgb_data = Some(Arc::new(rgb));
    }
}
