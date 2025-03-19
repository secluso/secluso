//! Code to implement custom motion detection for the Raspberry Pi camera
//! Assumes the cameras supports YUV420 codec
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

use fast_image_resize::images::Image;
use fast_image_resize::{PixelType, ResizeAlg, ResizeOptions, Resizer};
use ndarray::parallel::prelude::*;
use std::num::NonZero;
use std::{
    io,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, SystemTime},
};

use crate::raspberry_pi;
use crate::raspberry_pi::rpi_dual_stream::{RawFrame, SharedCameraStream};
use image::{GrayImage, ImageBuffer};
use imageproc::region_labelling::Connectivity;
use libblur::{
    BlurImage, BlurImageMut, ConvolutionMode, EdgeMode, FastBlurChannels, ThreadingPolicy,
};
use ndarray::{Array2, Zip};
use rayon::prelude::{ParallelSlice, ParallelSliceMut};

const ALPHA: f32 = 0.05; // Background update assuming updates every second. Adjusts based on motion FPS.

/// The three parameters below have been run through an optimization program on 5 hours worth of video to ensure accuracy. Changing them is not recommended.
const THRESHOLD: u8 = 10; // Motion detection threshold [Optimized]

const MINIMUM_TOTAL_CLUSTERED_POINTS: usize = 330; // The minimum sum of the points within all the clustered groups to be considered motion [Optimized]
const MINIMUM_INDIVIDUAL_CLUSTER_POINTS: usize = 210; // The minimum amount of points for a cluster to be considered not noise [Optimized]

// Frame dimensions (must match what is used in capture)
const WIDTH: usize = 1920; //TODO: for YUV420 to work properly with this code, this must be divisible by 64. Consider using padding for other resolution support in the future (if need be)
const HEIGHT: usize = 1080;

/// MotionDetection reads raw YUV420 frames from the shared camera stream and checks for motion.
pub struct MotionDetection {
    latest_frame: Arc<Mutex<Option<RawFrame>>>,
    motion: Option<BackgroundSubtractor>,
    last_detection: Option<SystemTime>,
    motion_fps: u64,
}

#[derive(Clone)]
pub struct BackgroundSubtractor {
    background: Array2<f32>,
}

impl BackgroundSubtractor {
    /// Initialize with the first frame
    pub fn new(initial_frame: &GrayImage) -> Self {
        let (width, height) = initial_frame.dimensions();
        let bg_vec: Vec<f32> = initial_frame.as_raw().iter().map(|&p| p as f32).collect();

        let bg = Array2::from_shape_vec((height as usize, width as usize), bg_vec)
            .expect("Failed to create ndarray from initial frame");

        BackgroundSubtractor { background: bg }
    }

    /// Update background model and detect motion
    /// Updated from IP motion detection to be parallelized for faster run time and high efficiency
    pub fn apply(&mut self, frame: &GrayImage, adjusted_alpha: f32) -> GrayImage {
        let (width, height) = frame.dimensions();

        // Convert GrayImage pixels to f32 and form a ndarray.
        let frame_vec: Vec<f32> = frame.as_raw().iter().map(|&p| p as f32).collect();
        let frame_array = Array2::from_shape_vec((height as usize, width as usize), frame_vec)
            .expect("Failed to create ndarray from frame");

        // Compute the difference in parallel using Zip:
        // diff = abs(frame_array - background)
        let mut diff = frame_array.clone();
        Zip::from(&mut diff)
            .and(&self.background)
            .par_for_each(|d, &bg| {
                *d = (*d - bg).abs();
            });

        // Update the background in parallel:
        Zip::from(&mut self.background)
            .and(&frame_array)
            .par_for_each(|bg, &fa| {
                *bg = fa * adjusted_alpha + *bg * (1.0 - adjusted_alpha);
            });

        // Create a binary mask in parallel.
        // For each element in diff, if > THRESHOLD, set to 255, otherwise 0.
        let mask = diff.mapv(|v| if v > THRESHOLD as f32 { 255 } else { 0 });
        let out_vec: Vec<u8> = mask.into_raw_vec();

        let result = GrayImage::from_raw(width, height, out_vec)
            .expect("Failed to create GrayImage from mask");
        result
    }
}

/** This method takes a YUV420 raw image and performs a parallel YUV420->RGB conversion,
   then computes a custom grayscale variant based on the standard deviation of the red, green and blue channels for the image.
   The standard grayscale formula is Gray = 0.299 * Red + 0.587 * Green + 0.114 * Blue.
   This can lose a lot of detail in blue-dominated infrared images considering how blue is only weighted at 11.4% in the usual formula.
   This aims to solve that issue through adaptive gray scaling, by calculating the optimal weights for each image
   Downsides: Extra computational expense to calculate adaptive weights, versus using pre-defined.

    Outside the YUV->RGB method being called (referenced from below), it runs at 15ms on average on a 1292x972 frame on a Raspberry Pi Zero 2W.
**/
fn adaptive_grayscale(raw_frame: &RawFrame, width: usize, height: usize) -> Option<GrayImage> {
    let expected_size = width * height * 3 / 2; // For 8-bit yuv420p, frame size = width * height * 3/2 bytes.

    let data = &raw_frame.data;
    if data.len() < expected_size as usize {
        return None;
    }

    // Split the raw data into Y, U, and V planes.
    let y_plane = &data[..width * height]; // The Y plane of YUV420 is the first W*H pixels
    let u_plane = &data[width * height..width * height + (width * height) / 4]; // The U plane is right after the Y plane, consisting of 1/4 W*H pixels.
    let v_plane = &data[width * height + (width * height) / 4..]; // The V plane is right after the U plane, consisting of 1/4 W*H pixels.

    // Perform a fast YUV -> RGB approximation
    let rgb_pixels = yuv_to_rgb(y_plane, u_plane, v_plane, width as usize, height as usize);
    let total_rgb_pixels = (width * height) as f32;

    // Compute the channel (R,G,B) sums and squared sums in parallel.
    let (sum_r, sum_g, sum_b, squared_sum_r, squared_sum_g, squared_sum_b) = rgb_pixels
        .par_chunks_exact(3)
        .map(|chunk| {
            let r = chunk[0] as f32;
            let g = chunk[1] as f32;
            let b = chunk[2] as f32;
            (r, g, b, r * r, g * g, b * b) // first 3 = sums, second 3 = sum of squares
        })
        .reduce(
            || (0.0, 0.0, 0.0, 0.0, 0.0, 0.0),
            |a, b| {
                (
                    a.0 + b.0,
                    a.1 + b.1,
                    a.2 + b.2,
                    a.3 + b.3,
                    a.4 + b.4,
                    a.5 + b.5,
                )
            },
        );

    // Calculate means for R, G, B
    let mean_r = sum_r / total_rgb_pixels;
    let mean_g = sum_g / total_rgb_pixels;
    let mean_b = sum_b / total_rgb_pixels;

    // Calculate STD of R, G, B using squared sums and means.
    let std_r = ((squared_sum_r / total_rgb_pixels) - (mean_r * mean_r)).sqrt();
    let std_g = ((squared_sum_g / total_rgb_pixels) - (mean_g * mean_g)).sqrt();
    let std_b = ((squared_sum_b / total_rgb_pixels) - (mean_b * mean_b)).sqrt();

    // Compute adaptive weights (STD of individual / (R_std + G_std + B_std))
    let total_std = std_r + std_g + std_b;
    let (w_r, w_g, w_b) = if total_std == 0.0 {
        (1.0 / 3.0, 1.0 / 3.0, 1.0 / 3.0)
    } else {
        (std_r / total_std, std_g / total_std, std_b / total_std)
    };

    // Precompute lookup tables for each channel (seems to save roughly 20% of CPU runtime)
    // Each table maps an 8-bit value to its weighted contribution.
    let mut lut_r = [0u8; 256];
    let mut lut_g = [0u8; 256];
    let mut lut_b = [0u8; 256];
    for i in 0..256 {
        // Multiply the channel value by its weight -> round it -> then clamp it.
        lut_r[i] = (w_r * i as f32).round().clamp(0.0, 255.0) as u8;
        lut_g[i] = (w_g * i as f32).round().clamp(0.0, 255.0) as u8;
        lut_b[i] = (w_b * i as f32).round().clamp(0.0, 255.0) as u8;
    }

    // Prepare the output grayscale buffer.
    let mut gray_pixels = vec![0u8; (width * height) as usize];

    // Compute the grayscale values in parallel.
    // Use the lookup table from earlier to perform these actions to save some CPU time
    gray_pixels
        .par_chunks_mut(1024) // Process in chunks to reduce scheduling overhead.
        .enumerate()
        .for_each(|(chunk_index, gray_chunk)| {
            let start = chunk_index * 1024;
            for (i, pixel) in gray_chunk.iter_mut().enumerate() {
                let idx = start + i;

                // Compute the index into rgb_pixels
                let base = idx * 3;
                let r = rgb_pixels[base] as usize;
                let g = rgb_pixels[base + 1] as usize;
                let b = rgb_pixels[base + 2] as usize;

                // Sum the weighted contributions from the lookup tables.
                let gray = lut_r[r] as u16 + lut_g[g] as u16 + lut_b[b] as u16;
                *pixel = gray.clamp(0, 255) as u8;
            }
        });

    return GrayImage::from_raw(width as u32, height as u32, gray_pixels);
}

/**
Tested with 1292x972 resized frames
This method approximates of YUV -> RGB, average runtime: 17ms on Raspberry Pi Zero 2W
Without approximation feature, runtime was 64ms for this method on average.
**/
fn yuv_to_rgb(
    y_plane: &[u8],
    u_plane: &[u8],
    v_plane: &[u8],
    width: usize,
    height: usize,
) -> Vec<u8> {
    // Allocate output buffer for RGB pixels.
    let mut rgb = vec![0u8; width * height * 3];

    // Split output buffer into rows.
    let mut rows: Vec<&mut [u8]> = rgb.chunks_mut(width * 3).collect();
    let block_width = width / 2;

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
                let y0_offset = by * 2 * width;
                let y1_offset = (by * 2 + 1) * width;

                // Process each 2x2 pixel block.
                for bx in 0..block_width {
                    let x0 = bx * 2;
                    let x1 = x0 + 1;
                    let uv_index = by * block_width + bx;

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
    rgb
}

impl MotionDetection {
    pub fn new(motion_fps: u64, shared_stream: Arc<SharedCameraStream>) -> io::Result<Self> {
        let latest_frame = Arc::new(Mutex::new(None));
        let latest_frame_clone = Arc::clone(&latest_frame);

        let raw_buffer = Arc::clone(&shared_stream.raw_buffer);

        thread::spawn(move || {
            println!("Starting raw motion detection background thread");
            loop {
                // Acquire the next frame from the raw buffer.
                let frame = raw_buffer.pop();
                {
                    let mut lock = latest_frame_clone.lock().unwrap();
                    *lock = Some(frame);
                }
            }
        });

        Ok(MotionDetection {
            latest_frame,
            motion: None,
            last_detection: None,
            motion_fps,
        })
    }

    pub fn downscale_with_fast_image_resize(
        src: &GrayImage,
        target_width: u32,
        target_height: u32,
    ) -> GrayImage {
        let src_width = src.width();
        let src_height = src.height();
        let src_data = src.to_vec();

        // Create a fast_image_resize Image from the GrayImage data.
        // Note: fast_image_resize appears to be about 30x faster than regular resize from Rust.

        let src_image = Image::from_vec_u8(src_width, src_height, src_data, PixelType::U8)
            .expect("Failed to create source image");

        // Create a target image with our desired width/height for later
        let mut dst_image = Image::new(target_width, target_height, PixelType::U8);
        let mut resizer = Resizer::new();

        resizer
            .resize(
                &src_image,
                &mut dst_image,
                &ResizeOptions::new().resize_alg(ResizeAlg::Nearest),
            )
            .expect("Resizing failed");
        GrayImage::from_raw(target_width, target_height, dst_image.buffer().to_vec())
            .expect("Failed to create GrayImage from resized data")
    }

    pub fn handle_motion_event(&mut self) -> io::Result<bool> {
        debug!("Called handle_motion_event");
        let binding = self.latest_frame.lock().unwrap();
        let raw_frame = match binding.as_ref() {
            Some(frame) => frame,
            None => {
                debug!("No frame received yet!");
                return Ok(false);
            }
        };

        // Compare latest frame against last timestamp to see if enough time has elapsed (considering motion_fps)
        let latest_time = raw_frame.timestamp;
        if let Some(last) = self.last_detection {
            let elapsed = latest_time.duration_since(last).unwrap_or_default();
            let frame_interval = Duration::from_millis(1000 / self.motion_fps);
            if elapsed < frame_interval {
                return Ok(false);
            }
        }

        debug!("Processing raw frame for motion detection");
        self.last_detection = Some(latest_time);

        // Convert the raw frame (YUV420) to grayscale via YUV420 -> RGB -> adaptive grayscale thresholding
        let grayscale_conversion_time = SystemTime::now();
        let grayscale = match adaptive_grayscale(raw_frame, WIDTH, HEIGHT) {
            Some(img) => img,
            None => {
                eprintln!("Failed to convert raw frame to grayscale");
                return Ok(false);
            }
        };

        debug!(
            "Elapsed Time for grayscale: {}ms",
            grayscale_conversion_time.elapsed().unwrap().as_millis()
        );

        // Downscale to 640x480 from 1920x1080 to reduce load on background subtractor & clustering (by a magnitude of ~10x for ~2x the cost)
        let (mut w, mut h) = grayscale.dimensions();
        let processed = if w > 640 && h > 480 {
            w = 640;
            h = 480;
            Self::downscale_with_fast_image_resize(&grayscale, w, h)
        } else {
            grayscale.clone()
        };

        let clahe_plus_blur = SystemTime::now();
        // Perform CLAHE (Contrast-Limited Adaptive Histogram Equalization)
        let clahe_processed_img =
            raspberry_pi::clahe::default_clahe(processed, w as usize, h as usize);

        let src = BlurImage::borrow(
            &mut ImageBuffer::as_raw(&clahe_processed_img),
            w,
            h,
            FastBlurChannels::Plane,
        );
        let mut dst = BlurImageMut::alloc(w, h, FastBlurChannels::Plane);

        // Perform Gaussian Blur operation
        // Roughly ~6ms/image on Raspberry Pi Zero 2W
        libblur::gaussian_blur(
            &src,
            &mut dst,
            5,
            0.0,
            EdgeMode::Reflect101,
            ThreadingPolicy::Fixed(NonZero::new(1).unwrap()),
            ConvolutionMode::Exact,
        )
        .unwrap();

        debug!(
            "CLAHE plus blur runtime: {}ms",
            clahe_plus_blur.elapsed().unwrap().as_millis()
        );

        // Ensure dst.data is properly converted to a Vec<u8> if needed
        let buffer_data = dst.data.borrow().to_vec();
        let blurred_image = GrayImage::from_raw(w, h, buffer_data).unwrap();

        // Initialize the background subtractor on the first frame.
        if self.motion.is_none() {
            self.motion = Some(BackgroundSubtractor::new(&blurred_image));
            return Ok(false);
        }

        // Apply background subtraction.
        let bg_subtract = SystemTime::now();
        let mut bgs = self.motion.clone().unwrap();
        let diff_result = bgs.apply(&blurred_image, ALPHA / self.motion_fps as f32);
        self.motion = Some(bgs);

        debug!(
            "Elapsed Time for background subtractor result: {}ms",
            bg_subtract.elapsed().unwrap().as_millis()
        );

        // Parallelize the check global points
        let total_points = diff_result
            .as_raw()
            .par_iter()
            .filter(|&&p| p == 255)
            .count();

        let w = blurred_image.width();
        let scale_factor: f64 = (w as f64 * h as f64) / (640.0 * 480.0);

        // Otherwise, run simple clustering algorithm to find concentrated changes
        // While this is about 15x faster than the DBSCAN clustering algorithm used in the other class, it's both less accurate and still presents extra compute time.
        if (total_points as f64) >= scale_factor * (MINIMUM_TOTAL_CLUSTERED_POINTS as f64) {
            let cluster_time = SystemTime::now();

            // Use connected component labeling with eight-way connectivity (such that, we consider any point in any direction for a given point)
            let labeled = imageproc::region_labelling::connected_components(
                &diff_result,
                Connectivity::Eight,
                image::Luma([0u8]), // These are the background pixels
            );

            // Collect the label from each pixel into a vector.
            let pixel_labels: Vec<u32> = labeled.pixels().map(|pixel| pixel.0[0]).collect();

            // Use Rayon to count the area (number of pixels) per label in parallel.
            let area_by_label: std::collections::HashMap<u32, usize> = pixel_labels
                .par_iter()
                .filter(|&&label| label != 0) // Skip background
                .fold(
                    || std::collections::HashMap::new(),
                    |mut acc, &label| {
                        *acc.entry(label).or_insert(0) += 1;
                        acc
                    },
                )
                .reduce(
                    || std::collections::HashMap::new(),
                    |mut map1, map2| {
                        for (label, count) in map2 {
                            *map1.entry(label).or_insert(0) += count;
                        }
                        map1
                    },
                );

            // Determine the minimum area threshold for an individual component.
            let min_area = (scale_factor * MINIMUM_INDIVIDUAL_CLUSTER_POINTS as f64) as usize;

            // Sum the area of all connected components that exceed the minimum area in parallel.
            let total_clustered_points: usize = area_by_label
                .par_iter()
                .filter(|&(_label, &area)| area >= min_area)
                .map(|(_label, &area)| area)
                .sum();

            debug!(
                "Elapsed Time for CCL: {}ms",
                cluster_time.elapsed().unwrap().as_millis()
            );
            if (total_clustered_points as f64)
                >= scale_factor * (MINIMUM_TOTAL_CLUSTERED_POINTS as f64)
            {
                self.motion = Some(BackgroundSubtractor::new(&blurred_image));
                debug!(
                    "Motion detected (CCL) with {} clustered points (of {} total).",
                    total_clustered_points, total_points
                );
                return Ok(true);
            } else {
                debug!(
                    "{} clustered points of {} total",
                    total_clustered_points, total_points
                )
            }
        }

        Ok(false)
    }
}
