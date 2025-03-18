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
use std::{
    io,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, SystemTime},
};

use crate::raspberry_pi::rpi_dual_stream::{RawFrame, SharedCameraStream};
use image::GrayImage;
use imageproc::region_labelling::Connectivity;
use ndarray::{Array2, Zip};

const ALPHA: f32 = 0.05; // Background update rate
const THRESHOLD: u8 = 70; // Motion detection threshold

const MINIMUM_TOTAL_CLUSTERED_POINTS: usize = 700; // The minimum sum of the points within all the clustered groups to be considered motion
const MINIMUM_INDIVIDUAL_CLUSTER_POINTS: usize = 400; // The minimum amount of points for a cluster to be considered not noise
const MINIMUM_GLOBAL_POINTS: usize = 2500; // The minimum amount of individual global points (could be noise) to be considered motion

// Frame dimensions (must match what is used in capture)
const WIDTH: u32 = 1920; //TODO: for YUV420 to work properly with this code, this must be divisible by 64. Consider using padding for other resolution support in the future (if need be)
const HEIGHT: u32 = 1080;

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
    pub fn apply(&mut self, frame: &GrayImage) -> GrayImage {
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
                *bg = fa * ALPHA + *bg * (1.0 - ALPHA);
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

/// MotionDetection reads raw YUV420 frames from the shared camera stream and checks for motion.
pub struct MotionDetection {
    latest_frame: Arc<Mutex<Option<RawFrame>>>,
    motion: Option<BackgroundSubtractor>,
    last_detection: Option<SystemTime>,
    motion_fps: u64,
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
                let frame = raw_buffer.acquire();
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

    /// Converts a raw YUV420 frame to a grayscale image by extracting the Y plane.
    /// The Y plane is the first width * height bytes (in 8 bit)
    fn raw_to_gray(raw: &RawFrame) -> Option<GrayImage> {
        let expected_size = WIDTH as usize * HEIGHT as usize;
        if raw.data.len() < expected_size {
            return None;
        }

        let y_plane = raw.data[..expected_size].to_vec();
        GrayImage::from_raw(WIDTH, HEIGHT, y_plane)
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

        // Convert the raw frame (YUV420) to grayscale.
        let gray = SystemTime::now();
        let grayscale = match Self::raw_to_gray(raw_frame) {
            Some(img) => img,
            None => {
                eprintln!("Failed to convert raw frame to grayscale");
                return Ok(false);
            }
        };
        debug!(
            "Elapsed Time for grayscale: {}ms",
            gray.elapsed().unwrap().as_millis()
        );

        // Downscale to 640x480 from 1920x1080 to reduce load on background subtractor & clustering (by a magnitude of ~10x for ~2x the cost)
        let resize = SystemTime::now();
        let (mut w, mut h) = grayscale.dimensions();
        let processed = if w > 640 && h > 480 {
            w = 640;
            h = 480;
            Self::downscale_with_fast_image_resize(&grayscale, w, h)
        } else {
            grayscale.clone()
        };

        debug!(
            "Elapsed Time for resize: {}ms",
            resize.elapsed().unwrap().as_millis()
        );

        // Initialize the background subtractor on the first frame.
        if self.motion.is_none() {
            self.motion = Some(BackgroundSubtractor::new(&processed));
            return Ok(false);
        }

        // Apply background subtraction.
        let bg_subtract = SystemTime::now();
        let mut bgs = self.motion.clone().unwrap();
        let diff_result = bgs.apply(&processed);
        self.motion = Some(bgs);

        debug!(
            "Elapsed Time for background subtractor result: {}ms",
            bg_subtract.elapsed().unwrap().as_millis()
        );

        // Parallelize the check global points
        let start_check_all = SystemTime::now();
        let w = processed.width() as usize;
        let data_points: Vec<(f64, f64)> = diff_result
            .as_raw()
            .par_iter()
            .enumerate()
            .filter_map(|(i, &p)| {
                if p == 255 {
                    // Compute row and column from the index.
                    let row = (i / w) as f64;
                    let col = (i % w) as f64;
                    Some((col, row))
                } else {
                    None
                }
            })
            .collect();

        debug!(
            "Elapsed Time for check global: {}ms",
            start_check_all.elapsed().unwrap().as_millis()
        );

        let total_points = data_points.len();
        let scale_factor: f64 = (w as f64 * h as f64) / (640.0 * 480.0);

        // We don't need to perform any clustering at all  if we have a massive amount of differing points (as noise isn't possible in this quantity)
        if (total_points as f64) >= scale_factor * (MINIMUM_GLOBAL_POINTS as f64) {
            self.motion = Some(BackgroundSubtractor::new(&processed));
            debug!(
                "Motion detected (GLOBAL) with {} points (threshold {:.2}).",
                total_points,
                scale_factor * MINIMUM_GLOBAL_POINTS as f64
            );
            return Ok(true);
        }

        // Otherwise, run simple clustering algorithm to find concentrated changes
        // While this is about 15x faster than the DBSCAN clustering algorithm used in the other class, it's both less accurate and still presents extra compute time.
        // Roughly ~453ms/run on average on a Raspberry Pi Zero 2W
        // Potential to try multi-threading in the future (consider doing own implementation)
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
                self.motion = Some(BackgroundSubtractor::new(&processed));
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
