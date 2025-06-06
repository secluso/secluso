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

use ndarray::parallel::prelude::*;
use std::{
    io,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use crate::raspberry_pi;
use crate::raspberry_pi::rpi_dual_stream::RawFrame;
use image::GrayImage;
use imageproc::region_labelling::Connectivity;

use crate::raspberry_pi::motion::background::BackgroundSubtractor;
use raspberry_pi::motion::preprocessing;

const ALPHA: f32 = 0.05; // Background update assuming updates every second. Adjusts based on motion FPS.
pub(crate) const WEIGHT_BLUE_THRESHOLD: f32 = 70.0; // The threshold we consider an image to be night vision based on the emphasis on blue in R, G, B.

/// The three parameters below have been run through an optimization program on 5 hours worth of video to ensure accuracy. Changing them is not recommended.
pub(crate) const DAY_THRESHOLD: u8 = 10; // Motion detection threshold [Optimized]
pub(crate) const NIGHT_THRESHOLD: u8 = 7; // Motion detection threshold [Optimized]
const MINIMUM_TOTAL_CLUSTERED_POINTS: usize = 330; // The minimum sum of the points within all the clustered groups to be considered motion [Optimized]
const MINIMUM_INDIVIDUAL_CLUSTER_POINTS: usize = 210; // The minimum amount of points for a cluster to be considered not noise [Optimized]

/// MotionDetection reads raw YUV420 frames from the shared camera stream and checks for motion.
pub struct MotionDetection {
    total_width: usize,
    total_height: usize,
    latest_frame: Arc<Mutex<Option<RawFrame>>>,
    motion: Option<BackgroundSubtractor>,
    last_detection: Option<SystemTime>,
    motion_fps: u64,
}

impl MotionDetection {
    pub fn new(
        latest_frame: Arc<Mutex<Option<RawFrame>>>,
        total_width: usize,
        total_height: usize,
        motion_fps: u64,
    ) -> io::Result<Self> {
        Ok(MotionDetection {
            latest_frame,
            total_width,
            total_height,
            motion: None,
            last_detection: None,
            motion_fps,
        })
    }

    // We run this method every time we want to check for motion.
    pub fn handle_motion_event(&mut self) -> Result<bool, anyhow::Error> {
        debug!("Called handle_motion_event");
        let raw_frame = {
            let binding = self.latest_frame.lock().unwrap();
            match binding.as_ref() {
                Some(frame) => frame.clone(),
                None => {
                    debug!("No frame received yet!");
                    return Ok(false);
                }
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

        // Preprocess the image.
        let (blurred_image, w_b) =
            preprocessing::preprocess(raw_frame.clone(), self.total_width, self.total_height)?;

        // Initialize the background subtractor on the first frame.
        if self.motion.is_none() {
            self.motion = Some(BackgroundSubtractor::new(&blurred_image));
            return Ok(false);
        }

        // Apply background subtraction.
        let bg_subtract = SystemTime::now();
        let mut bgs = self.motion.clone().unwrap();
        let diff_result = bgs.apply(
            &blurred_image,
            ALPHA / self.motion_fps as f32,
            w_b >= WEIGHT_BLUE_THRESHOLD,
        );
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

        // Scale depending on if we have an image below 640x480 (as the motion pixel # depends on the adjusted frame resolution)
        let w = blurred_image.width();
        let h = blurred_image.height();
        let scale_factor: f64 = (w as f64 * h as f64) / (640.0 * 480.0);

        // Run simple clustering algorithm to find concentrated changes
        // While this is about 15x faster than the DBSCAN clustering algorithm used in the other class, it's both less accurate and still presents extra compute time.
        if (total_points as f64) >= scale_factor * (MINIMUM_TOTAL_CLUSTERED_POINTS as f64) {
            let cluster_time = SystemTime::now();

            // Use connected component labeling with eight-way connectivity (such that, we consider any point in any direction for a given point)
            let total_clustered_points =
                Self::compute_connected_components(diff_result, scale_factor);

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

    fn compute_connected_components(diff_result: GrayImage, scale_factor: f64) -> usize {
        // Parallelize the check global points
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

        return total_clustered_points;
    }
}
