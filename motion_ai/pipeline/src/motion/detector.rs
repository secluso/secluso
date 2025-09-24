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

use anyhow::anyhow;
use rayon::iter::ParallelIterator;
use std::collections::HashSet;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use image::{GrayImage, Luma};
use imageproc::region_labelling::Connectivity;
use log::{debug, warn};
use rayon::iter::IntoParallelRefIterator;

use crate::frame::RawFrame;
use crate::logic::pipeline::RunId;
use crate::logic::telemetry::{TelemetryPacket, TelemetryRun};
use crate::motion::background::BackgroundSubtractor;
use crate::motion::preprocessing;

const ALPHA: f32 = 0.05; // Background update assuming updates every second. Adjusts based on motion FPS.
pub(crate) const WEIGHT_BLUE_THRESHOLD: f32 = 70.0; // The threshold we consider an image to be night vision based on the emphasis on blue in R, G, B.

/// The three parameters below have been run through an optimization program on 5 hours worth of video to ensure accuracy. Changing them is not recommended.
pub(crate) const DAY_THRESHOLD: u8 = 10; // Motion detection threshold [Optimized]
pub(crate) const NIGHT_THRESHOLD: u8 = 7; // Motion detection threshold [Optimized]
const MINIMUM_TOTAL_CLUSTERED_POINTS: usize = 330; // The minimum sum of the points within all the clustered groups to be considered motion [Optimized]
const MINIMUM_INDIVIDUAL_CLUSTER_POINTS: usize = 210; // The minimum amount of points for a cluster to be considered not noise [Optimized]

/// MotionDetection reads raw YUV420 frames from the shared camera stream and checks for motion.
pub struct MotionDetection {
    motion: Option<BackgroundSubtractor>,
}

impl MotionDetection {
    pub fn new() -> Self {
        MotionDetection { motion: None }
    }

    // We run this method every time we want to check for motion.
    pub fn start(
        &mut self,
        raw_frame: &RawFrame,
        telemetry: &mut TelemetryRun,
        run_id: &RunId,
        alpha_ratio: f32,
    ) -> Result<bool, anyhow::Error> {
        debug!("Processing raw frame for motion detection");

        // Preprocess the image.
        let (blurred_image, w_b) = preprocessing::preprocess(
            raw_frame.clone(),
            telemetry,
            run_id,
            raw_frame.width,
            raw_frame.height,
        )?;

        let threshold_used: u32 = if w_b >= WEIGHT_BLUE_THRESHOLD {
            NIGHT_THRESHOLD as u32
        } else {
            DAY_THRESHOLD as u32
        };

        // Initialize the background subtractor on the first frame.
        if self.motion.is_none() {
            self.motion = Some(BackgroundSubtractor::new(&blurred_image));
            return Ok(false);
        }

        // Apply background subtraction.
        let bg_subtract = SystemTime::now();
        let mut bgs = match self.motion.as_ref() {
            Some(motion) => motion.clone(),
            None => return Err(anyhow!("Background subtractor not initialized")),
        };

        bgs.save_backed_image(telemetry.run_id.as_str(), run_id)?; // Save the backing of the bg first
        let diff_result = bgs.apply(
            &blurred_image,
            ALPHA / alpha_ratio,
            w_b >= WEIGHT_BLUE_THRESHOLD,
        );
        RawFrame::save_gray_image(&diff_result, telemetry.run_id.as_str(), run_id, "bg_result")?; // Now save the mask comparison

        self.motion = Some(bgs);

        let ms = bg_subtract.elapsed().unwrap_or_default().as_millis();
        let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
        telemetry.write(&TelemetryPacket::StageDuration {
            ts,
            run_id: run_id.clone(),
            stage_name: "bg_apply",
            stage_kind: "motion",
            duration_ms: ms,
        })?;
        debug!(
            "Elapsed Time for background subtractor result: {}",
            match bg_subtract.elapsed() {
                Ok(duration) => format!("{}ms", duration.as_millis()),
                Err(e) => {
                    warn!("SystemTime error in timing background subtractor: {:?}", e);
                    "error".into()
                }
            }
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
            let (total_clustered_points, denoised) =
                Self::compute_connected_components(diff_result, scale_factor);

            RawFrame::save_gray_image(
                &denoised,
                telemetry.run_id.as_str(),
                run_id,
                "detected_without_noise",
            )?; // Now save the mask comparison

            debug!(
                "Elapsed Time for CCL: {}ms",
                match cluster_time.elapsed() {
                    Ok(duration) => format!("{}ms", duration.as_millis()),
                    Err(e) => {
                        warn!("SystemTime error in timing background subtractor: {:?}", e);
                        "error".into()
                    }
                }
            );

            let ms = cluster_time.elapsed().unwrap_or_default().as_millis();
            let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
            telemetry.write(&TelemetryPacket::StageDuration {
                ts,
                run_id: run_id.clone(),
                stage_name: "connected_components",
                stage_kind: "motion",
                duration_ms: ms,
            })?;
            if (total_clustered_points as f64)
                >= scale_factor * (MINIMUM_TOTAL_CLUSTERED_POINTS as f64)
            {
                self.motion = Some(BackgroundSubtractor::new(&blurred_image));
                debug!(
                    "Motion detected (CCL) with {} clustered points (of {} total).",
                    total_clustered_points, total_points
                );

                let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
                telemetry.write(&TelemetryPacket::MotionMetrics {
                    run_id: run_id.clone(),
                    w_b,
                    total_points: total_points as u32,
                    clustered_points: total_clustered_points as u32,
                    threshold: threshold_used,
                    ts,
                })?;
                return Ok(true);
            } else {
                debug!(
                    "{} clustered points of {} total",
                    total_clustered_points, total_points
                )
            }
        }

        let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
        telemetry.write(&TelemetryPacket::MotionMetrics {
            run_id: run_id.clone(),
            w_b,
            total_points: total_points as u32,
            clustered_points: 0,
            threshold: threshold_used,
            ts,
        })?;

        Ok(false)
    }

    fn compute_connected_components(
        diff_result: GrayImage,
        scale_factor: f64,
    ) -> (usize, GrayImage) {
        // Parallelize the check global points
        // Use connected component labeling with eight-way connectivity (such that, we consider any point in any direction for a given point)
        let labeled = imageproc::region_labelling::connected_components(
            &diff_result,
            Connectivity::Eight,
            Luma([0u8]), // These are the background pixels
        );

        // Collect the label from each pixel into a vector.
        let pixel_labels: Vec<u32> = labeled.pixels().map(|pixel| pixel.0[0]).collect();

        // Use Rayon to count the area (number of pixels) per label in parallel.
        let area_by_label: std::collections::HashMap<u32, usize> = pixel_labels
            .par_iter()
            .filter(|&&label| label != 0) // Skip background
            .fold(std::collections::HashMap::new, |mut acc, &label| {
                *acc.entry(label).or_insert(0) += 1;
                acc
            })
            .reduce(std::collections::HashMap::new, |mut map1, map2| {
                for (label, count) in map2 {
                    *map1.entry(label).or_insert(0) += count;
                }
                map1
            });

        // Determine the minimum area threshold for an individual component.
        let min_area = (scale_factor * MINIMUM_INDIVIDUAL_CLUSTER_POINTS as f64) as usize;

        let accepted_labels: HashSet<u32> = area_by_label
            .par_iter()
            .filter(|&(_, &area)| area >= min_area)
            .map(|(&label, _)| label)
            .collect();

        // Sum the area of all connected components that exceed the minimum area in parallel.
        let count = accepted_labels
            .par_iter()
            .map(|label| area_by_label[label])
            .sum();

        // Reconstruct the mask without noised areas
        let mut denoised = GrayImage::new(diff_result.width(), diff_result.height());
        for (x, y, pixel) in labeled.enumerate_pixels() {
            let label = pixel.0[0];
            let out_val = if accepted_labels.contains(&label) {
                255
            } else {
                0
            };
            denoised.put_pixel(x, y, Luma([out_val]))
        }

        (count, denoised)
    }
}
