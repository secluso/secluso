//! Code to implement custom motion detection for the IP camera(s)
//! Assumes the cameras supports MJPEG codec
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

use image::{imageops, GenericImageView, GrayImage, ImageReader};
use linfa::dataset::Labels;
use linfa::prelude::Transformer;
use linfa::Dataset;
use linfa_clustering::AppxDbscan;
use ndarray::{Array, Array2, Ix1, OwnedRepr};
use reqwest::blocking::{Client, Response};
use reqwest::header::{HeaderValue, CONTENT_TYPE};
use std::io::{BufRead, BufReader, Read};
use std::ops::Div;
use std::process::exit;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use std::{io, thread};

const ALPHA: f32 = 0.05; // Background update rate
const THRESHOLD: u8 = 70; // Motion detection threshold

const DBSCAN_TOLERANCE: f64 = 20.; // The minimum distance from a given point to a nearby point for it to be considered part of a cluster
const MINIMUM_TOTAL_CLUSTERED_POINTS: usize = 700; // The minimum sum of the points within all the clustered groups to be considered motion
const MINIMUM_INDIVIDUAL_CLUSTER_POINTS: usize = 400; // The minimum amount of points for a cluster to be considered not noise
const MINIMUM_GLOBAL_POINTS: usize = 2500; // The minimum amount of individual global points (could be noise) to be considered motion

pub struct MotionDetection {
    latest_frame: Arc<Mutex<Option<MPEGFrame>>>,
    motion: Option<BackgroundSubtractor>,
    last_detection: Option<SystemTime>, // This is meant for checking the last frame we ran motion detection on against the current frame timestamp.
    motion_fps: u64,
}

pub(crate) struct MPEGFrame {
    frame: Vec<u8>,
    timestamp: SystemTime,
}

#[derive(Clone)]
pub(crate) struct BackgroundSubtractor {
    background: Array2<f32>,
}

impl BackgroundSubtractor {
    /// Initialize with the first frame
    pub(crate) fn new(initial_frame: &GrayImage) -> Self {
        let (width, height) = initial_frame.dimensions();

        // Directly convert the GrayImage buffer to a ndarray
        let bg_vec: Vec<f32> = initial_frame.as_raw().iter().map(|&p| p as f32).collect();

        let bg = Array2::from_shape_vec((height as usize, width as usize), bg_vec)
            .expect("Failed to create ndarray from initial frame");

        BackgroundSubtractor { background: bg }
    }

    /// Update background model and detect motion
    pub(crate) fn apply(&mut self, frame: &GrayImage) -> GrayImage {
        let (width, height) = frame.dimensions();

        // Convert GrayImage to ndarray efficiently
        let frame_vec: Vec<f32> = frame.as_raw().iter().map(|&p| p as f32).collect();
        let frame_array = Array2::from_shape_vec((height as usize, width as usize), frame_vec)
            .expect("Failed to create ndarray from frame");

        // Compute absolute difference
        let diff = (&frame_array - &self.background).mapv(f32::abs);

        // Update background model using an exponential moving average
        self.background = (&frame_array * ALPHA) + (&self.background * (1.0 - ALPHA));

        // Threshold the difference array to create the motion mask
        let mask = diff.mapv(|v| if v > THRESHOLD as f32 { 255u8 } else { 0u8 });

        // Convert ndarray to GrayImage using direct byte copy
        let output_vec: Vec<u8> = mask.into_raw_vec();
        GrayImage::from_raw(width, height, output_vec)
            .expect("Failed to create GrayImage from ndarray")
    }
}

impl MotionDetection {
    pub fn new(
        ip: String,
        username: String,
        password: String,
        motion_fps: u64,
    ) -> io::Result<Self> {
        let latest_frame: Arc<Mutex<Option<MPEGFrame>>> = Arc::new(Mutex::new(None));
        let latest_frame_clone = Arc::clone(&latest_frame);

        thread::spawn(move || {
            debug!("Starting MJPEG motion detection background thread");
            Self::process_mjpeg_stream(&latest_frame_clone, ip, username, password);
        });

        Ok(Self {
            latest_frame,
            motion: None,
            last_detection: None,
            motion_fps,
        })
    }

    /// Reads the multipart/x-mixed-replace stream, printing debug info for each line,
    /// and attempts to parse `Content-Length` to read JPEG frames.
    fn process_mjpeg_stream(
        latest_frame: &Arc<Mutex<Option<MPEGFrame>>>,
        ip: String,
        username: String,
        password: String,
    ) {
        let url = format!("http://{}/cgi-bin/mjpg/video.cgi?subtype=1", ip);
        let url_req = reqwest::Url::try_from(url.as_str()).unwrap();

        // We make an initial request to get the Digest Auth challenge
        let client = Client::new();
        let response = client.get(url_req.clone()).send().expect("");

        if response.status() != 401 {
            println!(
                "Unexpected status from camera MJPEG attempt: {}",
                response.status()
            );
            exit(1);
        }

        // Extract Digest parameters from WWW-Authenticate header returned
        let www_authenticate = response
            .headers()
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        let mut pw_client = http_auth::PasswordClient::try_from(www_authenticate)
            .expect("Unable to instantiate PasswordClient from www_authenticate for MJPEG stream");
        let authorization = pw_client
            .respond(&http_auth::PasswordParams {
                username: username.as_str(),
                password: password.as_str(),
                uri: url_req.path(),
                method: reqwest::Method::GET.as_str(),
                body: Some(&[]),
            })
            .unwrap();
        debug!("MJPG Authorization: {}", &authorization);
        let mut authorization = HeaderValue::try_from(authorization).unwrap();
        authorization.set_sensitive(true);

        // Make the authenticated request with Digest Auth
        let response = client
            .get(url_req)
            .header(reqwest::header::AUTHORIZATION, authorization)
            .send()
            .expect("");

        if !response.status().is_success() {
            println!(
                "Failed to authenticate to camera MJPEG: HTTP {}",
                response.status()
            );
            exit(1);
        }

        // Detect boundary from Content-Type
        let boundary =
            Self::get_mjpeg_boundary(&response).unwrap_or_else(|| "--myboundary".to_string()); // fallback is "myboundary", seems to be the default in Amcrest cameras
        debug!("Using boundary: {}", boundary);

        let mut reader = BufReader::new(response);
        loop {
            // Read lines until we see one that starts with --<boundary> or we reach EOF
            let maybe_line =
                Self::read_ascii_line(&mut reader).expect("Error reading line from camera stream.");

            if maybe_line.is_none() {
                debug!("EOF reached... exiting MJPEG loop.");
                break;
            }

            let line = maybe_line.unwrap();

            let trimmed = line.trim();
            if trimmed.starts_with(&boundary) {
                // Found the start of a part
                let mut content_length: Option<usize> = None;

                // Now read headers until blank line
                loop {
                    let hdr_line =
                        Self::read_ascii_line(&mut reader).expect("Failed to read header line.");

                    if hdr_line.is_none() {
                        return;
                    }

                    let hdr_line = hdr_line.unwrap();
                    let hdr_trimmed = hdr_line.trim();

                    if hdr_trimmed.is_empty() {
                        // blank line means next is the JPEG bytes
                        break;
                    }

                    if let Some(cl) = hdr_trimmed.strip_prefix("Content-Length:") {
                        let len_str = cl.trim();
                        let len = len_str
                            .parse::<usize>()
                            .expect("Content-Length not a valid integer.");
                        content_length = Some(len);
                    }
                }

                // If we got a content length, then we can read exactly that many bytes for JPEG
                if let Some(len) = content_length {
                    let mut frame_data = vec![0u8; len];
                    reader
                        .read_exact(&mut frame_data)
                        .expect("Failed reading JPEG data from stream.");

                    // Acquire the mutex and replace the latest frame.
                    let mut binding = latest_frame.lock().unwrap();
                    *binding = Some(MPEGFrame {
                        frame: frame_data,
                        timestamp: SystemTime::now(),
                    });
                } else {
                    debug!("No Content-Length header found for this part");
                }
            }
        }
    }

    /// Attempts to extract boundary from Content-Type: multipart/x-mixed-replace; boundary=...
    fn get_mjpeg_boundary(resp: &Response) -> Option<String> {
        if let Some(ct_val) = resp.headers().get(CONTENT_TYPE) {
            let ct_str = ct_val.to_str().ok()?;
            if let Some(idx) = ct_str.to_lowercase().find("boundary=") {
                let after = &ct_str[idx + "boundary=".len()..];
                // Trim semicolons/spaces/quotes
                let boundary_str =
                    after.trim_matches(|c: char| c.is_whitespace() || c == ';' || c == '"');
                if !boundary_str.is_empty() {
                    // Ensure the boundary lines in the stream are prefixed with "--",
                    if !boundary_str.starts_with("--") {
                        return Some(format!("--{}", boundary_str));
                    }
                    return Some(boundary_str.to_string());
                }
            }
        }
        None
    }

    /// Reads a line (ends with b'\n'), returns None if EOF without data.
    fn read_ascii_line<R: BufRead>(reader: &mut R) -> std::io::Result<Option<String>> {
        let mut buffer = Vec::new();
        let bytes_read = reader
            .read_until(b'\n', &mut buffer)
            .expect("read_until failed.");

        if bytes_read == 0 {
            // We reached EOF
            return Ok(None);
        }

        // Strip trailing newline and/or carriage return
        while buffer.ends_with(&[b'\n']) || buffer.ends_with(&[b'\r']) {
            buffer.pop();
        }

        // Convert to String (lossy), so invalid UTF-8 won't cause errors
        let line_str = String::from_utf8_lossy(&buffer).to_string();
        Ok(Some(line_str))
    }

    pub fn handle_motion_event(&mut self) -> io::Result<bool> {
        let binding = self.latest_frame.lock().unwrap();
        if let Some(latest_frame) = binding.as_ref() {
            let latest_video_time = latest_frame.timestamp;
            let latest_video = latest_frame.frame.clone();

            // Ensure that either no detection has occurred before, or that this isn't the same frame as last time.
            if self.last_detection.is_none()
                || self
                    .last_detection
                    .map(|last_time| {
                        latest_video_time
                            .duration_since(last_time)
                            .map(|d| d >= Duration::from_millis(1000.div(self.motion_fps)))
                            .unwrap_or(false)
                    })
                    .unwrap_or(false)
            {
                let decoded = ImageReader::new(io::Cursor::new(latest_video))
                    .with_guessed_format()
                    .expect("Could not guess JPEG format")
                    .decode()
                    .expect("Failed to decode JPEG frame");

                // Update our last checked frame to the current one.
                self.last_detection = Some(latest_video_time);

                // Convert to grayscale for better comparison
                let mut grayscale = decoded.to_luma8();

                let (mut width, mut height) = decoded.dimensions();
                if width > 640 && height > 480 {
                    // Enforce 640x480 as the maximum. This is to reduce system strain on CPU usage, as the higher it is, it will grow exponentially from here.
                    // 320x240 was tested, but unfortunately I don't think the massive loss in accuracy is worth the performance boost
                    // TODO: We may need to re-think this approach for outdoor cameras.
                    width = 640;
                    height = 480;
                    grayscale =
                        imageops::resize(&grayscale, 640, 480, imageops::FilterType::Nearest);
                }

                // Determine how much we need to scale our constants for minimum point motion detection based on the tested resolution (640x480)
                let points_scale_factor: f64 = (width as f64 * height as f64) / (640.0 * 480.0);

                if self.motion.is_none() {
                    // We instantiate the BackgroundSubtractor with our first image as a baseline to compare to.
                    self.motion = Some(BackgroundSubtractor::new(&grayscale));
                } else {
                    let diff_result = self.motion.clone().unwrap().apply(&grayscale);
                    let mut data_vec = Vec::new();
                    let mut targets = Vec::new();

                    // Iterate efficiently without unnecessary variable tracking
                    for (x, y, pixel) in diff_result.enumerate_pixels() {
                        if pixel[0] == 255 {
                            data_vec.extend_from_slice(&[x as f64, y as f64]);
                            targets.push(1.0);
                        }
                    }

                    let total_amt_of_points = targets.len();

                    // We don't need to perform DBScan if we have a massive amount of differing points (as noise isn't possible in this quantity)
                    if total_amt_of_points as f64
                        >= points_scale_factor * MINIMUM_GLOBAL_POINTS as f64
                    {
                        self.motion = Some(BackgroundSubtractor::new(&grayscale));
                        debug!(
                            "Motion was detected via global analysis with {} total points",
                            total_amt_of_points
                        );

                        // Should you wish to see the computed motion difference images, uncomment this block (and the other below)
                        /*
                        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
                        let millis = current_time.as_secs() * 1000 + current_time.subsec_nanos() as u64 / 1_000_000;
                        diff_result.save(format!("difference_global_{:?}.png", millis)).expect("Failed to save difference image!");
                        */

                        return Ok(true);
                    } else if total_amt_of_points as f64
                        >= points_scale_factor * MINIMUM_TOTAL_CLUSTERED_POINTS as f64
                    {
                        // We don't need to check the clusters if the global amount of points don't exceed the min clustered amount
                        // Else, if there's less, we may still want to observe to see if there's large *localized* cluster(s) of points that moved

                        // We formulate a dataset with these changed points
                        let x: ndarray::ArrayBase<OwnedRepr<f64>, ndarray::Ix2> =
                            Array::from_shape_vec((total_amt_of_points, 2), data_vec)
                                .expect("Was not able to convert to X");
                        let y: ndarray::ArrayBase<OwnedRepr<f64>, ndarray::Ix1> =
                            Array::from_shape_vec(total_amt_of_points, targets)
                                .expect("Was not able to convert to Y");
                        let dataset: Dataset<f64, f64, Ix1> = Dataset::new(x, y);

                        // Thus, we compute an approximation of DBScan (the approximation itself seems to not be implemented in linfa yet, but will future-proof our impl),
                        // which can find clusters of *grouped* differing points to determine if we have noise or something that actually moved.
                        let cluster_memberships = AppxDbscan::params(
                            (points_scale_factor * MINIMUM_INDIVIDUAL_CLUSTER_POINTS as f64)
                                as usize,
                        )
                        .tolerance(points_scale_factor * DBSCAN_TOLERANCE)
                        .transform(dataset)
                        .unwrap();
                        let label_count = cluster_memberships.label_count().remove(0);

                        let mut total_count = 0;
                        for (label, count) in label_count {
                            if label.is_some() {
                                // We've detected a cluster of grouped points, so we accumulate it
                                total_count += count;
                            }
                        }

                        if total_count as f64
                            >= points_scale_factor * MINIMUM_TOTAL_CLUSTERED_POINTS as f64
                        {
                            // We replace the BackgroundSubtractor with the current image. This helps account for a major change in the image such as a new object being placed, etc.
                            // Should there be no huge change, and the image reverts back to the baseline, it'll just be replaced again shortly after at this same point without ill effect.
                            // This is due to us capping the motion detection notification rate at a minimum of 60 seconds.
                            self.motion = Some(BackgroundSubtractor::new(&grayscale));
                            debug!("Motion was detected via cluster analysis with {} clustered points and {} total points", total_count, total_amt_of_points);

                            // Should you wish to see the computed motion difference images, uncomment this block (and the other above)
                            /*
                            let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
                            let millis = current_time.as_secs() * 1000 + current_time.subsec_nanos() as u64 / 1_000_000;
                            diff_result.save(format!("difference_cluster_{:?}.png", millis)).expect("Failed to save difference image!");
                            */

                            return Ok(true);
                        }
                    }
                }
            }
        }

        return Ok(false);
    }
}
