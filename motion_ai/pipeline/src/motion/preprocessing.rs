use crate::frame::RawFrame;
use crate::logic::pipeline::RunId;
use crate::logic::telemetry::{TelemetryPacket, TelemetryRun};
use crate::motion::{clahe, detector};
use anyhow::anyhow;
use fast_image_resize::images::Image;
use fast_image_resize::{PixelType, ResizeAlg, ResizeOptions, Resizer};
use image::{GrayImage, ImageBuffer, Luma};
use libblur::{
    BlurImage, BlurImageMut, ConvolutionMode, EdgeMode, FastBlurChannels, ThreadingPolicy,
};
use log::{debug, warn};
use rayon::iter::IndexedParallelIterator;
use rayon::iter::ParallelIterator;
use rayon::prelude::{ParallelSlice, ParallelSliceMut};
use std::num::NonZero;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Preprocesses a raw frame through CLAHE
pub fn preprocess(
    raw_frame: RawFrame,
    telemetry: &mut TelemetryRun,
    run_id: &RunId,
    total_width: usize,
    total_height: usize,
) -> Result<(ImageBuffer<Luma<u8>, Vec<u8>>, f32), anyhow::Error> {
    // Convert the raw frame (YUV420) to grayscale via YUV420 -> RGB -> adaptive grayscale thresholding
    let grayscale_conversion_time = SystemTime::now();
    let (w_b, grayscale) = adaptive_grayscale(&raw_frame, total_width, total_height)?;

    debug!(
        "Elapsed Time for grayscale: {}",
        match grayscale_conversion_time.elapsed() {
            Ok(duration) => format!("{}ms", duration.as_millis()),
            Err(e) => {
                warn!("SystemTime error in timing background subtractor: {:?}", e);
                "error".into()
            }
        }
    );
    let grayscale_ms = grayscale_conversion_time
        .elapsed()
        .unwrap_or_default()
        .as_millis();
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    telemetry.write(&TelemetryPacket::StageDuration {
        ts,
        run_id: run_id.clone(),
        stage_name: "adaptive_grayscale",
        stage_kind: "preprocess",
        duration_ms: grayscale_ms,
    })?;

    RawFrame::save_gray_image(
        &grayscale,
        telemetry.run_id.as_str(),
        run_id,
        "adaptive_grayscale",
    )?;
    // TODO: Also save w_b value for debugging
    // TODO: Save time for each of these (ms per func) as well

    // Downscale to 640x480 from 1920x1080 to reduce load on background subtractor & clustering (by a magnitude of ~10x for ~2x the cost)
    let (mut w, mut h) = grayscale.dimensions();
    let mut processed = if w > 640 && h > 480 {
        w = 640;
        h = 480;
        downscale_with_fast_image_resize(&grayscale, w, h)
    } else {
        grayscale.clone()
    };

    // At night, we don't run CLAHE, so that we don't amplify noise in the image. Reduces false positives this way.
    if w_b < detector::WEIGHT_BLUE_THRESHOLD {
        // Perform CLAHE (Contrast-Limited Adaptive Histogram Equalization)
        let clahe = SystemTime::now();
        processed = clahe::default_clahe(processed, w as usize, h as usize);
        debug!(
            "CLAHE runtime: {}ms",
            match clahe.elapsed() {
                Ok(duration) => format!("{}ms", duration.as_millis()),
                Err(e) => {
                    warn!("SystemTime error in timing background subtractor: {:?}", e);
                    "error".into()
                }
            }
        );

        let clahe_ms = clahe.elapsed().unwrap_or_default().as_millis();
        let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();

        telemetry.write(&TelemetryPacket::StageDuration {
            ts,
            run_id: run_id.clone(),
            stage_name: "clahe",
            stage_kind: "preprocess",
            duration_ms: clahe_ms,
        })?;

        RawFrame::save_gray_image(&processed, telemetry.run_id.as_str(), run_id, "clahe")?;
    }

    let src = BlurImage::borrow(
        &mut ImageBuffer::as_raw(&processed),
        w,
        h,
        FastBlurChannels::Plane,
    );

    let mut dst = BlurImageMut::alloc(w, h, FastBlurChannels::Plane);

    // Perform Gaussian Blur operation
    // Roughly ~6ms/image on Raspberry Pi Zero 2W
    let blur_t0 = Instant::now();
    const THREAD_COUNT: usize = 1;
    libblur::gaussian_blur(
        &src,
        &mut dst,
        5,
        0.0,
        EdgeMode::Reflect101,
        ThreadingPolicy::Fixed(
            NonZero::new(THREAD_COUNT).ok_or_else(|| anyhow!("Thread count must be non-zero"))?,
        ),
        ConvolutionMode::Exact,
    )
        .map_err(|e| anyhow!("Gaussian blur failed: {:?}", e))?;

    let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    let blur_ms = blur_t0.elapsed().as_millis();

    telemetry.write(&TelemetryPacket::StageDuration {
        ts,
        run_id: run_id.clone(),
        stage_name: "guassian_blur",
        stage_kind: "preprocess",
        duration_ms: blur_ms,
    })?;

    // Ensure dst.data is properly converted to a Vec<u8> if needed
    let buffer_data = dst.data.borrow().to_vec();
    let blurred_image = GrayImage::from_raw(w, h, buffer_data)
        .ok_or_else(|| anyhow::anyhow!("Failed to create GrayImage from blur buffer"))?;

    RawFrame::save_gray_image(&blurred_image, telemetry.run_id.as_str(), run_id, "blurred")?;

    return Ok((blurred_image, w_b));
}

/** This method takes a YUV420 raw image and performs a parallel YUV420->RGB conversion,
then computes a custom grayscale variant based on the standard deviation of the red, green and blue channels for the image.
The standard grayscale formula is Gray = 0.299 * Red + 0.587 * Green + 0.114 * Blue.
This can lose a lot of detail in blue-dominated infrared images considering how blue is only weighted at 11.4% in the usual formula.
This aims to solve that issue through adaptive gray scaling, by calculating the optimal weights for each image
Downsides: Extra computational expense to calculate adaptive weights, versus using pre-defined.

 Outside the YUV->RGB method being called (referenced from below), it runs at 15ms on average on a 1292x972 frame on a Raspberry Pi Zero 2W.
 **/
pub(crate) fn adaptive_grayscale(
    raw_frame: &RawFrame,
    rgb_width: usize,
    rgb_height: usize,
) -> Result<(f32, GrayImage), anyhow::Error> {
    let rgb_pixels = raw_frame
        .rgb_data
        .as_ref()
        .map(|v| v.as_slice())
        .ok_or_else(|| anyhow!("Missing RGB data in RawFrame"))?;

    let total_rgb_pixels = (rgb_width * rgb_height) as f32;

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
    let mut gray_pixels = vec![0u8; rgb_width * rgb_height];

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

    return Ok((
        w_b,
        GrayImage::from_raw(rgb_width as u32, rgb_height as u32, gray_pixels)
            .ok_or_else(|| anyhow!("GrayImage::from_raw failed: pixel buffer size mismatch"))?,
    ));
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
