//! SPDX-License-Identifier: GPL-3.0-or-later

/*M///////////////////////////////////////////////////////////////////////////////////////
//
//  IMPORTANT: READ BEFORE DOWNLOADING, COPYING, INSTALLING OR USING.
//
//  By downloading, copying, installing or using the software you agree to this license.
//  If you do not agree to this license, do not download, install,
//  copy or use the software.
//
//
//                           License Agreement
//                For Open Source Computer Vision Library
//
// Copyright (C) 2013, NVIDIA Corporation, all rights reserved.
// Copyright (C) 2014, Itseez Inc., all rights reserved.
// Third party copyrights are property of their respective owners.
//
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
//
//   * Redistribution's of source code must retain the above copyright notice,
//     this list of conditions and the following disclaimer.
//
//   * Redistribution's in binary form must reproduce the above copyright notice,
//     this list of conditions and the following disclaimer in the documentation
//     and/or other materials provided with the distribution.
//
//   * The name of the copyright holders may not be used to endorse or promote products
//     derived from this software without specific prior written permission.
//
// This software is provided by the copyright holders and contributors "as is" and
// any express or implied warranties, including, but not limited to, the implied
// warranties of merchantability and fitness for a particular purpose are disclaimed.
// In no event shall the copyright holders or contributors be liable for any direct,
// indirect, incidental, special, exemplary, or consequential damages
// (including, but not limited to, procurement of substitute goods or services;
// loss of use, data, or profits; or business interruption) however caused
// and on any theory of liability, whether in contract, strict liability,
// or tort (including negligence or otherwise) arising in any way out of
// the use of this software, even if advised of the possibility of such damage.
//
//M*/

/**

This class serves as a Rust replication of OpenCV's CLAHE ("Contrast-Limited Adaptive Histogram Equalization") C++ implementation for grayscale images.
Developed to avoid using bindings and have a smaller binary size.
Reference Source: https://github.com/opencv/opencv/blob/8207549638c60d46ebe85af7b3a3f50bb5ef49d5/modules/imgproc/src/clahe.cpp#L47

 **/
extern crate image;

use image::{GrayImage, Luma};

/// On average, this implementation takes roughly 36ms/frame to run on a 640x480 frame on a Raspberry Pi Zero 2W.
pub(crate) fn default_clahe(
    orig_img: GrayImage,
    orig_width: usize,
    orig_height: usize,
) -> GrayImage {
    // CLAHE parameters used during Optuna hyper parameter optimization
    // grid (tilesX, tilesY) and clip limit.
    let grid_x = 8usize;
    let grid_y = 8usize;
    let clip_limit = 2.0_f32;

    // If the image dimensions are not divisible by the grid,
    // extend the image using BORDER_REFLECT_101.
    let need_extension = !orig_width.is_multiple_of(grid_x) || !orig_height.is_multiple_of(grid_y);
    let (src_for_lut, ext_width, ext_height) = if need_extension {
        let ext = extend_image_reflect101(&orig_img, grid_x, grid_y);
        (ext.clone(), ext.width() as usize, ext.height() as usize)
    } else {
        (orig_img.clone(), orig_width, orig_height)
    };

    // Compute tile size based on the (possibly extended) image.
    let tile_width = ext_width / grid_x;
    let tile_height = ext_height / grid_y;

    // Convert the image used for LUT computation to a 2D vector.
    let src_for_lut_vec = image_to_vec(&src_for_lut);

    // Compute a LUT for each tile.
    let tile_luts = compute_all_tile_luts(
        &src_for_lut_vec,
        grid_x,
        grid_y,
        tile_width,
        tile_height,
        clip_limit,
    );

    // Use the original image for interpolation.
    let orig_vec = image_to_vec(&orig_img);
    let result_vec = interpolate(
        &orig_vec,
        &tile_luts,
        grid_x,
        grid_y,
        tile_width,
        tile_height,
    );

    let mut out_img = GrayImage::new(orig_width as u32, orig_height as u32);
    for (y, row) in result_vec.iter().enumerate().take(orig_height) {
        for (x, &val) in row.iter().enumerate().take(orig_width) {
            out_img.put_pixel(x as u32, y as u32, Luma([val]));
        }
    }

    out_img
}

/// Extend the image so that its dimensions become divisible by grid_x and grid_y via BORDER_REFLECT_101 strategy
fn extend_image_reflect101(img: &GrayImage, grid_x: usize, grid_y: usize) -> GrayImage {
    let width = img.width() as usize;
    let height = img.height() as usize;
    let new_width = if width.is_multiple_of(grid_x) {
        width
    } else {
        width + (grid_x - (width % grid_x))
    };
    let new_height = if height.is_multiple_of(grid_y) {
        height
    } else {
        height + (grid_y - (height % grid_y))
    };

    let mut extended = GrayImage::new(new_width as u32, new_height as u32);
    for y in 0..new_height {
        for x in 0..new_width {
            let orig_x = reflect101(x, width);
            let orig_y = reflect101(y, height);
            let pixel = img.get_pixel(orig_x as u32, orig_y as u32)[0];
            extended.put_pixel(x as u32, y as u32, Luma([pixel]));
        }
    }
    extended
}

/// Implements BORDER_REFLECT_101 for a coordinate.
fn reflect101(x: usize, max: usize) -> usize {
    if max == 0 {
        return 0;
    }
    let period = 2 * max - 2;
    let mut r = x % period;
    if r >= max {
        r = period - r;
    }
    r
}

/// Converts a GrayImage into a 2D Vec<Vec<u8>>.
fn image_to_vec(img: &GrayImage) -> Vec<Vec<u8>> {
    let width = img.width() as usize;
    let height = img.height() as usize;
    let mut vec = vec![vec![0u8; width]; height];
    for (y, row) in vec.iter_mut().enumerate().take(height) {
        for (x, val) in row.iter_mut().enumerate().take(width) {
            *val = img.get_pixel(x as u32, y as u32)[0];
        }
    }

    vec
}

/// For each tile, compute its LUT by calculating the histogram, clipping it (with redistribution), and then computing the cumulative distribution.
fn compute_all_tile_luts(
    image: &[Vec<u8>],
    grid_x: usize,
    grid_y: usize,
    tile_width: usize,
    tile_height: usize,
    clip_limit: f32,
) -> Vec<Vec<[u8; 256]>> {
    let mut luts = vec![vec![[0u8; 256]; grid_x]; grid_y];
    for (j, row) in luts.iter_mut().enumerate().take(grid_y) {
        for (i, lut) in row.iter_mut().enumerate().take(grid_x) {
            let x0 = i * tile_width;
            let x1 = x0 + tile_width;
            let y0 = j * tile_height;
            let y1 = y0 + tile_height;
            *lut = compute_tile_lut(image, x0, x1, y0, y1, clip_limit);
        }
    }

    luts
}

/// Compute the LUT for one tile using a histogram with 256 bins.
/// Histogram bins exceeding the clip limit are clipped and their excess is redistributed.
fn compute_tile_lut(
    image: &[Vec<u8>],
    x0: usize,
    x1: usize,
    y0: usize,
    y1: usize,
    clip_limit: f32,
) -> [u8; 256] {
    let tile_area = (x1 - x0) * (y1 - y0);
    let hist_size = 256;
    let mut hist = [0usize; 256];

    // Build histogram.
    for row in image.iter().take(y1).skip(y0) {
        for &val in row.iter().take(x1).skip(x0) {
            hist[val as usize] += 1;
        }
    }

    // Compute the clip limit per bin.
    let clip_limit_int =
        (((clip_limit * tile_area as f32) / hist_size as f32).max(1.0)).floor() as usize;
    let mut clipped = 0;
    for bin in hist.iter_mut().take(hist_size) {
        if *bin > clip_limit_int {
            clipped += *bin - clip_limit_int;
            *bin = clip_limit_int;
        }
    }

    // Redistribute the excess pixels.
    let redist_batch = clipped / hist_size;
    let mut residual = clipped % hist_size;
    for bin in hist.iter_mut().take(hist_size) {
        *bin += redist_batch;
    }
    if residual > 0 {
        let residual_step = std::cmp::max(hist_size / residual, 1);
        let mut i = 0;
        while i < hist_size && residual > 0 {
            hist[i] += 1;
            residual -= 1;
            i += residual_step;
        }
    }

    // Compute the cumulative distribution function (CDF) and build the LUT.
    let mut cdf = [0usize; 256];
    cdf[0] = hist[0];
    for i in 1..hist_size {
        cdf[i] = cdf[i - 1] + hist[i];
    }
    let lut_scale = 255.0_f32 / tile_area as f32;
    let mut lut = [0u8; 256];
    for i in 0..hist_size {
        // Saturate to [0, 255].
        let val = (cdf[i] as f32 * lut_scale).round() as i32;
        lut[i] = if val < 0 {
            0
        } else if val > 255 {
            255
        } else {
            val as u8
        };
    }
    lut
}

/// Interpolates the final image using bilinear interpolation between neighboring LUTs.
/// The tile size is based on the extended image, while interpolation is performed on the original image.
fn interpolate(
    image: &[Vec<u8>],
    tile_luts: &[Vec<[u8; 256]>],
    grid_x: usize,
    grid_y: usize,
    tile_width: usize,
    tile_height: usize,
) -> Vec<Vec<u8>> {
    let height = image.len();
    let width = image[0].len();
    let inv_tile_width = 1.0_f32 / tile_width as f32;
    let inv_tile_height = 1.0_f32 / tile_height as f32;
    let mut output = vec![vec![0u8; width]; height];

    for y in 0..height {
        // Compute the floating-point tile coordinate in y.
        let tyf = y as f32 * inv_tile_height - 0.5;
        let mut ty1 = tyf.floor() as isize;
        let ty2 = ty1 + 1;
        let ya = tyf - ty1 as f32;
        let ya1 = 1.0 - ya;
        if ty1 < 0 {
            ty1 = 0;
        }

        let tile_y1 = ty1 as usize;
        let tile_y2 = if (ty2 as usize) < grid_y {
            ty2 as usize
        } else {
            tile_y1
        };

        for x in 0..width {
            // Compute the floating-point tile coordinate in x.
            let txf = x as f32 * inv_tile_width - 0.5;
            let mut tx1 = txf.floor() as isize;
            let tx2 = tx1 + 1;
            let xa = txf - tx1 as f32;
            let xa1 = 1.0 - xa;
            if tx1 < 0 {
                tx1 = 0;
            }

            let tile_x1 = tx1 as usize;
            let tile_x2 = if (tx2 as usize) < grid_x {
                tx2 as usize
            } else {
                tile_x1
            };
            let pixel = image[y][x] as usize;

            // Retrieve the mapped values from the four neighboring LUTs.
            let tl = tile_luts[tile_y1][tile_x1][pixel] as f32;
            let tr = tile_luts[tile_y1][tile_x2][pixel] as f32;
            let bl = tile_luts[tile_y2][tile_x1][pixel] as f32;
            let br = tile_luts[tile_y2][tile_x2][pixel] as f32;
            let top = xa1 * tl + xa * tr;
            let bottom = xa1 * bl + xa * br;
            let new_val = ya1 * top + ya * bottom;
            output[y][x] = new_val.round().clamp(0.0, 255.0) as u8;
        }
    }

    output
}
