// -----------------------------------------------------------------------------
// Portions of this file were ported from the NanoDet project from C++ into Rust
// (https://github.com/RangiLyu/nanodet),
// Copyright 2020–2025 NanoDet authors, licensed under the Apache License 2.0.
// -----------------------------------------------------------------------------

use std::collections::HashMap;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use image::RgbImage;
use image::imageops::FilterType;
use ndarray::{Array, Array4, Ix3, s};
use ort::value::TensorRef;

use crate::frame::RawFrame;
use crate::logic::pipeline::RunId;
use crate::logic::telemetry::{TelemetryPacket, TelemetryRun};
use crate::ml::models::{
    BoxInfo, DetectionResult, DetectionType, ModelError, ModelKind, ModelRunner, with_session,
};

/// Number of output classes in the NanoDet COCO 2017 model.
const NUM_CLASSES: usize = 80;

/// Feature map strides used by NanoDet’s FPN head. Each stride corresponds to a different resolution level.
const STRIDES: [i32; 4] = [8, 16, 32, 64];

/// Maximum bin index for NanoDet’s distance regression (DISTR head).
const REG_MAX: usize = 7;

/// Runs NanoDet object detection using a cached ONNX session and post-processing pipeline.
pub struct NanodetRunner;

/// Implements the NanoDet inference flow, including image preprocessing, session execution,
/// decoding, non-max suppression, and telemetry emission.
impl ModelRunner for NanodetRunner {
    /// Main inference pipeline: preprocesses frame, runs ONNX model,
    /// applies postprocessing (decode + NMS), and emits telemetry.
    fn decode(
        kind: &ModelKind,
        frame: &RawFrame,
        telemetry: &mut TelemetryRun,
        run_id: &RunId,
    ) -> Result<DetectionResult, ModelError> {
        const W: usize = 416;
        const H: usize = 416;

        let old_w: u32 = frame.width as u32;
        let old_h: u32 = frame.height as u32;

        let img = RgbImage::from_raw(
            old_w,
            old_h,
            frame
                .rgb_data
                .as_ref()
                .expect("Missing RGB")
                .as_ref()
                .clone(),
        )
        .expect("Failed to create RGB image from raw data");

        // todo: replace with fast image resize
        // Resize the original RGB image to the model’s expected input resolution (416x416).
        let resized = image::imageops::resize(&img, W as u32, H as u32, FilterType::Triangle);
        let mut image_data: Vec<f32> = Vec::with_capacity(W * H * 3);

        let mut b_data = Vec::with_capacity(H * W);
        let mut g_data = Vec::with_capacity(H * W);
        let mut r_data = Vec::with_capacity(H * W);

        for pixel in resized.pixels() {
            b_data.push(pixel[2] as f32);
            g_data.push(pixel[1] as f32);
            r_data.push(pixel[0] as f32);
        }

        // Normalize each RGB channel using NanoDet training statistics.
        for val in b_data.iter_mut() {
            *val = (*val - 103.53) * 0.017429;
        }
        for val in g_data.iter_mut() {
            *val = (*val - 116.28) * 0.017507;
        }
        for val in r_data.iter_mut() {
            *val = (*val - 123.675) * 0.017125;
        }

        // Then interleave in CHW:
        image_data.extend(&b_data);
        image_data.extend(&g_data);
        image_data.extend(&r_data);

        // Construct CHW-ordered ONNX input tensor.
        let input_tensor = Array4::from_shape_vec((1, 3, H, W), image_data)?;
        let start = Instant::now();

        let input_value = TensorRef::from_array_view((
            input_tensor.shape().to_vec(),
            input_tensor
                .as_slice()
                .ok_or_else(|| ModelError::Inference("Failed to get tensor slice".into()))?,
        ))?;

        let inputs = ort::inputs![input_value];
        let all_boxes = with_session(kind, |sess| {
            let ort_t0 = Instant::now();
            let outs = sess.run(inputs).expect("ORT run failed");
            let ort_ms = ort_t0.elapsed().as_millis();
            let ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis();
            let _ = telemetry.write(&TelemetryPacket::StageDuration {
                ts,
                run_id: run_id.clone(),
                stage_name: "ort_run",
                stage_kind: "inference",
                duration_ms: ort_ms,
            });

            // Extract model output tensor for post-processing.
            let output = &outs[0];

            let predictions = output
                .try_extract_array::<f32>()
                .expect("Failed to extract array");
            let array = predictions.to_owned();
            let arr3 = match array.into_dimensionality::<Ix3>() {
                Ok(v) => v,
                Err(e) => {
                    log::error!("Invalid output shape: {e}");
                    return vec![];
                }
            };
            let cls_preds = arr3.slice(s![.., .., 0..NUM_CLASSES]);
            let box_preds = arr3.slice(s![.., .., NUM_CLASSES..]);

            let dec_t0 = Instant::now();

            let mut result1 = decode_infer(
                cls_preds.into_owned(),
                box_preds.into_owned(),
                0.4,
                H as i32,
            ); // H can be based as input size. Square shape. 416 by 416 (i = 416)
            for class_boxes in &mut result1 {
                nms(class_boxes, 0.5);
            }

            // Flatten class-wise detections into a single vector.
            let all_boxes: Vec<BoxInfo> = result1.into_iter().flatten().collect();

            let mut grouped: HashMap<i32, Vec<f32>> = HashMap::new();

            // Group confidences by label
            for det in &all_boxes {
                grouped.entry(det.label).or_default().push(det.confidence);
            }

            // Build (label, count, avg_conf, max_conf) list
            let mut label_stats = Vec::with_capacity(grouped.len());
            for (label, confs) in grouped {
                let count = confs.len();
                let avg_conf = confs.iter().copied().sum::<f32>() / count as f32;
                let max_conf = confs.iter().copied().fold(0.0, f32::max);
                label_stats.push((label, count, avg_conf, max_conf));
            }

            let dec_ms = dec_t0.elapsed().as_millis();
            let ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis();
            let _ = telemetry.write(&TelemetryPacket::StageDuration {
                ts,
                run_id: run_id.clone(),
                stage_name: "post_decode_nms",
                stage_kind: "inference",
                duration_ms: dec_ms,
            });

            // Emit telemetry
            let run_id_s = run_id.0.clone();
            let _ = telemetry.write(&TelemetryPacket::DetectionsSummary {
                ts: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis(),
                run_id: run_id_s.as_str(),
                label_stats: label_stats.as_slice(),
            });

            all_boxes
        });

        //let final_image = draw_boxes(resized.clone(), all_boxes.clone());
        //final_image.save("output.jpg").unwrap();

        Ok(DetectionResult {
            runtime: start.elapsed(),
            results: all_boxes?,
        })
    }
}

/// Applies non-maximum suppression (NMS) to reduce overlapping boxes within each class.
fn nms(input_boxes: &mut Vec<BoxInfo>, nms_threshold: f32) {
    input_boxes.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let mut areas: Vec<f32> = input_boxes
        .iter()
        .map(|b| (b.x2 - b.x1 + 1.0) * (b.y2 - b.y1 + 1.0))
        .collect();

    let mut i = 0;
    while i < input_boxes.len() {
        let mut j = i + 1;
        while j < input_boxes.len() {
            let xx1 = f32::max(input_boxes[i].x1, input_boxes[j].x1);
            let yy1 = f32::max(input_boxes[i].y1, input_boxes[j].y1);
            let xx2 = f32::min(input_boxes[i].x2, input_boxes[j].x2);
            let yy2 = f32::min(input_boxes[i].y2, input_boxes[j].y2);

            let w = f32::max(0.0, xx2 - xx1 + 1.0);
            let h = f32::max(0.0, yy2 - yy1 + 1.0);
            let inter = w * h;
            let ovr = inter / (areas[i] + areas[j] - inter);

            if ovr >= nms_threshold {
                input_boxes.remove(j);
                areas.remove(j);
            } else {
                j += 1;
            }
        }
        i += 1;
    }
}

/// Decodes model output tensors into bounding boxes using class scores and distribution regression.
// score_threshold = 0.4, nms_threshold = 0.5
fn decode_infer(
    cls_pred: Array<f32, Ix3>,
    dis_pred: Array<f32, Ix3>,
    threshold: f32,
    input_size_: i32,
) -> Vec<Vec<BoxInfo>> {
    let mut results: Vec<Vec<BoxInfo>> =
        std::iter::repeat_with(Vec::new).take(NUM_CLASSES).collect(); // one Vec per class

    let mut total_idx: i32 = 0;
    for stride in STRIDES {
        let feature_h = (input_size_ as f32 / stride as f32).ceil() as i32;
        let feature_w = (input_size_ as f32 / stride as f32).ceil() as i32;

        for idx in total_idx..(feature_h * feature_w + total_idx) {
            let row = (idx - total_idx) / feature_w;
            let col = (idx - total_idx) % feature_w;
            let mut score = -0.0;
            let mut cur_label = 0;
            for label in 0..NUM_CLASSES {
                let cur_score = cls_pred[[0, idx as usize, label]];
                if cur_score > score {
                    score = cur_score;
                    cur_label = label;
                }
            }
            if score > threshold {
                let cur_dis = dis_pred.slice(s![0, idx, ..]); // shape: [32]
                let bbox_pred = cur_dis.to_vec(); // Make a flat Vec

                results[cur_label].push(dis_pred2bbox(
                    &bbox_pred,
                    cur_label as i32,
                    score,
                    col,
                    row,
                    stride,
                    input_size_ as f64,
                ));
            }
        }
        total_idx += feature_h * feature_w;
    }

    results
}

/// Converts NanoDet distribution head predictions into absolute bounding box coordinates.
fn dis_pred2bbox(
    dfl_det: &[f32],
    label: i32,
    score: f32,
    x: i32,
    y: i32,
    stride: i32,
    input_size_: f64,
) -> BoxInfo {
    let ct_x = (x as f32 + 0.5) * stride as f32;
    let ct_y = (y as f32 + 0.5) * stride as f32;
    let mut dis_pred = [0.0f32; 4];

    for (i, dis_slot) in dis_pred.iter_mut().enumerate() {
        let offset = i * (REG_MAX + 1);
        let side_logits = &dfl_det[offset..offset + REG_MAX + 1];
        let mut dis = 0f32;
        let mut dis_after_sm = vec![0.0f32; REG_MAX + 1];
        activation_function_softmax(side_logits, &mut dis_after_sm);
        for (j, &p) in dis_after_sm.iter().enumerate().take(REG_MAX + 1) {
            dis += (j as f32) * p;
        }

        dis *= stride as f32;
        *dis_slot = dis;
    }

    let x_min = f32::max(ct_x - dis_pred[0], 0.0);
    let y_min = f32::max(ct_y - dis_pred[1], 0.0);
    let x_max = f32::min(ct_x + dis_pred[2], input_size_ as f32);
    let y_max = f32::min(ct_y + dis_pred[3], input_size_ as f32);

    BoxInfo {
        x1: x_min,
        y1: y_min,
        x2: x_max,
        y2: y_max,
        score,
        label,
        det_type: decode_label(label),
        confidence: score,
    }
}

/// Source of COCO 2017 labels: https://github.com/amikelive/coco-labels/blob/master/coco-labels-2014_2017.txt
/// Maps COCO 2017 class IDs to internal detection labels of interest (Human, Car, Animal, etc).
#[inline]
fn decode_label(label: i32) -> DetectionType {
    match label {
        0 => DetectionType::Human,
        2 => DetectionType::Car,
        15 | 16 => DetectionType::Animal,
        _ => DetectionType::Other,
    }
}

/// Applies numerically stable softmax to a slice of logits in-place.
fn activation_function_softmax(src: &[f32], dst: &mut [f32]) {
    let alpha = src.iter().cloned().fold(f32::NEG_INFINITY, f32::max);
    let mut denominator = 0.0;

    for (i, &val) in src.iter().enumerate() {
        let exp_val = (val - alpha).exp();
        dst[i] = exp_val;
        denominator += exp_val;
    }

    for val in dst.iter_mut() {
        *val /= denominator;
    }
}
