use crate::frame::RawFrame;
use crate::logic::context::StateContext;
use crate::logic::telemetry::{TelemetryPacket, TelemetryRun};
use crate::ml::models::DetectionType;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// Describes the type of stage within the pipeline (e.g., motion, inference).
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize, Hash, Eq)]
pub enum StageType {
    Motion,
    Inference,
    Custom(String),
}

/// Converts StageType to a human-readable string.
impl fmt::Display for StageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StageType::Motion => write!(f, "motion"),
            StageType::Inference => write!(f, "inference"),
            StageType::Custom(s) => write!(f, "{s}"),
        }
    }
}

/// Represents the result of executing a pipeline stage.
/// Continue: proceed to next stage
/// Drop: stop processing this frame
/// Fault: stage encountered an unrecoverable error
pub enum StageResult {
    Continue,
    Drop(String),
    Fault(String),
}

/// Trait that all pipeline stages must implement.
/// Provides a standardized interface for running processing logic on a frame.
pub trait PipelineStage: Send {
    //name, kind, handle
    fn name(&self) -> &'static str;

    fn kind(&self) -> StageType;

    fn handle(
        &self,
        frame: &mut RawFrame,
        ctx: &mut StateContext,
        telemetry: &mut TelemetryRun,
    ) -> Result<StageResult, anyhow::Error>;
}

/// Performs motion detection on the frame using YUV-to-RGB conversion and context settings.
pub struct MotionStage;

/// Pipeline stage that identifies whether meaningful motion occurred in the frame.
impl PipelineStage for MotionStage {
    fn name(&self) -> &'static str {
        "motion"
    }

    fn kind(&self) -> StageType {
        StageType::Motion
    }

    fn handle(
        &self,
        frame: &mut RawFrame,
        ctx: &mut StateContext,
        telemetry: &mut TelemetryRun,
    ) -> Result<StageResult, anyhow::Error> {
        println!("Motion stage handle called!");
        frame.yuv_to_rgb(); // We convert the existing YUV data to RGB state for motion analysis (stores in frame)
        let how_often_average: f32 = 1f32; // TODO: Find this # by figuring out how often we detect motion... running avg in context? What about for gaps where we send the video and aren't actively detecting? Still update?
        if let Ok(result) =
            ctx.motion_detection
                .start(frame, telemetry, &ctx.run_id, how_often_average)
        {
            // Motion was detected — continue with next stage.
            if result {
                Ok(StageResult::Continue)
            } else {
                // No motion found for this frame
                let ts = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis();
                telemetry.write(&TelemetryPacket::DroppedFrame {
                    run_id: ctx.run_id.clone(),
                    ts,
                    reason: "no_motion",
                })?;
                Ok(StageResult::Drop("no motion detected".into()))
            }
        } else {
            //Err
            Ok(StageResult::Fault(
                "Failed to process motion detection for this frame".into(),
            ))
        }
    }
}

/// Performs object detection using the currently active ML model.
pub struct InferenceStage;

/// Pipeline stage that runs inference and filters based on required labels (e.g., human detection).
impl PipelineStage for InferenceStage {
    fn name(&self) -> &'static str {
        "inference"
    }

    fn kind(&self) -> StageType {
        StageType::Inference
    }

    fn handle(
        &self,
        frame: &mut RawFrame,
        ctx: &mut StateContext,
        telemetry: &mut TelemetryRun,
    ) -> Result<StageResult, anyhow::Error> {
        if !ctx.use_inference {
            let ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis();
            telemetry.write(&TelemetryPacket::InferenceSkipped {
                run_id: ctx.run_id.clone(),
                ts,
                reason: "use_inference=false",
            })?;
            return Ok(StageResult::Continue);
        }

        println!("Inference stage handle called!");

        // Run the current model and handle inference errors.
        let result = match ctx.active_model.run(frame, telemetry, &ctx.run_id) {
            Ok(res) => res,
            Err(e) => {
                log::error!("Model run failed: {e:?}");
                let ts = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis();
                telemetry.write(&TelemetryPacket::DroppedFrame {
                    run_id: ctx.run_id.clone(),
                    ts,
                    reason: "infer_error",
                })?;
                return Ok(StageResult::Fault("Failed to run model".into()));
            }
        };

        // Attach detection results to the frame.
        frame.detection_result = Some(result.clone());

        // Save annotated detection frame to disk.
        let rel_path = match frame.save_png(
            telemetry.run_id.clone().as_str(),
            &ctx.run_id,
            "det_box",
            true,
        ) {
            Ok(p) => p,
            Err(e) => {
                log::error!("PNG write error: {e:?}");
                let ts = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis();
                telemetry.write(&TelemetryPacket::DroppedFrame {
                    run_id: ctx.run_id.clone(),
                    ts,
                    reason: "io_error:save_png",
                })?;
                return Ok(StageResult::Fault("Failed to write image".into()));
            }
        };

        let pkt = TelemetryPacket::Detection {
            run_id: ctx.run_id.clone(),
            frame_rel: rel_path.as_str(),
            detections: result.results.len(),
            latency_ms: result.runtime.as_millis() as u32,
            ts: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time should go forward.")
                .as_millis(),
        };

        if let Err(e) = telemetry.write(&pkt) {
            log::error!("Telemetry write error: {e:?}");
            return Ok(StageResult::Fault("Failed to write telemetry".into()));
        }

        const REQUIRED_LABEL: DetectionType = DetectionType::Human;
        if result.results.iter().any(|b| b.det_type == REQUIRED_LABEL) {
            Ok(StageResult::Continue)
        } else {
            let ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis();
            telemetry.write(&TelemetryPacket::DroppedFrame {
                run_id: ctx.run_id.clone(),
                ts,
                reason: "no_human",
            })?;
            Ok(StageResult::Drop("no human detected".into()))
        }
    }
}
