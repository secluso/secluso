use crate::logic::intent::Intent;
use crate::logic::pipeline::RunId;
use serde::Serialize;
use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::Path,
};
use std::sync::atomic::Ordering;
use crate::frame::SAVE_IMAGES;

/// Represents a structured telemetry message logged during pipeline operation.
/// Encodes metadata about performance, state transitions, detection outcomes, and events.
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TelemetryPacket<'a> {
    // Logs stats for a specific pipeline stage execution
    Stage {
        //implemented
        run_id: RunId,
        stage: &'a str,
        calls: u64,
        last_latency_ms: u32,
        faults: u64,
        dropped_frames: u64,
        replay_frame_idx: Option<usize>,
        ts: u128,
    },
    // Snapshot of system state at each pipeline tick
    TickStats {
        ts: u128,
        run_id: RunId,
        activity: &'static str,
        health: &'static str,
        event_queue_len: usize,
        standby_has_frame: bool,
        active_has_frame: bool,
        max_event_queue_len: usize,
    },
    // Details of motion detection points/clusters
    MotionMetrics {
        run_id: RunId,
        w_b: f32,
        total_points: u32,
        clustered_points: u32,
        threshold: u32,
        ts: u128,
    },
    // Frame dropped due to failure or resource constraints
    DroppedFrame {
        run_id: RunId,
        ts: u128,
        reason: &'a str, // heat / load / critical / etc
    },
    // Inference bypassed due to system load or config
    InferenceSkipped {
        run_id: RunId,
        ts: u128,
        reason: &'a str,
    },
    // CPU/RAM/temp snapshot
    Health {
        run_id: RunId,
        cpu_pct: f32,
        ram_pct: f32,
        temp_c: f32,
        ts: u128,
    },
    // ML model change triggered by health events
    ModelSwitch {
        ts: u128,
        run_id: RunId,
        from: &'a str,
        to: &'a str,
        reason: &'a str,
        health: &'a str,
    },
    // Duration spent in a specific FSM state
    StateDuration {
        run_id: RunId,
        ts: u128,
        state: &'a str,
        fsm: &'a str,
        duration_ms: u128,
    },
    DetectionsSummary {
        ts: u128,
        run_id: &'a str,
        label_stats: &'a [(
            /*label:*/ i32,
            /*count:*/ usize,
            /*avg:*/ f32,
            /*max:*/ f32,
        )],
    },
    // Activity or health FSM state change
    FSMTransition {
        run_id: RunId,
        from: &'a str,
        to: &'a str,
        reason: &'a str,
    },
    // Detection result for a single frame
    Detection {
        run_id: RunId,
        frame_rel: &'a str,
        detections: usize,
        latency_ms: u32,
        ts: u128,
    },
    // Total duration for stage (optional additional stat)
    StageDuration {
        ts: u128,
        run_id: RunId,
        stage_name: &'a str,
        stage_kind: &'a str,
        duration_ms: u128,
    },
    // Captures each dispatched intent during pipeline flow
    IntentTriggered {
        run_id: RunId,
        intent: Intent,
        ts: u128,
    },
}

/*
pub enum FrameExport {
    InitialFrame,
    AdaptiveGrayscale,
    CLAHE,
    Blur,
    BgSubtractNoised,
    BgSubtractDenoised,
    BgSubtractBackend,
    MLResults,
}*/

/// Represents a telemetry logging session for a single pipeline run.
/// Manages writing structured logs to a file in the run directory.
pub struct TelemetryRun {
    pub run_id: String,
    pub log: Option<File>,
    activated: bool
}

impl TelemetryRun {
    /// Initializes a new telemetry run by creating a unique output directory and log file.
    /// Boolean activated indicates whether we actually write logs or not (may not want to for privacy’s sake)
    pub fn new(activated: bool) -> Result<Self, anyhow::Error> {
        // 1. create run directory
        let run_id = chrono::Utc::now().format("%Y-%m-%dT%H-%M-%SZ").to_string();
        SAVE_IMAGES.store(activated, Ordering::Relaxed);

        if activated {
            let base = Path::new("output").join("runs").join(&run_id);
            std::fs::create_dir_all(base.join("frames"))?;

            // 2. open log file
            let log = OpenOptions::new()
                .append(true)
                .create(true)
                .open(base.join("telemetry.log"))?;

            Ok(Self { run_id, log: Some(log), activated: true })
        } else {
            Ok(Self { run_id, log: None, activated: false })
        }
    }

    /// Serializes and writes a telemetry packet as a line to the log file.
    pub fn write(&mut self, pkt: &TelemetryPacket) -> Result<(), anyhow::Error> {
        if let Some(log) = &mut self.log {
            if self.activated {
                let line = serde_json::to_string(pkt)?;
                writeln!(log, "{line}")?;
            }
        }
        Ok(())
    }
}
