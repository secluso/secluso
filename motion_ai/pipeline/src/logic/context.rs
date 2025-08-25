//! Shared, mutable runtime context the FSM and stages read/write during a run
use crate::logic::activity_states::ActivityState;
use crate::logic::health_states::HealthState;
use crate::logic::pipeline::RunId;
use crate::ml::models::ModelKind;
use crate::motion::detector::MotionDetection;
use std::collections::HashMap;
use std::time::Instant;
use crate::frame::RawFrame;

/// Per-run, in-memory state updated by the FSM and stages
pub struct StateContext {
    /// Current activity/lifecycle state (Idle -> .. -> Cooldown)
    pub(crate) activity: ActivityState,
    /// Coarse health classification (Normal / High Temp / etc)
    pub(crate) health: HealthState,
    /// Currently selected ML model for inference
    pub(crate) active_model: ModelKind,
    /// Motion detection accumulator and thresholds.
    pub(crate) motion_detection: MotionDetection,
    /// Run identifier (UUID); set to the first frame's run ID when known
    pub(crate) run_id: RunId,
    //last_motion_time: Option<Instant>,
    // latency_ema: f32,
    // temp_history: VecDeque<f32>,
    // backoff_until: Option<Instant>,
    /// Whether to execute model inference for this run/frame.
    pub use_inference: bool,
    // pub metadata: HashMap<String, String>,
    /// Per stage counters and last-latency samples.
    pub stats: HashMap<String, StageStats>,
    pub last_detection: Option<Instant>,
    pub last_detection_frame: Option<RawFrame>
}

impl StateContext {
    /// Construct a default context used at the start of a run/session.
    pub(crate) fn new() -> Self {
        Self {
            activity: ActivityState::Idle,
            health: HealthState::Normal,
            active_model: ModelKind::Accurate,
            motion_detection: MotionDetection::new(),
            run_id: RunId::new(), // Will be replaced with the first frame, so it can be this instead of an Option for ease-of-use
            //last_motion_time: None,
            //// latency_ema: 0.0,
            // temp_history: Default::default(),
            // backoff_until: None,
            use_inference: true,
            // metadata: Default::default(),
            stats: Default::default(),
            last_detection: None,
            last_detection_frame: None,
        }
    }
}

/// Rolling per-stage telemetry counters for the current run
#[derive(Default)]
pub struct StageStats {
    /// Total calls to this stage.
    pub calls: u64,
    /// Last observed end-to-end latency in milliseconds
    pub last_latency_ms: Option<u32>,
    /// Number of faults observed (non-recoverable errors).
    pub faults: u64, //todo: what does this represent? might overlap with dropped_frames
    /// Number of frames intentionally dropped by this stage.
    pub dropped_frames: u64,
}
