use crate::frame::RawFrame;
use crate::logic::activity_states::{
    ActivityState, CooldownState, DetectingState, IdleState, PrimedState,
};
use crate::logic::context::StateContext;
use crate::logic::fsm::FsmRegistry;
use crate::logic::health_states::HealthState;
use crate::logic::health_states::{
    CriticalTempState, HighTempState, NormalState, ResourceLowState,
};
use crate::logic::intent::{Intent, IntentBus};
use crate::logic::replay::ReplayRecorder;
use crate::logic::stages::{PipelineStage, StageResult, StageType};
use crate::logic::telemetry::{TelemetryPacket, TelemetryRun};
use crate::logic::timer::{Timer, TimerManager};
use crate::ml::models::init_model_paths;
use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::default::Default;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The main sequential container for executing image processing stages.
/// Each stage handles a specific task (e.g., motion, detection, inference).
pub struct Pipeline {
    stages: Vec<Box<dyn PipelineStage>>,
}

/// Unique identifier for a single frame run within the pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct RunId(pub String);

/// Creates new UUID-based Run IDs.
impl RunId {
    pub fn new() -> Self {
        RunId(uuid::Uuid::new_v4().to_string())
    }
}

/// Contains logic to run individual stages and track their telemetry.
impl Pipeline {
    /// Executes a specific pipeline stage, handles telemetry logging, and returns the result.
    pub(crate) fn run(
        &mut self,
        stage_type: StageType,
        frame_buffer: &mut FrameBuffer,
        recorder: &mut ReplayRecorder,
        telemetry: &mut TelemetryRun,
        ctx: &mut StateContext,
    ) -> Result<StageResult, anyhow::Error> {
        println!("Running stage type {:?}", stage_type);
        let frame = match frame_buffer.active.as_mut() {
            Some(f) => f,
            None => {
                let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
                telemetry.write(&TelemetryPacket::DroppedFrame {
                    run_id: ctx.run_id.clone(),
                    ts,
                    reason: "frame_missing",
                })?;
                return Ok(StageResult::Drop("no frame found".into()));
            }
        };

        let stage = self
            .stages
            .iter_mut()
            .find(|s| s.kind() == stage_type)
            .with_context(|| format!("Stage {:?} not found in pipeline", stage_type))?;
        recorder.record_frame(&frame);

        let start = Instant::now();
        let name = stage.name();
        let result = stage.handle(frame, ctx, telemetry);
        let latency = start.elapsed().as_millis() as u32;

        let s = ctx.stats.entry(name.to_string()).or_default();
        s.calls += 1;
        s.last_latency_ms = Some(latency);
        if let Ok(StageResult::Fault(_)) = result {
            s.faults += 1;
        }

        telemetry.write(&TelemetryPacket::Stage {
            run_id: ctx.run_id.clone(),
            stage: name,
            calls: s.calls,
            last_latency_ms: latency,
            faults: s.faults,
            dropped_frames: s.dropped_frames,
            replay_frame_idx: Some(recorder.frames.len().saturating_sub(1)),
            ts: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
        })?;

        result
    }

    /// Returns the next stage after the current one, or `None` if at the end.
    pub(crate) fn next_stage(&self, current: StageType) -> Option<StageType> {
        let idx = self.stages.iter().position(|s| s.kind() == current)?;
        if let Some(event) = self.stages.get(idx + 1) {
            Some(event.kind())
        } else {
            None
        }
    }
}

/// Builder for composing a custom ordered pipeline of stages.
pub struct PipelineBuilder {
    stages: Vec<Box<dyn PipelineStage>>,
}

/// Implements chaining and filtering logic for pipeline composition.
impl PipelineBuilder {
    pub fn new() -> Self {
        PipelineBuilder { stages: vec![] }
    }

    /// Adds a stage to the pipeline.
    pub fn then<S: PipelineStage + 'static>(mut self, stage: S) -> Self {
        self.stages.push(Box::new(stage));
        self
    }

    #[allow(dead_code)]
    pub fn from_vec(stages: Vec<Box<dyn PipelineStage>>) -> Self {
        Self { stages }
    }

    /// Finalizes and returns the configured pipeline.
    pub fn build(self) -> Pipeline {
        Pipeline {
            stages: self.stages,
        }
    }

    /// Filters stages by allowed types, returning a new builder.
    #[allow(dead_code)]
    pub fn filter_by_type(self, allowed: Vec<StageType>) -> Self {
        let filtered = self
            .stages
            .into_iter()
            .filter(|s| allowed.contains(&s.kind()))
            .collect();

        Self { stages: filtered }
    }
}

/// Defines all possible events that can occur in the pipeline.
/// These drive transitions in the FSM and trigger telemetry.
#[derive(Clone, Serialize, Deserialize)]
pub enum PipelineEvent {
    MotionStart,
    DetectionDone,
    InferenceCompleted,
    StageSuccess(StageType),
    Fault(StageType, String),
    Drop(StageType, String),
    TemperatureRise(f32),
    TemperatureDrop(f32),
    CriticalTemperature(f32),
    ResourceLow, // todo - what resources does this apply to
    Tick,
    BackoffExpired,
    NewFrame,
    ResourceNormal,
}

/// Top-level controller that manages event queue processing, FSM transitions,
/// intent execution, and telemetry emission.
pub struct PipelineController {
    intent_bus: IntentBus,
    host_data: PipelineHostData,
    recorder: ReplayRecorder,
    pub activity_registry: FsmRegistry<ActivityState>,
    pub health_registry: FsmRegistry<HealthState>,
    last_health_change: Option<(HealthState, Instant)>,
    last_activity_change: Option<(ActivityState, Instant)>,
    max_event_queue_len: usize,
}

/// Holds the current active and standby frame references used by the pipeline.
pub struct FrameBuffer {
    pub(crate) standby: Option<RawFrame>,
    pub(crate) active: Option<RawFrame>,
}

/// Shared mutable data for the pipeline, used across event processing and FSM transitions.
pub struct PipelineHostData {
    pub recorder: ReplayRecorder,
    pub event_queue: VecDeque<PipelineEvent>,
    pub ctx: StateContext,
    pub pipeline: Pipeline,
    pub(crate) timer: Box<dyn Timer>,
    pub frame_buffer: FrameBuffer,
    pub telemetry: TelemetryRun,
}

/// Implements pipeline orchestration logic including ticking, pushing frames,
/// and reacting to state transitions.
impl PipelineController {
    /// Constructs and initializes the pipeline controller and FSM registries.
    pub fn new(pipeline: Pipeline, write_logs: bool) -> Result<Self, anyhow::Error> {
        let mut activity_registry: FsmRegistry<ActivityState> = FsmRegistry {
            handlers: HashMap::new(),
        };

        // Nothing is happening whatsoever.
        activity_registry.register(ActivityState::Idle, Box::new(IdleState));

        // Awaiting a frame.
        activity_registry.register(ActivityState::Primed, Box::new(PrimedState));

        // Detecting on a frame.
        activity_registry.register(ActivityState::Detecting, Box::new(DetectingState));

        // Cooling down after a full run. Doesn't need to run, motion's already detected.
        // This value will depend on how often we want to detect motion events.
        activity_registry.register(ActivityState::Cooldown, Box::new(CooldownState));

        let mut health_registry: FsmRegistry<HealthState> = FsmRegistry {
            handlers: HashMap::new(),
        };

        health_registry.register(HealthState::Normal.into(), Box::new(NormalState));

        health_registry.register(HealthState::HighTemp.into(), Box::new(HighTempState));

        health_registry.register(HealthState::ResourceLow.into(), Box::new(ResourceLowState));

        health_registry.register(
            HealthState::CriticalTemp.into(),
            Box::new(CriticalTempState),
        );

        init_model_paths()?; // We should occasionally query this to hot-reload. But for this purpose, initializing and checking everything is OK is good enough

        Ok(Self {
            intent_bus: IntentBus {}, // todo: new()
            activity_registry,
            health_registry,
            last_health_change: None,
            recorder: ReplayRecorder::default(),
            host_data: PipelineHostData {
                recorder: Default::default(),
                event_queue: VecDeque::new(),
                ctx: StateContext::new(),
                pipeline,
                timer: Box::new(TimerManager::new()),
                frame_buffer: FrameBuffer {
                    standby: None,
                    active: None,
                },
                telemetry: TelemetryRun::new(write_logs)?,
            },
            last_activity_change: None,
            max_event_queue_len: 0,
        })
    }

    // Was there a positive motion event in the last 30 seconds? TODO: Adjust 30 accordingly
    pub fn motion_recently(&mut self) -> bool {
        match self.host_data.ctx.last_detection {
            None => {
                //println!("No detection recently");
                false
            }
            Some(last_detection) => {
                let elapsed = last_detection.elapsed();
                let secs = elapsed.as_secs();
                if elapsed <= Duration::from_secs(30) {
                    println!("Motion detected {} seconds ago (within 30s window).", secs);
                    true
                } else {
                    println!("Motion detected {} seconds ago (outside 30s window).", secs);
                    false
                }
            }
        }
    }

    /// Loads a new frame into the standby buffer and queues a NewFrame event.
    pub fn push_frame(&mut self, frame: RawFrame) {
        self.host_data.frame_buffer.standby = Some(frame); // Replace the standby frame with a more recent one.
        self.host_data
            .event_queue
            .push_back(PipelineEvent::NewFrame); // Should this be an event? We'd only need this to run once per tick, maybe use a boolean field
    }

    /// Begins processing by queuing a MotionStart event.
    pub fn start_working(&mut self) {
        self.host_data
            .event_queue
            .push_back(PipelineEvent::MotionStart);
    }

    /// Main loop to process events, update health/activity FSMs,
    /// emit telemetry, and dispatch intents.
    pub fn tick(&mut self, temp_label: &'static str) -> Result<bool, anyhow::Error> {
        // Is there a timer event?
        if let Some(e) = self.host_data.timer.poll() {
            self.host_data.event_queue.push_back(e);
        }

        // Is there a health event?
        let health_response = crate::logic::health_states::update(
            &mut self.host_data.ctx,
            &mut self.host_data.telemetry,
            temp_label,
        );

        if let Ok(Some(he)) = health_response {
            self.host_data.event_queue.push_back(he);
        } else if let Err(e) = health_response {
            // We should exit. Something's wrong with sensors...
            return Err(e);
        }

        self.host_data.event_queue.push_back(PipelineEvent::Tick);
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        self.max_event_queue_len = self
            .max_event_queue_len
            .max(self.host_data.event_queue.len());
        self.host_data
            .telemetry
            .write(&TelemetryPacket::TickStats {
                ts,
                run_id: self.host_data.ctx.run_id.clone(),
                activity: self.host_data.ctx.activity.as_str(),
                health: self.host_data.ctx.health.as_str(),
                event_queue_len: self.host_data.event_queue.len(),
                max_event_queue_len: self.max_event_queue_len,
                standby_has_frame: self.host_data.frame_buffer.standby.is_some(),
                active_has_frame: self.host_data.frame_buffer.active.is_some(),
            })?;

        // We'll read the new CPU, memory, temp values on Tick in FSM and based on that set throttles / etc accordingly

        while let Some(event) = self.host_data.event_queue.pop_front() {
            self.recorder.record_event(&event);
            let (new_activity_state, mut intents_a) = self.activity_registry.handle(
                &mut self.host_data.pipeline,
                &mut self.host_data.ctx,
                &event,
                |ctx| &ctx.activity,
            );

            match &self.last_activity_change {
                Some((prev_state, _)) if new_activity_state != *prev_state => {
                    if let Some((prev, t0)) = self.last_activity_change.take() {
                        let elapsed = t0.elapsed().as_millis();
                        self.host_data
                            .telemetry
                            .write(&TelemetryPacket::StateDuration {
                                run_id: self.host_data.ctx.run_id.clone(),
                                ts: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
                                fsm: "activity",
                                state: prev.as_str(),
                                duration_ms: elapsed,
                            })?;
                    }
                    self.last_activity_change = Some((new_activity_state.clone(), Instant::now()));
                }

                None => {
                    // First time initializing — don't emit telemetry, just record timestamp
                    self.last_activity_change = Some((new_activity_state.clone(), Instant::now()));
                }

                _ => {
                    // No state change — do nothing
                }
            }

            let (new_health_state, mut intents) = self.health_registry.handle(
                &mut self.host_data.pipeline,
                &mut self.host_data.ctx,
                &event,
                |ctx| &ctx.health,
            );

            match &self.last_health_change {
                Some((prev_state, _)) if new_health_state != *prev_state => {
                    if let Some((prev, t0)) = self.last_health_change.take() {
                        let elapsed = t0.elapsed().as_millis();
                        self.host_data
                            .telemetry
                            .write(&TelemetryPacket::StateDuration {
                                run_id: self.host_data.ctx.run_id.clone(),
                                ts: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
                                fsm: "health",
                                state: prev.as_str(),
                                duration_ms: elapsed,
                            })?;
                    }
                    self.last_health_change = Some((new_health_state.clone(), Instant::now()));
                }

                None => {
                    // First time initializing — don't emit telemetry, just record timestamp
                    self.last_health_change = Some((new_health_state.clone(), Instant::now()));
                }

                _ => {
                    // No state change — do nothing
                }
            }
            intents.append(&mut intents_a);

            for intent in intents {
                self.recorder.record_intent(&intent);
                self.intent_bus.execute(&mut self.host_data, &intent)?;
            }

            self.host_data.ctx.health = new_health_state;
            self.host_data.ctx.activity = new_activity_state;
        }

        Ok(true)
    }

    /// Dynamically injects a new pipeline stage at a specific index and logs the transition.
    #[allow(dead_code)]
    fn inject_stage<S: PipelineStage + 'static>(
        &mut self,
        pipeline: &mut Pipeline,
        stage: S,
        position: usize,
    ) -> Result<(), anyhow::Error> {
        //self.host_data.ctx.top_state = TopState::Degraded(DegradedState::ThrottledInference);

        self.intent_bus.execute(
            &mut self.host_data,
            &Intent::LogTransition {
                from: "Dynamic".into(),
                to: format!("Injected@{}", position),
                reason: "Live reconfig".into(),
                triggered_by: None,
            },
        )?;

        let mut stages = pipeline.stages.split_off(position);
        pipeline.stages.push(Box::new(stage));
        pipeline.stages.append(&mut stages);

        Ok(())
    }
}

impl Default for PipelineController {
    fn default() -> Self {
        todo!()
    }
}

/// Macro to concisely build a pipeline using a chained stage definition.
#[macro_export]
macro_rules! pipeline {
    ( $($stage:expr), * $(,)? ) => {{
        let mut builder = privastead_motion_ai::logic::pipeline::PipelineBuilder::new();
        $(
        builder = builder.then($stage);
        )*
        builder.build()
    }};
}
