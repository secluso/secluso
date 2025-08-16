use std::cmp::Reverse;
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
use crate::logic::stages::{PipelineStage, StageResult, StageType};
use crate::logic::telemetry::{TelemetryPacket, TelemetryRun};
use crate::logic::timer::{Timer, TimerManager};
use crate::ml::models::init_model_paths;
use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::collections::{BinaryHeap, BTreeMap, HashMap, VecDeque};
use std::default::Default;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use log::debug;

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
        telemetry: &mut TelemetryRun,
        ctx: &mut StateContext,
    ) -> Result<StageResult, anyhow::Error> {
        debug!("Running stage type {:?}", stage_type);
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
            host_data: PipelineHostData {
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
                    debug!("Motion detected {} seconds ago (within 30s window).", secs);
                    true
                } else {
                    debug!("Motion detected {} seconds ago (outside 30s window).", secs);
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

    // turn intent into a readable label
    fn intent_label(intent: &Intent) -> String {
        format!("{intent:?}")
    }

    // label for events for per-event stats
    fn event_label(event: &PipelineEvent) -> String {
        format!("{event:?}")
    }

    /// Main loop to process events, update health/activity FSMs,
    /// emit telemetry, and dispatch intents.
    pub fn tick(&mut self, temp_label: &'static str) -> Result<bool, anyhow::Error> {
        let time = SystemTime::now();

        // Is there a timer event?
        if let Some(e) = self.host_data.timer.poll() {
            self.host_data.event_queue.push_back(e);
        }

        let time_before_health = SystemTime::now();
        // Is there a health event?
        let health_response = crate::logic::health_states::update(
            &mut self.host_data.ctx,
            &mut self.host_data.telemetry,
            temp_label,
        );
        let health_elapsed = time_before_health.elapsed()?;

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
        let before_events_run = SystemTime::now();
        // High-level phase timers
        let mut t_record_event: u128 = 0;
        let mut t_activity_handle: u128 = 0;
        let mut t_health_handle: u128 = 0;
        let mut t_state_telemetry: u128 = 0;
        let mut t_record_intent: u128 = 0;
        let mut t_intent_execute: u128 = 0;
        let mut t_ctx_assign: u128 = 0;

        // fine-grained samples
        let mut intent_samples: Vec<(String, u128)> = Vec::with_capacity(64);
        let mut event_samples: Vec<(String, u128)> = Vec::with_capacity(64);

        let mut events_processed: u64 = 0;
        let mut intents_processed: u64 = 0;

        while let Some(event) = self.host_data.event_queue.pop_front() {
            let ev_label = Self::event_label(&event);

            let ev_t0 = Instant::now();

            // record_event
            {
                let t0 = Instant::now();
                t_record_event += t0.elapsed().as_millis() as u128;
            }

            // activity.handle(...)
            let (new_activity_state, mut intents_a) = {
                let t0 = Instant::now();
                let out = self.activity_registry.handle(
                    &mut self.host_data.pipeline,
                    &mut self.host_data.ctx,
                    &event,
                    |ctx| &ctx.activity,
                );
                t_activity_handle += t0.elapsed().as_millis() as u128;
                out
            };

            // activity state-change telemetry (if any)
            match &self.last_activity_change {
                Some((prev_state, _)) if new_activity_state != *prev_state => {
                    if let Some((prev, t0inst)) = self.last_activity_change.take() {
                        let elapsed = t0inst.elapsed().as_millis();
                        let t0 = Instant::now();
                        self.host_data.telemetry.write(&TelemetryPacket::StateDuration {
                            run_id: self.host_data.ctx.run_id.clone(),
                            ts: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
                            fsm: "activity",
                            state: prev.as_str(),
                            duration_ms: elapsed,
                        })?;
                        t_state_telemetry += t0.elapsed().as_millis() as u128;
                    }
                    self.last_activity_change = Some((new_activity_state.clone(), Instant::now()));
                }
                None => {
                    self.last_activity_change = Some((new_activity_state.clone(), Instant::now()));
                }
                _ => {}
            }

            // health.handle(...)
            let (new_health_state, mut intents) = {
                let t0 = Instant::now();
                let out = self.health_registry.handle(
                    &mut self.host_data.pipeline,
                    &mut self.host_data.ctx,
                    &event,
                    |ctx| &ctx.health,
                );
                t_health_handle += t0.elapsed().as_millis() as u128;
                out
            };

            // health state-change telemetry (if any)
            match &self.last_health_change {
                Some((prev_state, _)) if new_health_state != *prev_state => {
                    if let Some((prev, t0inst)) = self.last_health_change.take() {
                        let elapsed = t0inst.elapsed().as_millis();
                        let t0 = Instant::now();
                        self.host_data.telemetry.write(&TelemetryPacket::StateDuration {
                            run_id: self.host_data.ctx.run_id.clone(),
                            ts: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
                            fsm: "health",
                            state: prev.as_str(),
                            duration_ms: elapsed,
                        })?;
                        t_state_telemetry += t0.elapsed().as_millis() as u128;
                    }
                    self.last_health_change = Some((new_health_state.clone(), Instant::now()));
                }
                None => {
                    self.last_health_change = Some((new_health_state.clone(), Instant::now()));
                }
                _ => {}
            }

            intents.append(&mut intents_a);

            // intents loop with per-intent timing + label capture
            for intent in intents {
                let label = Self::intent_label(&intent);

                {
                    let t0 = Instant::now();
                    t_record_intent += t0.elapsed().as_millis();
                }

                let exec_t0 = Instant::now();
                self.intent_bus.execute(&mut self.host_data, &intent)?;
                let exec_ms = exec_t0.elapsed().as_millis();

                t_intent_execute += exec_ms;
                intents_processed += 1;
                intent_samples.push((label, exec_ms));
            }

            // assign new states
            {
                let t0 = Instant::now();
                self.host_data.ctx.health = new_health_state;
                self.host_data.ctx.activity = new_activity_state;
                t_ctx_assign += t0.elapsed().as_millis() as u128;
            }

            let ev_ms = ev_t0.elapsed().as_millis() as u128;
            event_samples.push((ev_label, ev_ms));
            events_processed += 1;
        }

        let event_run_time = before_events_run.elapsed()?;
        let total_elapsed = time.elapsed()?;

        if total_elapsed > Duration::from_millis(10_000) {
            println!("===START TICK===");
            println!("Total time: {}ms", total_elapsed.as_millis());
            println!("Health run time: {}ms", health_elapsed.as_millis());
            println!("Event run time: {}ms", event_run_time.as_millis());

            // phase breakdown
            let ert = event_run_time.as_millis() as u128;
            let print_item = |label: &str, ms: u128| {
                let pct = if ert > 0 { (ms as f64 * 100.0) / ert as f64 } else { 0.0 };
                println!("{:<22} {:>8} ms  ({:>5.1}%)", label, ms, pct);
            };
            println!("-- Event-time breakdown --");
            print_item("record_event", t_record_event);
            print_item("activity_handle", t_activity_handle);
            print_item("health_handle", t_health_handle);
            print_item("state_telemetry", t_state_telemetry);
            print_item("record_intent", t_record_intent);
            print_item("intent_execute", t_intent_execute);
            print_item("ctx_assign", t_ctx_assign);
            println!("events_processed: {events_processed}, intents_processed: {intents_processed}");

            // per-intent aggregation
            if !intent_samples.is_empty() {
                let mut agg: BTreeMap<String, (u64, u128, u128)> = BTreeMap::new();
                // value = (count, total_ms, max_ms)

                for (label, ms) in &intent_samples {
                    let e = agg.entry(label.clone()).or_insert((0, 0, 0));
                    e.0 += 1;
                    e.1 += *ms;
                    if *ms > e.2 { e.2 = *ms; }
                }

                println!("-- Intents by label (count / total / avg / max ms) --");
                // Sort by total desc for readability
                let mut rows: Vec<_> = agg.into_iter().collect();
                rows.sort_by_key(|(_, v)| Reverse(v.1)); // total desc

                for (label, (count, total, maxv)) in rows.iter().take(50) { // cap rows
                    let avg = if *count > 0 { (*total as f64) / (*count as f64) } else { 0.0 };
                    println!("{:<40} {:>5}  {:>8}  {:>7.2}  {:>8}",
                             label, count, total, avg, maxv);
                }

                // Top-N slowest single intent executions
                let mut topk: BinaryHeap<(u128, String)> = BinaryHeap::new();
                for (label, ms) in &intent_samples {
                    topk.push((*ms, label.clone()));
                    if topk.len() > 10 { topk.pop(); } // keep top 10
                }

                let mut slow_list: Vec<_> = topk.into_sorted_vec();
                slow_list.reverse(); // biggest first
                println!("-- Top 10 slowest intent calls (ms) --");
                for (ms, label) in slow_list {
                    println!("{:>6}  {}", ms, label);
                }
            }

            // per-event timing
            if !event_samples.is_empty() {
                let mut agg_ev: BTreeMap<String, (u64, u128, u128)> = BTreeMap::new();
                for (label, ms) in &event_samples {
                    let e = agg_ev.entry(label.clone()).or_insert((0, 0, 0));
                    e.0 += 1;
                    e.1 += *ms;
                    if *ms > e.2 { e.2 = *ms; }
                }

                println!("-- Events by label (count / total / avg / max ms) --");
                let mut rows: Vec<_> = agg_ev.into_iter().collect();
                rows.sort_by_key(|(_, v)| Reverse(v.1));
                for (label, (count, total, maxv)) in rows.iter().take(50) {
                    let avg = if *count > 0 { (*total as f64) / (*count as f64) } else { 0.0 };
                    println!("{:<32} {:>5}  {:>8}  {:>7.2}  {:>8}",
                             label, count, total, avg, maxv);
                }
            }

            println!("================\n");
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
