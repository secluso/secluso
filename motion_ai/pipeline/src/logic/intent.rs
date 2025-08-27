use crate::logic::activity_states::ActivityState;
use crate::logic::health_states::HealthState;
use crate::logic::pipeline::{PipelineEvent, PipelineHostData, RunId};
use crate::logic::stages::{StageResult, StageType};
use crate::logic::telemetry::TelemetryPacket;
use crate::ml::models::ModelKind;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use log::debug;

/// Represents actions or commands that can be issued within the pipeline to modify behavior, log transitions, or trigger processing stages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Intent {
    RunStage(StageType),    // Triggers execution of a specific pipeline stage
    StartTimer(Duration),   // Starts a countdown timer
    CancelTimer,            // Cancels any running timer
    AllowInference(bool),   // Enables or disables ML inference
    SwitchModel(ModelKind), // Switches active ML model
    LogActivity {
        // Logs an activity state transition
        from: ActivityState,
        to: ActivityState,
        reason: String,
    },
    LogHealth {
        // Logs a health state transition
        from: HealthState,
        to: HealthState,
        reason: String,
    },
    Chain(Vec<Intent>), // Executes a sequence of intents in order
    NoOp,               // Does nothing (placeholder)
    ActivateFrame,      // Promotes standby frame to active and saves PNG
    LogTransition {
        // Logs a generic FSM transition
        from: String,
        to: String,
        triggered_by: Option<PipelineEvent>,
        reason: String,
    },
    ConcludePipeline,
}

/// Dispatches and executes intents, modifying pipeline state or context as needed.
pub struct IntentBus;

impl IntentBus {
    /// Applies an intent to the pipeline system, possibly modifying state, triggering telemetry, or queuing events.
    pub(crate) fn execute(
        &self,
        host_data: &mut PipelineHostData,
        intent: &Intent,
    ) -> Result<(), anyhow::Error> {
        // TODO: Shouldn't this be the KIND of intent? Will this work?
        host_data
            .telemetry
            .write(&TelemetryPacket::IntentTriggered {
                run_id: host_data.ctx.run_id.clone(),
                intent: intent.clone(),
                ts: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("Time should go forward.")
                    .as_millis(),
            })?;

        match intent {
            // Moves a standby frame into the active buffer and logs it for analysis.
            Intent::ActivateFrame => {
                // Standby => None, Active => most recent frame
                let most_recent_frame = host_data.frame_buffer.standby.take();
                host_data.frame_buffer.active = most_recent_frame;
                host_data.ctx.run_id = RunId::new(); // We're now starting with a new frame, so we need a new way to identify it within our pipeline telemetry

                // When we encounter a new frame, we need to save a copy of it for later analysis after initially accepting it (as in, we have a new empty spot to process)
                if let Some(ref mut frame) = host_data.frame_buffer.active {
                    frame.save_png(
                        host_data.telemetry.run_id.clone().as_str(),
                        &host_data.ctx.run_id,
                        "acceptance",
                        false,
                    )?;
                }
            }

            // Executes a specific pipeline stage and generates appropriate events based on the result.
            Intent::RunStage(kind) => {
                // TODO: Based on the results here, we schedule more intents..

                let ctx = &mut host_data.ctx;
                let pipeline = &mut host_data.pipeline;
                let frame_buffer = &mut host_data.frame_buffer;
                let telemetry = &mut host_data.telemetry;
                match pipeline.run(kind.clone(), frame_buffer, telemetry, ctx)? {
                    StageResult::Continue => host_data
                        .event_queue
                        .push_back(PipelineEvent::StageSuccess(kind.clone())), // TODO: Make use of some success method
                    StageResult::Drop(reason) => {
                        host_data
                            .event_queue
                            .push_back(PipelineEvent::Drop(kind.clone(), reason));
                        // Drop is logged at the stage with a specific reason (no duplicate here).
                    } // TODO: Make use of some fail method to inform FSM
                    StageResult::Fault(msg) => {
                        log::error!("Fault in stage : {}", msg);
                        host_data
                            .event_queue
                            .push_back(PipelineEvent::Fault(kind.clone(), msg));
                    }
                }
            }

            // Starts a timer with a given duration.
            Intent::StartTimer(duration) => {
                host_data.timer.start(*duration);
            }

            // Cancels any running timer.
            Intent::CancelTimer => {
                //                println!("[Intent] Cancelling timer...");
                //                 TimerManager::global().deadline = None;
                host_data.timer.cancel()
            }

            // Executes a sequence of intents recursively.
            Intent::Chain(intents) => {
                for inner in intents {
                    self.execute(host_data, inner)?;
                }
            }

            // Logs an activity state transition and updates context.
            Intent::LogActivity { from, to, reason } => {
                println!("ACT: {from:?} -> {to:?} - {reason}");
                host_data.ctx.activity = *to;
            }

            // Logs a health state transition and updates context.
            Intent::LogHealth { from, to, reason } => {
                println!("HLT: {from:?} -> {to:?} -> {reason}");
                host_data.ctx.health = *to;
            }

            // Logs a generic finite state machine transition to telemetry.
            Intent::LogTransition {
                from,
                to,
                triggered_by: _triggered_by,
                reason,
            } => {
                let run_id = host_data.ctx.run_id.clone();
                host_data.telemetry.write(&TelemetryPacket::FSMTransition {
                    run_id,
                    from: from.as_str(),
                    to: to.as_str(),
                    reason: reason.as_str(),
                })?;
            }

            // Enables or disables the inference stage based on resource or health context.
            Intent::AllowInference(choice) => {
                host_data.ctx.use_inference = choice.clone(); // todo: check this flag when running InferenceStage to either run the stage or just return a blanket Continue
            }

            // Switches the active model and logs the transition based on current health context.
            Intent::SwitchModel(model) => {
                let prev_model = host_data.ctx.active_model;
                host_data.ctx.active_model = model.clone();

                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("time")
                    .as_millis();

                let from_s = prev_model.to_string();
                let to_s = model.to_string();
                let health_s = host_data.ctx.health.to_string();

                host_data.telemetry.write(&TelemetryPacket::ModelSwitch {
                    ts: now,
                    run_id: host_data.ctx.run_id.clone(),
                    from: from_s.as_str(),
                    to: to_s.as_str(),
                    reason: "health-driven",
                    health: health_s.as_str(),
                })?;
            }

            Intent::ConcludePipeline => {
                debug!("Updating last detection to now!");
                host_data.ctx.last_detection = Some(Instant::now());
                host_data.ctx.last_detection_frame = host_data.frame_buffer.active.take();
            }

            _ => {}
        }

        Ok(())
    }
}
