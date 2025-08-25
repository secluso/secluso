use crate::logic::context::StateContext;
use crate::logic::fsm::{StateHandler, TransitionDecision};
use crate::logic::intent::Intent;
use crate::logic::pipeline::{Pipeline, PipelineEvent};
use crate::logic::stages::StageType;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::{Duration};

#[derive(Hash, Eq, PartialEq, Clone, Debug, Copy, Serialize, Deserialize)]
/// Activity lifecycle states for a single processing cycle
pub enum ActivityState {
    Idle,
    Primed,
    Detecting,
    Cooldown,
}

impl fmt::Display for ActivityState {
    /// Human-readable name used in logs/telemetry/UI
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            ActivityState::Idle => "Idle",
            ActivityState::Primed => "Primed",
            ActivityState::Detecting => "Detecting",
            ActivityState::Cooldown => "Cooldown",
        };
        write!(f, "{}", name)
    }
}
impl ActivityState {
    /// Static string form (no allocation) for hot paths, patterning
    pub fn as_str(&self) -> &'static str {
        match self {
            ActivityState::Idle => "Idle",
            ActivityState::Primed => "Primed",
            ActivityState::Detecting => "Detecting",
            ActivityState::Cooldown => "Cooldown",
        }
    }
}

pub struct IdleState;

impl StateHandler<ActivityState> for IdleState {
    /// Motion Start -> Primed (+ start 500ms timer), otherwise stay
    fn on_event(
        &mut self,
        _pipeline: &mut Pipeline,
        _ctx: &mut StateContext,
        event: &PipelineEvent,
    ) -> TransitionDecision<ActivityState> {
        match event {
            PipelineEvent::MotionStart => TransitionDecision::Transition {
                to: ActivityState::Primed,
                reason: "Motion".into(),
                intents: vec![Intent::StartTimer(Duration::from_millis(500))],
            },
            _ => TransitionDecision::Stay(vec![Intent::NoOp]),
        }
    }
}

pub struct PrimedState;

impl StateHandler<ActivityState> for PrimedState {
    /// New Frame -> Detecting (+ Activate Frame, run Motion), otherwise stay
    fn on_event(
        &mut self,
        _pipeline: &mut Pipeline,
        _ctx: &mut StateContext,
        event: &PipelineEvent,
    ) -> TransitionDecision<ActivityState> {
        match event {
            PipelineEvent::NewFrame => TransitionDecision::Transition {
                to: ActivityState::Detecting,
                reason: "New Frame".into(),
                intents: vec![Intent::ActivateFrame, Intent::RunStage(StageType::Motion)],
            },
            _ => TransitionDecision::Stay(vec![Intent::NoOp]),
        }
    }
}

pub struct DetectingState;

impl StateHandler<ActivityState> for DetectingState {
    /// Pipeline driver: on StageSuccess run next or finish -> Cooldown; Drop/Fault -> Cooldown
    fn on_event(
        &mut self,
        pipeline: &mut Pipeline,
        _ctx: &mut StateContext,
        event: &PipelineEvent,
    ) -> TransitionDecision<ActivityState> {
        match event {
            PipelineEvent::StageSuccess(stage) => {
                if let Some(next_stage) = pipeline.next_stage(stage.clone()) {
                    TransitionDecision::Stay(vec![Intent::RunStage(next_stage)])
                } else {
                    TransitionDecision::Transition {
                        to: ActivityState::Cooldown,
                        reason: "Pipeline complete".into(),
                        intents: vec![Intent::ConcludePipeline, Intent::StartTimer(Duration::from_millis(500))],
                    }
                }
            }
            PipelineEvent::Drop(stage_type, reason) => TransitionDecision::Transition {
                to: ActivityState::Cooldown,
                reason: format!(
                    "Requested frame drop at stage {:?} for reason {}",
                    stage_type, reason
                )
                .into(),
                intents: vec![Intent::StartTimer(Duration::from_millis(500))],
            },
            PipelineEvent::Fault(stage_type, reason) => TransitionDecision::Transition {
                to: ActivityState::Cooldown,
                reason: format!("Pipeline fault at stage {:?} : {}", stage_type, reason),
                intents: vec![Intent::StartTimer(Duration::from_millis(500))],
            },
            _ => TransitionDecision::Stay(vec![Intent::NoOp]),
        }
    }
}

pub struct CooldownState;

impl StateHandler<ActivityState> for CooldownState {
    /// BackoffExpired -> Primed, otherwise stay
    fn on_event(
        &mut self,
        _pipeline: &mut Pipeline,
        _ctx: &mut StateContext,
        event: &PipelineEvent,
    ) -> TransitionDecision<ActivityState> {
        match event {
            PipelineEvent::BackoffExpired => TransitionDecision::Transition {
                to: ActivityState::Primed,
                reason: "Timer expired".into(),
                intents: vec![Intent::NoOp],
            },
            _ => TransitionDecision::Stay(vec![Intent::NoOp]),
        }
    }
}
