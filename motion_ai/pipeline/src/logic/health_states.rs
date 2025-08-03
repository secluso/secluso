use crate::config::{
    CPU_RESOURCE_CAP, MEMORY_RESOURCE_CAP, THRESH_TEMP_CRITICAL, THRESH_TEMP_HIGH,
};
use crate::logic::context::StateContext;
use crate::logic::fsm::{StateHandler, TransitionDecision};
use crate::logic::intent::Intent;
use crate::logic::pipeline::PipelineEvent::TemperatureDrop;
use crate::logic::pipeline::{Pipeline, PipelineEvent};
use crate::ml::models::ModelKind;
use std::fmt;

use crate::logic::telemetry::{TelemetryPacket, TelemetryRun};
use once_cell::sync::Lazy;
use serde::Deserialize;
use serde::Serialize;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use sysinfo::{Components, CpuRefreshKind, MemoryRefreshKind, RefreshKind, System};
use thiserror::Error;

/// Represents the health status of the system based on temperature and resource usage.
#[derive(Hash, Eq, PartialEq, Clone, Debug, Copy, Serialize, Deserialize)]
pub enum HealthState {
    Normal,
    HighTemp,
    ResourceLow,
    CriticalTemp,
}

/// Enables readable string formatting for HealthState enum values.
impl fmt::Display for HealthState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            HealthState::Normal => "Normal",
            HealthState::HighTemp => "HighTemp",
            HealthState::ResourceLow => "ResourceLow",
            HealthState::CriticalTemp => "CriticalTemp",
        };
        write!(f, "{}", name)
    }
}

/// Provides utility methods for HealthState (e.g. string conversion).
impl HealthState {
    pub fn as_str(&self) -> &'static str {
        match self {
            HealthState::Normal => "Normal",
            HealthState::HighTemp => "HighTemp",
            HealthState::ResourceLow => "ResourceLow",
            HealthState::CriticalTemp => "CriticalTemp",
        }
    }
}

/// Shared System instance for efficient hardware usage tracking.
static SYS: Lazy<Mutex<System>> = Lazy::new(|| {
    let kind = RefreshKind::nothing()
        .with_cpu(CpuRefreshKind::everything())
        .with_memory(MemoryRefreshKind::with_ram(Default::default()));
    Mutex::new(System::new_with_specifics(kind))
});

/// Checks system health and returns a PipelineEvent if the state changes.
pub fn update(
    ctx: &mut StateContext,
    telemetry: &mut TelemetryRun,
    temp_label: &'static str
) -> Result<Option<PipelineEvent>, anyhow::Error> {
    let temp = read_current_temp(temp_label)?;
    let cpu_and_mem = read_cpu_and_memory()?;

    let cpu = cpu_and_mem.cpu_pct;
    let mem = ((cpu_and_mem.used_kib as f32) / (cpu_and_mem.total_kib as f32)) * 100.0;

    telemetry.write(&TelemetryPacket::Health {
        run_id: ctx.run_id.clone(),
        cpu_pct: cpu,
        ram_pct: mem,
        temp_c: temp,
        ts: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time should go forward.")
            .as_millis(),
    })?;

    let next = if temp >= THRESH_TEMP_CRITICAL {
        HealthState::CriticalTemp
    } else if temp >= THRESH_TEMP_HIGH {
        HealthState::HighTemp
    } else if cpu >= CPU_RESOURCE_CAP || mem >= MEMORY_RESOURCE_CAP {
        HealthState::ResourceLow
    } else {
        HealthState::Normal
    };

    if next == ctx.health {
        return Ok(None);
    }

    let ev = match next {
        HealthState::HighTemp => PipelineEvent::TemperatureRise(temp),
        HealthState::CriticalTemp => PipelineEvent::CriticalTemperature(temp),
        HealthState::ResourceLow => PipelineEvent::ResourceLow,
        HealthState::Normal => match ctx.health {
            HealthState::HighTemp | HealthState::CriticalTemp => {
                PipelineEvent::TemperatureDrop(temp)
            }
            HealthState::ResourceLow => PipelineEvent::ResourceNormal,
            HealthState::Normal => return Ok(None),
        },
    };

    ctx.health = next;
    Ok(Some(ev))
}

/// State representing a healthy system — no throttling or adaptation.
pub struct NormalState;

/// Handles transitions from Normal to degraded health states.
impl StateHandler<HealthState> for NormalState {
    fn on_event(
        &mut self,
        _pipeline: &mut Pipeline,
        _ctx: &mut StateContext,
        e: &PipelineEvent,
    ) -> TransitionDecision<HealthState> {
        match e {
            PipelineEvent::TemperatureRise(_) => TransitionDecision::Transition {
                to: HealthState::HighTemp,
                reason: "temp high".into(),
                intents: vec![
                    Intent::SwitchModel(ModelKind::Fast),
                    Intent::AllowInference(true),
                ],
            },
            PipelineEvent::ResourceLow => TransitionDecision::Transition {
                to: HealthState::ResourceLow,
                reason: "cpu/ram high".into(),
                intents: vec![
                    Intent::SwitchModel(ModelKind::Fast),
                    Intent::AllowInference(true),
                ],
            },
            PipelineEvent::CriticalTemperature(_) => TransitionDecision::Transition {
                to: HealthState::CriticalTemp,
                reason: "temp critical".into(),
                intents: vec![Intent::AllowInference(false)],
            },
            _ => TransitionDecision::Stay(vec![Intent::NoOp]),
        }
    }
}

/// State representing elevated CPU temperature (non-critical).
pub struct HighTempState;

/// Transitions to Normal once the temperature drops sufficiently.
impl StateHandler<HealthState> for HighTempState {
    fn on_event(
        &mut self,
        _pipeline: &mut Pipeline,
        _ctx: &mut StateContext,
        e: &PipelineEvent,
    ) -> TransitionDecision<HealthState> {
        match e {
            TemperatureDrop(_) => TransitionDecision::Transition {
                to: HealthState::Normal,
                reason: "cooled below high".into(),
                intents: vec![
                    Intent::SwitchModel(ModelKind::Accurate), // <-- back to big model
                    Intent::AllowInference(true),
                ],
            },
            _ => TransitionDecision::Stay(vec![Intent::NoOp]),
        }
    }
}

/// State representing high CPU or memory usage.
pub struct ResourceLowState;

/// Transitions back to Normal when resource usage falls below threshold.
impl StateHandler<HealthState> for ResourceLowState {
    fn on_event(
        &mut self,
        _pipeline: &mut Pipeline,
        _ctx: &mut StateContext,
        e: &PipelineEvent,
    ) -> TransitionDecision<HealthState> {
        match e {
            PipelineEvent::ResourceNormal => TransitionDecision::Transition {
                to: HealthState::Normal,
                reason: "resources normal".into(),
                intents: vec![
                    Intent::SwitchModel(ModelKind::Accurate), // <-- restore
                    Intent::AllowInference(true),
                ],
            },
            _ => TransitionDecision::Stay(vec![Intent::NoOp]),
        }
    }
}

/// State representing critically high CPU temperature — disables inference.
pub struct CriticalTempState;

/// Waits for temperature to drop before transitioning out of critical state.
impl StateHandler<HealthState> for CriticalTempState {
    fn on_event(
        &mut self,
        _pipeline: &mut Pipeline,
        _ctx: &mut StateContext,
        e: &PipelineEvent,
    ) -> TransitionDecision<HealthState> {
        match e {
            TemperatureDrop(t) if *t < THRESH_TEMP_HIGH => TransitionDecision::Transition {
                to: HealthState::HighTemp,
                reason: "cooled below critical".into(),
                intents: vec![
                    Intent::AllowInference(false), // still throttled
                                                   // keep Fast model
                ],
            },
            _ => TransitionDecision::Stay(vec![Intent::NoOp]),
        }
    }
}

/// Represents possible errors when attempting to read temperature.
#[derive(Debug, Error)]
pub enum TempError {
    #[error("CPU temp sensor not found (expected label: {0})")]
    SensorNotFound(&'static str),
    #[error("CPU temp reading missing")]
    ReadingMissing,
}

/// Reads the current CPU temperature using system sensors.
pub fn read_current_temp(temp_label: &'static str) -> Result<f32, TempError> {
    let comps = Components::new_with_refreshed_list();

    comps
        .iter()
        .find(|c| c.label() == temp_label)
        .ok_or(TempError::SensorNotFound(temp_label))? //TODO: replace w/ RPI
        .temperature()
        .ok_or(TempError::ReadingMissing)
}

/// Captures current CPU load and memory usage snapshot.
pub struct CpuAndMemoryUsage {
    cpu_pct: f32,
    used_kib: u64,
    total_kib: u64,
}

/// Returns current CPU usage percentage and memory usage in KiB.
pub fn read_cpu_and_memory() -> Result<CpuAndMemoryUsage, anyhow::Error> {
    let mut sys = SYS
        .lock()
        .map_err(|_| anyhow::anyhow!("SYS mutex poisoned"))?;
    sys.refresh_cpu_usage();
    sys.refresh_memory();

    Ok(CpuAndMemoryUsage {
        cpu_pct: sys.global_cpu_usage(),
        used_kib: sys.used_memory(),
        total_kib: sys.total_memory(),
    })
}
