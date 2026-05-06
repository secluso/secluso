//! SPDX-License-Identifier: GPL-3.0-or-later
use serde::Serialize;
use tauri::{AppHandle, Emitter};
use uuid::Uuid;

#[derive(Debug, Serialize, Clone)]
#[serde(tag = "type")]
pub enum ProvisionEvent {
  #[serde(rename = "step_start")]
  StepStart {
    run_id: Uuid,
    step: String,
    title: String,
  },

  #[serde(rename = "log")]
  Log {
    run_id: Uuid,
    level: String,
    step: Option<String>,
    line: String,
  },

  #[serde(rename = "step_ok")]
  StepOk {
    run_id: Uuid,
    step: String,
  },

  #[serde(rename = "step_error")]
  StepError {
    run_id: Uuid,
    step: String,
    message: String,
  },

  #[serde(rename = "done")]
  Done {
    run_id: Uuid,
    ok: bool,
  },
}

pub fn emit(app: &AppHandle, ev: ProvisionEvent) {
  // ignore errors when no listener is attached
  let _ = app.emit("provision:event", ev);
}

pub fn step_start(app: &AppHandle, run_id: Uuid, step: &str, title: &str) {
  emit(
    app,
    ProvisionEvent::StepStart {
      run_id,
      step: step.to_string(),
      title: title.to_string(),
    },
  );
}

pub fn step_ok(app: &AppHandle, run_id: Uuid, step: &str) {
  emit(
    app,
    ProvisionEvent::StepOk {
      run_id,
      step: step.to_string(),
    },
  );
}

pub fn step_error(app: &AppHandle, run_id: Uuid, step: &str, msg: impl Into<String>) {
  emit(
    app,
    ProvisionEvent::StepError {
      run_id,
      step: step.to_string(),
      message: msg.into(),
    },
  );
}

pub fn log_line(app: &AppHandle, run_id: Uuid, level: &str, step: Option<&str>, line: impl Into<String>) {
  emit(
    app,
    ProvisionEvent::Log {
      run_id,
      level: level.to_string(),
      step: step.map(|s| s.to_string()),
      line: line.into(),
    },
  );
}
