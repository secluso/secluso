//! SPDX-License-Identifier: GPL-3.0-or-later
mod events;
mod harden;
mod preflight;
mod provision;
mod script;
mod ssh;
pub(crate) mod types;

use crate::provision_server::events::{emit, log_line, step_error, step_ok, step_start, ProvisionEvent};
use crate::provision_server::harden::{check_password_auth, disable_password_auth as disable_password_auth_impl};
use crate::provision_server::preflight::run_preflight;
use crate::provision_server::provision::run_provision;
use crate::provision_server::ssh::{connect_ssh, fetch_host_key};
use crate::provision_server::types::{HostKeyProof, ServerPlan, ServerRuntimePlan, SshHostKeyTarget, SshTarget};
use anyhow::Result;
use serde::Serialize;
use tauri::AppHandle;
use uuid::Uuid;

// tauri commands

#[tauri::command]
pub async fn check_ssh_password_auth(target: SshTarget) -> Result<bool, String> {
  tokio::task::spawn_blocking(move || check_password_auth(&target))
    .await
    .map_err(|e| e.to_string())
    .and_then(|r| r.map_err(|e| e.to_string()))
}

#[tauri::command]
pub async fn disable_ssh_password_auth(target: SshTarget) -> Result<(), String> {
  tokio::task::spawn_blocking(move || disable_password_auth_impl(&target))
    .await
    .map_err(|e| e.to_string())
    .and_then(|r| r.map_err(|e| e.to_string()))
}

#[tauri::command]
pub async fn fetch_server_host_key(target: SshHostKeyTarget) -> Result<HostKeyProof, String> {
  // Host key discovery can block on DNS/TCP/SSH handshake
  // Thus, we should use async runtime just like test_server_ssh below and provision_server's background worker in this module.
  tokio::task::spawn_blocking(move || fetch_host_key(&target))
    .await
    .map_err(|e| e.to_string())
    .and_then(|r| r.map_err(|e| e.to_string()))
}

#[tauri::command]
pub async fn test_server_ssh(app: AppHandle, target: SshTarget, runtime: Option<ServerRuntimePlan>, server_url: Option<String>) -> Result<(), String> {
  let run_id = Uuid::new_v4();
  step_start(&app, run_id, "ssh_test", "Connecting via SSH");

  let app2 = app.clone();
  let res = tokio::task::spawn_blocking(move || -> Result<()> {
    let (sess, _temps) = connect_ssh(&target)?;
    step_ok(&app2, run_id, "ssh_test");
    step_start(&app2, run_id, "preflight", "Checking server compatibility");
    run_preflight(&app2, run_id, "preflight", &sess, &target, runtime.as_ref(), server_url.as_deref())?;
    step_ok(&app2, run_id, "preflight");
    Ok(())
  })
  .await
  .map_err(|e| e.to_string())
  .and_then(|r| r.map_err(|e| e.to_string()));

  match res {
    Ok(_) => {
      step_ok(&app, run_id, "ssh_test");
      emit(&app, ProvisionEvent::Done { run_id, ok: true });
      Ok(())
    }
    Err(e) => {
      step_error(&app, run_id, "ssh_test", &e);
      emit(&app, ProvisionEvent::Done { run_id, ok: false });
      Err(e)
    }
  }
}

#[derive(Debug, Serialize)]
pub struct ProvisionStart {
  pub run_id: Uuid,
}

#[tauri::command]
pub async fn provision_server(app: AppHandle, target: SshTarget, plan: ServerPlan) -> Result<ProvisionStart, String> {
  let run_id = Uuid::new_v4();

  // return so ui can start listening while work runs in the background
  let app2 = app.clone();
  tokio::task::spawn_blocking(move || {
    if let Err(e) = run_provision(&app2, run_id, target, plan) {
      // ensure we end with done false
      emit(&app2, ProvisionEvent::Done { run_id, ok: false });
      log_line(&app2, run_id, "error", Some("fatal"), format!("{e:#}"));
    } else {
      emit(&app2, ProvisionEvent::Done { run_id, ok: true });
    }
  });

  Ok(ProvisionStart { run_id })
}
