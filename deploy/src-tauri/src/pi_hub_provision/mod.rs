//! SPDX-License-Identifier: GPL-3.0-or-later
pub(crate) mod credentials;
mod events;
mod image_inject;
pub(crate) mod model;
mod prepare;
pub(crate) mod temp;

use crate::pi_hub_provision::credentials::generate_user_credentials_only;
use crate::pi_hub_provision::events::{emit, log_line, ProvisionEvent};
use crate::pi_hub_provision::model::SigKey;
use crate::pi_hub_provision::prepare::run_prepare_image;
use crate::pi_hub_provision::temp::shared_temp_dir;
use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Mutex;
use tauri::{AppHandle, State};
use uuid::Uuid;

// api wiring for tauri commands

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareImageRequest {
    qr_output_path: String,
    image_output_path: String,
    custom_wic_path: Option<String>,
    os_repo: Option<String>,
    binaries_repo: Option<String>,
    sig_keys: Option<Vec<SigKey>>,
    github_token: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareImageResponse {
    out_image: String,
}

#[derive(Debug, Serialize)]
pub struct BuildStart {
    pub run_id: Uuid,
}

// Holds a prepared run between prepare_image (registers it) and begin_run (starts it)
// lets the status page attach its event listener before any events are emitted..
// essentially this fixes a listener-attach race
#[derive(Default)]
pub struct PendingRuns(pub Mutex<HashMap<Uuid, PrepareImageRequest>>);

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateUserCredentialsRequest {
    server_url: String,
    output_path: String,
    qr_output_path: Option<String>,
}

#[tauri::command]
pub async fn generate_user_credentials(
    app: AppHandle,
    req: GenerateUserCredentialsRequest,
) -> std::result::Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || -> anyhow::Result<()> {
        let run_id = Uuid::new_v4();
        let work_dir = shared_temp_dir("secluso-user-creds").context("creating temp work dir")?;
        let work_path = work_dir.path();

        generate_user_credentials_only(
            &app,
            run_id,
            work_path,
            &req.server_url,
            "secluso/secluso",
            None,
            None,
        )?;

        let out_path = Path::new(&req.output_path);
        if let Some(parent) = out_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        fs::copy(work_path.join("user_credentials"), &req.output_path)
            .with_context(|| format!("copying user_credentials to {}", req.output_path))?;

        if let Some(qr_out) = &req.qr_output_path {
            let qr_src = work_path.join("user_credentials_qrcode.png");
            if qr_src.exists() {
                let qr_path = Path::new(qr_out);
                if let Some(parent) = qr_path.parent() {
                    if !parent.as_os_str().is_empty() {
                        fs::create_dir_all(parent)?;
                    }
                }
                fs::copy(&qr_src, qr_out)
                    .with_context(|| format!("copying QR code to {}", qr_out))?;
            } else {
                anyhow::bail!("Expected QR code missing at {}", qr_src.display());
            }
        }

        Ok(())
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(err_to_string)
}

// register the run and hand back its id.
#[tauri::command]
pub async fn prepare_image(
    pending: State<'_, PendingRuns>,
    req: PrepareImageRequest,
) -> std::result::Result<BuildStart, String> {
    let run_id = Uuid::new_v4();
    pending
        .0
        .lock()
        .map_err(|_| "pending-runs lock poisoned".to_string())?
        .insert(run_id, req);
    Ok(BuildStart { run_id })
}

// called once the listener is attached
#[tauri::command]
pub async fn begin_run(
    app: AppHandle,
    pending: State<'_, PendingRuns>,
    run_id: Uuid,
) -> std::result::Result<(), String> {
    let req = pending
        .0
        .lock()
        .map_err(|_| "pending-runs lock poisoned".to_string())?
        .remove(&run_id)
        .ok_or_else(|| "unknown or already-started run".to_string())?;
    let app2 = app.clone();

    tokio::task::spawn_blocking(move || match run_prepare_image(&app2, run_id, req) {
        Ok(result) => {
            log_line(
                &app2,
                run_id,
                "info",
                Some("result"),
                format!("Image saved at: {}", result.out_image),
            );
            emit(&app2, ProvisionEvent::Done { run_id, ok: true });
        }
        Err(e) => {
            log_line(&app2, run_id, "error", Some("fatal"), format!("{e:#}"));
            emit(&app2, ProvisionEvent::Done { run_id, ok: false });
        }
    });

    Ok(())
}

fn err_to_string(e: anyhow::Error) -> String {
    format!("{:#}", e)
}
