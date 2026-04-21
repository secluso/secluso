//! SPDX-License-Identifier: GPL-3.0-or-later
use crate::pi_hub_provision::credentials::generate_user_credentials_only;
use crate::pi_hub_provision::temp::shared_temp_dir;
use crate::provision_server::events::{log_line, step_ok, step_start};
use crate::provision_server::preflight::run_preflight;
use crate::provision_server::script::remote_provision_script;
use crate::provision_server::ssh::{
  cleanup_remote_path, connect_ssh, create_remote_temp_dir, exec_remote_script_streaming, scp_upload_bytes, sudo_prefix,
};
use crate::provision_server::types::{ServerPlan, ServerSecrets, SshTarget};
use anyhow::{bail, Context, Result};
use reqwest::blocking::Client;
use secluso_update::{
  build_github_client, default_signers, download_and_verify_component, fetch_latest_release, Component as ReleaseComponent,
  Signer,
};
use secluso_client_server_lib::auth::parse_user_credentials;
use std::fs;
use std::path::PathBuf;
use std::thread::sleep;
use std::time::Duration;
use tauri::AppHandle;
use uuid::Uuid;

const INSTALL_PREFIX: &str = "/opt/secluso";
const SERVER_UNIT: &str = "secluso-server.service";
const UPDATER_SERVICE: &str = "secluso-updater.service";
const UPDATE_INTERVAL_SECS: &str = "1800";

struct DownloadedArtifacts {
  release_tag: String,
  server_manifest_version: String,
  server_bytes: Vec<u8>,
  updater_bytes: Vec<u8>,
}

fn remote_stage_path(stage_dir: &str, name: &str) -> String {
  format!("{stage_dir}/{name}")
}

fn normalize_repo(input: &str) -> String {
  let trimmed = input.trim().trim_end_matches('/');
  if let Some(idx) = trimmed.find("github.com/") {
    let repo = &trimmed[idx + "github.com/".len()..];
    return repo.trim_end_matches(".git").to_string();
  }
  trimmed.trim_end_matches(".git").to_string()
}

fn resolve_signers(sig_keys: &[crate::provision_server::types::SigKey]) -> Vec<Signer> {
  if sig_keys.is_empty() {
    return default_signers();
  }

  sig_keys
    .iter()
    .map(|key| Signer {
      label: key.name.trim().to_string(),
      github_user: key.github_user.trim().to_string(),
      fingerprint: key
        .fingerprint
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned),
    })
    .collect()
}

fn download_verified_artifacts(
  app: &AppHandle,
  run_id: Uuid,
  owner_repo: &str,
  remote_arch: &str,
  sig_keys: &[crate::provision_server::types::SigKey],
  github_token: Option<&str>,
) -> Result<DownloadedArtifacts> {
  let signers = resolve_signers(sig_keys);
  let client = build_github_client(20, github_token, "secluso-deploy")?;
  let release = fetch_latest_release(&client, owner_repo)
    .with_context(|| format!("Fetching latest release metadata for {owner_repo}"))?;
  log_line(
    app,
    run_id,
    "info",
    Some("artifacts"),
    format!("Latest immutable release for {owner_repo}: {}", release.tag_name),
  );

  let server_verified = download_and_verify_component(
    &client,
    &release,
    ReleaseComponent::Server,
    remote_arch,
    None,
    &signers,
  )
  .with_context(|| format!("Downloading and verifying secluso-server for {remote_arch}"))?;

  let bundle_dir = shared_temp_dir("secluso-server-bundle").context("creating temp bundle dir")?;
  let bundle_path = bundle_dir.path().join("release.zip");
  fs::write(&bundle_path, &server_verified.bundle_bytes)
    .with_context(|| format!("writing temporary bundle {}", bundle_path.display()))?;

  let updater_verified = download_and_verify_component(
    &client,
    &release,
    ReleaseComponent::Updater,
    remote_arch,
    Some(bundle_path.to_str().context("bundle path is not valid UTF-8")?),
    &signers,
  )
  .with_context(|| format!("Downloading and verifying secluso-update for {remote_arch}"))?;

  log_line(
    app,
    run_id,
    "info",
    Some("artifacts"),
    format!(
      "Verified release bundle {} for {} (server={} bytes, updater={} bytes).",
      release.tag_name,
      remote_arch,
      server_verified.component_bytes.len(),
      updater_verified.component_bytes.len()
    ),
  );

  Ok(DownloadedArtifacts {
    release_tag: server_verified.release_tag,
    server_manifest_version: server_verified.manifest_version,
    server_bytes: server_verified.component_bytes,
    updater_bytes: updater_verified.component_bytes,
  })
}

pub fn run_provision(app: &AppHandle, run_id: Uuid, target: SshTarget, plan: ServerPlan) -> Result<()> {
  let owner_repo = plan
    .binaries_repo
    .as_ref()
    .map(|repo| normalize_repo(repo))
    .unwrap_or_else(|| "secluso/secluso".to_string());

  step_start(app, run_id, "ssh_connect", "Connecting via SSH");
  let (sess, _temps) = connect_ssh(&target)?;
  step_ok(app, run_id, "ssh_connect");

  let (sudo_cmd, sudo_pw) = sudo_prefix(&target);

  step_start(app, run_id, "preflight", "Checking server compatibility");
  let preflight = run_preflight(
    app,
    run_id,
    "preflight",
    &sess,
    &target,
    Some(&plan.runtime),
    plan.secrets.as_ref().map(|value| value.server_url.as_str()),
  )?;
  step_ok(app, run_id, "preflight");

  cleanup_preflight_helpers(app, run_id, &sess, &sudo_cmd, sudo_pw.as_deref())?;

  // detect remote state
  step_start(app, run_id, "detect", "Detecting remote install state");
  let remote_has_bin = preflight.remote_has_bin;
  let remote_has_unit = preflight.remote_has_unit;
  log_line(app, run_id, "info", Some("detect"), format!("REMOTE_HAS_BIN={remote_has_bin}"));
  log_line(app, run_id, "info", Some("detect"), format!("REMOTE_HAS_UNIT={remote_has_unit}"));
  log_line(app, run_id, "info", Some("detect"), format!("REMOTE_SERVICE_ACTIVE={}", preflight.service_active));
  log_line(
    app,
    run_id,
    "info",
    Some("detect"),
    format!(
      "REMOTE_SERVER_VERSION={}",
      preflight.installed_version.clone().unwrap_or_else(|| "unknown".to_string())
    ),
  );
  log_line(
    app,
    run_id,
    "info",
    Some("detect"),
    format!("REMOTE_PORT_{}_IN_USE={}", plan.runtime.listen_port, preflight.port_in_use),
  );
  step_ok(app, run_id, "detect");

  let overwrite = plan.overwrite.unwrap_or(false);
  let sig_keys = plan.sig_keys.clone().unwrap_or_default();

  // decide if this is a first install
  let first_install = overwrite || !(remote_has_bin && remote_has_unit);
  if !first_install && !preflight.remote_has_credentials_full {
    bail!(
      "Existing install is missing /var/lib/secluso/credentials_full. That older server layout is no longer updated in place. Turn on Overwrite existing install to replace it cleanly."
    );
  }

  let mut generated_user_credentials: Option<Vec<u8>> = None;
  // Give each provisioning run its own remote staging dir.
  // Installer now reads inputs from one private per-run location instead of fixed top-level temp paths.
  let remote_stage_dir = create_remote_temp_dir(&sess, "secluso-provision")
    .context("creating remote staging dir")?;

  let provision_result = (|| -> Result<()> {
    step_start(app, run_id, "artifacts", "Downloading verified release binaries");
    let artifacts = download_verified_artifacts(
      app,
      run_id,
      &owner_repo,
      &preflight.remote_arch,
      &sig_keys,
      plan.github_token.as_deref(),
    )?;
    // Keep the uploaded binaries non-executable here.
    // They only become executable when the remote installer places them into the actual install path.
    scp_upload_bytes(
      &sess,
      &remote_stage_path(&remote_stage_dir, "secluso-server"),
      0o600,
      &artifacts.server_bytes,
    )?;
    scp_upload_bytes(
      &sess,
      &remote_stage_path(&remote_stage_dir, "secluso-update"),
      0o600,
      &artifacts.updater_bytes,
    )?;
    step_ok(app, run_id, "artifacts");

    // step 2 generate and upload secrets
    step_start(app, run_id, "secrets", "Preparing runtime secrets");
    let secrets = plan.secrets.as_ref().context("Missing secrets config")?;
    let sa_path = PathBuf::from(&secrets.service_account_key_path);
    let sa = std::fs::read(&sa_path).with_context(|| format!("Missing service account key at {}", sa_path.display()))?;
    scp_upload_bytes(
      &sess,
      &remote_stage_path(&remote_stage_dir, "service_account_key.json"),
      0o600,
      &sa,
    )?;

    if first_install {
      let work_dir = shared_temp_dir("secluso-server-creds").context("creating temp work dir")?;
      let work_path = work_dir.path();
      let sig_keys = plan.sig_keys.as_ref().map(|keys| {
        keys
          .iter()
          .map(|k| crate::pi_hub_provision::model::SigKey {
            name: k.name.trim().to_string(),
            github_user: k.github_user.trim().to_string(),
            fingerprint: k
              .fingerprint
              .as_deref()
              .map(str::trim)
              .filter(|v| !v.is_empty())
              .map(ToOwned::to_owned),
          })
          .collect::<Vec<_>>()
      });
      generate_user_credentials_only(
        app,
        run_id,
        work_path,
        &secrets.server_url,
        &owner_repo,
        sig_keys.as_deref(),
        plan.github_token.as_deref(),
      )?;

      let uc_path = work_path.join("user_credentials");
      let uc = std::fs::read(&uc_path).with_context(|| format!("Missing user credentials at {}", uc_path.display()))?;
      let credentials_full_path = work_path.join("credentials_full");
      let credentials_full = std::fs::read(&credentials_full_path)
        .with_context(|| format!("Missing credentials_full at {}", credentials_full_path.display()))?;

      let qr_src = work_path.join("user_credentials_qrcode.png");
      if !qr_src.exists() {
        bail!("Missing QR code at {}", qr_src.display());
      }
      let qr_path = PathBuf::from(&secrets.user_credentials_qr_path);
      if let Some(parent) = qr_path.parent() {
        if !parent.as_os_str().is_empty() {
          std::fs::create_dir_all(parent)?;
        }
      }
      std::fs::copy(&qr_src, &qr_path).with_context(|| format!("Saving QR code to {}", qr_path.display()))?;

      scp_upload_bytes(
        &sess,
        &remote_stage_path(&remote_stage_dir, "user_credentials"),
        0o600,
        &uc,
      )?;
      scp_upload_bytes(
        &sess,
        &remote_stage_path(&remote_stage_dir, "credentials_full"),
        0o600,
        &credentials_full,
      )?;
      generated_user_credentials = Some(uc);
    } else {
      log_line(
        app,
        run_id,
        "info",
        Some("secrets"),
        "Existing install detected. Leaving the current server credentials unchanged.".to_string(),
      );
    }
    step_ok(app, run_id, "secrets");

    // step 3 run the remote provision script
    step_start(app, run_id, "remote", "Running remote installer");
    let mut envs = vec![
      ("INSTALL_PREFIX", INSTALL_PREFIX.to_string()),
      ("OWNER_REPO", owner_repo.to_string()),
      ("SERVER_UNIT", SERVER_UNIT.to_string()),
      ("UPDATER_SERVICE", UPDATER_SERVICE.to_string()),
      ("UPDATE_INTERVAL_SECS", UPDATE_INTERVAL_SECS.to_string()),
      ("BIND_ADDRESS", plan.runtime.bind_address.clone()),
      ("LISTEN_PORT", plan.runtime.listen_port.to_string()),
      ("SUDO_CMD", sudo_cmd.clone()),
      ("ENABLE_UPDATER", if plan.auto_updater.enable { "1".to_string() } else { "0".to_string() }),
      ("OVERWRITE", if overwrite { "1".to_string() } else { "0".to_string() }),
      ("FIRST_INSTALL", if first_install { "1".to_string() } else { "0".to_string() }),
      ("RELEASE_TAG", artifacts.release_tag.clone()),
      // The remote script only trusts staged inputs under this directory for this run.
      ("STAGING_DIR", remote_stage_dir.clone()),
      (
        "SIG_KEYS",
        sig_keys
          .iter()
          .map(|k| {
            let mut value = format!("{}:{}", k.name.trim(), k.github_user.trim());
            if let Some(fingerprint) = k.fingerprint.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
              value.push(':');
              value.push_str(fingerprint);
            }
            value
          })
          .filter(|v| !v.trim().is_empty())
          .collect::<Vec<_>>()
          .join(","),
      ),
    ];
    if let Some(token) = plan.github_token.as_ref().map(|v| v.trim().to_string()).filter(|v| !v.is_empty()) {
      envs.push(("GITHUB_TOKEN", token));
    }
    exec_remote_script_streaming(
      app,
      run_id,
      "remote",
      &sess,
      &envs.iter().map(|(k, v)| (*k, v.clone())).collect::<Vec<_>>(),
      sudo_pw,
      remote_provision_script(),
    )?;

    step_ok(app, run_id, "remote");

    step_start(app, run_id, "health", "Checking public server health");
    if first_install {
      if let Some(uc) = generated_user_credentials.as_ref() {
        let probe_version = plan
          .manifest_version_override
          .as_deref()
          .map(str::trim)
          .filter(|value| !value.is_empty())
          .unwrap_or(&artifacts.server_manifest_version);
        verify_public_server_health(app, run_id, &plan, secrets, probe_version, uc)?;
      } else {
        log_line(app, run_id, "warn", Some("health"), "Skipping public health check because generated credentials are unavailable.".to_string());
      }
    } else {
      log_line(
        app,
        run_id,
        "info",
        Some("health"),
        "Skipping public health check for update-only runs because no new credentials were generated.".to_string(),
      );
    }
    step_ok(app, run_id, "health");
    Ok(())
  })();

  // Old staged binaries and secrets do not need to hang around after the run finishes.
  let cleanup_result = cleanup_remote_path(&sess, &remote_stage_dir);
  if let Err(err) = provision_result {
    let _ = cleanup_result;
    return Err(err);
  }
  cleanup_result?;
  Ok(())
}

fn cleanup_preflight_helpers(
  app: &AppHandle,
  run_id: Uuid,
  sess: &ssh2::Session,
  sudo_cmd: &str,
  sudo_pw: Option<&str>,
) -> Result<()> {
  let systemctl_prefix = if sudo_cmd.is_empty() {
    "systemctl".to_string()
  } else {
    format!("{sudo_cmd} systemctl")
  };
  let shell_prefix = if sudo_cmd.is_empty() {
    "".to_string()
  } else {
    format!("{sudo_cmd} ")
  };

  let script = format!(
    "set +e\n\
if command -v systemctl >/dev/null 2>&1; then\n\
  units=\"$({systemctl_prefix} list-units --all --plain --no-legend 'secluso-preflight-http-*' 2>/dev/null | awk '{{print $1}}')\"\n\
  if [ -n \"$units\" ]; then\n\
    while IFS= read -r unit; do\n\
      [ -z \"$unit\" ] && continue\n\
      {systemctl_prefix} stop \"$unit\" >/dev/null 2>&1 || true\n\
      {systemctl_prefix} reset-failed \"$unit\" >/dev/null 2>&1 || true\n\
    done <<'EOF'\n\
$units\n\
EOF\n\
  fi\n\
fi\n\
{shell_prefix}rm -rf /tmp/secluso-preflight-http.* >/dev/null 2>&1 || true\n\
exit 0\n"
  );

  exec_remote_script_streaming(
    app,
    run_id,
    "preflight",
    sess,
    &[],
    sudo_pw.map(str::to_string),
    &script,
  )?;
  Ok(())
}

fn verify_public_server_health(
  app: &AppHandle,
  run_id: Uuid,
  plan: &ServerPlan,
  secrets: &ServerSecrets,
  probe_version: &str,
  user_credentials: &[u8],
) -> Result<()> {
  let (username, password) = parse_user_credentials(user_credentials.to_vec()).context("Parsing generated user credentials")?;
  let status_url = format!("{}/status", secrets.server_url.trim_end_matches('/'));
  let client = Client::builder()
    .timeout(Duration::from_secs(15))
    .build()
    .context("Creating HTTP client for post-install health check")?;

  log_line(
    app,
    run_id,
    "info",
    Some("health"),
    "Checking the public /status endpoint from this computer.".to_string(),
  );

  let mut discovered_version = None;
  probe_public_server_health(
    &client,
    &status_url,
    &plan.runtime.exposure_mode,
    plan.runtime.listen_port,
    probe_version,
    &username,
    &password,
    8,
    Duration::from_secs(2),
    |attempt| {
      log_line(
        app,
        run_id,
        "warn",
        Some("health"),
        format!("Public /status probe not ready yet (attempt {attempt}/8). Retrying..."),
      );
    },
    |server_version| {
      discovered_version = Some(server_version.to_string());
    },
  )?;

  if let Some(server_version) = discovered_version {
    log_line(app, run_id, "info", Some("health"), format!("Remote server version header: {server_version}"));
  }

  log_line(
    app,
    run_id,
    "info",
    Some("health"),
    "Authenticated public health check succeeded.".to_string(),
  );
  Ok(())
}

fn unreachable_public_status_error(exposure_mode: &str, listen_port: u16, err: &reqwest::Error) -> anyhow::Error {
  if exposure_mode == "proxy" {
    anyhow::anyhow!(
      "Secluso finished installing, but the public /status endpoint is not reachable from this computer yet: {}. Check your reverse proxy route, TLS setup, and whether it forwards to 127.0.0.1:{}.",
      err,
      listen_port
    )
  } else {
    anyhow::anyhow!(
      "Secluso finished installing, but the public /status endpoint is not reachable from this computer yet: {}. Check that port {} is open in the server firewall and your provider security group.",
      err,
      listen_port
    )
  }
}

fn probe_public_server_health<F, G>(
  client: &Client,
  status_url: &str,
  exposure_mode: &str,
  listen_port: u16,
  probe_version: &str,
  username: &str,
  password: &str,
  max_attempts: usize,
  retry_delay: Duration,
  mut on_retry: F,
  mut on_version: G,
) -> Result<()>
where
  F: FnMut(usize),
  G: FnMut(&str),
{
  let mut discover = None;
  let mut last_discover_err = None;
  for attempt in 1..=max_attempts {
    match client
      .get(status_url)
      .header("Client-Version", probe_version)
      .send()
    {
      Ok(response) => {
        discover = Some(response);
        break;
      }
      Err(err) => {
        last_discover_err = Some(err);
        if attempt < max_attempts {
          on_retry(attempt);
          sleep(retry_delay);
        }
      }
    }
  }

  let discover = match discover {
    Some(response) => response,
    None => {
      let err = last_discover_err.context("Public /status probe failed without an error.")?;
      return Err(unreachable_public_status_error(exposure_mode, listen_port, &err));
    }
  };

  let server_version = discover
    .headers()
    .get("X-Server-Version")
    .and_then(|value| value.to_str().ok())
    .map(|value| value.to_string());

  let Some(server_version) = server_version else {
    bail!("Reached the server, but it did not return X-Server-Version. This does not look like a healthy Secluso server response.");
  };
  on_version(&server_version);

  let auth = client
    .get(status_url)
    .header("Client-Version", &server_version)
    .basic_auth(username, Some(password))
    .send()
    .context("Authenticated health check failed.")?;

  if !auth.status().is_success() {
    bail!(
      "The server is reachable, but the authenticated /status check failed with HTTP {}.",
      auth.status()
    );
  }

  Ok(())
}
