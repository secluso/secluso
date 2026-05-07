//! SPDX-License-Identifier: GPL-3.0-or-later
use crate::provision_server::events::log_line;
use crate::provision_server::ssh::sudo_prefix;
use crate::provision_server::types::{ServerRuntimePlan, SshAuth, SshTarget};
use anyhow::{bail, Context, Result};
use reqwest::blocking::Client;
use ssh2::Session;
use std::io::{Read, Write};
use std::thread::sleep;
use std::time::Duration;
use tauri::AppHandle;
use url::Url;
use uuid::Uuid;

pub const DEFAULT_SERVER_HTTP_PORT: u16 = 8000;
const MIN_DISK_KB: u64 = 3 * 1024 * 1024;
const WARN_MEM_KB: u64 = 768 * 1024;
const PUBLIC_PROBE_ATTEMPTS: usize = 2;
const PUBLIC_PROBE_RETRY_DELAY: Duration = Duration::from_secs(1);
const PUBLIC_PROBE_HTTP_TIMEOUT: Duration = Duration::from_secs(3);
const REMOTE_HTTPS_PROBE_MAX_TIME_SECS: u64 = 3;
const REMOTE_PROBE_START_TIMEOUT_SECS: u64 = 8;

struct TempHttpProbe {
  unit_name: String,
  root_dir: String,
  uses_sudo: bool,
}

pub struct PreflightReport {
  pub remote_has_bin: bool,
  pub remote_has_unit: bool,
  pub service_active: bool,
  pub installed_version: Option<String>,
  pub port_in_use: bool,
  pub remote_has_credentials_full: bool,
  pub remote_arch: String,
}

struct ExecResult {
  stdout: String,
  stderr: String,
  exit: i32,
}

pub fn run_preflight(
  app: &AppHandle,
  run_id: Uuid,
  step: &str,
  sess: &Session,
  target: &SshTarget,
  runtime: Option<&ServerRuntimePlan>,
  public_server_url: Option<&str>,
) -> Result<PreflightReport> {
  log_line(app, run_id, "info", Some(step), "Starting server preflight checks.");

  let uname = remote_shell(sess, "uname -s", None)?;
  let kernel = uname.stdout.trim();
  if kernel != "Linux" {
    bail!("Unsupported remote OS: expected Linux, got {kernel}.");
  }
  log_line(app, run_id, "info", Some(step), format!("Remote OS kernel: {kernel}"));

  let os_release = remote_shell(sess, "if [ -f /etc/os-release ]; then cat /etc/os-release; fi", None)?;
  let pretty_name = parse_os_release_field(&os_release.stdout, "PRETTY_NAME");
  let distro_id = parse_os_release_field(&os_release.stdout, "ID");
  let distro_like = parse_os_release_field(&os_release.stdout, "ID_LIKE");
  if let Some(name) = pretty_name {
    log_line(app, run_id, "info", Some(step), format!("Remote distribution: {name}"));
  }
  if !remote_success(sess, "command -v apt-get >/dev/null 2>&1", None)? {
    bail!("This server does not provide apt-get. Automatic provisioning currently expects a Debian/Ubuntu-style Linux server.");
  }
  if distro_id.as_deref() != Some("debian")
    && distro_id.as_deref() != Some("ubuntu")
    && !distro_like
      .as_deref()
      .unwrap_or_default()
      .split_whitespace()
      .any(|v| v == "debian" || v == "ubuntu")
  {
    log_line(
      app,
      run_id,
      "warn",
      Some(step),
      "This distro is not clearly Debian/Ubuntu-like. Provisioning may still work because apt-get exists, but it is less certain.".to_string(),
    );
  }

  let pid1 = remote_shell(sess, "ps -p 1 -o comm= | tr -d '[:space:]'", None)?;
  if pid1.stdout.trim() != "systemd" {
    bail!("PID 1 is not systemd. Secluso provisioning expects a systemd-based Linux server.");
  }
  if !remote_success(sess, "command -v systemctl >/dev/null 2>&1", None)? {
    bail!("systemctl is missing. Secluso provisioning expects systemd utilities to be installed.");
  }

  verify_sudo_access(app, run_id, step, sess, target)?;

  let arch = remote_shell(sess, "uname -m", None)?;
  let arch = arch.stdout.trim();
  let remote_arch = match arch {
    "x86_64" => "x86_64".to_string(),
    "aarch64" | "arm64" => "aarch64".to_string(),
    other => bail!("Unsupported CPU architecture: {other}. Supported server architectures are x86_64 and aarch64."),
  };
  log_line(
    app,
    run_id,
    "info",
    Some(step),
    format!("Remote CPU architecture: {arch} (using bundle target {remote_arch})"),
  );

  let disk = remote_shell(sess, "df -Pk / | awk 'NR==2 {print $4}'", None)?;
  let avail_kb = parse_u64_field(disk.stdout.trim(), "available disk space")?;
  if avail_kb < MIN_DISK_KB {
    bail!(
      "Not enough free disk space on /. Need at least about 3 GiB available, found {:.1} MiB.",
      avail_kb as f64 / 1024.0
    );
  }
  log_line(
    app,
    run_id,
    "info",
    Some(step),
    format!("Free disk space on /: {:.1} GiB", avail_kb as f64 / 1024.0 / 1024.0),
  );

  let mem = remote_shell(sess, "awk '/MemAvailable:/ {print $2}' /proc/meminfo", None)?;
  let mem_kb = parse_u64_field(mem.stdout.trim(), "available memory")?;
  if mem_kb < WARN_MEM_KB {
    log_line(
      app,
      run_id,
      "warn",
      Some(step),
      format!(
        "Low available memory detected: {:.0} MiB. Secluso may still install, but downloads, updates, and first startup may be slower.",
        mem_kb as f64 / 1024.0
      ),
    );
  } else {
    log_line(
      app,
      run_id,
      "info",
      Some(step),
      format!("Available memory: {:.0} MiB", mem_kb as f64 / 1024.0),
    );
  }

  verify_outbound_network(app, run_id, step, sess)?;

  let remote_has_bin = remote_success(sess, "test -x /usr/bin/secluso-server", None)?;
  let remote_has_unit = remote_success(
    sess,
    "systemctl list-unit-files --type=service | awk '{print $1}' | grep -qx 'secluso-server.service'",
    None,
  )?;
  let service_active = remote_success(sess, "systemctl is-active --quiet secluso-server.service", None)?;
  let remote_has_credentials_full = remote_success(sess, "test -f /var/lib/secluso/credentials_full", None)?;
  let version = if remote_has_bin {
    let out = remote_shell(
      sess,
      "if [ -x /usr/bin/secluso-server ]; then /usr/bin/secluso-server --version 2>/dev/null | head -n1; fi",
      None,
    )?;
    let trimmed = out.stdout.trim();
    if trimmed.is_empty() { None } else { Some(trimmed.to_string()) }
  } else {
    None
  };

  if remote_has_bin || remote_has_unit {
    log_line(
      app,
      run_id,
      "info",
      Some(step),
      format!(
        "Existing install detected: binary={}, unit={}, active={}, version={}",
        remote_has_bin,
        remote_has_unit,
        service_active,
        version.clone().unwrap_or_else(|| "unknown".to_string())
      ),
    );
    if !remote_has_credentials_full {
      log_line(
        app,
        run_id,
        "warn",
        Some(step),
        "Existing install is missing /var/lib/secluso/credentials_full. This older layout is no longer upgraded in place; use Overwrite existing install for a clean reinstall.".to_string(),
      );
    }
  } else {
    log_line(app, run_id, "info", Some(step), "No existing Secluso server install detected.".to_string());
  }

  let listen_port = runtime.map(|value| value.listen_port).unwrap_or(DEFAULT_SERVER_HTTP_PORT);
  let removed_stale_probe = cleanup_stale_preflight_port_listener(app, run_id, step, sess, target, listen_port)?;
  if removed_stale_probe {
    log_line(
      app,
      run_id,
      "info",
      Some(step),
      format!("Removed a stale temporary preflight listener from port {listen_port} before re-checking the port."),
    );
  }
  let port_probe = remote_with_optional_sudo(
    sess,
    target,
    &format!("ss -ltnpH | awk '$4 ~ /:{}$/ {{print}}'", listen_port),
    &format!("ss -ltnH | awk '$4 ~ /:{}$/ {{print}}'", listen_port),
  )?;
  let port_lines = port_probe
    .stdout
    .lines()
    .map(str::trim)
    .filter(|line| !line.is_empty())
    .collect::<Vec<_>>();
  let port_in_use = !port_lines.is_empty();
  let mut occupied_by_secluso =
    port_probe.stdout.contains("secluso-server")
      || port_probe.stdout.contains("/usr/bin/secluso-server")
      || service_active;
  if port_in_use {
    for line in &port_lines {
      log_line(app, run_id, "warn", Some(step), format!("Port {listen_port} listener: {line}"));
    }
    if !occupied_by_secluso {
      if let Some(status_url) = direct_status_url_for_preflight(runtime, public_server_url, listen_port)? {
        match verify_existing_secluso_status_endpoint(app, run_id, step, status_url.as_ref()) {
          Ok(()) => {
            occupied_by_secluso = true;
            log_line(
              app,
              run_id,
              "info",
              Some(step),
              format!("Port {listen_port} is already serving a healthy Secluso endpoint."),
            );
          }
          Err(err) => {
            log_line(
              app,
              run_id,
              "warn",
              Some(step),
              format!("Port {listen_port} is in use, and the existing listener did not look like a healthy Secluso endpoint: {err:#}"),
            );
          }
        }
      }
    }

    if !occupied_by_secluso {
      bail!(
        "Port {listen_port} is already in use by another service or stale listener. Listener details: {}",
        port_lines.join(" | ")
      );
    }
    log_line(
      app,
      run_id,
      "warn",
      Some(step),
      format!("Port {listen_port} is already in use by an existing Secluso install or compatible listener."),
    );
  } else {
    log_line(app, run_id, "info", Some(step), format!("Port {listen_port} is free on the server."));
  }

  check_firewall(app, run_id, step, sess, target, runtime)?;
  verify_public_http_reachability(
    app,
    run_id,
    step,
    sess,
    target,
    runtime,
    public_server_url,
    port_in_use,
    occupied_by_secluso,
  )?;

  Ok(PreflightReport {
    remote_has_bin,
    remote_has_unit,
    service_active,
    installed_version: version,
    port_in_use,
    remote_has_credentials_full,
    remote_arch,
  })
}

fn cleanup_stale_preflight_port_listener(
  app: &AppHandle,
  run_id: Uuid,
  step: &str,
  sess: &Session,
  target: &SshTarget,
  listen_port: u16,
) -> Result<bool> {
  let probe = remote_with_optional_sudo(
    sess,
    target,
    &format!("ss -ltnpH | awk '$4 ~ /:{}$/ {{print}}'", listen_port),
    &format!("ss -ltnH | awk '$4 ~ /:{}$/ {{print}}'", listen_port),
  )?;
  let pids = extract_listener_pids(&probe.stdout);
  if pids.is_empty() {
    return Ok(false);
  }

  let mut removed_any = false;
  for pid in pids {
    let inspect_cmd = format!(
      "cwd=$(readlink -f /proc/{pid}/cwd 2>/dev/null || true)\n\
cmd=$(tr '\\0' ' ' </proc/{pid}/cmdline 2>/dev/null || true)\n\
printf 'CWD=%s\\nCMD=%s\\n' \"$cwd\" \"$cmd\""
    );
    let inspect = remote_with_optional_sudo(sess, target, &inspect_cmd, &inspect_cmd)?;
    if inspect.exit != 0 {
      continue;
    }

    let cwd = parse_prefixed_output_field(&inspect.stdout, "CWD=").unwrap_or_default();
    let cmd = parse_prefixed_output_field(&inspect.stdout, "CMD=").unwrap_or_default();
    let is_stale_probe = looks_like_stale_preflight_listener(&cwd, &cmd, listen_port);
    if !is_stale_probe {
      continue;
    }

    log_line(
      app,
      run_id,
      "warn",
      Some(step),
      format!("Stopping stale preflight helper on port {listen_port} (pid {pid})."),
    );

    let cleanup_cmd = format!(
      "kill {pid} >/dev/null 2>&1 || true\n\
if [ -n '{cwd}' ] && [ -d '{cwd}' ]; then rm -rf '{cwd}'; fi",
      cwd = shell_escape(&cwd)
    );
    let cleanup = remote_with_optional_sudo(sess, target, &cleanup_cmd, &cleanup_cmd)?;
    if cleanup.exit != 0 {
      log_line(
        app,
        run_id,
        "warn",
        Some(step),
        format!(
          "Failed to fully clean up stale preflight helper pid {pid}. {}",
          summarize_remote_failure(&cleanup)
        ),
      );
      continue;
    }

    removed_any = true;
  }

  Ok(removed_any)
}

fn verify_sudo_access(app: &AppHandle, run_id: Uuid, step: &str, sess: &Session, target: &SshTarget) -> Result<()> {
  if target.user == "root" {
    log_line(app, run_id, "info", Some(step), "SSH user is root; sudo check not needed.".to_string());
    return Ok(());
  }

  let (cmd, stdin, mode_label) = match target.sudo.mode.as_str() {
    "password" => {
      let pw = target.sudo.password.clone().unwrap_or_default();
      if pw.is_empty() {
        bail!("A sudo password is required for this login, but the sudo password field is empty.");
      }
      ("sudo -S -p '' true", Some(format!("{pw}\n")), "explicit sudo password")
    }
    "same" => match &target.auth {
      SshAuth::Password { password } if !password.is_empty() => {
        ("sudo -S -p '' true", Some(format!("{password}\n")), "same-as-login password")
      }
      _ => ("sudo -n true", None, "passwordless sudo"),
    },
    _ => ("sudo -n true", None, "passwordless sudo"),
  };

  let sudo = remote_shell(sess, cmd, stdin.as_deref())?;
  if sudo.exit != 0 {
    bail!(
      "sudo is not working with the current settings (mode: {mode_label}). {}",
      summarize_remote_failure(&sudo)
    );
  }
  log_line(app, run_id, "info", Some(step), format!("Verified sudo access using {mode_label}."));
  Ok(())
}

fn verify_public_http_reachability(
  app: &AppHandle,
  run_id: Uuid,
  step: &str,
  sess: &Session,
  target: &SshTarget,
  runtime: Option<&ServerRuntimePlan>,
  public_server_url: Option<&str>,
  port_in_use: bool,
  existing_secluso_listener: bool,
) -> Result<()> {
  let exposure_mode = runtime.map(|value| value.exposure_mode.as_str()).unwrap_or("direct");
  let listen_port = runtime.map(|value| value.listen_port).unwrap_or(DEFAULT_SERVER_HTTP_PORT);
  let bind_address = runtime.map(|value| value.bind_address.as_str()).unwrap_or("0.0.0.0");

  if exposure_mode != "direct" {
    log_line(
      app,
      run_id,
      "info",
      Some(step),
      "Skipping public port probe during preflight because reverse proxy mode is selected.".to_string(),
    );
    return Ok(());
  }

  let Some(public_server_url) = public_server_url.map(str::trim).filter(|value| !value.is_empty()) else {
    log_line(
      app,
      run_id,
      "warn",
      Some(step),
      "Skipping public port probe during preflight because no public URL was provided.".to_string(),
    );
    return Ok(());
  };

  let base_url = prepare_direct_probe_base_url(public_server_url, listen_port)?;

  if port_in_use {
    if existing_secluso_listener {
      let status_url = base_url.join("status").context("Preparing preflight /status probe URL")?;
      log_line(
        app,
        run_id,
        "info",
        Some(step),
        format!(
          "Port {listen_port} is already serving Secluso. Reusing its public /status endpoint for reachability preflight."
        ),
      );
      verify_existing_secluso_status_endpoint(app, run_id, step, status_url.as_ref())?;
      return Ok(());
    }

    log_line(
      app,
      run_id,
      "warn",
      Some(step),
      format!(
        "Skipping temporary public port probe because port {listen_port} is already in use and the Secluso service is not active."
      ),
    );
    return Ok(());
  }

  let probe_token = format!("secluso-preflight-{}", Uuid::new_v4());
  log_line(
    app,
    run_id,
    "info",
    Some(step),
    format!("Starting a temporary public probe on port {listen_port}."),
  );
  let probe = match start_temp_http_probe(sess, target, listen_port, bind_address, &probe_token)? {
    Some(value) => value,
    None => {
      log_line(
        app,
        run_id,
        "warn",
        Some(step),
        "Skipping public port probe because no temporary HTTP probe helper (python3 or busybox) is available on the server.".to_string(),
      );
      return Ok(());
    }
  };

  let probe_url = base_url
    .join("secluso-preflight-probe.txt")
    .context("Preparing temporary HTTP probe URL")?;

  log_line(
    app,
    run_id,
    "info",
    Some(step),
    format!(
      "Checking whether {} is reachable from this computer.",
      base_url.as_str().trim_end_matches('/')
    ),
  );

  let probe_result = probe_public_demo_endpoint(probe_url.as_ref(), &probe_token, listen_port);
  if let Err(err) = stop_temp_http_probe(sess, target, &probe) {
    log_line(
      app,
      run_id,
      "warn",
      Some(step),
      format!("Temporary public probe cleanup warning: {err:#}"),
    );
  }
  probe_result?;

  log_line(
    app,
    run_id,
    "info",
    Some(step),
    format!("Public port probe succeeded on TCP port {listen_port}."),
  );
  Ok(())
}

fn prepare_direct_probe_base_url(public_server_url: &str, listen_port: u16) -> Result<Url> {
  let parsed = Url::parse(public_server_url)
    .with_context(|| format!("Public URL '{public_server_url}' is not a valid URL for direct-mode preflight."))?;

  if parsed.scheme() != "http" {
    bail!(
      "Direct mode must use an http:// public URL during preflight. Received '{}'.",
      public_server_url
    );
  }

  if parsed.path() != "/" || parsed.query().is_some() || parsed.fragment().is_some() {
    bail!(
      "Direct mode public URL must be a plain host or host:port without a path, query, or fragment. Received '{}'.",
      public_server_url
    );
  }

  let effective_port = parsed.port_or_known_default().unwrap_or(80);
  if effective_port != listen_port {
    bail!(
      "Direct mode public URL port {} does not match the configured Secluso listen port {}.",
      effective_port,
      listen_port
    );
  }

  Ok(parsed)
}

fn verify_existing_secluso_status_endpoint(app: &AppHandle, run_id: Uuid, step: &str, status_url: &str) -> Result<()> {
  let client = Client::builder()
    .timeout(PUBLIC_PROBE_HTTP_TIMEOUT)
    .build()
    .context("Creating HTTP client for preflight reachability check")?;

  let response = client
    .get(status_url)
    .send()
    .with_context(|| format!("Existing Secluso /status endpoint is not reachable from this computer at {status_url}"))?;

  let server_version = response
    .headers()
    .get("X-Server-Version")
    .and_then(|value| value.to_str().ok())
    .map(str::to_string);

  let Some(server_version) = server_version else {
    bail!(
      "Reached {}, but it did not return X-Server-Version. This does not look like a healthy Secluso /status response.",
      status_url
    );
  };

  log_line(
    app,
    run_id,
    "info",
    Some(step),
    format!("Existing public Secluso /status endpoint is reachable (X-Server-Version: {server_version})."),
  );
  Ok(())
}

fn start_temp_http_probe(
  sess: &Session,
  target: &SshTarget,
  listen_port: u16,
  bind_address: &str,
  probe_token: &str,
) -> Result<Option<TempHttpProbe>> {
  let uses_sudo = target.user != "root";
  let unit_name = format!("secluso-preflight-http-{}", Uuid::new_v4().simple());
  let inner_start_cmd = format!(
    "set -eu\n\
probe_root=\"$(mktemp -d /tmp/secluso-preflight-http.XXXXXX)\"\n\
printf '%s\\n' '{probe_token}' > \"$probe_root/secluso-preflight-probe.txt\"\n\
if ! command -v systemd-run >/dev/null 2>&1; then\n\
  echo 'SECLUSO_HTTP_PROBE_SYSTEMD_RUN_MISSING' >&2\n\
  exit 126\n\
fi\n\
if command -v python3 >/dev/null 2>&1; then\n\
  helper_cmd=\"cd '$probe_root' && exec python3 -m http.server {listen_port} --bind '{bind_address}' >> '$probe_root/server.log' 2>&1\"\n\
elif command -v busybox >/dev/null 2>&1; then\n\
  helper_cmd=\"exec busybox httpd -f -p '{bind_address}:{listen_port}' -h '$probe_root' >> '$probe_root/server.log' 2>&1\"\n\
else\n\
  echo 'SECLUSO_HTTP_PROBE_HELPER_MISSING' >&2\n\
  exit 127\n\
fi\n\
systemd-run --quiet --unit '{unit_name}' bash -lc \"$helper_cmd\"\n\
sleep 1\n\
if ! systemctl is-active --quiet '{unit_name}'; then\n\
  systemctl status '{unit_name}' --no-pager >/dev/null 2>&1 || true\n\
  exit 125\n\
fi\n\
printf 'UNIT=%s\\nROOT=%s\\n' '{unit_name}' \"$probe_root\""
  );
  let start_cmd = format!(
    "if command -v timeout >/dev/null 2>&1; then timeout {REMOTE_PROBE_START_TIMEOUT_SECS}s bash -lc '{}'; else bash -lc '{}'; fi",
    shell_escape(&inner_start_cmd),
    shell_escape(&inner_start_cmd)
  );
  let result = remote_shell_for_probe(sess, target, &start_cmd, uses_sudo)?;

  if result.exit == 127 && result.stderr.contains("SECLUSO_HTTP_PROBE_HELPER_MISSING") {
    return Ok(None);
  }
  if result.exit == 126 && result.stderr.contains("SECLUSO_HTTP_PROBE_SYSTEMD_RUN_MISSING") {
    return Ok(None);
  }
  if result.exit == 124 {
    bail!(
      "Timed out while starting the temporary HTTP probe on port {listen_port}. The remote helper did not detach cleanly within {} seconds.",
      REMOTE_PROBE_START_TIMEOUT_SECS
    );
  }
  if result.exit != 0 {
    bail!(
      "Failed to start a temporary HTTP probe on port {listen_port}. {}",
      summarize_remote_failure(&result)
    );
  }

  let unit_name = result
    .stdout
    .lines()
    .find_map(|line| line.strip_prefix("UNIT="))
    .map(str::trim)
    .filter(|value| !value.is_empty())
    .map(str::to_string)
    .context("Temporary HTTP probe did not report its systemd unit.")?;
  let root_dir = result
    .stdout
    .lines()
    .find_map(|line| line.strip_prefix("ROOT="))
    .map(str::trim)
    .filter(|value| !value.is_empty())
    .map(str::to_string)
    .context("Temporary HTTP probe did not report its temp directory.")?;

  Ok(Some(TempHttpProbe { unit_name, root_dir, uses_sudo }))
}

fn stop_temp_http_probe(sess: &Session, target: &SshTarget, probe: &TempHttpProbe) -> Result<()> {
  let stop_cmd = format!(
    "systemctl stop '{}' >/dev/null 2>&1 || true\n\
systemctl reset-failed '{}' >/dev/null 2>&1 || true\n\
rm -rf '{}'",
    shell_escape(&probe.unit_name),
    shell_escape(&probe.unit_name),
    shell_escape(&probe.root_dir)
  );
  let result = remote_shell_for_probe(sess, target, &stop_cmd, probe.uses_sudo)?;
  if result.exit != 0 {
    bail!("Temporary HTTP probe cleanup failed. {}", summarize_remote_failure(&result));
  }
  Ok(())
}

fn probe_public_demo_endpoint(probe_url: &str, probe_token: &str, listen_port: u16) -> Result<()> {
  let client = Client::builder()
    .timeout(PUBLIC_PROBE_HTTP_TIMEOUT)
    .build()
    .context("Creating HTTP client for public port probe")?;
  let probe_display_url = Url::parse(probe_url)
    .ok()
    .map(|url| {
      let mut trimmed = url.clone();
      trimmed.set_path("");
      trimmed.set_query(None);
      trimmed.set_fragment(None);
      trimmed.to_string().trim_end_matches('/').to_string()
    })
    .unwrap_or_else(|| probe_url.to_string());
  let probe_timeout_budget_secs =
    (PUBLIC_PROBE_ATTEMPTS as u64 * PUBLIC_PROBE_HTTP_TIMEOUT.as_secs())
      + ((PUBLIC_PROBE_ATTEMPTS.saturating_sub(1)) as u64 * PUBLIC_PROBE_RETRY_DELAY.as_secs());

  let mut last_error = None;
  for attempt in 1..=PUBLIC_PROBE_ATTEMPTS {
    match client.get(probe_url).send() {
      Ok(response) => {
        let status = response.status();
        let body = response
          .text()
          .with_context(|| format!("Reading HTTP probe response body from {probe_url}"))?;
        if status.is_success() && body.contains(probe_token) {
          return Ok(());
        }

        last_error = Some(anyhow::anyhow!(
          "Reached {}, but the response did not match the expected temporary probe (HTTP {}).",
          probe_url,
          status
        ));
      }
      Err(err) => {
        last_error = Some(anyhow::anyhow!(
          "Could not reach the temporary public probe at {} from this computer within about {} seconds: {}. Check that TCP port {} is open in the server firewall, cloud security group, and any home-router port forwarding rules.",
          probe_display_url,
          probe_timeout_budget_secs,
          err,
          listen_port
        ));
      }
    }

    if attempt < PUBLIC_PROBE_ATTEMPTS {
      sleep(PUBLIC_PROBE_RETRY_DELAY);
    }
  }

  Err(last_error.context("Public HTTP probe failed without an error.")?)
}

fn direct_status_url_for_preflight(
  runtime: Option<&ServerRuntimePlan>,
  public_server_url: Option<&str>,
  listen_port: u16,
) -> Result<Option<Url>> {
  let exposure_mode = runtime.map(|value| value.exposure_mode.as_str()).unwrap_or("direct");
  if exposure_mode != "direct" {
    return Ok(None);
  }

  let Some(public_server_url) = public_server_url.map(str::trim).filter(|value| !value.is_empty()) else {
    return Ok(None);
  };

  let base_url = prepare_direct_probe_base_url(public_server_url, listen_port)?;
  Ok(Some(base_url.join("status").context("Preparing preflight /status probe URL")?))
}

fn verify_outbound_network(app: &AppHandle, run_id: Uuid, step: &str, sess: &Session) -> Result<()> {
  let dns_checks = [
    (
      "api.github.com",
      "Future auto-updates may fail until the server can resolve api.github.com.",
    ),
    (
      "oauth2.googleapis.com",
      "Firebase push setup may fail until the server can resolve oauth2.googleapis.com.",
    ),
    (
      "fcm.googleapis.com",
      "Push notifications may fail until the server can resolve fcm.googleapis.com.",
    ),
  ];
  for (host, warning) in dns_checks {
    let probe = format!("getent ahostsv4 {host} >/dev/null 2>&1 || getent hosts {host} >/dev/null 2>&1");
    if remote_success(sess, &probe, None)? {
      log_line(app, run_id, "info", Some(step), format!("DNS lookup for {host} succeeded."));
    } else {
      log_line(app, run_id, "warn", Some(step), format!("DNS lookup for {host} failed. {warning}"));
    }
  }

  let https_checks = [
    (
      "https://api.github.com",
      "Future auto-updates may fail until the server can reach GitHub over HTTPS.",
    ),
    (
      "https://oauth2.googleapis.com",
      "Firebase push setup may fail until the server can reach Google OAuth over HTTPS.",
    ),
  ];
  for (url, warning) in https_checks {
    let probe = format!(
      "if command -v curl >/dev/null 2>&1; then curl -fsSI --connect-timeout {timeout} --max-time {timeout} {url} >/dev/null; else exit 42; fi",
      timeout = REMOTE_HTTPS_PROBE_MAX_TIME_SECS
    );
    let result = remote_shell(sess, &probe, None)?;
    match result.exit {
      0 => log_line(app, run_id, "info", Some(step), format!("Outbound HTTPS to {url} succeeded.")),
      42 => log_line(
        app,
        run_id,
        "warn",
        Some(step),
        format!("curl is not installed yet, so the remote HTTPS probe for {url} was skipped."),
      ),
      _ => log_line(app, run_id, "warn", Some(step), format!("Outbound HTTPS probe for {url} failed. {warning}")),
    }
  }

  Ok(())
}

fn check_firewall(
  app: &AppHandle,
  run_id: Uuid,
  step: &str,
  sess: &Session,
  target: &SshTarget,
  runtime: Option<&ServerRuntimePlan>,
) -> Result<()> {
  let exposure_mode = runtime.map(|value| value.exposure_mode.as_str()).unwrap_or("direct");
  let listen_port = runtime.map(|value| value.listen_port).unwrap_or(DEFAULT_SERVER_HTTP_PORT);
  let allow_ufw_rule = runtime.map(|value| value.allow_ufw_rule).unwrap_or(false);
  if exposure_mode == "proxy" {
    if remote_success(sess, "command -v nginx >/dev/null 2>&1 || command -v caddy >/dev/null 2>&1 || command -v apache2 >/dev/null 2>&1", None)? {
      log_line(
        app,
        run_id,
        "info",
        Some(step),
        format!("Reverse proxy mode selected. Make sure your existing proxy forwards to 127.0.0.1:{listen_port}."),
      );
    } else {
      log_line(
        app,
        run_id,
        "warn",
        Some(step),
        format!("Reverse proxy mode selected, but no common proxy binary was detected. Make sure something forwards traffic to 127.0.0.1:{listen_port}."),
      );
    }
    return Ok(());
  }

  if !remote_success(sess, "command -v ufw >/dev/null 2>&1", None)? {
    log_line(
      app,
      run_id,
      "warn",
      Some(step),
      format!("ufw is not installed. If your provider uses a cloud firewall or security group, make sure TCP port {listen_port} is allowed."),
    );
    return Ok(());
  }

  let uses_sudo = target.user != "root";
  let ufw = remote_shell_for_probe(sess, target, "ufw status", uses_sudo)?;
  if ufw.exit != 0 {
    log_line(
      app,
      run_id,
      "warn",
      Some(step),
      format!("Could not inspect ufw status. {}", summarize_remote_failure(&ufw)),
    );
    return Ok(());
  }
  let status = ufw.stdout.to_lowercase();
  if status.contains("inactive") {
    log_line(
      app,
      run_id,
      "warn",
      Some(step),
      format!(
        "ufw is inactive. That is fine locally, but you may still need to open TCP port {listen_port} in your provider firewall or security group."
      ),
    );
  } else if ufw_allows_tcp_port(&status, listen_port) {
    log_line(app, run_id, "info", Some(step), format!("ufw appears to allow TCP port {listen_port}."));
  } else if allow_ufw_rule {
    log_line(
      app,
      run_id,
      "warn",
      Some(step),
      format!("ufw is active and does not allow TCP port {listen_port}; adding an allow rule with user permission."),
    );
    let add_rule = remote_shell_for_probe(
      sess,
      target,
      &format!("ufw allow {listen_port}/tcp comment 'Secluso server'"),
      uses_sudo,
    )?;
    if add_rule.exit != 0 {
      bail!(
        "ufw is active, but Secluso could not add an allow rule for TCP port {listen_port}. {}",
        summarize_remote_failure(&add_rule)
      );
    }

    let updated = remote_shell_for_probe(sess, target, "ufw status", uses_sudo)?;
    if updated.exit != 0 || !ufw_allows_tcp_port(&updated.stdout.to_lowercase(), listen_port) {
      bail!("Secluso ran ufw allow for TCP port {listen_port}, but could not verify the resulting ufw rule.");
    }
    log_line(app, run_id, "info", Some(step), format!("Added ufw allow rule for TCP port {listen_port}."));
  } else {
    bail!(
      "ufw is active and does not allow TCP port {listen_port}. Enable permission to add a ufw rule, or run this on the server: sudo ufw allow {listen_port}/tcp"
    );
  }
  Ok(())
}

fn ufw_allows_tcp_port(status: &str, listen_port: u16) -> bool {
  let port_tcp = format!("{listen_port}/tcp");
  let port_any = listen_port.to_string();
  status.lines().any(|line| {
    let line = line.trim();
    line.contains("allow")
      && (line.split_whitespace().any(|field| field == port_tcp)
        || line.split_whitespace().any(|field| field == port_any))
  })
}

fn parse_os_release_field(contents: &str, key: &str) -> Option<String> {
  contents
    .lines()
    .find_map(|line| line.strip_prefix(&format!("{key}=")))
    .map(|value| value.trim_matches('"').to_string())
}

fn parse_u64_field(raw: &str, label: &str) -> Result<u64> {
  raw.parse::<u64>()
    .with_context(|| format!("Failed to parse {label} from '{raw}'"))
}

fn parse_prefixed_output_field(contents: &str, prefix: &str) -> Option<String> {
  contents
    .lines()
    .find_map(|line| line.strip_prefix(prefix))
    .map(str::trim)
    .map(str::to_string)
}

fn looks_like_stale_preflight_listener(cwd: &str, cmd: &str, listen_port: u16) -> bool {
  if cwd.starts_with("/tmp/secluso-preflight-http.") || cmd.contains("/tmp/secluso-preflight-http.") {
    return true;
  }

  let python_pattern = format!("-m http.server {listen_port}");
  if cmd.contains("python3") && cmd.contains(&python_pattern) {
    return true;
  }

  let busybox_pattern = format!(":{listen_port}");
  if cmd.contains("busybox httpd") && cmd.contains(&busybox_pattern) {
    return true;
  }

  false
}

fn extract_listener_pids(contents: &str) -> Vec<String> {
  let mut out = Vec::new();
  for line in contents.lines() {
    let mut rest = line;
    while let Some(idx) = rest.find("pid=") {
      let after = &rest[idx + 4..];
      let pid = after
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>();
      if !pid.is_empty() && !out.iter().any(|existing| existing == &pid) {
        out.push(pid.clone());
      }
      rest = &after[pid.len()..];
    }
  }
  out
}

fn shell_escape(cmd: &str) -> String {
  cmd.replace('\'', r"'\''")
}

fn remote_success(sess: &Session, cmd: &str, stdin: Option<&str>) -> Result<bool> {
  Ok(remote_shell(sess, cmd, stdin)?.exit == 0)
}

fn remote_with_optional_sudo(sess: &Session, target: &SshTarget, sudo_cmd: &str, fallback_cmd: &str) -> Result<ExecResult> {
  if target.user == "root" {
    return remote_shell(sess, sudo_cmd, None);
  }

  match target.sudo.mode.as_str() {
    "password" => {
      let pw = target.sudo.password.clone().unwrap_or_default();
      if pw.is_empty() {
        return remote_shell(sess, fallback_cmd, None);
      }
      remote_shell(sess, sudo_cmd, Some(&format!("{pw}\n")))
    }
    "same" => match &target.auth {
      SshAuth::Password { password } if !password.is_empty() => {
        remote_shell(sess, sudo_cmd, Some(&format!("{password}\n")))
      }
      _ => {
        let res = remote_shell(sess, &format!("sudo -n {sudo_cmd}"), None)?;
        if res.exit == 0 { Ok(res) } else { remote_shell(sess, fallback_cmd, None) }
      }
    },
    _ => remote_shell(sess, fallback_cmd, None),
  }
}

fn remote_shell_for_probe(sess: &Session, target: &SshTarget, cmd: &str, uses_sudo: bool) -> Result<ExecResult> {
  if !uses_sudo {
    return remote_shell(sess, cmd, None);
  }

  let (sudo_cmd, sudo_pw) = sudo_prefix(target);
  if sudo_cmd.is_empty() {
    return remote_shell(sess, cmd, None);
  }

  let wrapped = format!("{sudo_cmd} bash -lc '{}'", shell_escape(cmd));
  let stdin = sudo_pw.map(|value| format!("{value}\n"));
  remote_shell(sess, &wrapped, stdin.as_deref())
}

fn remote_shell(sess: &Session, cmd: &str, stdin: Option<&str>) -> Result<ExecResult> {
  let full = format!("bash -lc '{}'", shell_escape(cmd));
  let mut channel = sess.channel_session().context("Failed to open SSH channel")?;
  channel.exec(&full).with_context(|| format!("Remote exec failed: {cmd}"))?;
  if let Some(stdin) = stdin {
    channel.write_all(stdin.as_bytes()).ok();
    channel.flush().ok();
  }
  channel.send_eof().ok();

  let mut stdout = String::new();
  let mut stderr = String::new();
  channel.read_to_string(&mut stdout).ok();
  channel.stderr().read_to_string(&mut stderr).ok();
  channel.wait_close().ok();
  let exit = channel.exit_status().unwrap_or(255);

  Ok(ExecResult { stdout, stderr, exit })
}

fn summarize_remote_failure(result: &ExecResult) -> String {
  let stderr = result.stderr.trim();
  if !stderr.is_empty() {
    return stderr.to_string();
  }
  let stdout = result.stdout.trim();
  if !stdout.is_empty() {
    return stdout.to_string();
  }
  format!("command exited with status {}", result.exit)
}
