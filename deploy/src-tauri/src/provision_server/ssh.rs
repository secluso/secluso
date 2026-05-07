//! SPDX-License-Identifier: GPL-3.0-or-later
use crate::provision_server::events::log_line;
use crate::provision_server::types::{HostKeyProof, SshAuth, SshHostKeyTarget, SshTarget};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use sha2::{Digest, Sha256};
use ssh2::Session;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;
use tauri::AppHandle;
use tempfile::NamedTempFile;
use uuid::Uuid;

const SSH_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const SSH_IO_TIMEOUT: Duration = Duration::from_secs(30);

struct RemoteExecResult {
  stdout: String,
  stderr: String,
  exit: i32,
}

pub struct TempKeyFiles {
  pub key_file: Option<NamedTempFile>,
}

impl TempKeyFiles {
  pub fn new() -> Self {
    Self { key_file: None }
  }
}

fn connect_tcp(host: &str, port: u16) -> Result<TcpStream> {
  let target_addr = format!("{host}:{port}");
  let addrs = target_addr
    .to_socket_addrs()
    .with_context(|| format!("Failed to resolve SSH target {}", target_addr))?
    .collect::<Vec<_>>();
  if addrs.is_empty() {
    bail!("Failed to resolve SSH target {}.", target_addr);
  }

  let mut last_err = None;
  let mut tcp = None;
  for addr in addrs {
    match TcpStream::connect_timeout(&addr, SSH_CONNECT_TIMEOUT) {
      Ok(stream) => {
        tcp = Some(stream);
        break;
      }
      Err(err) => {
        last_err = Some((addr, err));
      }
    }
  }

  let tcp = match tcp {
    Some(stream) => stream,
    None => {
      let detail = match last_err {
        Some((addr, err)) => format!("{addr} ({err})"),
        None => "no resolved addresses".to_string(),
      };
      bail!(
        "Failed to connect to {} within {} seconds: {}",
        target_addr,
        SSH_CONNECT_TIMEOUT.as_secs(),
        detail
      );
    }
  };

  tcp.set_read_timeout(Some(SSH_IO_TIMEOUT)).ok();
  tcp.set_write_timeout(Some(SSH_IO_TIMEOUT)).ok();
  Ok(tcp)
}

// Split raw transport/handshake from authentication so fetch_host_key and connect_ssh share exactly one connection setup path
fn handshake_ssh_session(host: &str, port: u16) -> Result<Session> {
  let tcp = connect_tcp(host, port)?;
  let mut sess = Session::new().context("Failed to create SSH session")?;
  sess.set_timeout(SSH_IO_TIMEOUT.as_millis() as u32);
  sess.set_tcp_stream(tcp);
  sess.handshake().context("SSH handshake failed")?;
  Ok(sess)
}

fn ssh_host_key_algorithm_name(kind: ssh2::HostKeyType) -> &'static str {
  match kind {
    ssh2::HostKeyType::Rsa => "ssh-rsa",
    ssh2::HostKeyType::Dss => "ssh-dss",
    ssh2::HostKeyType::Ecdsa256 => "ecdsa-sha2-nistp256",
    ssh2::HostKeyType::Ecdsa384 => "ecdsa-sha2-nistp384",
    ssh2::HostKeyType::Ecdsa521 => "ecdsa-sha2-nistp521",
    ssh2::HostKeyType::Ed25519 => "ssh-ed25519",
    ssh2::HostKeyType::Unknown => "unknown",
  }
}

pub fn read_host_key_proof(sess: &Session) -> Result<HostKeyProof> {
  // Mirror the OpenSSH SHA256:... fingerprint format
  // plan is for UI to show users the same kind of thing they'd see in a provider console
  let (host_key, host_key_type) = sess.host_key().context("SSH server did not provide a host key")?;
  let digest = Sha256::digest(host_key);
  Ok(HostKeyProof {
    algorithm: ssh_host_key_algorithm_name(host_key_type).to_string(),
    sha256: format!("SHA256:{}", STANDARD_NO_PAD.encode(digest)),
  })
}

pub fn fetch_host_key(target: &SshHostKeyTarget) -> Result<HostKeyProof> {
  // Discovery intentionally stops after handshake.
  // Allows us to show the server identity without changing auth/provision behavior
  let sess = handshake_ssh_session(&target.host, target.port)?;
  read_host_key_proof(&sess)
}

pub fn connect_ssh(target: &SshTarget) -> Result<(Session, TempKeyFiles)> {
  let sess = handshake_ssh_session(&target.host, target.port)?;
  let presented_host_key = read_host_key_proof(&sess)?;
  let expected_host_key = target
    .expected_host_key
    .as_ref()
    .context("SSH host key verification is required. Fetch and verify the server fingerprint before continuing.")?;

  if expected_host_key.sha256 != presented_host_key.sha256 || expected_host_key.algorithm != presented_host_key.algorithm {
    bail!(
      "SSH host key verification failed. Expected {} {} but the server presented {} {}. Re-check the server fingerprint before continuing.",
      expected_host_key.algorithm,
      expected_host_key.sha256,
      presented_host_key.algorithm,
      presented_host_key.sha256
    );
  }

  let mut temps = TempKeyFiles::new();

  match &target.auth {
    SshAuth::Password { password } => {
      sess.userauth_password(&target.user, password)
        .context("SSH password authentication failed")?;
    }
    SshAuth::KeyFile { path, passphrase } => {
      let p = Path::new(path);
      sess.userauth_pubkey_file(&target.user, None, p, passphrase.as_deref())
        .with_context(|| format!("SSH keyfile authentication failed (path={})", path))?;
    }
    SshAuth::KeyText { text, passphrase } => {
      // write key text to a temp file and use it as a keyfile
      // most openssh private keys work with libssh2 if the format is supported
      let mut f = NamedTempFile::new().context("Failed to create temp key file")?;
      f.write_all(text.as_bytes()).context("Failed writing temp key")?;
      f.flush().ok();

      // try to set 0600 on unix when possible
      #[cfg(unix)]
      {
        use std::os::unix::fs::PermissionsExt;
        let perm = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(f.path(), perm).ok();
      }

      let p = f.path().to_path_buf();
      temps.key_file = Some(f);

      sess.userauth_pubkey_file(&target.user, None, &p, passphrase.as_deref())
        .context("SSH pasted-key authentication failed")?;
    }
  }

  if !sess.authenticated() {
    bail!("SSH authentication did not succeed.");
  }

  Ok((sess, temps))
}

pub fn sudo_prefix(target: &SshTarget) -> (String, Option<String>) {
  // returns ("sudo -S -p ''", Some(password)) or ("", None) for root or no sudo
  if target.user == "root" {
    return ("".to_string(), None);
  }

  // decide sudo password behavior
  match target.sudo.mode.as_str() {
    "password" => {
      let pw = target.sudo.password.clone().unwrap_or_default();
      if pw.is_empty() {
        ("sudo -S -p ''".to_string(), None) // will likely fail but we stream it
      } else {
        ("sudo -S -p ''".to_string(), Some(pw))
      }
    }
    "same" => {
      // if login auth is password, reuse it. if key based, assume passwordless sudo
      match &target.auth {
        SshAuth::Password { password } if !password.is_empty() => ("sudo -S -p ''".to_string(), Some(password.clone())),
        _ => ("sudo".to_string(), None),
      }
    }
    _ => ("sudo".to_string(), None),
  }
}

pub fn exec_remote_script_streaming(
  app: &AppHandle,
  run_id: Uuid,
  step: &str,
  sess: &Session,
  env_kv: &[(&str, String)],
  sudo_pw: Option<String>,
  script: &str,
) -> Result<()> {
  let mut cmd = String::new();
  for (k, v) in env_kv {
    // shell safe single quote escaping
    let escaped = v.replace('\'', r"'\''");
    cmd.push_str(&format!("{k}='{escaped}' "));
  }
  cmd.push_str("bash -s");

  let mut channel = sess.channel_session().context("Failed to open SSH channel")?;
  channel.exec(&cmd).with_context(|| format!("Failed to exec remote bash: {cmd}"))?;

  // if sudo needs a password and the script uses sudo -s, we send it first
  // the script reads sudo_pass from env but some sudo calls may still read stdin
  if let Some(pw) = sudo_pw {
    let _ = channel.write_all(format!("{pw}\n").as_bytes());
  }

  channel.write_all(script.as_bytes()).context("Failed to write script to SSH stdin")?;
  channel.send_eof().ok();

  // stream stdout and stderr
  let mut stdout = String::new();
  let mut stderr = String::new();

  // ssh2 does not give line by line callbacks so we poll reads and split ourselves
  let mut out_buf = [0u8; 8192];
  let mut err_buf = [0u8; 8192];

  // buffers for partial lines
  let mut out_acc = String::new();
  let mut err_acc = String::new();

  loop {
    let mut did_any = false;

    match channel.read(&mut out_buf) {
      Ok(0) => {}
      Ok(n) => {
        did_any = true;
        let chunk = String::from_utf8_lossy(&out_buf[..n]);
        stdout.push_str(&chunk);
        out_acc.push_str(&chunk);
        while let Some(pos) = out_acc.find('\n') {
          let line = out_acc[..pos].trim_end().to_string();
          out_acc = out_acc[pos + 1..].to_string();
          handle_remote_line(app, run_id, step, "info", &line);
        }
      }
      Err(_) => {}
    }

    match channel.stderr().read(&mut err_buf) {
      Ok(0) => {}
      Ok(n) => {
        did_any = true;
        let chunk = String::from_utf8_lossy(&err_buf[..n]);
        stderr.push_str(&chunk);
        err_acc.push_str(&chunk);
        while let Some(pos) = err_acc.find('\n') {
          let line = err_acc[..pos].trim_end().to_string();
          err_acc = err_acc[pos + 1..].to_string();
          handle_remote_line(app, run_id, step, "error", &line);
        }
      }
      Err(_) => {}
    }

    if channel.eof() {
      break;
    }

    if !did_any {
      // avoid a busy loop
      std::thread::sleep(Duration::from_millis(30));
    }
  }

  if !out_acc.trim().is_empty() {
    handle_remote_line(app, run_id, step, "info", out_acc.trim_end());
  }
  if !err_acc.trim().is_empty() {
    handle_remote_line(app, run_id, step, "error", err_acc.trim_end());
  }

  channel.wait_close().ok();
  let exit = channel.exit_status().unwrap_or(255);

  if exit != 0 {
    bail!("Remote script failed (exit={exit}).");
  }

  Ok(())
}

fn handle_remote_line(app: &AppHandle, run_id: Uuid, step: &str, default_level: &str, line: &str) {
  // allow remote to emit structured events
  // ::SECLUSO_EVENT::{"level":"info","step":"download","msg":"Downloading zip"}
  const PREFIX: &str = "::SECLUSO_EVENT::";

  if let Some(rest) = line.strip_prefix(PREFIX) {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(rest) {
      let level = v.get("level").and_then(|x| x.as_str()).unwrap_or("info");
      let rstep = v.get("step").and_then(|x| x.as_str()).unwrap_or(step);
      let msg = v.get("msg").and_then(|x| x.as_str()).unwrap_or(line);
      log_line(app, run_id, level, Some(rstep), msg.to_string());
      return;
    }
  }

  if !line.trim().is_empty() {
    log_line(app, run_id, default_level, Some(step), line.to_string());
  }
}

pub fn scp_upload_bytes(sess: &Session, remote_path: &str, mode: i32, bytes: &[u8]) -> Result<()> {
  let path = Path::new(remote_path);
  let mut remote = sess
    .scp_send(path, mode, bytes.len() as u64, None)
    .with_context(|| format!("Failed to SCP send to {remote_path}"))?;
  remote.write_all(bytes).context("Failed to write SCP bytes")?;
  remote.send_eof().ok();
  remote.wait_eof().ok();
  remote.close().ok();
  remote.wait_close().ok();
  Ok(())
}

pub fn create_remote_temp_dir(sess: &Session, prefix: &str) -> Result<String> {
  // Each run gets its own remote staging dir.
  // Useful bit is that uploads for this run no longer collide with shared fixed temp paths.
  let template = format!("/tmp/{prefix}.XXXXXX");
  let cmd = format!(
    "stage_dir=\"$(mktemp -d {})\" && chmod 700 \"$stage_dir\" && printf '%s' \"$stage_dir\"",
    shell_word(&template)
  );
  let result = remote_shell(sess, &cmd, None)?;
  if result.exit != 0 {
    bail!(
      "Failed to create remote staging dir: {}",
      summarize_remote_failure(&result)
    );
  }

  let stage_dir = result.stdout.trim();
  if stage_dir.is_empty() {
    bail!("Failed to create remote staging dir: empty result");
  }

  Ok(stage_dir.to_string())
}

pub fn cleanup_remote_path(sess: &Session, remote_path: &str) -> Result<()> {
  // Best to clear staged inputs once the provisioning run is over.
  let cmd = format!("rm -rf -- {}", shell_word(remote_path));
  let result = remote_shell(sess, &cmd, None)?;
  if result.exit != 0 {
    bail!(
      "Failed to clean up remote path {}: {}",
      remote_path,
      summarize_remote_failure(&result)
    );
  }
  Ok(())
}

fn remote_shell(sess: &Session, cmd: &str, stdin: Option<&str>) -> Result<RemoteExecResult> {
  let full = format!("bash -lc '{}'", shell_single_quote_inner(cmd));
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

  Ok(RemoteExecResult { stdout, stderr, exit })
}

fn summarize_remote_failure(result: &RemoteExecResult) -> String {
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

fn shell_single_quote_inner(s: &str) -> String {
  s.replace('\'', r#"'\''"#)
}

fn shell_word(s: &str) -> String {
  if s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '/' | ':' | '@')) {
    s.to_string()
  } else {
    format!("'{}'", s.replace('\'', r#"'\''"#))
  }
}
