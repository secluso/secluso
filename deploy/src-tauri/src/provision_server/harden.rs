//! SPDX-License-Identifier: GPL-3.0-or-later
//!
//! Server hardening helpers. Currently exposes detection and disabling of SSH
//! password authentication so a user provisioning via key-based login can
//! lock the server down to keys only.
use crate::provision_server::ssh::{connect_ssh, sudo_prefix};
use crate::provision_server::types::SshTarget;
use anyhow::{bail, Context, Result};
use ssh2::Session;
use std::io::{Read, Write};

struct ExecResult {
  stdout: String,
  stderr: String,
  exit: i32,
}

fn shell_escape(cmd: &str) -> String {
  cmd.replace('\'', r"'\''")
}

fn remote_sudo(sess: &Session, target: &SshTarget, cmd: &str) -> Result<ExecResult> {
  let (sudo_cmd, sudo_pw) = sudo_prefix(target);
  let wrapped = if sudo_cmd.is_empty() {
    format!("bash -lc '{}'", shell_escape(cmd))
  } else {
    format!("{sudo_cmd} bash -lc '{}'", shell_escape(cmd))
  };

  let mut channel = sess.channel_session().context("Failed to open SSH channel")?;
  channel.exec(&wrapped).with_context(|| format!("Remote exec failed: {cmd}"))?;
  if let Some(pw) = sudo_pw {
    channel.write_all(format!("{pw}\n").as_bytes()).ok();
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

fn summarize(result: &ExecResult) -> String {
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

// Returns true if the server is currently accepting SSH password authentication.
fn detect_password_auth(sess: &Session, target: &SshTarget) -> Result<bool> {
  let probe_cmd = r#"
sshd_bin=""
for candidate in /usr/sbin/sshd /sbin/sshd /usr/local/sbin/sshd; do
  if [ -x "$candidate" ]; then sshd_bin="$candidate"; break; fi
done
if [ -z "$sshd_bin" ] && command -v sshd >/dev/null 2>&1; then
  sshd_bin="$(command -v sshd)"
fi
if [ -n "$sshd_bin" ]; then
  out="$("$sshd_bin" -T 2>/dev/null | awk 'tolower($1)=="passwordauthentication" {print tolower($2); found=1} END {if (!found) print ""}' | tail -n1)"
  if [ -n "$out" ]; then
    printf 'EFFECTIVE=%s\n' "$out"
    exit 0
  fi
fi

val=""
for f in /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config; do
  if [ -f "$f" ]; then
    found="$(grep -iE '^[[:space:]]*PasswordAuthentication[[:space:]]+' "$f" 2>/dev/null | tail -n1 | awk '{print tolower($2)}')"
    if [ -n "$found" ]; then val="$found"; fi
  fi
done
if [ -z "$val" ]; then val="yes"; fi
printf 'PARSED=%s\n' "$val"
"#;

  let result = remote_sudo(sess, target, probe_cmd)?;
  if result.exit != 0 {
    bail!("Failed to inspect sshd config: {}", summarize(&result));
  }

  let value = result
    .stdout
    .lines()
    .find_map(|line| line.strip_prefix("EFFECTIVE=").or_else(|| line.strip_prefix("PARSED=")))
    .map(str::trim)
    .map(str::to_ascii_lowercase)
    .unwrap_or_else(|| "yes".to_string());

  Ok(value == "yes")
}

fn disable_password_auth_remote(sess: &Session, target: &SshTarget) -> Result<()> {
  // Write a drop-in if the daemon includes sshd_config.d/*.conf, otherwise edit /etc/ssh/sshd_config in place with a backup.
  let script = r#"
set -eu
mkdir -p /etc/ssh/sshd_config.d
uses_include=0
if grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/' /etc/ssh/sshd_config 2>/dev/null; then
  uses_include=1
fi

if [ "$uses_include" = "1" ]; then
  cat > /etc/ssh/sshd_config.d/99-secluso-disable-password.conf <<'CFG'
# Added by Secluso deploy tool.
# Disables SSH password and keyboard-interactive logins so only keys work.
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
CFG
  chmod 644 /etc/ssh/sshd_config.d/99-secluso-disable-password.conf
else
  if [ ! -f /etc/ssh/sshd_config.secluso.bak ]; then
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.secluso.bak
  fi
  for key in PasswordAuthentication KbdInteractiveAuthentication ChallengeResponseAuthentication; do
    if grep -qE "^[[:space:]]*${key}[[:space:]]+" /etc/ssh/sshd_config; then
      sed -i -E "s|^[[:space:]]*${key}[[:space:]]+.*$|${key} no|I" /etc/ssh/sshd_config
    else
      printf '%s no\n' "$key" >> /etc/ssh/sshd_config
    fi
  done
fi

# Validate config before reloading so a broken edit cannot take effect.
sshd_bin=""
for candidate in /usr/sbin/sshd /sbin/sshd /usr/local/sbin/sshd; do
  if [ -x "$candidate" ]; then sshd_bin="$candidate"; break; fi
done
if [ -z "$sshd_bin" ] && command -v sshd >/dev/null 2>&1; then
  sshd_bin="$(command -v sshd)"
fi
if [ -n "$sshd_bin" ]; then
  if ! "$sshd_bin" -t; then
    echo "sshd configuration test failed; not reloading" >&2
    exit 1
  fi
fi

reloaded=0
for unit in ssh sshd ssh.socket; do
  if systemctl reload "$unit" >/dev/null 2>&1; then reloaded=1; break; fi
done
if [ "$reloaded" = "0" ]; then
  for unit in ssh sshd; do
    if systemctl restart "$unit" >/dev/null 2>&1; then reloaded=1; break; fi
  done
fi
if [ "$reloaded" = "0" ]; then
  echo "Could not reload or restart the sshd service" >&2
  exit 1
fi

# Confirm the effective config now refuses passwords.
if [ -n "$sshd_bin" ]; then
  effective="$("$sshd_bin" -T 2>/dev/null | awk 'tolower($1)=="passwordauthentication" {print tolower($2)}' | tail -n1)"
  if [ "$effective" = "yes" ]; then
    echo "Password authentication is still enabled after the change" >&2
    exit 1
  fi
fi
"#;

  let result = remote_sudo(sess, target, script)?;
  if result.exit != 0 {
    bail!("Failed to disable SSH password authentication: {}", summarize(&result));
  }
  Ok(())
}

pub fn check_password_auth(target: &SshTarget) -> Result<bool> {
  let (sess, _temps) = connect_ssh(target)?;
  detect_password_auth(&sess, target)
}

pub fn disable_password_auth(target: &SshTarget) -> Result<()> {
  let (sess, _temps) = connect_ssh(target)?;
  disable_password_auth_remote(&sess, target)
}
