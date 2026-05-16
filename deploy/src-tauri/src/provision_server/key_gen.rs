//! SPDX-License-Identifier: GPL-3.0-or-later
//!
//! Generate an Ed25519 SSH keypair locally and install the public key into the user's authorized_keys on a remote server.
//! sidesteps the Linux/macOS/Windows differences in the ssh-keygen CLI by doing everything in Rust via ssh key crate
use crate::provision_server::ssh::connect_ssh;
use crate::provision_server::types::SshTarget;
use anyhow::{bail, Context, Result};
use serde::Serialize;
use ssh_key::{Algorithm, LineEnding, PrivateKey};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct KeyGenResult {
  pub private_path: String,
  pub public_path: String,
  pub public_key: String,
  pub fingerprint: String,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DefaultKeyPath {
  pub home_directory: String,
  pub directory: String,
  pub default_file_name: String,
  pub default_full_path: String,
}

const DEFAULT_FILE_NAME: &str = "id_ed25519_secluso";

pub fn default_key_path() -> DefaultKeyPath {
  let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
  let ssh_dir = home.join(".ssh");
  let full = ssh_dir.join(DEFAULT_FILE_NAME);
  DefaultKeyPath {
    home_directory: home.to_string_lossy().to_string(),
    directory: ssh_dir.to_string_lossy().to_string(),
    default_file_name: DEFAULT_FILE_NAME.to_string(),
    default_full_path: full.to_string_lossy().to_string(),
  }
}

pub fn generate_keypair(save_path: &str, comment: Option<&str>, passphrase: Option<&str>) -> Result<KeyGenResult> {
  let private_path = PathBuf::from(save_path);
  if private_path.as_os_str().is_empty() {
    bail!("A save path is required for the new SSH key.");
  }
  if private_path.exists() {
    bail!(
      "A file already exists at {}. Choose a different path or move the existing file out of the way.",
      private_path.display()
    );
  }

  if let Some(parent) = private_path.parent() {
    if !parent.as_os_str().is_empty() {
      let needs_create = !parent.exists();
      std::fs::create_dir_all(parent)
        .with_context(|| format!("Failed to create directory {}", parent.display()))?;
      if needs_create && parent.file_name().and_then(|n| n.to_str()) == Some(".ssh") {
        set_dir_mode(parent, 0o700);
      }
    }
  }

  let mut rng = rand::rngs::OsRng;
  let mut key = PrivateKey::random(&mut rng, Algorithm::Ed25519)
    .context("Failed to generate Ed25519 SSH key")?;
  if let Some(comment) = comment.filter(|c| !c.is_empty()) {
    key.set_comment(comment);
  }

  // The unencrypted key keeps the same public half
  let public_key_for_output = key.public_key().clone();

  let private_to_write = match passphrase.filter(|p| !p.is_empty()) {
    Some(pw) => key
      .encrypt(&mut rng, pw.as_bytes())
      .context("Failed to encrypt the private key with the provided passphrase")?,
    None => key,
  };

  let openssh_priv = private_to_write
    .to_openssh(LineEnding::LF)
    .context("Failed to encode the private key in OpenSSH format")?;
  write_private_key(&private_path, openssh_priv.as_bytes())
    .with_context(|| format!("Failed to write private key to {}", private_path.display()))?;

  let public_key_string = public_key_for_output
    .to_openssh()
    .context("Failed to encode the public key in OpenSSH format")?;
  let public_path = append_extension(&private_path, "pub");
  let mut pub_contents = public_key_string.clone();
  pub_contents.push('\n');
  std::fs::write(&public_path, pub_contents.as_bytes())
    .with_context(|| format!("Failed to write public key to {}", public_path.display()))?;

  let fingerprint = public_key_for_output.fingerprint(ssh_key::HashAlg::Sha256).to_string();

  Ok(KeyGenResult {
    private_path: private_path.to_string_lossy().to_string(),
    public_path: public_path.to_string_lossy().to_string(),
    public_key: public_key_string,
    fingerprint,
  })
}

pub fn install_public_key_on_server(target: &SshTarget, public_key: &str) -> Result<()> {
  let pub_key = public_key.trim();
  if pub_key.is_empty() {
    bail!("Public key is empty; nothing to install.");
  }
  if pub_key.contains('\n') || pub_key.contains('\r') {
    bail!("Public key must be a single line.");
  }

  let (sess, _temps) = connect_ssh(target)?;

  // No sudo
  let script = r#"
set -eu
read -r pub_key
test -n "$pub_key" || { echo "empty key" >&2; exit 1; }
mkdir -p "$HOME/.ssh"
chmod 700 "$HOME/.ssh"
touch "$HOME/.ssh/authorized_keys"
chmod 600 "$HOME/.ssh/authorized_keys"
if ! grep -qxF "$pub_key" "$HOME/.ssh/authorized_keys" 2>/dev/null; then
  # Ensure the file ends with a newline before appending
  if [ -s "$HOME/.ssh/authorized_keys" ] && [ "$(tail -c 1 "$HOME/.ssh/authorized_keys" | wc -l)" -eq 0 ]; then
    printf '\n' >> "$HOME/.ssh/authorized_keys"
  fi
  printf '%s\n' "$pub_key" >> "$HOME/.ssh/authorized_keys"
fi
"#;

  let mut channel = sess
    .channel_session()
    .context("Failed to open SSH channel for key install")?;
  channel
    .exec(&format!("bash -lc '{}'", script.replace('\'', r"'\''")))
    .context("Failed to start authorized_keys install script")?;
  channel
    .write_all(format!("{pub_key}\n").as_bytes())
    .context("Failed to send public key over SSH")?;
  channel.send_eof().ok();

  let mut stdout = String::new();
  let mut stderr = String::new();
  channel.read_to_string(&mut stdout).ok();
  channel.stderr().read_to_string(&mut stderr).ok();
  channel.wait_close().ok();
  let exit = channel.exit_status().unwrap_or(255);

  if exit != 0 {
    let detail = if !stderr.trim().is_empty() {
      stderr.trim().to_string()
    } else if !stdout.trim().is_empty() {
      stdout.trim().to_string()
    } else {
      format!("authorized_keys script exited with status {exit}")
    };
    bail!("Failed to install public key on server: {detail}");
  }

  Ok(())
}

#[cfg(unix)]
fn write_private_key(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
  use std::fs::OpenOptions;
  use std::os::unix::fs::OpenOptionsExt;

  let mut file = OpenOptions::new()
    .write(true)
    .create_new(true)
    .mode(0o600)
    .open(path)?;
  file.write_all(bytes)?;
  file.flush()
}

#[cfg(not(unix))]
fn write_private_key(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
  // On Windows, NTFS ACLs control private-key access.
  std::fs::write(path, bytes)
}

#[cfg(unix)]
fn set_dir_mode(dir: &Path, mode: u32) {
  use std::os::unix::fs::PermissionsExt;
  if let Ok(meta) = std::fs::metadata(dir) {
    let mut perms = meta.permissions();
    perms.set_mode(mode);
    let _ = std::fs::set_permissions(dir, perms);
  }
}

#[cfg(not(unix))]
fn set_dir_mode(_dir: &Path, _mode: u32) {}

fn append_extension(path: &Path, ext: &str) -> PathBuf {
  let mut name = path.as_os_str().to_os_string();
  name.push(".");
  name.push(ext);
  PathBuf::from(name)
}
