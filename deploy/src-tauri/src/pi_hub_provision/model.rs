//! SPDX-License-Identifier: GPL-3.0-or-later
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Secluso {
  pub server_url: Option<String>,
  pub camera_name: Option<String>,
  pub release_mode: Option<String>,
  pub release_tag: Option<String>,
  pub asset_name: Option<String>,
  pub asset_kind: Option<String>,
  pub install_dir: Option<String>,
  pub etc_dir: Option<String>,
  pub repo: Option<String>,
  pub sig_keys: Option<Vec<SigKey>>,
  pub github_token: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct Config {
  pub output_name: String,
  pub hostname: String,
  pub user: User,

  #[serde(default)]
  pub ssh: Ssh,

  #[serde(default)]
  pub wifi: Option<Wifi>,

  #[serde(default)]
  pub apt: Apt,

  #[serde(default)]
  pub secluso: Option<Secluso>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct User {
  pub name: String,
  pub password: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct Wifi {
  pub country: String,
  pub ssid: String,
  pub psk: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SigKey {
  pub name: String,
  pub github_user: String,
  #[serde(default)]
  pub fingerprint: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub(crate) struct Ssh {
  #[serde(default)]
  pub enable: bool,
  #[serde(default)]
  pub authorized_keys: Vec<String>,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub(crate) struct Apt {
  #[serde(default)]
  pub packages: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct RuntimeConfig {
  pub base_image: String,
  pub rpicam_apps_commit: String,
  pub output_name: String,
  pub hostname: String,
  pub variant: String,
  pub user: User,
  pub ssh: Ssh,
  pub wifi: Option<Wifi>,
  pub apt: Apt,
  pub secluso: Option<Secluso>,
}
