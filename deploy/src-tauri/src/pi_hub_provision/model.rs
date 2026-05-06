//! SPDX-License-Identifier: GPL-3.0-or-later
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SigKey {
  pub name: String,
  pub github_user: String,
  #[serde(default)]
  pub fingerprint: Option<String>,
}
