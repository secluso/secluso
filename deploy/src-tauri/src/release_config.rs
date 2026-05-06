//! SPDX-License-Identifier: GPL-3.0-or-later
use secluso_update::{default_signers, Signer};

pub trait ReleaseSigKey {
    fn name(&self) -> &str;
    fn github_user(&self) -> &str;
    fn fingerprint(&self) -> Option<&str>;
}

impl ReleaseSigKey for crate::pi_hub_provision::model::SigKey {
    fn name(&self) -> &str {
        &self.name
    }

    fn github_user(&self) -> &str {
        &self.github_user
    }

    fn fingerprint(&self) -> Option<&str> {
        self.fingerprint.as_deref()
    }
}

impl ReleaseSigKey for crate::provision_server::types::SigKey {
    fn name(&self) -> &str {
        &self.name
    }

    fn github_user(&self) -> &str {
        &self.github_user
    }

    fn fingerprint(&self) -> Option<&str> {
        self.fingerprint.as_deref()
    }
}

pub fn normalize_repo(input: &str) -> String {
    // Users may paste either owner/repo... an HTTPS GitHub URL... or a URL with a trailing .git suffix.
    // All of those should resolve to the owner/repo string used by the GitHub release API.
    // GitHub REST release endpoints take the repository as owner and repo path parameters, see here: https://docs.github.com/en/rest/releases/releases?apiVersion=2026-03-10#get-the-latest-release.
    let trimmed = input.trim().trim_end_matches('/');
    if let Some(idx) = trimmed.find("github.com/") {
        let repo = &trimmed[idx + "github.com/".len()..];
        return repo.trim_end_matches(".git").to_string();
    }
    trimmed.trim_end_matches(".git").to_string()
}

pub fn resolve_signers<K: ReleaseSigKey>(sig_keys: Option<&[K]>) -> Vec<Signer> {
    // An omitted or empty signer list means the default Secluso release signers are required.
    // When custom keys are provided, each field is trimmed before being handed to the updater library
    // The updater later resolves GitHub-published signing keys through GitHub's GPG key API, see here: https://docs.github.com/en/rest/users/gpg-keys?apiVersion=2026-03-10
    let Some(sig_keys) = sig_keys else {
        return default_signers();
    };

    if sig_keys.is_empty() {
        return default_signers();
    }

    sig_keys
        .iter()
        .map(|key| Signer {
            label: key.name().trim().to_string(),
            github_user: key.github_user().trim().to_string(),
            fingerprint: key
                .fingerprint()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned),
        })
        .collect()
}
