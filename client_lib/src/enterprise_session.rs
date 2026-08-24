//! SPDX-License-Identifier: GPL-3.0-or-later
//!
//! Bearer-token session for the enterprise DS

use serde::Deserialize;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Refresh this long before the token actually expires
const REFRESH_MARGIN: Duration = Duration::from_secs(60);

/// /account/register, /account/login and /account/refresh
#[derive(Debug, Deserialize)]
pub struct AuthBody {
    pub access_token: String,
    #[serde(default)]
    pub token_type: String,
    pub refresh_token: String,
    /// Seconds until access_token expires.
    pub expires_in: i64,
}

#[derive(Debug, Clone)]
struct Tokens {
    access: String,
    refresh: String,
    /// When the access token stops being usable.
    expires_at: Instant,
}

/// So a cloned HttpClient refreshes once rather than once per clone.
#[derive(Clone, Default)]
pub struct EnterpriseSession {
    tokens: Arc<Mutex<Option<Tokens>>>,
}

impl EnterpriseSession {
    pub fn new() -> Self {
        Self::default()
    }

    /// Store what a login or refresh returned.
    pub fn store(&self, body: AuthBody) -> io::Result<String> {
        let access = body.access_token.clone();

        let expires_at = Instant::now()
            + Duration::from_secs(body.expires_in.max(0) as u64)
                .saturating_sub(REFRESH_MARGIN);

        let mut guard = self
            .tokens
            .lock()
            .map_err(|_| io::Error::other("Session lock was poisoned".to_string()))?;

        *guard = Some(Tokens {
            access: access.clone(),
            refresh: body.refresh_token,
            expires_at,
        });

        Ok(access)
    }

    pub fn access_token(&self) -> Option<String> {
        let guard = self.tokens.lock().ok()?;
        let tokens = guard.as_ref()?;

        (Instant::now() < tokens.expires_at).then(|| tokens.access.clone())
    }

    pub fn refresh_token(&self) -> Option<String> {
        let guard = self.tokens.lock().ok()?;
        guard.as_ref().map(|tokens| tokens.refresh.clone())
    }

    pub fn clear(&self) {
        if let Ok(mut guard) = self.tokens.lock() {
            *guard = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(expires_in: i64) -> AuthBody {
        AuthBody {
            access_token: "access".to_string(),
            token_type: "Bearer".to_string(),
            refresh_token: "refresh".to_string(),
            expires_in,
        }
    }

    #[test]
    fn a_fresh_token_is_handed_out() {
        let session = EnterpriseSession::new();
        session.store(body(900)).unwrap();

        assert_eq!(session.access_token().as_deref(), Some("access"));
        assert_eq!(session.refresh_token().as_deref(), Some("refresh"));
    }

    #[test]
    fn nothing_is_handed_out_before_a_login() {
        let session = EnterpriseSession::new();

        assert!(session.access_token().is_none());
        assert!(session.refresh_token().is_none());
    }

    #[test]
    fn a_token_inside_the_refresh_margin_is_already_stale() {
        // 15s left against a 60s margin: still valid to the server.. not worth sending though
        let session = EnterpriseSession::new();
        session.store(body(15)).unwrap();

        assert!(session.access_token().is_none());
        // Costs a refresh and not a re-login.
        assert_eq!(session.refresh_token().as_deref(), Some("refresh"));
    }

    #[test]
    fn clearing_forces_a_fresh_login() {
        let session = EnterpriseSession::new();
        session.store(body(900)).unwrap();
        session.clear();

        assert!(session.access_token().is_none());
        assert!(session.refresh_token().is_none());
    }

    #[test]
    fn clones_share_one_session() {
        // Otherwise every clone would log in separately and they'd fight over the single-use refresh token.
        let session = EnterpriseSession::new();
        let clone = session.clone();

        session.store(body(900)).unwrap();
        assert_eq!(clone.access_token().as_deref(), Some("access"));

        clone.clear();
        assert!(session.access_token().is_none());
    }
}
