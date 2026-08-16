//! SPDX-License-Identifier: GPL-3.0-or-later

use crate::http_client::HttpClient;
use std::io;

#[cfg(feature = "p2p")]
use crate::p2p::{self, quic::PeerConnection, Role};
#[cfg(feature = "p2p")]
use std::collections::HashMap;
#[cfg(feature = "p2p")]
use std::sync::Mutex;
#[cfg(feature = "p2p")]
use std::time::{Duration, Instant};

/// Largest livestream chunk
pub const MAX_LIVESTREAM_CHUNK: usize = 20 * 1024 * 1024;

/// How long to wait on direct for a specific chunk before giving up on it and asking the relay.
#[cfg(feature = "p2p")]
const DIRECT_CHUNK_TIMEOUT: Duration = Duration::from_millis(1500);

/// Where did session ended up using?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Path {
    Direct,
    Relay,
}

pub struct LivestreamSession {
    http_client: HttpClient,
    group_name: String,

    #[cfg(feature = "p2p")]
    direct: Option<Direct>,
}

#[cfg(feature = "p2p")]
struct Direct {
    connection: PeerConnection,
    runtime: tokio::runtime::Runtime,
    /// Chunks that arrived before they were asked for.
    pending: Mutex<HashMap<u64, Vec<u8>>>,
}

impl LivestreamSession {
    /// Open a session, trying for a direct connection first.
    pub fn open(http_client: HttpClient, group_name: &str, _camera: &str) -> Self {
        Self {
            http_client,
            group_name: group_name.to_string(),
            #[cfg(feature = "p2p")]
            direct: None,
        }
    }

    /// As above, but attempt direct
    #[cfg(feature = "p2p")]
    pub fn open_direct(http_client: HttpClient, group_name: &str, camera: &str, role: Role) -> Self {
        let direct = Self::establish_direct(&http_client, camera, role);

        if direct.is_none() {
            log_relay_fallback(camera);
        }

        Self {
            http_client,
            group_name: group_name.to_string(),
            direct,
        }
    }

    #[cfg(not(feature = "p2p"))]
    pub fn open_direct(http_client: HttpClient, group_name: &str, camera: &str) -> Self {
        Self::open(http_client, group_name, camera)
    }

    #[cfg(feature = "p2p")]
    fn establish_direct(http_client: &HttpClient, camera: &str, role: Role) -> Option<Direct> {
        // Only the enterprise DS has a rendezvous to exchange candidates
        if !http_client.backend().is_enterprise() {
            return None;
        }

        let path = p2p::try_direct(http_client, camera, role).ok().flatten()?;

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .ok()?;

        let connection = runtime.block_on(p2p::quic::connect(path)).ok()?;

        Some(Direct {
            connection,
            runtime,
            pending: Mutex::new(HashMap::new()),
        })
    }

    pub fn path(&self) -> Path {
        #[cfg(feature = "p2p")]
        if self.direct.is_some() {
            return Path::Direct;
        }

        Path::Relay
    }

    /// Send a chunk. Returns the number of chunks the server has pending
    pub fn upload_chunk(&self, chunk_number: u64, data: Vec<u8>) -> io::Result<usize> {
        #[cfg(feature = "p2p")]
        if let Some(direct) = &self.direct {
            match direct
                .runtime
                .block_on(direct.connection.send_chunk(chunk_number, &data))
            {
                Ok(()) => return Ok(0),
                // Don't fail the stream over it. The relay is still there.
                Err(e) => log_direct_failure("send", e),
            }
        }

        self.http_client
            .livestream_upload(&self.group_name, data, chunk_number)
    }

    /// Fetch a chunk by number.
    pub fn retrieve_chunk(&self, chunk_number: u64) -> io::Result<Vec<u8>> {
        #[cfg(feature = "p2p")]
        if let Some(direct) = &self.direct {
            match self.retrieve_direct(direct, chunk_number) {
                Ok(Some(chunk)) => return Ok(chunk),
                // Nothing arrived in time, or the connection broke. Either way, relay.
                Ok(None) => {}
                Err(e) => log_direct_failure("receive", e),
            }
        }

        self.http_client
            .livestream_retrieve(&self.group_name, chunk_number)
    }

    /// Read from the direct path until the wanted chunk shows up or the budget runs out.
    #[cfg(feature = "p2p")]
    fn retrieve_direct(&self, direct: &Direct, chunk_number: u64) -> io::Result<Option<Vec<u8>>> {
        if let Ok(mut pending) = direct.pending.lock() {
            if let Some(chunk) = pending.remove(&chunk_number) {
                return Ok(Some(chunk));
            }
        }

        let deadline = Instant::now() + DIRECT_CHUNK_TIMEOUT;

        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());

            let received = direct.runtime.block_on(async {
                tokio::time::timeout(remaining, direct.connection.recv_chunk(MAX_LIVESTREAM_CHUNK))
                    .await
            });

            match received {
                Ok(Ok((number, chunk))) if number == chunk_number => return Ok(Some(chunk)),
                Ok(Ok((number, chunk))) => {
                    if let Ok(mut pending) = direct.pending.lock() {
                        pending.insert(number, chunk);
                    }
                }
                Ok(Err(e)) => return Err(e),
                // Timed out waiting.
                Err(_) => break,
            }
        }

        Ok(None)
    }
}

#[cfg(feature = "p2p")]
fn log_direct_failure(what: &str, error: io::Error) {
    #[cfg(feature = "logging")]
    log::debug!("Direct livestream {what} failed, using the relay: {error}");
    #[cfg(not(feature = "logging"))]
    let _ = (what, error);
}

#[cfg(feature = "p2p")]
fn log_relay_fallback(camera: &str) {
    #[cfg(feature = "logging")]
    log::debug!("No direct path to {camera}; livestreaming through the relay");
    #[cfg(not(feature = "logging"))]
    let _ = camera;
}

#[cfg(test)]
mod tests {
    use super::*;
    use secluso_client_server_lib::auth::ServerBackend;

    fn relay_session() -> LivestreamSession {
        LivestreamSession::open(
            HttpClient::new_with_backend(
                "http://127.0.0.1:1".to_string(),
                "user".to_string(),
                "pass".to_string(),
                ServerBackend::SelfHosted,
            ),
            "group",
            "camera",
        )
    }

    #[test]
    fn a_session_with_no_direct_path_reports_relay() {
        assert_eq!(relay_session().path(), Path::Relay);
    }

    #[cfg(feature = "p2p")]
    #[test]
    fn the_self_hosted_backend_never_attempts_a_direct_path() {
        // no rendezvous to exchange candidates through
        let client = HttpClient::new_with_backend(
            "http://127.0.0.1:1".to_string(),
            "user".to_string(),
            "pass".to_string(),
            ServerBackend::SelfHosted,
        );

        let session = LivestreamSession::open_direct(client, "group", "camera", Role::Camera);

        assert_eq!(session.path(), Path::Relay);
    }

    #[cfg(feature = "p2p")]
    #[test]
    fn an_unreachable_enterprise_server_still_yields_a_working_session() {
        // Nothing is listening on this port. 
        let client = HttpClient::new_with_backend(
            "http://127.0.0.1:1".to_string(),
            "user".to_string(),
            "pass".to_string(),
            ServerBackend::Enterprise,
        );

        let session = LivestreamSession::open_direct(client, "group", "camera", Role::App);

        assert_eq!(session.path(), Path::Relay);
    }
}
