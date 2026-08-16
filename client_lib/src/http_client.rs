//! Secluso HTTP client for using the delivery service (DS).
//!
//! SPDX-License-Identifier: GPL-3.0-or-later

use crate::enterprise_session::{AuthBody, EnterpriseSession};
use crate::object_name::object_name;
use base64::engine::general_purpose::STANDARD as base64_engine;
use base64::{engine::general_purpose, Engine as _};
use reqwest::blocking::{Body, Client, RequestBuilder};
use reqwest::Url;
use reqwest::StatusCode;
use secluso_client_server_lib::auth::ServerBackend;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Write, Read};
use std::net::TcpStream;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::{Duration, Instant};
use std::env;

// Some of these constants are based on the ones in server/main.rs.
const MAX_MOTION_FILE_SIZE: u64 = 50 * 1024 * 1024; // 50 mebibytes
const MAX_LIVESTREAM_FILE_SIZE: u64 = 20 * 1024 * 1024; // 20 mebibytes
const MAX_COMMAND_FILE_SIZE: u64 = 100 * 1024; // 100 kibibytes
const MAX_CHECK_RESP_SIZE: u64 = 20 * 1024; // 20 kibibytes
const MAX_NOTIFICATION_TARGET_SIZE: u64 = 10 * 1024; // 10 kibibytes
const IOS_NOTIFICATION_RESP_MAX_SIZE: u64 = 10 * 1024; // 10 kibibytes
const MAX_RELAY_MSG_SIZE: u64 = 100 * 1024; // 100 kibibytes

// The enterprise DS pushes livestream events over a WebSocket
const ENTERPRISE_LIVESTREAM_POLL_INTERVAL: Duration = Duration::from_secs(1);
const ENTERPRISE_LIVESTREAM_POLL_WINDOW: Duration = Duration::from_secs(30);

// Same for config commands
const ENTERPRISE_CONFIG_POLL_INTERVAL: Duration = Duration::from_secs(1);
const ENTERPRISE_CONFIG_POLL_WINDOW: Duration = Duration::from_secs(30);

/// One camera to ask about in a bulk check.
#[derive(Debug, Clone)]
pub struct BulkCheckRequest {
    pub group_name: String,
    pub epoch_to_check: u64,
    /// The group's MLS exporter key.
    pub object_key: Option<Vec<u8>>,
}

/// `filename` is for enterprise DS
#[derive(Debug, Serialize)]
struct MotionPair {
    group_name: String,
    epoch_to_check: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    filename: Option<String>,
}

#[derive(Debug, Serialize)]
struct MotionPairs {
    group_names: Vec<MotionPair>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Subscription {
    pub uuid: String,
    pub tier: String,
    pub status: String,
    #[serde(default)]
    pub expires_at: Option<i64>,
    #[serde(default)]
    pub role: Option<String>,
}

/// What a subscription is storing, broken down by what it is storing.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct UsageReport {
    pub subscription: String,
    pub tier: String,
    pub object_count: i64,
    pub object_bytes: i64,
    pub livestream_count: i64,
    pub livestream_bytes: i64,
    pub debug_count: i64,
    pub debug_bytes: i64,
    pub stored_bytes: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SubscriptionList {
    pub subscriptions: Vec<Subscription>,
}

/// A camera that has something waiting, and when it landed.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct GroupTimestamp {
    pub group_name: String,
    pub timestamp: i64,
}

/// What the enterprise DS answers with on every /livestream route.
#[derive(Debug, Default, Deserialize)]
pub struct LivestreamStatus {
    pub active: bool,
    #[serde(default)]
    pub session: Option<String>,
    #[serde(default)]
    pub chunks: i64,
}

#[derive(Clone)]
pub struct HttpClient {
    server_addr: String,
    server_username: String,
    server_password: String,
    /// Which delivery service this is.
    backend: ServerBackend,
    /// Bearer tokens for enterprise DS
    session: EnterpriseSession,
    /// Which subscription this camera bills against on the enterprise DS.
    subscription_uuid: Arc<Mutex<Option<String>>>,
    /// Current livestream session id per group on the enterprise DS.
    livestream_sessions: Arc<Mutex<HashMap<String, String>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IosRelayBinding {
    pub relay_base_url: String,
    pub hub_token: String,
    pub app_install_id: String,
    pub hub_id: String,
    pub device_token: String,
    pub expires_at_epoch_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationTarget {
    pub platform: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ios_relay_binding: Option<IosRelayBinding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unifiedpush_endpoint_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unifiedpush_pub_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unifiedpush_auth: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingStatus {
    pub status: String,
    #[serde(default)]
    pub notification_target: Option<NotificationTarget>,
}

const TRUSTED_IOS_RELAY_HOSTS: &[&str] = &["relay.secluso.com", "testing-relay.secluso.com"];


/// Everything HTTP goes through here.
fn client_builder() -> reqwest::blocking::ClientBuilder {
    #[cfg(not(target_os = "android"))]
    {
        Client::builder()
    }
    #[cfg(target_os = "android")]
    {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("ring supports the default TLS versions")
        .with_root_certificates(roots)
        .with_no_client_auth();

        Client::builder().use_preconfigured_tls(config)
    }
}

//TODO: There's a lot of repitition between the functions here.

// Note: The server needs a unique name for each camera.
// The name needs to be available to both the camera and the app.
// We use the MLS group name for that purpose.

// Mirror the server-side relay checks before the hub sends any outbound iOS request.
// Ensures a malicious/stale notification target cannot turn the hub into a generic HTTPS client.
fn validate_ios_relay_base_url(raw_url: &str) -> io::Result<Url> {
    let parsed = Url::parse(raw_url)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    if parsed.scheme() != "https" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "iOS relay base URL must use https",
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "iOS relay base URL must not include credentials",
        ));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "iOS relay base URL must not include a query or fragment",
        ));
    }
    if parsed.path() != "/" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "iOS relay base URL must not include a path prefix",
        ));
    }

    let host = parsed.host_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "iOS relay base URL is missing a host",
        )
    })?;
    let port = parsed.port_or_known_default().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "iOS relay base URL is missing an https port",
        )
    })?;
    if port != 443 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "iOS relay base URL must use the default https port",
        ));
    }
    if !TRUSTED_IOS_RELAY_HOSTS
        .iter()
        .any(|allowed| host.eq_ignore_ascii_case(allowed))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Refusing unexpected iOS relay host: {host}"),
        ));
    }

    Ok(parsed)
}

pub fn validate_ios_relay_binding(binding: &IosRelayBinding) -> io::Result<Url> {
    let relay_base = binding.relay_base_url.trim();
    if relay_base.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "iOS relay base URL is required",
        ));
    }
    validate_ios_relay_base_url(relay_base)
}

impl HttpClient {
    /// Attach whatever the server we're talking to expects.
    pub fn authorized_headers(&self, request_builder: RequestBuilder) -> RequestBuilder {
        if self.backend.is_enterprise() {
            if let Ok(token) = self.access_token() {
                let request_builder =
                    request_builder.header("Authorization", format!("Bearer {}", token));
                return match self.subscription_uuid() {
                    Some(uuid) => request_builder.header("X-Subscription-Uuid", uuid),
                    None => request_builder,
                };
            }
        }

        let auth_value = format!("{}:{}", self.server_username, self.server_password);
        let auth_encoded = general_purpose::STANDARD.encode(auth_value);
        let auth_header = format!("Basic {}", auth_encoded);

        request_builder.header("Authorization", auth_header).header("Client-Version", env!("CARGO_PKG_VERSION"))
    }

    pub fn new(
        server_addr: String, // ip_addr:port
        server_username: String,
        server_password: String,
    ) -> Self {
        Self::new_with_backend(
            server_addr,
            server_username,
            server_password,
            ServerBackend::default(),
        )
    }

    pub fn new_with_backend(
        server_addr: String,
        server_username: String,
        server_password: String,
        backend: ServerBackend,
    ) -> Self {
        Self {
            server_addr,
            server_username,
            server_password,
            backend,
            session: EnterpriseSession::new(),
            subscription_uuid: Arc::new(Mutex::new(None)),
            livestream_sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn subscription_uuid(&self) -> Option<String> {
        self.subscription_uuid.lock().ok().and_then(|g| g.clone())
    }

    pub fn set_subscription_uuid(&self, uuid: Option<String>) {
        if let Ok(mut guard) = self.subscription_uuid.lock() {
            *guard = uuid;
        }
    }

    pub fn livestream_session_ready(&self, group_name: &str) -> bool {
        if !self.backend.is_enterprise() {
            return true;
        }
        self.livestream_session(group_name).is_ok()
    }

    pub fn forget_livestream_session(&self, group_name: &str) {
        if let Ok(mut guard) = self.livestream_sessions.lock() {
            guard.remove(group_name);
        }
    }

    fn remember_livestream_session(&self, group_name: &str, session: &str) {
        if let Ok(mut guard) = self.livestream_sessions.lock() {
            guard.insert(group_name.to_string(), session.to_string());
        }
    }

    fn livestream_session(&self, group_name: &str) -> io::Result<String> {
        if let Some(session) = self
            .livestream_sessions
            .lock()
            .ok()
            .and_then(|guard| guard.get(group_name).cloned())
        {
            return Ok(session);
        }

        // No run holds a session; so lets adopt the current one.
        let status = self.enterprise_livestream_status(group_name)?;
        match status.session.filter(|_| status.active) {
            Some(session) => {
                if let Ok(mut guard) = self.livestream_sessions.lock() {
                    guard
                        .entry(group_name.to_string())
                        .or_insert_with(|| session.clone());
                }
                Ok(session)
            }
            None => Err(io::Error::other(
                "No livestream session yet; start or check the stream first".to_string(),
            )),
        }
    }

    /// Attach the livestream session id
    fn livestream_headers(&self, request_builder: RequestBuilder, group_name: &str) -> io::Result<RequestBuilder> {
        if !self.backend.is_enterprise() {
            return Ok(request_builder);
        }

        Ok(request_builder.header("X-Livestream-Session", self.livestream_session(group_name)?))
    }

    /// GET /livestream/<camera> on the enterprise DS
    fn enterprise_livestream_status(&self, group_name: &str) -> io::Result<LivestreamStatus> {
        let client = client_builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(io::Error::other)?;

        let response = self
            .authorized_headers(client.get(format!("{}/livestream/{}", self.server_addr, group_name)))
            .send()
            .map_err(io::Error::other)?;

        if !response.status().is_success() {
            return Err(io::Error::other(format!(
                "Server error: {}",
                response.status()
            )));
        }

        // Deliberately not remembering the session here.
        response.json().map_err(io::Error::other)
    }

    pub fn backend(&self) -> ServerBackend {
        self.backend
    }

    /// A usable access token, logging in or refreshing if the one we hold has aged out.
    ///
    /// Refresh first: it skips the server's Argon2 verification
    fn access_token(&self) -> io::Result<String> {
        if let Some(token) = self.session.access_token() {
            return Ok(token);
        }

        if let Some(refresh) = self.session.refresh_token() {
            match self.post_auth(
                "/account/refresh",
                json!({
                    "username": self.server_username,
                    "refresh_token": refresh,
                }),
            ) {
                Ok(body) => return self.session.store(body),
                Err(_) => self.session.clear(),
            }
        }

        let body = self.post_auth(
            "/account/login",
            json!({
                "client_id": self.server_username,
                "client_secret": self.server_password,
            }),
        )?;

        self.session.store(body)
    }

    /// One unauthenticated POST to an /account route.
    fn post_auth(&self, path: &str, payload: serde_json::Value) -> io::Result<AuthBody> {
        let client = client_builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(io::Error::other)?;

        let response = client
            .post(format!("{}{}", self.server_addr, path))
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .map_err(io::Error::other)?;

        if !response.status().is_success() {
            return Err(io::Error::other(format!(
                "Enterprise auth failed at {path}: {}",
                response.status()
            )));
        }

        response.json::<AuthBody>().map_err(io::Error::other)
    }

    pub fn register(&self) -> io::Result<()> {
        if !self.backend.is_enterprise() {
            return Ok(());
        }

        match self.post_auth(
            "/account/register",
            json!({
                "username": self.server_username,
                "password": self.server_password,
            }),
        ) {
            Ok(body) => {
                self.session.store(body)?;
            }
            Err(_) => {
                self.access_token()?;
            }
        }

        self.ensure_subscription()
    }

    fn ensure_subscription(&self) -> io::Result<()> {
        if !self.backend.is_enterprise() {
            return Ok(());
        }

        let client = client_builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(io::Error::other)?;

        let existing = self
            .authorized_headers(client.get(format!("{}/subscription", self.server_addr)))
            .send()
            .map_err(io::Error::other)?;

        if existing.status().is_success() {
            let body: SubscriptionList = existing.json().map_err(io::Error::other)?;
            let mut active = body
                .subscriptions
                .iter()
                .filter(|sub| sub.status == "active");
            if let Some(sub) = active.next() {
                // Adopt it only when it's unambiguous
                if self.subscription_uuid().is_none() && active.next().is_none() {
                    self.set_subscription_uuid(Some(sub.uuid.clone()));
                }
                return Ok(());
            }
        }

        // Nothing yet, so take the free tier.
        let response = self
            .authorized_headers(client.post(format!("{}/subscription/free", self.server_addr)))
            .send()
            .map_err(io::Error::other)?;

        if response.status() == StatusCode::FORBIDDEN {
            return Err(io::Error::other(
                "This delivery service does not allow self-serve subscriptions; the \
                 account must be provisioned by the platform"
            ));
        }

        if !response.status().is_success() && response.status() != StatusCode::CONFLICT {
            return Err(io::Error::other(format!(
                "Could not claim a subscription: {}",
                response.status()
            )));
        }

        if response.status().is_success() {
            if let Ok(sub) = response.json::<Subscription>() {
                self.set_subscription_uuid(Some(sub.uuid));
            }
        }

        self.session.clear();

        Ok(())
    }

    /// Where an object is on whichever DS this is.
    fn object_url(
        &self,
        group_name: &str,
        file_name: &str,
        object_name: Option<&str>,
    ) -> io::Result<String> {
        if !self.backend.is_enterprise() {
            return Ok(format!("{}/{}/{}", self.server_addr, group_name, file_name));
        }

        let object_name = object_name.ok_or_else(|| {
            io::Error::other(
                "The enterprise delivery service needs a derived object name".to_string(),
            )
        })?;

        Ok(format!("{}/{}", self.server_addr, object_name))
    }

    fn give_hint_to_updater() {
        if let Ok(update_hint_path_str) = env::var("UPDATE_HINT_PATH") {
            let update_hint_path = Path::new(&update_hint_path_str);

            if !update_hint_path.exists() {
                if let Err(e) = File::create(update_hint_path) {
                    eprintln!("Failed to create file: {}", e);
                }
                println!("Update hint file created: {}", update_hint_path_str);
            }
        }
    }

    /// Atomically confirm pairing with app and receive any phone-side notification target metadata.
    pub fn send_pairing_token(&self, pairing_token: &str) -> io::Result<PairingStatus> {
        let url = format!("{}/pair", self.server_addr);

        let body = json!({
            "pairing_token": pairing_token,
            "role": "camera",
        });

        let client = client_builder()
            .timeout(Duration::from_secs(45)) // Wait up to 45s
            .build()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        let response = self.authorized_headers(client
            .post(&url))
            .header("Content-Type", "application/json")
            .body(body.to_string())
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::TimedOut, e.to_string()))?;

        if response.status() == StatusCode::CONFLICT {
            Self::give_hint_to_updater();
        }

        if !response.status().is_success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Pairing failed: {}", response.status()),
            ));
        }

        let text = response
            .text()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        serde_json::from_str::<PairingStatus>(&text)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }

    pub fn fetch_notification_target(&self) -> io::Result<Option<NotificationTarget>> {
        let max_size = MAX_NOTIFICATION_TARGET_SIZE;

        let url = format!("{}/notification_target", self.server_addr);

        let client = client_builder()
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        let response = self.authorized_headers(client
            .get(&url))
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::TimedOut, e.to_string()))?;

        if response.status() == StatusCode::CONFLICT {
            Self::give_hint_to_updater();
        }

        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }

        if !response.status().is_success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Notification target fetch failed: {}", response.status()),
            ));
        }

        let mut buf = Vec::new();
        let mut limited = response.take(max_size);
        limited.read_to_end(&mut buf)?;

        if buf.len() >= max_size as usize {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Notification target response exceeded maximum allowed size",
            ));
        }

        let target = serde_json::from_slice::<NotificationTarget>(&buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        Ok(Some(target))
    }

    pub fn send_ios_notification(
        &self,
        notification: Vec<u8>,
        binding: &IosRelayBinding,
    ) -> io::Result<()> {
        const IOS_RELAY_USER_AGENT: &str = "SeclusoCameraHub/1.0";

        let relay_base = validate_ios_relay_binding(binding)?;
        let relay_url = relay_base
            .join("hub/notify")
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

        let payload = json!({
            "hub_token": binding.hub_token,
            "app_install_id": binding.app_install_id,
            "hub_id": binding.hub_id,
            "device_token": binding.device_token,
            "payload": {
                "aps": {
                    "content-available": 1
                },
                "body": base64_engine.encode(notification),
            },
            "push_type": "background",
        });

        let client = client_builder()
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        // This does NOT need authorized_headers as it's a separate relay (public Secluso iOS relay)
        let response = client
            .post(relay_url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .header("User-Agent", IOS_RELAY_USER_AGENT)
            .body(payload.to_string())
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        if response.status() == StatusCode::CONFLICT {
            Self::give_hint_to_updater();
        }

        if !response.status().is_success() {
            let status = response.status();
            let content_type = response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("<missing>")
                .to_string();
            let server = response
                .headers()
                .get(reqwest::header::SERVER)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("<missing>")
                .to_string();
            let via = response
                .headers()
                .get(reqwest::header::VIA)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("<missing>")
                .to_string();
            let cf_ray = response
                .headers()
                .get("cf-ray")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("<missing>")
                .to_string();

            let max_size = IOS_NOTIFICATION_RESP_MAX_SIZE;

            let mut buf = Vec::new();
            let mut limited = response.take(max_size);
            limited.read_to_end(&mut buf)?;

            let body = if buf.len() >= max_size.try_into().unwrap() {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!(
                        "ios notification response exceeded maximum allowed size"
                    ),
                ));
            } else {
                String::from_utf8_lossy(&buf).to_string()
            };


            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "Relay error: {status} (content-type={content_type}, server={server}, via={via}, cf-ray={cf_ray}) {body}"
                ),
            ));
        }

        Ok(())
    }

    /// Uploads an (encrypted) file.
    ///
    /// object_name = enterprise DS's name for ref it
    pub fn upload_enc_file(
        &self,
        group_name: &str,
        enc_file_path: &Path,
        num_apps: usize,
        object_name: Option<&str>,
    ) -> io::Result<()> {
        let enc_file_name = enc_file_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap()
            .to_string();

        let server_url = format!(
            "{}/{}",
            self.object_url(group_name, &enc_file_name, object_name)?,
            num_apps
        );

        let file = File::open(enc_file_path)?;
        let reader = BufReader::new(file);

        let client = client_builder()
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        let response = self.authorized_headers(client
            .post(server_url))
            .header("Content-Type", "application/octet-stream")
            .body(Body::new(reader))
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        if response.status() == StatusCode::CONFLICT {
            Self::give_hint_to_updater();
        }

        if !response.status().is_success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Server error: {}", response.status()),
            ));
        }

        Ok(())
    }

    /// Fetches an (encrypted) video file or thumbnail, persists it, and then deletes it from the server.
    pub fn fetch_enc_file(
        &self,
        group_name: &str,
        enc_file_path: &Path,
        object_name: Option<&str>,
    ) -> io::Result<()> {
        let max_size = MAX_MOTION_FILE_SIZE;

        let enc_file_name = enc_file_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap()
            .to_string();

        self.fetch_enc_file_named(group_name, &enc_file_name, enc_file_path, max_size, object_name)
    }

    /// Fetches an encrypted file whose server-side name and local temp filename differ.
    pub fn fetch_enc_file_named(
        &self,
        group_name: &str,
        server_file_name: &str,
        local_file_path: &Path,
        max_size: u64,
        object_name: Option<&str>,
    ) -> io::Result<()> {
        let server_url = self.object_url(group_name, server_file_name, object_name)?;

        let client = client_builder()
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        let response = self.authorized_headers(client
            .get(&server_url))
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        if response.status() == StatusCode::CONFLICT {
            Self::give_hint_to_updater();
        }

        if !response.status().is_success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Server error: {}", response.status()),
            ));
        }

        let mut file = BufWriter::new(File::create(local_file_path)?);

        let mut limited = response.take(max_size);

        let bytes_copied = io::copy(&mut limited, &mut file)?;
        file.flush().unwrap();
        file.into_inner()?.sync_all()?;

        if bytes_copied >= max_size {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "File download exceeded maximum allowed size",
            ));
        }

        let del_response = self.authorized_headers(client
            .delete(&server_url))
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        if del_response.status() == StatusCode::CONFLICT {
            Self::give_hint_to_updater();
        }

        if !del_response.status().is_success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Server error: {}", del_response.status()),
            ));
        }

        Ok(())
    }

    pub fn deregister(&self, group_name: &str) -> io::Result<()> {
        let server_url = if self.backend.is_enterprise() {
            format!("{}/camera/{}", self.server_addr, group_name)
        } else {
            format!("{}/{}", self.server_addr, group_name)
        };

        let client = client_builder().build().expect("default HTTP client");
        let response = self.authorized_headers(client
            .delete(&server_url))
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        if response.status() == StatusCode::CONFLICT {
            Self::give_hint_to_updater();
        }

        if !response.status().is_success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Server error: {}", response.status()),
            ));
        }

        Ok(())
    }

    pub fn send_fcm_notification(&self, notification: Vec<u8>) -> io::Result<()> {
        let server_url = format!("{}/fcm_notification", self.server_addr);

        let client = client_builder().build().expect("default HTTP client");
        let response = self.authorized_headers(client
            .post(server_url))
            .header("Content-Type", "application/octet-stream")
            .body(notification)
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        if response.status() == StatusCode::CONFLICT {
            Self::give_hint_to_updater();
        }

        if !response.status().is_success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Server error: {}", response.status()),
            ));
        }

        Ok(())
    }

    /// Start a livestream session
    pub fn livestream_start(&self, group_name: &str) -> io::Result<()> {
        // Enterprise mints a session id here and every chunk has to include
        if self.backend.is_enterprise() {
            let client = client_builder()
                .timeout(Duration::from_secs(30))
                .build()
                .map_err(io::Error::other)?;

            let response = self
                .authorized_headers(
                    client.post(format!("{}/livestream/{}", self.server_addr, group_name)),
                )
                .send()
                .map_err(io::Error::other)?;

            if !response.status().is_success() {
                return Err(io::Error::other(format!(
                    "Server error: {}",
                    response.status()
                )));
            }

            let status: LivestreamStatus = response.json().map_err(io::Error::other)?;
            let session = status.session.ok_or_else(|| {
                io::Error::other("Server started a livestream with no session".to_string())
            })?;

            self.remember_livestream_session(group_name, &session);

            return Ok(());
        }

        let server_url = format!("{}/livestream/{}", self.server_addr, group_name);

        let client = client_builder().build().expect("default HTTP client");
        let response = self.authorized_headers(client
            .post(server_url))
            .header("Content-Type", "application/octet-stream")
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        if response.status() == StatusCode::CONFLICT {
            Self::give_hint_to_updater();
        }

        if !response.status().is_success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Server error: {}", response.status()),
            ));
        }

        Ok(())
    }

    fn livestream_wait_for_start(
        &self,
        group_name: &str,
        window: Duration,
    ) -> io::Result<bool> {
        use tungstenite::client::IntoClientRequest;

        let ws_addr = self
            .server_addr
            .replacen("https://", "wss://", 1)
            .replacen("http://", "ws://", 1);
        let mut request = format!("{ws_addr}/livestream/{group_name}")
            .into_client_request()
            .map_err(io::Error::other)?;

        let token = self.access_token()?;
        request.headers_mut().insert(
            "Authorization",
            format!("Bearer {token}").parse().map_err(io::Error::other)?,
        );
        if let Some(uuid) = self.subscription_uuid() {
            request.headers_mut().insert(
                "X-Subscription-Uuid",
                uuid.parse().map_err(io::Error::other)?,
            );
        }

        // A plain TcpStream so the wait window can be a socket read timeout.
        let host = request
            .uri()
            .host()
            .ok_or_else(|| io::Error::other("no host in the socket url"))?
            .to_string();
        let secure = request.uri().scheme_str() == Some("wss");
        let port = request.uri().port_u16().unwrap_or(if secure { 443 } else { 80 });
        let stream = TcpStream::connect((host.as_str(), port))?;
        stream.set_read_timeout(Some(window))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;

        let connector = if secure {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let config = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .map_err(io::Error::other)?
            .with_root_certificates(roots)
            .with_no_client_auth();
            tungstenite::Connector::Rustls(Arc::new(config))
        } else {
            tungstenite::Connector::Plain
        };

        let (mut socket, _response) =
            tungstenite::client_tls_with_config(request, stream, None, Some(connector))
                .map_err(|e| io::Error::other(e.to_string()))?;

        loop {
            match socket.read() {
                Ok(tungstenite::Message::Text(text)) => {
                    let Ok(event) = serde_json::from_str::<serde_json::Value>(&text) else {
                        continue;
                    };
                    let kind = event.get("type").and_then(|v| v.as_str()).unwrap_or("");
                    if kind != "start" && kind != "chunk" {
                        continue;
                    }

                    // Adopt only if no run holds a session; see livestream_check.
                    if let Some(session) = event.get("session").and_then(|v| v.as_str()) {
                        if let Ok(mut guard) = self.livestream_sessions.lock() {
                            guard
                                .entry(group_name.to_string())
                                .or_insert_with(|| session.to_string());
                        }
                    }
                    let _ = socket.close(None);
                    return Ok(true);
                }
                Ok(_) => continue,
                Err(tungstenite::Error::Io(e))
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    let _ = socket.close(None);
                    return Ok(false);
                }
                Err(e) => return Err(io::Error::other(e.to_string())),
            }
        }
    }

    /// Checks to see if there's a livestream request.
    pub fn livestream_check(&self, group_name: &str) -> io::Result<()> {
        let max_size = MAX_CHECK_RESP_SIZE;

        // The enterprise DS pushes start/chunk/end events over a WebSocket, polling as backup
        if self.backend.is_enterprise() {
            match self.livestream_wait_for_start(group_name, ENTERPRISE_LIVESTREAM_POLL_WINDOW) {
                Ok(true) => return Ok(()),
                Ok(false) => {
                    return Err(io::Error::other("No livestream requested".to_string()))
                }
                Err(e) => {
                    log::debug!("Livestream socket unavailable ({e}); falling back to polling");
                }
            }

            let deadline = Instant::now() + ENTERPRISE_LIVESTREAM_POLL_WINDOW;

            loop {
                let status = self.enterprise_livestream_status(group_name)?;
                if status.active {
                    // This run streams into the session the viewer opened.
                    if let Some(session) = status.session.as_deref() {
                        if let Ok(mut guard) = self.livestream_sessions.lock() {
                            guard
                                .entry(group_name.to_string())
                                .or_insert_with(|| session.to_string());
                        }
                    }
                    return Ok(());
                }

                if Instant::now() >= deadline {
                    return Err(io::Error::other("No livestream requested".to_string()));
                }

                sleep(ENTERPRISE_LIVESTREAM_POLL_INTERVAL);
            }
        }

        let server_url = format!("{}/livestream/{}", self.server_addr, group_name);

        let client = client_builder()
            .timeout(None) // Disable timeout to allow long-polling
            .build()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        let response = self.authorized_headers(client
            .get(&server_url))
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        if response.status() == StatusCode::CONFLICT {
            Self::give_hint_to_updater();
        }

        if !response.status().is_success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Server error: {}", response.status()),
            ));
        }

        let mut buf = Vec::new();
        let mut limited = response.take(max_size);
        limited.read_to_end(&mut buf)?;

        if buf.len() >= max_size as usize {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Livestream check response exceeded maximum allowed size",
            ));
        }
        let reader = BufReader::new(&buf[..]);

        for line in reader.lines() {
            let line = line?;
            if line.starts_with("data:") {
                return Ok(());
            }
        }

        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Server error"),
        ));
    }

    /// Uploads some (encrypted) livestream data to the server.
    /// Returns the number of pending files in the server.
    pub fn livestream_upload(
        &self,
        group_name: &str,
        data: Vec<u8>,
        chunk_number: u64,
    ) -> io::Result<usize> {
        let server_url = format!(
            "{}/livestream/{}/{}",
            self.server_addr, group_name, chunk_number
        );

        let client = client_builder()
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        let response = self.livestream_headers(self.authorized_headers(client
            .post(server_url)), group_name)?
            .header("Content-Type", "application/octet-stream")
            .body(data)
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        if response.status() == StatusCode::CONFLICT {
            Self::give_hint_to_updater();
        }

        if !response.status().is_success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Server error: {}", response.status()),
            ));
        }

        let body = response
            .text()
            .map_err(|e: reqwest::Error| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        // The enterprise DS answers with the session status as JSON
        if self.backend.is_enterprise() {
            let status: LivestreamStatus =
                serde_json::from_str(&body).map_err(io::Error::other)?;
            return Ok(if status.active { 1 } else { 0 });
        }

        let num_files: usize = body
            .parse()
            .map_err(|e: std::num::ParseIntError| {
                io::Error::new(io::ErrorKind::Other, e.to_string())
            })?;

        Ok(num_files)
    }

    /// Retrieves and returns (encrypted) livestream data.
    pub fn livestream_retrieve(
        &self, group_name: &str,
        chunk_number: u64,
    ) -> io::Result<Vec<u8>> {
        let max_size = MAX_LIVESTREAM_FILE_SIZE;

        let server_url = format!(
            "{}/livestream/{}/{}",
            self.server_addr, group_name, chunk_number
        );
        let server_del_url = format!("{}/{}/{}", self.server_addr, group_name, chunk_number);

        let client = client_builder()
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        let response = self.livestream_headers(self.authorized_headers(client
            .get(&server_url)), group_name)?
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        if response.status() == StatusCode::CONFLICT {
            Self::give_hint_to_updater();
        }

        if !response.status().is_success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Server error: {}", response.status()),
            ));
        }

        let mut response_vec = Vec::new();
        let mut limited = response.take(max_size);

        limited.read_to_end(&mut response_vec)?;

        if response_vec.len() >= max_size.try_into().unwrap() {
            return Err(io::Error::new(io::ErrorKind::Other, "Livestream chunk download exceeded maximum allowed size"));
        }

        // The DIY server frees a chunk by fetch-then-delete.
        // The enterprise DS sweeps the whole session
        if self.backend.is_enterprise() {
            return Ok(response_vec);
        }

        let del_response = self.authorized_headers(client
            .delete(&server_del_url))
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        if del_response.status() == StatusCode::CONFLICT {
            Self::give_hint_to_updater();
        }

        if !del_response.status().is_success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Server error: {}", del_response.status()),
            ));
        }

        Ok(response_vec)
    }

    /// End a livestream session
    // FIXME: shares a lot of code with livestream_start
    pub fn livestream_end(&self, group_name: &str) -> io::Result<()> {
        let server_url = format!("{}/livestream_end/{}", self.server_addr, group_name);

        let client = client_builder().build().expect("default HTTP client");
        let response = self.authorized_headers(client
            .post(server_url))
            .header("Content-Type", "application/octet-stream")
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        if response.status() == StatusCode::CONFLICT {
            Self::give_hint_to_updater();
        }

        if !response.status().is_success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Server error: {}", response.status()),
            ));
        }

        Ok(())
    }

    /// Send a config command
    pub fn config_command(&self, group_name: &str, command: Vec<u8>) -> io::Result<()> {
        let server_url = format!("{}/config/{}", self.server_addr, group_name);

        if command.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Error: empty config command",
            ));
        }

        let expected_size = command.len().to_string();

        let client = client_builder().build().expect("default HTTP client");
        let response = self.authorized_headers(client
            .post(server_url))
            .header("Content-Type", "application/octet-stream")
            .header("X-Command-Size", expected_size)
            .body(command)
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        if response.status() == StatusCode::CONFLICT {
            Self::give_hint_to_updater();
        }

        if !response.status().is_success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Server error: {}", response.status()),
            ));
        }

        Ok(())
    }

    /// Checks to see if there's a config command.
    /// The server sends the command encoded in Base64.
    /// This function converts the command to Vec<u8> to returns it.
    /// Waits for a config command for this camera.
    pub fn config_check(&self, group_name: &str) -> io::Result<Vec<u8>> {
        let max_size = MAX_CHECK_RESP_SIZE;

        let server_url = format!("{}/config/{}", self.server_addr, group_name);

        let client = client_builder()
            .timeout(None) // Disable timeout to allow long-polling
            .build()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        let response = self.authorized_headers(client
            .get(&server_url))
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        if response.status() == StatusCode::CONFLICT {
            Self::give_hint_to_updater();
        }

        if !response.status().is_success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Server error: {}", response.status()),
            ));
        }

        let mut buf = Vec::new();
        let mut limited = response.take(max_size);
        limited.read_to_end(&mut buf)?;

        if buf.len() >= max_size as usize {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Livestream check response exceeded maximum allowed size",
            ));
        }

        if self.backend.is_enterprise() {
            if !buf.is_empty() {
                return base64_engine
                    .decode(String::from_utf8_lossy(&buf).trim().as_bytes())
                    .map_err(|e| io::Error::other(format!("Invalid config command: {e}")));
            }

            return self.poll_config_command(group_name, max_size);
        }

        let reader = BufReader::new(&buf[..]);

        for line in reader.lines() {
            let line = line?;
            if line.starts_with("data:") {
                let encoded_command = &line[5..];
                let command = base64_engine
                    .decode(encoded_command)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
                return Ok(command);
            }
        }

        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Server error"),
        ));
    }

    /// Ask which cameras have a video waiting
    pub fn bulk_check(&self, cameras: &[BulkCheckRequest]) -> io::Result<Vec<GroupTimestamp>> {
        if cameras.is_empty() {
            return Ok(Vec::new());
        }

        let body = self.bulk_check_body(cameras)?;
        let server_url = format!("{}/bulkCheck", self.server_addr);

        let client = client_builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(io::Error::other)?;

        let response = self
            .authorized_headers(client.post(&server_url))
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .map_err(io::Error::other)?;

        if response.status() == StatusCode::CONFLICT {
            Self::give_hint_to_updater();
        }

        if !response.status().is_success() {
            return Err(io::Error::other(format!(
                "Server error: {}",
                response.status()
            )));
        }

        let mut buf = Vec::new();
        let mut limited = response.take(MAX_CHECK_RESP_SIZE);
        limited.read_to_end(&mut buf)?;

        if buf.len() >= MAX_CHECK_RESP_SIZE as usize {
            return Err(io::Error::other(
                "Bulk check response exceeded maximum allowed size".to_string(),
            ));
        }

        serde_json::from_slice(&buf)
            .map_err(|e| io::Error::other(format!("Invalid bulk check response: {e}")))
    }

    fn bulk_check_body(&self, cameras: &[BulkCheckRequest]) -> io::Result<String> {
        let enterprise = self.backend.is_enterprise();

        let group_names = cameras
            .iter()
            .map(|camera| {
                let filename = if enterprise {
                    let key = camera.object_key.as_deref().ok_or_else(|| {
                        io::Error::other(format!(
                            "No object key for {}; the enterprise DS needs a derived name",
                            camera.group_name
                        ))
                    })?;

                    Some(object_name(
                        key,
                        &camera.group_name,
                        camera.epoch_to_check,
                    )?)
                } else {
                    None
                };

                Ok(MotionPair {
                    group_name: camera.group_name.clone(),
                    epoch_to_check: camera.epoch_to_check,
                    filename,
                })
            })
            .collect::<io::Result<Vec<_>>>()?;

        serde_json::to_string(&MotionPairs { group_names })
            .map_err(|e| io::Error::other(format!("Could not encode the bulk check: {e}")))
    }

    /// Wait for a config command, polling, for clients that don't hold a WebSocket.
    ///
    /// The enterprise DS pushes over a socket
    fn poll_config_command(&self, group_name: &str, max_size: u64) -> io::Result<Vec<u8>> {
        let server_url = format!("{}/config/{}", self.server_addr, group_name);
        let deadline = Instant::now() + ENTERPRISE_CONFIG_POLL_WINDOW;

        let client = client_builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(io::Error::other)?;

        loop {
            sleep(ENTERPRISE_CONFIG_POLL_INTERVAL);

            let response = self
                .authorized_headers(client.get(&server_url))
                .send()
                .map_err(io::Error::other)?;

            if !response.status().is_success() {
                return Err(io::Error::other(format!(
                    "Server error: {}",
                    response.status()
                )));
            }

            let mut buf = Vec::new();
            response.take(max_size).read_to_end(&mut buf)?;

            if !buf.is_empty() {
                return base64_engine
                    .decode(String::from_utf8_lossy(&buf).trim().as_bytes())
                    .map_err(|e| io::Error::other(format!("Invalid config command: {e}")));
            }

            if Instant::now() >= deadline {
                return Err(io::Error::other("No config command".to_string()));
            }
        }
    }

    /// What this subscription is storing right now.
    ///
    /// Enterprise only; the self-hosted server has no notion of a quota to report against.
    pub fn fetch_usage(&self) -> io::Result<UsageReport> {
        self.enterprise_json("GET", "usage", None)
    }

    /// Invite an account onto a subscription. Caller must be its admin.
    pub fn add_subscription_member(
        &self,
        sub_uuid: &str,
        username: &str,
        role: Option<&str>,
    ) -> io::Result<Subscription> {
        self.enterprise_json(
            "POST",
            &format!("subscription/{sub_uuid}/members"),
            Some(json!({ "username": username, "role": role })),
        )
    }

    pub fn remove_subscription_member(
        &self,
        sub_uuid: &str,
        username: &str,
    ) -> io::Result<Subscription> {
        self.enterprise_json(
            "DELETE",
            &format!("subscription/{sub_uuid}/members/{username}"),
            None,
        )
    }

    pub fn cancel_subscription(&self, sub_uuid: &str) -> io::Result<Subscription> {
        self.enterprise_json("DELETE", &format!("subscription/{sub_uuid}"), None)
    }

    pub fn list_subscriptions(&self) -> io::Result<SubscriptionList> {
        self.enterprise_json("GET", "subscription", None)
    }

    /// Upload debug logs.
    ///
    /// On the enterprise service these are encrypted to a pub key
    pub fn upload_debug_logs(&self, logs: Vec<u8>) -> io::Result<()> {
        let client = client_builder()
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(io::Error::other)?;

        let response = self
            .authorized_headers(client.post(format!("{}/debug_logs", self.server_addr)))
            .header("Content-Type", "application/octet-stream")
            .body(logs)
            .send()
            .map_err(io::Error::other)?;

        if response.status() == StatusCode::CONFLICT {
            Self::give_hint_to_updater();
        }

        if !response.status().is_success() {
            return Err(io::Error::other(format!(
                "Server error: {}",
                response.status()
            )));
        }

        Ok(())
    }

    /// One JSON request against an enterprise-only route.
    fn enterprise_json<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> io::Result<T> {
        if !self.backend.is_enterprise() {
            return Err(io::Error::other(format!(
                "/{path} only exists on the enterprise delivery service"
            )));
        }

        let client = client_builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(io::Error::other)?;

        let url = format!("{}/{}", self.server_addr, path);
        let request = match method {
            "POST" => client.post(url),
            "DELETE" => client.delete(url),
            _ => client.get(url),
        };

        let mut request = self.authorized_headers(request);
        if let Some(body) = body {
            request = request
                .header("Content-Type", "application/json")
                .body(body.to_string());
        }

        let response = request.send().map_err(io::Error::other)?;

        if !response.status().is_success() {
            return Err(io::Error::other(format!(
                "Server error: {}",
                response.status()
            )));
        }

        response.json().map_err(io::Error::other)
    }

    /// Enterprise only: the self-hosted server has no rendezvous
    #[cfg(feature = "p2p")]
    pub fn publish_p2p_addresses(
        &self,
        camera: &str,
        role: &str,
        addresses: &[String],
    ) -> io::Result<()> {
        if !self.backend.is_enterprise() {
            return Err(io::Error::other(
                "Peer address exchange needs the enterprise delivery service".to_string(),
            ));
        }

        let client = client_builder()
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(io::Error::other)?;

        let response = self
            .authorized_headers(client.post(format!("{}/p2p/{}", self.server_addr, camera)))
            .header("Content-Type", "application/json")
            .body(
                serde_json::to_string(&json!({ "role": role, "addresses": addresses }))
                    .map_err(io::Error::other)?,
            )
            .send()
            .map_err(io::Error::other)?;

        if !response.status().is_success() {
            return Err(io::Error::other(format!(
                "Server error: {}",
                response.status()
            )));
        }

        Ok(())
    }

    /// Read where the other side says it can be reached.
    #[cfg(feature = "p2p")]
    pub fn fetch_p2p_peers(&self, camera: &str, role: &str) -> io::Result<crate::p2p::PeersResult> {
        if !self.backend.is_enterprise() {
            return Err(io::Error::other(
                "Peer address exchange needs the enterprise delivery service".to_string(),
            ));
        }

        let client = client_builder()
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(io::Error::other)?;

        let response = self
            .authorized_headers(client.get(format!(
                "{}/p2p/{}?role={}",
                self.server_addr, camera, role
            )))
            .send()
            .map_err(io::Error::other)?;

        if !response.status().is_success() {
            return Err(io::Error::other(format!(
                "Server error: {}",
                response.status()
            )));
        }

        response.json().map_err(io::Error::other)
    }

    /// Send a config response
    pub fn config_response(&self, group_name: &str, response: Vec<u8>) -> io::Result<()> {
        let server_url = format!("{}/config_response/{}", self.server_addr, group_name);

        let client = client_builder().build().expect("default HTTP client");
        let response = self.authorized_headers(client
            .post(server_url))
            .header("Content-Type", "application/octet-stream")
            .body(response)
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        if response.status() == StatusCode::CONFLICT {
            Self::give_hint_to_updater();
        }

        if !response.status().is_success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Server error: {}", response.status()),
            ));
        }

        Ok(())
    }

    /// Checks and retrieve a config command response.
    pub fn fetch_config_response(
        &self,
        group_name: &str,
    ) -> io::Result<Vec<u8>> {
        let max_size = MAX_COMMAND_FILE_SIZE;

        let server_url = format!("{}/config_response/{}", self.server_addr, group_name);

        let client = client_builder()
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        let response = self.authorized_headers(client
            .get(&server_url))
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        if response.status() == StatusCode::CONFLICT {
            Self::give_hint_to_updater();
        }

        if !response.status().is_success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Server error: {}", response.status()),
            ));
        }

        let mut response_vec = Vec::new();
        let mut limited = response.take(max_size);

        limited.read_to_end(&mut response_vec)?;

        if response_vec.len() >= max_size.try_into().unwrap() {
            return Err(io::Error::new(io::ErrorKind::Other, "Config response download exceeded maximum allowed size"));
        }

        Ok(response_vec)
    }

    /// A receive that answers immediately
    pub fn receive_msg_nowait(&self, msg_tag: &str) -> io::Result<Option<Vec<u8>>> {
        let server_url = format!("{}/receive_msg/{}?wait=0", self.server_addr, msg_tag);

        let client = client_builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(io::Error::other)?;

        let response = self
            .authorized_headers(client.get(&server_url))
            .send()
            .map_err(io::Error::other)?;

        if response.status() == StatusCode::NO_CONTENT {
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(io::Error::other(format!(
                "Server error: {}",
                response.status()
            )));
        }

        let mut data = Vec::new();
        response
            .take(MAX_RELAY_MSG_SIZE)
            .read_to_end(&mut data)?;

        Ok(Some(data))
    }

    pub fn receive_msg(&self, msg_tag: &str) -> io::Result<Vec<u8>> {
        let max_size = MAX_RELAY_MSG_SIZE;

        let server_url = format!("{}/receive_msg/{}", self.server_addr, msg_tag);

        let client = client_builder()
            .timeout(None)
            .build()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        let response = self.authorized_headers(client
            .get(&server_url))
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        
        if response.status() == StatusCode::CONFLICT {
            Self::give_hint_to_updater();
        }

        if response.status() == StatusCode::REQUEST_TIMEOUT {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Server error: timeout",
            ));
        }

        if !response.status().is_success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Server error: {}", response.status()),
            ));
        }

        let mut data = Vec::new();
        let mut limited = response.take(max_size);
        limited.read_to_end(&mut data)?;

        if data.len() >= max_size as usize {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Relay message exceeded maximum allowed size",
            ));
        }

        Ok(data)
    }

    pub fn send_msg(&self, msg_tag: &str, data: Vec<u8>) -> io::Result<()> {
        let server_url = format!("{}/send_msg/{}", self.server_addr, msg_tag);

        let client = client_builder().build().expect("default HTTP client");
        let response = self.authorized_headers(client
            .post(server_url))
            .header("Content-Type", "application/octet-stream")
            .body(data)
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        if response.status() == StatusCode::CONFLICT {
            Self::give_hint_to_updater();
        }

        if !response.status().is_success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Server error: {}", response.status()),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        object_name, validate_ios_relay_base_url, validate_ios_relay_binding, BulkCheckRequest,
        HttpClient, IosRelayBinding, ServerBackend,
    };

    // Build an otherwise-valid relay binding and let each test vary only the relay base URL it wants to validate.
    fn client(backend: ServerBackend) -> HttpClient {
        HttpClient::new_with_backend(
            "https://ds.example.com".to_string(),
            "user".to_string(),
            "pass".to_string(),
            backend,
        )
    }

    fn camera(object_key: Option<Vec<u8>>) -> BulkCheckRequest {
        BulkCheckRequest {
            group_name: "motion_group".to_string(),
            epoch_to_check: 42,
            object_key,
        }
    }

    #[test]
    fn self_hosted_bulk_check_sends_group_and_epoch() {
        let body = client(ServerBackend::SelfHosted)
            .bulk_check_body(&[camera(None)])
            .unwrap();

        assert!(body.contains("\"group_name\":\"motion_group\""));
        assert!(body.contains("\"epoch_to_check\":42"));

        assert!(!body.contains("filename"));
    }

    #[test]
    fn enterprise_bulk_check_asks_for_the_name_an_upload_would_have_used() {
        let key = b"an exporter secret".to_vec();

        let body = client(ServerBackend::Enterprise)
            .bulk_check_body(&[camera(Some(key.clone()))])
            .unwrap();

        let uploaded_as = object_name(&key, "motion_group", 42).unwrap();

        assert!(
            body.contains(&format!("\"filename\":\"{uploaded_as}\"")),
            "bulk check asked for a different name than an upload would store under: {body}"
        );

        assert!(body.contains("\"group_name\":\"motion_group\""));
    }

    #[test]
    fn enterprise_bulk_check_needs_a_key() {
        let error = client(ServerBackend::Enterprise)
            .bulk_check_body(&[camera(None)])
            .unwrap_err();

        assert!(error.to_string().contains("No object key"));
    }

    #[test]
    fn a_different_epoch_asks_for_a_different_object() {
        let key = b"an exporter secret".to_vec();
        let client = client(ServerBackend::Enterprise);

        let mut later = camera(Some(key.clone()));
        later.epoch_to_check = 43;

        assert_ne!(
            client.bulk_check_body(&[camera(Some(key))]).unwrap(),
            client.bulk_check_body(&[later]).unwrap()
        );
    }

    #[test]
    fn the_backend_decides_the_object_url() {
        let self_hosted = client(ServerBackend::SelfHosted);
        assert_eq!(
            self_hosted.object_url("group", "42", None).unwrap(),
            "https://ds.example.com/group/42"
        );

        let enterprise = client(ServerBackend::Enterprise);
        assert_eq!(
            enterprise.object_url("group", "42", Some("deadbeef")).unwrap(),
            "https://ds.example.com/deadbeef"
        );

        assert!(enterprise.object_url("group", "42", None).is_err());
    }

    fn ios_binding(relay_base_url: &str) -> IosRelayBinding {
        IosRelayBinding {
            relay_base_url: relay_base_url.to_string(),
            hub_token: "hub-token".to_string(),
            app_install_id: "install-id".to_string(),
            hub_id: "hub-id".to_string(),
            device_token: "device-token".to_string(),
            expires_at_epoch_ms: 1,
        }
    }

    #[test]
    // Tests that the camera hub accepts the public production relay.
    fn accepts_trusted_ios_relay_host() {
        validate_ios_relay_base_url("https://relay.secluso.com")
            .expect("trusted relay host should be accepted");
    }

    #[test]
    // Tests that server-side iOS relay checks reject unexpected relay hosts before the target can be persisted to the hub.
    fn rejects_untrusted_ios_relay_host() {
        let err = validate_ios_relay_base_url("https://evil.example")
            .expect_err("unexpected relay host should be rejected");

        assert!(err
            .to_string()
            .contains("Refusing unexpected iOS relay host"));
    }

    #[test]
    // Tests that the binding-level check rejects incomplete relay bindings before send_notification hands them to the HTTP client.
    fn rejects_empty_ios_relay_base_url() {
        let err = validate_ios_relay_binding(&ios_binding("   "))
            .expect_err("empty relay base URL should be rejected");

        assert!(err.to_string().contains("iOS relay base URL is required"));
    }
}
