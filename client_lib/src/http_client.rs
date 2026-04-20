//! Secluso HTTP client for using the delivery service (DS).
//!
//! SPDX-License-Identifier: GPL-3.0-or-later

use base64::engine::general_purpose::STANDARD as base64_engine;
use base64::{engine::general_purpose, Engine as _};
use reqwest::blocking::{Body, Client, RequestBuilder};
use reqwest::Url;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Write, Read};
use std::path::Path;
use std::time::Duration;
use std::env;

// Some of these constants are based on the ones in server/main.rs.
const MAX_MOTION_FILE_SIZE: u64 = 50 * 1024 * 1024; // 50 mebibytes
const MAX_LIVESTREAM_FILE_SIZE: u64 = 20 * 1024 * 1024; // 20 mebibytes
const MAX_COMMAND_FILE_SIZE: u64 = 100 * 1024; // 100 kibibytes
const MAX_CHECK_RESP_SIZE: u64 = 20 * 1024; // 20 kibibytes
const MAX_NOTIFICATION_TARGET_SIZE: u64 = 10 * 1024; // 10 kibibytes
const IOS_NOTIFICATION_RESP_MAX_SIZE: u64 = 10 * 1024; // 10 kibibytes

#[derive(Clone)]
pub struct HttpClient {
    server_addr: String,
    server_username: String,
    server_password: String,
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
    pub fn authorized_headers(&self, request_builder: RequestBuilder) -> RequestBuilder {
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
        Self {
            server_addr,
            server_username,
            server_password,
        }
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

        let client = Client::builder()
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

        let client = Client::builder()
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

        let client = Client::builder()
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
    pub fn upload_enc_file(&self, group_name: &str, enc_file_path: &Path, num_apps: u32) -> io::Result<()> {
        let enc_file_name = enc_file_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap()
            .to_string();

        let server_url = format!("{}/{}/{}/{}", self.server_addr, group_name, enc_file_name, num_apps);

        let file = File::open(enc_file_path)?;
        let reader = BufReader::new(file);

        let client = Client::builder()
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
        &self, group_name: &str,
        enc_file_path: &Path,
    ) -> io::Result<()> {
        let max_size = MAX_MOTION_FILE_SIZE;

        let enc_file_name = enc_file_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap()
            .to_string();

        self.fetch_enc_file_named(group_name, &enc_file_name, enc_file_path, max_size)
    }

    /// Fetches an encrypted file whose server-side name and local temp filename differ.
    pub fn fetch_enc_file_named(
        &self,
        group_name: &str,
        server_file_name: &str,
        local_file_path: &Path,
        max_size: u64,
    ) -> io::Result<()> {
        let server_url = format!("{}/{}/{}", self.server_addr, group_name, server_file_name);

        let client = Client::builder()
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
        let server_url = format!("{}/{}", self.server_addr, group_name);

        let client = Client::new();
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

        let client = Client::new();
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
        let server_url = format!("{}/livestream/{}", self.server_addr, group_name);

        let client = Client::new();
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

    /// Checks to see if there's a livestream request.
    pub fn livestream_check(&self, group_name: &str) -> io::Result<()> {
        let max_size = MAX_CHECK_RESP_SIZE;

        let server_url = format!("{}/livestream/{}", self.server_addr, group_name);

        let client = Client::builder()
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

        let client = Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

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

        let num_files: usize = response
            .text()
            .map_err(|e: reqwest::Error| io::Error::new(io::ErrorKind::Other, e.to_string()))?
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

        let client = Client::builder()
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
            return Err(io::Error::new(io::ErrorKind::Other, "Livestream chunk download exceeded maximum allowed size"));
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

        let client = Client::new();
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

        let client = Client::new();
        let response = self.authorized_headers(client
            .post(server_url))
            .header("Content-Type", "application/octet-stream")
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
    pub fn config_check(&self, group_name: &str) -> io::Result<Vec<u8>> {
        let max_size = MAX_CHECK_RESP_SIZE;

        let server_url = format!("{}/config/{}", self.server_addr, group_name);

        let client = Client::builder()
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

    /// Send a config response
    pub fn config_response(&self, group_name: &str, response: Vec<u8>) -> io::Result<()> {
        let server_url = format!("{}/config_response/{}", self.server_addr, group_name);

        let client = Client::new();
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

        let client = Client::builder()
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
}

#[cfg(test)]
mod tests {
    use super::{validate_ios_relay_base_url, validate_ios_relay_binding, IosRelayBinding};

    // Build an otherwise-valid relay binding and let each test vary only the relay base URL it wants to validate.
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
