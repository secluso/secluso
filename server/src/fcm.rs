//! Secluso FCM.
//!
//! SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{Context, Result};
use base64::{engine::general_purpose, Engine};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use plist::Value;
use reqwest::blocking::Client;
use reqwest::Url;
use secluso_server_backbone::types::ConfigResponse;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashSet;
use std::error::Error;
use std::io::{self, ErrorKind};
use std::path::Path;
use std::{fs, thread, time};
use std::sync::OnceLock;
use rocket::tokio::sync::Mutex;

use rocket::tokio::fs as tokio_fs;
use rocket::tokio::io::AsyncWriteExt;

use crate::security::check_path_sandboxed;

// Fixed bundle id used to locate the Firebase app
const BUNDLE_ID: &str = "com.secluso.mobile";
const FIREBASE_API_HOST: &str = "firebase.googleapis.com";
const FCM_API_HOST: &str = "fcm.googleapis.com";
const OAUTH_TOKEN_ALLOWED_HOSTS: &[&str] = &[
    "oauth2.googleapis.com",
    "www.googleapis.com",
    "accounts.google.com",
];

const LEGACY_FCM_TOKEN_FILE: &str = "fcm_token";
const FCM_TOKENS_DIR: &str = "fcm_tokens";
const FCM_TOKEN_FILE_PREFIX: &str = "fcm_token_";

// In this file we send very sensitive stuff over HTTP requests: a JWT assertion signed with the
// Firebase service-account private key, bearer access tokens, and push payloads tied to user
// devices. If any endpoint URL is quietly changed to plain http:// or to a lookalike host,
// that sensitive data can be leaked even if the rest of the code looks normal. Static analyzers
// (and real attackers) care about this because string-built URLs can be influenced by config files,
// environment drift, bad defaults, or future refactors.
//
// So we do two explicit checks every time:
// 1) scheme must be HTTPS (transport encryption is non-negotiable);
// 2) host must be in a small allowlist for the API we expect.
fn validate_https_url(raw_url: &str, allowed_hosts: &[&str], label: &str) -> Result<Url> {
    let parsed = Url::parse(raw_url).with_context(|| format!("Invalid {label} URL: {raw_url}"))?;
    if parsed.scheme() != "https" {
        anyhow::bail!("Refusing non-HTTPS {label} URL: {raw_url}");
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("URL missing host for {label}: {raw_url}"))?;
    if !allowed_hosts
        .iter()
        .any(|allowed| host.eq_ignore_ascii_case(allowed))
    {
        anyhow::bail!("Refusing unexpected host '{host}' for {label}");
    }

    Ok(parsed)
}

// Platform specific helpers for Firebase apps
enum Platform {
    Ios,
    Android,
}

impl Platform {
    fn apps_path(&self) -> &'static str {
        match self {
            Platform::Ios => "iosApps",
            Platform::Android => "androidApps",
        }
    }

    fn id_key(&self) -> &'static str {
        match self {
            Platform::Ios => "bundleId",
            Platform::Android => "packageName",
        }
    }

    fn display(&self) -> &'static str {
        match self {
            Self::Ios => "Secluso iOS",
            Self::Android => "Secluso Android",
        }
    }
}

#[allow(non_snake_case)]
#[derive(Deserialize)]
struct App {
    appId: String,
    #[serde(default)]
    bundleId: Option<String>,
    #[serde(default)]
    packageName: Option<String>,
}

#[derive(Deserialize)]
struct ListApps {
    #[serde(default)]
    apps: Vec<App>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct Operation {
    name: String,
    done: Option<bool>,
    #[serde(default)]
    error: Option<serde_json::Value>,
    #[serde(default)]
    response: Option<App>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct ServiceAccountKey {
    #[serde(rename = "type")]
    key_type: String,
    project_id: String,
    private_key_id: String,
    private_key: String,
    client_email: String,
    client_id: String,
    auth_uri: String,
    token_uri: String,
    auth_provider_x509_cert_url: String,
    client_x509_cert_url: String,
}

#[derive(Debug, Serialize)]
struct Claims {
    iss: String,
    scope: String,
    aud: String,
    exp: usize,
    iat: usize,
}

fn fetch_token(
    service_account_key: &ServiceAccountKey,
    client: &Client,
    scope: String,
) -> Result<String, Box<dyn Error>> {
    let token_uri = validate_https_url(
        &service_account_key.token_uri,
        OAUTH_TOKEN_ALLOWED_HOSTS,
        "OAuth token endpoint",
    )?;

    // Build an access token for Firebase API requests
    // Create the JWT claims
    let iat = Utc::now();
    let exp = iat + Duration::minutes(60);
    let claims = Claims {
        iss: service_account_key.client_email.clone(),
        scope: scope,
        aud: token_uri.as_str().to_string(),
        exp: exp.timestamp() as usize,
        iat: iat.timestamp() as usize,
    };

    // Encode the JWT
    let header = Header::new(Algorithm::RS256);
    let private_key = service_account_key.private_key.replace("\\n", "\n");
    let encoding_key = EncodingKey::from_rsa_pem(private_key.as_bytes())?;
    let jwt = encode(&header, &claims, &encoding_key)?;

    // Obtain the OAuth 2.0 token
    let token_response: serde_json::Value = client
        .post(token_uri)
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", &jwt),
        ])
        .send()?
        .error_for_status()?
        .json()?;

    Ok(token_response["access_token"]
        .as_str()
        .ok_or("Failed to get access_token")?
        .to_string())
}

fn fetch_app_identifier(
    client: &Client,
    service_account_key: &ServiceAccountKey,
    access_token: &str,
    arch: Platform,
) -> Result<Option<String>, Box<dyn Error>> {
    // Request the list of apps associated with the project
    let request_android_app_list_url = format!(
        "https://firebase.googleapis.com/v1beta1/projects/{}/{}?showDeleted=false&pageSize=10",
        service_account_key.project_id,
        arch.apps_path()
    );
    let request_android_app_list_url = validate_https_url(
        &request_android_app_list_url,
        &[FIREBASE_API_HOST],
        "Firebase app list endpoint",
    )?;

    // Send the request for the app list
    let apps: ListApps = client
        .get(request_android_app_list_url)
        .bearer_auth(access_token.to_string())
        .send()
        .context("Failed to send App Identifier request")?
        .error_for_status()
        .context("Bad request on App Identifier request")?
        .json()
        .context("Failed to convert ListApps to JSON")?;

    for app in apps.apps {
        let ident = match arch {
            Platform::Android => app.packageName.as_deref(),
            Platform::Ios => app.bundleId.as_deref(),
        };

        if let Some(pkg_or_bundle) = ident {
            if pkg_or_bundle == BUNDLE_ID {
                return Ok(Some(app.appId));
            }
        }
    }

    Ok(None)
}

fn fetch_operation_status(
    client: &Client,
    access_token: &str,
    name: String,
) -> Result<Option<String>> {
    let request_operation_url = format!("https://firebase.googleapis.com/v1beta1/{}", name);
    let request_operation_url = validate_https_url(
        &request_operation_url,
        &[FIREBASE_API_HOST],
        "Firebase operation endpoint",
    )?;

    // Check long running operation status
    let op: Operation = client
        .get(request_operation_url)
        .bearer_auth(access_token.to_string())
        .send()?
        .error_for_status()
        .context("Bad request on operation status")?
        .json()
        .context("Failed to parse operation JSON")?;

    if let Some(err) = op.error {
        anyhow::bail!("Operation failed: {}", err);
    }

    if op.done != Some(true) {
        return Ok(None);
    }

    if let Some(app) = op.response {
        return Ok(Some(app.appId));
    }

    Ok(None)
}

fn create_app(
    client: &Client,
    service_account_key: &ServiceAccountKey,
    access_token: &str,
    arch: Platform,
) -> Result<Option<String>, Box<dyn Error>> {
    // Build the app creation request for the project
    let request_android_app_list_url = format!(
        "https://firebase.googleapis.com/v1beta1/projects/{}/{}",
        service_account_key.project_id,
        arch.apps_path()
    );
    let request_android_app_list_url = validate_https_url(
        &request_android_app_list_url,
        &[FIREBASE_API_HOST],
        "Firebase app creation endpoint",
    )?;

    // Build the app creation payload

    let message = json!({
        "displayName": arch.display(),
        (arch.id_key()): BUNDLE_ID,
    });

    // Send the app creation request
    let response_text = client
        .post(request_android_app_list_url)
        .bearer_auth(access_token.to_string())
        .header("Content-Type", "application/json")
        .json(&message)
        .send()?
        .error_for_status()?
        .text();

    let json_body: serde_json::Value = serde_json::from_str(
        response_text
            .context("Failed to get response body")?
            .as_str(),
    )
    .context("JSON was not well-formatted")?;

    if let Some(operation_name) = json_body.get("name").and_then(|n| n.as_str()) {
        // Poll the operation until the app id is available
        for _ in 0..15 {
            thread::sleep(time::Duration::from_millis(1000));

            if let Ok(Some(app_id)) =
                fetch_operation_status(&client, access_token, operation_name.to_string())
            {
                return Ok(Some(app_id));
            }
        }
    }

    Ok(None)
}

fn send_config_request(
    client: &Client,
    service_account_key: &ServiceAccountKey,
    access_token: &str,
    arch: Platform,
    app_id: String,
) -> Result<String, Box<dyn Error>> {
    let request_operation_url = format!(
        "https://firebase.googleapis.com/v1beta1/projects/{}/{}/{}/config",
        service_account_key.project_id,
        arch.apps_path(),
        app_id
    );
    let request_operation_url = validate_https_url(
        &request_operation_url,
        &[FIREBASE_API_HOST],
        "Firebase config endpoint",
    )?;

    // Send the request for the config file
    let response = client
        .get(request_operation_url)
        .bearer_auth(access_token.to_string())
        .send()?
        .error_for_status()?;

    let json_body: serde_json::Value = serde_json::from_str(
        response
            .text()
            .context("Failed to get response body")?
            .as_str(),
    )
    .context("JSON was not well-formatted")?;
    let config_file_contents = json_body
        .get("configFileContents")
        .and_then(|v| v.as_str())
        .ok_or("Was not able to fetch the config contents")?;

    Ok(config_file_contents.to_string())
}

pub fn fetch_config() -> Result<ConfigResponse, Box<dyn Error>> {
    // Orchestrate app discovery creation and config retrieval
    let client = Client::builder().https_only(true).build()?;

    // Read the service account key file
    let service_account_key: ServiceAccountKey = serde_json::from_str(
        &fs::read_to_string("service_account_key.json")
            .context("Failed to read service_account_key.json")?,
    )
    .context("Failed to parse service_account_key.json")?;

    // Read the service account key file
    let access_token = fetch_token(
        &service_account_key,
        &client,
        "https://www.googleapis.com/auth/firebase".to_string(),
    )?;
    let access_token = access_token.as_str();

    let mut pre_app_id_ios =
        fetch_app_identifier(&client, &service_account_key, access_token, Platform::Ios)?;
    let mut pre_app_id_android = fetch_app_identifier(
        &client,
        &service_account_key,
        access_token,
        Platform::Android,
    )?;

    if pre_app_id_ios.is_none() {
        pre_app_id_ios = create_app(&client, &service_account_key, access_token, Platform::Ios)?;
    }

    if pre_app_id_android.is_none() {
        pre_app_id_android = create_app(
            &client,
            &service_account_key,
            access_token,
            Platform::Android,
        )?;
    }

    let app_id_ios =
        pre_app_id_ios.context("Failure either creating or retrieving iOS app ID for Firebase")?;
    let app_id_android = pre_app_id_android
        .context("Failure either creating or retrieving Android app ID for Firebase")?;

    let ios_contents = send_config_request(
        &client,
        &service_account_key,
        access_token,
        Platform::Ios,
        app_id_ios.clone(),
    )?;
    let android_contents = send_config_request(
        &client,
        &service_account_key,
        access_token,
        Platform::Android,
        app_id_android.clone(),
    )?;

    let ios_contents_decoded = String::from_utf8(
        general_purpose::STANDARD
            .decode(ios_contents)
            .context("Failed to decode base64 file contents")?,
    )
    .context("Failed to convert base64 bytes into a string")?;
    let android_contents_decoded = String::from_utf8(
        general_purpose::STANDARD
            .decode(android_contents)
            .context("Failed to decode base64 file contents")?,
    )
    .context("Failed to convert base64 bytes into a string")?;

    let json_body_android: serde_json::Value =
        serde_json::from_str(android_contents_decoded.as_str())
            .context("JSON was not well-formatted")?;
    let project_info = json_body_android
        .get("project_info")
        .context("Failed to get project info")?;
    let messaging_sender_id = project_info
        .get("project_number")
        .and_then(|v| v.as_str())
        .context("Failed to parse project Number from Android firebase response")?;
    let storage_bucket = project_info
        .get("storage_bucket")
        .and_then(|v| v.as_str())
        .context("Failed to parse storage bucket from android firebase response")?;
    let project_id = service_account_key.project_id;

    let clients = json_body_android
        .get("client")
        .context("Failed to get 'client' from Android JSON config")?;
    let clients_array = clients
        .as_array()
        .context("'client' key in Android JSON was not an array")?;
    let first_client = clients_array
        .get(0)
        .context("clients_array in Android JSON had 0 keys")?;

    let api_key_android = first_client
        .get("api_key")
        .context("Failed to find api key in Android JSON")?
        .as_array()
        .context("Failed to convert api key field to array in Android JSON")?
        .get(0)
        .context("Failed to find any keys in Android JSON")?
        .get("current_key")
        .context("Failed to get current key in Android JSON")?
        .as_str()
        .context("Failed to convert current key to String in Android JSON")?;

    let ios_contents_parsed: Value = plist::from_bytes(ios_contents_decoded.as_bytes())
        .context("Failed to parse iOS plist from Firebase")?;
    let ios_contents_dict = ios_contents_parsed
        .as_dictionary()
        .context("Failed to convert iOS plist to dictionary")?;
    let api_key_ios = ios_contents_dict
        .get("API_KEY")
        .context("Failed to fetch API key from iOS plist from Firebase")?
        .as_string()
        .context("Failed to convert iOS API Key to a string")?;

    let response = ConfigResponse {
        api_key_ios: api_key_ios.to_string(),
        api_key_android: api_key_android.to_string(),
        app_id_android: app_id_android.to_string(),
        app_id_ios: app_id_ios.to_string(),
        messaging_sender_id: messaging_sender_id.to_string(),
        project_id: project_id,
        storage_bucket: storage_bucket.to_string(),
        bundle_id: BUNDLE_ID.to_string(),
    };

    Ok(response)
}

pub fn send_notification(device_token: String, msg: Vec<u8>) -> Result<(), Box<dyn Error>> {
    let client = Client::builder().https_only(true).build()?;

    // Read the service account key file
    let service_account_key: ServiceAccountKey =
        serde_json::from_str(&fs::read_to_string("service_account_key.json")?)?;

    let access_token = fetch_token(
        &service_account_key,
        &client,
        "https://www.googleapis.com/auth/firebase.messaging".to_string(),
    )?;

    // The FCM endpoint for sending messages
    let fcm_url = format!(
        "https://fcm.googleapis.com/v1/projects/{}/messages:send",
        service_account_key.project_id
    );
    let fcm_url = validate_https_url(&fcm_url, &[FCM_API_HOST], "FCM endpoint")?;

    // Create the FCM message payload
    let message = json!({
        "message": {
            "token": device_token,
            "data": {
                "title": "",
                "body": general_purpose::STANDARD.encode(msg),
            },
            "android": {
                "priority": "high"
            },
            "apns": {
                "headers": {
                    "apns-push-type": "background",
                    "apns-priority": "5"
                },
                "payload": {
                    "aps": {
                        "content-available": 1
                    }
                }
            }
        }
    });

    // Send the POST request
    let response = client
        .post(fcm_url)
        .bearer_auth(access_token)
        .header("Content-Type", "application/json")
        .json(&message)
        .send()?;

    // Check the response status
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().unwrap_or_default();
        return Err(
            anyhow::anyhow!("Error: Failed to send notification. ({status}). {body}").into(),
        );
    }

    Ok(())
}

static FCM_TOKEN_STORE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

// FIXME: we only add fcm_tokens, but never remove stale ones.
pub(crate) async fn store_fcm_token(root: &Path, token: &str) -> io::Result<()> {
    // Two overlapping calls to store_fcm_token from one app for the same token can
    // result in duplicates. This lock is used to prevent that.
    let lock = FCM_TOKEN_STORE_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock.lock().await;

    tokio_fs::create_dir_all(root).await?;

    let tokens_dir = root.join(FCM_TOKENS_DIR);
    check_path_sandboxed(root, &tokens_dir)?;
    tokio_fs::create_dir_all(&tokens_dir).await?;

    let mut entries = tokio_fs::read_dir(&tokens_dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        if !entry.file_type().await?.is_file() {
            continue;
        }

        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };

        if !file_name.starts_with(FCM_TOKEN_FILE_PREFIX) {
            continue;
        }

        let path = entry.path();
        check_path_sandboxed(root, &path)?;

        let existing = tokio_fs::read_to_string(&path).await?;
        if existing.trim() == token {
            return Ok(());
        }
    }

    for index in 1u64.. {
        let token_path = tokens_dir.join(format!("{}{}", FCM_TOKEN_FILE_PREFIX, index));
        check_path_sandboxed(root, &token_path)?;

        let mut file = match tokio_fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&token_path)
            .await
        {
            Ok(file) => file,
            Err(e) if e.kind() == ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        };

        file.write_all(token.as_bytes()).await?;
        file.sync_all().await?;
        return Ok(());
    }

    unreachable!()
}

pub(crate) async fn load_fcm_tokens(root: &Path) -> io::Result<Vec<String>> {
    let mut tokens = Vec::new();
    let mut seen = HashSet::new();

    if !root.exists() {
        return Ok(tokens);
    }

    let legacy_token_path = root.join(LEGACY_FCM_TOKEN_FILE);
    check_path_sandboxed(root, &legacy_token_path)?;
    if legacy_token_path.exists() {
        let token = tokio_fs::read_to_string(&legacy_token_path).await?;
        let token = token.trim().to_string();

        if !token.is_empty() && seen.insert(token.clone()) {
            tokens.push(token);
        }
    }

    let tokens_dir = root.join(FCM_TOKENS_DIR);
    check_path_sandboxed(root, &tokens_dir)?;

    if !tokens_dir.exists() {
        return Ok(tokens);
    }

    let mut entries = tokio_fs::read_dir(&tokens_dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        if !entry.file_type().await?.is_file() {
            continue;
        }

        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };

        if !file_name.starts_with(FCM_TOKEN_FILE_PREFIX) {
            continue;
        }

        let token_path = entry.path();
        check_path_sandboxed(root, &token_path)?;

        let token = tokio_fs::read_to_string(token_path).await?;
        let token = token.trim().to_string();

        if !token.is_empty() && seen.insert(token.clone()) {
            tokens.push(token);
        }
    }

    Ok(tokens)
}