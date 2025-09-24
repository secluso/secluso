//! Secluso FCM.
//!
//! Copyright (C) 2025  Ardalan Amiri Sani
//!
//! This program is free software: you can redistribute it and/or modify
//! it under the terms of the GNU General Public License as published by
//! the Free Software Foundation, either version 3 of the License, or
//! (at your option) any later version.
//!
//! This program is distributed in the hope that it will be useful,
//! but WITHOUT ANY WARRANTY; without even the implied warranty of
//! MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//! GNU General Public License for more details.
//!
//! You should have received a copy of the GNU General Public License
//! along with this program.  If not, see <https://www.gnu.org/licenses/>.

use base64::{engine::general_purpose, Engine};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::error::Error;
use std::fs;
use std::io;

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

pub fn send_notification(device_token: String, msg: Vec<u8>) -> Result<(), Box<dyn Error>> {
    // Read the service account key file
    let service_account_key: ServiceAccountKey =
        serde_json::from_str(&fs::read_to_string("service_account_key.json")?)?;

    // Create the JWT claims
    let iat = Utc::now();
    let exp = iat + Duration::minutes(60);
    let claims = Claims {
        iss: service_account_key.client_email.clone(),
        scope: "https://www.googleapis.com/auth/firebase.messaging".to_string(),
        aud: service_account_key.token_uri.clone(),
        exp: exp.timestamp() as usize,
        iat: iat.timestamp() as usize,
    };

    // Encode the JWT
    let header = Header::new(Algorithm::RS256);
    let private_key = service_account_key.private_key.replace("\\n", "\n");
    let encoding_key = EncodingKey::from_rsa_pem(private_key.as_bytes())?;
    let jwt = encode(&header, &claims, &encoding_key)?;

    // Obtain the OAuth 2.0 token
    let client = Client::new();
    let token_response: serde_json::Value = client
        .post(&service_account_key.token_uri)
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", &jwt),
        ])
        .send()?
        .json()?;

    let access_token = token_response["access_token"]
        .as_str()
        .ok_or("Failed to get access_token")?;

    // The FCM endpoint for sending messages
    let fcm_url = format!(
        "https://fcm.googleapis.com/v1/projects/{}/messages:send",
        service_account_key.project_id
    );

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
        return Err(Box::new(io::Error::other(format!(
            "Error: Failed to send notification. ({:?}).",
            response.text()
        ))));
    }

    Ok(())
}
