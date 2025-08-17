//! Privastead HTTP client for using the delivery service (DS).
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

use std::fs::File;
use std::io::{self, Write, BufReader, BufWriter, BufRead};
use std::path::Path;
use std::time::Duration;
use reqwest::blocking::{Client, Body};
use base64::{engine::general_purpose, Engine as _};
use base64::engine::general_purpose::STANDARD as base64_engine;
use serde_json::json;

#[derive(Clone)]
pub struct HttpClient {
    server_addr: String,
    server_username: String,
    server_password: String,
}

//TODO: There's a lot of repitition between the functions here.

// Note: The server needs a unique name for each camera.
// The name needs to be available to both the camera and the app.
// We use the MLS group name for that purpose.

impl HttpClient {
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

    /// Atomically confrm pairing with app
    pub fn send_pairing_token(&self, pairing_token: &str) -> io::Result<String> {
        let url = format!("{}/pair", self.server_addr);

        let auth_value = format!("{}:{}", self.server_username, self.server_password);
        let auth_encoded = general_purpose::STANDARD.encode(auth_value);
        let auth_header = format!("Basic {}", auth_encoded);

        let body = json!({
            "pairing_token": pairing_token,
            "role": "camera",
        });

        let client = Client::builder()
            .timeout(Duration::from_secs(45)) // Wait up to 45s
            .build()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        let response = client
            .post(&url)
            .header("Authorization", auth_header)
            .header("Content-Type", "application/json")
            .body(body.to_string())
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::TimedOut, e.to_string()))?;

        if !response.status().is_success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Pairing failed: {}", response.status()),
            ));
        }

        let text = response
            .text()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        let json: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        let status = json["status"]
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Missing 'status'"))?;

        Ok(status.to_string())
    }

    /// Uploads an (encrypted) video file.
    pub fn upload_enc_video(
        &self,
        group_name: &str,
        enc_file_path: &Path,
    ) -> io::Result<()> {
        let enc_file_name = enc_file_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap()
            .to_string();

        let server_url = format!("{}/{}/{}", self.server_addr, group_name, enc_file_name);

        let file = File::open(enc_file_path)?;
        let reader = BufReader::new(file);

        let auth_value = format!("{}:{}", self.server_username, self.server_password);
        let auth_encoded = general_purpose::STANDARD.encode(auth_value);
        let auth_header = format!("Basic {}", auth_encoded);

        let client = Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        let response = client
            .post(server_url)
            .header("Content-Type", "application/octet-stream")
            .header("Authorization", auth_header)
            .body(Body::new(reader))
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        if !response.status().is_success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Server error: {}", response.status()),
            ));
        }

        Ok(())
    }

    /// Fetches an (encrypted) video file, persists it, and then deletes it from the server.
    pub fn fetch_enc_video(
        &self,
        group_name: &str,
        enc_file_path: &Path,
    ) -> io::Result<()> {
        let enc_file_name = enc_file_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap()
            .to_string();

        let server_url = format!("{}/{}/{}", self.server_addr, group_name, enc_file_name);

        let auth_value = format!("{}:{}", self.server_username, self.server_password);
        let auth_encoded = general_purpose::STANDARD.encode(auth_value);
        let auth_header = format!("Basic {}", auth_encoded);

        let client = Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        let mut response = client
            .get(&server_url)
            .header("Authorization", auth_header.clone())
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?
            .error_for_status()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        if !response.status().is_success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Server error: {}", response.status()),
            ));
        }

        let mut file = BufWriter::new(File::create(enc_file_path)?);

        io::copy(&mut response, &mut file)?;
        file.flush().unwrap();
        file.into_inner()?.sync_all()?;

        let del_response = client
            .delete(&server_url)
            .header("Authorization", auth_header)
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?
            .error_for_status()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        if !del_response.status().is_success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Server error: {}", del_response.status()),
            ));
        }

        Ok(())
    }

    pub fn deregister(
        &self,
        group_name: &str,
    ) -> io::Result<()> {
        let server_url = format!("{}/{}", self.server_addr, group_name);

        let auth_value = format!("{}:{}", self.server_username, self.server_password);
        let auth_encoded = general_purpose::STANDARD.encode(auth_value);
        let auth_header = format!("Basic {}", auth_encoded);

        let client = Client::new();
        let response = client
            .delete(&server_url)
            .header("Authorization", auth_header.clone())
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?
            .error_for_status()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        if !response.status().is_success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Server error: {}", response.status()),
            ));
        }

        Ok(())
    }

    pub fn send_fcm_notification(
        &self,
        notification: Vec<u8>,
    ) -> io::Result<()> {
        let server_url = format!("{}/fcm_notification", self.server_addr);

        let auth_value = format!("{}:{}", self.server_username, self.server_password);
        let auth_encoded = general_purpose::STANDARD.encode(auth_value);
        let auth_header = format!("Basic {}", auth_encoded);

        let client = Client::new();
        let response = client
            .post(server_url)
            .header("Content-Type", "application/octet-stream")
            .header("Authorization", auth_header)
            .body(notification)
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        if !response.status().is_success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Server error: {}", response.status()),
            ));
        }

        Ok(())
    }

    /// Start a livestream session
    pub fn livestream_start(
        &self,
        group_name: &str,
    ) -> io::Result<()> {
        let server_url = format!("{}/livestream/{}", self.server_addr, group_name);

        let auth_value = format!("{}:{}", self.server_username, self.server_password);
        let auth_encoded = general_purpose::STANDARD.encode(auth_value);
        let auth_header = format!("Basic {}", auth_encoded);

        let client = Client::new();
        let response = client
            .post(server_url)
            .header("Content-Type", "application/octet-stream")
            .header("Authorization", auth_header)
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

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
        let server_url = format!("{}/livestream/{}", self.server_addr, group_name);

        let auth_value = format!("{}:{}", self.server_username, self.server_password);
        let auth_encoded = general_purpose::STANDARD.encode(auth_value);
        let auth_header = format!("Basic {}", auth_encoded);

        let client = Client::builder()
            .timeout(None) // Disable timeout to allow long-polling
            .build()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        let response = client
            .get(&server_url)
            .header("Authorization", auth_header)
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?
            .error_for_status()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        let reader = BufReader::new(response);

        for line in reader.lines() {
            let line = line?;
            if line.starts_with("data:") {
                //println!("Received event data: {}", &line[5..]);
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
        let server_url = format!("{}/livestream/{}/{}", self.server_addr, group_name, chunk_number);

        let auth_value = format!("{}:{}", self.server_username, self.server_password);
        let auth_encoded = general_purpose::STANDARD.encode(auth_value);
        let auth_header = format!("Basic {}", auth_encoded);

        let client = Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        let response = client
            .post(server_url)
            .header("Content-Type", "application/octet-stream")
            .header("Authorization", auth_header)
            .body(data)
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

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
            .map_err(|e: std::num::ParseIntError| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        Ok(num_files)
    }

    /// Retrieves and returns (encrypted) livestream data.
    pub fn livestream_retrieve(
        &self,
        group_name: &str,
        chunk_number: u64,
    ) -> io::Result<Vec<u8>> {
        let server_url = format!("{}/livestream/{}/{}", self.server_addr, group_name, chunk_number);
        let server_del_url = format!("{}/{}/{}", self.server_addr, group_name, chunk_number);

        let auth_value = format!("{}:{}", self.server_username, self.server_password);
        let auth_encoded = general_purpose::STANDARD.encode(auth_value);
        let auth_header = format!("Basic {}", auth_encoded);

        let client = Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        let response = client
            .get(&server_url)
            .header("Authorization", auth_header.clone())
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?
            .error_for_status()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        if !response.status().is_success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Server error: {}", response.status()),
            ));
        }

        let response_vec = response
            .bytes()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?
            .to_vec();

        let del_response = client
            .delete(&server_del_url)
            .header("Authorization", auth_header)
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?
            .error_for_status()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

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
    pub fn livestream_end(
        &self,
        group_name: &str,
    ) -> io::Result<()> {
        let server_url = format!("{}/livestream_end/{}", self.server_addr, group_name);

        let auth_value = format!("{}:{}", self.server_username, self.server_password);
        let auth_encoded = general_purpose::STANDARD.encode(auth_value);
        let auth_header = format!("Basic {}", auth_encoded);

        let client = Client::new();
        let response = client
            .post(server_url)
            .header("Content-Type", "application/octet-stream")
            .header("Authorization", auth_header)
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        if !response.status().is_success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Server error: {}", response.status()),
            ));
        }

        Ok(())
    }

    /// Send a config command
    pub fn config_command(
        &self,
        group_name: &str,
        command: Vec<u8>,
    ) -> io::Result<()> {
        let server_url = format!("{}/config/{}", self.server_addr, group_name);

        let auth_value = format!("{}:{}", self.server_username, self.server_password);
        let auth_encoded = general_purpose::STANDARD.encode(auth_value);
        let auth_header = format!("Basic {}", auth_encoded);

        let client = Client::new();
        let response = client
            .post(server_url)
            .header("Content-Type", "application/octet-stream")
            .header("Authorization", auth_header)
            .body(command)
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

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
        let server_url = format!("{}/config/{}", self.server_addr, group_name);

        let auth_value = format!("{}:{}", self.server_username, self.server_password);
        let auth_encoded = general_purpose::STANDARD.encode(auth_value);
        let auth_header = format!("Basic {}", auth_encoded);

        let client = Client::builder()
            .timeout(None) // Disable timeout to allow long-polling
            .build()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        let response = client
            .get(&server_url)
            .header("Authorization", auth_header)
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?
            .error_for_status()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        let reader = BufReader::new(response);

        for line in reader.lines() {
            let line = line?;
            if line.starts_with("data:") {
                let encoded_command = &line[5..];
                let command = base64_engine.decode(encoded_command)
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
    pub fn config_response(
        &self,
        group_name: &str,
        response: Vec<u8>,
    ) -> io::Result<()> {
        let server_url = format!("{}/config_response/{}", self.server_addr, group_name);

        let auth_value = format!("{}:{}", self.server_username, self.server_password);
        let auth_encoded = general_purpose::STANDARD.encode(auth_value);
        let auth_header = format!("Basic {}", auth_encoded);

        let client = Client::new();
        let response = client
            .post(server_url)
            .header("Content-Type", "application/octet-stream")
            .header("Authorization", auth_header)
            .body(response)
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

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
        let server_url = format!("{}/config_response/{}", self.server_addr, group_name);

        let auth_value = format!("{}:{}", self.server_username, self.server_password);
        let auth_encoded = general_purpose::STANDARD.encode(auth_value);
        let auth_header = format!("Basic {}", auth_encoded);

        let client = Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        let response = client
            .get(&server_url)
            .header("Authorization", auth_header.clone())
            .send()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?
            .error_for_status()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        if !response.status().is_success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Server error: {}", response.status()),
            ));
        }

        let response_vec = response
            .bytes()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?
            .to_vec();

        Ok(response_vec)
    }
}