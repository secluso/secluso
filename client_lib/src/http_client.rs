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

#[derive(Clone)]
pub struct HttpClient {
    server_addr: String,
    server_username: String,
    server_password: String,
}

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

        let server_url = format!("http://{}/{}/{}", self.server_addr, group_name, enc_file_name);

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
    
        let server_url = format!("http://{}/{}/{}", self.server_addr, group_name, enc_file_name);

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
        let server_url = format!("http://{}/{}", self.server_addr, group_name);

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
        let server_url = format!("http://{}/fcm_notification", self.server_addr);

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
        let server_url = format!("http://{}/livestream/{}", self.server_addr, group_name);

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

    /// Checks to see if there's a livestream request. If so, returns the epoch is the client
    /// is expecting the livestream to be on.
    pub fn livestream_check(&self, group_name: &str) -> io::Result<()> {
        let server_url = format!("http://{}/livestream/{}", self.server_addr, group_name);
    
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
            if line.starts_with("data: ") {
                println!("Received event data: {}", &line[6..]);
                break;
            }
        }
    
        Ok(())
    }
    
    /// Uploads some (encrypted) livestream data to the server.
    /// Returns the number of pending files in the server.
    pub fn livestream_upload(  
        &self,      
        group_name: &str,
        data: Vec<u8>,
        chunk_number: u64,        
    ) -> io::Result<usize> {
        let server_url = format!("http://{}/livestream/{}/{}", self.server_addr, group_name, chunk_number);

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
        let server_url = format!("http://{}/livestream/{}/{}", self.server_addr, group_name, chunk_number);

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