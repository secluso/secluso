//! Secluso user authentication
//!
//! SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::Context;
use rand::distr::Uniform;
use rand::Rng;
use std::io;

pub const NUM_USERNAME_CHARS: usize = 14;
pub const NUM_PASSWORD_CHARS: usize = 14;

pub const USER_CREDENTIALS_VERSION: &str = "uc-v1.0";

#[derive(serde::Serialize, serde::Deserialize)]
pub struct UserCredentials {
    #[serde(rename = "v", alias = "version")]
    pub version: String,

    #[serde(rename = "u", alias = "username")]
    pub username: String,

    #[serde(rename = "p", alias = "password")]
    pub password: String,

    #[serde(rename = "sa", alias = "server_addr")]
    pub server_addr: String,
}

pub fn parse_user_credentials(credentials: Vec<u8>) -> io::Result<(String, String)> {
    let username_password = String::from_utf8(credentials)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    if username_password.len() != NUM_USERNAME_CHARS + NUM_PASSWORD_CHARS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid credentials".to_string(),
        ));
    }

    Ok((
        username_password[0..NUM_USERNAME_CHARS].to_string(),
        username_password[NUM_USERNAME_CHARS..].to_string(),
    ))
}

pub fn parse_user_credentials_full(
    credentials_full: Vec<u8>,
) -> io::Result<(String, String, String)> {
    let credentials_full_string = String::from_utf8(credentials_full)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    if credentials_full_string.len() <= NUM_USERNAME_CHARS + NUM_PASSWORD_CHARS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid credentials".to_string(),
        ));
    }

    Ok((
        credentials_full_string[0..NUM_USERNAME_CHARS].to_string(),
        credentials_full_string[NUM_USERNAME_CHARS..NUM_USERNAME_CHARS + NUM_PASSWORD_CHARS]
            .to_string(),
        credentials_full_string[NUM_USERNAME_CHARS + NUM_PASSWORD_CHARS..].to_string(),
    ))
}

pub fn generate_random(num_chars: usize, special_characters: bool) -> String {
    // We exclude : because that character has a special use in the http(s) auth header.
    // We exclude / because that character is used within the Linux file system
    let charset: &[u8] = if special_characters {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                           abcdefghijklmnopqrstuvwxyz\
                           0123456789\
                           !@#$%^&*()-_=+[]{}|;,.<>?"
    } else {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                           abcdefghijklmnopqrstuvwxyz\
                           0123456789"
    };

    let mut rng = rand::rng();
    (0..num_chars)
        .map(|_| {
            let idx = rng.sample(Uniform::new(0, charset.len()).unwrap());
            charset[idx] as char
        })
        .collect()
}

pub fn create_user_credentials(server_addr: String) -> anyhow::Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let username = generate_random(NUM_USERNAME_CHARS, true);
    let password = generate_random(NUM_PASSWORD_CHARS, true);

    let credentials_string = format!("{}{}", username, password);
    let credentials = credentials_string.into_bytes();

    let credentials_full_testing_string = format!("{}{}{}", username, password, server_addr);
    let credentials_full_testing = credentials_full_testing_string.into_bytes();

    let user_credentials = UserCredentials {
        version: USER_CREDENTIALS_VERSION.to_string(),
        username,
        password,
        server_addr,
    };
    let credentials_full_string = serde_json::to_string(&user_credentials)
        .context("Failed to serialize user credentials into JSON")?;
    let credentials_full = credentials_full_string.into_bytes();
    
    Ok((credentials, credentials_full, credentials_full_testing))
}
