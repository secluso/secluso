//! Privastead user authentication
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

use std::io;
use rand::{thread_rng, Rng};
use rand::distributions::Uniform;

pub const NUM_USERNAME_CHARS: usize = 14;
pub const NUM_PASSWORD_CHARS: usize = 14;

pub fn parse_user_credentials(credentials: Vec<u8>) -> io::Result<(String, String)> {
    let username_password = String::from_utf8(credentials)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    if username_password.len() != NUM_USERNAME_CHARS + NUM_PASSWORD_CHARS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid credentials"),
        ));
    }

    Ok((
        username_password[0..NUM_USERNAME_CHARS].to_string(),
        username_password[NUM_USERNAME_CHARS..].to_string(),
    ))
}

pub fn parse_user_credentials_full(credentials_full: Vec<u8>) -> io::Result<(String, String, String)> {
    let credentials_full_string = String::from_utf8(credentials_full)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    println!("Debug: {}", credentials_full_string.len());
    if credentials_full_string.len() <= NUM_USERNAME_CHARS + NUM_PASSWORD_CHARS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid credentials"),
        ));
    }

    Ok((
        credentials_full_string[0..NUM_USERNAME_CHARS].to_string(),
        credentials_full_string[NUM_USERNAME_CHARS..NUM_USERNAME_CHARS + NUM_PASSWORD_CHARS].to_string(),
        credentials_full_string[NUM_USERNAME_CHARS + NUM_PASSWORD_CHARS..].to_string(),
    ))
}

fn generate_random(num_chars: usize) -> String {
    let charset: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                           abcdefghijklmnopqrstuvwxyz\
                           0123456789\
                           !@#$%^&*()-_=+[]{}|;:,.<>?/";
    
    let mut rng = thread_rng();
    (0..num_chars)
        .map(|_| {
            let idx = rng.sample(Uniform::new(0, charset.len()));
            charset[idx] as char
        })
        .collect()
}

pub fn create_user_credentials(server_addr: String) -> (Vec<u8>, Vec<u8>) {
    let username = generate_random(NUM_USERNAME_CHARS);
    let password = generate_random(NUM_PASSWORD_CHARS);

    let credentials_string = format!("{}{}", username, password);
    let credentials = credentials_string.into_bytes();

    let credentials_full_string = format!("{}{}{}", username, password, server_addr);
    let credentials_full = credentials_full_string.into_bytes();

    (credentials, credentials_full)
}
    