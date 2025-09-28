//! Secluso DS Authentication.
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

use base64::{engine::general_purpose, Engine as _};
use dashmap::DashMap;
use rocket::http::Status;
use rocket::request::{FromRequest, Outcome, Request};
use rocket::State;
use secluso_client_server_lib::auth::{
    parse_user_credentials, NUM_PASSWORD_CHARS, NUM_USERNAME_CHARS,
};
use std::collections::HashMap;
use std::collections::VecDeque;
use std::ffi::OsString;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::str;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;
use subtle::{Choice, ConstantTimeEq};

const DUMMY_PASSWORD: [u8; NUM_PASSWORD_CHARS] = [0u8; NUM_PASSWORD_CHARS];

// Temporal window of which we examine the amount of fails a user makes
const FAIL_WINDOW: Duration = Duration::from_secs(5 * 60);

// The amount of times we allow authentication fails within the FAIL_WINDOW.
const MAX_FAILS: usize = 5;

// The length at which a person with a given IP is locked out if they perform MAX_FAILS fails within the FAIL_WINDOW.
const LOCKOUT: Duration = Duration::from_secs(15 * 60);

pub struct BasicAuth {
    pub username: String,
}

// Store for each IP the amount of invalid attempts of logging in to prevent bruteforcing.
#[derive(Default)]
pub struct FailEntry {
    pub attempts: VecDeque<Instant>,
    pub locked_until: Option<Instant>,
}

// DashMap helps avoid normal user issues in cases of brute-forcing from lots of different IPs at once.
pub type FailStore = Arc<DashMap<String, FailEntry>>;

type UserStore = Mutex<HashMap<String, String>>;

// Check and see if the given IP (key) is in lock-mode.
fn is_locked(store: &FailStore, key: &str) -> bool {
    if let Some(mut state) = store.get_mut(key) {
        if let Some(until) = state.locked_until {
            if Instant::now() < until {
                return true;
            } else {
                state.locked_until = None; // No longer in a lock.
            }
        }
    }
    false
}

// Records a failure for the given IP (key). If the key has now reached the point of locking, this will return true.
fn record_failure(store: &FailStore, key: &str) -> bool {
    let mut state = store.entry(key.to_string()).or_default();
    let now = Instant::now();

    // Discard attempts not within the FAIL_WINDOW, allows us to count easily and get rid of excess memory
    while let Some(&t) = state.attempts.front() {
        if now.duration_since(t) > FAIL_WINDOW {
            state.attempts.pop_front();
        } else {
            break;
        }
    }

    // Add the current time.
    state.attempts.push_back(now);

    // If we reached MAX_FAILS, set the locked_until field and return true.
    if state.attempts.len() >= MAX_FAILS {
        state.locked_until = Some(now + LOCKOUT);
        true
    } else {
        false
    }
}

/// Convert &str to fixed-length bytes for constant-time comparison.
/// Assumes passwords are ASCII (or otherwise 1 byte per char) and always NUM_PASSWORD_CHARS long.
/// If the length differs, we still produce a fixed-size array (zero-padded/truncated),
/// which will fail the ct_eq against a valid stored password but preserves constant-time behavior.
fn to_fixed_bytes(s: &str) -> [u8; NUM_PASSWORD_CHARS] {
    let b = s.as_bytes();
    let mut out = [0u8; NUM_PASSWORD_CHARS];
    let n = b.len().min(NUM_PASSWORD_CHARS);
    out[..n].copy_from_slice(&b[..n]);
    out
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for BasicAuth {
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let auth_header = req.headers().get_one("Authorization");
        let user_store = req.guard::<&State<UserStore>>().await.unwrap();
        let fail_store = req.guard::<&State<FailStore>>().await.unwrap();

        let ip = req
            .client_ip()
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "unknown".into());

        {
            if is_locked(fail_store, &ip) {
                return Outcome::Error((Status::TooManyRequests, ()));
            }
        }

        if let Some(auth_value) = auth_header {
            if let Some((username, password)) = decode_basic_auth(auth_value) {
                let password_bytes: [u8; NUM_PASSWORD_CHARS] = to_fixed_bytes(&password);

                let users = user_store.lock().unwrap();
                let (stored_password_bytes, user_exists): ([u8; NUM_PASSWORD_CHARS], bool) =
                    match users.get(&username) {
                        Some(stored_password) => (to_fixed_bytes(stored_password), true),
                        None => (DUMMY_PASSWORD, false),
                    };

                let eq: Choice = stored_password_bytes.ct_eq(&password_bytes);

                if bool::from(eq) && user_exists {
                    return Outcome::Success(BasicAuth { username });
                }
            }
        }

        // Failed to authenticate, so we accumulate the internal counter to guard against brute-forcing attempts.
        {
            let now_locked = record_failure(fail_store, &ip);
            if now_locked {
                return Outcome::Error((Status::TooManyRequests, ()));
            }
        }

        Outcome::Error((Status::Unauthorized, ()))
    }
}

fn decode_basic_auth(auth_value: &str) -> Option<(String, String)> {
    if let Some(encoded) = auth_value.strip_prefix("Basic ") {
        // Remove "Basic " prefix
        let decoded = general_purpose::STANDARD.decode(encoded).ok()?;
        let decoded_str = str::from_utf8(&decoded).ok()?;
        let mut parts = decoded_str.splitn(2, ':');
        let username = parts.next()?.to_string();
        let password = parts.next()?.to_string();

        if username.len() != NUM_USERNAME_CHARS || password.len() != NUM_PASSWORD_CHARS {
            return None;
        }

        return Some((username, password));
    }
    None
}

pub fn initialize_users() -> UserStore {
    let mut users = HashMap::new();
    let dir = "./user_credentials".to_string();
    match fs::read_dir(dir.clone()) {
        Ok(files) => {
            for file in files {
                match file {
                    Ok(f) => {
                        match f.file_type() {
                            Ok(file_type) => {
                                //Ignore dir, symlink, etc.
                                if file_type.is_file() {
                                    let mut pathname = OsString::from(dir.clone() + "/");
                                    pathname.push(f.file_name());
                                    let fil =
                                        fs::File::open(pathname).expect("Could not open file");
                                    let mut reader = BufReader::with_capacity(
                                        fil.metadata().unwrap().len().try_into().unwrap(),
                                        fil,
                                    );
                                    let data = reader.fill_buf().unwrap();
                                    // The returned username has NUM_USERNAME_CHARS characters.
                                    // The returned password has NUM_PASSWORD_CHARS characters.
                                    // See client_server_lib/src/auth.rs
                                    let (username, password) =
                                        parse_user_credentials(data.to_vec()).unwrap();
                                    let old = users.insert(username.clone(), password);
                                    if old.is_some() {
                                        panic!("Duplicate client!");
                                    }
                                    let files_path_string = format!("./data/{}", username);
                                    let files_path = Path::new(&files_path_string);
                                    if !files_path.exists() {
                                        fs::create_dir_all(files_path).unwrap();
                                    }
                                }
                            }
                            Err(e) => {
                                panic!("Could not get file type: {:?}", e);
                            }
                        }
                    }
                    Err(e) => {
                        panic!("Could not read file from directory: {:?}", e);
                    }
                }
            }
        }
        Err(e) => {
            panic!("Could not read directory: {:?}", e);
        }
    }
    Mutex::new(users)
}
