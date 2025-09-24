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
use secluso_client_server_lib::auth::{parse_user_credentials, NUM_USERNAME_CHARS, NUM_PASSWORD_CHARS};
use rocket::http::Status;
use rocket::request::{FromRequest, Outcome, Request};
use rocket::State;
use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::str;
use std::sync::Mutex;
use subtle::{Choice, ConstantTimeEq};

const DUMMY_PASSWORD: [u8; NUM_PASSWORD_CHARS] = [0u8; NUM_PASSWORD_CHARS];

pub struct BasicAuth {
    pub username: String,
}

type UserStore = Mutex<HashMap<String, String>>;

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

        if let Some(auth_value) = auth_header {
            if let Some((username, password)) = decode_basic_auth(auth_value) {
                let password_bytes: [u8; NUM_PASSWORD_CHARS] = to_fixed_bytes(&password);

                let users = user_store.lock().unwrap();
                let (stored_password_bytes, user_exists): ([u8; NUM_PASSWORD_CHARS], bool) = match users.get(&username) {
                    Some(stored_password) => (to_fixed_bytes(stored_password), true),
                    None => (DUMMY_PASSWORD, false),
                };

                let eq: Choice = stored_password_bytes.ct_eq(&password_bytes);

                if bool::from(eq) && user_exists {
                    return Outcome::Success(BasicAuth { username });
                }
            }
        }

        Outcome::Error((Status::Unauthorized, ()))
    }
}

fn decode_basic_auth(auth_value: &str) -> Option<(String, String)> {
    if auth_value.starts_with("Basic ") {
        let encoded = &auth_value[6..]; // Remove "Basic " prefix
        let decoded = general_purpose::STANDARD.decode(encoded).ok()?;
        let decoded_str = str::from_utf8(&decoded).ok()?;
        let mut parts = decoded_str.splitn(2, ':');
        let username = parts.next()?.to_string();
        let password = parts.next()?.to_string();

        if username.len() != NUM_USERNAME_CHARS ||
            password.len() != NUM_PASSWORD_CHARS {

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
                                    debug!("Loading credentials for client {:?}", username);
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
