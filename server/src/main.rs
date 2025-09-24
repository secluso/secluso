//! Secluso Delivery Service (DS).
//! The DS is implemented as an HTTP server.
//! The DS is fully untrusted.
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

#[macro_use]
extern crate rocket;

use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as base64_engine;
use base64::Engine;
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use rocket::data::{Data, ToByteUnit};
use rocket::response::content::RawText;
use rocket::response::stream::{Event, EventStream};
use rocket::serde::json::Json;
use rocket::serde::Deserialize;
use rocket::tokio;
use rocket::tokio::fs::{self, File};
use rocket::tokio::select;
use rocket::tokio::sync::broadcast::{channel, Sender};
use rocket::tokio::sync::Notify;
use rocket::tokio::task;
use rocket::tokio::time::timeout;
use rocket::Shutdown;
use serde::Serialize;
use serde_json::Number;
use std::sync::{Arc, Mutex};
use std::time::Instant;

mod auth;
mod fcm;
mod security;

use crate::auth::{initialize_users, BasicAuth, FailStore};
use crate::fcm::send_notification;
use crate::security::check_path_sandboxed;

// Per-user livestream start state
#[derive(Clone)]
struct EventState {
    sender: Sender<()>,
    events: Arc<DashMap<String, String>>, // <Camera, Event Msg>
}

// Bulk check JSON structures

#[derive(Deserialize)]
struct MotionPair {
    group_name: String,
    epoch_to_check: Number,
}

#[derive(Deserialize)]
struct MotionPairs {
    group_names: Vec<MotionPair>,
}

#[derive(Serialize)]
struct GroupTimestamp {
    group_name: String,
    timestamp: i64,
}

// Pairing structures
#[derive(Debug)]
struct PairingEntry {
    phone_connected: bool,
    camera_connected: bool,
    phone_notified: bool,
    camera_notified: bool,
    created_at: Instant,
    notify: Arc<Notify>,
    expired: bool,
}

#[derive(serde::Deserialize)]
struct PairingRequest {
    pairing_token: String,
    role: String,
}

#[derive(serde::Serialize)]
struct PairingResponse {
    status: String,
}

type SharedPairingState = Arc<Mutex<HashMap<String, Arc<Mutex<PairingEntry>>>>>;
type AllEventState = Arc<DashMap<String, EventState>>;

// Simple rate limiters for the server
const MAX_MOTION_FILE_SIZE: usize = 50; // in mebibytes
const MAX_NUM_PENDING_MOTION_FILES: usize = 100;
const MAX_LIVESTREAM_FILE_SIZE: usize = 20; // in mebibytes
const MAX_NUM_PENDING_LIVESTREAM_FILES: usize = 50;
const MAX_COMMAND_FILE_SIZE: usize = 10; // in kibibytes

async fn get_num_files(path: &Path) -> io::Result<usize> {
    let mut entries = fs::read_dir(path).await?;
    let mut num_files = 0;

    while let Some(entry) = entries.next_entry().await? {
        if entry.file_type().await?.is_file() {
            num_files += 1;
        }
    }

    Ok(num_files)
}

#[post("/pair", data = "<data>")]
async fn pair(
    data: Json<PairingRequest>,
    state: &rocket::State<SharedPairingState>,
) -> Json<PairingResponse> {
    debug!(
        "[PAIR] Entered pair method with role: {}, token: {}",
        data.role, data.pairing_token
    );

    let role = data.role.to_lowercase();
    if role != "phone" && role != "camera" {
        debug!("[PAIR] Invalid role: {}", role);
        return Json(PairingResponse {
            status: "invalid_role".into(),
        });
    }

    let token = &data.pairing_token;
    let entry_arc = {
        let mut sessions = state.lock().unwrap();
        debug!("[PAIR] Looking up or creating session for token: {}", token);
        sessions
            .entry(token.clone())
            .or_insert_with(|| {
                debug!("[PAIR] No existing session found. Creating new entry.");
                Arc::new(Mutex::new(PairingEntry {
                    phone_connected: false,
                    camera_connected: false,
                    phone_notified: false,
                    camera_notified: false,
                    created_at: Instant::now(),
                    notify: Arc::new(Notify::new()),
                    expired: false,
                }))
            })
            .clone()
    };

    let token = &data.pairing_token;

    // Check for disallowed quote characters in the token
    if token.contains('"') {
        debug!("[PAIR] Invalid token contains quote character: {}", token);
        return Json(PairingResponse {
            status: "invalid_token".into(),
        });
    }

    let notify;
    let expired_at;
    {
        let mut entry = entry_arc.lock().unwrap();

        if entry.expired {
            debug!("[PAIR] Session already expired for token: {}", token);
            return Json(PairingResponse {
                status: "expired".into(),
            });
        }

        let elapsed = entry.created_at.elapsed();
        debug!(
            "[PAIR] Elapsed: {:?}, phone_notified: {}, camera_notified: {}",
            elapsed, entry.phone_notified, entry.camera_notified
        );

        if elapsed > Duration::from_secs(45) || entry.phone_notified || entry.camera_notified {
            debug!("[PAIR] Expiring session due to timeout or notification flag");
            entry.expired = true;
            return Json(PairingResponse {
                status: "expired".into(),
            });
        }

        match role.as_str() {
            "phone" => {
                debug!("[PAIR] Phone connected");
                entry.phone_connected = true;
            }
            "camera" => {
                debug!("[PAIR] Camera connected");
                entry.camera_connected = true;
            }
            _ => unreachable!(),
        }

        debug!(
            "[PAIR] phone_connected: {}, camera_connected: {}",
            entry.phone_connected, entry.camera_connected
        );

        if entry.phone_connected && entry.camera_connected {
            debug!("[PAIR] Both parties connected, returning 'paired'");
            entry.notify.notify_waiters();
            match role.as_str() {
                "phone" => entry.phone_notified = true,
                "camera" => entry.camera_notified = true,
                _ => {}
            }
            entry.expired = true;
            return Json(PairingResponse {
                status: "paired".into(),
            });
        }

        notify = entry.notify.clone();
        expired_at = entry.created_at + Duration::from_secs(45);
        debug!(
            "[PAIR] Only one side connected, waiting until {:?}",
            expired_at
        );
    }

    let wait_duration = expired_at.saturating_duration_since(Instant::now());
    debug!(
        "[PAIR] Awaiting notify or timeout for up to {:?}",
        wait_duration
    );
    let _ = timeout(wait_duration, notify.notified()).await;

    let mut entry = entry_arc.lock().unwrap();
    let still_valid = entry.phone_connected && entry.camera_connected;

    if still_valid {
        debug!("[PAIR] Notify wait completed: still valid. Returning paired response");
        match role.as_str() {
            "phone" => entry.phone_notified = true,
            "camera" => entry.camera_notified = true,
            _ => {}
        }
        entry.expired = true;
        Json(PairingResponse {
            status: "paired".into(),
        })
    } else {
        debug!("[PAIR] Notify wait completed: pairing expired.");
        entry.expired = true;
        match role.as_str() {
            "phone" => entry.phone_notified = true,
            "camera" => entry.camera_notified = true,
            _ => {}
        }
        Json(PairingResponse {
            status: "expired".into(),
        })
    }
}

#[post("/<camera>/<filename>", data = "<data>")]
async fn upload(
    camera: &str,
    filename: &str,
    data: Data<'_>,
    auth: BasicAuth,
) -> io::Result<String> {
    let root = Path::new("data").join(&auth.username);
    let camera_path = root.join(camera);
    check_path_sandboxed(&root, &camera_path)?;

    if !camera_path.exists() {
        fs::create_dir_all(&camera_path).await?;
    }

    let num_pending_files = get_num_files(&camera_path).await?;
    if num_pending_files > MAX_NUM_PENDING_MOTION_FILES {
        return Err(io::Error::other("Error: Reached max motion pending limit."));
    }

    let filepath = Path::new(&camera_path).join(filename);
    check_path_sandboxed(&root, &filepath)?;

    let filepath_tmp = Path::new(&camera_path).join(format!("{}_tmp", filename));
    check_path_sandboxed(&root, &filepath_tmp)?;

    let mut file = fs::File::create(&filepath_tmp).await?;
    let mut stream = data.open(MAX_MOTION_FILE_SIZE.mebibytes());
    tokio::io::copy(&mut stream, &mut file).await?;
    // Flush the file to disk
    file.sync_all().await?;

    // We write to a temp file first and then rename to avoid a race with the retrieve operation.
    fs::rename(filepath_tmp, filepath).await?;

    // Flush the directory entry metadata to disk
    let camera_dir = File::open(camera_path).await?;
    camera_dir.sync_all().await?;

    Ok("ok".to_string())
}

#[post("/bulkCheck", format = "application/json", data = "<data>")]
async fn bulk_group_check(data: Json<MotionPairs>, auth: BasicAuth) -> Json<Vec<GroupTimestamp>> {
    let root = Path::new("data").join(&auth.username);
    let pairs_wrapper: MotionPairs = data.into_inner();
    let pair_list = pairs_wrapper.group_names;

    let mut results: Vec<GroupTimestamp> = Vec::new();

    for pair in pair_list {
        let group_name = pair.group_name;
        let epoch_to_check = pair.epoch_to_check;

        let camera_path = root.join(&group_name);
        if check_path_sandboxed(&root, &camera_path).is_err() {
            continue;
        }

        let filepath = camera_path.join(epoch_to_check.to_string());
        if check_path_sandboxed(&root, &filepath).is_err() {
            continue;
        }

        if let Ok(true) = Path::try_exists(&filepath) {
            if let Ok(meta) = fs::metadata(&filepath).await {
                let ts = meta
                    .created()
                    .or_else(|_| meta.modified())
                    .and_then(|t| t.duration_since(UNIX_EPOCH).map_err(std::io::Error::other))
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);

                results.push(GroupTimestamp {
                    group_name,
                    timestamp: ts,
                });
            }
        }
    }

    Json(results)
}

#[get("/<camera>/<filename>")]
async fn retrieve(camera: &str, filename: &str, auth: BasicAuth) -> Option<RawText<File>> {
    let root = Path::new("data").join(&auth.username);
    let camera_path = root.join(camera);
    if check_path_sandboxed(&root, &camera_path).is_err() {
        return None;
    }

    let filepath = camera_path.join(filename);
    if check_path_sandboxed(&root, &filepath).is_err() {
        return None;
    }

    File::open(filepath).await.map(RawText).ok()
}

#[delete("/<camera>/<filename>")]
async fn delete_file(camera: &str, filename: &str, auth: BasicAuth) -> Option<()> {
    let root = Path::new("data").join(&auth.username);
    let camera_path = root.join(camera);
    if check_path_sandboxed(&root, &camera_path).is_err() {
        return None;
    }

    let filepath = camera_path.join(filename);
    if check_path_sandboxed(&root, &filepath).is_err() {
        return None;
    }

    fs::remove_file(filepath).await.ok()
}

#[delete("/<camera>")]
async fn delete_camera(camera: &str, auth: BasicAuth) -> io::Result<()> {
    let root = Path::new("data").join(&auth.username);
    let camera_path = root.join(camera);
    check_path_sandboxed(&root, &camera_path)?;

    fs::remove_dir_all(camera_path).await
}

#[post("/fcm_token", data = "<data>")]
async fn upload_fcm_token(data: Data<'_>, auth: BasicAuth) -> io::Result<String> {
    let root = Path::new("data").join(&auth.username);
    let token_path = root.join("fcm_token");
    check_path_sandboxed(&root, &token_path)?;

    let mut file = fs::File::create(&token_path).await?;
    // FIXME: hardcoded max size
    let mut stream = data.open(5.kibibytes());
    tokio::io::copy(&mut stream, &mut file).await?;
    // Flush the file to disk
    file.sync_all().await?;

    Ok("ok".to_string())
}

#[post("/fcm_notification", data = "<data>")]
async fn send_fcm_notification(data: Data<'_>, auth: BasicAuth) -> io::Result<String> {
    let root = Path::new("data").join(&auth.username);
    let token_path = root.join("fcm_token");
    check_path_sandboxed(&root, &token_path)?;

    if !token_path.exists() {
        return Err(io::Error::other("Error: FCM token not available."));
    }
    let token = fs::read_to_string(token_path).await?;

    // FIXME: hardcoded max size
    let notification_msg = data.open(8.kibibytes()).into_bytes().await?;
    task::block_in_place(|| {
        // FIXME: caller won't know if the notification failed to send

        match send_notification(token, notification_msg.to_vec()) {
            Ok(_) => {
                debug!("Notification sent successfully.");
            }
            Err(e) => {
                debug!("Failed to send notification: {}", e);
            }
        }
    });
    Ok("ok".to_string())
}

fn get_user_state(all_state: AllEventState, username: &str) -> EventState {
    // retun the EventState for the user. If it doesn't exist, add it and return it.
    match all_state.entry(username.to_string()) {
        Entry::Occupied(entry) => entry.get().clone(),
        Entry::Vacant(entry) => {
            let (tx, _) = channel(1024);
            let user_state = EventState {
                events: Arc::new(DashMap::new()),
                sender: tx,
            };
            entry.insert(user_state.clone());
            user_state
        }
    }
}

#[post("/livestream/<camera>")]
async fn livestream_start(
    camera: &str,
    auth: BasicAuth,
    all_state: &rocket::State<AllEventState>,
) -> io::Result<()> {
    let root = Path::new("data").join(&auth.username);
    let camera_path = root.join(camera);
    check_path_sandboxed(&root, &camera_path)?;

    if !camera_path.exists() {
        fs::create_dir_all(&camera_path).await?;
    }

    let update_path = Path::new(&camera_path).join("0");
    check_path_sandboxed(&root, &update_path)?;

    if update_path.exists() {
        return Err(io::Error::other(
            "Error: Previous update has not been retrieved yet.",
        ));
    }

    let livestream_end_path = Path::new(&camera_path).join("livestream_end");
    check_path_sandboxed(&root, &livestream_end_path)?;

    if livestream_end_path.exists() {
        fs::remove_file(livestream_end_path).await.ok();
    }

    let user_state = get_user_state(all_state.inner().clone(), &auth.username);

    let epoch = "placeholder".to_string();
    user_state.events.insert(camera.to_string(), epoch);
    let _ = user_state.sender.send(());

    Ok(())
}

#[get("/livestream/<camera>")]
async fn livestream_check(
    camera: &str,
    auth: BasicAuth,
    all_state: &rocket::State<AllEventState>,
    mut end: Shutdown,
) -> EventStream![] {
    let camera = camera.to_string();

    let root = Path::new("data").join(&auth.username);
    let camera_path = root.join(&camera);

    let user_state = get_user_state(all_state.inner().clone(), &auth.username);
    let mut rx = user_state.sender.subscribe();

    EventStream! {
        if check_path_sandboxed(&root, &camera_path).is_err() {
            yield Event::data("invalid");
            return;
        }

        loop {
            if let Some((_key, epoch)) = user_state.events.remove(&camera) {
                // wipe all the data from the previous stream (if any)
                // FIXME: error is ignored here and other uses of ok()
                fs::remove_dir_all(&camera_path).await.ok();
                fs::create_dir_all(&camera_path).await.ok();
                yield Event::data(epoch.to_string());
                return;
            }

            select! {
                msg = rx.recv() => match msg {
                    Ok(()) => {},
                    Err(_) => break,
                },
                _ = &mut end => break,
            };
        }
    }
}

#[post("/livestream/<camera>/<filename>", data = "<data>")]
async fn livestream_upload(
    camera: &str,
    filename: &str,
    data: Data<'_>,
    auth: BasicAuth,
    all_state: &rocket::State<AllEventState>,
) -> io::Result<String> {
    let root = Path::new("data").join(&auth.username);
    let camera_path = root.join(camera);
    check_path_sandboxed(&root, &camera_path)?;

    if !camera_path.exists() {
        return Err(io::Error::other(
            "Error: Livestream session not started properly.",
        ));
    }

    let livestream_end_path = camera_path.join("livestream_end");
    check_path_sandboxed(&root, &livestream_end_path)?;

    if livestream_end_path.exists() {
        // If it's a commit msg, let it be uploaded.
        if filename != "0" {
            fs::remove_file(livestream_end_path).await.ok();
            return Ok(0.to_string());
        }
    }

    let num_pending_files = get_num_files(&camera_path).await?;
    if num_pending_files > MAX_NUM_PENDING_LIVESTREAM_FILES {
        return Err(io::Error::other(
            "Error: Reached max livestream pending limit.",
        ));
    }

    let filepath = Path::new(&camera_path).join(filename);
    check_path_sandboxed(&root, &filepath)?;

    let filepath_tmp = Path::new(&camera_path).join(format!("{}_tmp", filename));
    check_path_sandboxed(&root, &filepath_tmp)?;

    let mut file = fs::File::create(&filepath_tmp).await?;
    let mut stream = data.open(MAX_LIVESTREAM_FILE_SIZE.mebibytes());
    tokio::io::copy(&mut stream, &mut file).await?;
    // Flush the file to disk
    file.sync_all().await?;

    // We write to a temp file first and then rename to avoid a race with the retrieve operation.
    fs::rename(filepath_tmp, filepath).await?;

    // Flush the directory entry metadata to disk
    let camera_dir = File::open(camera_path).await?;
    camera_dir.sync_all().await?;

    let user_state = get_user_state(all_state.inner().clone(), &auth.username);
    let _ = user_state.sender.send(());

    // Returns the number of pending files
    Ok((num_pending_files + 1).to_string())
}

#[get("/livestream/<camera>/<filename>")]
async fn livestream_retrieve(
    camera: &str,
    filename: &str,
    auth: BasicAuth,
    all_state: &rocket::State<AllEventState>,
) -> Option<RawText<File>> {
    let root = Path::new("data").join(&auth.username);
    let camera_path = root.join(camera);
    if check_path_sandboxed(&root, &camera_path).is_err() {
        return None;
    }

    let filepath = camera_path.join(filename);
    if check_path_sandboxed(&root, &filepath).is_err() {
        return None;
    }

    if camera_path.exists() {
        if !filepath.exists() {
            let user_state = get_user_state(all_state.inner().clone(), &auth.username);
            let mut rx = user_state.sender.subscribe();
            let _ = rx.recv().await;
        }
        let response = File::open(&filepath).await.map(RawText).ok();
        return response;
    }

    None
}

#[post("/livestream_end/<camera>")]
async fn livestream_end(camera: &str, auth: BasicAuth) -> io::Result<()> {
    let root = Path::new("data").join(&auth.username);
    let camera_path = root.join(camera);
    check_path_sandboxed(&root, &camera_path)?;

    if !camera_path.exists() {
        fs::create_dir_all(&camera_path).await?;
    }

    let livestream_end_path = camera_path.join("livestream_end");
    check_path_sandboxed(&root, &livestream_end_path)?;

    let _ = File::create(livestream_end_path).await?;

    Ok(())
}

#[post("/config/<camera>", data = "<data>")]
async fn config_command(
    camera: &str,
    data: Data<'_>,
    auth: BasicAuth,
    all_state: &rocket::State<AllEventState>,
) -> io::Result<()> {
    let root = Path::new("data").join(&auth.username);
    let camera_path = root.join(camera);
    check_path_sandboxed(&root, &camera_path)?;

    if !camera_path.exists() {
        fs::create_dir_all(&camera_path).await?;
    }

    //FIXME: if we receive two commands back to back, one could overwrite the other.
    let command_file_name = "command".to_string();
    let command_path = Path::new(&camera_path).join(&command_file_name);
    check_path_sandboxed(&root, &command_path)?;

    let mut file = fs::File::create(&command_path).await?;
    let mut stream = data.open(MAX_COMMAND_FILE_SIZE.kibibytes());
    tokio::io::copy(&mut stream, &mut file).await?;
    // Flush the file to disk
    file.sync_all().await?;

    let user_state = get_user_state(all_state.inner().clone(), &auth.username);

    user_state
        .events
        .insert(camera.to_string(), command_file_name);
    let _ = user_state.sender.send(());

    Ok(())
}

#[get("/config/<camera>")]
async fn config_check(
    camera: &str,
    auth: BasicAuth,
    all_state: &rocket::State<AllEventState>,
    mut end: Shutdown,
) -> EventStream![] {
    let camera = camera.to_string();

    let root = Path::new("data").join(&auth.username);
    let camera_path = root.join(&camera);

    let user_state = get_user_state(all_state.inner().clone(), &auth.username);
    let mut rx = user_state.sender.subscribe();

    EventStream! {
        if check_path_sandboxed(&root, &camera_path).is_err() {
            yield Event::data("invalid");
            return;
        }

        loop {
            if let Some((_key, command_file_name)) = user_state.events.remove(&camera) {
                let command_path = Path::new(&camera_path).join(&command_file_name);
                if check_path_sandboxed(&root, &command_path).is_err() {
                    yield Event::data("invalid");
                    return;
                }

                let content = match fs::read(&command_path).await {
                    Ok(data) => data,
                    Err(_) => {
                        yield Event::data("error reading file");
                        return;
                    }
                };

                fs::remove_file(&camera_path).await.ok();

                // Encode binary data as base64 and return
                let encoded = base64_engine.encode(&content);
                yield Event::data(encoded);
                return;
            }

            select! {
                msg = rx.recv() => match msg {
                    Ok(()) => {},
                    Err(_) => break,
                },
                _ = &mut end => break,
            };
        }
    }
}

#[post("/config_response/<camera>", data = "<data>")]
async fn config_response(camera: &str, data: Data<'_>, auth: BasicAuth) -> io::Result<()> {
    let root = Path::new("data").join(&auth.username);
    let camera_path = root.join(camera);
    check_path_sandboxed(&root, &camera_path)?;

    if !camera_path.exists() {
        return Err(io::Error::other("Error: config camera doesn't exist."));
    }

    let filepath = camera_path.join("config_response");
    check_path_sandboxed(&root, &filepath)?;

    let filepath_tmp = camera_path.join("config_response_tmp");
    check_path_sandboxed(&root, &filepath_tmp)?;

    let mut file = fs::File::create(&filepath_tmp).await?;
    let mut stream = data.open(MAX_COMMAND_FILE_SIZE.kibibytes());
    tokio::io::copy(&mut stream, &mut file).await?;
    // Flush the file to disk
    file.sync_all().await?;

    // We write to a temp file first and then rename to avoid a race with the retrieve operation.
    fs::rename(filepath_tmp, filepath).await?;

    // Flush the directory entry metadata to disk
    let camera_dir = File::open(camera_path).await?;
    camera_dir.sync_all().await?;

    Ok(())
}

#[get("/config_response/<camera>")]
async fn retrieve_config_response(camera: &str, auth: BasicAuth) -> Option<RawText<File>> {
    let root = Path::new("data").join(&auth.username);
    let camera_path = root.join(camera);
    if check_path_sandboxed(&root, &camera_path).is_err() {
        return None;
    }

    let filepath = camera_path.join("config_response");
    if check_path_sandboxed(&root, &filepath).is_err() {
        return None;
    }

    if camera_path.exists() {
        let response = File::open(&filepath).await.map(RawText).ok();
        fs::remove_file(filepath).await.ok();
        return response;
    }

    None
}

#[post("/debug_logs", data = "<data>")]
async fn upload_debug_logs(data: Data<'_>, auth: BasicAuth) -> io::Result<String> {
    let root = Path::new("data").join(&auth.username);
    let logs_path = root.join("debug_logs");
    check_path_sandboxed(&root, &logs_path)?;

    let mut file = fs::File::create(&logs_path).await?;
    // FIXME: hardcoded max size
    let mut stream = data.open(5.mebibytes());
    tokio::io::copy(&mut stream, &mut file).await?;
    // Flush the file to disk
    file.sync_all().await?;

    Ok("ok".to_string())
}

#[launch]
fn rocket() -> _ {
    let all_event_state: AllEventState = Arc::new(DashMap::new());
    let pairing_state: SharedPairingState = Arc::new(Mutex::new(HashMap::new()));
    let failure_store: FailStore = Arc::new(DashMap::new());

    let config = rocket::Config {
        port: 8000,
        address: "127.0.0.1".parse().unwrap(),
        ..rocket::Config::default()
    };

    rocket::custom(config)
        .manage(all_event_state)
        .manage(initialize_users())
        .manage(failure_store)
        .manage(pairing_state)
        .mount(
            "/",
            routes![
                pair,
                upload,
                bulk_group_check,
                retrieve,
                delete_file,
                delete_camera,
                upload_fcm_token,
                send_fcm_notification,
                livestream_start,
                livestream_check,
                livestream_upload,
                livestream_retrieve,
                livestream_end,
                config_command,
                config_check,
                config_response,
                retrieve_config_response,
                upload_debug_logs,
            ],
        )
}
