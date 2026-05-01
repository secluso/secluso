//! Secluso Delivery Service (DS).
//! The DS is implemented as an HTTP server.
//! The DS is fully untrusted.
//!
//! SPDX-License-Identifier: GPL-3.0-or-later

#[macro_use]
extern crate rocket;

use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::io;
use std::io::ErrorKind;
use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as base64_engine;
use base64::Engine;
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use rocket::data::{Data, Limits, ToByteUnit};
use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::{Header, Status};
use rocket::request::{FromRequest, Outcome};
use rocket::response::content::RawText;
use rocket::response::stream::{Event, EventStream};
use rocket::response::status::Custom;
use rocket::serde::json::Json;
use rocket::tokio;
use rocket::tokio::fs::{self, File};
use rocket::tokio::select;
use rocket::tokio::sync::broadcast::{channel, Sender};
use rocket::tokio::sync::Mutex as AsyncMutex;
use rocket::tokio::sync::Notify;
use rocket::tokio::task;
use rocket::tokio::time::timeout;
use rocket::tokio::io::AsyncWriteExt;
use rocket::{Response, Request, Shutdown};
use secluso_server_backbone::types::{
    ConfigResponse, GroupTimestamp, MotionPairs, NotificationTarget, PairingRequest,
    PairingResponse, ServerStatus,
};
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub mod auth;
pub mod fcm;
pub mod notification_target;
pub mod security;

use self::auth::{initialize_users, BasicAuth, FailStore};
use self::fcm::send_notification;
use self::security::{check_path_sandboxed, join_validated_child};

// Store the version of the current crate, which we'll use in all responses.
#[derive(Default, Clone)]
struct ServerVersionHeader {
    version: String,
}

#[rocket::async_trait]
impl Fairing for ServerVersionHeader {
    // Information provided to rocket to determine set of callbacks we're registering for.
    fn info(&self) -> Info {
        Info {
            name: "Add Server Version headers to all responses",
            kind: Kind::Response,
        }
    }

    // Response callback - we want to intercept and add the X-Server-Version to each AUTHENTICATED response.
    // This will allow us to do compatability checks in the app.
    async fn on_response<'r>(&self, request: &'r Request<'_>, response: &mut Response<'r>) {
        // When the cache lookup fails (from the &BasicAuth request guard), this defaults to 'false' within the authenticated field.
        let auth: &BasicAuth = request.local_cache(|| BasicAuth {
            username: "N/A".to_string(),
            authenticated: false,
        });
        if auth.authenticated {
            let header = Header::new("X-Server-Version", self.version.clone());
            response.set_header(header); // Modify the request with the new header
        }
    }
}

// Per-user livestream start state
#[derive(Clone)]
struct EventState {
    sender: Sender<()>,
    events: Arc<DashMap<String, String>>, // <Camera, Event Msg>
}

// Pairing structures
#[derive(Debug)]
struct PairingEntry {
    phone_connected: bool,
    camera_connected: bool,
    phone_notified: bool,
    camera_notified: bool,
    notification_target: Option<NotificationTarget>,
    created_at: Instant,
    notify: Arc<Notify>,
    expired: bool,
}

type PairingSessionKey = (String, String);
type SharedPairingState = Arc<Mutex<HashMap<PairingSessionKey, Arc<Mutex<PairingEntry>>>>>;
type AllEventState = Arc<DashMap<String, EventState>>;

// Simple rate limiters for the server
const MAX_MOTION_FILE_SIZE: usize = 50; // in mebibytes
const MAX_NUM_PENDING_MOTION_FILES: usize = 100;
const MAX_LIVESTREAM_FILE_SIZE: usize = 20; // in mebibytes
const MAX_NUM_PENDING_LIVESTREAM_FILES: usize = 50;
const MAX_COMMAND_FILE_SIZE: usize = 100; // in kibibytes
const MAX_JSON_SIZE: usize = 10; // in kibibytes
#[cfg(not(test))]
const PAIRING_SESSION_TIMEOUT: Duration = Duration::from_secs(45);
#[cfg(test)]
const PAIRING_SESSION_TIMEOUT: Duration = Duration::from_millis(250);

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

async fn persist_pair_notification_target(
    auth: &BasicAuth,
    target: &NotificationTarget,
) -> io::Result<()> {
    let root = Path::new("data").join(&auth.username);
    let target_path = root.join("notification_target.json");
    check_path_sandboxed(&root, &target_path)?;

    fs::create_dir_all(&root).await?;
    let target_json = serde_json::to_vec(target)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    fs::write(target_path, target_json).await?;
    Ok(())
}

async fn load_notification_target(
    root: &Path,
    notification_target_policy: &notification_target::UnifiedPushPolicy,
) -> io::Result<Option<NotificationTarget>> {
    let target_path = root.join("notification_target.json");
    check_path_sandboxed(root, &target_path)?;

    if !target_path.exists() {
        return Ok(None);
    }

    let raw = fs::read_to_string(target_path).await?;
    let parsed = serde_json::from_str::<NotificationTarget>(&raw)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    if let Err(err) =
        notification_target::validate_notification_target(notification_target_policy, &parsed)
    {
        warn!("Ignoring invalid persisted notification target: {err}");
        return Ok(None);
    }

    Ok(Some(parsed))
}

#[post("/pair", data = "<data>")]
async fn pair(
    data: Json<PairingRequest>,
    state: &rocket::State<SharedPairingState>,
    notification_target_policy: &rocket::State<notification_target::UnifiedPushPolicy>,
    auth: &BasicAuth,
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
            notification_target: None,
        });
    }

    let token = &data.pairing_token;

    // Check for disallowed quote characters in the token
    if token.contains('"') {
        debug!("[PAIR] Invalid token contains quote character: {}", token);
        return Json(PairingResponse {
            status: "invalid_token".into(),
            notification_target: None,
        });
    }

    let session_key = (auth.username.clone(), token.clone());
    let entry_arc = {
        let mut sessions = state.lock().unwrap();
        debug!(
            "[PAIR] Looking up or creating session for user: {}, token: {}",
            auth.username, token
        );
        sessions
            .entry(session_key)
            .or_insert_with(|| {
                debug!("[PAIR] No existing session found. Creating new entry.");
                Arc::new(Mutex::new(PairingEntry {
                    phone_connected: false,
                    camera_connected: false,
                    phone_notified: false,
                    camera_notified: false,
                    notification_target: None,
                    created_at: Instant::now(),
                    notify: Arc::new(Notify::new()),
                    expired: false,
                }))
            })
            .clone()
    };

    let notify;
    let expired_at;
    let target_to_persist;
    {
        let mut entry = entry_arc.lock().unwrap();

        if entry.expired {
            debug!("[PAIR] Session already expired for token: {}", token);
            return Json(PairingResponse {
                status: "expired".into(),
                notification_target: entry.notification_target.clone(),
            });
        }

        let elapsed = entry.created_at.elapsed();
        debug!(
            "[PAIR] Elapsed: {:?}, phone_notified: {}, camera_notified: {}",
            elapsed, entry.phone_notified, entry.camera_notified
        );

        if elapsed > PAIRING_SESSION_TIMEOUT || entry.phone_notified || entry.camera_notified {
            debug!("[PAIR] Expiring session due to timeout or notification flag");
            entry.expired = true;
            return Json(PairingResponse {
                status: "expired".into(),
                notification_target: entry.notification_target.clone(),
            });
        }

        match role.as_str() {
            "phone" => {
                debug!("[PAIR] Phone connected");
                entry.phone_connected = true;
                entry.notification_target = data.notification_target.clone().and_then(|target| {
                    if let Err(err) = notification_target::validate_notification_target(
                        notification_target_policy.inner(),
                        &target,
                    ) {
                        warn!("Dropping invalid notification target from pair payload: {err}");
                        None
                    } else {
                        Some(target)
                    }
                });
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

        target_to_persist = if role == "phone" {
            entry.notification_target.clone()
        } else {
            None
        };

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
                notification_target: entry.notification_target.clone(),
            });
        }

        notify = entry.notify.clone();
        expired_at = entry.created_at + PAIRING_SESSION_TIMEOUT;
        debug!(
            "[PAIR] Only one side connected, waiting until {:?}",
            expired_at
        );
    }

    if let Some(target) = target_to_persist.as_ref() {
        if let Err(e) = persist_pair_notification_target(&auth, target).await {
            error!("[PAIR] Failed to persist notification target from pair payload: {e}");
        } else {
            debug!(
                "[PAIR] Persisted notification target from pair payload (platform={})",
                target.platform
            );
        }
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
            notification_target: entry.notification_target.clone(),
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
            notification_target: entry.notification_target.clone(),
        })
    }
}

#[post("/<camera>/<filename>/<counter>", data = "<data>")]
async fn upload(
    camera: &str,
    filename: &str,
    counter: u32,
    data: Data<'_>,
    auth: &BasicAuth,
) -> io::Result<String> {
    // Validate counter (must be 1 or 2)
    if counter == 0 || counter > 2 {
        return Err(io::Error::other("counter must be 1 or 2"));
    }

    let root = Path::new("data").join(&auth.username);
    let camera_path = join_validated_child(&root, camera, "camera")?;
    check_path_sandboxed(&root, &camera_path)?;

    if !camera_path.exists() {
        fs::create_dir_all(&camera_path).await?;
    }

    let num_pending_files = get_num_files(&camera_path).await?;
    if num_pending_files > MAX_NUM_PENDING_MOTION_FILES {
        return Err(io::Error::other("Error: Reached max motion pending limit."));
    }

    let filepath = camera_path.join(filename);
    check_path_sandboxed(&root, &filepath)?;

    let filepath_tmp = camera_path.join(format!("{}_tmp", filename));
    check_path_sandboxed(&root, &filepath_tmp)?;

    let refcount_path = camera_path.join(format!(".{}.refcount", filename));
    check_path_sandboxed(&root, &refcount_path)?;

    let refcount_tmp_path = camera_path.join(format!(".{}.refcount_tmp", filename));
    check_path_sandboxed(&root, &refcount_tmp_path)?;

    let mut file = fs::File::create(&filepath_tmp).await?;
    let mut stream = data.open(MAX_MOTION_FILE_SIZE.mebibytes());
    tokio::io::copy(&mut stream, &mut file).await?;
    file.sync_all().await?;

    // We write to a temp file first and then rename to avoid a race with the retrieve operation.
    fs::rename(&filepath_tmp, &filepath).await?;

    // Write refcount atomically
    fs::write(&refcount_tmp_path, counter.to_string()).await?;
    fs::rename(&refcount_tmp_path, &refcount_path).await?;

    // Flush the directory entry metadata to disk
    let camera_dir = File::open(&camera_path).await?;
    camera_dir.sync_all().await?;

    Ok("ok".to_string())
}

#[post("/bulkCheck", format = "application/json", data = "<data>")]
async fn bulk_group_check(data: Json<MotionPairs>, auth: &BasicAuth) -> Json<Vec<GroupTimestamp>> {
    let root = Path::new("data").join(&auth.username);
    let pairs_wrapper: MotionPairs = data.into_inner();
    let pair_list = pairs_wrapper.group_names;

    let mut results: Vec<GroupTimestamp> = Vec::new();

    for pair in pair_list {
        let group_name = pair.group_name;
        let epoch_to_check = pair.epoch_to_check;

        let camera_path = match join_validated_child(&root, &group_name, "camera") {
            Ok(path) => path,
            Err(_) => continue,
        };
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
async fn retrieve(camera: &str, filename: &str, auth: &BasicAuth) -> Option<RawText<File>> {
    let root = Path::new("data").join(&auth.username);
    let camera_path = join_validated_child(&root, camera, "camera").ok()?;
    if check_path_sandboxed(&root, &camera_path).is_err() {
        return None;
    }

    let filepath = camera_path.join(filename);
    if check_path_sandboxed(&root, &filepath).is_err() {
        return None;
    }

    File::open(filepath).await.map(RawText).ok()
}

static FILE_LOCKS: Lazy<AsyncMutex<HashMap<String, Arc<AsyncMutex<()>>>>> =
    Lazy::new(|| AsyncMutex::new(HashMap::new()));

async fn get_file_lock(camera: String) -> Arc<AsyncMutex<()>> {
    let mut locks = FILE_LOCKS.lock().await;
    locks
        .entry(camera)
        .or_insert_with(|| Arc::new(AsyncMutex::new(())))
        .clone()
}

async fn remove_file_lock(camera: &str) {
    let mut map = FILE_LOCKS.lock().await;
    map.remove(camera);
}

#[delete("/<camera>/<filename>")]
async fn delete_file(camera: &str, filename: &str, auth: &BasicAuth) -> Option<()> {
    let root = Path::new("data").join(&auth.username);
    let camera_path = join_validated_child(&root, camera, "camera").ok()?;

    if check_path_sandboxed(&root, &camera_path).is_err() {
        return None;
    }

    let filepath = camera_path.join(filename);
    if check_path_sandboxed(&root, &filepath).is_err() {
        return None;
    }

    let refcount_path = camera_path.join(format!(".{}.refcount", filename));
    if check_path_sandboxed(&root, &refcount_path).is_err() {
        return None;
    }

    // Two concurrent delete calls could race and we'll end
    // up not deleting the file. That's why we need this lock.
    let file_lock = get_file_lock(camera.to_string()).await;
    let _guard = file_lock.lock().await;

    // Read refcount (default = 1 if missing)
    let refcount = match fs::read_to_string(&refcount_path).await {
        Ok(contents) => contents
            .trim()
            .parse::<u32>()
            .ok()
            .filter(|v| *v >= 1)
            .unwrap_or(1),
        Err(e) if e.kind() == ErrorKind::NotFound => 1,
        Err(_) => return None,
    };

    if refcount > 1 {
        let new_refcount = refcount - 1;
        if fs::write(&refcount_path, new_refcount.to_string())
            .await
            .is_err()
        {
            return None;
        }
    } else {
        // Delete actual file
        if fs::remove_file(&filepath).await.is_err() {
            return None;
        }

        // Best-effort remove refcount file
        match fs::remove_file(&refcount_path).await {
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(_) => return None,
        }
    }

    Some(())
}

#[delete("/<camera>")]
async fn delete_camera(camera: &str, auth: &BasicAuth) -> io::Result<()> {
    let root = Path::new("data").join(&auth.username);
    let camera_path = join_validated_child(&root, camera, "camera")?;
    check_path_sandboxed(&root, &camera_path)?;

    remove_file_lock(camera).await;

    fs::remove_dir_all(camera_path).await
}

#[post("/fcm_token", data = "<data>")]
async fn upload_fcm_token(data: Data<'_>, auth: &BasicAuth) -> io::Result<String> {
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

#[post("/notification_target", format = "json", data = "<data>")]
async fn upload_notification_target(
    data: Json<NotificationTarget>,
    notification_target_policy: &rocket::State<notification_target::UnifiedPushPolicy>,
    auth: &BasicAuth,
) -> io::Result<String> {
    let target = data.into_inner();
    notification_target::validate_notification_target(notification_target_policy.inner(), &target)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

    let root = Path::new("data").join(&auth.username);
    let target_path = root.join("notification_target.json");
    check_path_sandboxed(&root, &target_path)?;

    fs::create_dir_all(&root).await?;
    let target_json = serde_json::to_vec(&target)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    fs::write(target_path, target_json).await?;

    Ok("ok".to_string())
}

#[get("/notification_target")]
async fn retrieve_notification_target(
    notification_target_policy: &rocket::State<notification_target::UnifiedPushPolicy>,
    auth: &BasicAuth,
) -> Option<Json<NotificationTarget>> {
    let root = Path::new("data").join(&auth.username);
    let parsed = load_notification_target(&root, notification_target_policy.inner())
        .await
        .ok()??;
    Some(Json(parsed))
}

#[post("/fcm_notification", data = "<data>")]
async fn send_fcm_notification(
    data: Data<'_>,
    notification_target_policy: &rocket::State<notification_target::UnifiedPushPolicy>,
    auth: &BasicAuth,
) -> io::Result<String> {
    let root = Path::new("data").join(&auth.username);
    let notification_target =
        load_notification_target(&root, notification_target_policy.inner()).await?;
    let notification_msg = data.open(8.kibibytes()).into_bytes().await?;

    if let Some(target) = notification_target.as_ref() {
        if target.platform.eq_ignore_ascii_case("android_unified") {
            let endpoint_url = match target.unifiedpush_endpoint_url.as_deref() {
                Some(value) if !value.trim().is_empty() => value,
                _ => {
                    debug!("Skipping UnifiedPush notification; endpoint URL not available");
                    return Ok("ok".to_string());
                }
            };
            let pub_key = match target.unifiedpush_pub_key.as_deref() {
                Some(value) if !value.trim().is_empty() => value,
                _ => {
                    debug!("Skipping UnifiedPush notification; public key not available");
                    return Ok("ok".to_string());
                }
            };
            let auth_secret = match target.unifiedpush_auth.as_deref() {
                Some(value) if !value.trim().is_empty() => value,
                _ => {
                    debug!("Skipping UnifiedPush notification; auth secret not available");
                    return Ok("ok".to_string());
                }
            };

            match notification_target::send_notification(
                notification_target_policy.inner(),
                endpoint_url,
                pub_key,
                auth_secret,
                notification_msg.as_ref(),
            )
            .await
            {
                Ok(_) => {
                    debug!("UnifiedPush notification sent successfully.");
                }
                Err(e) => {
                    debug!("Failed to send UnifiedPush notification: {}", e);
                }
            }
            return Ok("ok".to_string());
        }
    }

    let token_path = root.join("fcm_token");
    check_path_sandboxed(&root, &token_path)?;
    if !token_path.exists() {
        return Err(io::Error::other("Error: FCM token not available."));
    }
    let token = fs::read_to_string(token_path).await?;

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
    auth: &BasicAuth,
    all_state: &rocket::State<AllEventState>,
) -> io::Result<()> {
    let root = Path::new("data").join(&auth.username);
    let camera_path = join_validated_child(&root, camera, "camera")?;
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
    auth: &BasicAuth,
    all_state: &rocket::State<AllEventState>,
    mut end: Shutdown,
) -> EventStream![] {
    let camera = camera.to_string();

    let root = Path::new("data").join(&auth.username);
    let camera_path = join_validated_child(&root, &camera, "camera");

    let user_state = get_user_state(all_state.inner().clone(), &auth.username);
    let mut rx = user_state.sender.subscribe();

    EventStream! {
        let camera_path = match camera_path.as_ref() {
            Ok(path) => path,
            Err(_) => {
                yield Event::data("invalid");
                return;
            }
        };

        if check_path_sandboxed(&root, camera_path).is_err() {
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
    auth: &BasicAuth,
    all_state: &rocket::State<AllEventState>,
) -> io::Result<String> {
    let root = Path::new("data").join(&auth.username);
    let camera_path = join_validated_child(&root, camera, "camera")?;
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
    auth: &BasicAuth,
    all_state: &rocket::State<AllEventState>,
) -> Option<RawText<File>> {
    let root = Path::new("data").join(&auth.username);
    let camera_path = join_validated_child(&root, camera, "camera").ok()?;
    if check_path_sandboxed(&root, &camera_path).is_err() {
        return None;
    }

    let filepath = camera_path.join(filename);
    if check_path_sandboxed(&root, &filepath).is_err() {
        return None;
    }

    if camera_path.exists() {
        let user_state = get_user_state(all_state.inner().clone(), &auth.username);
        let mut rx = user_state.sender.subscribe();

        // IMPORTANT: If we check the filepath exists() first and only subscribe after, there is a tiny race:
        // 1. app asks for the next livestream chunk
        // 2. we check disk and don't see it yet
        // 3. camera uploads that chunk and sends the new chunk signal
        // 4. we subscribe too late and miss that signal
        // 5. this request can sit here forever even though the chunk exists
        //
        // So we subscribe up front, then keep re-checking the file.
        for _ in 0..3 {
            if filepath.exists() {
                let response = File::open(&filepath).await.map(RawText).ok();
                return response;
            }

            // Don't hang this request forever if the chunk never arrives.
            let _ = timeout(Duration::from_secs(5), rx.recv()).await;
        }

        if filepath.exists() {
            let response = File::open(&filepath).await.map(RawText).ok();
            return response;
        }
    }

    None
}

#[post("/livestream_end/<camera>")]
async fn livestream_end(camera: &str, auth: &BasicAuth) -> io::Result<()> {
    let root = Path::new("data").join(&auth.username);
    let camera_path = join_validated_child(&root, camera, "camera")?;
    check_path_sandboxed(&root, &camera_path)?;

    if !camera_path.exists() {
        fs::create_dir_all(&camera_path).await?;
    }

    let livestream_end_path = camera_path.join("livestream_end");
    check_path_sandboxed(&root, &livestream_end_path)?;

    let _ = File::create(livestream_end_path).await?;

    Ok(())
}

struct ExpectedCommandSize(u64);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ExpectedCommandSize {
    type Error = String;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match req.headers().get_one("X-Command-Size") {
            Some(value) => match value.parse::<u64>() {
                Ok(size) => Outcome::Success(ExpectedCommandSize(size)),
                Err(_) => Outcome::Error((
                    Status::BadRequest,
                    "Invalid X-Command-Size header".to_string(),
                )),
            },
            None => Outcome::Error((
                Status::LengthRequired,
                "Missing X-Command-Size header".to_string(),
            )),
        }
    }
}

#[post("/config/<camera>", data = "<data>")]
async fn config_command(
    camera: &str,
    data: Data<'_>,
    expected_size: ExpectedCommandSize,
    auth: &BasicAuth,
    all_state: &rocket::State<AllEventState>,
) -> Result<(), Custom<String>> {
    let expected_size = expected_size.0;
    let max_size = MAX_COMMAND_FILE_SIZE.kibibytes().as_u64();

    if expected_size > max_size {
        return Err(Custom(
            Status::PayloadTooLarge,
            "Command is too large".to_string(),
        ));
    }

    if expected_size == 0 {
        return Err(Custom(
            Status::BadRequest,
            "Empty command upload is not allowed".to_string(),
        ));
    }

    let root = Path::new("data").join(&auth.username);
    let camera_path = join_validated_child(&root, camera, "camera")
        .map_err(internal_error)?;
    check_path_sandboxed(&root, &camera_path)
        .map_err(internal_error)?;

    if !camera_path.exists() {
        fs::create_dir_all(&camera_path).await
            .map_err(internal_error)?;
    }

    //FIXME: if we receive two commands back to back, one could overwrite the other.
    let command_file_name = "command".to_string();
    let command_path = camera_path.join(&command_file_name);
    let temp_command_path = camera_path.join("command.partial");

    check_path_sandboxed(&root, &command_path)
        .map_err(internal_error)?;
    check_path_sandboxed(&root, &temp_command_path)
        .map_err(internal_error)?;

    let result = async {
        let mut file = fs::File::create(&temp_command_path).await?;
        let mut stream = data.open(max_size.bytes());

        let bytes_written = tokio::io::copy(&mut stream, &mut file).await?;

        file.flush().await?;
        file.sync_all().await?;
        drop(file);

        Ok::<u64, io::Error>(bytes_written)
    }.await;

    let bytes_written = match result {
        Ok(n) => n,
        Err(e) => {
            let _ = fs::remove_file(&temp_command_path).await;
            return Err(Custom(
                Status::BadRequest,
                format!("Failed to receive complete command: {e}"),
            ));
        }
    };

    if bytes_written != expected_size {
        let _ = fs::remove_file(&temp_command_path).await;
        return Err(Custom(
            Status::BadRequest,
            format!(
                "Incomplete command upload: expected {expected_size} bytes, received {bytes_written} bytes"
            ),
        ));
    }

    fs::rename(&temp_command_path, &command_path).await
        .map_err(internal_error)?;

    let user_state = get_user_state(all_state.inner().clone(), &auth.username);

    user_state
        .events
        .insert(camera.to_string(), command_file_name);

    let _ = user_state.sender.send(());

    Ok(())
}

fn internal_error(e: impl std::fmt::Display) -> Custom<String> {
    Custom(Status::InternalServerError, e.to_string())
}

#[get("/config/<camera>")]
async fn config_check(
    camera: &str,
    auth: &BasicAuth,
    all_state: &rocket::State<AllEventState>,
    mut end: Shutdown,
) -> EventStream![] {
    let camera = camera.to_string();

    let root = Path::new("data").join(&auth.username);
    let camera_path = join_validated_child(&root, &camera, "camera");

    let user_state = get_user_state(all_state.inner().clone(), &auth.username);
    let mut rx = user_state.sender.subscribe();

    EventStream! {
        let camera_path = match camera_path.as_ref() {
            Ok(path) => path,
            Err(_) => {
                yield Event::data("invalid");
                return;
            }
        };

        if check_path_sandboxed(&root, camera_path).is_err() {
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
async fn config_response(camera: &str, data: Data<'_>, auth: &BasicAuth) -> io::Result<()> {
    let root = Path::new("data").join(&auth.username);
    let camera_path = join_validated_child(&root, camera, "camera")?;
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
async fn retrieve_config_response(camera: &str, auth: &BasicAuth) -> Option<RawText<File>> {
    let root = Path::new("data").join(&auth.username);
    let camera_path = join_validated_child(&root, camera, "camera").ok()?;
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

// state.inner() utilizes a borrowed value
// When changing from BasicAuth -> &BasicAuth, we needed to specify where the borrowed value is borrowed from
// Thus, the 'a lifetime specifier was added here
#[get("/fcm_config")]
async fn retrieve_fcm_data<'a>(
    state: &'a rocket::State<ConfigResponse>,
    _auth: &BasicAuth,
) -> Json<&'a ConfigResponse> {
    Json(state.inner())
}

#[get("/status")]
async fn retrieve_server_status(_auth: &BasicAuth) -> Json<ServerStatus> {
    let server_status = ServerStatus { ok: true };

    Json(server_status)
}

#[post("/debug_logs", data = "<data>")]
async fn upload_debug_logs(data: Data<'_>, auth: &BasicAuth) -> io::Result<String> {
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
fn rocket() -> rocket::Rocket<rocket::Build> {
    build_rocket()
}

pub fn build_rocket() -> rocket::Rocket<rocket::Build> {
    let all_event_state: AllEventState = Arc::new(DashMap::new());
    let pairing_state: SharedPairingState = Arc::new(Mutex::new(HashMap::new()));
    let failure_store: FailStore = Arc::new(DashMap::new());

    let mut network_type: Option<String> = None;
    let mut bind_address: Option<String> = None;
    let mut listen_port: Option<u16> = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--network-type" {
            if let Some(value) = args.next() {
                network_type = Some(value);
            }
        } else if arg == "--bind-address" {
            if let Some(value) = args.next() {
                bind_address = Some(value);
            }
        } else if arg == "--port" {
            if let Some(value) = args.next() {
                if let Ok(parsed) = value.parse::<u16>() {
                    listen_port = Some(parsed);
                } else {
                    eprintln!("Invalid --port={value}. Falling back to default 8000.");
                }
            }
        } else if let Some(value) = arg.strip_prefix("--network-type=") {
            network_type = Some(value.to_string());
        } else if let Some(value) = arg.strip_prefix("--bind-address=") {
            bind_address = Some(value.to_string());
        } else if let Some(value) = arg.strip_prefix("--port=") {
            if let Ok(parsed) = value.parse::<u16>() {
                listen_port = Some(parsed);
            } else {
                eprintln!("Invalid --port={value}. Falling back to default 8000.");
            }
        }
    }

    let address = bind_address.unwrap_or_else(|| match network_type.as_deref() {
        Some("http") => "0.0.0.0".to_string(),
        Some("https") | None => "127.0.0.1".to_string(),
        Some(other) => {
            eprintln!("Unknown --network-type={other}. Use http or https.");
            "127.0.0.1".to_string()
        }
    });

    let config = rocket::Config {
        port: listen_port.unwrap_or(8000),
        address: address.parse().unwrap(),
        limits: Limits::default().limit("json", MAX_JSON_SIZE.kibibytes()),
        ..rocket::Config::default()
    };

    // Fetch the relevant app FCM data and store globally for future requests asking for it.
    // Tests and local tooling can skip this with SECLUSO_SKIP_FCM_CONFIG=1.
    let fcm_config = if std::env::var("SECLUSO_SKIP_FCM_CONFIG").is_ok() {
        ConfigResponse::default()
    } else {
        fcm::fetch_config().expect("Failed to fetch config")
    };
    let notification_target_policy = notification_target::UnifiedPushPolicy::from_env()
        .expect("Failed to parse UnifiedPush allowlist");

    rocket::custom(config)
        .attach(ServerVersionHeader {
            version: env!("CARGO_PKG_VERSION").to_string(), // Fetch the version of this crate
        })
        .manage(all_event_state)
        .manage(initialize_users())
        .manage(failure_store)
        .manage(pairing_state)
        .manage(fcm_config)
        .manage(notification_target_policy)
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
                upload_notification_target,
                retrieve_notification_target,
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
                retrieve_fcm_data,
                retrieve_server_status,
            ],
        )
}

#[cfg(test)]
mod pairing_tests {
    use super::{auth::BasicAuth, notification_target, pair, PairingRequest, SharedPairingState};
    use rocket::serde::json::Json;
    use rocket::State;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    fn test_auth(username: &str) -> BasicAuth {
        BasicAuth {
            username: username.to_string(),
            authenticated: true,
        }
    }

    #[rocket::async_test]
    async fn pairing_succeeds_with_same_authenticated_account() {
        let state: SharedPairingState = Arc::new(Mutex::new(HashMap::new()));
        let policy = notification_target::UnifiedPushPolicy::from_env().unwrap();
        let auth = test_auth("sameacctuser01");

        let (phone_response, camera_response) = rocket::tokio::join!(
            pair(
                Json(PairingRequest {
                    pairing_token: "shared-token".to_string(),
                    role: "phone".to_string(),
                    notification_target: None,
                }),
                State::from(&state),
                State::from(&policy),
                &auth,
            ),
            pair(
                Json(PairingRequest {
                    pairing_token: "shared-token".to_string(),
                    role: "camera".to_string(),
                    notification_target: None,
                }),
                State::from(&state),
                State::from(&policy),
                &auth,
            )
        );

        assert_eq!(phone_response.into_inner().status, "paired");
        assert_eq!(camera_response.into_inner().status, "paired");
    }

    #[rocket::async_test]
    async fn pairing_does_not_cross_authenticated_accounts() {
        let state: SharedPairingState = Arc::new(Mutex::new(HashMap::new()));
        let policy = notification_target::UnifiedPushPolicy::from_env().unwrap();
        let phone_auth = test_auth("phoneaccount01");
        let camera_auth = test_auth("cameraaccount1");

        let (phone_response, camera_response) = rocket::tokio::join!(
            pair(
                Json(PairingRequest {
                    pairing_token: "shared-token".to_string(),
                    role: "phone".to_string(),
                    notification_target: None,
                }),
                State::from(&state),
                State::from(&policy),
                &phone_auth,
            ),
            pair(
                Json(PairingRequest {
                    pairing_token: "shared-token".to_string(),
                    role: "camera".to_string(),
                    notification_target: None,
                }),
                State::from(&state),
                State::from(&policy),
                &camera_auth,
            )
        );

        assert_eq!(phone_response.into_inner().status, "expired");
        assert_eq!(camera_response.into_inner().status, "expired");
    }
}

#[cfg(test)]
mod contract_tests {
    use super::build_rocket;
    use rocket::http::Method;
    use secluso_server_backbone::routes::BASE_ROUTES;
    use secluso_server_backbone::HttpMethod;

    fn to_rocket_method(method: HttpMethod) -> Method {
        match method {
            HttpMethod::Get => Method::Get,
            HttpMethod::Post => Method::Post,
            HttpMethod::Delete => Method::Delete,
            HttpMethod::Put => Method::Put,
        }
    }

    #[test]
    fn base_routes_are_mounted() {
        std::env::set_var("SECLUSO_SKIP_FCM_CONFIG", "1");
        std::env::set_var("SECLUSO_SKIP_USER_CREDENTIALS", "1");
        let rocket = build_rocket();
        let routes: Vec<_> = rocket.routes().collect();

        for spec in BASE_ROUTES {
            let expected_method = to_rocket_method(spec.method);
            let route = routes
                .iter()
                .find(|route| route.method == expected_method && route.uri == spec.path);
            let route =
                route.unwrap_or_else(|| panic!("Missing route: {:?} {}", spec.method, spec.path));
            let route_uri = route.uri.to_string();
            let actual_params = extract_params(&route_uri);
            assert_eq!(
                actual_params.as_slice(),
                spec.params,
                "Param mismatch for {:?} {}",
                spec.method,
                spec.path
            );
        }
    }

    fn extract_params(path: &str) -> Vec<&str> {
        let path = path.split('?').next().unwrap_or(path);
        let mut params = Vec::new();
        let mut in_param = false;
        let mut start = 0;

        for (idx, ch) in path.char_indices() {
            if ch == '<' {
                in_param = true;
                start = idx + 1;
                continue;
            }
            if ch == '>' && in_param {
                let raw = &path[start..idx];
                let name = raw.trim_end_matches("..");
                params.push(name);
                in_param = false;
            }
        }

        params
    }
}
