//! Privastead Delivery Service (DS).
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

use std::io;
use std::path::Path;

use rocket::data::{Data, ToByteUnit};
use rocket::response::content::RawText;
use rocket::tokio::fs::{self, File};
use rocket::tokio::task;
use rocket::serde::json::Json;
use rocket::tokio::sync::broadcast::{channel, Sender};
use rocket::response::stream::{Event, EventStream};
use rocket::Shutdown;
use rocket::tokio::select;
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use std::sync::Arc;
use rocket::serde::Deserialize;
use serde_json::Number;

mod auth;
mod fcm;
mod security;

use crate::auth::{initialize_users, BasicAuth};
use crate::security::{check_path_sandboxed};
use crate::fcm::send_notification;

// Per-user livestream start state
#[derive(Clone)]
struct LivestreamStartState {
    sender: Sender<()>,
    cameras_started: Arc<DashMap<String, String>>,
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

type AllLiveStreamStartState = Arc<DashMap<String, LivestreamStartState>>;

// Simple rate limiters for the server
const MAX_MOTION_FILE_SIZE: usize = 50; // in mebibytes
const MAX_NUM_PENDING_MOTION_FILES: usize = 100;
const MAX_LIVESTREAM_FILE_SIZE: usize = 20; // in mebibytes
const MAX_NUM_PENDING_LIVESTREAM_FILES: usize = 50;

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

#[post("/<camera>/<filename>", data = "<data>")]
async fn upload(
    camera: &str,
    filename: &str,
    data: Data<'_>,
    auth: BasicAuth,
) -> io::Result<String> {
    let root = Path::new("data").join(&auth.username);
    let camera_path = root.join(camera);
    if !camera_path.exists() {
        fs::create_dir_all(&camera_path).await?;
    }

    let num_pending_files = get_num_files(&camera_path).await?;
    if num_pending_files > MAX_NUM_PENDING_MOTION_FILES {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Error: Reached max motion pending limit.",
        ));
    }

    let filepath = Path::new(&camera_path).join(filename);
    let filepath_tmp = Path::new(&camera_path).join(format!("{}_tmp", filename));

    data.open(MAX_MOTION_FILE_SIZE.mebibytes())
        .into_file(&filepath_tmp)
        .await?;
    // We write to a temp file first and then rename to avoid a race with the retrieve operation.
    fs::rename(filepath_tmp, filepath).await?;

    Ok("ok".to_string())
}


#[post("/bulkCheck", format = "application/json", data = "<data>")]
async fn bulk_group_check(
    data: Json<MotionPairs>,
    auth: BasicAuth,
) -> RawText<String> {
    let root = Path::new("data").join(&auth.username);
    let pairs_wrapper: MotionPairs = data.into_inner();
    let pair_list = pairs_wrapper.group_names;

    let mut valid_pairs = Vec::new();

    for pair in pair_list {
        let group_name = pair.group_name;
        let epoch_to_check = pair.epoch_to_check;

        let camera_path = root.join(&group_name);
        let filepath = camera_path.join(epoch_to_check.to_string());

        if check_path_sandboxed(&root, &filepath).is_err() {
            continue;
        }

        if let Ok(true) = Path::try_exists(&filepath) {
            valid_pairs.push(group_name);
        }
    }

    RawText(valid_pairs.iter().map(|x| x.to_string() + ",").collect::<String>())
}

#[get("/<camera>/<filename>")]
async fn retrieve(
    camera: &str,
    filename: &str,
    auth: BasicAuth,
) -> Option<RawText<File>> {
    let root = Path::new("data").join(&auth.username);
    let camera_path = root.join(camera);
    let filepath = camera_path.join(filename);

    if check_path_sandboxed(&root, &filepath).is_err() {
        return None;
    }

    File::open(filepath).await.map(RawText).ok()
}

#[delete("/<camera>/<filename>")]
async fn delete_file(
    camera: &str,
    filename: &str,
    auth: BasicAuth,
) -> Option<()> {
    let root = Path::new("data").join(&auth.username);
    let camera_path = root.join(camera);
    let filepath = camera_path.join(filename);

    if check_path_sandboxed(&root, &filepath).is_err() {
        return None;
    }

    fs::remove_file(filepath).await.ok()
}

#[delete("/<camera>")]
async fn delete_camera(
    camera: &str,
    auth: BasicAuth,
) -> io::Result<()> {
    let root = Path::new("data").join(&auth.username);
    let camera_path = root.join(camera);

    check_path_sandboxed(&root, &camera_path)?;

    fs::remove_dir_all(camera_path).await
}

#[post("/fcm_token", data = "<data>")]
async fn upload_fcm_token(
    data: Data<'_>,
    auth: BasicAuth,
) -> io::Result<String> {
    let root = Path::new("data").join(&auth.username);
    let token_path = root.join("fcm_token");

    check_path_sandboxed(&Path::new("data"), &token_path)?;

    // FIXME: hardcoded max size
    data.open(5.kibibytes()).into_file(token_path).await?;
    Ok("ok".to_string())
}

#[post("/fcm_notification", data = "<data>")]
async fn send_fcm_notification(
    data: Data<'_>,
    auth: BasicAuth,
) -> io::Result<String> {
    let root = Path::new("data").join(&auth.username);
    let token_path = root.join("fcm_token");
    if !token_path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Error: FCM token not available.",
        ));
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

fn get_user_state(
    all_state: AllLiveStreamStartState,
    username: &str,
) -> LivestreamStartState {
    // retun the LivestreamStartState for the user. If it doesn't exist, add it and return it.
    match all_state.entry(username.to_string()) {
        Entry::Occupied(entry) => entry.get().clone(),
        Entry::Vacant(entry) => {
            let (tx, _) = channel(1024);
            let user_state = LivestreamStartState {
                cameras_started: Arc::new(DashMap::new()),
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
    all_state: &rocket::State<AllLiveStreamStartState>,
) -> io::Result<()> {
    let root = Path::new("data").join(&auth.username);
    let camera_path = root.join(camera);

    check_path_sandboxed(&root, &camera_path)?;

    let update_path = Path::new(&camera_path).join("0");
    let livestream_end_path = Path::new(&camera_path).join("livestream_end");

    check_path_sandboxed(&root, &update_path)?;
    check_path_sandboxed(&root, &livestream_end_path)?;
    if update_path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Error: Previous update has not been retrieved yet.",
        ));
    }

    if livestream_end_path.exists() {
        fs::remove_file(livestream_end_path).await.ok();
    }

    fs::create_dir_all(&camera_path).await?;

    let user_state = get_user_state(all_state.inner().clone(), &auth.username);

    let epoch = format!("placeholder");
    user_state.cameras_started.insert(camera.to_string(), epoch);
    let _ = user_state.sender.send(());

    Ok(())
}

#[get("/livestream/<camera>")]
async fn livestream_check(
    camera: &str,
    auth: BasicAuth,
    all_state: &rocket::State<AllLiveStreamStartState>,
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
            if let Some((_key, epoch)) = user_state.cameras_started.remove(&camera) {
                // wipe all the data from the previous stream (if any)
                // FIXME: error is ignored here and other uses of ok()
                fs::remove_dir_all(&camera_path).await.ok();
                fs::create_dir_all(&camera_path).await.ok();
                yield Event::data(epoch.to_string());
                break;
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
    all_state: &rocket::State<AllLiveStreamStartState>,
) -> io::Result<String> {
    let root = Path::new("data").join(&auth.username);
    let camera_path = root.join(camera);

    if !camera_path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Error: Livestream session not started properly.",
        ));
    }

    let livestream_end_path = camera_path.join("livestream_end");
    if livestream_end_path.exists() {
        fs::remove_file(livestream_end_path).await.ok();
        return Ok(0.to_string());
    }

    let num_pending_files = get_num_files(&camera_path).await?;
    if num_pending_files > MAX_NUM_PENDING_LIVESTREAM_FILES {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Error: Reached max livestream pending limit.",
        ));
    }

    let filepath = Path::new(&camera_path).join(filename);
    let filepath_tmp = Path::new(&camera_path).join(format!("{}_tmp", filename));

    check_path_sandboxed(&root, &filepath)?;
    check_path_sandboxed(&root, &filepath_tmp)?;

    data.open(MAX_LIVESTREAM_FILE_SIZE.mebibytes())
        .into_file(&filepath_tmp)
        .await?;
    // We write to a temp file first and then rename to avoid a race with the retrieve operation.
    fs::rename(filepath_tmp, filepath).await?;

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
    all_state: &rocket::State<AllLiveStreamStartState>,
) -> Option<RawText<File>> {
    let root = Path::new("data").join(&auth.username);
    let camera_path = root.join(camera);
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
    let livestream_end_path = camera_path.join("livestream_end");

    check_path_sandboxed(&root, &livestream_end_path)?;

    if !camera_path.exists() {
        rocket::tokio::fs::create_dir_all(&camera_path).await?;
    }

    let _ = File::create(livestream_end_path).await?;

    Ok(())
}

#[launch]
fn rocket() -> _ {
    let all_livestream_start_state: AllLiveStreamStartState = Arc::new(DashMap::new());

    let config = rocket::Config {
        port: 8080,
        address: "0.0.0.0".parse().unwrap(),
        ..rocket::Config::default()
    };

    rocket::custom(config)
        .manage(all_livestream_start_state)
        .manage(initialize_users())
        .mount(
            "/",
            routes![
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
            ],
        )
}
