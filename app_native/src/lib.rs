//! App library.
//!
//! SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::anyhow;
use anyhow::Context;
use log::{debug, error, info};
use rand::distr::Alphanumeric;
use rand::Rng;
use secluso_client_lib::config::{
    Heartbeat, HeartbeatRequest, HeartbeatResult, OPCODE_HEARTBEAT_REQUEST, OPCODE_HEARTBEAT_RESPONSE,
    AddAppRequest, AddAppResponseCommon, AddAppResponseDedicated, OPCODE_ADD_APP_REQUEST, OPCODE_ADD_APP_RESPONSE,
};
use secluso_client_lib::mls_client::{Contact, MlsClient, ClientType};
use secluso_client_lib::mls_clients::MlsClients;
use secluso_client_lib::mls_clients::{
    CONFIG, FCM, LIVESTREAM, MLS_CLIENT_TAGS, MOTION, NUM_MLS_CLIENTS, THUMBNAIL,
    NUM_COMMON_MLS_CLIENTS, NUM_DEDICATED_MLS_CLIENTS,
};
use secluso_client_lib::pairing::{self, MAX_ALLOWED_MSG_LEN};
use secluso_client_lib::video::{encrypt_video_file, decrypt_video_file, decrypt_thumbnail_file};
use openmls::prelude::KeyPackage;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::array;
use std::fs;
use std::io;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::SocketAddr;
use std::net::TcpStream;
use std::str;
use std::str::FromStr;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::io::ErrorKind;

// Used to generate random names.
// With 16 alphanumeric characters, the probability of collision is very low.
// Note: even if collision happens, it has no impact on
// our security guarantees. Will only cause availability issues.
const NUM_RANDOM_CHARS: u8 = 16;
const CAMERA_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const CAMERA_IO_TIMEOUT: Duration = Duration::from_secs(12);
const CAMERA_CONNECT_RETRIES: usize = 3;
const CAMERA_CONNECT_RETRY_DELAY: Duration = Duration::from_millis(350);

#[flutter_rust_bridge::frb]
pub struct Clients {
    mls_clients: MlsClients,
}

#[flutter_rust_bridge::frb]
impl Clients {
    pub fn new(first_time: bool, file_dir: String) -> io::Result<Self> {
        let mls_clients: MlsClients = array::from_fn(|i| {
            let app_name = get_app_name(
                first_time,
                file_dir.clone(),
                format!("app_{}_name", MLS_CLIENT_TAGS[i]),
            );

            let mut mls_client = MlsClient::new(
                app_name,
                first_time,
                file_dir.clone(),
                MLS_CLIENT_TAGS[i].to_string(),
                ClientType::App,
            )
                .expect("MlsClient::new() for returned error.");

            // Make sure the groups_state files are created in case we initialize again soon.
            mls_client.save_group_state().unwrap();

            mls_client
        });

        Ok(Self { mls_clients })
    }
}

fn get_app_name(first_time: bool, file_dir: String, filename: String) -> String {
    let app_name = if first_time {
        let mut rng = rand::rng();
        let aname: String = (0..NUM_RANDOM_CHARS)
            .map(|_| rng.sample(Alphanumeric) as char)
            .collect();

        let mut file =
            fs::File::create(file_dir.clone() + "/" + &filename).expect("Could not create file");
        file.write_all(aname.as_bytes()).unwrap();
        file.flush().unwrap();
        file.sync_all().unwrap();

        aname
    } else {
        let file =
            fs::File::open(file_dir.clone() + "/" + &filename).expect("Cannot open file to send");
        let mut reader =
            BufReader::with_capacity(file.metadata().unwrap().len().try_into().unwrap(), file);
        let aname = reader.fill_buf().unwrap();

        String::from_utf8(aname.to_vec()).unwrap()
    };

    app_name
}

fn write_varying_len(stream: &mut TcpStream, msg: &[u8]) -> io::Result<()> {
    // FIXME: is u64 necessary?
    let len = msg.len() as u64;
    let len_data = len.to_be_bytes();

    stream.write_all(&len_data)?;
    stream.write_all(msg)?;
    stream.flush()?;

    Ok(())
}

fn read_varying_len(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut len_data = [0u8; 8];
    stream.read_exact(&mut len_data)?;
    let len = u64::from_be_bytes(len_data);

    if len > MAX_ALLOWED_MSG_LEN {
        error!("Communicated message length ({len}) exceeds the allowed length ({MAX_ALLOWED_MSG_LEN})");
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "Intended message length is too large",
        ))
    }

    let mut msg = vec![0u8; len as usize];
    stream.read_exact(&mut msg)?;

    Ok(msg)
}

fn perform_pairing_handshake(
    stream: &mut TcpStream,
    app_key_package: KeyPackage,
) -> anyhow::Result<KeyPackage> {
    let pairing = pairing::App::new(app_key_package);
    let app_msg = pairing.generate_msg_to_camera();
    write_varying_len(stream, &app_msg)?;
    let camera_msg = read_varying_len(stream)?;
    let camera_key_package = pairing.process_camera_msg(camera_msg)?;

    Ok(camera_key_package)
}

fn send_wifi_and_pairing_info(
    stream: &mut TcpStream,
    mls_client: &mut MlsClient,
    wifi_ssid: String,
    wifi_password: String,
    pairing_token: String,
) -> io::Result<()> {
    let wifi_msg = json!({
        "ssid": wifi_ssid,
        "passphrase": wifi_password,
        "pairing_token": pairing_token
    });
    info!("Sending wifi info {}", wifi_msg);
    let wifi_info_msg = match mls_client.encrypt(&serde_json::to_vec(&wifi_msg)?) {
        Ok(msg) => msg,
        Err(e) => {
            info!("Failed to encrypt SSID: {e}");
            return Err(e);
        }
    };
    info!("Before Wifi Msg Sent");
    write_varying_len(stream, &wifi_info_msg)?;
    info!("After Wifi Msg Sent");

    mls_client.save_group_state().unwrap();

    Ok(())
}

fn send_credentials_full(
    stream: &mut TcpStream,
    mls_client: &mut MlsClient,
    credentials_full: String,
) -> io::Result<()> {
    let msg = credentials_full.into_bytes();
    let encrypted_msg = match mls_client.encrypt(&msg) {
        Ok(msg) => msg,
        Err(e) => {
            info!("Failed to encrypt credentials_full: {e}");
            return Err(e);
        }
    };

    write_varying_len(stream, &encrypted_msg)?;

    mls_client.save_group_state().unwrap();

    Ok(())
}

fn receive_firmware_version(
    stream: &mut TcpStream,
) -> anyhow::Result<String> {
    info!("Sending credentials_full");
    let firmware_version_bytes = read_varying_len(stream)?;
    let firmware_version = String::from_utf8(firmware_version_bytes)?;

    Ok(firmware_version)
}

fn send_timestamp(
    stream: &mut TcpStream,
) -> anyhow::Result<()> {
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let timestamp_vec = bincode::serialize(&timestamp).unwrap();
    write_varying_len(stream, &timestamp_vec)?;

    Ok(())
}

fn connect_camera_stream(addr: &SocketAddr) -> io::Result<TcpStream> {
    let mut last_error: Option<io::Error> = None;

    for attempt in 1..=CAMERA_CONNECT_RETRIES {
        info!(
            "Connecting to camera (attempt {attempt}/{CAMERA_CONNECT_RETRIES}, addr={addr})"
        );

        match TcpStream::connect_timeout(addr, CAMERA_CONNECT_TIMEOUT) {
            Ok(stream) => {
                stream.set_read_timeout(Some(CAMERA_IO_TIMEOUT))?;
                stream.set_write_timeout(Some(CAMERA_IO_TIMEOUT))?;
                let _ = stream.set_nodelay(true);
                info!("Connected to camera transport (addr={addr})");
                return Ok(stream);
            }
            Err(e) => {
                info!("Error (connect attempt {attempt}): {e}");
                last_error = Some(e);
                if attempt < CAMERA_CONNECT_RETRIES {
                    thread::sleep(CAMERA_CONNECT_RETRY_DELAY);
                }
            }
        }
    }

    Err(last_error.unwrap_or_else(|| io::Error::other("camera connect failed")))
}

#[flutter_rust_bridge::frb]
fn pair_with_camera(
    stream: &mut TcpStream,
    camera_name: &str,
    mls_clients: &mut MlsClients,
    secret: Vec<u8>,
) -> anyhow::Result<()> {
    for index in 0..mls_clients.len() {
        let mls_client = &mut mls_clients[index];

        let app_key_package = mls_client.key_package();

        let camera_key_package = perform_pairing_handshake(stream, app_key_package)?;

        let camera_welcome_msg = read_varying_len(stream)?;
        let group_name = read_varying_len(stream)?;
        let group_name_string = str::from_utf8(&group_name)?.to_string();

        let contact = MlsClient::create_contact(camera_name, camera_key_package)?;

        process_welcome_message(
            mls_client,
            contact,
            camera_welcome_msg,
            secret.clone(),
            group_name_string,
        )?;
    }

    Ok(())
}

fn process_welcome_message(
    mls_client: &mut MlsClient,
    contact: Contact,
    welcome_msg: Vec<u8>,
    secret: Vec<u8>,
    group_name: String,
) -> io::Result<()> {
    mls_client.process_welcome_with_secret(contact, welcome_msg, secret, &group_name)?;
    mls_client.save_group_state().unwrap();

    Ok(())
}

pub fn encrypt_settings_message(
    clients_reg: &mut Option<Box<Clients>>,
    message: Vec<u8>,
) -> anyhow::Result<Vec<u8>> {
    if clients_reg.is_none() {
        return Err(anyhow!("Error: clients not initialized!"));
    }

    let clients = clients_reg.as_mut().unwrap();
    let config_mls_client = &mut clients.mls_clients[CONFIG];

    debug!("Encrypting message");
    let settings_msg = config_mls_client
        .encrypt(&message)
        .context("Failed to encrypt SSID")?;
    config_mls_client.save_group_state().unwrap();

    Ok(settings_msg)
}

#[allow(clippy::too_many_arguments)]
#[flutter_rust_bridge::frb]
pub fn add_camera(
    clients_reg: &mut Option<Box<Clients>>,
    camera_name: String,
    camera_ip: String,
    secret_vec: Vec<u8>,
    standalone_camera: bool,
    wifi_ssid: String,
    wifi_password: String,
    pairing_token: String,
    credentials_full: String,
) -> String {
    if clients_reg.is_none() {
        info!("Error: clients not initialized!");
        return "Error".to_string();
    }

    let clients = clients_reg.as_mut().unwrap();

    //Make sure the camera_name is not used before for another camera.
    for mls_client in &clients.as_mut().mls_clients {
        if mls_client.get_group_name().is_ok() {
            info!("Error: camera_name used before!");
            return "Error".to_string();
        }
    }

    // Connect to the camera
    //FIXME: port number hardcoded.
    let addr = match SocketAddr::from_str(&(camera_ip + ":12348")) {
        Ok(a) => a,
        Err(e) => {
            info!("Error: invalid IP address: {e}");
            return "Error".to_string();
        }
    };

    let mut stream = match connect_camera_stream(&addr) {
        Ok(s) => s,
        Err(e) => {
            info!("Error (connect): {e}");
            return "Error".to_string();
        }
    };

    if standalone_camera {
        // Need to send timestamp. RPi needs it for setting date/time.
        info!("Sending timestamp to camera");
        if let Err(e) = send_timestamp(
            &mut stream,
        ) {
            info!("Error (sending timestamp): {e}");
            return "Error".to_string();
        }
    }

    info!("Waiting for firmware version from camera");
    let firmware_version =
        match receive_firmware_version(&mut stream) {
            Ok(version) => version,
            Err(e) => {
                info!("Error (firmware): {e}");
                return "Error".to_string();
            }
        };

    let app_native_version = format!("v{}", env!("CARGO_PKG_VERSION"));
    info!("Camera version = {}, app native version = {}", firmware_version, app_native_version);
    if app_native_version != firmware_version {
        return "PairVersionIncompatible".to_string();
    }

    // Perform pairing
    info!("Starting camera pairing handshake");
    if let Err(e) = pair_with_camera(
        &mut stream,
        &camera_name,
        &mut clients.as_mut().mls_clients,
        secret_vec,
    ) {
        info!("Error (pairing): {e}");
        return "Error".to_string();
    }
    info!("Camera pairing handshake completed");

    // Send credentials (username, password, and IP address of the server)
    info!("Sending credentials to camera");
    if let Err(e) = send_credentials_full(
        &mut stream,
        &mut clients.mls_clients[CONFIG],
        credentials_full,
    ) {
        info!("Error (credentials): {e}");
        return "Error".to_string();
    }

    // Send Wi-Fi info
    if standalone_camera {
        info!("Sending Wi-Fi info to camera");
        if let Err(e) = send_wifi_and_pairing_info(
            &mut stream,
            &mut clients.mls_clients[CONFIG],
            wifi_ssid,
            wifi_password,
            pairing_token,
        ) {
            info!("Error (WiFi-info): {e}");
            return "Error".to_string();
        }
    }

    firmware_version
}

pub fn initialize(
    clients: &mut Option<Box<Clients>>,
    file_dir: String,
    first_time: bool,
) -> io::Result<bool> {
    info!("Initialize start");
    *clients = Some(Box::new(Clients::new(first_time, file_dir)?));

    Ok(true)
}

pub fn decrypt_video(
    clients: &mut Option<Box<Clients>>,
    encrypted_filename: String,
) -> io::Result<String> {
    if clients.is_none() {
        return Err(io::Error::other(
            "Error: clients not initialized!".to_string(),
        ));
    }

    let clients = clients.as_mut().unwrap();
    let file_dir = clients.mls_clients[MOTION].get_file_dir();
    let enc_pathname: String = format!("{}/encrypted/{}", file_dir, encrypted_filename);
    info!("Encrypted pathname: {}", enc_pathname);

    decrypt_video_file(
        &mut clients.mls_clients[MOTION],
        &enc_pathname,
    )
}

// This function is used to aid in performance testing; this is not used in the production app
pub fn encrypt_video(
    clients: &mut Option<Box<Clients>>,
    video_pathname: String,
    enc_pathname: String,
    timestamp: u64,
) -> io::Result<u64> {
    if clients.is_none() {
        return Err(io::Error::other(
            "Error: clients not initialized!".to_string(),
        ));
    }

    let clients = clients.as_mut().unwrap();
    encrypt_video_file(
        &mut clients.mls_clients[MOTION],
        &video_pathname,
        &enc_pathname,
        timestamp
    )
}

pub fn decrypt_thumbnail(
    clients: &mut Option<Box<Clients>>,
    encrypted_filename: String,
    pending_meta_directory: String,
) -> io::Result<String> {
    if clients.is_none() {
        return Err(io::Error::other(
            "Error: clients not initialized!".to_string(),
        ));
    }

    let clients = clients.as_mut().unwrap();
    let file_dir = clients.mls_clients[THUMBNAIL].get_file_dir();
    let enc_pathname: String = format!("{}/encrypted/{}", file_dir, encrypted_filename);
    info!("Encrypted pathname: {}", enc_pathname);

    decrypt_thumbnail_file(
        &mut clients.mls_clients[THUMBNAIL],
        &enc_pathname,
        &pending_meta_directory,
    )
}

pub fn decrypt_message(
    clients: &mut Option<Box<Clients>>,
    client_tag: &str,
    message: Vec<u8>,
) -> io::Result<String> {
    if clients.is_none() {
        return Err(io::Error::other(
            "Error: clients not initialized!".to_string(),
        ));
    }

    let mls_client_index = client_tag_to_index(client_tag);
    if mls_client_index.is_none() {
        return Err(io::Error::other("Error: No matching client!".to_string()));
    }

    let dec_msg_bytes =
        clients.as_mut().unwrap().mls_clients[mls_client_index.unwrap()].decrypt(message, true)?;
    clients.as_mut().unwrap().mls_clients[mls_client_index.unwrap()].save_group_state().unwrap();

    // New JSON structure. Ensure valid JSON string
    if let Ok(message) = str::from_utf8(&dec_msg_bytes) {
        if serde_json::from_str::<serde_json::Value>(message).is_ok() {
            return Ok(message.to_string());
        }
    }

    // For messages not in JSON. For now, this is only for decoding FCM messages. TODO: Port all FCM over to JSON
    let response = if dec_msg_bytes.len() == 8 {
        let timestamp: u64 = bincode::deserialize(&dec_msg_bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        if timestamp != 0 {
            timestamp.to_string()
        } else {
            "Download".to_string()
        }
    } else {
        return Err(io::Error::other(format!(
            "Error: invalid len in decrypted msg ({})",
            dec_msg_bytes.len()
        )));
    };

    Ok(response)
}

pub fn get_group_name(clients: &mut Option<Box<Clients>>, client_tag: &str) -> io::Result<String> {
    if clients.is_none() {
        return Err(io::Error::other(
            "Error: clients not initialized!".to_string(),
        ));
    }

    let mls_client_index = client_tag_to_index(client_tag);
    if mls_client_index.is_none() {
        return Err(io::Error::other("Error: No matching client!".to_string()));
    }

    clients.as_mut().unwrap().mls_clients[mls_client_index.unwrap()].get_group_name()
}

pub fn get_client_epoch(
    clients: &mut Option<Box<Clients>>,
    client_tag: &str,
) -> io::Result<u64> {
    if clients.is_none() {
        return Err(io::Error::other(
            "Error: clients not initialized!".to_string(),
        ));
    }

    let mls_client_index = client_tag_to_index(client_tag);
    if mls_client_index.is_none() {
        return Err(io::Error::other("Error: No matching client!".to_string()));
    }

    clients.as_mut().unwrap().mls_clients[mls_client_index.unwrap()].get_epoch()
}

fn client_tag_to_index(tag: &str) -> Option<usize> {
    match tag {
        "motion" => Some(MOTION),
        "livestream" => Some(LIVESTREAM),
        "fcm" => Some(FCM),
        "config" => Some(CONFIG),
        "thumbnail" => Some(THUMBNAIL),
        _ => None,
    }
}

pub fn livestream_decrypt(
    clients: &mut Option<Box<Clients>>,
    enc_data: Vec<u8>,
    expected_chunk_number: u64,
) -> io::Result<Vec<u8>> {
    if clients.is_none() {
        return Err(io::Error::other(
            "Error: clients not initialized!".to_string(),
        ));
    }

    let dec_data = clients.as_mut().unwrap().mls_clients[LIVESTREAM].decrypt(enc_data, true)?;
    clients.as_mut().unwrap().mls_clients[LIVESTREAM].save_group_state().unwrap();

    // check the chunk number
    if dec_data.len() < 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Error: too few bytes!".to_string(),
        ));
    }

    let chunk_number = u64::from_be_bytes(dec_data[..8].try_into().unwrap());
    if chunk_number != expected_chunk_number {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Error: invalid chunk number!".to_string(),
        ));
    }

    Ok(dec_data[8..].to_vec())
}

pub fn livestream_update(
    clients: &mut Option<Box<Clients>>,
    updates_msg: Vec<u8>,
) -> io::Result<()> {
    if clients.is_none() {
        return Err(io::Error::other(
            "Error: clients not initialized!".to_string(),
        ));
    }

    let update_commit_msgs: Vec<Vec<u8>> = bincode::deserialize(&updates_msg).map_err(|e| {
        io::Error::other(format!(
            "Error: deserialization of updates_msg failed! - {e}"
        ))
    })?;

    for commit_msg in update_commit_msgs {
        let _ = clients.as_mut().unwrap().mls_clients[LIVESTREAM].decrypt(commit_msg, false)?;
    }

    clients.as_mut().unwrap().mls_clients[LIVESTREAM].save_group_state().unwrap();

    Ok(())
}

pub fn deregister(clients: &mut Option<Box<Clients>>) {
    if clients.is_none() {
        info!("Error: clients not initialized!");
        return;
    }

    let mls_clients = &mut clients.as_mut().unwrap().mls_clients;

    for i in 0..NUM_MLS_CLIENTS {
        let file_dir = mls_clients[i].get_file_dir();

        if let Err(e) = mls_clients[i].clean() {
            info!("Error: Cleaning client_{} failed: {e}", MLS_CLIENT_TAGS[i]);
        }

        let _ = fs::remove_file(format!("{}/app_{}_name", file_dir, MLS_CLIENT_TAGS[i]));
    }

    *clients = None;
}

pub fn generate_heartbeat_request_config_command(
    clients: &mut Option<Box<Clients>>,
    timestamp: u64,
) -> io::Result<Vec<u8>> {
    if clients.is_none() {
        return Err(io::Error::other(
            "Error: clients not initialized!".to_string(),
        ));
    }

    let heartbeat_request =
        HeartbeatRequest::generate(&mut clients.as_mut().unwrap().mls_clients, timestamp)?;

    let mut config_msg = vec![OPCODE_HEARTBEAT_REQUEST];
    config_msg.extend(bincode::serialize(&heartbeat_request).unwrap());

    let config_msg_enc = clients.as_mut().unwrap().mls_clients[CONFIG].encrypt(&config_msg)?;

    clients.as_mut().unwrap().mls_clients[CONFIG].save_group_state().unwrap();

    Ok(config_msg_enc)
}

pub fn process_heartbeat_config_response(
    clients: &mut Option<Box<Clients>>,
    config_response: Vec<u8>,
    expected_timestamp: u64,
) -> io::Result<String> {
    if clients.is_none() {
        return Err(io::Error::other(
            "Error: clients not initialized!".to_string(),
        ));
    }

    match clients.as_mut().unwrap().mls_clients[CONFIG].decrypt(config_response, true) {
        Ok(command) => {
            clients.as_mut().unwrap().mls_clients[CONFIG].save_group_state().unwrap();
            match command[0] {
                OPCODE_HEARTBEAT_RESPONSE => {
                    let heartbeat: Heartbeat =
                        bincode::deserialize(&command[1..]).map_err(|e| {
                            io::Error::other(format!("Failed to deserialize heartbeat msg - {e}"))
                        })?;

                    let heartbeat_result = heartbeat.process(
                        &mut clients.as_mut().unwrap().mls_clients,
                        expected_timestamp,
                    )?;

                    match heartbeat_result {
                        HeartbeatResult::HealthyHeartbeat(_timestamp) => {
                            Ok(format!("healthy_{}", heartbeat.firmware_version))
                        }
                        HeartbeatResult::InvalidTimestamp => Ok("invalid timestamp".to_string()),
                        HeartbeatResult::InvalidCiphertext => Ok("invalid ciphertext".to_string()),
                        HeartbeatResult::InvalidEpoch => Ok("invalid epoch".to_string()),
                    }
                }
                _ => {
                    error!("Error: Unexpected config command response opcode! - {}", command[0]);
                    Err(io::Error::other(
                        "Error: Unexpected config response opcode!".to_string(),
                    ))
                }
            }
        }
        Err(e) => {
            error!("Failed to decrypt command message: {e}");
            clients.as_mut().unwrap().mls_clients[CONFIG].save_group_state().unwrap();
            Err(io::Error::other(format!(
                "Failed to decrypt command message: {e}"
            )))
        }
    }
}

pub fn get_key_packages(clients: &mut Option<Box<Clients>>) -> io::Result<Vec<u8>> {
    if clients.is_none() {
        return Err(io::Error::other(
            "Error: clients not initialized!".to_string(),
        ));
    }

    let key_packages: [KeyPackage; NUM_MLS_CLIENTS] =
        std::array::from_fn(|i| clients.as_mut().unwrap().mls_clients[i].key_package());

    let key_packages_vec = bincode::serialize(&key_packages).unwrap(); 

    Ok(key_packages_vec)
}

pub fn generate_add_app_request_config_command(
    clients: &mut Option<Box<Clients>>,
    new_app_key_packages_vec: Vec<u8>,
    secret: Vec<u8>,
) -> io::Result<Vec<u8>> {
    if clients.is_none() {
        return Err(io::Error::other(
            "Error: clients not initialized!".to_string(),
        ));
    }

    let new_app_key_packages: [KeyPackage; NUM_MLS_CLIENTS] =
        bincode::deserialize(&new_app_key_packages_vec).unwrap();

    let add_app_requests: [AddAppRequest; NUM_MLS_CLIENTS] = std::array::from_fn(|i| AddAppRequest {
        secret: secret.clone(),
        new_app_key_package: new_app_key_packages[i].clone(),
    });

    let mut config_msg = vec![OPCODE_ADD_APP_REQUEST];
    config_msg.extend(bincode::serialize(&add_app_requests).unwrap());

    let config_msg_enc = clients.as_mut().unwrap().mls_clients[CONFIG].encrypt(&config_msg)?;

    clients.as_mut().unwrap().mls_clients[CONFIG].save_group_state().unwrap();

    Ok(config_msg_enc)
}

#[derive(Serialize, Deserialize)]
struct NewAppData {
    pub camera_key_package: KeyPackage,
    pub welcome_msg_vec: Vec<u8>,
    pub group_name: String,
}

pub fn process_add_app_config_response(
    clients: &mut Option<Box<Clients>>,
    config_response: Vec<u8>,
    secret: Vec<u8>,
) -> io::Result<Vec<u8>> {
    if clients.is_none() {
        return Err(io::Error::other(
            "Error: clients not initialized!".to_string(),
        ));
    }

    match clients.as_mut().unwrap().mls_clients[CONFIG].decrypt(config_response, true) {
        Ok(command) => {
            clients.as_mut().unwrap().mls_clients[CONFIG].save_group_state().unwrap();
            match command[0] {
                OPCODE_ADD_APP_RESPONSE => {
                    let (add_app_resps_com, add_app_resps_ded):
                        ([AddAppResponseCommon; NUM_COMMON_MLS_CLIENTS], [AddAppResponseDedicated; NUM_DEDICATED_MLS_CLIENTS]) =
                        bincode::deserialize(&command[1..]).map_err(|e| {
                            io::Error::other(format!("Failed to deserialize add_app msg - {e}"))
                        })?;

                    let new_app_data: [NewAppData; NUM_MLS_CLIENTS] = std::array::from_fn(|i| {
                        if i < NUM_COMMON_MLS_CLIENTS {
                            // Merge the psk_proposal and commit for the add operation
                            clients.as_mut().unwrap().mls_clients[i].decrypt(add_app_resps_com[i].psk_proposal_vec.clone(), false).unwrap();
                            clients.as_mut().unwrap().mls_clients[i].decrypt_with_secret(add_app_resps_com[i].commit_msg_vec.clone(), false, secret.clone()).unwrap();
                            clients.as_mut().unwrap().mls_clients[i].save_group_state().unwrap();

                            // Prepare data for the new app
                            NewAppData {
                                camera_key_package: add_app_resps_com[i].camera_key_package.clone(),
                                welcome_msg_vec: add_app_resps_com[i].welcome_msg_vec.clone(),
                                group_name: clients.as_mut().unwrap().mls_clients[i].get_group_name().unwrap(),
                            }
                        } else {
                            NewAppData {
                                camera_key_package: add_app_resps_ded[i - NUM_COMMON_MLS_CLIENTS].camera_key_package.clone(),
                                welcome_msg_vec: add_app_resps_ded[i - NUM_COMMON_MLS_CLIENTS].welcome_msg_vec.clone(),
                                group_name: add_app_resps_ded[i - NUM_COMMON_MLS_CLIENTS].group_name.clone(),
                            }
                        }
                    });

                    let new_app_data_vec = bincode::serialize(&new_app_data).unwrap();

                    return Ok(new_app_data_vec)
                }
                _ => {
                    error!("Error: Unexpected config command response opcode! - {}", command[0]);
                    Err(io::Error::other(
                        "Error: Unexpected config response opcode!".to_string(),
                    ))
                }
            }
        }
        Err(e) => {
            error!("Failed to decrypt command message: {e}");
            Err(io::Error::other(format!(
                "Failed to decrypt command message: {e}"
            )))
        }
    }
}

pub fn join_camera_groups(
    clients: &mut Option<Box<Clients>>,
    secret: Vec<u8>,
    new_app_data_vec: Vec<u8>,
) -> io::Result<[u64; NUM_MLS_CLIENTS]> {
    let new_app_data: [NewAppData; NUM_MLS_CLIENTS] =
        bincode::deserialize(&new_app_data_vec).unwrap();

    let epochs: [u64; NUM_MLS_CLIENTS] = std::array::from_fn(|i| {
        let app_contact =
            MlsClient::create_contact("camera", new_app_data[i].camera_key_package.clone()).unwrap();

        clients.as_mut().unwrap().mls_clients[i].process_welcome_with_secret(app_contact, new_app_data[i].welcome_msg_vec.clone(), secret.clone(), &new_app_data[i].group_name).unwrap();
        clients.as_mut().unwrap().mls_clients[i].save_group_state().unwrap();

        clients.as_mut().unwrap().mls_clients[i].get_epoch().unwrap()
    });

    // FIXME: return the firmware version too.
    // FIXME: return a String, similar to add_camera
    Ok(epochs)
}
