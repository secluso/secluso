use anyhow::anyhow;
use anyhow::Context;
use log::{debug, error, info};
use rand::Rng;
use secluso_client_lib::config::{
    Heartbeat, HeartbeatRequest, HeartbeatResult, OPCODE_HEARTBEAT_REQUEST,
    OPCODE_HEARTBEAT_RESPONSE,
};
use secluso_client_lib::mls_client::{Contact, KeyPackages, MlsClient};
use secluso_client_lib::mls_clients::MlsClients;
use secluso_client_lib::mls_clients::{
    CONFIG, FCM, LIVESTREAM, MLS_CLIENT_TAGS, MOTION, NUM_MLS_CLIENTS, THUMBNAIL,
};
use secluso_client_lib::pairing;
use secluso_client_lib::thumbnail_meta_info::{ThumbnailMetaInfo, THUMBNAIL_SANITY};
use secluso_client_lib::video_net_info::{VideoNetInfo, VIDEONETINFO_SANITY};
use serde_json::json;
use std::array;
use std::fs;
use std::fs::File;
use std::io;
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::net::SocketAddr;
use std::net::TcpStream;
use std::path::Path;
use std::str;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

// Used to generate random names.
// With 16 alphanumeric characters, the probability of collision is very low.
// Note: even if collision happens, it has no impact on
// our security guarantees. Will only cause availability issues.
const NUM_RANDOM_CHARS: u8 = 16;

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
            )
            .expect("MlsClient::new() for returned error.");

            // Make sure the groups_state files are created in case we initialize again soon.
            mls_client.save_group_state();

            mls_client
        });

        Ok(Self { mls_clients })
    }
}

fn get_app_name(first_time: bool, file_dir: String, filename: String) -> String {
    let app_name = if first_time {
        let mut rng = rand::thread_rng();
        let aname: String = (0..NUM_RANDOM_CHARS)
            .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
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

    let mut msg = vec![0u8; len as usize];
    stream.read_exact(&mut msg)?;

    Ok(msg)
}

fn perform_pairing_handshake(
    stream: &mut TcpStream,
    app_key_packages: KeyPackages,
) -> anyhow::Result<KeyPackages> {
    let pairing = pairing::App::new(app_key_packages);
    let app_msg = pairing.generate_msg_to_camera();
    write_varying_len(stream, &app_msg)?;
    let camera_msg = read_varying_len(stream)?;
    let camera_key_packages = pairing.process_camera_msg(camera_msg)?;

    Ok(camera_key_packages)
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

    mls_client.save_group_state();

    Ok(())
}

fn send_credentials_full(
    stream: &mut TcpStream,
    mls_client: &mut MlsClient,
    credentials_full: String,
) -> io::Result<()> {
    info!("Sending credentials_full");
    let msg = credentials_full.into_bytes();
    let encrypted_msg = match mls_client.encrypt(&msg) {
        Ok(msg) => msg,
        Err(e) => {
            info!("Failed to encrypt credentials_full: {e}");
            return Err(e);
        }
    };

    write_varying_len(stream, &encrypted_msg)?;

    mls_client.save_group_state();

    Ok(())
}

fn receive_firmware_version(
    stream: &mut TcpStream,
    mls_client: &mut MlsClient,
) -> anyhow::Result<String> {
    info!("Sending credentials_full");
    let encrypted_msg = read_varying_len(stream)?;

    let firmware_version_bytes = match mls_client.decrypt(encrypted_msg, true) {
        Ok(msg) => msg,
        Err(e) => {
            info!("Failed to decrypt firmware version: {e}");
            return Err(e.into());
        }
    };

    mls_client.save_group_state();

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

#[flutter_rust_bridge::frb]
fn pair_with_camera(
    stream: &mut TcpStream,
    camera_name: &str,
    mls_clients: &mut MlsClients,
    secret: Vec<u8>,
) -> anyhow::Result<()> {
    for index in 0..mls_clients.len() {
        let mut mls_client = &mut mls_clients[index];

        let app_key_packages = mls_client.key_packages();

        let camera_key_packages = perform_pairing_handshake(stream, app_key_packages)?;

        let camera_welcome_msg = read_varying_len(stream)?;
        let group_name = read_varying_len(stream)?;
        let group_name_string = str::from_utf8(&group_name)?.to_string();

        let contact = MlsClient::create_contact(camera_name, camera_key_packages)?;

        process_welcome_message(
            &mut mls_client,
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
    mls_client.process_welcome(contact, welcome_msg, secret, group_name)?;
    mls_client.save_group_state();

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
    config_mls_client.save_group_state();

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
    info!("Rust: add_camera method triggered");
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

    let mut stream = match TcpStream::connect(&addr) {
        Ok(s) => s,
        Err(e) => {
            info!("Error (connect): {e}");
            return "Error".to_string();
        }
    };

    if standalone_camera {
        // Need to send timestamp. RPi needs it for setting date/time.
        if let Err(e) = send_timestamp(
            &mut stream,
        ) {
            info!("Error (sending timestamp): {e}");
            return "Error".to_string();
        }
    }

    // Perform pairing
    if let Err(e) = pair_with_camera(
        &mut stream,
        &camera_name,
        &mut clients.as_mut().mls_clients,
        secret_vec,
    ) {
        info!("Error (pairing): {e}");
        return "Error".to_string();
    }

    // Send credentials (username, password, and IP address of the server)
    if let Err(e) = send_credentials_full(
        &mut stream,
        &mut clients.mls_clients[CONFIG],
        credentials_full,
    ) {
        info!("Error (credentials): {e}");
        return "Error".to_string();
    }

    let firmware_version =
        match receive_firmware_version(&mut stream, &mut clients.mls_clients[CONFIG]) {
            Ok(version) => version,
            Err(e) => {
                info!("Error (firmware): {e}");
                return "Error".to_string();
            }
        };

    // Send Wi-Fi info
    if standalone_camera {
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

fn read_next_msg_from_file(file: &mut File) -> io::Result<Vec<u8>> {
    let mut len_buffer = [0u8; 4];
    let len_bytes_read = file.read(&mut len_buffer)?;
    if len_bytes_read != 4 {
        return Err(io::Error::other(
            "Error: not enough bytes to read the len from file".to_string(),
        ));
    }

    let msg_len = u32::from_be_bytes(len_buffer);

    let mut buffer = vec![0; msg_len.try_into().unwrap()];
    let bytes_read = file.read(&mut buffer)?;
    if bytes_read != msg_len as usize {
        return Err(io::Error::other(
            "Error: not enough bytes to read the message from file".to_string(),
        ));
    }

    Ok(buffer)
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

    let file_dir = clients.as_mut().unwrap().mls_clients[MOTION].get_file_dir();
    info!("File dir: {}", file_dir);
    let enc_pathname: String = format!("{}/videos/{}", file_dir, encrypted_filename);

    let mut enc_file = fs::File::open(enc_pathname).expect("Could not open encrypted file");

    let enc_msg = read_next_msg_from_file(&mut enc_file)?;
    // The first message is a commit message
    clients.as_mut().unwrap().mls_clients[MOTION].decrypt(enc_msg, false)?;
    clients.as_mut().unwrap().mls_clients[MOTION].save_group_state();

    let enc_msg = read_next_msg_from_file(&mut enc_file)?;
    // The second message is the video info
    let dec_msg = clients.as_mut().unwrap().mls_clients[MOTION].decrypt(enc_msg, true)?;

    let info: VideoNetInfo = bincode::deserialize(&dec_msg)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    if info.sanity != *VIDEONETINFO_SANITY || info.num_msg == 0 {
        return Err(io::Error::other("Error: Corrupt VideoNetInfo message."));
    }

    // The rest of the messages are video data
    //Note: we're building the filename based on the timestamp in the message.
    //The encrypted filename however is not protected and hence the server could have changed it.
    //Therefore, it is possible that the names won't match.
    //This is not an issue.
    //We should use the timestamp in the decrypted filename going forward
    //and discard the encrypted filename.
    let dec_filename = format!("video_{}.mp4", info.timestamp);
    let dec_pathname: String = format!("{}/videos/{}", file_dir, dec_filename);

    if Path::new(&dec_pathname).exists() {
        return Ok("Duplicate".to_string());
    }

    let mut dec_file = fs::File::create(&dec_pathname).expect("Could not create decrypted file");

    for expected_chunk_number in 0..info.num_msg {
        let enc_msg = read_next_msg_from_file(&mut enc_file)?;
        let dec_msg = clients.as_mut().unwrap().mls_clients[MOTION].decrypt(enc_msg, true)?;

        // check the chunk number
        if dec_msg.len() < 8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Error: too few bytes!".to_string(),
            ));
        }

        let chunk_number = u64::from_be_bytes(dec_msg[..8].try_into().unwrap());
        if chunk_number != expected_chunk_number {
            let _ = fs::remove_file(&dec_pathname);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Error: invalid chunk number!".to_string(),
            ));
        }

        let _ = dec_file.write_all(&dec_msg[8..]);
    }

    // Here, we first make sure the dec_file is flushed.
    // Then, we save groups state, which persists the update.
    dec_file.flush().unwrap();
    dec_file.sync_all().unwrap();
    clients.as_mut().unwrap().mls_clients[MOTION].save_group_state();

    Ok(dec_filename)
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

    let file_dir = clients.as_mut().unwrap().mls_clients[THUMBNAIL].get_file_dir();
    info!("File dir: {}", file_dir);
    let enc_pathname: String = format!("{}/videos/{}", file_dir, encrypted_filename);

    let mut enc_file = fs::File::open(enc_pathname).expect("Could not open encrypted file");

    let enc_msg = read_next_msg_from_file(&mut enc_file)?;
    // The first message is a commit message
    clients.as_mut().unwrap().mls_clients[THUMBNAIL].decrypt(enc_msg, false)?;
    clients.as_mut().unwrap().mls_clients[MOTION].save_group_state();

    let enc_msg = read_next_msg_from_file(&mut enc_file)?;
    // The second message is the timestamp
    let dec_msg = clients.as_mut().unwrap().mls_clients[THUMBNAIL].decrypt(enc_msg, true)?;

    let thumbnail_meta_info: ThumbnailMetaInfo = bincode::deserialize(&dec_msg)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    if thumbnail_meta_info.sanity != *THUMBNAIL_SANITY {
        return Err(io::Error::other("Error: Corrupt ThumbalMetaInfo message."));
    }

    let dec_filename: String = thumbnail_meta_info.filename;
    let dec_pathname: String = format!("{}/videos/{}", file_dir, dec_filename);

    if Path::new(&dec_pathname).exists() {
        // TODO: Should this be an error?
        return Ok("Duplicate".to_string());
    }

    // Write a metadata file for the thumbnail, which will be deleted later and stored in the database via the pending processor.
    let dec_meta_file_path: String = format!(
        "{}/meta_{}.txt",
        pending_meta_directory, thumbnail_meta_info.timestamp
    );
    let meta_file = File::create(&dec_meta_file_path)?;
    let mut meta_file_writer = BufWriter::new(meta_file);

    // Write JSON data to file.
    serde_json::to_writer(&mut meta_file_writer, &thumbnail_meta_info.detections)
        .map_err(std::io::Error::other)?;

    let mut dec_file = fs::File::create(&dec_pathname).expect("Could not create decrypted file");

    let enc_msg = read_next_msg_from_file(&mut enc_file)?;
    let dec_msg = clients.as_mut().unwrap().mls_clients[THUMBNAIL].decrypt(enc_msg, true)?;

    let _ = dec_file.write_all(&dec_msg);

    // Here, we first make sure the dec_file is flushed.
    // Then, we save groups state, which persists the update.
    dec_file.flush().unwrap();
    dec_file.sync_all().unwrap();
    clients.as_mut().unwrap().mls_clients[THUMBNAIL].save_group_state();

    Ok(dec_filename)
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
    clients.as_mut().unwrap().mls_clients[mls_client_index.unwrap()].save_group_state();

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
    clients.as_mut().unwrap().mls_clients[LIVESTREAM].save_group_state();

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

    clients.as_mut().unwrap().mls_clients[LIVESTREAM].save_group_state();

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

    clients.as_mut().unwrap().mls_clients[CONFIG].save_group_state();

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
            clients.as_mut().unwrap().mls_clients[CONFIG].save_group_state();
            info!("Decrypted command: {}", command.len());
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
                    error!("Error: Unknown config command response opcode!");
                    Err(io::Error::other(
                        "Error: Unknown config response opcode!".to_string(),
                    ))
                }
            }
        }
        Err(e) => {
            error!("Failed to decrypt command message: {e}");
            clients.as_mut().unwrap().mls_clients[CONFIG].save_group_state();
            Err(io::Error::other(format!(
                "Failed to decrypt command message: {e}"
            )))
        }
    }
}
