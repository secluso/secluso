//! Camera hub pairing
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

use crate::initialize_mls_clients;
use crate::traits::Camera;
use cfg_if::cfg_if;
use image::Luma;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::random::OpenMlsRand;
use openmls_traits::OpenMlsProvider;
use qrcode::QrCode;
use rand::Rng;
use secluso_client_lib::http_client::HttpClient;
use secluso_client_lib::mls_client::{KeyPackages, MlsClient};
use secluso_client_lib::mls_clients::{MlsClients, CONFIG};
use secluso_client_lib::pairing;
use secluso_client_server_lib::auth::parse_user_credentials_full;
use serde_json::Value;
use std::fs::File;
use std::io;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::fs;
use std::{thread, time::Duration};

// Used to generate random names.
// With 16 alphanumeric characters, the probability of collision is very low.
// Note: even if collision happens, it has no impact on
// our security guarantees. Will only cause availability issues.
const NUM_RANDOM_CHARS: u8 = 16;

// Used to ensure there can't be attempted concurrent pairing
static LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn write_varying_len(stream: &mut TcpStream, msg: &[u8]) -> io::Result<()> {
    // FIXME: is u64 necessary?
    let len = msg.len() as u64;
    let len_data = len.to_be_bytes();

    stream.write_all(&len_data)?;
    stream.write_all(msg)?;
    stream.flush()?;

    Ok(())
}

use std::io::ErrorKind;

fn read_varying_len(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut len_data = [0u8; 8];

    match stream.read_exact(&mut len_data) {
        Ok(_) => {}
        Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
            return Err(io::Error::new(
                ErrorKind::WouldBlock,
                "Length read would block",
            ));
        }
        Err(e) => return Err(e),
    }

    let len = u64::from_be_bytes(len_data);
    let mut msg = vec![0u8; len as usize];
    let mut offset = 0;

    while offset < msg.len() {
        match stream.read(&mut msg[offset..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "Socket closed during read",
                ))
            }
            Ok(n) => {
                offset += n;
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                // retry a few times with a short delay
                thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(e) => return Err(e),
        }
    }

    Ok(msg)
}

#[cfg(feature = "raspberry")]
fn receive_timestamp_set_system_time(stream: &mut TcpStream) -> io::Result<()> {
    let timestamp_vec = read_varying_len(stream)?;
    let timestamp: u64 = bincode::deserialize(&timestamp_vec).unwrap();
    let _ = Command::new("date")
        .arg("-s")
        .arg(format!("@{}", timestamp))
        .output()?;

    Ok(())
}

fn perform_pairing_handshake(
    stream: &mut TcpStream,
    camera_key_packages: KeyPackages,
) -> anyhow::Result<KeyPackages> {
    let pairing = pairing::Camera::new(camera_key_packages);

    let app_msg = read_varying_len(stream)?;
    let (app_key_packages, camera_msg) =
        pairing.process_app_msg_and_generate_msg_to_app(app_msg)?;
    write_varying_len(stream, &camera_msg)?;

    Ok(app_key_packages)
}

fn generate_camera_secret(camera: &dyn Camera) -> Vec<u8> {
    let crypto = OpenMlsRustCrypto::default();
    let secret = crypto
        .crypto()
        .random_vec(pairing::NUM_SECRET_BYTES)
        .unwrap();

    // Save as QR code to be shown to the app
    let code = QrCode::new(secret.clone()).unwrap();
    let image = code.render::<Luma<u8>>().build();
    image
        .save(format!(
            "camera_{}_secret_qrcode.png",
            camera.get_name().replace(" ", "_").to_lowercase()
        ))
        .unwrap();

    secret
}

pub fn get_input_camera_secret() -> Vec<u8> {
    let pathname = "./camera_secret";
    let file = File::open(pathname).expect(
        "Could not open file \"camera_secret\". You can generate this with the config_tool",
    );
    let mut reader =
        BufReader::with_capacity(file.metadata().unwrap().len().try_into().unwrap(), file);
    let data = reader.fill_buf().unwrap();

    data.to_vec()
}

fn pair_with_app(
    stream: &mut TcpStream,
    camera_key_packages: KeyPackages,
) -> anyhow::Result<KeyPackages> {
    perform_pairing_handshake(stream, camera_key_packages)
}

fn invite(
    stream: &mut TcpStream,
    mls_client: &mut MlsClient,
    app_key_packages: KeyPackages,
    camera_secret: Vec<u8>,
) -> io::Result<()> {
    let app_contact = MlsClient::create_contact("app", app_key_packages)?;
    debug!("Added contact.");

    let welcome_msg_vec = mls_client
        .invite(&app_contact, camera_secret)
        .inspect_err(|_| {
            error!("invite() returned error:");
        })?;
    mls_client.save_group_state();
    debug!("App invited to the group.");

    write_varying_len(stream, &welcome_msg_vec)?;

    // Next, send the shared group name
    let group_name = mls_client.get_group_name()?;
    write_varying_len(stream, group_name.as_bytes())?;

    Ok(())
}

fn decrypt_msg(mls_client: &mut MlsClient, msg: Vec<u8>) -> io::Result<Vec<u8>> {
    let decrypted_msg = mls_client.decrypt(msg, true)?;
    mls_client.save_group_state();

    Ok(decrypted_msg)
}

fn receive_credentials_full(stream: &mut TcpStream, mls_client: &mut MlsClient) -> io::Result<()> {
    let encrypted_msg = read_varying_len(stream)?;
    let credentials_full_bytes = decrypt_msg(mls_client, encrypted_msg)?;

    // Write to file
    let mut file = fs::File::create("credentials_full").expect("Could not create file");
    file.write_all(&credentials_full_bytes).unwrap();
    file.flush().unwrap();
    file.sync_all().unwrap();

    Ok(())
}

fn send_firmware_version(stream: &mut TcpStream, mls_client: &mut MlsClient) -> io::Result<()> {
    let msg = format!("v{}", env!("CARGO_PKG_VERSION"));
    let encrypted_msg = mls_client.encrypt(msg.as_bytes())?;
    mls_client.save_group_state();

    write_varying_len(stream, &encrypted_msg)?;

    Ok(())
}

fn request_wifi_info(
    stream: &mut TcpStream,
    mls_client: &mut MlsClient,
) -> io::Result<(String, String, String)> {
    // Combine into one message to reduce risk of non-blocking errors
    let wifi_msg = read_varying_len(stream)?;
    let wifi_bytes = decrypt_msg(mls_client, wifi_msg)?;

    let payload_msg = String::from_utf8(wifi_bytes).expect("Invalid UTF-8 for WiFi message");
    debug!("Recieved Wifi Payload: {payload_msg}");
    let json: Value = serde_json::from_str(&payload_msg)?;

    Ok((
        json["ssid"]
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Missing or invalid ssid"))?
            .to_string(),
        json["passphrase"]
            .as_str()
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "Missing or invalid passphrase")
            })?
            .to_string(),
        json["pairing_token"]
            .as_str()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Missing or invalid pairing token",
                )
            })?
            .to_string(),
    ))
}

fn attempt_wifi_connection(ssid: String, password: String) -> io::Result<()> {
    debug!("[Pairing] Attempting wifi connection");

    // Disable hotspot
    let _ = Command::new("sh")
        .arg("-c")
        .arg("nmcli connection down id Hotspot")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output()?; // wait for shutdown

    thread::sleep(Duration::from_secs(3));

    for n in 1..=3 {
        println!("[Pairing] Attempt {n} to connect to Wi-Fi");

        // Rescan and wait for SSID to appear
        let _ = Command::new("nmcli")
            .arg("dev")
            .arg("wifi")
            .arg("rescan")
            .output();

        thread::sleep(Duration::from_secs(2));

        let check_output = Command::new("sh")
            .arg("-c")
            .arg(format!("nmcli -t -f SSID dev wifi | grep -Fx \"{}\"", ssid))
            .output()?;

        if !check_output.status.success() {
            debug!("[Pairing] SSID '{}' not found in scan", ssid);
            if n == 3 {
                bring_hotspot_back_up()?;
                return Err(io::Error::new(io::ErrorKind::NotFound, "SSID not found"));
            }
            continue;
        }

        // Delete previous connection if it exists
        let _ = Command::new("sh")
            .arg("-c")
            .arg(format!("nmcli connection delete id \"{}\"", ssid))
            .output(); // ignore error if it doesn't exist

        // Try connecting
        let connect_output = Command::new("sh")
            .arg("-c")
            .arg(format!(
                "nmcli dev wifi connect \"{}\" password \"{}\"",
                ssid, password
            ))
            .output()?;

        if connect_output.status.success() {
            debug!("[Pairing] Connected successfully on attempt {n}");

            // Autoconnect on reboot
            let _ = Command::new("sh")
                .arg("-c")
                .arg(format!(
                    "nmcli connection modify \"{}\" connection.autoconnect yes",
                    ssid
                ))
                .output();
            return Ok(());
        }

        debug!(
            "[Pairing] Connection failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&connect_output.stdout),
            String::from_utf8_lossy(&connect_output.stderr),
        );

        thread::sleep(Duration::from_secs(3));
    }

    bring_hotspot_back_up()?;

    Err(io::Error::other(format!(
        "Failed to connect to Wi-Fi '{}'",
        ssid
    )))
}

fn bring_hotspot_back_up() -> io::Result<()> {
    debug!("[Pairing] Bringing hotspot back up...");
    Command::new("sh")
        .arg("-c")
        .arg("nmcli connection up id Hotspot")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output()?;
    Ok(())
}

pub fn create_wifi_hotspot() {
    let _ = Command::new("sh")
        .arg("-c")
        .arg("nmcli device wifi hotspot ssid Secluso password \"12345678\"")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
        .wait();
}

#[allow(clippy::too_many_arguments)]
pub fn pair_all(
    camera: &dyn Camera,
    mls_clients: &mut MlsClients,
    input_camera_secret: Option<Vec<u8>>,
    connect_to_wifi: bool,
) -> io::Result<()> {
    // Ensure that two cameras don't attempt to pair at the same time (as this would introduce an error when opening two of the same port simultaneously)
    let _lock = LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();

    let secret = if let Some(s) = input_camera_secret.clone() {
        s
    } else {
        generate_camera_secret(camera)
    };

    if input_camera_secret.is_none() {
        println!("[{}] File camera_{}_secret_qrcode.png was just created. Use the QR code in the app to pair.", camera.get_name(), camera.get_name().replace(" ", "_").to_lowercase());
    } else {
        println!("Use the camera QR code in the app to pair.");
    }

    // Loop and continuously try to pair with the app (in case of failures)
    let listener = TcpListener::bind("0.0.0.0:12348").unwrap();
    for incoming in listener.incoming() {
        match incoming {
            Ok(mut stream) => {
                debug!("[Pairing] Incoming connection accepted.");

                if let Err(e) = stream.set_nonblocking(false) {
                    debug!("[Pairing] Failed to set blocking mode: {e}");
                }

                if let Err(e) = stream.set_read_timeout(Some(Duration::from_secs(10))) {
                    debug!("[Pairing] Failed to set read timeout: {e}");
                }

                if let Err(e) = stream.set_write_timeout(Some(Duration::from_secs(10))) {
                    debug!("[Pairing] Failed to set write timeout: {e}");
                }

                let result = {
                    let mut success = true;

                    cfg_if! {
                        if #[cfg(feature = "raspberry")] {
                            // Receive timestamp and set system date and time.
                            // This is because an RPi doesn't have a battery-backed real-time clock.
                            // Therefore, if it remains off before pairing, its wall clock will be off.
                            // This then prevents successful pairing due to MLS checking the lifetime
                            // of key packages.
                            match receive_timestamp_set_system_time(&mut stream) {
                                Ok(()) => {}
                                Err(e) => {
                                    debug!("[Pairing] Failed to receive and set timestamp: {e}");
                                    success = false;
                                }
                            }

                            // Re-create mls_client objects in order to get fresh key packages
                            *mls_clients = initialize_mls_clients(camera, true);
                        }
                    }

                    let mls_clients_ref = &mut *mls_clients;

                    if success {
                        debug!("[Pairing] Before pairing");
                        for mls_client in mls_clients_ref.iter_mut() {
                            match pair_with_app(&mut stream, mls_client.key_packages()) {
                                Ok(app_key_packages) => {
                                    if let Err(e) = invite(
                                        &mut stream,
                                        mls_client,
                                        app_key_packages,
                                        secret.clone(),
                                    ) {
                                        debug!("[Pairing] Failed to create group: {e}");
                                        success = false;
                                        break;
                                    }
                                }
                                Err(e) => {
                                    debug!("[Pairing] Pairing failed: {e}");
                                    success = false;
                                    break;
                                }
                            }
                        }
                    }

                    if success {
                        match receive_credentials_full(&mut stream, &mut mls_clients[CONFIG]) {
                            Ok(()) => {}
                            Err(e) => {
                                debug!("[Pairing] Failed to receive credentials_full: {e}");
                                success = false;
                            }
                        }
                    }

                    let http_client = if success {
                        let (server_username, server_password, server_addr) =
                            read_parse_full_credentials();
                        Some(HttpClient::new(
                            server_addr,
                            server_username,
                            server_password,
                        ))
                    } else {
                        success = false;
                        None
                    };

                    if success {
                        match send_firmware_version(&mut stream, &mut mls_clients[CONFIG]) {
                            Ok(()) => {}
                            Err(e) => {
                                debug!("[Pairing] Failed to send firmware_version: {e}");
                                success = false;
                            }
                        }
                    }

                    let mut changed_wifi = false;

                    if connect_to_wifi && success {
                        debug!("[Pairing] Before request wifi info");
                        match request_wifi_info(&mut stream, &mut mls_clients[CONFIG]) {
                            Ok((ssid, password, pairing_token)) => {
                                if connect_to_wifi {
                                    match attempt_wifi_connection(ssid, password) {
                                        Ok(_) => {
                                            changed_wifi = true;
                                            debug!("[Pairing] Attempting to confirm pairing...");
                                            match http_client
                                                .unwrap()
                                                .send_pairing_token(&pairing_token)
                                            {
                                                Ok(status) => {
                                                    debug!("[Pairing] Pairing token acknowledged with status: {status}");
                                                    match status.as_str() {
                                                        "paired" => {
                                                            debug!("[Pairing] Success: both sides connected.");
                                                        }
                                                        "expired" => {
                                                            debug!("[Pairing] Error: pairing token expired.");
                                                            success = false;
                                                        }
                                                        "invalid_token" | "invalid_role" => {
                                                            debug!("[Pairing] Error: invalid input ({status})");
                                                            success = false;
                                                        }
                                                        _ => {
                                                            debug!("[Pairing] Unexpected status: {status}");
                                                            success = false;
                                                        }
                                                    }
                                                }
                                                Err(e) => {
                                                    error!("[Pairing] Failed to send pairing token: {e}");
                                                    success = false;
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            debug!(
                                                "[Pairing] Error connecting to user provided WiFi: {}",
                                                e
                                            );
                                            success = false;
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                debug!("[Pairing] Failed to retrieve user WiFi information: {}", e);
                                success = false;
                            }
                        }
                    }

                    if changed_wifi && !success {
                        debug!("[Pairing] Creating WiFi hotspot after fail");
                        create_wifi_hotspot();
                    }

                    success
                };

                if result {
                    break;
                } else {
                    // Get rid of any potential failed pairs beforehand.
                    for mls_client in mls_clients.iter_mut() {
                        mls_client.clean().unwrap();
                    }

                    // We cannot use the old user objects, so create new clients.
                    *mls_clients = initialize_mls_clients(camera, true);

                    debug!("[Pairing] Error — resetting for next connection");
                    continue;
                }
            }

            Err(e) => {
                debug!("[Pairing] Incoming connection error: {e}");
                continue;
            }
        }
    }

    if input_camera_secret.is_none() {
        let _ = fs::remove_file(format!(
            "camera_{}_secret_qrcode.png",
            camera.get_name().replace(" ", "_").to_lowercase()
        ));
    }

    Ok(())
}

pub fn get_names(
    camera: &dyn Camera,
    first_time: bool,
    camera_filename: String,
    group_filename: String,
) -> (String, String) {
    let state_dir = camera.get_state_dir();
    let state_dir_path = Path::new(&state_dir);
    let camera_path = state_dir_path.join(camera_filename);
    let group_path = state_dir_path.join(group_filename);

    let (camera_name, group_name) = if first_time {
        let mut rng = rand::thread_rng();
        let cname: String = (0..NUM_RANDOM_CHARS)
            .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
            .collect();

        let mut file = File::create(camera_path).expect("Could not create file");
        file.write_all(cname.as_bytes()).unwrap();
        file.flush().unwrap();
        file.sync_all().unwrap();

        let gname: String = (0..NUM_RANDOM_CHARS)
            .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
            .collect();

        file = File::create(group_path).expect("Could not create file");
        file.write_all(gname.as_bytes()).unwrap();
        file.flush().unwrap();
        file.sync_all().unwrap();

        (cname, gname)
    } else {
        let file = File::open(camera_path).expect("Cannot open file to send");
        let mut reader =
            BufReader::with_capacity(file.metadata().unwrap().len().try_into().unwrap(), file);
        let cname = reader.fill_buf().unwrap();

        let file = File::open(group_path).expect("Cannot open file to send");
        let mut reader =
            BufReader::with_capacity(file.metadata().unwrap().len().try_into().unwrap(), file);
        let gname = reader.fill_buf().unwrap();

        (
            String::from_utf8(cname.to_vec()).unwrap(),
            String::from_utf8(gname.to_vec()).unwrap(),
        )
    };

    (camera_name, group_name)
}

/// Returns username, password, and server addr
pub fn read_parse_full_credentials() -> (String, String, String) {
    let file = fs::File::open("credentials_full").expect("Could not open user_credentials file");
    let mut reader =
        BufReader::with_capacity(file.metadata().unwrap().len().try_into().unwrap(), file);
    let data = reader.fill_buf().unwrap();

    let credentials_full_bytes = data.to_vec();

    let (server_username, server_password, server_addr) =
        parse_user_credentials_full(credentials_full_bytes).unwrap();

    (server_username, server_password, server_addr)
}
