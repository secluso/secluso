//! Camera hub pairing
//!
//! SPDX-License-Identifier: GPL-3.0-or-later

use crate::initialize_mls_clients;
use crate::notification_target::persist_notification_target;
use crate::traits::Camera;
use cfg_if::cfg_if;
use openmls::prelude::KeyPackage;
use rand::Rng;
use secluso_client_lib::http_client::HttpClient;
use secluso_client_lib::mls_client::MlsClient;
use secluso_client_lib::mls_clients::{MlsClients, CONFIG};
use secluso_client_lib::pairing::{self, generate_ip_camera_secret, MAX_ALLOWED_MSG_LEN};
use secluso_client_server_lib::auth::parse_user_credentials_full;
use serde_json::Value;
use std::fs;
use std::fs::File;
use std::io;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::process::Output;
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::{thread, time::Duration};
use url::Url;
use std::io::ErrorKind;

// Used to generate random names.
// With 16 alphanumeric characters, the probability of collision is very low.
// Note: even if collision happens, it has no impact on
// our security guarantees. Will only cause availability issues.
const NUM_RANDOM_CHARS: u8 = 16;

// Used to ensure there can't be attempted concurrent pairing
static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
const HOTSPOT_CONNECTION_NAME: &str = "Hotspot";

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

    if len > MAX_ALLOWED_MSG_LEN {
        error!("Communicated message length ({len}) exceeds the allowed length ({MAX_ALLOWED_MSG_LEN})");
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "Intended message length is too large",
        ))
    }

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
    camera_key_package: KeyPackage,
) -> anyhow::Result<KeyPackage> {
    let pairing = pairing::Camera::new(camera_key_package);

    let app_msg = read_varying_len(stream)?;
    let (app_key_package, camera_msg) = pairing.process_app_msg_and_generate_msg_to_app(app_msg)?;
    write_varying_len(stream, &camera_msg)?;

    Ok(app_key_package)
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

// Read the WiFi password contents from file to use for the hotspot
pub fn get_input_wifi_password() -> String {
    let pathname = "./wifi_password";
    let contents = fs::read_to_string(pathname).expect("Failed to read from \"wifi_password\" file. You can generate this in config tool");
    return contents;
}

fn invite(
    stream: &mut TcpStream,
    mls_client: &mut MlsClient,
    app_key_package: KeyPackage,
    camera_secret: Vec<u8>,
) -> io::Result<()> {
    let app_contact = MlsClient::create_contact("app", app_key_package)?;
    debug!("Added contact.");

    let (welcome_msg_vec, _, _) = mls_client
        .invite_with_secret(&app_contact, camera_secret)
        .inspect_err(|_| {
            error!("invite() returned error:");
        })?;
    mls_client.save_group_state().unwrap();
    debug!("App invited to the group.");

    write_varying_len(stream, &welcome_msg_vec)?;

    // Next, send the shared group name
    let group_name = mls_client.get_group_name()?;
    write_varying_len(stream, group_name.as_bytes())?;

    Ok(())
}

fn decrypt_msg(mls_client: &mut MlsClient, msg: Vec<u8>) -> io::Result<Vec<u8>> {
    let decrypted_msg = mls_client.decrypt(msg, true)?;
    mls_client.save_group_state().unwrap();

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

fn send_firmware_version(stream: &mut TcpStream) -> io::Result<()> {
    let msg = format!("v{}", env!("CARGO_PKG_VERSION"));
    write_varying_len(stream, &msg.as_bytes())?;

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

fn nmcli_output(args: &[&str]) -> io::Result<Output> {
    // Wrapper to keep all the NetworkManager calls looking the same. Nudges us to explicit argv usage.
    Command::new("nmcli").args(args).output()
}

fn nmcli_stdout(args: &[&str]) -> io::Result<String> {
    // We mostly care about the plain stdout answer
    let output = nmcli_output(args)?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn ensure_command_success(output: Output, context: &str) -> io::Result<Output> {
    // NetworkManager failures here change pairing state, so do not silently ignore them.
    if output.status.success() {
        return Ok(output);
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Err(io::Error::other(format!("{context}: {stderr}")))
}

fn active_connections() -> io::Result<Vec<(String, String, String)>> {
    // Read the active profile list once so readiness checks reason about the same NM view.
    let output = nmcli_stdout(&["-t", "-f", "NAME,TYPE,DEVICE", "connection", "show", "--active"])?;
    let mut active = Vec::new();
    for line in output.lines() {
        let mut parts = line.splitn(3, ':');
        let name = parts.next().unwrap_or_default().trim();
        let kind = parts.next().unwrap_or_default().trim();
        let device = parts.next().unwrap_or_default().trim();
        if !name.is_empty() && name != "lo" {
            active.push((name.to_string(), kind.to_string(), device.to_string()));
        }
    }

    Ok(active)
}

fn active_connection_device(name: &str) -> io::Result<Option<String>> {
    // Tie later route/IP checks to the device that actually owns the requested profile.
    Ok(active_connections()?
        .into_iter()
        .find_map(|(active_name, _kind, device)| {
            if active_name == name && !device.is_empty() && device != "--" {
                Some(device)
            } else {
                None
            }
        }))
}

fn wifi_connection_mode(name: &str) -> io::Result<Option<String>> {
    // AP-mode profiles are the ones that keep the camera discoverable hotspot alive.
    let output = nmcli_stdout(&["-g", "802-11-wireless.mode", "connection", "show", name])?;
    let mode = output.trim();
    if mode.is_empty() {
        return Ok(None);
    }

    Ok(Some(mode.to_string()))
}

fn active_hotspot_connection_names() -> io::Result<Vec<String>> {
    // Detect active hotspot profiles generically instead of relying on one fixed connection name.
    let mut names = Vec::new();
    for (name, kind, _device) in active_connections()? {
        if kind != "wifi" {
            continue;
        }

        if wifi_connection_mode(&name)?.as_deref() == Some("ap") {
            names.push(name);
        }
    }

    Ok(names)
}

fn ssid_visible(ssid: &str) -> io::Result<bool> {
    // Answers if the radio see the target SSID yet
    let output = nmcli_stdout(&["-t", "-f", "SSID", "device", "wifi"])?;
    Ok(output.lines().any(|line| line == ssid))
}

fn active_connection_names() -> io::Result<Vec<String>> {
    // The readiness path only cares whether the target profile is active at all.
    Ok(active_connections()?
        .into_iter()
        .map(|(name, _kind, _device)| name)
        .collect())
}

fn wifi_has_ipv4(device: &str) -> io::Result<bool> {
    // -g asks nmcli for just the raw value. If this comes back empty, DHCP probably has not finished yet
    let output = nmcli_stdout(&["-g", "IP4.ADDRESS", "device", "show", device])?;
    Ok(output.lines().any(|line| !line.trim().is_empty()))
}

fn has_default_route(device: &str) -> io::Result<bool> {
    // We also need a default route on the joined Wi-Fi device itself, otherwise the relay/server request can still fail even though some other interface kept the box online.
    let output = Command::new("ip")
        .args(["route", "show", "default", "dev", device])
        .output()?;
    Ok(!String::from_utf8_lossy(&output.stdout).trim().is_empty())
}

fn parse_server_host_port(server_addr: &str) -> io::Result<(String, u16)> {
    // in pairing we store the relay as a URL string, but the readiness probe wants a concrete host + port.
    // Pulling this out into its own helper makes makes readability better instead of mixing and parsing intertwined....
    let url = Url::parse(server_addr)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    let host = url
        .host_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Missing host in server URL"))?
        .to_string();
    let port = url
        .port_or_known_default()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Missing port in server URL"))?;

    Ok((host, port))
}

fn server_socket_reachable(server_addr: &str) -> io::Result<bool> {
    // not trying to fully talk HTTP yet; we only want proof that the network path to the relay/server socket exists
    let (host, port) = parse_server_host_port(server_addr)?;
    let mut resolved = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    if let Some(socket_addr) = resolved.next() {
        return Ok(TcpStream::connect_timeout(&socket_addr, Duration::from_secs(3)).is_ok());
    }

    Err(io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        "Could not resolve server address",
    ))
}

fn wait_for_wifi_readiness(ssid: &str, server_addr: &str, timeout: Duration) -> io::Result<()> {
    // nmcli device wifi connect ... returning success only tells us the radio likely associated to the network.
    // It does *not* mean the box is fully online yet.
    //
    // DHCP might still be finishing, the default route might not exist yet, or the
    // server could still be unreachable for another second or two.....
    //
    // This seems to be what made pairing feel random before: sometimes the next HTTP request landed after the network finished coming up, sometimes it landed a bit too
    // early and the whole attempt looked broken even though Wi-Fi itself worked.
    //
    // So here we wait for the checks that mean verify the connection is usable before we move on to pairing :)
    let start = std::time::Instant::now();
    let mut last_reason = String::from("network not ready yet");

    while start.elapsed() < timeout {
        // Checks are intentionally split out one by one. Allows logs to show
        // what layer is lagging: wrong active connection, no device yet, no DHCP yet, no route yet, or no relay reachability yet...
        let active_names = active_connection_names()?;
        if !active_names.iter().any(|name| name == ssid) {
            last_reason = format!("active connections are {:?}, expected {}", active_names, ssid);
            thread::sleep(Duration::from_millis(500));
            continue;
        }

        // A successful join is not enough if the hotspot profile never actually went away.
        let hotspot_names = active_hotspot_connection_names()?;
        if !hotspot_names.is_empty() {
            last_reason = format!("hotspot connection(s) still active: {:?}", hotspot_names);
            thread::sleep(Duration::from_millis(500));
            continue;
        }

        // Use the concrete device behind this SSID so later checks are not satisfied by the wrong interface.
        let Some(device) = active_connection_device(ssid)? else {
            last_reason = format!("SSID '{ssid}' has no active device yet");
            thread::sleep(Duration::from_millis(500));
            continue;
        };

        if !wifi_has_ipv4(&device)? {
            last_reason = format!("wifi device {device} has no IPv4 address yet");
            thread::sleep(Duration::from_millis(500));
            continue;
        }

        if !has_default_route(&device)? {
            last_reason = format!("default route not ready yet on device {device}");
            thread::sleep(Duration::from_millis(500));
            continue;
        }

        if !server_socket_reachable(server_addr)? {
            last_reason = "server socket not reachable yet".to_string();
            thread::sleep(Duration::from_millis(750));
            continue;
        }

        debug!("[Pairing] Wi-Fi readiness confirmed for SSID '{ssid}'");
        return Ok(());
    }

    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        format!("Timed out waiting for Wi-Fi readiness: {last_reason}"),
    ))
}

fn wait_for_hotspot_shutdown(timeout: Duration) -> io::Result<()> {
    // NetworkManager can report the connect succeeded before it has fully torn AP mode down.
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        let hotspot_names = active_hotspot_connection_names()?;
        if hotspot_names.is_empty() {
            return Ok(());
        }

        thread::sleep(Duration::from_millis(500));
    }

    Err(io::Error::other("Timed out waiting for hotspot to shut down"))
}

fn wait_for_ssid_visibility(ssid: &str, timeout: Duration) -> io::Result<()> {
    // If the scan happened a little too early, we would miss the SSID, give up on that try, and make the flow feel flaky for no
    // great reason. Polling is less fancy, but it matches better than fixed sleeps
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if ssid_visible(ssid)? {
            return Ok(());
        }

        let _ = nmcli_output(&["device", "wifi", "rescan"]);
        thread::sleep(Duration::from_millis(750));
    }

    Err(io::Error::new(io::ErrorKind::NotFound, "SSID not found"))
}

fn attempt_wifi_connection(ssid: String, password: String, server_addr: &str) -> io::Result<()> {
    debug!("[Pairing] Attempting wifi connection");

    // First get out of hotspot mode cleanly so NetworkManager is not juggling both flows at once.
    // We still leave ourselves a path to bring the hotspot back if pairing fails.
    // Drop every active AP profile first so pairing does not "succeed" with the hotspot still running.
    for hotspot_name in active_hotspot_connection_names()? {
        let output = Command::new("nmcli")
            .args(["connection", "down", "id", hotspot_name.as_str()])
            .output()?; // wait for shutdown
        ensure_command_success(
            output,
            &format!("Failed to bring hotspot connection '{hotspot_name}' down"),
        )?;
    }

    // Keep one fallback for older setups that still expect the canonical Hotspot profile name.
    if let Err(e) = wait_for_hotspot_shutdown(Duration::from_secs(8)) {
        let fallback_output = Command::new("nmcli")
            .args(["connection", "down", "id", HOTSPOT_CONNECTION_NAME])
            .output()?;
        if fallback_output.status.success() {
            wait_for_hotspot_shutdown(Duration::from_secs(8))?;
        } else {
            return Err(io::Error::other(format!(
                "{e}; fallback shutdown of '{HOTSPOT_CONNECTION_NAME}' also failed: {}",
                String::from_utf8_lossy(&fallback_output.stderr).trim()
            )));
        }
    }

    // Keep a short buffer after leaving hotspot mode so NetworkManager can settle before
    // we kick off scans/connect attempts.
    thread::sleep(Duration::from_secs(2));

    for n in 1..=4 {
        println!("[Pairing] Attempt {n} to connect to Wi-Fi");

        // split availability check from our attempt to join it on purpose.
        // behaves a lot better in the real world than immediately attempting
        // a connect on a network that may have only just started showing up
        if let Err(e) = wait_for_ssid_visibility(&ssid, Duration::from_secs(12)) {
            debug!("[Pairing] SSID '{}' not found in scan: {}", ssid, e);
            if n == 4 {
                bring_hotspot_back_up()?;
                return Err(e);
            }
            continue;
        }

        // Blow away any stale profile for this SSID before retrying. Reusing a half-bad
        // saved connection can make retries behave weirdly differently from a fresh join.
        let _ = Command::new("nmcli")
            .args(["connection", "delete", "id", ssid.as_str()])
            .output(); // ignore error if it doesn't exist

        // Use direct nmcli args instead of shell strings so we are not depending on quoting luck
        let connect_output = Command::new("nmcli")
            .args([
                "device",
                "wifi",
                "connect",
                ssid.as_str(),
                "password",
                password.as_str(),
            ])
            .output()?;

        if connect_output.status.success() {
            // we've verified the association worked; need to verify it's ready now
            debug!("[Pairing] Association succeeded on attempt {n}; waiting for full network readiness");

            // Autoconnect on reboot
            let _ = Command::new("nmcli")
                .args([
                    "connection",
                    "modify",
                    ssid.as_str(),
                    "connection.autoconnect",
                    "yes",
                ])
                .output();

            // Prove it's ready thru an IP, default route and a path to the relay.
            match wait_for_wifi_readiness(&ssid, server_addr, Duration::from_secs(25)) {
                Ok(()) => return Ok(()),
                Err(e) => {
                    debug!("[Pairing] Wi-Fi readiness check failed on attempt {n}: {e}");
                }
            }
        }

        debug!(
            "[Pairing] Connection failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&connect_output.stdout),
            String::from_utf8_lossy(&connect_output.stderr),
        );

        // Give NetworkManager a second to unwind the failed attempt before we try again.
        thread::sleep(Duration::from_secs(2));
    }

    bring_hotspot_back_up()?;

    Err(io::Error::other(format!(
        "Failed to connect to Wi-Fi '{}'",
        ssid
    )))
}

fn bring_hotspot_back_up() -> io::Result<()> {
    debug!("[Pairing] Bringing hotspot back up...");
    // If pairing fails, we want the device to recover back into the discoverable state
    let output = Command::new("nmcli")
        .args(["connection", "up", "id", "Hotspot"])
        .output()?;
    ensure_command_success(output, "Failed to bring hotspot back up")?;
    Ok(())
}

pub fn create_wifi_hotspot() {
    // less fragile than shell parsing to use argv
    let _ = Command::new("nmcli")
        .args([
            "device", "wifi", "hotspot", "ssid", "Secluso", "password", get_input_wifi_password().as_str(),
        ])
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
) -> anyhow::Result<()> {
    // Ensure that two cameras don't attempt to pair at the same time (as this would introduce an error when opening two of the same port simultaneously)
    let _lock = LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();

    let secret = if let Some(s) = input_camera_secret.clone() {
        s
    } else {
        // This has to be an IP camera. If the camera_secret does not exist for Raspberry Pi, it will not proceed earlier on in the flow.
        generate_ip_camera_secret(&camera.get_name())?
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

                    if success {
                        debug!("[Pairing] Before sending firmware version");
                        match send_firmware_version(&mut stream) {
                            Ok(()) => {}
                            Err(e) => {
                                debug!("[Pairing] Failed to send firmware_version: {e}");
                                success = false;
                            }
                        }
                    }

                    let mls_clients_ref = &mut *mls_clients;

                    if success {
                        debug!("[Pairing] Before pairing");
                        for mls_client in mls_clients_ref.iter_mut() {
                            match perform_pairing_handshake(&mut stream, mls_client.key_package()) {
                                Ok(app_key_package) => {
                                    if let Err(e) = invite(
                                        &mut stream,
                                        mls_client,
                                        app_key_package,
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
                        debug!("[Pairing] Before receiving credentials");
                        match receive_credentials_full(&mut stream, &mut mls_clients[CONFIG]) {
                            Ok(()) => {}
                            Err(e) => {
                                debug!("[Pairing] Failed to receive credentials_full: {e}");
                                success = false;
                            }
                        }
                    }

                    let server_addr = if success {
                        debug!("[Pairing] Before parsing credentials");
                        let (_, _, server_addr) = read_parse_full_credentials();
                        Some(server_addr)
                    } else {
                        success = false;
                        None
                    };

                    let http_client = if success {
                        debug!("[Pairing] Before parsing credentials");
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

                    let mut changed_wifi = false;

                    if connect_to_wifi && success {
                        debug!("[Pairing] Before request wifi info");
                        match request_wifi_info(&mut stream, &mut mls_clients[CONFIG]) {
                            Ok((ssid, password, pairing_token)) => {
                                if connect_to_wifi {
                                    match attempt_wifi_connection(
                                        ssid,
                                        password,
                                        server_addr.as_ref().unwrap(),
                                    ) {
                                        Ok(_) => {
                                            changed_wifi = true;
                                            debug!("[Pairing] Attempting to confirm pairing...");
                                            match http_client
                                                .unwrap()
                                                .send_pairing_token(&pairing_token)
                                            {
                                                Ok(pairing_status) => {
                                                    debug!(
                                                        "[Pairing] Pairing token acknowledged with status: {}",
                                                        pairing_status.status
                                                    );
                                                    if let Some(target) =
                                                        pairing_status.notification_target.as_ref()
                                                    {
                                                        if let Err(e) = persist_notification_target(
                                                            &camera.get_state_dir(),
                                                            target,
                                                        ) {
                                                            error!(
                                                                "[Pairing] Failed to persist notification target: {e}"
                                                            );
                                                        }
                                                    }
                                                    match pairing_status.status.as_str() {
                                                        "paired" => {
                                                            debug!("[Pairing] Success: both sides connected.");
                                                        }
                                                        "expired" => {
                                                            debug!("[Pairing] Error: pairing token expired.");
                                                            success = false;
                                                        }
                                                        "invalid_token" | "invalid_role" => {
                                                            debug!(
                                                                "[Pairing] Error: invalid input ({})",
                                                                pairing_status.status
                                                            );
                                                            success = false;
                                                        }
                                                        _ => {
                                                            debug!(
                                                                "[Pairing] Unexpected status: {}",
                                                                pairing_status.status
                                                            );
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
    state_dir: String,
    first_time: bool,
    camera_filename: String,
    group_filename: String,
) -> (String, String) {
    let state_dir_path = Path::new(&state_dir);
    let camera_path = state_dir_path.join(camera_filename);
    let group_path = state_dir_path.join(group_filename);

    let (camera_name, group_name) = if first_time {
        let mut rng = rand::rng();
        let cname: String = (0..NUM_RANDOM_CHARS)
            .map(|_| rng.sample(rand::distr::Alphanumeric) as char)
            .collect();

        let mut file = File::create(camera_path).expect("Could not create file");
        file.write_all(cname.as_bytes()).unwrap();
        file.flush().unwrap();
        file.sync_all().unwrap();

        let gname: String = (0..NUM_RANDOM_CHARS)
            .map(|_| rng.sample(rand::distr::Alphanumeric) as char)
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
