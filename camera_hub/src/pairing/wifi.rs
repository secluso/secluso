//! Camera hub pairing over a WiFi hotspot
//!
//! SPDX-License-Identifier: GPL-3.0-or-later

use crate::notification_target::persist_notification_target;
use crate::traits::Camera;
use crate::pairing::flow::decrypt_msg;
use secluso_client_lib::http_client::{HttpClient, PairingStatus};
use secluso_client_lib::mls_client::MlsClient;
use secluso_client_lib::mls_clients::{MlsClients, CONFIG};
use secluso_client_lib::pairing::MessageTransport;
use serde_json::Value;
use std::fs;
use std::io;
use std::io::ErrorKind;
use std::net::{TcpStream, ToSocketAddrs};
use std::process::Output;
use std::process::{Command, Stdio};
use std::{thread, time::Duration};
use url::Url;

const HOTSPOT_CONNECTION_NAME: &str = "Hotspot";

// Read the WiFi password contents from file to use for the hotspot
pub fn get_input_wifi_password() -> String {
    let pathname = match std::env::var("SECLUSO_USE_PROVISION").as_deref() {
        Ok("1") => "/provision/wifi_password",
        _ => "./wifi_password",
    };

    fs::read_to_string(pathname)
        .expect("Failed to read from \"wifi_password\" file. You can generate this in config tool")
}

pub(crate) fn request_wifi_info(
    msg_transport: &mut dyn MessageTransport,
    mls_client: &mut MlsClient,
) -> anyhow::Result<(String, String, String)> {
    // Combine into one message to reduce risk of non-blocking errors
    let wifi_msg = msg_transport.receive_msg("")?;
    let wifi_bytes = decrypt_msg(mls_client, wifi_msg)?;

    let payload_msg = String::from_utf8(wifi_bytes).expect("Invalid UTF-8 for WiFi message");
    debug!("Recieved Wifi Payload: {payload_msg}");
    let json: Value = serde_json::from_str(&payload_msg)?;

    Ok((
        json["ssid"]
            .as_str()
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "Missing or invalid ssid"))?
            .to_string(),
        json["passphrase"]
            .as_str()
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "Missing or invalid passphrase"))?
            .to_string(),
        json["pairing_token"]
            .as_str()
            .ok_or_else(|| {
                io::Error::new(ErrorKind::InvalidData, "Missing or invalid pairing token")
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
    let output = nmcli_stdout(&[
        "-t",
        "-f",
        "NAME,TYPE,DEVICE",
        "connection",
        "show",
        "--active",
    ])?;
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
        .map_err(|e| io::Error::new(ErrorKind::InvalidInput, e.to_string()))?;
    let host = url
        .host_str()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "Missing host in server URL"))?
        .to_string();
    let port = url
        .port_or_known_default()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "Missing port in server URL"))?;

    Ok((host, port))
}

fn server_socket_reachable(server_addr: &str) -> io::Result<bool> {
    // not trying to fully talk HTTP yet; we only want proof that the network path to the relay/server socket exists
    let (host, port) = parse_server_host_port(server_addr)?;
    let mut resolved = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|e| io::Error::other(e.to_string()))?;

    if let Some(socket_addr) = resolved.next() {
        return Ok(TcpStream::connect_timeout(&socket_addr, Duration::from_secs(3)).is_ok());
    }

    Err(io::Error::new(
        ErrorKind::AddrNotAvailable,
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
            last_reason = format!(
                "active connections are {active_names:?}, expected {ssid}",
            );
            thread::sleep(Duration::from_millis(500));
            continue;
        }

        // A successful join is not enough if the hotspot profile never actually went away.
        let hotspot_names = active_hotspot_connection_names()?;
        if !hotspot_names.is_empty() {
            last_reason = format!("hotspot connection(s) still active: {hotspot_names:?}");
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
        ErrorKind::TimedOut,
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

    Err(io::Error::other(
        "Timed out waiting for hotspot to shut down",
    ))
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

    Err(io::Error::new(ErrorKind::NotFound, "SSID not found"))
}

pub(crate) fn attempt_wifi_connection(
    ssid: &str,
    password: &str,
    server_addr: &str,
) -> io::Result<()> {
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
        if let Err(e) = wait_for_ssid_visibility(ssid, Duration::from_secs(12)) {
            debug!("[Pairing] SSID '{ssid}' not found in scan: {e}");
            if n == 4 {
                bring_hotspot_back_up()?;
                return Err(e);
            }
            continue;
        }

        // Blow away any stale profile for this SSID before retrying. Reusing a half-bad
        // saved connection can make retries behave weirdly differently from a fresh join.
        let _ = Command::new("nmcli")
            .args(["connection", "delete", "id", ssid])
            .output(); // ignore error if it doesn't exist

        // Use direct nmcli args instead of shell strings so we are not depending on quoting luck
        let connect_output = Command::new("nmcli")
            .args([
                "device",
                "wifi",
                "connect",
                ssid,
                "password",
                password,
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
                    ssid,
                    "connection.autoconnect",
                    "yes",
                ])
                .output();

            // Prove it's ready thru an IP, default route and a path to the relay.
            match wait_for_wifi_readiness(ssid, server_addr, Duration::from_secs(25)) {
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
        "Failed to connect to Wi-Fi '{ssid}'"
    )))
}

pub(crate) fn send_pairing_token_after_wifi_ready(
    http_client: &HttpClient,
    pairing_token: &str,
) -> io::Result<PairingStatus> {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    let mut attempt = 1;
    let mut last_error = None;

    while std::time::Instant::now() < deadline {
        match http_client.send_pairing_token(pairing_token) {
            Ok(status) => return Ok(status),
            Err(e) => {
                debug!("[Pairing] Pairing token POST attempt {attempt} failed: {e}");
                last_error = Some(e);
                attempt += 1;
                thread::sleep(Duration::from_secs(1));
            }
        }
    }

    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            ErrorKind::TimedOut,
            "Timed out sending pairing token after Wi-Fi became ready",
        )
    }))
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
    let password = get_input_wifi_password();

    loop {
        // less fragile than shell parsing to use argv
        match Command::new("nmcli")
            .args([
                "device",
                "wifi",
                "hotspot",
                "ssid",
                "Secluso",
                "password",
                password.as_str(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(mut child) => match child.wait() {
                Ok(status) if status.success() => return,
                Ok(status) => {
                    debug!("[Pairing] Failed to create WiFi hotspot; nmcli exited with {status}");
                }
                Err(e) => {
                    debug!("[Pairing] Failed to wait for WiFi hotspot creation: {e}");
                }
            },
            Err(e) => {
                debug!("[Pairing] Failed to start WiFi hotspot creation: {e}");
            }
        }

        thread::sleep(Duration::from_secs(2));
    }
}

pub(crate) fn attempt_wifi_pair(
    msg_transport: &mut dyn MessageTransport,
    mls_clients: &mut MlsClients,
    http_client: &HttpClient,
    camera: &dyn Camera,
    server_addr: &str,
) -> (bool, bool) {
    let mut changed_wifi = false;
    debug!("[Pairing] Before request wifi info");
    match request_wifi_info(msg_transport, &mut mls_clients[CONFIG]) {
        Ok((ssid, password, pairing_token)) => {
            match attempt_wifi_connection(&ssid, &password, server_addr) {
                Ok(()) => {
                    changed_wifi = true;
                    debug!("[Pairing] Attempting to confirm pairing...");
                    match send_pairing_token_after_wifi_ready(http_client, &pairing_token) {
                        Ok(pairing_status) => {
                            debug!(
                                "[Pairing] Pairing token acknowledged with status: {}",
                                pairing_status.status
                            );
                            if let Some(target) = pairing_status.notification_target.as_ref() {
                                if let Err(e) =
                                    persist_notification_target(&camera.get_state_dir(), target)
                                {
                                    error!("[Pairing] Failed to persist notification target: {e}");
                                }
                            }
                            match pairing_status.status.as_str() {
                                "paired" => {
                                    debug!("[Pairing] Success: both sides connected.");
                                    return (changed_wifi, true);
                                }
                                "expired" => {
                                    debug!("[Pairing] Error: pairing token expired.");
                                }
                                "invalid_token" | "invalid_role" => {
                                    debug!(
                                        "[Pairing] Error: invalid input ({})",
                                        pairing_status.status
                                    );
                                }
                                _ => {
                                    debug!(
                                        "[Pairing] Unexpected status: {}",
                                        pairing_status.status
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            error!("[Pairing] Failed to send pairing token: {e}");
                        }
                    }
                }
                Err(e) => {
                    debug!("[Pairing] Error connecting to user provided WiFi: {e}");
                }
            }
        }
        Err(e) => {
            debug!("[Pairing] Failed to retrieve user WiFi information: {e}");
        }
    }
    (changed_wifi, false)
}