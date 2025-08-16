//! Privastead camera hub update code.
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

use docopt::Docopt;
use anyhow::Result;
use reqwest::blocking::Client;
use semver::Version;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::Duration;
use serde::Deserialize;
use p384::ecdsa::{VerifyingKey, Signature};
use p384::elliptic_curve::pkcs8::DecodePublicKey;
use ecdsa::signature::Verifier;
use bytes::Bytes;

const BIN_NAME: &str = "privastead-camera-hub-aarch64-unknown-linux-gnu";
const SIGNATURE1_NAME: &str = "privastead-camera-hub-aarch64-unknown-linux-gnu-signer1.sig";
const SIGNATURE2_NAME: &str = "privastead-camera-hub-aarch64-unknown-linux-gnu-signer2.sig";

pub fn check_update(server_addr: &str) -> Result<()> {
    let current_version = match get_current_version() {
        Ok(version) => version,
        Err(_) => Version::parse("0.0.0")?,
    };
    println!("current_version = {current_version}");

    let _ = fs::remove_file(BIN_NAME);
    let _ = fs::remove_file(SIGNATURE1_NAME);
    let _ = fs::remove_file(SIGNATURE2_NAME);

    let client = Client::builder()
        .user_agent("privastead-updater")
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()?;

    let latest = fetch_latest_release(server_addr, &client)?;

    let latest_version = Version::parse(&latest.trim_start_matches('v'))?;
    if latest_version <= current_version {
        println!("Already on latest version ({current_version}).");
        return Ok(());
    }

    println!("Found newer version: {latest_version}");

    let bin_bytes = fetch_file(server_addr, &client, &latest, BIN_NAME)?;
    let signer_1_sig_bytes = fetch_file(server_addr, &client, &latest, SIGNATURE1_NAME)?;
    let signer_2_sig_bytes = fetch_file(server_addr, &client, &latest, SIGNATURE2_NAME)?;

    println!("Verifying signatures...");

    // Only proceed if the binary is signed by both signers
    check_signer_signature(&bin_bytes, &signer_1_sig_bytes, "signer1")?;
    check_signer_signature(&bin_bytes, &signer_2_sig_bytes, "signer2")?;

    println!("Signatures verified. Updating...");

    // Replace current executable
    let tmp_path = "../camera_hub/target/release/privastead-camera-hub-tmp";
    let final_path = "../camera_hub/target/release/privastead-camera-hub";

    fs::write(&tmp_path, &bin_bytes)?;
    fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o755))?;

    // Stop the service
    let status = Command::new("sh")
        .arg("-c")
        .arg("sudo systemctl stop privastead.service")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?
        .wait()?;

    if status.success() {
        println!("Service stopped successfully.");
    } else {
        eprintln!("Failed to stop service. Exit code: {:?}", status.code());
    }

    // Atomically replace the old binary
    fs::rename(tmp_path, final_path)?;

    // Start the service
    let status = Command::new("sh")
        .arg("-c")
        .arg("sudo systemctl start privastead.service")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?
        .wait()?;

    if status.success() {
        println!("Service started successfully.");
    } else {
        eprintln!("Failed to start service. Exit code: {:?}", status.code());
    }

    println!("Updated to version {latest_version}");

    Ok(())
}

fn fetch_latest_release(server_addr: &str, client: &Client) -> Result<String> {
    let url = format!("https://{}/latest_release", server_addr);

    let request = client.get(&url);

    let response = request.send()?.error_for_status()?;
    let response_text = response.text()?;
    let response_text_trimmed = response_text.trim_end_matches(&['\r', '\n'][..]);
    Ok(response_text_trimmed.to_string())
}

fn fetch_file(server_addr: &str, client: &Client, latest: &str, filename: &str) -> Result<Bytes> {
    let url = format!("https://{}/{latest}/{filename}", server_addr);
    println!("url = {url}");

    let bytes = client
    .get(url)
    .header("Accept", "application/octet-stream")
    .send()?
    .error_for_status()?
    .bytes()?;

    println!("{filename}: bytes.len() = {}", bytes.len());

    Ok(bytes)
}

fn get_current_version() -> Result<Version> {
    let version_string = fs::read_to_string("../camera_hub/current_version")?;
    let version = Version::parse(&version_string.trim_start_matches('v'))?;
    Ok(version)
}

/// Each signer has two keys: main and backup.
/// They can sign the binary with either key.
fn check_signer_signature(bin_bytes: &Bytes, sig_bytes: &Bytes, signer: &str) -> Result<()> {
    if let Ok(()) = check_signature(bin_bytes, sig_bytes, format!("pubkey_{}_main.pem", signer)) {
        println!("Verified by {}'s main key", signer);
        return Ok(());
    }

    check_signature(bin_bytes, sig_bytes, format!("pubkey_{}_backup.pem", signer))?;
    println!("Verified by {}'s backup key", signer);
    Ok(())
}

fn check_signature(bin_bytes: &Bytes, sig_bytes: &Bytes, pubkey_filename: String) -> Result<()> {
    // Load PEM-encoded public key
    let pem_str = fs::read_to_string(pubkey_filename)?;
    
    // Load VerifyingKey from PEM contents
    let verifying_key = VerifyingKey::from_public_key_pem(&pem_str)?;

    let signature = Signature::from_der(&sig_bytes)?;

    verifying_key.verify(&bin_bytes, &signature)?;

    Ok(())
}

const USAGE: &str = "
Helps update camera_hub.

Usage:
  privastead-update --server-addr ADDR
  privastead-config-tool (--version | -v)
  privastead-config-tool (--help | -h)

Options:
    --server-addr ADDR              Address of the server.
    --version, -v                   Show tool version.
    --help, -h                      Show this screen.
";

#[derive(Debug, Deserialize)]
struct Args {
    flag_server_addr: String,
}

fn main() -> ! {
    let version = env!("CARGO_PKG_NAME").to_string() + ", version: " + env!("CARGO_PKG_VERSION");

    let args: Args = Docopt::new(USAGE)
        .map(|d| d.help(true))
        .map(|d| d.version(Some(version)))
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    loop {
        println!("Going to check for updates.");
        match check_update(&args.flag_server_addr) {
            Ok(()) => {},
            Err(e) => println!("Update check failed: {}", e),
        }

        sleep(Duration::from_secs(60));
    }
}