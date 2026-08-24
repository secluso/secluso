//! Secluso config tool.
//!
//! SPDX-License-Identifier: GPL-3.0-or-later

#[macro_use]
extern crate serde_derive;

use docopt::Docopt;
use qrcode::QrCode;
use image::Luma;
use std::fs;
use std::io;
use std::io::Write;
use std::fs::create_dir;
use std::path::Path;
use url::Url;
use secluso_client_server_lib::auth::{create_user_credentials_for, ServerBackend};
use anyhow::Context;
use anyhow::anyhow;

const USAGE: &str = "
Helps configure the Secluso server, camera, and app.

Usage:
  secluso-config-tool --generate-user-credentials --server-addr ADDR --dir DIR [--enterprise]
  secluso-config-tool --generate-camera-secret --dir DIR
  secluso-config-tool (--version | -v)
  secluso-config-tool (--help | -h)

Options:
    --generate-user-credentials     Generate a random username and a random key to be used to authenticate with the server.
    --generate-camera-secret        Generate a random secret to be used for camera pairing (used for Raspberry Pi cameras).
    --server-addr ADDR              Address (URL) of the server, e.g., https://example.com:8080/ or http://192.168.0.1/.
    --enterprise                    The address is the hosted enterprise server, not a self-hosted one.
                                    Changes how the camera and app authenticate and how objects are named.
    --dir DIR                       Directory for storing the camera's secret files.
    --version, -v                   Show tool version.
    --help, -h                      Show this screen.
";

#[derive(Debug, Deserialize)]
struct Args {
    flag_generate_user_credentials: bool,
    flag_generate_camera_secret: bool,
    flag_server_addr: String,
    flag_dir: String,
    flag_enterprise: bool,
}

fn main() -> io::Result<()> {
    let version = env!("CARGO_PKG_NAME").to_string() + ", version: " + env!("CARGO_PKG_VERSION");

    let args: Args = Docopt::new(USAGE)
        .map(|d| d.help(true))
        .map(|d| d.version(Some(version)))
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    if args.flag_generate_user_credentials {
        let backend = if args.flag_enterprise {
            ServerBackend::Enterprise
        } else {
            ServerBackend::SelfHosted
        };
        if let Err(e) =
            generate_user_credentials(Path::new(&args.flag_dir), &args.flag_server_addr, backend)
        {
            println!("Failed to generate!");
            println!("Error: {}", e);
        } else {
            println!("Successfully generated!");
        }
    } else if args.flag_generate_camera_secret {
        if let Err(e) = secluso_client_lib::pairing::generate_raspberry_camera_secret(Path::new(&args.flag_dir), true) {
            println!("Failed to generate camera secret!");
            println!("Error: {}", e);
        }
    } else {
        println!("Unsupported command!");
    }

    Ok(())
}


fn generate_user_credentials(
    dir: &Path,
    mut server_addr: &str,
    backend: ServerBackend,
) -> anyhow::Result<()> {
    if let Ok(parsed_url) = Url::parse(server_addr) {
        if parsed_url.scheme() != "http" && parsed_url.scheme() != "https" {
            return Err(anyhow!("Invalid server URL scheme: {}", parsed_url.scheme()));
        }
    } else {
        return Err(anyhow!("Invalid server URL"));
    }

    // Remove trailing slash.
    server_addr = server_addr.trim_end_matches('/');


    let (credentials, credentials_full, credentials_full_testing) =
        create_user_credentials_for(server_addr.to_string(), backend)?;

    // Create the directory if it doesn't exist
    create_dir(dir).context("Failed to create directory (it may already exist)")?;

    // Save the credentials in a file to be given to the server (delivery service)
    let mut file =
        fs::File::create(dir.join("user_credentials")).context("Could not create user_credentials file")?;
    file.write_all(&credentials).context("Failed to write to file")?;

    // Also save credentials_full as a plain file.
    let mut file = fs::File::create(dir.join("user_credentials_full"))
        .context("Could not create user_credentials_full file")?;
    file.write_all(&credentials_full)
        .context("Failed to write to file")?;

    // Save the credentials_full (which includes the server addr) as QR code to be shown to the app
    let code = QrCode::new(&credentials_full).context("Failed to generate QR code")?;
    let image = code.render::<Luma<u8>>().build();
    image
        .save(dir.join("user_credentials_qrcode.png"))
        .context("Failed to save image")?;

    // Save the credentials_full in a file to be used for testing with the example app
    let mut file =
        fs::File::create(dir.join("user_credentials_for_testing")).expect("Could not create file");
    let _ = file.write_all(&credentials_full_testing);

    Ok(())
}

