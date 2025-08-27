//! Privastead config tool.
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
extern crate serde_derive;

use docopt::Docopt;
use image::Luma;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::random::OpenMlsRand;
use openmls_traits::OpenMlsProvider;
use qrcode::QrCode;
use std::fs;
use std::io;
use std::io::Write;
use url::Url;
use privastead_client_server_lib::auth::create_user_credentials;

// FIXME: these constants should match the ones in rest of the code.
// Consolidate the constants in one place.

pub const NUM_SECRET_BYTES: usize = 72;

const USAGE: &str = "
Helps configure the Privastead server, camera, and app.

Usage:
  privastead-config-tool --generate-user-credentials --server-addr ADDR --dir DIR
  privastead-config-tool --generate-camera-secret --dir DIR
  privastead-config-tool (--version | -v)
  privastead-config-tool (--help | -h)

Options:
    --generate-user-credentials     Generate a random username and a random key to be used to authenticate with the server.
    --generate-camera-secret        Generate a random secret to be used for camera pairing (used for Raspberry Pi cameras).
    --server-addr ADDR              Address (URL) of the server, e.g., https://example.com:8080/ or http://192.168.0.1/.
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
}

fn main() -> io::Result<()> {
    let version = env!("CARGO_PKG_NAME").to_string() + ", version: " + env!("CARGO_PKG_VERSION");

    let args: Args = Docopt::new(USAGE)
        .map(|d| d.help(true))
        .map(|d| d.version(Some(version)))
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    if args.flag_generate_user_credentials {
        generate_user_credentials(args.flag_dir, args.flag_server_addr);
    } else if args.flag_generate_camera_secret {
        generate_camera_secret(args.flag_dir);
    } else {
        println!("Unsupported command!");
    }

    Ok(())
}

fn generate_user_credentials(dir: String, mut server_addr: String) {
    if let Ok(parsed_url) = Url::parse(&server_addr) {
        if parsed_url.scheme() != "http" && parsed_url.scheme() != "https" {
            println!("Invalid server URL scheme: {}", parsed_url.scheme());
            return;
        }
    } else {
        println!("Invalid server URL");
        return;
    }

    if server_addr.ends_with('/') {
        server_addr.pop();
    }

    let (credentials, credentials_full) =
        create_user_credentials(server_addr);

    // Save the credentials in a file to be given to the server (delivery service)
    let mut file =
        fs::File::create(dir.clone() + "/user_credentials").expect("Could not create file");
    let _ = file.write_all(&credentials);

    // Save the credentials_full (which includes the server addr) as QR code to be shown to the app
    let code = QrCode::new(&credentials_full).unwrap();
    let image = code.render::<Luma<u8>>().build();
    image
        .save(dir.clone() + "/user_credentials_qrcode.png")
        .unwrap();

    // Save the credentials_full in a file to be used for testing with the example app
    let mut file =
        fs::File::create(dir.clone() + "/user_credentials_for_testing").expect("Could not create file");
    let _ = file.write_all(&credentials_full);

    println!("Generated!")
}

fn generate_camera_secret(dir: String) {
    let crypto = OpenMlsRustCrypto::default();
    let secret = crypto
        .crypto()
        .random_vec(NUM_SECRET_BYTES)
        .unwrap();

    // Save in a file to be given to the camera
    let mut file =
        fs::File::create(dir.clone() + "/camera_secret").expect("Could not create file");
    let _ = file.write_all(&secret);

    // Save as QR code to be shown to the app
    let code = QrCode::new(secret.clone()).unwrap();
    let image = code.render::<Luma<u8>>().build();
    image
        .save(dir.clone() + "/camera_secret_qrcode.png")
        .unwrap();

    println!("Generated!")
}
