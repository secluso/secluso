//! Secluso app-camera pairing protocol.
//!
//! SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{anyhow, Context};
use openmls::prelude::KeyPackage;
use serde::{Deserialize, Serialize};
use std::fs;
use std::fs::create_dir;
use std::io::Write;
use std::path::Path;

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::random::OpenMlsRand;
use openmls_traits::OpenMlsProvider;
use rand::distr::Uniform;
use rand::Rng;

pub const NUM_SECRET_BYTES: usize = 72;
pub const CAMERA_SECRET_VERSION: &str = "v1.2";
const WIFI_PASSWORD_LEN: usize = 10;
pub const MAX_ALLOWED_MSG_LEN: u64 = 8192;

#[cfg(feature = "camera_secret_qrcode")]
fn save_camera_secret_qrcode(path: &Path, content: &[u8]) -> anyhow::Result<()> {
    use image::Luma;
    use qrcode::QrCode;

    let code =
        QrCode::new(content).context("Failed to generate QR code from camera secret bytes")?;
    code.render::<Luma<u8>>()
        .build()
        .save(path)
        .with_context(|| format!("Failed to save QR code image to {}", path.display()))?;

    Ok(())
}

#[cfg(not(feature = "camera_secret_qrcode"))]
fn save_camera_secret_qrcode(_path: &Path, _content: &[u8]) -> anyhow::Result<()> {
    Err(anyhow!(
        "camera secret QR code support is not enabled in this build"
    ))
}

// We version the QR code, store secret bytes as well (base64-url-encoded) as the Wi-Fi passphrase for Raspberry Pi cameras.
// Versioned QR codes can be helpful to ensure compatibility.
// Allows us to create backwards compatibility for previous QR versions without needing to re-generate QR codes again for users.
#[derive(Serialize, Deserialize)]
pub struct CameraSecret {
    #[serde(rename = "v", alias = "version")]
    pub version: String,

    // "cameras secret" = "cs", we shorten the fields to reduce the amount of bytes represented in the QrCode.
    // But this shouldn't be "s" to maintain separation from the user credentials qr code
    #[serde(rename = "cs", alias = "secret")]
    pub secret: String,

    #[serde(rename = "wp", alias = "wiif_password")]
    pub wifi_password: Option<String>,
}

#[derive(Serialize, Deserialize, PartialEq)]
enum PairingMsgType {
    AppToCameraMsg,
    CameraToAppMsg,
}

#[derive(Serialize, Deserialize)]
struct PairingMsgContent {
    msg_type: PairingMsgType,
    key_package: KeyPackage,
}

#[derive(Serialize, Deserialize)]
struct PairingMsg {
    content_vec: Vec<u8>,
}

pub struct App {
    key_package: KeyPackage,
}

pub fn generate_ip_camera_secret(camera_name: &str) -> anyhow::Result<Vec<u8>> {
    let crypto = OpenMlsRustCrypto::default();
    let secret = crypto
        .crypto()
        .random_vec(NUM_SECRET_BYTES)
        .context("Failed to generate camera secret bytes")?;

    let camera_secret = CameraSecret {
        version: CAMERA_SECRET_VERSION.to_string(),
        secret: base64_url::encode(&secret),
        wifi_password: None,
    };

    let writeable_secret = serde_json::to_string(&camera_secret)
        .context("Failed to serialize camera secret into JSON")?;

    // Save as QR code to be shown to the app.
    let qrcode_path = format!(
        "camera_{}_secret_qrcode.png",
        camera_name.replace(" ", "_").to_lowercase()
    );
    save_camera_secret_qrcode(Path::new(&qrcode_path), writeable_secret.as_bytes())?;

    Ok(secret)
}

fn generate_wifi_password(dir: &Path) -> anyhow::Result<String> {
    // Generate the randomized WiFi password
    let wifi_password = generate_random(WIFI_PASSWORD_LEN, false); //10 characters that are upper/low alphanumeric
    fs::File::create(dir.join("wifi_password")).context("Could not create wifi_password file")?;

    fs::write(dir.join("wifi_password"), wifi_password.clone())
        .with_context(|| format!("Could not create {}", dir.display()))?;

    Ok(wifi_password)
}

pub fn generate_random(num_chars: usize, special_characters: bool) -> String {
    // We exclude : because that character has a special use in the http(s) auth header.
    // We exclude / because that character is used within the Linux file system
    let charset: &[u8] = if special_characters {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                           abcdefghijklmnopqrstuvwxyz\
                           0123456789\
                           !@#$%^&*()-_=+[]{}|;,.<>?"
    } else {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                           abcdefghijklmnopqrstuvwxyz\
                           0123456789"
    };

    let mut rng = rand::rng();
    (0..num_chars)
        .map(|_| {
            let idx = rng.sample(Uniform::new(0, charset.len()).unwrap());
            charset[idx] as char
        })
        .collect()
}

pub fn generate_raspberry_camera_secret(
    dir: &Path,
    error_on_folder_exist: bool,
) -> anyhow::Result<()> {
    // If it already exists and we don't want to try re-generating credentials..
    if dir.exists() && error_on_folder_exist {
        return Err(anyhow!("The directory exists!"));
    }

    // Create the directory if it doesn't exist
    if !dir.exists() {
        create_dir(dir)?;
    }

    let crypto = OpenMlsRustCrypto::default();
    let secret = crypto
        .crypto()
        .random_vec(NUM_SECRET_BYTES)
        .context("Failed to generate camera secret bytes")?;

    let wifi_password = generate_wifi_password(dir)?;
    let camera_secret = CameraSecret {
        version: CAMERA_SECRET_VERSION.to_string(),
        secret: base64_url::encode(&secret),
        wifi_password: Some(wifi_password),
    };

    let qr_content = serde_json::to_string(&camera_secret)
        .context("Failed to serialize camera secret into JSON")?;

    // Save in a file to be given to the camera
    // The camera secret does not need to be versioned. We're not worried about the formatting ever changing.
    // Just put the secret by itself in this file.
    let mut file =
        std::fs::File::create(dir.join("camera_secret")).context("Could not create file")?;
    file.write_all(&secret)
        .context("Failed to write camera secret data to file")?;

    // Save as QR code to be shown to the app (with secret + version + wifi password).
    save_camera_secret_qrcode(&dir.join("camera_secret_qrcode.png"), qr_content.as_bytes())?;

    Ok(())
}

impl App {
    pub fn new(key_package: KeyPackage) -> Self {
        Self { key_package }
    }

    pub fn generate_msg_to_camera(&self) -> Vec<u8> {
        let msg_content = PairingMsgContent {
            msg_type: PairingMsgType::AppToCameraMsg,
            key_package: self.key_package.clone(),
        };
        let msg_content_vec = bincode::serialize(&msg_content).unwrap();

        let msg = PairingMsg {
            content_vec: msg_content_vec,
        };

        bincode::serialize(&msg).unwrap()
    }

    pub fn process_camera_msg(&self, camera_msg_vec: Vec<u8>) -> anyhow::Result<KeyPackage> {
        let camera_msg: PairingMsg = bincode::deserialize(&camera_msg_vec)?;

        let camera_msg_content: PairingMsgContent = bincode::deserialize(&camera_msg.content_vec)?;
        // Check the message type
        if camera_msg_content.msg_type != PairingMsgType::CameraToAppMsg {
            panic!("Received invalid pairing message!");
        }

        Ok(camera_msg_content.key_package)
    }
}

pub struct Camera {
    key_package: KeyPackage,
}

impl Camera {
    // FIXME: identical to App::new()
    pub fn new(key_package: KeyPackage) -> Self {
        Self { key_package }
    }

    pub fn process_app_msg_and_generate_msg_to_app(
        &self,
        app_msg_vec: Vec<u8>,
    ) -> anyhow::Result<(KeyPackage, Vec<u8>)> {
        let app_msg: PairingMsg = bincode::deserialize(&app_msg_vec).unwrap();

        let app_msg_content: PairingMsgContent =
            bincode::deserialize(&app_msg.content_vec).unwrap();

        // Check the message type
        if app_msg_content.msg_type != PairingMsgType::AppToCameraMsg {
            panic!("Received invalid pairing message!");
        }

        // Generate response
        let msg_content = PairingMsgContent {
            msg_type: PairingMsgType::CameraToAppMsg,
            key_package: self.key_package.clone(),
        };
        let msg_content_vec = bincode::serialize(&msg_content).unwrap();

        let resp_msg = PairingMsg {
            content_vec: msg_content_vec,
        };

        let resp_msg_vec = bincode::serialize(&resp_msg).unwrap();

        Ok((app_msg_content.key_package, resp_msg_vec))
    }
}
