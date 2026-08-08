//! Secluso app-camera pairing protocol.
//!
//! SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{anyhow, Context};
use openmls::prelude::KeyPackage;
use serde::{Deserialize, Serialize};
use std::fs;
use std::fs::create_dir;
use std::io::{self, Write, Read, ErrorKind};
use std::path::Path;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::random::OpenMlsRand;
use openmls_traits::OpenMlsProvider;
use rand::distr::Uniform;
use rand::Rng;
use rand::distr::Alphanumeric;
#[cfg(feature = "http_client")]
use crate::http_client::HttpClient;
use log::{error, info};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::str::FromStr;
use std::thread;
use std::time::Duration;

pub const NUM_SECRET_BYTES: usize = 72;
pub const CAMERA_SECRET_VERSION: &str = "v1.2";
const WIFI_PASSWORD_LEN: usize = 10;
pub const MAX_ALLOWED_MSG_LEN: u64 = 8192;
const CAMERA_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const CAMERA_IO_TIMEOUT: Duration = Duration::from_secs(12);
const CAMERA_CONNECT_RETRIES: usize = 3;
const CAMERA_CONNECT_RETRY_DELAY: Duration = Duration::from_millis(350);

// Used to generate random names.
// With 16 alphanumeric characters, the probability of collision is very low.
// Note: even if collision happens, it has no impact on
// our security guarantees. Will only cause availability issues.
const NUM_RANDOM_CHARS_FOR_NAMES: u8 = 16;

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

pub fn generate_android_camera_secret(camera_name: &str) -> anyhow::Result<Vec<u8>> {
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

    let qrcode_path = format!(
        "camera_{}_secret_qrcode_payload.json",
        camera_name.replace(" ", "_").to_lowercase()
    );

    std::fs::write(&qrcode_path, writeable_secret.as_bytes())
        .with_context(|| format!("Failed to write camera secret QR payload to {qrcode_path}"))?;

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

pub fn generate_add_app_secret() -> anyhow::Result<String> {
    let crypto = OpenMlsRustCrypto::default();
    let secret = crypto
        .crypto()
        .random_vec(NUM_SECRET_BYTES)
        .context("Failed to generate camera secret bytes")?;

    let add_app_secret = CameraSecret {
        version: CAMERA_SECRET_VERSION.to_string(),
        secret: base64_url::encode(&secret),
        wifi_password: None,
    };

    let qr_content = serde_json::to_string(&add_app_secret)
        .context("Failed to serialize add_app secret into JSON")?;

    Ok(qr_content)
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

pub trait MessageTransport {
    fn send_msg(&mut self, msg: &[u8], msg_tag: &str) -> io::Result<()>;
    fn receive_msg(&mut self, msg_tag: &str) -> io::Result<Vec<u8>>;
    fn wait_for_pairing_request(&mut self) -> io::Result<()>;
}

pub struct TcpStreamTransport {
    stream: Option<TcpStream>,
}

impl TcpStreamTransport {
    pub fn initialize_connect(
        camera_ip: String,
    ) -> io::Result<Self> {
        //FIXME: port number hardcoded.
        let addr = SocketAddr::from_str(&(camera_ip + ":12348"))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e}")))?;
        let stream = connect_camera_stream(&addr)?;

        Ok(Self {
            stream: Some(stream),
        })
    }

    pub fn initialize_no_connect() -> io::Result<Self> {
        Ok(Self {
            stream: None,
        })
    }
}

impl MessageTransport for TcpStreamTransport {
    fn send_msg(&mut self, msg: &[u8], _msg_tag: &str) -> io::Result<()> {
        if let Some(ref mut stream) = self.stream {
            return write_varying_len(stream, msg);
        }

        Err(io::Error::new(io::ErrorKind::NotConnected, "Not connected."))
    }

    fn receive_msg(&mut self, _msg_tag: &str) -> io::Result<Vec<u8>> {
        if let Some(ref mut stream) = self.stream {
            return read_varying_len(stream)
                .map_err(|e| io::Error::new(ErrorKind::Other, e.to_string()));
        }

        Err(io::Error::new(io::ErrorKind::NotConnected, "Not connected."))
    }

    fn wait_for_pairing_request(&mut self) -> io::Result<()> {
        let listener = TcpListener::bind("0.0.0.0:12348")?;
        let (stream, _addr) = listener.accept()?;
        stream.set_nonblocking(false)?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;

        self.stream = Some(stream);

        Ok(())
    }
}

#[cfg(feature = "http_client")]
pub struct RelayTransport {
    http_client: HttpClient,
}

#[cfg(feature = "http_client")]
impl RelayTransport {
    pub fn initialize_connect(
        server_username: String,
        server_password: String,
        server_addr: String,
    ) -> io::Result<Self> {
        let http_client = HttpClient::new(server_addr, server_username, server_password);
        http_client.send_msg("pairing_request", vec![1, 2, 3])?;
        
        let msg = http_client.receive_msg("pairing_request_ack")?;
        if msg != vec![4, 5, 6] {
            return Err(io::Error::new(io::ErrorKind::Other, "Unexpected pairing_request_ack msg"));
        }

        Ok(Self {
            http_client,
        })
    }

    pub fn initialize_no_connect(
        server_username: String,
        server_password: String,
        server_addr: String,
    ) -> io::Result<Self> {
        let http_client = HttpClient::new(server_addr, server_username, server_password);

        Ok(Self {
            http_client,
        })
    }
}

#[cfg(feature = "http_client")]
impl MessageTransport for RelayTransport {
    fn send_msg(&mut self, msg: &[u8], msg_tag: &str) -> io::Result<()> {
        // If RelayTransport is used, all msgs have to have tags.
        if msg_tag.is_empty() {
            return Err(io::Error::new(ErrorKind::InvalidInput, "msg_tag cannot be empty when using the relay transport"));
        }
        self.http_client.send_msg(msg_tag, msg.to_vec())
    }

    fn receive_msg(&mut self, msg_tag: &str) -> io::Result<Vec<u8>> {
        // If RelayTransport is used, all msgs have to have tags.
        if msg_tag.is_empty() {
            return Err(io::Error::new(ErrorKind::InvalidInput, "msg_tag cannot be empty when using the relay transport"));
        }
        self.http_client.receive_msg(msg_tag)
    }

    fn wait_for_pairing_request(&mut self) -> io::Result<()> {
        let msg = self.http_client.receive_msg("pairing_request")?;
        if msg != vec![1, 2, 3] {
            return Err(io::Error::new(io::ErrorKind::Other, "Unexpected pairing_request msg"));
        }

        self.http_client.send_msg("pairing_request_ack", vec![4, 5, 6])?;

        Ok(())
    }
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

fn read_varying_len(stream: &mut TcpStream) -> anyhow::Result<Vec<u8>> {
    let mut len_data = [0u8; 8];

    match stream.read_exact(&mut len_data) {
        Ok(()) => {}
        Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
            return Err(anyhow!(io::Error::new(
                ErrorKind::WouldBlock,
                "Length read would block",
            )))
        }
        Err(e) => return Err(anyhow!(e)),
    }

    let len = u64::from_be_bytes(len_data);

    if len > MAX_ALLOWED_MSG_LEN {
        error!("Communicated message length ({len}) exceeds the allowed length ({MAX_ALLOWED_MSG_LEN})");
        return Err(anyhow!(io::Error::new(
            ErrorKind::InvalidInput,
            "Intended message length is too large",
        )))
    }

    let mut msg = vec![0u8; usize::try_from(len)?];
    let mut offset = 0;

    while offset < msg.len() {
        match stream.read(&mut msg[offset..]) {
            Ok(0) => {
                return Err(anyhow!(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "Socket closed during read",
                )))
            }
            Ok(n) => {
                offset += n;
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                // retry a few times with a short delay
                thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return Err(anyhow!(e)),
        }
    }

    Ok(msg)
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

pub fn get_random_name() -> String {
    let mut rng = rand::rng();
    let name: String = (0..NUM_RANDOM_CHARS_FOR_NAMES)
        .map(|_| rng.sample(Alphanumeric) as char)
        .collect();

    name
}