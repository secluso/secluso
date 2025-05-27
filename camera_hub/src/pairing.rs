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

use image::Luma;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::random::OpenMlsRand;
use openmls_traits::OpenMlsProvider;
use privastead_client_lib::pairing;
use privastead_client_lib::user::{KeyPackages, User};
use qrcode::QrCode;
use rand::Rng;
use std::fs;
use std::fs::File;
use std::io;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::{thread, time::Duration};
use crate::traits::Camera;
use crate::{Clients, Client, CONFIG};

// Used to generate random names.
// With 16 alphanumeric characters, the probability of collision is very low.
// Note: even if collision happens, it has no impact on
// our security guarantees. Will only cause availability issues.
const NUM_RANDOM_CHARS: u8 = 16;

// Used to ensure there can't be attempted concurrent pairing
static LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn write_varying_len(stream: &mut TcpStream, msg: &[u8]) {
    // FIXME: is u64 necessary?
    let len = msg.len() as u64;
    let len_data = len.to_be_bytes();

    stream.write_all(&len_data).unwrap();
    stream.write_all(msg).unwrap();
    stream.flush().unwrap();
}

fn read_varying_len(stream: &mut TcpStream) -> Vec<u8> {
    let mut len_data = [0u8; 8];
    stream.read_exact(&mut len_data).unwrap();
    let len = u64::from_be_bytes(len_data);

    let mut msg = vec![0u8; len as usize];
    stream.read_exact(&mut msg).unwrap();

    msg
}

fn perform_pairing_handshake(
    stream: &mut TcpStream,
    camera_key_packages: KeyPackages,
    camera_secret: [u8; pairing::NUM_SECRET_BYTES],
) -> KeyPackages {
    let pairing = pairing::Camera::new(camera_secret, camera_key_packages);

    let app_msg = read_varying_len(stream);
    let (app_key_packages, camera_msg) = pairing.process_app_msg_and_generate_msg_to_app(app_msg);
    write_varying_len(stream, &camera_msg);

    app_key_packages
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
    input_camera_secret: Vec<u8>,
) -> KeyPackages {
    if input_camera_secret.len() != pairing::NUM_SECRET_BYTES {
        panic!("Invalid number of bytes in secret!");
    }

    let mut camera_secret = [0u8; pairing::NUM_SECRET_BYTES];
    camera_secret.copy_from_slice(&input_camera_secret[..]);

    let app_key_packages = perform_pairing_handshake(stream, camera_key_packages, camera_secret);

    app_key_packages
}

fn create_group_and_invite(
    stream: &mut TcpStream,
    client: &mut Client,
    app_key_packages: KeyPackages,
) -> io::Result<()> {
    let app_contact = client.user.add_contact("app", app_key_packages)?;
    debug!("Added contact.");

    client.user.create_group(&client.group_name);
    client.user.save_groups_state();
    debug!("Created group.");

    let welcome_msg_vec = client.user.invite(&app_contact, &client.group_name).map_err(|e| {
        error!("invite() returned error:");
        e
    })?;
    client.user.save_groups_state();
    debug!("App invited to the group.");

    write_varying_len(stream, &welcome_msg_vec);

    Ok(())
}

fn decrypt_msg(client: &mut User, msg: Vec<u8>) -> io::Result<Vec<u8>> {
    let decrypted_msg = client.decrypt(msg, true)?;
    client.save_groups_state();

    Ok(decrypted_msg)
}

fn get_wifi_info_and_connect(stream: &mut TcpStream, client: &mut User) -> io::Result<()> {
    let ssid_msg = read_varying_len(stream);
    let ssid_bytes = decrypt_msg(client, ssid_msg)?;
    let ssid = String::from_utf8(ssid_bytes).expect("Invalid UTF-8 for WiFi SSID");
    let password_msg = read_varying_len(stream);
    let password_bytes = decrypt_msg(client, password_msg)?;
    let password = String::from_utf8(password_bytes).expect("Invalid UTF-8 for WiFi password");

    // Disable the Hotspot first
    let _ = Command::new("sh")
        .arg("-c")
        .arg("nmcli connection down id Hotspot")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    // Wait a bit for Hotspot to get disabled
    thread::sleep(Duration::from_secs(5));

    // Connect to SSID
    let _ = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "nmcli device wifi connect \"{}\" password \"{}\"",
            ssid.clone(),
            password
        ))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    // Set up autoconnect to SSID on reboot
    let _ = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "nmcli connection modify \"{}\" connection.autoconnect yes",
            ssid
        ))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    Ok(())
}

pub fn create_wifi_hotspot() {
    let _ = Command::new("sh")
        .arg("-c")
        .arg("nmcli device wifi hotspot ssid Privastead password \"12345678\"")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
}

#[allow(clippy::too_many_arguments)]
pub fn create_camera_groups(
    camera: &dyn Camera,
    clients: &mut Clients,
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

    // Wait for the app to connect.
    let listener = TcpListener::bind("0.0.0.0:12348").unwrap();
    let (mut stream, _) = listener.accept().unwrap();

    for client in &mut *clients {
        let app_key_packages =
            pair_with_app(&mut stream, client.user.key_packages(), secret.clone());

        create_group_and_invite(
            &mut stream,
            client,
            app_key_packages,
        )?;
    }

    if input_camera_secret.is_none() {
        let _ = fs::remove_file(format!(
            "camera_{}_secret_qrcode.png",
            camera.get_name().replace(" ", "_").to_lowercase()
        ));
    }

    // FIXME: a fatal crash point here. The app thinks that pairing is finalized, but
    // not the camera.

    // Send WiFi info to the app.
    if connect_to_wifi {
        get_wifi_info_and_connect(&mut stream, &mut clients[CONFIG].user)?;
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

        //FIXME: how many random characters should we use here?
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

pub fn read_user_credentials(pathname: &str) -> Vec<u8> {
    let file = fs::File::open(pathname).expect("Could not open user_credentials file");
    let mut reader =
        BufReader::with_capacity(file.metadata().unwrap().len().try_into().unwrap(), file);
    let data = reader.fill_buf().unwrap();

    data.to_vec()
}