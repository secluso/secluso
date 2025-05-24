//! Privastead app native code
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

use rand::Rng;
use std::fs;
use std::fs::File;
use std::io;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::str::FromStr;
use std::sync::MutexGuard;

use privastead_client_lib::pairing;
use privastead_client_lib::user::{Contact, KeyPackages, User};
use privastead_client_lib::video_net_info::{VideoNetInfo, VIDEONETINFO_SANITY};

#[cfg(target_os = "android")]
use crate::logger::{AndroidLogger, Logger};

#[cfg(not(target_os = "android"))]
pub struct AndroidLogger {}

#[cfg(not(target_os = "android"))]
impl AndroidLogger {
    fn d<T>(&self, _text: T) -> io::Result<()> {
        Ok(())
    }
}

// Used to generate random names.
// With 16 alphanumeric characters, the probability of collision is very low.
// Note: even if collision happens, it has no impact on
// our security guarantees. Will only cause availability issues.
const NUM_RANDOM_CHARS: u8 = 16;

pub struct Clients {
    client_motion: User,
    client_livestream: User,
    client_fcm: User,
    client_config: User,
}

impl Clients {
    pub fn new(
        app_motion_name: String,
        app_livestream_name: String,
        app_fcm_name: String,
        app_config_name: String,
        first_time: bool,
        file_dir: String,
    ) -> io::Result<Self> {
        let mut client_motion = User::new(
            app_motion_name,
            first_time,
            file_dir.clone(),
            "motion".to_string(),
        )?;

        // Make sure the groups_state files are created in case we initialize again soon.
        client_motion.save_groups_state();

        let mut client_livestream = User::new(
            app_livestream_name,
            first_time,
            file_dir.clone(),
            "livestream".to_string(),
        )?;

        client_livestream.save_groups_state();

        let mut client_fcm = User::new(
            app_fcm_name,
            first_time,
            file_dir.clone(),
            "fcm".to_string(),
        )?;

        client_fcm.save_groups_state();

        let mut client_config = User::new(
            app_config_name,
            first_time,
            file_dir.clone(),
            "config".to_string(),
        )?;

        client_config.save_groups_state();

        Ok(Self {
            client_motion,
            client_livestream,
            client_fcm,
            client_config,
        })
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
    secret: [u8; pairing::NUM_SECRET_BYTES],
) -> io::Result<KeyPackages> {
    let pairing = pairing::App::new(secret, app_key_packages);
    let app_msg = pairing.generate_msg_to_camera();
    write_varying_len(stream, &app_msg)?;
    let camera_msg = read_varying_len(stream)?;
    let camera_key_packages = pairing.process_camera_msg(camera_msg);

    Ok(camera_key_packages)
}

fn send_wifi_info(
    stream: &mut TcpStream,
    client: &mut User,
    group_name: String,
    wifi_ssid: String,
    wifi_password: String,
) -> io::Result<()> {
    let wifi_ssid_msg = client.encrypt(&wifi_ssid.into_bytes(), group_name.clone())?;
    write_varying_len(stream, &wifi_ssid_msg)?;
    let wifi_password_msg = client.encrypt(&wifi_password.into_bytes(), group_name)?;
    write_varying_len(stream, &wifi_password_msg)?;
    client.save_groups_state();

    Ok(())
}

fn pair_with_camera(
    stream: &mut TcpStream,
    app_motion_key_packages: KeyPackages,
    app_livestream_key_packages: KeyPackages,
    app_fcm_key_packages: KeyPackages,
    app_config_key_packages: KeyPackages,
    secret: [u8; pairing::NUM_SECRET_BYTES],
) -> io::Result<(
    KeyPackages,
    Vec<u8>,
    KeyPackages,
    Vec<u8>,
    KeyPackages,
    Vec<u8>,
    KeyPackages,
    Vec<u8>,
)> {
    let camera_motion_key_packages =
        perform_pairing_handshake(stream, app_motion_key_packages, secret)?;
    let camera_motion_welcome_msg = read_varying_len(stream)?;

    let camera_livestream_key_packages =
        perform_pairing_handshake(stream, app_livestream_key_packages, secret)?;
    let camera_livestream_welcome_msg = read_varying_len(stream)?;

    let camera_fcm_key_packages = perform_pairing_handshake(stream, app_fcm_key_packages, secret)?;
    let camera_fcm_welcome_msg = read_varying_len(stream)?;

    let camera_config_key_packages =
        perform_pairing_handshake(stream, app_config_key_packages, secret)?;
    let camera_config_welcome_msg = read_varying_len(stream)?;

    Ok((
        camera_motion_key_packages,
        camera_motion_welcome_msg,
        camera_livestream_key_packages,
        camera_livestream_welcome_msg,
        camera_fcm_key_packages,
        camera_fcm_welcome_msg,
        camera_config_key_packages,
        camera_config_welcome_msg,
    ))
}

fn process_welcome_message(
    client: &mut User,
    contact: Contact,
    welcome_msg: Vec<u8>,
) -> io::Result<()> {
    client.process_welcome(contact, welcome_msg)?;
    client.save_groups_state();

    Ok(())
}

pub(crate) fn my_log<T: ToString + std::fmt::Display>(logger: Option<&AndroidLogger>, log: T) {
    if logger.is_some() {
        logger.unwrap().d(log.to_string()).expect("Failed to log");
    } else {
        println!("{}", log);
    }
}

pub fn initialize(
    mut clients: MutexGuard<'_, Option<Box<Clients>>>,
    file_dir: String,
    first_time: bool,
) -> io::Result<()> {
    *clients = None;

    let app_motion_name = get_app_name(first_time, file_dir.clone(), "app_motion_name".to_string());
    let app_livestream_name = get_app_name(
        first_time,
        file_dir.clone(),
        "app_livestream_name".to_string(),
    );
    let app_fcm_name = get_app_name(first_time, file_dir.clone(), "app_fcm_name".to_string());
    let app_config_name = get_app_name(first_time, file_dir.clone(), "app_config_name".to_string());

    *clients = Some(Box::new(Clients::new(
        app_motion_name,
        app_livestream_name,
        app_fcm_name,
        app_config_name,
        first_time,
        file_dir,
    )?));

    Ok(())
}

pub fn deregister(
    mut clients: MutexGuard<'_, Option<Box<Clients>>>,
    logger: Option<&AndroidLogger>,
) {
    if clients.is_none() {
        my_log(logger, "Error: clients not initialized!");
        return;
    }

    let file_dir = clients.as_mut().unwrap().client_motion.get_file_dir();

    match clients.as_mut().unwrap().client_motion.deregister() {
        Ok(_) => {}
        Err(e) => {
            my_log(
                logger,
                format!("Error: Deregistering client_motion failed: {e}"),
            );
        }
    }

    match clients.as_mut().unwrap().client_livestream.deregister() {
        Ok(_) => {}
        Err(e) => {
            my_log(
                logger,
                format!("Error: Deregistering client_livestream failed: {e}"),
            );
        }
    }

    match clients.as_mut().unwrap().client_fcm.deregister() {
        Ok(_) => {}
        Err(e) => {
            my_log(
                logger,
                format!("Error: Deregistering client_fcm failed: {e}"),
            );
        }
    }

    match clients.as_mut().unwrap().client_config.deregister() {
        Ok(_) => {}
        Err(e) => {
            my_log(
                logger,
                format!("Error: Deregistering client_config failed: {e}"),
            );
        }
    }

    // FIXME: We currently support one camera only. Therefore, here, we delete all state files.
    let _ = fs::remove_file(file_dir.clone() + "/app_motion_name");
    let _ = fs::remove_file(file_dir.clone() + "/app_livestream_name");
    let _ = fs::remove_file(file_dir.clone() + "/app_fcm_name");
    let _ = fs::remove_file(file_dir.clone() + "/app_config_name");

    *clients = None;
}

pub fn add_camera(
    mut clients: MutexGuard<'_, Option<Box<Clients>>>,
    camera_name: String,
    camera_ip: String,
    secret_vec: Vec<u8>,
    standalone_camera: bool,
    wifi_ssid: String,
    wifi_password: String,
) -> io::Result<()> {
    if clients.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Error: clients not initialized!"),
        ));
    }

    //Make sure the camera_name is not used before for another camera.
    if clients
        .as_mut()
        .unwrap()
        .client_motion
        .get_group_name(camera_name.clone())
        .is_ok()
        || clients
            .as_mut()
            .unwrap()
            .client_livestream
            .get_group_name(camera_name.clone())
            .is_ok()
        || clients
            .as_mut()
            .unwrap()
            .client_fcm
            .get_group_name(camera_name.clone())
            .is_ok()
        || clients
            .as_mut()
            .unwrap()
            .client_config
            .get_group_name(camera_name.clone())
            .is_ok()
    {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Error: camera_name used before!"),
        ));
    }

    if secret_vec.len() != pairing::NUM_SECRET_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Error: incorrect number of bytes in secret!"),
        ));
    }
    let mut camera_secret = [0u8; pairing::NUM_SECRET_BYTES];
    camera_secret.copy_from_slice(&secret_vec[..]);

    //FIXME: port number hardcoded.
    let addr = SocketAddr::from_str(&(camera_ip + ":12348")).expect("Invalid IP address/port");
    let mut stream = TcpStream::connect(&addr)?;

    let (
        camera_motion_key_packages,
        camera_motion_welcome_msg,
        camera_livestream_key_packages,
        camera_livestream_welcome_msg,
        camera_fcm_key_packages,
        camera_fcm_welcome_msg,
        camera_config_key_packages,
        camera_config_welcome_msg,
    ) = pair_with_camera(
        &mut stream,
        clients.as_mut().unwrap().client_motion.key_packages(),
        clients.as_mut().unwrap().client_livestream.key_packages(),
        clients.as_mut().unwrap().client_fcm.key_packages(),
        clients.as_mut().unwrap().client_config.key_packages(),
        camera_secret,
    )?;

    let motion_contact = clients
        .as_mut()
        .unwrap()
        .client_motion
        .add_contact(camera_name.clone(), camera_motion_key_packages)?;

    process_welcome_message(
        &mut clients.as_mut().unwrap().client_motion,
        motion_contact,
        camera_motion_welcome_msg,
    )?;

    let livestream_contact = clients
        .as_mut()
        .unwrap()
        .client_livestream
        .add_contact(camera_name.clone(), camera_livestream_key_packages)?;

    process_welcome_message(
        &mut clients.as_mut().unwrap().client_livestream,
        livestream_contact,
        camera_livestream_welcome_msg,
    )?;

    let fcm_contact = clients
        .as_mut()
        .unwrap()
        .client_fcm
        .add_contact(camera_name.clone(), camera_fcm_key_packages)?;

    process_welcome_message(
        &mut clients.as_mut().unwrap().client_fcm,
        fcm_contact,
        camera_fcm_welcome_msg,
    )?;

    let config_contact = clients
        .as_mut()
        .unwrap()
        .client_config
        .add_contact(camera_name.clone(), camera_config_key_packages)?;

    process_welcome_message(
        &mut clients.as_mut().unwrap().client_config,
        config_contact,
        camera_config_welcome_msg,
    )?;

    if standalone_camera {
        let group_name = clients
            .as_mut()
            .unwrap()
            .client_config
            .get_group_name(camera_name.to_string())
            .unwrap();
        send_wifi_info(
            &mut stream,
            &mut clients.as_mut().unwrap().client_config,
            group_name,
            wifi_ssid,
            wifi_password,
        )?;
    }

    Ok(())
}

fn read_next_msg_from_file(file: &mut File) -> io::Result<Vec<u8>> {
    let mut len_buffer = [0u8; 4];
    let len_bytes_read = file.read(&mut len_buffer)?;
    if len_bytes_read != 4 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Error: not enough bytes to read the len from file"),
        ));
    }

    let msg_len = u32::from_be_bytes(len_buffer);

    let mut buffer = vec![0; msg_len.try_into().unwrap()];
    let bytes_read = file.read(&mut buffer)?;
    if bytes_read != msg_len as usize {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Error: not enough bytes to read the message from file"),
        ));
    }

    Ok(buffer)
}

pub fn decrypt_video(
    mut clients: MutexGuard<'_, Option<Box<Clients>>>,
    encrypted_filename: String,
) -> io::Result<String> {
    if clients.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Error: clients not initialized!"),
        ));
    }

    let file_dir = clients.as_mut().unwrap().client_motion.get_file_dir();
    let enc_pathname: String = file_dir.to_owned() + "/" + &encrypted_filename;

    let mut enc_file = fs::File::open(enc_pathname).expect("Could not open encrypted file");

    let enc_msg = read_next_msg_from_file(&mut enc_file)?;
    // The first message is a commit message
    clients
        .as_mut()
        .unwrap()
        .client_motion
        .decrypt(enc_msg, false)?;

    let enc_msg = read_next_msg_from_file(&mut enc_file)?;
    // The second message is the video info
    let dec_msg = clients
        .as_mut()
        .unwrap()
        .client_motion
        .decrypt(enc_msg, true)?;

    let info: VideoNetInfo = bincode::deserialize(&dec_msg)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    if info.sanity != *VIDEONETINFO_SANITY || info.num_msg == 0 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Error: Corrupt VideoNetInfo message.",
        ));
    }

    // The rest of the messages are video data
    //Note: we're building the filename based on the timestamp in the message.
    //The encrypted filename however is not protected and hence the server could have changed it.
    //Therefore, it is possible that the names won't match.
    //This is not an issue.
    //We should use the timestamp in the decrypted filename going forward
    //and discard the encrypted filename.
    let dec_filename = format!("video_{}.mp4", info.timestamp);
    let dec_pathname: String = file_dir.to_owned() + "/" + &dec_filename;

    let mut dec_file = fs::File::create(&dec_pathname).expect("Could not create decrypted file");

    for expected_chunk_number in 0..info.num_msg {
        let enc_msg = read_next_msg_from_file(&mut enc_file)?;
        
        let dec_msg = clients
            .as_mut()
            .unwrap()
            .client_motion
            .decrypt(enc_msg, true)?;

        // check the chunk number
        if dec_msg.len() < 8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Error: too few bytes!"),
            ));
        }

        let chunk_number = u64::from_be_bytes(dec_msg[..8].try_into().unwrap());
        if chunk_number != expected_chunk_number {
            // Need to save groups state since we might have committed an update.
            clients.as_mut().unwrap().client_motion.save_groups_state();
            let _ = fs::remove_file(&dec_pathname);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Error: invalid chunk number!"),
            ));
        }

        let _ = dec_file.write_all(&dec_msg[8..]);
    }

    // Here, we first make sure the dec_file is flushed.
    // Then, we save groups state, which persists the update.
    dec_file.flush().unwrap();
    dec_file.sync_all().unwrap();
    clients.as_mut().unwrap().client_motion.save_groups_state();

    Ok(dec_filename)
}

pub fn decrypt_fcm_timestamp(
    mut clients: MutexGuard<'_, Option<Box<Clients>>>,
    message: Vec<u8>,
) -> io::Result<String> {
    if clients.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Error: clients not initialized!"),
        ));
    }

    let dec_msg_bytes = clients
        .as_mut()
        .unwrap()
        .client_fcm
        .decrypt(message, true)?;
    clients.as_mut().unwrap().client_fcm.save_groups_state();

    let response = if dec_msg_bytes.len() == 8 {
        let timestamp: u64 = bincode::deserialize(&dec_msg_bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        if timestamp != 0 {
            timestamp.to_string()
        } else {
            "Download".to_string()
        }
    } else {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "Error: invalid len in decrypted msg ({})",
                dec_msg_bytes.len()
            ),
        ));
    };

    Ok(response)
}

pub fn get_motion_group_name(
    mut clients: MutexGuard<'_, Option<Box<Clients>>>,
    camera_name: String,
) -> io::Result<String> {
    if clients.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Error: clients not initialized!"),
        ));
    }

    clients
        .as_mut()
        .unwrap()
        .client_motion
        .get_group_name(camera_name)
}

pub fn get_livestream_group_name(
    mut clients: MutexGuard<'_, Option<Box<Clients>>>,
    camera_name: String,
) -> io::Result<String> {
    if clients.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Error: clients not initialized!"),
        ));
    }

    clients
        .as_mut()
        .unwrap()
        .client_livestream
        .get_group_name(camera_name)
}

pub fn livestream_decrypt(
    mut clients: MutexGuard<'_, Option<Box<Clients>>>,
    enc_data: Vec<u8>,
    expected_chunk_number: u64,
) -> io::Result<Vec<u8>> {
    if clients.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Error: clients not initialized!"),
        ));
    }

    let dec_data = clients
        .as_mut()
        .unwrap()
        .client_livestream
        .decrypt(enc_data, true)?;
    clients
        .as_mut()
        .unwrap()
        .client_livestream
        .save_groups_state();

    // check the chunk number
    if dec_data.len() < 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Error: too few bytes!"),
        ));
    }

    let chunk_number = u64::from_be_bytes(dec_data[..8].try_into().unwrap());
    if chunk_number != expected_chunk_number {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Error: invalid chunk number!"),
        ));
    }

    Ok(dec_data[8..].to_vec())
}

pub fn livestream_update(
    mut clients: MutexGuard<'_, Option<Box<Clients>>>,
    updates_msg: Vec<u8>,
) -> io::Result<()> {
    if clients.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Error: clients not initialized!"),
        ));
    }

    let update_commit_msgs: Vec<Vec<u8>> = bincode::deserialize(&updates_msg)
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Error: deserialization of updates_msg failed! - {e}"),
            )
        })?;

    for commit_msg in update_commit_msgs {
        let _ = clients
            .as_mut()
            .unwrap()
            .client_livestream
            .decrypt(commit_msg, false)?;
    }

    clients
        .as_mut()
        .unwrap()
        .client_livestream
        .save_groups_state();

    Ok(())
}
