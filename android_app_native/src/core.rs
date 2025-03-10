//! Privastead app native code
//!
//! Copyright (C) 2024  Ardalan Amiri Sani
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
use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::str::FromStr;
#[cfg(not(target_os = "android"))]
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::thread;
use std::time::Duration;

#[cfg(target_os = "android")]
use crate::logger::AndroidLogger;
#[cfg(target_os = "android")]
use crate::logger::Logger;
use privastead_client_lib::pairing;
use privastead_client_lib::user::{KeyPackages, User, Contact};
use privastead_client_lib::video_net_info::{VideoAckInfo, VideoNetInfo, VIDEONETINFO_SANITY};
use privastead_client_server_lib::auth;

#[cfg(not(target_os = "android"))]
struct AndroidLogger {}
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
}

impl Clients {
    pub fn new(
        app_motion_name: String,
        server_motion_stream: Option<TcpStream>,
        app_livestream_name: String,
        server_livestream_stream: Option<TcpStream>,
        app_fcm_name: String,
        server_fcm_stream: Option<TcpStream>,
        first_time: bool,
        file_dir: String,
        user_credentials: Vec<u8>,
        token: String,
        need_network: bool,
    ) -> io::Result<Self> {
        let reregister: bool = !Path::new(&(file_dir.clone() + "/registration_done")).exists();

        let mut client_motion = User::new(
            app_motion_name,
            server_motion_stream,
            first_time,
            reregister,
            file_dir.clone(),
            "motion".to_string(),
            user_credentials.clone(),
            false,
        )?;

        // Make sure the groups_state files are created in case we initialize again soon.
        client_motion.save_groups_state();

        let mut client_livestream = User::new(
            app_livestream_name,
            server_livestream_stream,
            first_time,
            reregister,
            file_dir.clone(),
            "livestream".to_string(),
            user_credentials.clone(),
            false,
        )?;

        client_livestream.save_groups_state();

        let mut client_fcm = User::new(
            app_fcm_name,
            server_fcm_stream,
            first_time,
            reregister,
            file_dir.clone(),
            "fcm".to_string(),
            user_credentials,
            false,
        )?;

        if need_network && reregister {
            client_fcm.update_token(token)?;
            fs::File::create(file_dir.clone() + "/registration_done").expect("Could not create file");
        }
        client_fcm.save_groups_state();

        Ok(Self {
            client_motion,
            client_livestream,
            client_fcm,
        })
    }
}

struct FileDownload {
    waiting_for_next_video: bool,
    num_leftover_video_msgs: u64,
    writer: RefCell<Option<BufWriter<fs::File>>>,
}

impl FileDownload {
    pub fn new() -> Self {
        Self {
            waiting_for_next_video: true,
            num_leftover_video_msgs: 0,
            writer: RefCell::new(None),
        }
    }
}

pub struct LivestreamSession {
    camera_name: String,
    buffered_bytes: Vec<u8>,
}

impl LivestreamSession {
    pub fn new(camera_name: String) -> Self {
        Self {
            camera_name,
            buffered_bytes: Vec::new(),
        }
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
    wifi_ssid: String,
    wifi_password: String,
) -> io::Result<()> {
    write_varying_len(stream, &wifi_ssid.into_bytes())?;
    write_varying_len(stream, &wifi_password.into_bytes())?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn pair_with_camera(
    camera_ip: String,
    app_motion_key_packages: KeyPackages,
    app_livestream_key_packages: KeyPackages,
    app_fcm_key_packages: KeyPackages,
    secret: [u8; pairing::NUM_SECRET_BYTES],
    standalone_camera: bool,
    wifi_ssid: String,
    wifi_password: String,
) -> io::Result<(KeyPackages, Vec<u8>, KeyPackages, Vec<u8>, KeyPackages, Vec<u8>)> {
    //FIXME: port number hardcoded.
    let addr = SocketAddr::from_str(&(camera_ip + ":12348")).expect("Invalid IP address/port");
    let mut stream = TcpStream::connect(&addr)?;
    
    let camera_motion_key_packages =
        perform_pairing_handshake(&mut stream, app_motion_key_packages, secret)?;
    let camera_motion_welcome_msg = read_varying_len(&mut stream)?;

    let camera_livestream_key_packages =
        perform_pairing_handshake(&mut stream, app_livestream_key_packages, secret)?;
    let camera_livestream_welcome_msg = read_varying_len(&mut stream)?;

    let camera_fcm_key_packages =
        perform_pairing_handshake(&mut stream, app_fcm_key_packages, secret)?;
    let camera_fcm_welcome_msg = read_varying_len(&mut stream)?;

    if standalone_camera {
        send_wifi_info(&mut stream, wifi_ssid, wifi_password)?;
    }

    Ok((
        camera_motion_key_packages,
        camera_motion_welcome_msg,
        camera_livestream_key_packages,
        camera_livestream_welcome_msg,
        camera_fcm_key_packages,
        camera_fcm_welcome_msg,
    ))
}

fn process_welcome_message(client: &mut User, contact: Contact, welcome_msg: Vec<u8>) -> io::Result<()> {
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
    server_ip: String,
    token: String,
    file_dir: String,
    first_time: bool,
    user_credentials: Vec<u8>,
    need_network: bool,
    logger: Option<&AndroidLogger>,
) -> bool {
    *clients = None;

    if user_credentials.len() != (auth::NUM_USERNAME_BYTES + auth::NUM_SECRET_BYTES) {
        my_log(
            logger,
            "Error: incorrect number of bytes in user credentials!",
        );
        return false;
    }

    // FIXME: this part of the code has a lot of similarity to main() in camera.
    let delivery_service_addr: String = server_ip + ":12346";
    let mut motion_stream: Option<TcpStream> = None;
    let mut livestream_stream: Option<TcpStream> = None;
    let mut fcm_stream: Option<TcpStream> = None;

    if need_network {
        match TcpStream::connect(delivery_service_addr.clone()) {
            Ok(stream) => motion_stream = Some(stream),
            Err(_) => {
                let _ = fs::remove_file(file_dir.clone() + "/registration_done");
            }
        }

        match TcpStream::connect(delivery_service_addr.clone()) {
            Ok(stream) => livestream_stream = Some(stream),
            Err(_) => {
                let _ = fs::remove_file(file_dir.clone() + "/registration_done");
            }
        }

        match TcpStream::connect(delivery_service_addr) {
            Ok(stream) => fcm_stream = Some(stream),
            Err(_) => {
                let _ = fs::remove_file(file_dir.clone() + "/registration_done");
            }
        }

        if motion_stream.is_none() || livestream_stream.is_none() || fcm_stream.is_none() {
            my_log(
                logger,
                format!("Error: could not connect to the server!"),
            );
            return false;
        }
    }

    let app_motion_name = get_app_name(first_time, file_dir.clone(), "app_motion_name".to_string());
    let app_livestream_name = get_app_name(
        first_time,
        file_dir.clone(),
        "app_livestream_name".to_string(),
    );
    let app_fcm_name = get_app_name(first_time, file_dir.clone(), "app_fcm_name".to_string());

    *clients = Some(Box::new(
        match Clients::new(
            app_motion_name,
            motion_stream,
            app_livestream_name,
            livestream_stream,
            app_fcm_name,
            fcm_stream,
            first_time,
            file_dir,
            user_credentials,
            token,
            need_network,
        ) {
            Ok(c) => c,
            Err(e) => {
                my_log(
                    logger,
                    format!("Error: initialize() failed: {e}"),
                );
                return false;
            },
        },
    ));

    true
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

    // FIXME: We currently support one camera only. Therefore, here, we delete all state files.
    let _ = fs::remove_file(file_dir.clone() + "/registration_done");
    let _ = fs::remove_file(file_dir.clone() + "/app_motion_name");
    let _ = fs::remove_file(file_dir.clone() + "/app_livestream_name");
    let _ = fs::remove_file(file_dir.clone() + "/app_fcm_name");

    *clients = None;
}

pub fn update_token(
    mut clients: MutexGuard<'_, Option<Box<Clients>>>,
    token: String,
    logger: Option<&AndroidLogger>,
) -> bool {
    if clients.is_none() {
        my_log(logger, "Error: clients not initialized!");
        return false;
    }

    match clients.as_mut().unwrap().client_fcm.update_token(token) {
        Ok(_) => {}
        Err(e) => {
            my_log(logger, format!("Error: {e}"));
            return false;
        }
    }

    true
}

pub fn add_camera(
    mut clients: MutexGuard<'_, Option<Box<Clients>>>,
    camera_name: String,
    camera_ip: String,
    secret_vec: Vec<u8>,
    standalone_camera: bool,
    wifi_ssid: String,
    wifi_password: String,
    logger: Option<&AndroidLogger>,
) -> bool {
    if clients.is_none() {
        my_log(logger, "Error: clients not initialized!");
        return false;
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
            .client_fcm
            .get_group_name(camera_name.clone())
            .is_ok()
        || clients
            .as_mut()
            .unwrap()
            .client_livestream
            .get_group_name(camera_name.clone())
            .is_ok()
    {
        my_log(logger, "Error: camera_name used before!");
        return false;
    }

    if secret_vec.len() != pairing::NUM_SECRET_BYTES {
        my_log(logger, "Error: incorrect number of bytes in secret!");
        return false;
    }
    let mut camera_secret = [0u8; pairing::NUM_SECRET_BYTES];
    camera_secret.copy_from_slice(&secret_vec[..]);

    let (camera_motion_key_packages,
        camera_motion_welcome_msg,
        camera_livestream_key_packages,
        camera_livestream_welcome_msg,
        camera_fcm_key_packages,
        camera_fcm_welcome_msg) =
        match pair_with_camera(
            camera_ip,
            clients.as_mut().unwrap().client_motion.key_packages(),
            clients.as_mut().unwrap().client_livestream.key_packages(),
            clients.as_mut().unwrap().client_fcm.key_packages(),
            camera_secret,
            standalone_camera,
            wifi_ssid,
            wifi_password,
        ) {
            Ok(c) => c,
            Err(e) => {
                my_log(logger, format!("Error: {e}"));
                return false;
            }
        };

    let motion_contact = clients
        .as_mut()
        .unwrap()
        .client_motion
        .add_contact(camera_name.clone(), camera_motion_key_packages).unwrap();

    match process_welcome_message(
        &mut clients.as_mut().unwrap().client_motion,
        motion_contact,
        camera_motion_welcome_msg,
    ) {
        Ok(_) => {}
        Err(e) => {
            my_log(logger, format!("Error: {e}"));
            return false;
        }
    }

    let livestream_contact = clients
        .as_mut()
        .unwrap()
        .client_livestream
        .add_contact(camera_name.clone(), camera_livestream_key_packages).unwrap();
    
    match process_welcome_message(
        &mut clients.as_mut().unwrap().client_livestream,
        livestream_contact,
        camera_livestream_welcome_msg,
    ) {
        Ok(_) => {}
        Err(e) => {
            my_log(logger, format!("Error: {e}"));
            return false;
        }
    }

    let fcm_contact = clients
        .as_mut()
        .unwrap()
        .client_fcm
        .add_contact(camera_name.clone(), camera_fcm_key_packages).unwrap();

    match process_welcome_message(
        &mut clients.as_mut().unwrap().client_fcm,
        fcm_contact,
        camera_fcm_welcome_msg,
    ) {
        Ok(_) => {}
        Err(e) => {
            my_log(logger, format!("Error: {e}"));
            return false;
        }
    }

    true
}

///FIXME/TODO: the receiving logic here assumes that if there are no more messages
///to read from the server, it means that we have fully downloaded the files that
///we've started to download. That could not be the case if the cameras somehow
///get delayed in between sending messages of the same video. If this happens,
///we will lose some videos.
pub fn receive(
    mut clients: MutexGuard<'_, Option<Box<Clients>>>,
    logger: Option<&AndroidLogger>,
) -> String {
    let mut response: String = "None".to_string();
    let mut recvd_videos: Vec<String> = vec![];
    let mut num_finished_videos: usize = 0;
    let mut downloads: HashMap<String, FileDownload> = HashMap::new();
    let mut acks: Vec<VideoAckInfo> = vec![];
    let mut callback_error = false;

    if clients.is_none() {
        my_log(logger, "Error: clients not initialized!");
        return "Error".to_string();
    }

    let file_dir = clients.as_mut().unwrap().client_motion.get_file_dir();

    loop {
        let callback = |msg_bytes: Vec<u8>, contact_name: String| -> io::Result<()> {
            downloads.entry(contact_name.clone()).or_insert_with(FileDownload::new);
            let download = downloads.get_mut(&contact_name).unwrap();

            if download.waiting_for_next_video {
                let info: VideoNetInfo = match bincode::deserialize(&msg_bytes) {
                    Ok(inf) => inf,
                    Err(e) => {
                        // This could happen when the app terminates while it's receiving messages.
                        // The next time the app calls listen(), it could get here.
                        my_log(
                            logger,
                            format!("Error deserializing VideoNetInfo: {e} -  Dropping message."),
                        );
                        callback_error = true;
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            format!("Error deserializing VideoNetInfo: {e} -  Dropping message."),
                        ));
                    }
                };

                if info.sanity != *VIDEONETINFO_SANITY {
                    my_log(logger, "Error: not a VideoNetInfo message.".to_string());
                    callback_error = true;
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "Error: not a VideoNetInfo message.",
                    ));
                }

                if info.num_msg == 0 {
                    // A notification
                    let ack = VideoAckInfo::new(info.timestamp, false);
                    if !acks.contains(&ack) {
                        // This could happen if there are multiple notifications
                        // for the same video.
                        acks.push(ack);
                    }
                } else {
                    // A video
                    let filename: String = "video_".to_string().to_owned()
                        + &contact_name
                        + "_"
                        + &info.timestamp.to_string()
                        + ".mp4";
                    let pathname: String =
                        file_dir.to_owned() + "/" + &filename.clone();

                    let file = fs::File::create(pathname).expect("Could not create file");
                    download.writer = RefCell::new(Some(BufWriter::new(file)));
                    download.waiting_for_next_video = false;
                    download.num_leftover_video_msgs = info.num_msg;
                    recvd_videos.push(filename);
                    let ack = VideoAckInfo::new(info.timestamp, true);
                    if !acks.contains(&ack) {
                        // This could happen if the same video has been sent multiple times.
                        acks.push(ack);
                    }
                }
            } else {
                download
                    .writer
                    .borrow_mut()
                    .as_mut()
                    .unwrap()
                    .write_all(&msg_bytes)
                    .expect("Could not write data to file");
                download.num_leftover_video_msgs -= 1;
                if download.num_leftover_video_msgs == 0 {
                    download.writer = RefCell::new(None);
                    download.waiting_for_next_video = true;
                    num_finished_videos += 1;
                }
            }

            Ok(())
        };

        let msg_count: u64 = match clients.as_mut().unwrap().client_motion.receive(callback) {
            Ok(mc) => mc,
            Err(e) => {
                my_log(logger, format!("Error: {e}"));
                clients.as_mut().unwrap().client_motion.save_groups_state();
                //We shouldn't drain the messages here. We might end up here when the read blocks
                //since Android blocks network activity. If we try to read here, we'll keep getting
                //blocked.
                return "Error".to_string();
            }
        };

        if callback_error {
            my_log(logger, "Error: Detected callback error.".to_string());
            //Drain all remaining messages before returning an error
            //FIXME: this code is pretty much identical to the drain code in livestream_end.
            let need_to_wait: RefCell<bool> = RefCell::new(true);
            let mut callback_drain =
                |_msg_bytes: Vec<u8>, _contact_name: String| -> io::Result<()> { Ok(()) };

            while *need_to_wait.borrow() {
                match clients
                    .as_mut()
                    .unwrap()
                    .client_motion
                    .receive(&mut callback_drain)
                {
                    Ok(mc) => {
                        if mc == 0 {
                            *need_to_wait.borrow_mut() = false;
                        }
                    }
                    Err(e) => {
                        my_log(logger, format!("Error: {e}"));
                        clients.as_mut().unwrap().client_motion.save_groups_state();
                        return "Error".to_string();
                    }
                };
            }
            clients.as_mut().unwrap().client_motion.save_groups_state();
            return "Error".to_string();
        }

        // We add a video filename to recvd_videos as soon as start receiving it.
        // Here, we want to make sure the video is fully received before we return.
        if (msg_count == 0) && (recvd_videos.len() == num_finished_videos) {
            break;
        }
    }

    // We need to save groups/key store state after all the receive and before any send.
    // This is because our calls to receive might have processed a staged commit.
    // When we send a message, the camera will assume that we have received and merged
    // the commit. That's why we need to save state here so that the assumption is correct.
    clients.as_mut().unwrap().client_motion.save_groups_state();

    if !recvd_videos.is_empty() {
        response = "".to_string();

        for i in 0..recvd_videos.len() {
            response = response + &recvd_videos[i];

            if i < (recvd_videos.len() - 1) {
                response += ",";
            }
        }
    }

    // Send acks
    // FIXME: send all acks to all cameras!
    for camera_name in downloads.keys() {
        let group_name = clients
            .as_mut()
            .unwrap()
            .client_motion
            .get_group_name(camera_name.to_string())
            .unwrap();
        match clients
            .as_mut()
            .unwrap()
            .client_motion
            .send(&bincode::serialize(&acks).unwrap(), group_name)
        {
            Ok(_) => {}
            Err(e) => {
                my_log(logger, format!("Error: Failed to send ack message ({e})"));
            }
        }
    }
    clients.as_mut().unwrap().client_motion.save_groups_state();

    response
}

pub fn decrypt(
    mut clients: MutexGuard<'_, Option<Box<Clients>>>,
    message: Vec<u8>,
    logger: Option<&AndroidLogger>,
) -> String {
    if clients.is_none() {
        my_log(logger, "Error: clients not initialized!");
        return "Error".to_string();
    }

    let mut response: String = "None".to_string();

    let callback = |msg_bytes: Vec<u8>, contact_name: String| -> io::Result<()> {
        if msg_bytes.len() == 8 {
            let timestamp: u64 = bincode::deserialize(&msg_bytes).unwrap();
            if timestamp != 0 {
                response = contact_name + "_" + &timestamp.to_string();
            } else {
                response = "Download".to_string();
            }
        }
        Ok(())
    };

    match clients
        .as_mut()
        .unwrap()
        .client_fcm
        .receive_fcm(callback, message)
    {
        Ok(mc) => mc,
        Err(e) => {
            my_log(logger, format!("Error: {e}"));
            return "Error".to_string();
        }
    };
    clients.as_mut().unwrap().client_fcm.save_groups_state();

    response
}

pub fn livestream_start(
    mut clients: MutexGuard<'_, Option<Box<Clients>>>,
    mut session: MutexGuard<'_, Option<Box<LivestreamSession>>>,
    camera_name: String,
    logger: Option<&AndroidLogger>,
) -> bool {
    if clients.is_none() {
        my_log(logger, "Error: clients not initialized!");
        return false;
    }

    //Return error if we're already livestreaming.
    if session.is_some() {
        my_log(logger, "Error: Already in a livestream session!");
        return false;
    }

    *session = Some(Box::new(LivestreamSession::new(camera_name.clone())));

    // The drain_messages call has two purposes:
    // 1) Before we start the stream, we receive a message from the server.
    // This is because on the first stream, we need to receive the welcome message
    // that was sent by the camera in the initialization phase.
    // 2) We drain any leftover messages from the previous stream,
    // which did not get successfully drained in livestream_end.
    drain_messages(&mut clients);

    let start_signal = vec![13];
    let group_name = clients
        .as_mut()
        .unwrap()
        .client_livestream
        .get_group_name(camera_name)
        .unwrap();
    match clients
        .as_mut()
        .unwrap()
        .client_livestream
        .send(&start_signal, group_name)
    {
        Ok(_) => {}
        Err(e) => {
            my_log(logger, format!("Error: {e}"));
            return false;
        }
    }
    clients
        .as_mut()
        .unwrap()
        .client_livestream
        .save_groups_state();

    true
}

fn drain_messages(
    clients: &mut MutexGuard<'_, Option<Box<Clients>>>,
) {
    let mut need_to_wait = true;
    let mut callback = |_msg_bytes: Vec<u8>, _contact_name: String| -> io::Result<()> { Ok(()) };

    while need_to_wait {
        match clients
            .as_mut()
            .unwrap()
            .client_livestream
            .receive(&mut callback)
        {
            Ok(mc) => {
                if mc == 0 {
                    need_to_wait = false;
                }
            }
            Err(_) => {
                return;
            }
        };
        clients
            .as_mut()
            .unwrap()
            .client_livestream
            .save_groups_state();
    }
}

pub fn livestream_end(
    mut clients: MutexGuard<'_, Option<Box<Clients>>>,
    mut session: MutexGuard<'_, Option<Box<LivestreamSession>>>,
    logger: Option<&AndroidLogger>,
) -> bool {
    if clients.is_none() {
        my_log(logger, "Error: clients not initialized!");
        return false;
    }

    //First, wait a few seconds to make sure the camera stops streaming.
    thread::sleep(Duration::from_secs(5));

    //Then drain all the leftover messages.
    //This helps drain leftover messages from the previous stream.
    drain_messages(&mut clients);
    *session = None;

    true
}

pub fn livestream_read(
    mut clients: MutexGuard<'_, Option<Box<Clients>>>,
    mut session: MutexGuard<'_, Option<Box<LivestreamSession>>>,
    read_length: usize,
    logger: Option<&AndroidLogger>,
) -> Vec<u8> {
    let mut byte_array: Vec<u8> = vec![];

    if clients.is_none() || session.is_none() {
        my_log(logger, "Error: clients or session not initialized!");
        //FIXME: There's no good way to return an error. So we panic instead.
        panic!("Error: clients or session not initialized!");
    }

    if read_length <= session.as_mut().unwrap().buffered_bytes.len() {
        let bytes: Vec<u8> = session
            .as_mut()
            .unwrap()
            .buffered_bytes
            .drain(..read_length)
            .collect();
        byte_array.extend(bytes);

        return byte_array;
    }

    while read_length > session.as_mut().unwrap().buffered_bytes.len() {
        let callback = |msg_bytes: Vec<u8>, contact_name: String| -> io::Result<()> {
            if session.as_mut().unwrap().camera_name == contact_name {
                session
                    .as_mut()
                    .unwrap()
                    .buffered_bytes
                    .extend_from_slice(&msg_bytes);
            }

            Ok(())
        };
        match clients
            .as_mut()
            .unwrap()
            .client_livestream
            .receive(callback)
        {
            Ok(0) => {
                let empty_array: Vec<u8> = vec![];
                return empty_array;
            }
            Ok(_) => {}
            Err(e) => {
                my_log(logger, format!("Error: {e}"));
                //FIXME: There's no good way to return an error. So we panic instead.
                panic!("Error: {e}");
            }
        };
        clients
            .as_mut()
            .unwrap()
            .client_livestream
            .save_groups_state();
    }

    //FIXME: a couple of lines here are identical to the then-branch of the if condition earlier
    let bytes: Vec<u8> = session
        .as_mut()
        .unwrap()
        .buffered_bytes
        .drain(..read_length)
        .collect();
    byte_array.extend(bytes);

    byte_array
}

#[test]
fn receive_video_single_init() {
    use std::{thread, time::Duration};

    let file = fs::File::open("user_credentials").expect("Cannot open file to send");
    let mut reader =
        BufReader::with_capacity(file.metadata().unwrap().len().try_into().unwrap(), file);
    let user_credentials = reader.fill_buf().unwrap();

    let file2 = fs::File::open("camera_secret").expect("Cannot open file to send");
    let mut reader2 =
        BufReader::with_capacity(file2.metadata().unwrap().len().try_into().unwrap(), file2);
    let secret_vec = reader2.fill_buf().unwrap();

    let clients: Mutex<Option<Box<Clients>>> = Mutex::new(None);
    initialize(
        clients.lock().unwrap(),
        "127.0.0.1".to_string(),
        "".to_string(),
        "test_data".to_string(),
        true,
        user_credentials.to_vec(),
        None,
    );
    add_camera(
        clients.lock().unwrap(),
        "Home".to_string(),
        "127.0.0.1".to_string(),
        secret_vec.to_vec(),
        None,
    );

    loop {
        thread::sleep(Duration::from_secs(1));
        println!("Start receive");
        receive(clients.lock().unwrap(), None);
        println!("End receive");
    }

    deregister(clients.lock().unwrap(), None);
}

#[test]
fn receive_video_multi_init() {
    use std::{thread, time::Duration};

    let file = fs::File::open("user_credentials").expect("Cannot open file to send");
    let mut reader =
        BufReader::with_capacity(file.metadata().unwrap().len().try_into().unwrap(), file);
    let user_credentials = reader.fill_buf().unwrap();

    let file2 = fs::File::open("camera_secret").expect("Cannot open file to send");
    let mut reader2 =
        BufReader::with_capacity(file2.metadata().unwrap().len().try_into().unwrap(), file2);
    let secret_vec = reader2.fill_buf().unwrap();

    let clients: Mutex<Option<Box<Clients>>> = Mutex::new(None);
    initialize(
        clients.lock().unwrap(),
        "127.0.0.1".to_string(),
        "".to_string(),
        "test_data".to_string(),
        true,
        user_credentials.to_vec(),
        None,
    );
    add_camera(
        clients.lock().unwrap(),
        "Home".to_string(),
        "127.0.0.1".to_string(),
        secret_vec.to_vec(),
        None,
    );
    initialize(
        clients.lock().unwrap(),
        "127.0.0.1".to_string(),
        "".to_string(),
        "test_data".to_string(),
        false,
        user_credentials.to_vec(),
        None,
    );

    loop {
        thread::sleep(Duration::from_secs(1));
        receive(clients.lock().unwrap(), None);
    }

    deregister(clients.lock().unwrap(), None);
}

#[test]
fn receive_video_multi_init_loop() {
    use std::{thread, time::Duration};

    let file = fs::File::open("user_credentials").expect("Cannot open file to send");
    let mut reader =
        BufReader::with_capacity(file.metadata().unwrap().len().try_into().unwrap(), file);
    let user_credentials = reader.fill_buf().unwrap();

    let file2 = fs::File::open("camera_secret").expect("Cannot open file to send");
    let mut reader2 =
        BufReader::with_capacity(file2.metadata().unwrap().len().try_into().unwrap(), file2);
    let secret_vec = reader2.fill_buf().unwrap();

    let clients: Mutex<Option<Box<Clients>>> = Mutex::new(None);
    initialize(
        clients.lock().unwrap(),
        "127.0.0.1".to_string(),
        "".to_string(),
        "test_data".to_string(),
        true,
        user_credentials.to_vec(),
        None,
    );
    add_camera(
        clients.lock().unwrap(),
        "Home".to_string(),
        "127.0.0.1".to_string(),
        secret_vec.to_vec(),
        None,
    );

    loop {
        thread::sleep(Duration::from_secs(1));
        initialize(
            clients.lock().unwrap(),
            "127.0.0.1".to_string(),
            "".to_string(),
            "test_data".to_string(),
            false,
            user_credentials.to_vec(),
            None,
        );
        println!("Start receive");
        receive(clients.lock().unwrap(), None);
        println!("End receive");
    }

    deregister(clients.lock().unwrap(), None);
}

#[test]
fn receive_video_loop_phase_one() {
    use std::{thread, time::Duration};

    let file = fs::File::open("user_credentials").expect("Cannot open file to send");
    let mut reader =
        BufReader::with_capacity(file.metadata().unwrap().len().try_into().unwrap(), file);
    let user_credentials = reader.fill_buf().unwrap();

    let file2 = fs::File::open("camera_secret").expect("Cannot open file to send");
    let mut reader2 =
        BufReader::with_capacity(file2.metadata().unwrap().len().try_into().unwrap(), file2);
    let secret_vec = reader2.fill_buf().unwrap();

    let clients: Mutex<Option<Box<Clients>>> = Mutex::new(None);
    initialize(
        clients.lock().unwrap(),
        "127.0.0.1".to_string(),
        "".to_string(),
        "test_data".to_string(),
        true,
        user_credentials.to_vec(),
        None,
    );
    add_camera(
        clients.lock().unwrap(),
        "Home".to_string(),
        "127.0.0.1".to_string(),
        secret_vec.to_vec(),
        None,
    );

    loop {
        initialize(
            clients.lock().unwrap(),
            "127.0.0.1".to_string(),
            "".to_string(),
            "test_data".to_string(),
            false,
            user_credentials.to_vec(),
            None,
        );
        println!("Start receive");
        receive(clients.lock().unwrap(), None);
        println!("End receive");
        thread::sleep(Duration::from_secs(60));
    }

    deregister(clients.lock().unwrap(), None);
}

#[test]
fn receive_video_loop_phase_two() {
    use std::{thread, time::Duration};

    let file = fs::File::open("user_credentials").expect("Cannot open file to send");
    let mut reader =
        BufReader::with_capacity(file.metadata().unwrap().len().try_into().unwrap(), file);
    let user_credentials = reader.fill_buf().unwrap();

    let clients: Mutex<Option<Box<Clients>>> = Mutex::new(None);

    loop {
        initialize(
            clients.lock().unwrap(),
            "127.0.0.1".to_string(),
            "".to_string(),
            "test_data".to_string(),
            false,
            user_credentials.to_vec(),
            None,
        );
        println!("Start receive");
        receive(clients.lock().unwrap(), None);
        println!("End receive");
        thread::sleep(Duration::from_secs(60));
    }

    deregister(clients.lock().unwrap(), None);
}

#[test]
fn receive_video_two_cameras() {
    use std::{thread, time::Duration};
    use std::collections::HashMap;

    let camera_names: [String; 2] = ["Home1".to_string(), "Home2".to_string()];

    let file = fs::File::open("user_credentials").expect("Cannot open file to send");
    let mut reader =
        BufReader::with_capacity(file.metadata().unwrap().len().try_into().unwrap(), file);
    let user_credentials = reader.fill_buf().unwrap();

    let mut clients_all: HashMap<String, Mutex<Option<Box<Clients>>>> = HashMap::new();

    fs::remove_dir_all("test_data").unwrap();
    fs::create_dir("test_data").unwrap();

    for i in 0..2 {
        let clients = clients_all.entry(camera_names[i].clone()).or_insert(Mutex::new(None)).lock().unwrap();
        let folder_path = "test_data/".to_string() + &camera_names[i];

        fs::create_dir(folder_path.clone()).unwrap();

        initialize(
            clients,
            "127.0.0.1".to_string(),
            "".to_string(),
            folder_path,
            true,
            user_credentials.to_vec(),
            None,
        );

        let file2 = fs::File::open("camera_secret").expect("Cannot open file to send");
        let mut reader2 =
            BufReader::with_capacity(file2.metadata().unwrap().len().try_into().unwrap(), file2);
        let secret_vec = reader2.fill_buf().unwrap();

        let clients = clients_all.entry(camera_names[i].clone()).or_insert(Mutex::new(None)).lock().unwrap();

        add_camera(
            clients,
            camera_names[i].clone(),
            "127.0.0.1".to_string(),
            secret_vec.to_vec(),
            None,
        );
        println!("Camera added");

        // Camera hub instances listen on the same port.
        // Therefore, in the test here, we run them one by one manually
        // and connect to them here.
        if i == 0 {
            thread::sleep(Duration::from_secs(20));
        }
    }

    loop {
        for i in 0..2 {
            let clients = clients_all.entry(camera_names[i].clone()).or_insert(Mutex::new(None)).lock().unwrap();
            thread::sleep(Duration::from_secs(1));
            println!("Start receive");
            receive(clients, None);
            println!("End receive");
        }
    }

    for i in 0..2 {
        let clients = clients_all.entry(camera_names[i]).or_insert(Mutex::new(None)).lock().unwrap();
        deregister(clients, None);
    }
}
