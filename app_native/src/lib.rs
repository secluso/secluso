use rand::Rng;
use std::fs;
use std::fs::File;
use std::io;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::SocketAddr;
use std::net::TcpStream;
use std::str::FromStr;
use std::str;
use std::array;

use log::info;

use privastead_client_lib::pairing;
use privastead_client_lib::user::{Contact, KeyPackages, User};
use privastead_client_lib::video_net_info::{VideoNetInfo, VIDEONETINFO_SANITY};
use serde_json::json;

// Used to generate random names.
// With 16 alphanumeric characters, the probability of collision is very low.
// Note: even if collision happens, it has no impact on
// our security guarantees. Will only cause availability issues.
const NUM_RANDOM_CHARS: u8 = 16;

// FIXME: copied from camera_hub/main.rs
const NUM_CLIENTS: usize = 4;
static CLIENT_TAGS: [&str; NUM_CLIENTS] = [
    "motion",
    "livestream",
    "fcm",
    "config",
];
// indices for different clients
const MOTION: usize = 0;
const LIVESTREAM: usize = 1;
const FCM: usize = 2;
const CONFIG: usize = 3;

#[flutter_rust_bridge::frb]
pub struct Clients {
    users: [User; NUM_CLIENTS],
}

#[flutter_rust_bridge::frb]
impl Clients {
    pub fn new(
        first_time: bool,
        file_dir: String,
    ) -> io::Result<Self> {

        let users: [User; NUM_CLIENTS] = array::from_fn(|i| {
            let app_name = get_app_name(first_time, file_dir.clone(), format!("app_{}_name", CLIENT_TAGS[i]));    

            let mut user = User::new(
                app_name,
                first_time,
                file_dir.clone(),
                CLIENT_TAGS[i].to_string(),
            ).expect("User::new() for returned error.");

            // Make sure the groups_state files are created in case we initialize again soon.
            user.save_groups_state();

            user
        });

        Ok(Self {
            users,
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
) -> anyhow::Result<KeyPackages> {
    let pairing = pairing::App::new(secret, app_key_packages);
    let app_msg = pairing.generate_msg_to_camera();
    write_varying_len(stream, &app_msg)?;
    let camera_msg = read_varying_len(stream)?;
    let camera_key_packages = pairing.process_camera_msg(camera_msg)?;

    Ok(camera_key_packages)
}

fn send_wifi_info(
    stream: &mut TcpStream,
    client: &mut User,
    group_name: String,
    wifi_ssid: String,
    wifi_password: String,
) -> io::Result<()> {
    let wifi_msg = json!({
        "ssid": wifi_ssid,
        "passphrase": wifi_password
    });
    info!("Sending wifi info {}", wifi_msg);
    let wifi_info_msg = match client.encrypt(&serde_json::to_vec(&wifi_msg)?, &group_name) {
        Ok(msg) => msg,
        Err(e) => {
            info!("Failed to encrypt SSID: {e}");
            return Err(e);
        }
    };
    info!("Before Wifi Msg Sent");
    write_varying_len(stream, &wifi_info_msg)?;
    info!("After Wifi Msg Sent");

    client.save_groups_state();

    Ok(())
}

#[flutter_rust_bridge::frb]
fn pair_with_camera(
    stream: &mut TcpStream,
    camera_name: &str,
    users: &mut [User; NUM_CLIENTS],
    secret: [u8; pairing::NUM_SECRET_BYTES],
) -> anyhow::Result<()> {
    for mut user in users {
        let app_key_packages = user.key_packages();

        let camera_key_packages =
        perform_pairing_handshake(stream, app_key_packages, secret)?;

        let camera_welcome_msg = read_varying_len(stream)?;

        let contact = user
            .add_contact(camera_name, camera_key_packages)?;

        process_welcome_message(
            &mut user,
            contact,
            camera_welcome_msg,
        )?;
    }

    Ok(())
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

#[flutter_rust_bridge::frb]
pub fn add_camera(
    clients_reg: &mut Option<Box<Clients>>,
    camera_name: String,
    camera_ip: String,
    secret_vec: Vec<u8>,
    standalone_camera: bool,
    wifi_ssid: String,
    wifi_password: String,
) -> bool {
    info!("Rust: add_camera method triggered");
    if clients_reg.is_none() {
        info!("Error: clients not initialized!");
        return false;
    }

    let clients = clients_reg.as_mut().unwrap();

    //Make sure the camera_name is not used before for another camera.
    for user in &clients.as_mut().users {
        if user.get_group_name(&camera_name).is_ok() {
            info!("Error: camera_name used before!");
            return false;
        }
    }

    if secret_vec.len() != pairing::NUM_SECRET_BYTES {
        info!("Error: incorrect number of bytes in secret!");
        return false;
    }

    let mut camera_secret = [0u8; pairing::NUM_SECRET_BYTES];
    camera_secret.copy_from_slice(&secret_vec[..]);

    // Connect to the camera
    //FIXME: port number hardcoded.
    let addr = match SocketAddr::from_str(&(camera_ip + ":12348")) {
        Ok(a) => a,
        Err(e) => {
            info!("Error: invalid IP address: {e}");
            return false;
        }
    };

    let mut stream = match TcpStream::connect(&addr) {
        Ok(s) => s,
        Err(e) => {
            info!("Error: {e}");
            return false;
        }
    };

    // Perform pairing
    if let Err(e) = pair_with_camera(
        &mut stream,
        &camera_name,
        &mut clients.as_mut().users,
        camera_secret,
    ) {
        info!("Error: {e}");
        return false;
    }

    // Send Wi-Fi info
    if standalone_camera {
        let group_name = clients
            .users[CONFIG]
            .get_group_name(&camera_name)
            .unwrap();
        if let Err(e) = send_wifi_info(
            &mut stream,
            &mut clients.users[CONFIG],
            group_name,
            wifi_ssid,
            wifi_password,
        ) {
            info!("Error: {e}");
            return false;
        }
    }

    true
}

pub fn initialize(
    clients: &mut Option<Box<Clients>>,
    file_dir: String,
    first_time: bool,
) -> io::Result<bool> {
    info!("Initialize start");
    *clients = Some(Box::new(Clients::new(
        first_time,
        file_dir,
    )?));

    Ok(true)
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
    clients: &mut Option<Box<Clients>>,
    encrypted_filename: String,
) -> io::Result<String> {
    if clients.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Error: clients not initialized!"),
        ));
    }

    let file_dir = clients.as_mut().unwrap().users[MOTION].get_file_dir();
    info!("File dir: {}", file_dir);
    let enc_pathname: String = encrypted_filename;

    let mut enc_file = fs::File::open(enc_pathname).expect("Could not open encrypted file");

    let enc_msg = read_next_msg_from_file(&mut enc_file)?;
    // The first message is a commit message
    clients
        .as_mut()
        .unwrap()
        .users[MOTION]
        .decrypt(enc_msg, false)?;

    let enc_msg = read_next_msg_from_file(&mut enc_file)?;
    // The second message is the video info
    let dec_msg = clients
        .as_mut()
        .unwrap()
        .users[MOTION]
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
            .users[MOTION]
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
            clients.as_mut().unwrap().users[MOTION].save_groups_state();
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
    clients.as_mut().unwrap().users[MOTION].save_groups_state();

    Ok(dec_filename)
}

pub fn decrypt_fcm_message(
    clients: &mut Option<Box<Clients>>,
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
        .users[FCM]
        .decrypt(message, true)?;
    clients.as_mut().unwrap().users[FCM].save_groups_state();

    // New JSON structure. Ensure valid JSON string
    if let Ok(message) = str::from_utf8(&dec_msg_bytes) {
        if serde_json::from_str::<serde_json::Value>(message).is_ok() {
            return Ok(message.to_string());
        }
    }

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
    clients: &mut Option<Box<Clients>>,
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
        .users[MOTION]
        .get_group_name(&camera_name)
}

pub fn get_livestream_group_name(
    clients: &mut Option<Box<Clients>>,
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
        .users[LIVESTREAM]
        .get_group_name(&camera_name)
}

pub fn livestream_decrypt(
    clients: &mut Option<Box<Clients>>,
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
        .users[LIVESTREAM]
        .decrypt(enc_data, true)?;
    clients
        .as_mut()
        .unwrap()
        .users[LIVESTREAM]
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
    clients: &mut Option<Box<Clients>>,
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
            .users[LIVESTREAM]
            .decrypt(commit_msg, false)?;
    }

    clients
        .as_mut()
        .unwrap()
        .users[LIVESTREAM]
        .save_groups_state();

    Ok(())
}

pub fn deregister(clients: &mut Option<Box<Clients>>) {
    if clients.is_none() {
        info!("Error: clients not initialized!");
        return;
    }

    let users = &mut clients.as_mut().unwrap().users;

    for i in 0..NUM_CLIENTS {
        let file_dir = users[i].get_file_dir();

        if let Err(e) = users[i].clean() {
            info!("Error: Cleaning client_{} failed: {e}", CLIENT_TAGS[i]);
        }

        let _ = fs::remove_file(format!("{}/app_{}_name", file_dir, CLIENT_TAGS[i]));
    }


    *clients = None;
}
