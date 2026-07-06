use crate::core::initialize_mls_clients;
use crate::traits::Camera;
use crate::version::camera_version_info;
use openmls::key_packages::KeyPackage;
use secluso_client_lib::mls_client::MlsClient;
use secluso_client_lib::mls_clients::MlsClients;
use secluso_client_lib::pairing::{self, MessageTransport};
use std::io::ErrorKind;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use std::thread::sleep;
use std::{fs, io};

#[cfg(feature = "ip")]
use secluso_client_lib::pairing::generate_ip_camera_secret;

cfg_if::cfg_if! {
    if #[cfg(feature = "raspberry")] {
        use secluso_client_lib::mls_clients::CONFIG;
        use secluso_client_lib::pairing::TcpStreamTransport;
        use std::fs::File;
        use std::io::Write;
        use crate::pairing::wifi::{self, create_wifi_hotspot};
        use crate::pairing::io::read_parse_full_credentials;
        use std::process::Command;
        use secluso_client_lib::http_client::HttpClient;
    } else if #[cfg(feature = "test")] {
        use secluso_client_lib::mls_clients::CONFIG;
        use secluso_client_lib::pairing::TcpStreamTransport;
        use std::fs::File;
        use std::io::Write;
    } else if #[cfg(feature = "android")] {
        use crate::core::get_server_credentials;
        use secluso_client_lib::pairing::{RelayTransport, generate_android_camera_secret};
    }
}

// Used to ensure there can't be attempted concurrent pairing
static LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[allow(clippy::too_many_arguments)]
pub fn pair_all(
    camera: &dyn Camera,
    mls_clients: &mut MlsClients,
    input_camera_secret: Option<Vec<u8>>,
) -> anyhow::Result<()> {
    // Ensure that two cameras don't attempt to pair at the same time (as this would introduce an error when opening two of the same port simultaneously)
    let _lock = LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("Another user of the LOCK mutex panicked while holding the mutex");

    let secret = {
        #[cfg(any(feature = "raspberry", feature = "test"))]
        {
            assert!(
                input_camera_secret.is_some(),
                "A Raspberry Pi camera must have a camera secret"
            );

            println!("Use the camera QR code in the app to pair.");
            input_camera_secret.clone().unwrap()
        }
        #[cfg(feature = "ip")]
        {
            println!("[{}] File camera_{}_secret_qrcode.png was just created. Use the QR code in the app to pair.", camera.get_name(), camera.get_name().replace(' ', "_").to_lowercase());
            generate_ip_camera_secret(&camera.get_name())?
        }
        #[cfg(feature = "android")]
        {
            info!("[{}] File camera_{}_secret_qrcode.png was just created. Use the QR code in the app to pair.", camera.get_name(), camera.get_name().replace(' ', "_").to_lowercase());
            generate_android_camera_secret(&camera.get_name())?
            
        }
    };

    #[cfg(any(feature = "raspberry", feature = "test"))]
    let mut msg_transport = TcpStreamTransport::initialize_no_connect()?;
    #[cfg(feature = "android")]
    let mut msg_transport = {
        let (server_username, server_password, server_addr) = get_server_credentials();
        RelayTransport::initialize_no_connect(
            server_username,
            server_password,
            server_addr
        )?
    };

    // Loop and continuously try to pair with the app (in case of failures)
    loop {
        if let Err(e) = msg_transport.wait_for_pairing_request() {
            debug!("[Pairing] Failed to wait for pairing request: {e}. Will try again.");
            sleep(Duration::from_secs(1));
            continue;
        }

        if try_pairing(
            &mut msg_transport,
            mls_clients,
            &secret,
            #[cfg(feature = "raspberry")]
            camera,
        ) {
            // Pairing was successful!
            break;
        }

        // Get rid of any potential failed pairs beforehand.
        for mls_client in mls_clients.iter_mut() {
            mls_client.clean()?;
        }

        // We cannot use the old user objects, so create new clients.
        *mls_clients = initialize_mls_clients(camera, true)?;

        debug!("[Pairing] Error — resetting for next connection");
    }

    if input_camera_secret.is_none() {
        let _ = fs::remove_file(format!(
            "camera_{}_secret_qrcode.png",
            camera.get_name().replace(' ', "_").to_lowercase()
        ));
    }

    Ok(())
}

fn try_pairing(
    msg_transport: &mut dyn MessageTransport,
    mls_clients: &mut MlsClients,
    secret: &[u8],
    #[cfg(feature = "raspberry")]
    camera: &dyn Camera,
) -> bool {
    // Receive timestamp and set system date and time.
    // This is because an RPi doesn't have a battery-backed real-time clock.
    // Therefore, if it remains off before pairing, its wall clock will be off.
    // This then prevents successful pairing due to MLS checking the lifetime
    // of key packages.
    #[cfg(feature = "raspberry")]
    if let Err(e) = receive_timestamp_set_system_time(msg_transport) {
        debug!("[Pairing] Failed to receive and set timestamp: {e}");
        return false;
    }

    debug!("[Pairing] Before sending firmware version");
    if let Err(e) = send_firmware_version(msg_transport) {
        debug!("[Pairing] Failed to send firmware_version: {e}");
        return false;
    }

    debug!("[Pairing] Before pairing");
    for mls_client in mls_clients.iter_mut() {
        match perform_pairing_handshake(msg_transport, mls_client.key_package()) {
            Ok(app_key_package) => {
                if let Err(e) = invite(msg_transport, mls_client, app_key_package, secret.to_owned()) {
                    debug!("[Pairing] Failed to create group: {e}");
                    return false;
                }
            }
            Err(e) => {
                debug!("[Pairing] Pairing failed: {e}");
                return false;
            }
        }
    }

    #[cfg(not(feature = "android"))]
    {
        debug!("[Pairing] Before receiving credentials");
        match receive_credentials_full(msg_transport, &mut mls_clients[CONFIG]) {
            Ok(()) => {}
            Err(e) => {
                debug!("[Pairing] Failed to receive credentials_full: {e}");
                return false;
            }
        }
    }
    #[cfg(feature = "raspberry")]
    {
        debug!("[Pairing] Before parsing credentials");
        let (server_username, server_password, server_addr) =
            read_parse_full_credentials();
        let http_client = HttpClient::new(server_addr.clone(), server_username, server_password);

        let (changed_wifi, success) = wifi::attempt_wifi_pair(
            msg_transport,
            mls_clients,
            &http_client,
            camera,
            server_addr.as_str(),
        );

        if changed_wifi && !success {
            debug!("[Pairing] Creating WiFi hotspot after fail");
            create_wifi_hotspot();

            return false;
        }
    }
    true
}

fn send_firmware_version(
    msg_transport: &mut dyn MessageTransport
) -> io::Result<()> {
    let msg = serde_json::to_vec(&camera_version_info()?)
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e.to_string()))?;
    msg_transport.send_msg(&msg, "firmware_version")?;

    Ok(())
}

fn invite(
    msg_transport: &mut dyn MessageTransport,
    mls_client: &mut MlsClient,
    app_key_package: KeyPackage,
    camera_secret: Vec<u8>,
) -> io::Result<()> {
    let app_contact = MlsClient::create_contact("app", app_key_package)?;
    debug!("Added contact.");

    let (welcome_msg_vec, _, _) = mls_client
        .invite_with_secret(&app_contact, camera_secret)
        .inspect_err(|_| {
            error!("invite() returned error:");
        })?;
    mls_client.save_group_state()?;
    debug!("App invited to the group.");

    msg_transport.send_msg(&welcome_msg_vec, "welcome")?;

    // Next, send the shared group name
    let group_name = mls_client.get_group_name()?;
    msg_transport.send_msg(group_name.as_bytes(), "group_name")?;

    Ok(())
}

#[cfg(feature = "raspberry")]
fn receive_timestamp_set_system_time(
    msg_transport: &mut dyn MessageTransport,
) -> anyhow::Result<()> {
    let timestamp_vec = msg_transport.receive_msg("")?;
    let timestamp: u64 = bincode::deserialize(&timestamp_vec)?;
    let _ = Command::new("date")
        .arg("-s")
        .arg(format!("@{timestamp}"))
        .output()?;

    Ok(())
}

fn perform_pairing_handshake(
    msg_transport: &mut dyn MessageTransport,
    camera_key_package: KeyPackage,
) -> anyhow::Result<KeyPackage> {
    let pairing = pairing::Camera::new(camera_key_package);

    let app_msg = msg_transport.receive_msg("app_msg")?;
    let (app_key_package, camera_msg) = pairing.process_app_msg_and_generate_msg_to_app(app_msg)?;
    msg_transport.send_msg(&camera_msg, "camera_msg")?;

    Ok(app_key_package)
}

#[cfg(any(feature = "test", feature = "raspberry"))]
fn receive_credentials_full(
    msg_transport: &mut dyn MessageTransport,
    mls_client: &mut MlsClient,
) -> anyhow::Result<()> {
    let encrypted_msg = msg_transport.receive_msg("")?;
    let credentials_full_bytes = decrypt_msg(mls_client, encrypted_msg)?;

    // Write to file
    let mut file = File::create("credentials_full").expect("Could not create file");
    file.write_all(&credentials_full_bytes)?;
    file.flush()?;
    file.sync_all()?;

    Ok(())
}

#[cfg(any(feature = "test", feature = "raspberry"))]
pub(crate) fn decrypt_msg(mls_client: &mut MlsClient, msg: Vec<u8>) -> io::Result<Vec<u8>> {
    let decrypted_msg = mls_client.decrypt(msg, true)?;
    mls_client.save_group_state()?;

    Ok(decrypted_msg)
}