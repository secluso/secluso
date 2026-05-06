//! Camera hub config command processing
//!
//! SPDX-License-Identifier: GPL-3.0-or-later

use crate::DeliveryMonitor;
use crate::pairing::get_names;
use crate::version::camera_version_info;
use secluso_client_lib::config::{
    Heartbeat, HeartbeatRequest, OPCODE_HEARTBEAT_REQUEST, OPCODE_HEARTBEAT_RESPONSE,
    AddAppRequest, AddAppResponseCommon, AddAppResponseDedicated, OPCODE_ADD_APP_REQUEST, OPCODE_ADD_APP_RESPONSE,
};
use secluso_client_lib::http_client::HttpClient;
use secluso_client_lib::mls_clients::{NUM_MLS_CLIENTS, MlsClientsCommon, MlsClientsDedicated, CONFIG_DED,
    NUM_DEDICATED_MLS_CLIENTS, NUM_COMMON_MLS_CLIENTS};
use secluso_client_lib::mls_client::{MlsClient, ClientType};
use std::io;

pub fn process_config_command(
    clients_com: &mut MlsClientsCommon,
    clients_ded: &mut MlsClientsDedicated,
    enc_config_command: &[u8],
    http_client: &HttpClient,
    delivery_monitor_opt: Option<&mut DeliveryMonitor>,
    primary_app: bool,
    second_app_already_paired: bool,
) -> io::Result<Option<MlsClientsDedicated>> {
    debug!("Processing config command");
    match clients_ded[CONFIG_DED].decrypt(enc_config_command.to_vec(), true) {
        Ok(command) => {
            clients_ded[CONFIG_DED].save_group_state().unwrap();
            match command[0] {
                OPCODE_HEARTBEAT_REQUEST => {
                    debug!("Handling heartbeat request");
                    handle_heartbeat_request(
                        clients_com,
                        clients_ded,
                        &command[1..],
                        http_client,
                        delivery_monitor_opt,
                    )?;
                    Ok(None)
                },
                OPCODE_ADD_APP_REQUEST => {
                    if primary_app {
                        if !second_app_already_paired {
                            debug!("Handling add_app request");
                            handle_add_app_request(
                                clients_com,
                                clients_ded,
                                &command[1..],
                                http_client,
                            )
                        } else {
                            error!("Error: Secondary app is already paired!");
                            Ok(None)
                        }
                    } else {
                        error!("Error: Secondary app cannot add other apps!");
                        Ok(None)
                    }
                },
                _ => {
                    error!("Error: Unknown config command opcode!");
                    Ok(None)
                },
            }
        }
        Err(e) => {
            error!("Failed to decrypt command message: {e}");
            Ok(None)
        }
    }
}

fn handle_heartbeat_request(
    clients_com: &mut MlsClientsCommon,
    clients_ded: &mut MlsClientsDedicated,
    command_bytes: &[u8],
    http_client: &HttpClient,
    delivery_monitor_opt: Option<&mut DeliveryMonitor>,
) -> io::Result<()> {
    let mut heartbeat_request: HeartbeatRequest = bincode::deserialize(command_bytes)
        .map_err(|e| io::Error::other(format!("Failed to deserialize heartbeat msg - {e}")))?;

    let _ = heartbeat_request.process_update_proposals(clients_com, clients_ded);

    info!(
        "handle_heartbeat_request: {}, {}, {}",
        heartbeat_request.timestamp,
        heartbeat_request.motion_epoch,
        heartbeat_request.thumbnail_epoch
    );

    if let Some(delivery_monitor) = delivery_monitor_opt {
        delivery_monitor.process_heartbeat(
            heartbeat_request.motion_epoch,
            heartbeat_request.thumbnail_epoch,
        );
    }

    send_heartbeat_response(clients_com, clients_ded, heartbeat_request.timestamp, http_client)?;

    Ok(())
}

fn send_heartbeat_response(
    clients_com: &mut MlsClientsCommon,
    clients_ded: &mut MlsClientsDedicated,
    timestamp: u64,
    http_client: &HttpClient,
) -> io::Result<()> {
    let heartbeat = Heartbeat::generate(clients_com, clients_ded, timestamp, camera_version_info()?)?;

    let mut config_msg = vec![OPCODE_HEARTBEAT_RESPONSE];
    config_msg.extend(bincode::serialize(&heartbeat).unwrap());

    let config_msg_enc = clients_ded[CONFIG_DED].encrypt(&config_msg)?;
    clients_ded[CONFIG_DED].save_group_state().unwrap();

    http_client.config_response(&clients_ded[CONFIG_DED].get_group_name().unwrap(), config_msg_enc)?;

    Ok(())
}

fn handle_add_app_request(
    clients_com: &mut MlsClientsCommon,
    clients_ded: &mut MlsClientsDedicated,
    command_bytes: &[u8],
    http_client: &HttpClient,
) -> io::Result<Option<MlsClientsDedicated>> {
    let add_app_requests: [AddAppRequest; NUM_MLS_CLIENTS] = bincode::deserialize(command_bytes)
        .map_err(|e| io::Error::other(format!("Failed to deserialize add_app msg - {e}")))?;

    let add_app_resps_com: [AddAppResponseCommon; NUM_COMMON_MLS_CLIENTS] = std::array::from_fn(|i| {
        println!("handle_add_app_request [1]");
        let camera_key_package = clients_com[i].key_package();

        // FIXME: "app2" is hardcoded.
        println!("handle_add_app_request [2]");
        let camera_contact =
            MlsClient::create_contact("app2", add_app_requests[i].new_app_key_package.clone())
                .unwrap();

        println!("handle_add_app_request [3]");
        // FIXME: Use a different secret per channel
        let (welcome_msg_vec, psk_proposal_vec, commit_msg_vec) = clients_com[i]
            .invite_with_secret(&camera_contact, add_app_requests[i].secret.clone())
            .unwrap();

        println!("handle_add_app_request [4]");
        clients_com[i].save_group_state().unwrap();

        println!("handle_add_app_request [5]");
        AddAppResponseCommon {
            camera_key_package,
            welcome_msg_vec,
            psk_proposal_vec,
            commit_msg_vec,
        }
    });

    let [(client_l, resp_l), (client_c, resp_c)]: [(MlsClient, AddAppResponseDedicated); NUM_DEDICATED_MLS_CLIENTS] =
        std::array::from_fn(|i| {
        // This part of code has a lot in common with initialize_mls_clients() in main.rs

        // Initialize mls_client
        // FIXME
        let tag = if i == 0 {
            "livestream2"
        } else {
            "config2"
        };

        let (camera_name, group_name) = get_names(
                clients_ded[CONFIG_DED].get_file_dir(), // Could use either of the clients
                true,
                format!("camera_{}_name", tag),
                format!("group_{}_name", tag),
            );
        let mut client = MlsClient::new(
            camera_name,
            true,
            clients_ded[CONFIG_DED].get_file_dir(), // Could use either of the clients
            tag.to_string(),
            ClientType::Camera,
        )
        .expect("MlsClient::new() for returned error.");

        client.create_group(&group_name).unwrap();
        debug!("Created group.");

        client.save_group_state().unwrap();

        // Now invite
        let camera_key_package = client.key_package();
        let app_key_package = add_app_requests[i + NUM_COMMON_MLS_CLIENTS].new_app_key_package.clone();
        let app_contact = MlsClient::create_contact("app", app_key_package).unwrap();
        info!("Added contact.");

        let (welcome_msg_vec, _, _) = client
            .invite_with_secret(&app_contact, add_app_requests[i + NUM_COMMON_MLS_CLIENTS].secret.clone())
            .inspect_err(|_| {
                error!("invite() returned error:");
            }).unwrap();
        client.save_group_state().unwrap();
        info!("App invited to the group.");

        // Next, send the shared group name
        let group_name = client.get_group_name().unwrap();

        let resp = AddAppResponseDedicated {
            camera_key_package,
            welcome_msg_vec,
            group_name,
        };

        (client, resp)
    });

    let new_clients_ded: MlsClientsDedicated = [client_l, client_c];
    let add_app_resps_ded: [AddAppResponseDedicated; NUM_DEDICATED_MLS_CLIENTS] = [resp_l, resp_c];

    let add_app_resp_combined = (add_app_resps_com, add_app_resps_ded);

    // Send response
    let mut config_msg = vec![OPCODE_ADD_APP_RESPONSE];
    config_msg.extend(bincode::serialize(&add_app_resp_combined).unwrap());

    let config_msg_enc = clients_ded[CONFIG_DED].encrypt(&config_msg)?;
    println!("[1]: config_msg_enc len = {:?}", config_msg_enc.len());
    clients_ded[CONFIG_DED].save_group_state().unwrap();

    http_client.config_response(&clients_ded[CONFIG_DED].get_group_name().unwrap(), config_msg_enc)?;

    Ok(Some(new_clients_ded))
}
