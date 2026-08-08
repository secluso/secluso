//! Camera hub config command processing
//!
//! SPDX-License-Identifier: GPL-3.0-or-later

use crate::pairing::io::get_names;
use crate::version::camera_version_info;
use crate::delivery_monitor::DeliveryMonitor;
use secluso_client_lib::config::{
    AddAppRequest, AddAppResponseCommon, AddAppResponseDedicated, Heartbeat, HeartbeatRequest,
    OPCODE_ADD_APP_REQUEST, OPCODE_ADD_APP_RESPONSE, OPCODE_ADD_APP_INFO,
    OPCODE_HEARTBEAT_REQUEST, OPCODE_HEARTBEAT_RESPONSE, OPCODE_REMOVE_APP_REQUEST,
    OPCODE_REMOVE_APP_RESPONSE, OPCODE_REMOVE_APP_INFO,
};
use secluso_client_lib::http_client::HttpClient;
use secluso_client_lib::mls_client::{ClientType, MlsClient};
use secluso_client_lib::mls_clients::{
    MlsClientsCommon, MlsClientsDedicated, CONFIG_DED, NUM_COMMON_MLS_CLIENTS,
    NUM_DEDICATED_MLS_CLIENTS, NUM_MLS_CLIENTS,
};
use secluso_client_lib::pairing::get_random_name;
use std::collections::HashMap;
use std::io;

pub fn process_config_command(
    clients_com: &mut MlsClientsCommon,
    clients_ded: &mut MlsClientsDedicated,
    enc_config_command: &[u8],
    http_client: &HttpClient,
    delivery_monitor_opt: Option<&mut DeliveryMonitor>,
    primary_app: bool,
    secondary_app_limit_reached: bool,
    clients_ded_secondary: Option<&mut HashMap<String, MlsClientsDedicated>>,
) -> anyhow::Result<Option<(String, Option<MlsClientsDedicated>)>> {
    debug!("Processing config command");
    match clients_ded[CONFIG_DED].decrypt(enc_config_command.to_vec(), true) {
        Ok(command) => {
            clients_ded[CONFIG_DED].save_group_state()?;
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
                }
                OPCODE_ADD_APP_REQUEST => {
                    if primary_app {
                        if !secondary_app_limit_reached {
                            debug!("Handling add_app request");
                            handle_add_app_request(
                                clients_com,
                                clients_ded,
                                &command[1..],
                                http_client,
                                clients_ded_secondary,
                            )
                        } else {
                            error!("Error: Maximum number of secondary apps is already reached!");
                            Ok(None)
                        }
                    } else {
                        error!("Error: Secondary app cannot add other apps!");
                        Ok(None)
                    }
                }
                OPCODE_REMOVE_APP_REQUEST => {
                    if primary_app {
                        if let Some(ref other_secondary_deds) = clients_ded_secondary {
                            if !other_secondary_deds.is_empty() {
                                debug!("Handling remove_app request");
                                let removed_app_name = handle_remove_app_request(
                                    clients_com,
                                    clients_ded,
                                    &command[1..],
                                    http_client,
                                    clients_ded_secondary,
                                )?;
                                Ok(Some((removed_app_name, None)))
                            } else {
                                error!("Error: There are no secondary apps to be removed!");
                                Ok(None)
                            }
                        } else {
                            error!("Error: No secondary apps are provided!");
                            Ok(None)
                        }
                    } else {
                        error!("Error: Secondary app cannot remove other apps!");
                        Ok(None)
                    }
                }
                _ => {
                    error!("Error: Unknown config command opcode!");
                    Ok(None)
                }
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

    send_heartbeat_response(
        clients_com,
        clients_ded,
        heartbeat_request.timestamp,
        http_client,
    )?;

    Ok(())
}

fn send_heartbeat_response(
    clients_com: &mut MlsClientsCommon,
    clients_ded: &mut MlsClientsDedicated,
    timestamp: u64,
    http_client: &HttpClient,
) -> io::Result<()> {
    let heartbeat =
        Heartbeat::generate(clients_com, clients_ded, timestamp, camera_version_info()?)?;

    let mut config_msg = vec![OPCODE_HEARTBEAT_RESPONSE];
    config_msg.extend(bincode::serialize(&heartbeat).unwrap());

    let config_msg_enc = clients_ded[CONFIG_DED].encrypt(&config_msg)?;
    clients_ded[CONFIG_DED].save_group_state()?;

    http_client.config_response(
        &clients_ded[CONFIG_DED].get_group_name().unwrap(),
        config_msg_enc,
    )?;

    Ok(())
}

fn handle_add_app_request(
    clients_com: &mut MlsClientsCommon,
    clients_ded: &mut MlsClientsDedicated,
    command_bytes: &[u8],
    http_client: &HttpClient,
    clients_ded_secondary: Option<&mut HashMap<String, MlsClientsDedicated>>,
) -> anyhow::Result<Option<(String, Option<MlsClientsDedicated>)>> {
    let (add_app_requests, secret): ([AddAppRequest; NUM_MLS_CLIENTS], Vec<u8>) =
        bincode::deserialize(command_bytes)
        .map_err(|e| io::Error::other(format!("Failed to deserialize add_app msg - {e}")))?;

    let new_app_name = get_random_name();

    let add_app_resps_com: [AddAppResponseCommon; NUM_COMMON_MLS_CLIENTS] =
        std::array::from_fn(|i| {
            let camera_key_package = clients_com[i].key_package();

            let camera_contact = MlsClient::create_contact(
                &new_app_name,
                add_app_requests[i].new_app_key_package.clone(),
            )
            .unwrap();

            let update_proposals_vec = clients_com[i].get_update_proposals().unwrap();

            let (welcome_msg_vec, psk_proposal_vec, commit_msg_vec) = clients_com[i]
                .invite_with_secret(&camera_contact, secret.clone())
                .unwrap();

            clients_com[i].save_group_state().unwrap();

            AddAppResponseCommon {
                camera_key_package,
                welcome_msg_vec,
                psk_proposal_vec,
                commit_msg_vec,
                update_proposals_vec,
            }
        });

    let [(client_l, resp_l), (client_c, resp_c)]: [(MlsClient, AddAppResponseDedicated);
        NUM_DEDICATED_MLS_CLIENTS] = [
        create_client(0, &new_app_name, clients_ded, &add_app_requests, secret.clone())?,
        create_client(1, &new_app_name, clients_ded, &add_app_requests, secret.clone())?,
    ];

    let new_clients_ded: MlsClientsDedicated = [client_l, client_c];
    let add_app_resps_ded: [AddAppResponseDedicated; NUM_DEDICATED_MLS_CLIENTS] = [resp_l, resp_c];

    let add_app_resp_combined = (add_app_resps_com.clone(), add_app_resps_ded, new_app_name.clone());

    // Send response
    let mut config_msg = vec![OPCODE_ADD_APP_RESPONSE];
    config_msg.extend(bincode::serialize(&add_app_resp_combined)?);

    let config_msg_enc = clients_ded[CONFIG_DED].encrypt(&config_msg)?;
    clients_ded[CONFIG_DED].save_group_state()?;

    // To primary app
    http_client.config_response(
        &clients_ded[CONFIG_DED].get_group_name().unwrap(),
        config_msg_enc.clone(),
    )?;

    // To other secondary apps
    if let Some(other_secondary_deds) = clients_ded_secondary {
        let add_app_info = (add_app_resps_com, secret.clone());

        let mut other_config_msg = vec![OPCODE_ADD_APP_INFO];
        other_config_msg.extend(bincode::serialize(&add_app_info)?);

        for other_secondary_ded in other_secondary_deds.values_mut() {
            let other_config_msg_enc = other_secondary_ded[CONFIG_DED].encrypt(&other_config_msg)?;
            other_secondary_ded[CONFIG_DED].save_group_state()?;

            http_client.config_response(
                &other_secondary_ded[CONFIG_DED].get_group_name().unwrap(),
                other_config_msg_enc.clone(),
            )?;     
        }
    }

    Ok(Some((new_app_name, Some(new_clients_ded))))
}

fn create_client(
    i: usize,
    app_name: &str,
    clients_ded: &mut MlsClientsDedicated,
    add_app_requests: &[AddAppRequest; NUM_MLS_CLIENTS],
    secret: Vec<u8>,
) -> anyhow::Result<(MlsClient, AddAppResponseDedicated)> {
    // This part of code has a lot in common with initialize_mls_clients() in main.rs

    // Initialize mls_client
    let tag = if i == 0 {
        format!("livestream{}", app_name)
    } else {
        format!("config{}", app_name)
    };

    let (camera_name, group_name) = get_names(
        &clients_ded[CONFIG_DED].get_file_dir(), // Could use either of the clients
        true,
        format!("camera_{}_name", &tag),
        format!("group_{}_name", &tag),
    )?;
    let mut client = MlsClient::new(
        camera_name,
        true,
        clients_ded[CONFIG_DED].get_file_dir(), // Could use either of the clients
        tag,
        ClientType::Camera,
    )
    .expect("MlsClient::new() for returned error.");

    client.create_group(&group_name)?;
    debug!("Created group.");

    client.save_group_state()?;

    // Now invite
    let camera_key_package = client.key_package();
    let app_key_package = add_app_requests[i + NUM_COMMON_MLS_CLIENTS]
        .new_app_key_package
        .clone();
    let app_contact_name = format!("app{}", app_name);
    let app_contact = MlsClient::create_contact(&app_contact_name, app_key_package)?;
    info!("Added contact.");

    let (welcome_msg_vec, _, _) = client
        .invite_with_secret(
            &app_contact,
            secret,
        )
        .inspect_err(|_| {
            error!("invite() returned error:");
        })?;
    client.save_group_state()?;
    info!("App invited to the group.");

    // Next, send the shared group name
    let group_name = client.get_group_name()?;

    let resp = AddAppResponseDedicated {
        camera_key_package,
        welcome_msg_vec,
        group_name,
    };

    Ok((client, resp))
}

fn handle_remove_app_request(
    clients_com: &mut MlsClientsCommon,
    clients_ded: &mut MlsClientsDedicated,
    command_bytes: &[u8],
    http_client: &HttpClient,
    clients_ded_secondary: Option<&mut HashMap<String, MlsClientsDedicated>>,
) -> anyhow::Result<String> {
    let app_name: String = bincode::deserialize(command_bytes)
        .map_err(|e| io::Error::other(format!("Failed to deserialize remove_app msg - {e}")))?;

    if !clients_ded_secondary
        .as_ref()
        .is_some_and(|clients| clients.contains_key(&app_name))
    {
        return Err(anyhow::anyhow!("Cannot remove unknown secondary app"));
    }

    let remove_app_resps_com: [Vec<u8>; NUM_COMMON_MLS_CLIENTS] =
        std::array::from_fn(|i| {
            let remove_msg_vec = clients_com[i]
                .remove(&app_name)
                .unwrap();

            clients_com[i].save_group_state().unwrap();

            remove_msg_vec
        });

    // Send response
    let mut config_msg = vec![OPCODE_REMOVE_APP_RESPONSE];
    config_msg.extend(bincode::serialize(&remove_app_resps_com)?);

    let config_msg_enc = clients_ded[CONFIG_DED].encrypt(&config_msg)?;
    clients_ded[CONFIG_DED].save_group_state()?;

    // To primary app
    http_client.config_response(
        &clients_ded[CONFIG_DED].get_group_name().unwrap(),
        config_msg_enc.clone(),
    )?;

    // To secondary apps
    if let Some(other_secondary_deds) = clients_ded_secondary {
        let remove_app_info = (remove_app_resps_com, app_name.clone());

        let mut other_config_msg = vec![OPCODE_REMOVE_APP_INFO];
        other_config_msg.extend(bincode::serialize(&remove_app_info)?);

        for other_secondary_ded in other_secondary_deds.values_mut() {
            let other_config_msg_enc = other_secondary_ded[CONFIG_DED].encrypt(&other_config_msg)?;
            other_secondary_ded[CONFIG_DED].save_group_state()?;

            http_client.config_response(
                &other_secondary_ded[CONFIG_DED].get_group_name().unwrap(),
                other_config_msg_enc.clone(),
            )?;     
        }
    }

    Ok(app_name)
}
