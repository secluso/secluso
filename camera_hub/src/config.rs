//! Camera hub config command processing
//!
//! SPDX-License-Identifier: GPL-3.0-or-later

use crate::DeliveryMonitor;
use secluso_client_lib::config::{
    Heartbeat, HeartbeatRequest, OPCODE_HEARTBEAT_REQUEST, OPCODE_HEARTBEAT_RESPONSE,
};
use secluso_client_lib::http_client::HttpClient;
use secluso_client_lib::mls_clients::{MlsClients, CONFIG};
use std::io;

pub fn process_config_command(
    clients: &mut MlsClients,
    enc_config_command: &[u8],
    http_client: &HttpClient,
    delivery_monitor: &mut DeliveryMonitor,
) -> io::Result<()> {
    debug!("Processing config command");
    match clients[CONFIG].decrypt(enc_config_command.to_vec(), true) {
        Ok(command) => {
            clients[CONFIG].save_group_state();
            match command[0] {
                OPCODE_HEARTBEAT_REQUEST => {
                    debug!("Handling heartbeat request");
                    handle_heartbeat_request(
                        clients,
                        &command[1..],
                        http_client,
                        delivery_monitor,
                    )?;
                    Ok(())
                }
                _ => {
                    error!("Error: Unknown config command opcode!");
                    Ok(())
                }
            }
        }
        Err(e) => {
            error!("Failed to decrypt command message: {e}");
            Ok(())
        }
    }
}

fn handle_heartbeat_request(
    clients: &mut MlsClients,
    command_bytes: &[u8],
    http_client: &HttpClient,
    delivery_monitor: &mut DeliveryMonitor,
) -> io::Result<()> {
    let mut heartbeat_request: HeartbeatRequest = bincode::deserialize(command_bytes)
        .map_err(|e| io::Error::other(format!("Failed to deserialize heartbeat msg - {e}")))?;

    let _ = heartbeat_request.process_update_proposals(clients);

    info!(
        "handle_heartbeat_request: {}, {}, {}",
        heartbeat_request.timestamp,
        heartbeat_request.motion_epoch,
        heartbeat_request.thumbnail_epoch
    );
    delivery_monitor.process_heartbeat(
        heartbeat_request.motion_epoch,
        heartbeat_request.thumbnail_epoch,
    );

    send_heartbeat_response(clients, heartbeat_request.timestamp, http_client)?;

    Ok(())
}

fn send_heartbeat_response(
    clients: &mut MlsClients,
    timestamp: u64,
    http_client: &HttpClient,
) -> io::Result<()> {
    let heartbeat = Heartbeat::generate(
        clients,
        timestamp,
        format!("v{}", env!("CARGO_PKG_VERSION")),
    )?;

    let mut config_msg = vec![OPCODE_HEARTBEAT_RESPONSE];
    config_msg.extend(bincode::serialize(&heartbeat).unwrap());

    let config_msg_enc = clients[CONFIG].encrypt(&config_msg)?;
    clients[CONFIG].save_group_state();

    http_client.config_response(&clients[CONFIG].get_group_name().unwrap(), config_msg_enc)?;

    Ok(())
}
