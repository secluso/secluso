//! Camera hub config command processing
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

use std::io;
use std::time::{SystemTime, UNIX_EPOCH};
use privastead_client_lib::config::{OPCODE_HEARTBEAT_REQUEST, OPCODE_HEARTBEAT_RESPONSE, HeartbeatRequest, Heartbeat};
use privastead_client_lib::mls_clients::{CONFIG, MlsClients};
use privastead_client_lib::http_client::HttpClient;
use crate::DeliveryMonitor;

pub fn process_config_command(
    clients: &mut MlsClients,
    enc_config_command: &[u8],
    http_client: &HttpClient,
    delivery_monitor: &mut DeliveryMonitor,
) -> io::Result<()> {
    match clients[CONFIG]
        .decrypt(enc_config_command.to_vec(), true) {
            
        Ok(command) => {
            clients[CONFIG].save_group_state();
            match command[0] {
                OPCODE_HEARTBEAT_REQUEST => {
                    handle_heartbeat_request(clients, &command[1..], http_client, delivery_monitor)?;
                    Ok(())
                },
                _ => {
                    error!("Error: Unknown config command opcode!");
                    return Ok(());
                }
            }
        },
        Err(e) => {
            error!("Failed to decrypt command message: {e}");
            return Ok(());
        }
    }
}

fn handle_heartbeat_request(
    clients: &mut MlsClients,
    command_bytes: &[u8],
    http_client: &HttpClient,
    delivery_monitor: &mut DeliveryMonitor,
) -> io::Result<()> {
    let heartbeat_request: HeartbeatRequest = bincode::deserialize(command_bytes)
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to deserialize heartbeat msg - {e}"),
            )
        })?;

    info!("handle_heartbeat: {}, {}", heartbeat_request.timestamp, heartbeat_request.motion_epoch);
    delivery_monitor.process_heartbeat(heartbeat_request.motion_epoch);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Could not convert time")
        .as_secs();
    // The clocks on the two devices are not synchronized and might be off a bit.
    if now - heartbeat_request.timestamp < 10 || heartbeat_request.timestamp - now < 10 {
        // We only responsd to recent heartbeat requests.
        send_heartbeat_response(clients, heartbeat_request.timestamp, http_client)?;
    } else {
        info!("Won't respond to old heartbeat request (now = {now})");
    }

    Ok(())
}

fn send_heartbeat_response(
    clients: &mut MlsClients,
    timestamp: u64,
    http_client: &HttpClient,
) -> io::Result<()> {
    let heartbeat = Heartbeat::generate(clients, timestamp)?;

    let mut config_msg = vec![OPCODE_HEARTBEAT_RESPONSE];
    config_msg.extend(bincode::serialize(&heartbeat).unwrap());

    let config_msg_enc = clients[CONFIG].encrypt(&config_msg)?;
    clients[CONFIG].save_group_state();

    http_client.config_response(&clients[CONFIG].get_group_name().unwrap(), config_msg_enc)?;

    Ok(())
}