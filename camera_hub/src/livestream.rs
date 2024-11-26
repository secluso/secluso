//! Camera hub livestream
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

use crate::ip_camera::IpCamera;
use privastead_client_lib::user::User;
use std::io;
use std::io::Read;

pub fn is_there_livestream_start_request(client: &mut User) -> io::Result<bool> {
    let mut livestream_start = false;

    //FIXME: use the contact_name in order to stream only to that app.
    let callback = |msg_bytes: Vec<u8>, _contact_name: String| -> io::Result<()> {
        // Ignore other messages. Should we?
        if msg_bytes.len() == 1 && msg_bytes[0] == 13 {
            livestream_start = true;
            info!("livestream start request received");
        }

        Ok(())
    };

    client.receive(callback)?;
    client.save_groups_state();

    Ok(livestream_start)
}

pub fn livestream(client: &mut User, group_name: String, ip_camera: &IpCamera) -> io::Result<()> {
    let new_update = client
        .update(group_name.clone())
        .expect("Could not force an MLS update!");
    client.save_groups_state();
    if !new_update {
        // We don't want the attacker to force us to do more than one livestream session without an update.
        info!("Sent pending update. Will not livestream until update is acked (indirectly).");
        return Ok(());
    }

    let mut child = ip_camera.launch_livestream()?;
    let child_stdout_ret = child.stdout.take();
    if child_stdout_ret.is_none() {
        child.kill().unwrap();
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Failed to launch livestream.".to_string(),
        ));
    }

    let mut child_stdout = child_stdout_ret.unwrap();

    // We want each encrypted message to fit within one TCP packet (max size: 64 kB or 65535 B).
    // With these numbers, some experiments show that the encrypted message will have the max
    // size of 64687 B.
    let mut buffer = [0; 63 * 1024];

    // The first read blocks for the stream to be ready.
    // We want to start the tracker after that.
    // FIXME: the read and send code is duplicated here
    // and in the loop.
    let len = child_stdout.read(&mut buffer[..]).expect("Read failed!");
    client
        .send(&buffer[..len], group_name.clone())
        .map_err(|e| {
            error!("send() returned error:");
            e
        })?;
    client.save_groups_state();

    loop {
        let len = child_stdout.read(&mut buffer[..]).expect("Read failed!");
        let heartbeat = client
            .send(&buffer[..len], group_name.clone())
            .map_err(|e| {
                error!("send() returned error:");
                e
            })?;
        client.save_groups_state();

        if !heartbeat {
            info!("Ending livestream.");
            //terminate stream from the camera
            child.kill().unwrap();
            break;
        }
    }

    Ok(())
}
