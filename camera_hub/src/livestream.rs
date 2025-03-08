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

use crate::Camera;
use privastead_client_lib::user::User;
use std::io;
use std::pin::Pin;
use std::sync::mpsc;
use std::sync::mpsc::Sender;
use std::task::{Context, Poll};
use tokio::io::AsyncWrite;

pub struct LivestreamWriter {
    sender: Sender<Vec<u8>>,
    buffer: Vec<u8>,
}

impl LivestreamWriter {
    fn new(sender: Sender<Vec<u8>>) -> Self {
        Self {
            sender,
            buffer: Vec::new(),
        }
    }
}

impl AsyncWrite for LivestreamWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // We want each encrypted message to fit within one TCP packet (max size: 64 kB or 65535 B).
        // With these numbers, some experiments show that the encrypted message will have the max
        // size of 64687 B.
        let max_buf_size: usize = 62 * 1024;
        let min_buf_size: usize = 60 * 1024;

        self.buffer.extend_from_slice(buf);

        while self.buffer.len() >= min_buf_size {
            let len_to_send = if self.buffer.len() > max_buf_size {
                max_buf_size
            } else {
                self.buffer.len()
            };

            let data = self.buffer.drain(..len_to_send).collect();

            if self.sender.send(data).is_err() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Failed to send data over the channel",
                )));
            }
        }

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

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

pub fn livestream<C: Camera>(client: &mut User, group_name: String, camera: &C) -> io::Result<()> {
    let new_update = client
        .perform_update(group_name.clone())
        .expect("Could not force an MLS update!");
    // We must save state between the calls to perform_update() and send_update().
    // This is to make sure we don't end up sending an update to the app, which
    // we have not successfully committed/saved on our end.
    client.save_groups_state();
    client
        .send_update(group_name.clone())
        .expect("Could not send the pending update!");
    if !new_update {
        // We don't want the attacker to force us to do more than one livestream session without an update.
        info!("Sent pending update. Will not livestream until update is acked (indirectly).");
        return Ok(());
    }

    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let livestream_writer = LivestreamWriter::new(tx);
    camera.launch_livestream(livestream_writer).unwrap();

    // The first read blocks for the stream to be ready.
    // We want to start the heartbeat tracker after that.
    let mut first_send = true;

    loop {
        let data = rx.recv().unwrap();

        let heartbeat = client.send(&data, group_name.clone()).map_err(|e| {
            error!("send() returned error:");
            client.save_groups_state();
            e
        })?;

        if !heartbeat && !first_send {
            info!("Ending livestream.");
            break;
        }

        first_send = false;
    }
    client.save_groups_state();

    Ok(())
}
