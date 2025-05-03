//! Camera hub livestream
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

use crate::Camera;
use privastead_client_lib::http_client::HttpClient;
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

pub fn livestream(
    client: &mut User,
    group_name: String,
    camera: &dyn Camera,
    http_client: &HttpClient,
) -> io::Result<()> {
    // Update MLS epoch
    let (commit_msg, _epoch) = client.update(group_name.clone())?;
    client.save_groups_state();
    //FIXME: fatal crash point here. We have committed the update, but we will never send it.
    http_client.livestream_upload(&group_name, commit_msg, 0)?;

    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let livestream_writer = LivestreamWriter::new(tx);
    camera.launch_livestream(livestream_writer).unwrap();

    let mut chunk_number: u64 = 1;

    loop {
        let data = rx.recv().unwrap();
        let enc_data = client.encrypt(&data, group_name.clone())?;

        let num_pending_files =
            http_client.livestream_upload(&group_name, enc_data, chunk_number)?;
        chunk_number += 1;

        if num_pending_files > 5 {
            info!("Ending livestream.");
            break;
        }
    }

    client.save_groups_state();

    Ok(())
}
