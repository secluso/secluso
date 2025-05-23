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

/// Used to determine when to end livestream
const MAX_NUM_PENDING_LIVESTREAM_CHUNKS: usize = 5;

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
        self.buffer.extend_from_slice(buf);

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let data = self.buffer.drain(..).collect();

        if self.sender.send(data).is_err() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Other,
                "Failed to send data over the channel",
            )));
        }

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

        // The server returns 0 when the app has explicitly ended livestream
        if num_pending_files == 0 || num_pending_files > MAX_NUM_PENDING_LIVESTREAM_CHUNKS {
            info!("Ending livestream.");
            break;
        }
    }

    client.save_groups_state();

    Ok(())
}
