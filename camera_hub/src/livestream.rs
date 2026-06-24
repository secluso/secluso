//! Camera hub livestream
//!
//! SPDX-License-Identifier: GPL-3.0-or-later

use crate::delivery_monitor::DeliveryMonitor;
use crate::Camera;
use secluso_client_lib::http_client::HttpClient;
use secluso_client_lib::mls_client::MlsClient;
use secluso_client_lib::mls_clients::MAX_OFFLINE_WINDOW;
use std::io;
use std::pin::Pin;
use std::sync::mpsc;
use std::sync::mpsc::Sender;
use std::task::{Context, Poll};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
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
            return Poll::Ready(Err(io::Error::other(
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
    mls_client: &mut MlsClient,
    camera: &dyn Camera,
    delivery_monitor: &mut DeliveryMonitor,
    http_client: &HttpClient,
) -> io::Result<()> {
    if mls_client.offline_period() > MAX_OFFLINE_WINDOW {
        info!("App has been offline for too long. Won't send any more videos until there is a heartbeat.");
        // We return Ok(()) since we want the core() in main.rs to continue;
        // FIXME: not enforcing this yet.
        //return Ok(());
    }

    // Update MLS epoch
    let update_start = Instant::now();
    let (commit_msg, _epoch) = mls_client.update()?;
    debug!(
        "Livestream: mls_client.update() took {}ms",
        update_start.elapsed().as_millis()
    );
    mls_client.save_group_state().unwrap();
    let group_name = mls_client.get_group_name().unwrap();

    // Why bother with enqueueing the updates in the delivery monitor?
    // If we just try to send the update, we will have a severe fatal crash point.
    // The fatal crash point would be here because we have committed the update, but we would never send it.
    // It's severe because it is not that unlikely for it to happen, e.g., when there's something wrong
    // with the upload attempt to the server.
    // With the delivery monitor trick, we mitigate this.
    // We still have a fatal crash point here, but it's less severe (let's say medium severity).
    // This is because both operations before and after the fatal crash point are file system writes.
    // FIXME: fatal crash point here (see the comment above).
    delivery_monitor.enqueue_livestream_update(commit_msg);
    let pending_livestream_updates = delivery_monitor.get_livestream_updates();
    let updates_data = bincode::serialize(&pending_livestream_updates).unwrap();

    http_client.livestream_upload(&group_name, updates_data, 0)?;
    delivery_monitor.dequeue_livestream_updates();

    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let livestream_writer = LivestreamWriter::new(tx);
    camera.launch_livestream(livestream_writer)?;

    let mut chunk_number: u64 = 1;
    let mut last_recv = Instant::now();

    loop {
        // We include the chunk number in the chunk itself (and check it in the app)
        // to prevent a malicious server from reordering the chunks.
        let Ok(fragment) = rx.recv() else {
            info!("Ending livestream because the camera backend stopped producing fragments.");
            break;
        };
        debug!(
            "Livestream: {}ms since previous fragment for chunk {}",
            last_recv.elapsed().as_millis(),
            chunk_number
        );
        last_recv = Instant::now();
        let mut data: Vec<u8> = chunk_number.to_be_bytes().to_vec();
        data.extend(fragment);

        let received_epoch_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        debug!(
            "Livestream: Received data for chunk {} at {}",
            chunk_number, received_epoch_ms
        );

        let enc_start = Instant::now();
        let enc_data = mls_client.encrypt(&data)?;
        let enc_ms = enc_start.elapsed().as_millis();
        debug!(
            "Livestream: Took {}ms for chunk {} for encryption",
            enc_ms, chunk_number
        );

        let upload_start = Instant::now();
        let num_pending_files =
            http_client.livestream_upload(&group_name, enc_data, chunk_number)?;
        chunk_number += 1;

        let upload_ms = upload_start.elapsed().as_millis();
        let curr_epoch_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        debug!(
            "Livestream: Took {}ms for chunk {} for uploading (curr time = {})",
            upload_ms,
            chunk_number - 1,
            curr_epoch_ms
        );
        debug!(
            "Livestream: {} pending chunk(s) on server after chunk {}",
            num_pending_files,
            chunk_number - 1
        );

        // The server returns 0 when the app has explicitly ended livestream
        if num_pending_files == 0 || num_pending_files > MAX_NUM_PENDING_LIVESTREAM_CHUNKS {
            info!("Ending livestream.");
            break;
        }
    }

    let save_start = Instant::now();
    mls_client.save_group_state().unwrap();
    debug!(
        "Livestream: final save_group_state() took {}ms",
        save_start.elapsed().as_millis()
    );

    Ok(())
}
