//! SPDX-License-Identifier: GPL-3.0-or-later
//!
//! Direct P2P transport. Livestream chunks can skip the relay! (when possible)
//
//! A livestream through the delivery service costs an upload and a download of every chunk,
//! Also adds a round trip of latency
//!
//! When the camera and the phone can reach each other directly, none of that is necessary.
//!
//! Candidates: Each side collects the addresses it might be reachable on (local, STUN server)
//!
//! Exchange: Both publish their candidates to the delivery service  (POST /p2p/<camera>) and read the other's.
//! Basically... the server is a rendezvous point
//!
//! Punch: Both sides fire UDP packets at every candidate the other offered (simultaneously).
//! Each outbound packet opens a hole in the sender's own NAT that the peer's packets can come back through.
//!
//! QUIC: once we got packets, a QUIC connection is established over that same socket.
//! QUIC multiplexes, recovers loss, survives NAT rebinding..
//!
//! Relay used on fallback.

pub mod quic;
pub mod stun;

use crate::http_client::HttpClient;
use serde::{Deserialize, Serialize};
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

/// Which side of the connection this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    Camera,
    App,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Camera => "camera",
            Role::App => "app",
        }
    }

    /// (whose candidates we want)
    pub fn peer(&self) -> Role {
        match self {
            Role::Camera => Role::App,
            Role::App => Role::Camera,
        }
    }
}

/// How long to keep punching before giving up and using the relay.
pub const PUNCH_DEADLINE: Duration = Duration::from_secs(3);

/// Gap between punch packets.
pub const PUNCH_INTERVAL: Duration = Duration::from_millis(100);

/// Cap on candidates we will accept from a peer
pub const MAX_PEER_CANDIDATES: usize = 8;

/// How long to keep asking the rendezvous for the peer's candidates before concluding it isn't coming
pub const PEER_WAIT_DEADLINE: Duration = Duration::from_secs(6);

/// Gap between rendezvous polls while waiting for the peer to publish.
pub const PEER_WAIT_INTERVAL: Duration = Duration::from_millis(500);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishRequest {
    pub role: String,
    pub addresses: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Peer {
    pub role: String,
    pub addresses: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PeersResult {
    pub peers: Vec<Peer>,
}

/// The addresses this machine might be reachable on.
pub fn gather_candidates(socket: &UdpSocket) -> io::Result<Vec<SocketAddr>> {
    let mut candidates = Vec::new();

    // What we can see locally.
    if let Ok(local) = socket.local_addr() {
        if !local.ip().is_unspecified() {
            candidates.push(local);
        } else if let Some(routable) = primary_local_address(local.port()) {
            // Bound to 0.0.0.0
            candidates.push(routable);
        }
    }

    // What the world sees.
    if let Some(reflexive) = stun::discover_reflexive(socket, stun::DEFAULT_STUN_SERVERS) {
        if !candidates.contains(&reflexive) {
            candidates.push(reflexive);
        }
    }

    if candidates.is_empty() {
        return Err(io::Error::other(
            "No usable local addresses for a direct connection".to_string(),
        ));
    }

    Ok(candidates)
}

/// Ask the OS to route to a public address.
fn primary_local_address(port: u16) -> Option<SocketAddr> {
    let probe = UdpSocket::bind("0.0.0.0:0").ok()?;
    probe.connect("198.51.100.1:9").ok()?;
    let mut addr = probe.local_addr().ok()?;
    addr.set_port(port);
    Some(addr)
}

/// Tell the delivery service where we can be reached. read where the peer can be.
pub fn exchange_candidates(
    http_client: &HttpClient,
    camera: &str,
    role: Role,
    candidates: &[SocketAddr],
) -> io::Result<Vec<SocketAddr>> {
    http_client.publish_p2p_addresses(
        camera,
        role.as_str(),
        &candidates
            .iter()
            .map(|addr| addr.to_string())
            .collect::<Vec<_>>(),
    )?;

    fetch_peer_candidates(http_client, camera, role)
}

fn fetch_peer_candidates(
    http_client: &HttpClient,
    camera: &str,
    role: Role,
) -> io::Result<Vec<SocketAddr>> {
    let peers = http_client.fetch_p2p_peers(camera, role.as_str())?;

    Ok(peers
        .peers
        .into_iter()
        .filter(|peer| peer.role == role.peer().as_str())
        .flat_map(|peer| peer.addresses)
        .take(MAX_PEER_CANDIDATES)
        .filter_map(|addr| addr.parse::<SocketAddr>().ok())
        .collect())
}

/// Fire packets at every candidate until one answers until deadline
pub fn punch(socket: &UdpSocket, peers: &[SocketAddr]) -> io::Result<Option<SocketAddr>> {
    const PUNCH: &[u8] = b"secluso-punch";

    if peers.is_empty() {
        return Ok(None);
    }

    let previous_timeout = socket.read_timeout()?;
    socket.set_read_timeout(Some(PUNCH_INTERVAL))?;

    let deadline = Instant::now() + PUNCH_DEADLINE;
    let mut found = None;
    let mut buf = [0u8; 64];

    while Instant::now() < deadline && found.is_none() {
        for peer in peers {
            let _ = socket.send_to(PUNCH, peer);
        }

        // A reply means our packets are getting through and theirs can too.
        match socket.recv_from(&mut buf) {
            Ok((len, from)) if buf[..len].starts_with(PUNCH) => {
                if peers.contains(&from) {
                    found = Some(from);
                }
            }
            _ => {}
        }
    }

    socket.set_read_timeout(previous_timeout)?;

    Ok(found)
}

/// Try to reach the peer directly.
pub fn try_direct(
    http_client: &HttpClient,
    camera: &str,
    role: Role,
) -> io::Result<Option<DirectPath>> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;

    let candidates = gather_candidates(&socket)?;

    // Publish ours once, then poll for theirs.
    let mut peers = exchange_candidates(http_client, camera, role, &candidates)?;
    let deadline = Instant::now() + PEER_WAIT_DEADLINE;

    while peers.is_empty() && Instant::now() < deadline {
        std::thread::sleep(PEER_WAIT_INTERVAL);
        peers = fetch_peer_candidates(http_client, camera, role)?;
    }

    if peers.is_empty() {
        return Ok(None);
    }

    match punch(&socket, &peers)? {
        Some(peer) => Ok(Some(DirectPath { socket, peer, role })),
        None => Ok(None),
    }
}

/// A punched-through UDP path, ready for QUIC to be run over it.
pub struct DirectPath {
    pub socket: UdpSocket,
    pub peer: SocketAddr,
    pub role: Role,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_are_each_others_peer() {
        assert_eq!(Role::Camera.peer(), Role::App);
        assert_eq!(Role::App.peer(), Role::Camera);
        assert_eq!(Role::Camera.as_str(), "camera");
    }

    #[test]
    fn a_bound_socket_offers_at_least_one_candidate() {
        // No STUN in a test unfortunately... but we can try locally
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let candidates = gather_candidates(&socket).unwrap();

        assert!(!candidates.is_empty());
        assert!(candidates.iter().all(|addr| !addr.ip().is_unspecified()));
    }

    #[test]
    fn punching_at_nobody_gives_up_rather_than_hanging() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();

        assert!(punch(&socket, &[]).unwrap().is_none());
    }

    #[test]
    fn two_sockets_punch_through_to_each_other() {
        let camera = UdpSocket::bind("127.0.0.1:0").unwrap();
        let app = UdpSocket::bind("127.0.0.1:0").unwrap();

        let camera_addr = camera.local_addr().unwrap();
        let app_addr = app.local_addr().unwrap();

        let handle = std::thread::spawn(move || punch(&camera, &[app_addr]).unwrap());
        let found = punch(&app, &[camera_addr]).unwrap();

        assert_eq!(found, Some(camera_addr));
        assert_eq!(handle.join().unwrap(), Some(app_addr));
    }

    #[test]
    fn a_stranger_answering_is_ignored() {
        // Only addresses the rendezvous told us about count. Anything else is not our peer.
        let ours = UdpSocket::bind("127.0.0.1:0").unwrap();
        let stranger = UdpSocket::bind("127.0.0.1:0").unwrap();
        let ours_addr = ours.local_addr().unwrap();

        // Nobody is at this address, so the only replies come from the stranger.
        let unused = UdpSocket::bind("127.0.0.1:0").unwrap();
        let unused_addr = unused.local_addr().unwrap();
        drop(unused);

        let handle = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_millis(600);
            while Instant::now() < deadline {
                let _ = stranger.send_to(b"secluso-punch", ours_addr);
                std::thread::sleep(Duration::from_millis(50));
            }
        });

        assert_eq!(punch(&ours, &[unused_addr]).unwrap(), None);
        handle.join().unwrap();
    }
}