//! SPDX-License-Identifier: GPL-3.0-or-later
//!
//! QUIC over a punched-through UDP socket.
//!
//! Hole punching gets packets flowing.
//!
//! However, we need more than that...
//! - a stream
//! - ordering
//! - loss recovery
//! - a connection that survives the NAT rebinding (long livestream will provoke)
//! that's where QUIC comes in! Runs over the socket we already punched
//!
//! The camera listens and the app dials.
//!
//! NOTE: the certificate is not verified.
//! Chunks here === same MLS ciphertext that would otherwise go to the relay.
//! Encrypted before they reach this module and decrypted after they leave it.
//! QUIC is a pipe, not the security boundary.
//! If someone was to impersonate, they'd just get the ciphertext.
//!
//! TODO: Minting a second identity per device alongside the MLS one and distributing it
//!       Although, this is most likely unnecessary and more complex.

use super::{DirectPath, Role};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Connection, Endpoint, EndpointConfig, ServerConfig, TransportConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::io;
use std::sync::Arc;
use std::time::Duration;

/// Application-Layer Protocol Negotiation name.
/// Stops this connection being confused with anything else that might come along
const ALPN: &[u8] = b"secluso-livestream";

/// Drop the connection if the peer goes quiet for this long.
const IDLE_TIMEOUT: Duration = Duration::from_secs(15);

/// Keep the NAT binding alive during quiet moments between chunks.
const KEEP_ALIVE: Duration = Duration::from_secs(5);

/// A live direct connection to the peer.
pub struct PeerConnection {
    connection: Connection,
    /// Kept alive because dropping the endpoint closes the connection under it.
    _endpoint: Endpoint,
}

impl PeerConnection {
    /// Send one chunk.
    ///
    /// Each chunk has own unidirectional stream
    /// - chunks are independent
    /// - a stream per chunk means a slow or lost one cannot head-of-line block the next.
    pub async fn send_chunk(&self, number: u64, chunk: &[u8]) -> io::Result<()> {
        let mut stream = self
            .connection
            .open_uni()
            .await
            .map_err(|e| io::Error::other(format!("Could not open a stream: {e}")))?;

        let mut framed = Vec::with_capacity(8 + chunk.len());
        framed.extend_from_slice(&number.to_be_bytes());
        framed.extend_from_slice(chunk);

        stream
            .write_all(&framed)
            .await
            .map_err(|e| io::Error::other(format!("Could not send the chunk: {e}")))?;

        stream
            .finish()
            .map_err(|e| io::Error::other(format!("Could not finish the chunk: {e}")))?;

        Ok(())
    }

    /// Receive one chunk and the number it was sent as.
    pub async fn recv_chunk(&self, max_size: usize) -> io::Result<(u64, Vec<u8>)> {
        let mut stream = self
            .connection
            .accept_uni()
            .await
            .map_err(|e| io::Error::other(format!("Could not accept a stream: {e}")))?;

        let framed = stream
            .read_to_end(max_size + 8)
            .await
            .map_err(|e| io::Error::other(format!("Could not read the chunk: {e}")))?;

        if framed.len() < 8 {
            return Err(io::Error::other("Chunk arrived without a number".to_string()));
        }

        let number = u64::from_be_bytes(framed[..8].try_into().expect("8 bytes"));

        Ok((number, framed[8..].to_vec()))
    }

    pub fn remote_address(&self) -> std::net::SocketAddr {
        self.connection.remote_address()
    }

    pub fn close(&self) {
        self.connection.close(0u32.into(), b"done");
    }
}

/// Run QUIC over an already-punched path.
pub async fn connect(path: DirectPath) -> io::Result<PeerConnection> {
    let DirectPath { socket, peer, role } = path;

    socket.set_nonblocking(true)?;

    let runtime = quinn::default_runtime()
        .ok_or_else(|| io::Error::other("No async runtime for QUIC".to_string()))?;

    match role {
        // The camera listens.
        Role::Camera => {
            let endpoint = Endpoint::new(
                EndpointConfig::default(),
                Some(server_config()?),
                socket,
                runtime,
            )
            .map_err(|e| io::Error::other(format!("Could not open a QUIC endpoint: {e}")))?;

            let incoming = endpoint
                .accept()
                .await
                .ok_or_else(|| io::Error::other("QUIC endpoint closed".to_string()))?;

            let connection = incoming
                .await
                .map_err(|e| io::Error::other(format!("QUIC handshake failed: {e}")))?;

            Ok(PeerConnection {
                connection,
                _endpoint: endpoint,
            })
        }

        Role::App => {
            let mut endpoint = Endpoint::new(EndpointConfig::default(), None, socket, runtime)
                .map_err(|e| io::Error::other(format!("Could not open a QUIC endpoint: {e}")))?;
            endpoint.set_default_client_config(client_config()?);

            let connection = endpoint
                .connect(peer, "secluso")
                .map_err(|e| io::Error::other(format!("Could not dial the peer: {e}")))?
                .await
                .map_err(|e| io::Error::other(format!("QUIC handshake failed: {e}")))?;

            Ok(PeerConnection {
                connection,
                _endpoint: endpoint,
            })
        }
    }
}

/// Specify crypto provider rather than relying on the process-wide default.
fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn transport_config() -> Arc<TransportConfig> {
    let mut transport = TransportConfig::default();
    transport.max_idle_timeout(Some(
        IDLE_TIMEOUT
            .try_into()
            .expect("idle timeout fits in a QUIC varint"),
    ));
    transport.keep_alive_interval(Some(KEEP_ALIVE));
    Arc::new(transport)
}

/// A fresh self-signed certificate per session. Nothing verifies it (no point of persisting.. but see TODO)
fn server_config() -> io::Result<ServerConfig> {
    let cert = rcgen::generate_simple_self_signed(vec!["secluso".to_string()])
        .map_err(|e| io::Error::other(format!("Could not generate a certificate: {e}")))?;

    let cert_der = CertificateDer::from(cert.cert);
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());

    // The server has to advertise the same ALPN the client demands
    let mut crypto = rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| io::Error::other(format!("Could not build the QUIC server: {e}")))?
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key.into())
        .map_err(|e| io::Error::other(format!("Could not build the QUIC server: {e}")))?;
    crypto.alpn_protocols = vec![ALPN.to_vec()];

    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(crypto)
        .map_err(|e| io::Error::other(format!("Could not build the QUIC server: {e}")))?;

    let mut config = ServerConfig::with_crypto(Arc::new(quic_crypto));
    config.transport_config(transport_config());

    Ok(config)
}

fn client_config() -> io::Result<ClientConfig> {
    let mut crypto = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| io::Error::other(format!("Could not build the QUIC client: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyPeer))
        .with_no_client_auth();
    crypto.alpn_protocols = vec![ALPN.to_vec()];

    let quic_crypto = QuicClientConfig::try_from(crypto)
        .map_err(|e| io::Error::other(format!("Could not build the QUIC client: {e}")))?;

    let mut config = ClientConfig::new(Arc::new(quic_crypto));
    config.transport_config(transport_config());

    Ok(config)
}

/// Accepts whatever certificate the peer presents. See TODO
#[derive(Debug)]
struct AcceptAnyPeer;

impl ServerCertVerifier for AcceptAnyPeer {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;

    /// The handshake and a chunk (via usage of loopback)
    #[test]
    fn a_chunk_survives_the_round_trip() {
        let camera_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let app_socket = UdpSocket::bind("127.0.0.1:0").unwrap();

        let camera_addr = camera_socket.local_addr().unwrap();
        let app_addr = app_socket.local_addr().unwrap();

        let chunk = b"encrypted-livestream-chunk".to_vec();
        let expected = chunk.clone();

        let camera = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            runtime.block_on(async move {
                let connection = connect(DirectPath {
                    socket: camera_socket,
                    peer: app_addr,
                    role: Role::Camera,
                })
                .await
                .expect("camera should accept");

                connection.send_chunk(7, &chunk).await.expect("send");
                // Hold the connection open long enough for the chunk to drain.
                tokio::time::sleep(Duration::from_millis(200)).await;
            });
        });

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let received = runtime.block_on(async move {
            let connection = connect(DirectPath {
                socket: app_socket,
                peer: camera_addr,
                role: Role::App,
            })
            .await
            .expect("app should connect");

            connection.recv_chunk(64 * 1024).await.expect("recv")
        });

        camera.join().unwrap();
        assert_eq!(received, (7, expected));
    }
}
