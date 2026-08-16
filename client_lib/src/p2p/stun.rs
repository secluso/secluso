//! SPDX-License-Identifier: GPL-3.0-or-later
//!
//! a STUN-ning implementation... just enough STUN to find our own public address.
//!
//! Hole punching needs each side to know the address the OTHER side will see
//! This isn't something we can find locally... a NAT rewrites it
//!
//! Hand-rolled; we don't need more than a very minimal impl.

use rand::RngCore;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::time::Duration;

/// Public STUN server(s)...
/// TODO: Add more here
pub const DEFAULT_STUN_SERVERS: &[&str] = &[
    "stun.cloudflare.com:3478",
];

const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const MAGIC_COOKIE: u32 = 0x2112_A442;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const HEADER_LEN: usize = 20;
const TRANSACTION_ID_LEN: usize = 12;

/// Ask a STUN server what address it sees us from.
pub fn reflexive_address(socket: &UdpSocket, server: &str) -> io::Result<SocketAddr> {
    let mut transaction_id = [0u8; TRANSACTION_ID_LEN];
    rand::rng().fill_bytes(&mut transaction_id);

    let mut request = Vec::with_capacity(HEADER_LEN);
    request.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
    request.extend_from_slice(&0u16.to_be_bytes());
    request.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    request.extend_from_slice(&transaction_id);

    socket.send_to(&request, server)?;

    let previous_timeout = socket.read_timeout()?;
    socket.set_read_timeout(Some(Duration::from_secs(3)))?;

    let mut buf = [0u8; 512];
    let result = socket.recv_from(&mut buf);

    socket.set_read_timeout(previous_timeout)?;

    let (len, _) = result?;
    parse_binding_response(&buf[..len], &transaction_id)
}

/// Try each server
pub fn discover_reflexive(socket: &UdpSocket, servers: &[&str]) -> Option<SocketAddr> {
    servers
        .iter()
        .find_map(|server| reflexive_address(socket, server).ok())
}

fn parse_binding_response(buf: &[u8], transaction_id: &[u8]) -> io::Result<SocketAddr> {
    if buf.len() < HEADER_LEN {
        return Err(io::Error::other("STUN response is too short".to_string()));
    }

    let message_type = u16::from_be_bytes([buf[0], buf[1]]);
    if message_type != BINDING_SUCCESS {
        return Err(io::Error::other(format!(
            "STUN server did not accept the binding request (type {message_type:#06x})"
        )));
    }

    // Reject a reply to somebody else's request. On a shared socket we may see anything.
    if &buf[8..HEADER_LEN] != transaction_id {
        return Err(io::Error::other(
            "STUN response was for a different transaction".to_string(),
        ));
    }

    let mut cursor = HEADER_LEN;
    while cursor + 4 <= buf.len() {
        let attr_type = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]);
        let attr_len = u16::from_be_bytes([buf[cursor + 2], buf[cursor + 3]]) as usize;
        let value_start = cursor + 4;
        let value_end = value_start + attr_len;

        if value_end > buf.len() {
            break;
        }

        if attr_type == ATTR_XOR_MAPPED_ADDRESS {
            return parse_xor_mapped_address(&buf[value_start..value_end]);
        }

        // Attributes are padded to a 4-byte boundary.
        cursor = value_end + ((4 - (attr_len % 4)) % 4);
    }

    Err(io::Error::other(
        "STUN response had no XOR-MAPPED-ADDRESS".to_string(),
    ))
}

/// Only IPv4 is decoded (ipv6 doesn't need hole punching)
fn parse_xor_mapped_address(value: &[u8]) -> io::Result<SocketAddr> {
    if value.len() < 8 {
        return Err(io::Error::other("XOR-MAPPED-ADDRESS is too short".to_string()));
    }

    const FAMILY_IPV4: u8 = 0x01;
    if value[1] != FAMILY_IPV4 {
        return Err(io::Error::other(
            "XOR-MAPPED-ADDRESS is not IPv4".to_string(),
        ));
    }

    // Both the port and the address are XORed with the cookie
    let port = u16::from_be_bytes([value[2], value[3]]) ^ (MAGIC_COOKIE >> 16) as u16;
    let raw = u32::from_be_bytes([value[4], value[5], value[6], value[7]]) ^ MAGIC_COOKIE;

    Ok(SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::from(raw),
        port,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(transaction_id: &[u8; TRANSACTION_ID_LEN], attrs: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        buf.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
        buf.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        buf.extend_from_slice(transaction_id);
        buf.extend_from_slice(attrs);
        buf
    }

    fn xor_mapped(addr: Ipv4Addr, port: u16) -> Vec<u8> {
        let mut attr = vec![0u8, 0x01];
        attr.extend_from_slice(&(port ^ (MAGIC_COOKIE >> 16) as u16).to_be_bytes());
        attr.extend_from_slice(&(u32::from(addr) ^ MAGIC_COOKIE).to_be_bytes());

        let mut out = Vec::new();
        out.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        out.extend_from_slice(&(attr.len() as u16).to_be_bytes());
        out.extend_from_slice(&attr);
        out
    }

    #[test]
    fn decodes_our_public_address() {
        let id = [7u8; TRANSACTION_ID_LEN];
        let buf = response(&id, &xor_mapped(Ipv4Addr::new(203, 0, 113, 5), 51820));

        let addr = parse_binding_response(&buf, &id).unwrap();

        assert_eq!(addr.ip().to_string(), "203.0.113.5");
        assert_eq!(addr.port(), 51820);
    }

    #[test]
    fn skips_attributes_it_does_not_understand() {
        // Real servers send SOFTWARE and friends ahead of the address
        let id = [3u8; TRANSACTION_ID_LEN];
        let mut attrs = vec![0x80, 0x22, 0x00, 0x05, b'h', b'i', b'!', b'!', b'!', 0x00, 0x00, 0x00];
        attrs.extend_from_slice(&xor_mapped(Ipv4Addr::new(198, 51, 100, 9), 3478));

        let addr = parse_binding_response(&response(&id, &attrs), &id).unwrap();

        assert_eq!(addr.to_string(), "198.51.100.9:3478");
    }

    #[test]
    fn rejects_another_transaction() {
        // A shared socket sees other traffic
        let buf = response(&[1u8; TRANSACTION_ID_LEN], &xor_mapped(Ipv4Addr::LOCALHOST, 1));

        assert!(parse_binding_response(&buf, &[2u8; TRANSACTION_ID_LEN]).is_err());
    }

    #[test]
    fn rejects_an_error_response() {
        let id = [5u8; TRANSACTION_ID_LEN];
        let mut buf = response(&id, &[]);
        buf[0..2].copy_from_slice(&0x0111u16.to_be_bytes()); // Binding Error

        assert!(parse_binding_response(&buf, &id).is_err());
    }

    #[test]
    fn rejects_a_truncated_message() {
        assert!(parse_binding_response(&[0u8; 4], &[0u8; TRANSACTION_ID_LEN]).is_err());
    }
}