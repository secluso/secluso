//! Privastead client backend.
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

//! Based on the OpenMLS client (openmls/cli).
//! MIT License.

use super::stream::{read_varying_len, write_varying_len};
use ds_lib::*;
use openmls::prelude::*;
use privastead_client_server_lib::auth::{UserAuth, NUM_SECRET_BYTES, NUM_USERNAME_BYTES};
use privastead_client_server_lib::ops::{
    DEREGISTER_CLIENT, DO_AUTH, GET_NONCE, KEEP_ALIVE, KEEP_ALIVE_NO, KEEP_ALIVE_YES, RECV_MSGS,
    REGISTER_CLIENT, SEND_MSG, SEND_NOTIF, UPDATE_TOKEN,
};
use serde::Serialize as SerdeSerialize;
use std::io;
use std::net::TcpStream;
use tls_codec::{Deserialize, Serialize, TlsVecU16};

// FIXME: we have the same structure defined in ds.rs in the server.
#[derive(SerdeSerialize)]
struct UpdateTokenRequest {
    client_id: Vec<u8>,
    token: String,
}

impl UpdateTokenRequest {
    pub fn new(client_id: Vec<u8>, token: String) -> Self {
        Self { client_id, token }
    }
}

pub struct Backend {
    stream: TcpStream,
}

impl Backend {
    pub fn new(server_stream: TcpStream) -> Self {
        Self {
            stream: server_stream,
        }
    }

    pub fn auth_server_core(stream: &mut TcpStream, credentials: Vec<u8>) -> io::Result<()> {
        assert!(credentials.len() == (NUM_USERNAME_BYTES + NUM_SECRET_BYTES));

        let username: [u8; NUM_USERNAME_BYTES] =
            credentials[..NUM_USERNAME_BYTES].try_into().map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("try_into() for username failed ({e})"),
                )
            })?;
        let secret: [u8; NUM_SECRET_BYTES] =
            credentials[NUM_USERNAME_BYTES..].try_into().map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("try_into() for secret failed ({e})"),
                )
            })?;
        let user_auth = UserAuth::new(username, secret);

        let msg1_vec = vec![GET_NONCE];

        write_varying_len(stream, &msg1_vec)?;

        let resp1_vec = read_varying_len(stream)?;

        let mut msg2_vec = user_auth.generate_msg_to_server(resp1_vec);
        msg2_vec.push(DO_AUTH);

        write_varying_len(stream, &msg2_vec)?;

        let resp2_vec = read_varying_len(stream)?;
        let resp2: u8 = bincode::deserialize(&resp2_vec).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("deserialize in auth_server_core() failed ({e})"),
            )
        })?;

        if resp2 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("auth_server_core() returned error ({resp2})"),
            ));
        }

        Ok(())
    }

    /// Authenticate with the server.
    pub fn auth_server(&mut self, credentials: Vec<u8>) -> io::Result<()> {
        Self::auth_server_core(&mut self.stream, credentials)
    }

    /// Inform server of keep_alive requirement of the connection.
    pub fn keep_alive(&mut self, keep_alive: bool) -> io::Result<()> {
        let mut msg_vec = Vec::new();

        if keep_alive {
            msg_vec.push(KEEP_ALIVE_YES);
        } else {
            msg_vec.push(KEEP_ALIVE_NO);
        }

        msg_vec.push(KEEP_ALIVE);

        write_varying_len(&mut self.stream, &msg_vec)?;

        let resp_vec = read_varying_len(&mut self.stream)?;

        let resp: u8 = bincode::deserialize(&resp_vec).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("deserialize in keep_alive() failed ({e})"),
            )
        })?;

        if resp != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("keep_alive() returned error ({resp})"),
            ));
        }

        Ok(())
    }

    /// Register a new client with the server.
    pub fn register_client(&mut self, key_packages: Vec<(Vec<u8>, KeyPackage)>) -> io::Result<()> {
        let client_info = ClientInfo::new(
            key_packages
                .into_iter()
                .map(|(b, kp)| (b, KeyPackageIn::from(kp)))
                .collect(),
        );

        let mut info_vec = Vec::new();
        client_info.tls_serialize(&mut info_vec).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("tls_serialize in register_client() failed ({e})"),
            )
        })?;
        info_vec.push(REGISTER_CLIENT);
        write_varying_len(&mut self.stream, &info_vec)?;

        let resp_vec = read_varying_len(&mut self.stream)?;
        let resp: u8 = bincode::deserialize(&resp_vec).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("deserialize in register_client() failed ({e})"),
            )
        })?;

        if resp != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("register_client() returned error ({resp})"),
            ));
        }

        Ok(())
    }

    /// Degister the client from the server.
    pub fn deregister_client(&mut self, id: &[u8]) -> io::Result<()> {
        let mut msg_vec = id.to_vec();
        msg_vec.push(DEREGISTER_CLIENT);
        write_varying_len(&mut self.stream, &msg_vec)?;

        let resp_vec = read_varying_len(&mut self.stream)?;
        let resp: u8 = bincode::deserialize(&resp_vec).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("deserialize in deregister_client() failed ({e})"),
            )
        })?;

        if resp != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("deregister_client() returned error ({resp})"),
            ));
        }

        Ok(())
    }

    pub fn update_token(&mut self, id: &[u8], token: String) -> io::Result<()> {
        let request = UpdateTokenRequest::new(id.to_vec(), token);
        let mut msg_vec = bincode::serialize(&request).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("serialize in update_token() failed ({e})"),
            )
        })?;
        msg_vec.push(UPDATE_TOKEN);
        write_varying_len(&mut self.stream, &msg_vec)?;

        let resp_vec = read_varying_len(&mut self.stream)?;
        let resp: u8 = bincode::deserialize(&resp_vec).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("deserialize in update_token() failed ({e})"),
            )
        })?;

        if resp != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("update_token() returned error ({resp})"),
            ));
        }

        Ok(())
    }

    /// Send a group message.
    /// Returns true if receiver's heartbeat was received recently, false otherwise.
    /// FIXME/TODO: the heartbeat algorithm only works if there's one recipient.
    pub fn send_msg(&mut self, group_msg: &GroupMessage, fcm: bool) -> io::Result<bool> {
        let mut msg_vec = Vec::new();
        group_msg.tls_serialize(&mut msg_vec).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("tls_serialize in send_msg() failed ({e})"),
            )
        })?;
        if fcm {
            msg_vec.push(SEND_NOTIF);
        } else {
            msg_vec.push(SEND_MSG);
        }
        write_varying_len(&mut self.stream, &msg_vec)?;

        let resp_vec = read_varying_len(&mut self.stream)?;
        let resp: u8 = bincode::deserialize(&resp_vec).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("deserialize in send_msg() failed ({e})"),
            )
        })?;

        if resp == 0 {
            Ok(true)
        } else if resp == 255 {
            return Ok(false);
        } else {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("send_msg() returned error ({resp})"),
            ));
        }
    }

    /// Get a list of all new messages for the user.
    pub fn recv_msgs(&mut self, id: &[u8]) -> io::Result<Vec<MlsMessageIn>> {
        let mut id_vec = id.to_vec();
        id_vec.push(RECV_MSGS);
        write_varying_len(&mut self.stream, &id_vec)?;

        let resp_vec = read_varying_len(&mut self.stream)?;
        let resp = match TlsVecU16::<MlsMessageIn>::tls_deserialize(&mut resp_vec.as_slice()) {
            Ok(r) => r,
            Err(e) => {
                // This happens if the server returns an error or if tls_deserialize fails.
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("recv_msgs() returned error ({e})"),
                ));
            }
        };

        Ok(resp.into())
    }
}
