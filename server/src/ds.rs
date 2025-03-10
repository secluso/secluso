//! Privastead Delivery Service (DS).
//! The DS is fully untrusted.
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

//! Based on OpenMLS DS (openmls/delivery-service).
//! MIT License.
//!
//! # The OpenMLS Delivery Service (DS).
//!
//! This is a minimal implementation of 2.3. Delivery Service in
//! [The MLS Architecture](https://messaginglayersecurity.rocks/mls-architecture/draft-ietf-mls-architecture.html).
//! It is used for end-to-end testing of OpenMLS and can be used by other
//! implementations. However it should never be used in any sort of production
//! environment.
//!
//! Because the infrastructure description doesn't give a lot of guidelines on
//! the design of the DS we take a couple of deliberate design decisions here:
//! * The DS does not know about groups.
//! * Clients have to send a list of clients (group members) along with each
//!   message for the DS to know where to send the message.
//! * The DS stores and delivers key packages.
//!
//! This is a very basic delivery service that allows to register clients and
//! send messages to MLS groups.
//! Note that there are a lot of limitations to this service:
//! * No persistence layer such that all information gets lost when the process
//!   shuts down.
//! * No authentication for clients.
//! * Key packages can't be updated, changed or deleted at the moment.
//! * Messages lost in transit are gone.
//!
//! **⚠️ DON'T EXPECT ANY SECURITY OR PRIVACY FROM THIS!**
//!
//! The server always listens on localhost and should be run behind a TLS server
//! if accessible on the public internet.
//!
//! The DS returns a list of messages queued for the client in all groups they
//! are part of.

use crate::fcm::send_notification;
use chrono::Utc;
use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::ffi::OsStringExt;
use std::path::Path;
use tls_codec::{Deserialize, Serialize, TlsByteSliceU16, TlsByteVecU16, TlsSliceU16};

use ds_lib::*;
use openmls::prelude::*;

#[derive(Debug)]
struct EnhancedClientInfo {
    client_info: ClientInfo,
    /// Used for the FCM token needed to send push notifications to app.
    token: String,
    last_recv_timestamp: i64,
}

impl EnhancedClientInfo {
    pub fn new(client_info: ClientInfo, token: String) -> Self {
        Self {
            client_info,
            token,
            last_recv_timestamp: 0,
        }
    }
}

impl tls_codec::Size for EnhancedClientInfo {
    fn tls_serialized_len(&self) -> usize {
        self.client_info.tls_serialized_len()
            + TlsByteSliceU16(self.token.as_bytes()).tls_serialized_len()
    }
}

impl tls_codec::Serialize for EnhancedClientInfo {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let written = self.client_info.tls_serialize(writer)?;
        TlsByteSliceU16(self.token.as_bytes())
            .tls_serialize(writer)
            .map(|l| l + written)
    }
}

impl tls_codec::Deserialize for EnhancedClientInfo {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let client_info = ClientInfo::tls_deserialize(bytes)?;
        let token =
            String::from_utf8_lossy(TlsByteVecU16::tls_deserialize(bytes)?.as_slice()).into();
        Ok(Self::new(client_info, token))
    }
}

#[derive(Serialize, Deserialize)]
struct UpdateTokenRequest {
    client_id: Vec<u8>,
    token: String,
}

#[derive(Serialize, Deserialize, Default, Debug)]
struct TrafficMeter {
    outgoing: u64,
    last_saved_outgoing: u64,
    creation_time: i64, //in non-leap seconds since January 1, 1970 0:00:00 UTC -- “UNIX timestamp”
    allowed_rate: u64,  //in B/hour
    dir: String,
}

impl TrafficMeter {
    pub fn new(dir: String) -> Self {
        let outgoing_pathname = dir.clone() + "/ds_traffic_meter_outgoing";
        let creation_time_pathname = dir.clone() + "/ds_traffic_meter_creation_time";

        let outgoing = Self::restore_outgoing(outgoing_pathname);
        let creation_time = Self::restore_creation_time(creation_time_pathname);

        Self {
            outgoing,
            last_saved_outgoing: outgoing,
            creation_time,
            allowed_rate: 536870912, //0.5 GB/hour
            dir,
        }
    }

    pub fn add_to_outgoing_traffic_meter(&mut self, len: u64) {
        // Account for the 4 header bytes in each outgoing response.
        self.outgoing += len + 4;
        // Save every 1 MB
        if (self.outgoing - self.last_saved_outgoing) > 1048576 {
            self.save_outgoing();
            self.last_saved_outgoing = self.outgoing;
        }
    }

    /// FIXME: Since we don't know how much data will be sent in the upcoming message
    /// that we are authorizing, we might go over the limit.
    pub fn is_outgoing_traffic_allowed(&self) -> bool {
        // Calculate consumed rate
        let now: i64 = Utc::now().timestamp();
        let elapsed = now - self.creation_time;
        let hours_since_creation = (elapsed / 3600) + 1;
        let consumed_rate: u64 = self.outgoing / hours_since_creation as u64;

        consumed_rate < self.allowed_rate
    }

    fn restore_outgoing(outgoing_pathname: String) -> u64 {
        if Path::new(&outgoing_pathname.clone()).exists() {
            let file = fs::File::open(outgoing_pathname).expect("Could not open file");
            let mut reader =
                BufReader::with_capacity(file.metadata().unwrap().len().try_into().unwrap(), file);
            let data = reader.fill_buf().unwrap();
            bincode::deserialize(data).unwrap()
        } else {
            0
        }
    }

    fn save_outgoing(&self) {
        let data = bincode::serialize(&self.outgoing).unwrap();
        let pathname = self.dir.clone() + "/ds_traffic_meter_outgoing";
        let mut file = fs::File::create(pathname).expect("Could not create file");
        let _ = file.write_all(&data);
    }

    fn restore_creation_time(creation_time_pathname: String) -> i64 {
        if Path::new(&creation_time_pathname.clone()).exists() {
            let file = fs::File::open(creation_time_pathname).expect("Could not open file");
            let mut reader =
                BufReader::with_capacity(file.metadata().unwrap().len().try_into().unwrap(), file);
            let data = reader.fill_buf().unwrap();
            bincode::deserialize(data).unwrap()
        } else {
            // first time
            let creation_time = Utc::now().timestamp();
            Self::save_creation_time(creation_time_pathname, creation_time);
            creation_time
        }
    }

    fn save_creation_time(creation_time_pathname: String, creation_time: i64) {
        let data = bincode::serialize(&creation_time).unwrap();
        let mut file = fs::File::create(creation_time_pathname).expect("Could not create file");
        let _ = file.write_all(&data);
    }
}

/// The DS state.
/// It holds a list of clients and their information.
#[derive(Default, Debug)]
pub struct DeliveryService {
    clients: HashMap<Vec<u8>, EnhancedClientInfo>,
    //groups: HashMap<Vec<u8>, u64>,
    dir: String,
    traffic_meter: TrafficMeter,
}

//We don't persist the state currently. Persisting the clients field will end
//up rewriting the same messages again and again, which could be a lot.
//In case messages are lost, the camera will resend the video(s).

// === API ===
impl DeliveryService {
    pub fn new(dir: String) -> Self {
        let clients_dir_pathname = dir.clone() + "/ds_clients_state";
        //let groups_pathname = dir.clone() + "/ds_groups_state";

        fs::create_dir_all(clients_dir_pathname.clone()).unwrap();
        let clients = Self::restore_clients_state(clients_dir_pathname.to_string());

        let traffic_meter = TrafficMeter::new(dir.clone());

        Self {
            clients,
            dir,
            traffic_meter,
        }
    }

    fn restore_clients_state(dir: String) -> HashMap<Vec<u8>, EnhancedClientInfo> {
        let mut clients = HashMap::new();

        match fs::read_dir(dir.clone()) {
            Ok(files) => {
                for file in files {
                    match file {
                        Ok(f) => {
                            match f.file_type() {
                                Ok(file_type) => {
                                    //Ignore dir, symlink, etc.
                                    if file_type.is_file() {
                                        let mut pathname = OsString::from(dir.clone() + "/");
                                        pathname.push(f.file_name());
                                        let fil =
                                            fs::File::open(pathname).expect("Could not open file");
                                        let mut reader = BufReader::with_capacity(
                                            fil.metadata().unwrap().len().try_into().unwrap(),
                                            fil,
                                        );
                                        let data = reader.fill_buf().unwrap();
                                        let info =
                                            EnhancedClientInfo::tls_deserialize(&mut &data[..])
                                                .unwrap();
                                        log::debug!(
                                            "Loading info for client {:?}",
                                            info.client_info.id.clone()
                                        );
                                        let old = clients.insert(info.client_info.id.clone(), info);
                                        if old.is_some() {
                                            panic!("Duplicate client!");
                                        }
                                    }
                                }
                                Err(e) => {
                                    panic!("Could not get file type: {:?}", e);
                                }
                            }
                        }
                        Err(e) => {
                            panic!("Could not read file from directory: {:?}", e);
                        }
                    }
                }
            }
            Err(e) => {
                panic!("Could not read directory: {:?}", e);
            }
        }

        clients
    }

    fn save_client_state(&self, client: Vec<u8>) {
        let filename = OsString::from_vec(client.clone());
        let mut pathname = OsString::from(self.dir.clone() + "/ds_clients_state/");
        pathname.push(filename);

        let mut data = Vec::new();
        self.clients
            .get(&client)
            .unwrap()
            .tls_serialize(&mut data)
            .unwrap();
        let mut file = fs::File::create(pathname).expect("Could not create file");
        let _ = file.write_all(&data);
    }

    fn delete_client_state(&self, client: Vec<u8>) {
        let filename = OsString::from_vec(client.clone());
        let mut pathname = OsString::from(self.dir.clone() + "/ds_clients_state/");
        pathname.push(filename);
        let _ = fs::remove_file(pathname);
    }

    /// Registering a new client takes a serialised `ClientInfo` object and returns
    /// a simple "Welcome {client name}" on success.
    pub fn register_client(&mut self, buf: &[u8], resp_buf: &mut Vec<u8>) {
        if !self.traffic_meter.is_outgoing_traffic_allowed() {
            return;
        }

        let info = match ClientInfo::tls_deserialize(&mut &buf[..]) {
            Ok(i) => i,
            Err(_) => {
                let resp: u8 = 1;
                *resp_buf = bincode::serialize(&resp).unwrap();
                self.traffic_meter
                    .add_to_outgoing_traffic_meter(resp_buf.len() as u64);
                return;
            }
        };

        log::debug!("Registering client: {:?}", info);

        let mut einfo = EnhancedClientInfo::new(info, "".to_string());

        let id_clone = einfo.client_info.id.clone();

        // If we're updating the client, we need to keep the FCM token.
        if let Some(old) = self.clients.get_mut(&einfo.client_info.id.clone()) {
            log::debug!("Updating client!");
            einfo.token.clone_from(&old.token);
        }

        self.clients.insert(einfo.client_info.id.clone(), einfo);

        self.save_client_state(id_clone);

        let resp: u8 = 0;
        *resp_buf = bincode::serialize(&resp).unwrap();
        self.traffic_meter
            .add_to_outgoing_traffic_meter(resp_buf.len() as u64);
    }

    /// Deregister client
    pub fn deregister_client(&mut self, buf: &[u8], resp_buf: &mut Vec<u8>) {
        if !self.traffic_meter.is_outgoing_traffic_allowed() {
            return;
        }

        let client_id = buf;

        log::debug!("Deregister request. Client ID: {:?}", client_id);

        self.delete_client_state(client_id.to_vec());

        match self.clients.remove(client_id) {
            Some(_) => {}
            None => {
                log::debug!("Error: client not found: {:?}", client_id.to_vec());
                let resp: u8 = 1;
                *resp_buf = bincode::serialize(&resp).unwrap();
                self.traffic_meter
                    .add_to_outgoing_traffic_meter(resp_buf.len() as u64);
                return;
            }
        };

        // FIXME: no need for serialize here. Just push to vector.
        let resp: u8 = 0;
        *resp_buf = bincode::serialize(&resp).unwrap();
        self.traffic_meter
            .add_to_outgoing_traffic_meter(resp_buf.len() as u64);
    }

    /// Send an FCM push notification to (app) Client.
    fn send_push_notification(client: &mut EnhancedClientInfo, msg: Vec<u8>) {
        // No FCM token available.
        if client.token.is_empty() {
            return;
        }

        let _ = send_notification(client.token.clone(), msg);
    }

    /// Update the token in EnhancedClientInfo
    pub fn update_token(&mut self, buf: &[u8], resp_buf: &mut Vec<u8>) {
        if !self.traffic_meter.is_outgoing_traffic_allowed() {
            return;
        }

        let request: UpdateTokenRequest = bincode::deserialize(buf).unwrap();

        log::debug!(
            "Update token request. Client ID: {:?}, Token: {:?}",
            request.client_id,
            request.token
        );

        match self.clients.get_mut(&request.client_id.to_vec()) {
            Some(client) => {
                client.token = request.token;
            }
            None => {
                log::debug!("Error: client not found: {:?}", request.client_id.to_vec());
                let resp: u8 = 1;
                *resp_buf = bincode::serialize(&resp).unwrap();
                self.traffic_meter
                    .add_to_outgoing_traffic_meter(resp_buf.len() as u64);
                return;
            }
        };

        self.save_client_state(request.client_id.to_vec());

        // FIXME: no need for serialize here. Just push to vector.
        let resp: u8 = 0;
        *resp_buf = bincode::serialize(&resp).unwrap();
        self.traffic_meter
            .add_to_outgoing_traffic_meter(resp_buf.len() as u64);
    }

    /// Send an MLS message to a set of clients (group).
    /// This takes a serialised `GroupMessage` and stores the message for each
    /// client in the recipient list.
    /// If a handshake message is sent with an epoch smaller or equal to another
    /// handshake message this DS has seen, an error is returned and the message is not
    /// processed.
    /// Return 0 or 255 on success.
    /// 0 indicates that the receiver has called received recently (heartbeat yes).
    /// 255 means that the receiver has not called received recently (heartbeat no).
    /// FIXME/TODO: the heartbeat algorithm only works if there's one recipient.
    pub fn send_msg(&mut self, buf: &[u8], resp_buf: &mut Vec<u8>, fcm: bool) {
        if !self.traffic_meter.is_outgoing_traffic_allowed() {
            return;
        }

        let group_msg = GroupMessage::tls_deserialize(&mut &buf[..]).unwrap();
        log::debug!("Storing group message: {:?}", group_msg);

        let mut heartbeat: u8 = 0;

        for recipient in group_msg.recipients.iter() {
            let client = match self.clients.get_mut(recipient.as_slice()) {
                Some(client) => client,
                None => {
                    let resp: u8 = 1;
                    *resp_buf = bincode::serialize(&resp).unwrap();
                    self.traffic_meter
                        .add_to_outgoing_traffic_meter(resp_buf.len() as u64);
                    return;
                }
            };

            let current_timestamp = Utc::now().timestamp();
            //FIXME: why 3 seconds?
            heartbeat = if current_timestamp - client.last_recv_timestamp < 3 {
                0
            } else {
                255
            };

            if fcm {
                //FIXME: Currently, we only have one message to serialize, so the use of
                //Vec<> is unnecessary.
                let mut msgs: Vec<MlsMessageIn> = Vec::new();
                msgs.push(group_msg.msg.clone());
                match TlsSliceU16(&msgs).tls_serialize_detached() {
                    Ok(out) => {
                        Self::send_push_notification(client, out);
                    }
                    Err(_) => {
                        log::debug!("Error: failed to serialize!");
                        let resp: u8 = 2;
                        *resp_buf = bincode::serialize(&resp).unwrap();
                        self.traffic_meter
                            .add_to_outgoing_traffic_meter(resp_buf.len() as u64);
                        return;
                    }
                }
            } else {
                client.client_info.msgs.push(group_msg.msg.clone());
            }
        }

        *resp_buf = bincode::serialize(&heartbeat).unwrap();
        self.traffic_meter
            .add_to_outgoing_traffic_meter(resp_buf.len() as u64);
    }

    /// Receive all messages stored for the client `{id}`.
    /// This returns a serialised vector of `Message`s (see the `ds-lib` for
    /// details) the DS has stored for the given client.
    /// The messages are deleted on the DS when sent out.
    pub fn recv_msgs(&mut self, id: &[u8], resp_buf: &mut Vec<u8>) {
        if !self.traffic_meter.is_outgoing_traffic_allowed() {
            return;
        }

        log::debug!("Getting messages for client {:?}", id);
        let client = match self.clients.get_mut(id) {
            Some(client) => client,
            None => {
                log::debug!("Error: client not found: {:?}", id.to_vec());
                let resp: u8 = 1;
                *resp_buf = bincode::serialize(&resp).unwrap();
                self.traffic_meter
                    .add_to_outgoing_traffic_meter(resp_buf.len() as u64);
                return;
            }
        };

        client.last_recv_timestamp = Utc::now().timestamp();

        let mut out: Vec<MlsMessageIn> = Vec::new();
        // Return one message at a time for now so that the size of the response buffer does not
        // get too big, needing multiple TLS packets.
        if !client.client_info.msgs.is_empty() {
            let mut msgs: Vec<MlsMessageIn> = client.client_info.msgs.drain(..1).collect();
            out.append(&mut msgs);
        }
        log::debug!("out (msgs) = {:?}", out);

        match TlsSliceU16(&out).tls_serialize_detached() {
            Ok(out) => {
                *resp_buf = out;
                self.traffic_meter
                    .add_to_outgoing_traffic_meter(resp_buf.len() as u64);
            }
            Err(_) => {
                log::debug!("Error: failed to serialize!");
                let resp: u8 = 1;
                *resp_buf = bincode::serialize(&resp).unwrap();
                self.traffic_meter
                    .add_to_outgoing_traffic_meter(resp_buf.len() as u64);
            }
        }
    }
}
