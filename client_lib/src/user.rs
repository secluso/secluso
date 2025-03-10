//! Privastead client.
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

use super::backend::Backend;
use super::identity::Identity;
use super::openmls_rust_persistent_crypto::OpenMlsRustPersistentCrypto;
use super::pcs::PcsInitiator;
use ds_lib::GroupMessage;
use openmls::prelude::*;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{cell::RefCell, collections::HashMap};
use tls_codec::{Serialize as TlsSerialize, Deserialize as TlsDeserialize, TlsVecU16};

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

pub type KeyPackages = Vec<(Vec<u8>, KeyPackage)>;

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Contact {
    username: String,
    id: Vec<u8>,
    //FIXME: do we need to keep key_packages?
    key_packages: KeyPackages,
}

impl Contact {
    pub fn get_credential(&self) -> Credential {
        return self.key_packages[0].1.leaf_node().credential().clone();
    }
}

#[derive(Serialize, Deserialize)]
pub struct Group {
    group_name: String,
    mls_group: RefCell<MlsGroup>,
    pcs_initiator: Option<RefCell<PcsInitiator>>,
    // The "only" contact that is also in this group.
    only_contact: Option<Contact>,
}

pub struct User {
    pub(crate) username: String,
    pub(crate) groups: RefCell<HashMap<Vec<u8>, Group>>,
    pub(crate) identity: RefCell<Identity>,
    backend: Option<Backend>,
    provider: OpenMlsRustPersistentCrypto,
    file_dir: String,
    tag: String,
}

impl User {
    /// if first_time, create a new user with the given name and a fresh set of credentials.
    /// else, restore existing client.
    /// user_credentials: the user credentials needed to authenticate with the server. Different from OpenMLS credentials.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        username: String,
        server_stream: Option<TcpStream>,
        first_time: bool,
        reregister: bool,
        file_dir: String,
        tag: String,
        user_credentials: Vec<u8>,
        keep_alive: bool,
    ) -> io::Result<Self> {
        let mut crypto = OpenMlsRustPersistentCrypto::default();
        let groups = if first_time {
            RefCell::new(HashMap::new())
        } else {
            Self::restore_groups_state(file_dir.clone(), tag.clone())
        };
        if !first_time {
            let ks_files = Self::get_state_files_sorted(
                &file_dir,
                &("key_store_".to_string() + &tag.clone() + "_"),
            )
            .unwrap();
            let mut load_successful = false;
            for f in &ks_files {
                let ks_pathname = file_dir.clone() + "/" + f;
                let file = fs::File::open(ks_pathname).expect("Could not open file");
                let result = crypto.load_keystore(&file);
                if result.is_ok() {
                    load_successful = true;
                    break;
                }
            }

            if !load_successful {
                panic!("Could not successfully load the key store from file.");
            }
        }

        let backend = match server_stream {
            Some(stream) => Some(Backend::new(stream)),
            None => None
        };

        let mut out = Self {
            username: username.clone(),
            groups,
            identity: RefCell::new(Identity::new(
                CIPHERSUITE,
                &crypto,
                username.as_bytes(),
                first_time,
                file_dir.clone(),
                tag.clone(),
            )),
            backend,
            provider: crypto,
            file_dir,
            tag,
        };

        if out.backend.is_some() {
            // Authenticate with the server first for a new connection.
            out.backend.as_mut().unwrap().auth_server(user_credentials)?;

            // Inform the server whether this connection should be kept alive if idle
            out.backend.as_mut().unwrap().keep_alive(keep_alive)?;

            if reregister {
                let key_packages = out.key_packages();
                out.backend.as_mut().unwrap().register_client(key_packages)?;
            }
        }

        Ok(out)
    }

    pub fn deregister(&mut self) -> io::Result<()> {
        if self.backend.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Backend not initialized.",
            ));
        }

        self.backend
            .as_mut()
            .unwrap()
            .deregister_client(self.identity.borrow().identity())?;
        self.identity
            .borrow()
            .delete_signature_key(self.file_dir.clone(), self.tag.clone());

        let _ = fs::remove_file(self.file_dir.clone() + "/registration_done");

        let g_files = Self::get_state_files_sorted(
            &self.file_dir,
            &("groups_state_".to_string() + &self.tag.clone() + "_"),
        )
        .unwrap();
        for f in &g_files[..] {
            let _ = fs::remove_file(self.file_dir.clone() + "/" + f);
        }

        let ks_files = Self::get_state_files_sorted(
            &self.file_dir,
            &("key_store_".to_string() + &self.tag.clone() + "_"),
        )
        .unwrap();
        for f in &ks_files[..] {
            let _ = fs::remove_file(self.file_dir.clone() + "/" + f);
        }

        Ok(())
    }

    pub fn get_file_dir(&self) -> String {
        self.file_dir.clone()
    }

    /// Get the key packages fo this user.
    pub fn key_packages(&self) -> Vec<(Vec<u8>, KeyPackage)> {
        // clone first !
        let kpgs = self.identity.borrow().kp.clone();
        Vec::from_iter(kpgs)
    }

    /// Update FCM token in the server.
    pub fn update_token(&mut self, token: String) -> io::Result<()> {
        if self.backend.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Backend not initialized.",
            ));
        }

        self.backend
            .as_mut()
            .unwrap()
            .update_token(self.identity.borrow().identity(), token)
    }

    /// Get a list of clients in the group to send messages to.
    /// This is currently very simple: return the only_contact
    fn recipients(&self, group: &Group) -> Vec<Vec<u8>> {
        let recipients = vec![group.only_contact.as_ref().unwrap().id.clone()];
        recipients
    }

    /// Create a group with the given name.
    pub fn create_group(&mut self, name: String) {
        log::debug!("{} creates group {}", self.username, name);
        let group_id = name.as_bytes();
        let mut group_aad = group_id.to_vec();
        group_aad.extend(b" AAD");

        // NOTE: Since the DS currently doesn't distribute copies of the group's ratchet
        // tree, we need to include the ratchet_tree_extension.
        let group_config = MlsGroupCreateConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();

        let mut mls_group = MlsGroup::new_with_group_id(
            &self.provider,
            &self.identity.borrow().signer,
            &group_config,
            GroupId::from_slice(group_id),
            self.identity.borrow().credential_with_key.clone(),
        )
        .expect("Failed to create MlsGroup");
        //FIXME: needed?
        mls_group.set_aad(group_aad);

        let group = Group {
            group_name: name.clone(),
            mls_group: RefCell::new(mls_group),
            pcs_initiator: Some(RefCell::new(PcsInitiator::new())),
            only_contact: None,
        };

        if self
            .groups
            .borrow_mut()
            .insert(group_id.to_vec(), group)
            .is_some()
        {
            panic!("Group '{}' existed already", name);
        }
    }

    /// Invite a contact to a group.
    pub fn invite(&mut self, contact: &Contact, group_name: String) -> io::Result<Vec<u8>> {
        let joiner_key_package = contact.key_packages[0].1.clone();

        // Build a proposal with this key package and do the MLS bits.
        let group_id = group_name.as_bytes();
        let mut groups = self.groups.borrow_mut();
        let group = match groups.get_mut(group_id) {
            Some(g) => g,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "No group with name {group_name} known.",
                ))
            }
        };

        if group.only_contact.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Cannot invite more than one member to the group.",
            ));
        }

        // Note: out_messages is needed for other group members.
        // Currently, we don't need/use it since our groups only have
        // two members, an inviter (camera) and an invitee (app).
        let (_out_messages, welcome, _group_info) = group
            .mls_group
            .borrow_mut()
            .add_members(
                &self.provider,
                &self.identity.borrow().signer,
                &[joiner_key_package],
            )
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to add member to group - {e}"),
                )
            })?;

        // First, process the invitation on our end.
        group
            .mls_group
            .borrow_mut()
            .merge_pending_commit(&self.provider)
            .expect("error merging pending commit");

        // Second, send Welcome to the joiner.
        //log::trace!("Sending welcome");
        //self.backend.as_mut().unwrap().send_welcome(&welcome)?;
        let mut welcome_msg_vec = Vec::new();
        welcome.tls_serialize(&mut welcome_msg_vec).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("tls_serialize for welcome_msg failed ({e})"),
            )
        })?;

        group.only_contact = Some(contact.clone());

        Ok(welcome_msg_vec)
    }

    /// Join a group with the provided welcome message.
    fn join_group(&self, welcome: Welcome, expected_inviter: Contact) -> io::Result<()> {
        log::debug!("{} joining group ...", self.username);

        // NOTE: Since the DS currently doesn't distribute copies of the group's ratchet
        // tree, we need to include the ratchet_tree_extension.
        let group_config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();
        let mut mls_group =
            StagedWelcome::new_from_welcome(&self.provider, &group_config, welcome, None)
                .expect("Failed to create staged join")
                .into_group(&self.provider)
                .expect("Failed to create MlsGroup");

        let group_id = mls_group.group_id().to_vec();
        //FIXME (from openmls): Use Welcome's encrypted_group_info field to store group_name.
        let group_name = String::from_utf8(group_id.clone()).unwrap();
        let group_aad = group_name.clone() + " AAD";

        //FIXME: needed?
        mls_group.set_aad(group_aad.as_bytes().to_vec());

        // Currently, we only support groups that have one camera and one app.
        if mls_group.members().count() != 2 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "Unexpected group size in the invitation {:?}",
                    mls_group.members().count()
                ),
            ));
        }

        // Check to ensure the welcome message is from the contact we expect.
        // Also check the other group member (which should be us).
        let mut inviter_confirmed = false;
        let mut invitee_confirmed = false;
        for Member {
            index: _,
            encryption_key: _,
            signature_key: _,
            credential,
        } in mls_group.members()
        {
            let credential = BasicCredential::try_from(credential).unwrap();
            if expected_inviter.id == credential.identity() {
                inviter_confirmed = true;
            } else if self.identity.borrow().identity() == credential.identity() {
                invitee_confirmed = true;
            }
        }

        if !inviter_confirmed || !invitee_confirmed {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Unexpected inviter/invitee identity",
            ));
        }

        let group = Group {
            group_name: group_name.clone(),
            mls_group: RefCell::new(mls_group),
            pcs_initiator: None,
            only_contact: Some(expected_inviter),
        };

        log::trace!("   {}", group_name);

        match self.groups.borrow_mut().insert(group_id, group) {
            Some(_old) => panic!("Error: duplicate group"),
            None => Ok(()),
        }
    }

    /// Process a welcome message
    pub fn process_welcome(&mut self, expected_inviter: Contact, welcome_msg_vec: Vec<u8>) -> io::Result<()> {
        let welcome_msg = match MlsMessageIn::tls_deserialize(&mut welcome_msg_vec.as_slice()) {
            Ok(msg) => msg,
            Err(e) => {return Err(io::Error::new(io::ErrorKind::Other, format!("{}", e)))},
        };

        match welcome_msg.extract() {
            MlsMessageBodyIn::Welcome(welcome) => {
                self.join_group(welcome, expected_inviter)
                    .unwrap();
            }
            _ => panic!("Unsupported message type in process_welcome"),
        }

        Ok(())
    }

    /// Saves the groups and key store in persistent storage.
    /// Earlier versions of this function would simply reuse the same file names.
    /// However, we would every once in a while end up with a corrupted file (mainly key store):
    /// The old file was gone and the new one was not fully written.
    /// To mitigate that, we write the state in a file with a new file name,
    /// which has the current timestamp, appended to it.
    /// Only when that file is written and persisted, we delete the old ones.
    /// When using these files at initialization time, we use the one with the
    /// largest timestamp (we could end up with multiple files at initialization
    /// time if this function is not fully executed).
    pub fn save_groups_state(&mut self) {
        // Use nanos in order to ensure that each time this function is called, we will use a new file name.
        // This does make some assumptions about the execution speed, but those assumptions are reasonable (for now).
        let current_timestamp: u128 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Could not convert time")
            .as_nanos();

        let data = bincode::serialize(&self.groups.get_mut()).unwrap();
        let pathname = self.file_dir.clone()
            + "/groups_state_"
            + &self.tag.clone()
            + "_"
            + &current_timestamp.to_string();
        let mut file = fs::File::create(pathname.clone()).expect("Could not create file");
        file.write_all(&data).unwrap();
        file.flush().unwrap();
        file.sync_all().unwrap();

        let ks_pathname = self.file_dir.clone()
            + "/key_store_"
            + &self.tag.clone()
            + "_"
            + &current_timestamp.to_string();
        let mut ks_file = fs::File::create(ks_pathname.clone()).expect("Could not create file");
        self.provider.save_keystore(&ks_file).unwrap();
        ks_file.flush().unwrap();
        ks_file.sync_all().unwrap();

        //delete old groups state files
        let g_files = Self::get_state_files_sorted(
            &self.file_dir,
            &("groups_state_".to_string() + &self.tag.clone() + "_"),
        )
        .unwrap();
        assert!(
            g_files[0]
                == "groups_state_".to_owned()
                    + &self.tag.clone()
                    + "_"
                    + &current_timestamp.to_string()
        );
        for f in &g_files[1..] {
            let _ = fs::remove_file(self.file_dir.clone() + "/" + f);
        }

        let ks_files = Self::get_state_files_sorted(
            &self.file_dir,
            &("key_store_".to_string() + &self.tag.clone() + "_"),
        )
        .unwrap();
        assert!(
            ks_files[0]
                == "key_store_".to_owned()
                    + &self.tag.clone()
                    + "_"
                    + &current_timestamp.to_string()
        );
        for f in &ks_files[1..] {
            let _ = fs::remove_file(self.file_dir.clone() + "/" + f);
        }
    }

    pub fn restore_groups_state(file_dir: String, tag: String) -> RefCell<HashMap<Vec<u8>, Group>> {
        let g_files =
            Self::get_state_files_sorted(&file_dir, &("groups_state_".to_string() + &tag + "_"))
                .unwrap();
        for f in &g_files {
            let pathname = file_dir.clone() + "/" + f;
            let file = fs::File::open(pathname).expect("Could not open file");
            let mut reader =
                BufReader::with_capacity(file.metadata().unwrap().len().try_into().unwrap(), file);
            let data = reader.fill_buf().unwrap();
            let deserialize_result = bincode::deserialize(data);
            if let Ok(deserialized_data) = deserialize_result {
                return RefCell::new(deserialized_data);
            }
        }

        panic!("Could not successfully load the groups state from file.");
    }

    pub fn get_state_files_sorted(dir_path: &str, pattern: &str) -> std::io::Result<Vec<String>> {
        let mut matching_files: Vec<(String, u128)> = Vec::new();

        for entry in fs::read_dir(dir_path)? {
            let entry = entry?;
            let file_name = entry.file_name();
            let file_name_str = file_name.to_string_lossy();

            if file_name_str.starts_with(pattern) {
                if let Some(timestamp) = Self::extract_timestamp(&file_name_str, pattern) {
                    matching_files.push((file_name_str.to_string(), timestamp));
                }
            }
        }

        matching_files.sort_by(|a, b| b.1.cmp(&a.1));
        let sorted_files: Vec<String> = matching_files.into_iter().map(|(name, _)| name).collect();

        Ok(sorted_files)
    }

    fn extract_timestamp(file_name: &str, pattern: &str) -> Option<u128> {
        file_name
            .strip_prefix(pattern)?
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>()
            .parse::<u128>()
            .ok()
    }

    pub fn add_contact(&mut self, name: String, key_packages: KeyPackages) -> io::Result<Contact> {
        // FIXME: The identity of a client is defined as the identity of the first key
        // package right now.
        // Note: we only use one key package anyway.
        let key_package = key_packages[0].1.clone();
        let id = key_package
            .leaf_node()
            .credential()
            .serialized_content()
            .to_vec();
        let contact = Contact {
            username: name,
            key_packages,
            id: id.clone(),
        };

        let contact_comp = Some(contact.clone());
        for (_group_id, group) in self.groups.borrow().iter() {
            if group.only_contact == contact_comp {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Contact already exists".to_string(),
                ));
            }
        }

        Ok(contact)
    }

    pub fn get_group_name(&self, only_contact_name: String) -> io::Result<String> {
        for (_, group) in self.groups.borrow().iter() {
            if group.only_contact.is_some()
                && group.only_contact.as_ref().unwrap().username == only_contact_name
            {
                return Ok(group.group_name.clone());
            }
        }

        Err(io::Error::new(
            io::ErrorKind::Other,
            "Unknown group".to_string(),
        ))
    }

    /// Perform an MLS update
    /// Returns true if new update is performed
    /// Returns false if there is a pending update
    pub fn perform_update(&mut self, group_name: String) -> io::Result<bool> {
        let groups = self.groups.borrow();
        let group = match groups.get(group_name.as_bytes()) {
            Some(g) => g,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Unknown group".to_string(),
                ))
            }
        };

        if group.pcs_initiator.is_some() {
            let mut pcs_initiator = group.pcs_initiator.as_ref().unwrap().borrow_mut();
            if pcs_initiator.has_pending_update() {
                Ok(false)
            } else {
                let msg = self.update_commit(group)?;
                pcs_initiator.updated(&msg);
                Ok(true)
            }
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "Only the PCS initiator can force an update.",
            ))
        }
    }

    /// Send pending update
    pub fn send_update(&mut self, group_name: String) -> io::Result<()> {
        if self.backend.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Backend not initialized.",
            ));
        }

        let groups = self.groups.borrow();
        let group = match groups.get(group_name.as_bytes()) {
            Some(g) => g,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Unknown group".to_string(),
                ))
            }
        };

        if group.pcs_initiator.is_some() {
            let mut pcs_initiator = group.pcs_initiator.as_ref().unwrap().borrow_mut();
            if pcs_initiator.has_pending_update() {
                let msg = pcs_initiator.get_pending_update_msg();
                if msg.is_ok() {
                    // Send the MlsMessages to the group.
                    self.backend.as_mut().unwrap().send_msg(&msg.unwrap(), false)?;
                    Ok(())
                } else {
                    panic!("Has pending update but returns error for msg!");
                }
            } else {
                Err(io::Error::new(
                    io::ErrorKind::Other,
                    "No pending update to send.",
                ))
            }
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "Only the PCS initiator can send an update.",
            ))
        }
    }

    /// Generate a commit to update self leaf node in the ratchet tree, merge the commit, and return the message
    /// to be sent to other group members.
    fn update_commit(&self, group: &Group) -> io::Result<GroupMessage> {
        // FIXME: _welcome should be none, group_info should be some.
        // See openmls/src/group/mls_group/updates.rs.
        let (out_message, _welcome, _group_info) = group
            .mls_group
            .borrow_mut()
            .self_update(
                &self.provider,
                &self.identity.borrow().signer,
                LeafNodeParameters::default(),
            )
            .map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("Failed to self update - {e}"))
            })?;

        log::trace!("Generating update message");
        let group_recipients = self.recipients(group);
        // Generate the message to the group.
        let msg = GroupMessage::new(out_message.into(), &group_recipients);

        // Merge pending commit.
        group
            .mls_group
            .borrow_mut()
            .merge_pending_commit(&self.provider)
            .expect("error merging pending commit");

        Ok(msg)
    }

    /// Returns true if receiver's heartbeat was received recently, false otherwise.
    /// FIXME/TODO: the heartbeat algorithm only works if there's one recipient.
    fn send_core(&mut self, bytes: &[u8], group_name: String, fcm: bool) -> io::Result<bool> {
        if self.backend.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Backend not initialized.",
            ));
        }

        let groups = self.groups.borrow();
        let group = match groups.get(group_name.as_bytes()) {
            Some(g) => g,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Unknown group".to_string(),
                ))
            }
        };

        let message_out = group
            .mls_group
            .borrow_mut()
            .create_message(&self.provider, &self.identity.borrow().signer, bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{e}")))?;

        let msg = GroupMessage::new(message_out.into(), &self.recipients(group));
        log::debug!(" >>> send: {:?}", msg);
        self.backend.as_mut().unwrap().send_msg(&msg, fcm)
    }

    /// Send an array of bytes to the group.
    pub fn send(&mut self, bytes: &[u8], group_name: String) -> io::Result<bool> {
        self.send_core(bytes, group_name, false)
    }

    /// Send an array of bytes to the group through FCM.
    pub fn send_fcm(&mut self, bytes: &[u8], group_name: String) -> io::Result<bool> {
        self.send_core(bytes, group_name, true)
    }

    /// process_welcome: if true, this will only process welcome messages from the expected_inviter.
    /// if false, it will not process welcome messages at all.
    fn receive_core<F>(
        &mut self,
        mut callback: F,
        fcm: bool,
        fcm_msgs: Option<Vec<MlsMessageIn>>,
    ) -> io::Result<u64>
    where
        F: FnMut(Vec<u8>, String) -> io::Result<()>,
    {
        let mut process_protocol_message = |message: ProtocolMessage| {
            let mut groups = self.groups.borrow_mut();

            let group = match groups.get_mut(message.group_id().as_slice()) {
                Some(g) => g,
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!(
                            "Error getting group {:?} for a message. Dropping message.",
                            message.group_id()
                        ),
                    ));
                }
            };
            let mut mls_group = group.mls_group.borrow_mut();

            // This works since none of the other members of the group, other than the camera,
            // will be in our contact list (hence "only_matching_contact").
            let only_contact = group.only_contact.as_ref().unwrap();

            let processed_message = match mls_group.process_message(&self.provider, message) {
                Ok(msg) => msg,
                Err(e) => {
                    log::debug!("process_message returned: {e}");
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!(
                            "Error processing unverified message: {:?} -  Dropping message.",
                            e
                        ),
                    ));
                }
            };

            // Accepts messages from the only_contact in the group.
            // Note: in a ProcessedMessage, the credential of the message sender is already inspected.
            // See: openmls/src/framing/validation.rs
            let sender = processed_message.credential().clone();
            if sender != only_contact.get_credential() {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Error: received a message from an unknown party".to_string(),
                ));
            }

            match processed_message.into_content() {
                ProcessedMessageContent::ApplicationMessage(application_message) => {
                    if group.pcs_initiator.is_some() {
                        group
                            .pcs_initiator
                            .as_ref()
                            .unwrap()
                            .borrow_mut()
                            .message_received();
                    }

                    let application_message = application_message.into_bytes();

                    callback(application_message, only_contact.username.clone())?;
                    Ok(true)
                }
                ProcessedMessageContent::ProposalMessage(_proposal_ptr) => {
                    panic!("Unexpected proposal message!");
                }
                ProcessedMessageContent::ExternalJoinProposalMessage(_external_proposal_ptr) => {
                    panic!("Unexpected external join proposal message!");
                }
                ProcessedMessageContent::StagedCommitMessage(commit_ptr) => {
                    mls_group
                        .merge_staged_commit(&self.provider, *commit_ptr)
                        .expect("error merging staged commit");
                    Ok(false)
                }
            }
        };

        if !fcm && self.backend.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Backend not initialized.",
            ));
        }

        // Go through the list of messages and process them.
        let mut msg_count: u64 = 0;
        let mut msgs = if fcm {
            match fcm_msgs {
                Some(m) => m,
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "Error: fcm_msgs is None".to_string(),
                    ));
                }
            }
        } else {
            self.backend.as_mut().unwrap().recv_msgs(self.identity.borrow().identity())?
        };

        for message in msgs.drain(..) {
            msg_count += 1;
            match message.extract() {
                MlsMessageBodyIn::Welcome(_welcome) => {
                    panic!("Received an unexpected welcome message!");
                }
                MlsMessageBodyIn::PrivateMessage(message) => {
                    let _ = process_protocol_message(message.into());
                }
                MlsMessageBodyIn::PublicMessage(_message) => {
                    panic!("Received an unexpected public message!");
                }
                _ => panic!("Unsupported message type"),
            }
        }

        log::trace!("done with messages ...");

        Ok(msg_count)
    }

    /// Read all the messages in the server and process them using
    /// the callback function.
    pub fn receive<F>(&mut self, callback: F) -> io::Result<u64>
    where
        F: FnMut(Vec<u8>, String) -> io::Result<()>,
    {
        let msg_count = self.receive_core(callback, false, None)?;

        Ok(msg_count)
    }

    /// Process messages received through FCM using
    /// the callback function.
    pub fn receive_fcm<F>(&mut self, callback: F, fcm_payload: Vec<u8>) -> io::Result<u64>
    where
        F: FnMut(Vec<u8>, String) -> io::Result<()>,
    {
        match TlsVecU16::<MlsMessageIn>::tls_deserialize(&mut fcm_payload.as_slice()) {
            Ok(r) => {
                let msg_count =
                    self.receive_core(callback, true, Some(r.into()))?;
                Ok(msg_count)
            }
            Err(e) => {
                // This happens if the server returns an error or if tls_deserialize fails.
                Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Could not deserialize FCM msg ({e})"),
                ))
            }
        }
    }
}
