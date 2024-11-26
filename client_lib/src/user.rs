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
use std::{cell::RefCell, collections::HashMap};
use tls_codec::{Deserialize as TlsDeserialize, TlsVecU16};

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
    pub(crate) contacts: HashMap<Vec<u8>, Contact>,
    pub(crate) groups: RefCell<HashMap<Vec<u8>, Group>>,
    pub(crate) identity: RefCell<Identity>,
    backend: Backend,
    provider: OpenMlsRustPersistentCrypto,
    file_dir: String,
    tag: String,
}

impl User {
    /// if first_time, create a new user with the given name and a fresh set of credentials.
    /// else, restore existing client.
    /// user_credentials: the user credentials needed to authenticate with the server. Different from OpenMLS credentials.
    pub fn new(
        username: String,
        server_stream: TcpStream,
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
        let contacts = if first_time {
            HashMap::new()
        } else {
            Self::restore_contacts(file_dir.clone(), tag.clone())
        };
        if !first_time {
            let file = fs::File::open(file_dir.clone() + "/key_store_" + &tag.clone())
                .expect("Could not open file");
            crypto.load_keystore(&file).unwrap();
        }

        let mut out = Self {
            username: username.clone(),
            groups,
            contacts,
            identity: RefCell::new(Identity::new(
                CIPHERSUITE,
                &crypto,
                username.as_bytes(),
                first_time,
                file_dir.clone(),
                tag.clone(),
            )),
            backend: Backend::new(server_stream),
            provider: crypto,
            file_dir,
            tag,
        };

        // Authenticate with the server first for a new connection.
        out.backend.auth_server(user_credentials)?;

        // Inform the server whether this connection should be kept alive if idle
        out.backend.keep_alive(keep_alive)?;

        if reregister {
            out.backend.register_client(out.key_packages())?;
        }

        Ok(out)
    }

    pub fn deregister(&mut self) -> io::Result<()> {
        self.backend
            .deregister_client(self.identity.borrow().identity())?;
        self.identity
            .borrow()
            .delete_signature_key(self.file_dir.clone(), self.tag.clone());

        let _ = fs::remove_file(self.file_dir.clone() + "/registration_done");
        let _ = fs::remove_file(self.file_dir.clone() + "/groups_state_" + &self.tag.clone());
        let _ = fs::remove_file(self.file_dir.clone() + "/contacts_" + &self.tag.clone());
        let _ = fs::remove_file(self.file_dir.clone() + "/key_store_" + &self.tag.clone());

        Ok(())
    }

    pub fn get_file_dir(&self) -> String {
        self.file_dir.clone()
    }

    /// Add a key package to the user identity and return the pair [key package
    /// hash ref , key package]
    pub fn add_key_package(&self) -> (Vec<u8>, KeyPackage) {
        let kp = self
            .identity
            .borrow_mut()
            .add_key_package(CIPHERSUITE, &self.provider);
        (
            kp.hash_ref(self.provider.crypto())
                .unwrap()
                .as_slice()
                .to_vec(),
            kp,
        )
    }

    /// Get the key packages fo this user.
    pub fn key_packages(&self) -> Vec<(Vec<u8>, KeyPackage)> {
        // clone first !
        let kpgs = self.identity.borrow().kp.clone();
        Vec::from_iter(kpgs)
    }

    /// Generate new key_package.
    /// Note: A key_package should be used once only. In fact, the call to new_from_welcome()
    /// in join_group retires the key_package and the corresponding private key from
    /// the key store.
    pub fn generate_key_packages(&mut self) -> io::Result<()> {
        let _ = self.add_key_package();

        // Update the key package in the DS.
        // TODO/FIXME: this only works if the previous welcome messages using the
        // old key_package have been sent and processed.
        self.backend.register_client(self.key_packages())?;

        Ok(())
    }

    /// Update FCM token in the server.
    pub fn update_token(&mut self, token: String) -> io::Result<()> {
        self.backend
            .update_token(self.identity.borrow().identity(), token)
    }

    /// Get a list of clients in the group to send messages to.
    fn recipients(&self, group: &Group, exclude_contact: Option<&Contact>) -> Vec<Vec<u8>> {
        let mut recipients = Vec::new();

        let mls_group = group.mls_group.borrow();
        for Member {
            index: _,
            encryption_key: _,
            signature_key,
            credential,
        } in mls_group.members()
        {
            if self
                .identity
                .borrow()
                .credential_with_key
                .signature_key
                .as_slice()
                != signature_key.as_slice()
            {
                let credential = BasicCredential::try_from(credential).unwrap();
                match self.contacts.get(credential.identity()) {
                    Some(c) => {
                        if exclude_contact.is_none() || c != exclude_contact.unwrap() {
                            recipients.push(c.id.clone());
                        }
                    }
                    None => panic!("There's a member in the group we don't know."),
                };
            }
        }
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
    pub fn invite(&mut self, contact: &Contact, group_name: String) -> io::Result<()> {
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

        let (out_messages, welcome, _group_info) = group
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
        log::trace!("Sending welcome");
        self.backend.send_welcome(&welcome)?;

        // Finally, send the MlsMessages to the group.
        // Exclude the contact we just invited. It won't be able to process anyway.
        log::trace!("Sending proposal");
        let group_recipients = self.recipients(group, Some(contact));

        let msg = GroupMessage::new(out_messages.into(), &group_recipients);
        self.backend.send_msg(&msg, false)?;

        group.only_contact = Some(contact.clone());

        Ok(())
    }

    /// Join a group with the provided welcome message.
    fn join_group(&self, welcome: Welcome) -> io::Result<()> {
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

        let only_contact = Self::get_only_matching_contact(&mls_group, &self.contacts)?;

        let group = Group {
            group_name: group_name.clone(),
            mls_group: RefCell::new(mls_group),
            pcs_initiator: None,
            only_contact: Some(only_contact),
        };

        log::trace!("   {}", group_name);

        match self.groups.borrow_mut().insert(group_id, group) {
            Some(old) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Overrode the group {:?}", old.group_name),
            )),
            None => Ok(()),
        }
    }

    pub fn save_groups_state(&mut self) {
        let data = bincode::serialize(&self.groups.get_mut()).unwrap();
        let pathname = self.file_dir.clone() + "/groups_state_" + &self.tag.clone();
        let mut file = fs::File::create(pathname).expect("Could not create file");
        let _ = file.write_all(&data);

        let ks_pathname = self.file_dir.clone() + "/key_store_" + &self.tag.clone();
        let ks_file = fs::File::create(ks_pathname).expect("Could not create file");
        self.provider.save_keystore(&ks_file).unwrap();
    }

    pub fn restore_groups_state(file_dir: String, tag: String) -> RefCell<HashMap<Vec<u8>, Group>> {
        let pathname = file_dir + "/groups_state_" + &tag;
        let file = fs::File::open(pathname).expect("Could not open file");
        let mut reader =
            BufReader::with_capacity(file.metadata().unwrap().len().try_into().unwrap(), file);
        let data = reader.fill_buf().unwrap();

        RefCell::new(bincode::deserialize(data).unwrap())
    }

    pub fn save_contacts(&mut self) {
        let data = bincode::serialize(&self.contacts).unwrap();
        let pathname = self.file_dir.clone() + "/contacts_" + &self.tag.clone();
        let mut file = fs::File::create(pathname).expect("Could not create file");
        let _ = file.write_all(&data);
    }

    pub fn restore_contacts(file_dir: String, tag: String) -> HashMap<Vec<u8>, Contact> {
        let pathname = file_dir + "/contacts_" + &tag;
        let file = fs::File::open(pathname).expect("Could not open file");
        let mut reader =
            BufReader::with_capacity(file.metadata().unwrap().len().try_into().unwrap(), file);
        let data = reader.fill_buf().unwrap();

        bincode::deserialize(data).unwrap()
    }

    pub fn add_contact(&mut self, name: String, key_packages: KeyPackages) -> Contact {
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

        if self.contacts.insert(id, contact.clone()).is_some() {
            log::trace!("Contact already existed!");
            panic!("Contact already existed!");
        }

        self.save_contacts();

        log::trace!("Added contact {}", "");
        contact
    }

    pub fn get_group_name(&self, only_contact_name: String) -> io::Result<String> {
        for (_, group) in self.groups.borrow().iter() {
            if group.only_contact.is_some() && group.only_contact.as_ref().unwrap().username == only_contact_name {
                return Ok(group.group_name.clone());
            }
        }

        Err(io::Error::new(
            io::ErrorKind::Other,
            "Unknown group".to_string(),
        ))
    }

    /// Force an MLS update
    /// Returns true if new update is performed
    /// Returns false if pending update is re-sent
    pub fn update(&mut self, group_name: String) -> io::Result<bool> {
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
                    self.backend.send_msg(&msg.unwrap(), false)?;
                    Ok(false)
                } else {
                    panic!("Has pending update but returns error for msg!");
                }
            } else {
                let msg = self.update_commit(group)?;
                pcs_initiator.updated(&msg);
                let msg_copy = pcs_initiator.get_pending_update_msg();
                if msg_copy.is_ok() {
                    // Send the MlsMessages to the group.
                    self.backend.send_msg(&msg_copy.unwrap(), false)?;
                    Ok(true)
                } else {
                    panic!("Couldn't retrieve the update msg!");
                }
            }
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "Only the PCS initiator can force an update.",
            ))
        }
    }

    /// For testing only.
    /// Force an MLS update, but does not send the update to other group members.
    pub fn update_no_send(&mut self, group_name: String) -> io::Result<()> {
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
            if !pcs_initiator.has_pending_update() {
                let msg = self.update_commit(group)?;
                pcs_initiator.updated(&msg);
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::Other,
                    "There is already a pending update.",
                ))
            }
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "Only the PCS initiator can force an update.",
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
        let group_recipients = self.recipients(group, None);
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

        let msg = GroupMessage::new(message_out.into(), &self.recipients(group, None));
        log::debug!(" >>> send: {:?}", msg);
        self.backend.send_msg(&msg, fcm)
    }

    /// Send an array of bytes to the group.
    pub fn send(&mut self, bytes: &[u8], group_name: String) -> io::Result<bool> {
        self.send_core(bytes, group_name, false)
    }

    /// Send an array of bytes to the group through FCM.
    pub fn send_fcm(&mut self, bytes: &[u8], group_name: String) -> io::Result<bool> {
        self.send_core(bytes, group_name, true)
    }

    /// Return the contact for the member of the group that is also in the contacts.
    /// Returns error if there is no match or if more than one matches.
    //fn get_only_matching_contact(group: &Group, contacts: &HashMap<Vec<u8>, Contact>) -> io::Result<Contact> {
    fn get_only_matching_contact(
        mls_group: &MlsGroup,
        contacts: &HashMap<Vec<u8>, Contact>,
    ) -> io::Result<Contact> {
        let mut matching_contact: Option<Contact> = None;

        for Member {
            index: _,
            encryption_key: _,
            signature_key: _,
            credential,
        } in mls_group.members()
        {
            let credential = BasicCredential::try_from(credential).unwrap();
            if let Some(c) = contacts.get(credential.identity()) {
                if matching_contact.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "Multiple matching contacts!",
                    ));
                } else {
                    matching_contact = Some(c.clone());
                }
            }
        }

        if matching_contact.is_none() {
            return Err(io::Error::new(io::ErrorKind::Other, "No matching contact!"));
        }

        Ok(matching_contact.unwrap())
    }

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
            let only_contact = Self::get_only_matching_contact(&mls_group, &self.contacts)?;

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

                    callback(application_message, only_contact.username)?;
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
            self.backend.recv_msgs(self.identity.borrow().identity())?
        };

        for message in msgs.drain(..) {
            msg_count += 1;
            match message.extract() {
                MlsMessageBodyIn::Welcome(welcome) => {
                    self.join_group(welcome).unwrap();
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
        self.receive_core(callback, false, None)
    }

    /// Process messages received through FCM using
    /// the callback function.
    pub fn receive_fcm<F>(&mut self, callback: F, fcm_payload: Vec<u8>) -> io::Result<u64>
    where
        F: FnMut(Vec<u8>, String) -> io::Result<()>,
    {
        match TlsVecU16::<MlsMessageIn>::tls_deserialize(&mut fcm_payload.as_slice()) {
            Ok(r) => {
                self.receive_core(callback, true, Some(r.into()))
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
