//! Secluso client.
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

use super::identity::Identity;
use super::openmls_rust_persistent_crypto::OpenMlsRustPersistentCrypto;
use ds_lib::GroupMessage;
use openmls::prelude::*;
use openmls::schedule::{ExternalPsk, Psk, PreSharedKeyId};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::io::{BufRead, BufReader, Write};
use std::time::{SystemTime, UNIX_EPOCH};
use tls_codec::{Serialize as TlsSerialize, Deserialize as TlsDeserialize};
use crate::pairing;

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

pub type KeyPackages = Vec<(Vec<u8>, KeyPackage)>;

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Contact {
    username: String,
    id: Vec<u8>,
    //FIXME: do we need to keep key_packages?
    key_packages: KeyPackages,
    update_proposal: Option<QueuedProposal>,
    last_update_timestamp: u64,
}

impl Contact {
    pub fn get_credential(&self) -> Credential {
        return self.key_packages[0].1.leaf_node().credential().clone();
    }
}

pub struct Group {
    // Group name is a shared name for the group used by all members.
    // It is used by the Secluso framework, but not by OpenMLS.
    // OpenMLS uses group_id.
    // We keep these two separate because according to OpenMLS:
    // "Group IDs should be random and not be misused as, e.g., a group name."
    // Group name is not confidential. It is used by clients as a shared name
    // to exchange encrypted data via the delivery service.
    group_name: String,
    mls_group: MlsGroup,
    // The "only" contact that is also in this group.
    only_contact: Option<Contact>,
}

/// MlsGroup ins Group cannot be serialized, but it is stored in storage provider.
/// Therefore, we use GroupHelper to serialize other fields.
/// Upon deserialization, we read MlsGroup from the storage provider.
#[derive(Serialize, Deserialize)]
struct GroupHelper {
    group_name: String,
    // Needed in order to be able to read mls_group from storage upon
    // deserialization from files.
    group_id: Vec<u8>,
    only_contact: Option<Contact>,
}

impl Group {
    pub(self) fn from_deserialized(
        group_helper: GroupHelper,
        provider: &OpenMlsRustPersistentCrypto,
    ) -> io::Result<Self> {
        let mls_group_option = MlsGroup::load(provider.storage(), &GroupId::from_slice(&group_helper.group_id))
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to load group from storage provider - {e}"),
                )
            })?;

        if let Some(mls_group) = mls_group_option {
            return Ok(Group {
                group_name: group_helper.group_name,
                only_contact: group_helper.only_contact,
                mls_group,
            })
        } else {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Group not found in storage provider.",
            ))
        }
    }
}

pub struct MlsClient {
    pub(crate) username: String,
    pub(crate) group: Option<Group>,
    pub(crate) identity: Identity,
    provider: OpenMlsRustPersistentCrypto,
    file_dir: String,
    tag: String,
}

impl MlsClient {
    /// if first_time, create a new user with the given name and a fresh set of credentials.
    /// else, restore existing client.
    /// user_credentials: the user credentials needed to authenticate with the server. Different from OpenMLS credentials.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        username: String,
        first_time: bool,
        file_dir: String,
        tag: String,
    ) -> io::Result<Self> {
        let mut crypto = OpenMlsRustPersistentCrypto::default();
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
        let group = if first_time {
            None
        } else {
            Self::restore_group_state(file_dir.clone(), tag.clone(), &crypto)?
        };

        let out = Self {
            username: username.clone(),
            group,
            identity: Identity::new(
                CIPHERSUITE,
                &crypto,
                username.as_bytes(),
                first_time,
                file_dir.clone(),
                tag.clone(),
            ),
            provider: crypto,
            file_dir,
            tag,
        };

        Ok(out)
    }

    pub fn clean(&mut self) -> io::Result<()> {
        self.identity
            .delete_signature_key(self.file_dir.clone(), self.tag.clone());

        let g_files = Self::get_state_files_sorted(
            &self.file_dir,
            &("group_state_".to_string() + &self.tag.clone() + "_"),
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
        let kpgs = self.identity.kp.clone();
        Vec::from_iter(kpgs)
    }

    /// Get a list of clients in the group to send messages to.
    /// This is currently very simple: return the only_contact
    fn recipients(group: &Group) -> Vec<Vec<u8>> {
        let recipients = vec![group.only_contact.as_ref().unwrap().id.clone()];
        recipients
    }

    /// Create a group with the given name.
    pub fn create_group(
        &mut self,
        name: &str,
    ) -> io::Result<()> {
        if self.group.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Group previously created.",
            ))
        }

        log::debug!("{} creates group {}", self.username, name);
        let group_id = GroupId::random(self.provider.rand()).to_vec();

        // NOTE: Since the DS currently doesn't distribute copies of the group's ratchet
        // tree, we need to include the ratchet_tree_extension.
        let group_config = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build();

        let mls_group = MlsGroup::new_with_group_id(
            &self.provider,
            &self.identity.signer,
            &group_config,
            GroupId::from_slice(&group_id),
            self.identity.credential_with_key.clone(),
        )
        .expect("Failed to create MlsGroup");

        let group = Group {
            group_name: name.to_string(),
            mls_group: mls_group,
            only_contact: None,
        };

        self.group = Some(group);
        Ok(())
    }

    /// Invite a contact to a group.
    pub fn invite(&mut self, contact: &Contact, secret: Vec<u8>) -> io::Result<Vec<u8>> {
        if self.group.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Group not created yet".to_string(),
            ))
        }

        let group = self.group.as_mut().unwrap();

        if group.only_contact.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Cannot invite more than one member to the group.",
            ));
        }

        // Create an external psk proposal and commit it.
        // This is used for mutual authentication.
        if secret.len() != pairing::NUM_SECRET_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Invalid number of bytes in secret.",
            ));
        }

        let psk_id = vec![1u8, 2, 3];
        //let secret = [0u8; 64];
        let external_psk = ExternalPsk::new(psk_id);
        let preshared_key_id =
            PreSharedKeyId::new(CIPHERSUITE, self.provider.rand(), Psk::External(external_psk))
                .expect("An unexpected error occured.");
        preshared_key_id.store(&self.provider, &secret).unwrap();

        let (_psk_proposal, _proposal_ref) = group
            .mls_group
            .propose_external_psk(& self.provider, &self.identity.signer, preshared_key_id)
            .expect("Could not create PSK proposal");

        // Build a proposal with this key package and do the MLS bits.
        let joiner_key_package = contact.key_packages[0].1.clone();

        // Note: out_messages is needed for other group members.
        // Currently, we don't need/use it since our groups only have
        // two members, an inviter (camera) and an invitee (app).
        let (_out_messages, welcome, _group_info) = group
            .mls_group
            .add_members(
                &self.provider,
                &self.identity.signer,
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
            .merge_pending_commit(&self.provider)
            .expect("error merging pending commit");

        // Second, generate and return the Welcome message (to be sent to the joiner).
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
    fn join_group(
        &mut self,
        welcome: Welcome,
        expected_inviter: Contact,
        secret: Vec<u8>,
        group_name: String,
    ) -> io::Result<()> {
        if self.group.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Joined a group already.",
            ))
        }

        log::debug!("{} joining group ...", self.username);

        // Store the secret as an external psk.
        // This is used for mutual authentication.
        if secret.len() != pairing::NUM_SECRET_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Invalid number of bytes in secret.",
            ));
        }

        let psk_id = vec![1u8, 2, 3];
        let external_psk = ExternalPsk::new(psk_id);
        let preshared_key_id =
            PreSharedKeyId::new(CIPHERSUITE, self.provider.rand(), Psk::External(external_psk))
                .expect("An unexpected error occured.");
        preshared_key_id.store(&self.provider, &secret).unwrap();

        // NOTE: Since the DS doesn't distribute copies of the group's ratchet
        // tree, we need to include the ratchet_tree_extension.
        let group_config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();
        let mls_group =
            StagedWelcome::new_from_welcome(&self.provider, &group_config, welcome, None)
                .expect("Failed to create staged join")
                .into_group(&self.provider)
                .expect("Failed to create MlsGroup");

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
            } else if self.identity.identity() == credential.identity() {
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
            mls_group: mls_group,
            only_contact: Some(expected_inviter),
        };

        log::trace!("   {}", group_name);

        self.group = Some(group);
        Ok(())
    }

    /// Process a welcome message
    pub fn process_welcome(
        &mut self,
        expected_inviter: Contact,
        welcome_msg_vec: Vec<u8>,
        secret: Vec<u8>,
        group_name: String,
    ) -> io::Result<()> {
        let welcome_msg = match MlsMessageIn::tls_deserialize(&mut welcome_msg_vec.as_slice()) {
            Ok(msg) => msg,
            Err(e) => {return Err(io::Error::new(io::ErrorKind::Other, format!("{}", e)))},
        };

        match welcome_msg.extract() {
            MlsMessageBodyIn::Welcome(welcome) => {
                self.join_group(welcome, expected_inviter, secret, group_name)
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
    pub fn save_group_state(&mut self) {
        // Use nanos in order to ensure that each time this function is called, we will use a new file name.
        // This does make some assumptions about the execution speed, but those assumptions are reasonable (for now).
        let current_timestamp: u128 = Self::now_in_nano_secs();

        let group_helper_option = match &self.group {
            Some(group) => {
                Some(GroupHelper {
                    group_name: group.group_name.clone(),
                    group_id: group.mls_group.group_id().to_vec(),
                    only_contact: group.only_contact.clone(),
                })
            },
            None => None,
        };

        let data = bincode::serialize(&group_helper_option).unwrap();
        let pathname = self.file_dir.clone()
            + "/group_state_"
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
            &("group_state_".to_string() + &self.tag.clone() + "_"),
        )
        .unwrap();
        assert!(
            g_files[0]
                == "group_state_".to_owned()
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

    pub fn restore_group_state(file_dir: String, tag: String, provider: &OpenMlsRustPersistentCrypto) -> io::Result<Option<Group>> {
        let g_files =
            Self::get_state_files_sorted(&file_dir, &("group_state_".to_string() + &tag + "_"))
                .unwrap();
        for f in &g_files {
            let pathname = file_dir.clone() + "/" + f;
            let file = fs::File::open(pathname).expect("Could not open file");
            let mut reader =
                BufReader::with_capacity(file.metadata().unwrap().len().try_into().unwrap(), file);
            let data = reader.fill_buf().unwrap();
            let deserialize_result = bincode::deserialize(data);
            if let Ok(group_helper_option) = deserialize_result {
                match group_helper_option {
                    Some(group_helper) => {
                        let group = Group::from_deserialized(group_helper, provider)?;
                        return Ok(Some(group));
                    },
                    None => {
                        return Ok(None);
                    }
                }
            }
        }

        panic!("Could not successfully load the group state from file.");
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

    pub fn create_contact(name: &str, key_packages: KeyPackages) -> io::Result<Contact> {
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
            username: name.to_string(),
            key_packages,
            id: id.clone(),
            update_proposal: None,
            last_update_timestamp: Self::now_in_secs(),
        };

        Ok(contact)
    }

    pub fn get_group_name(&self) -> io::Result<String> {
        match &self.group {
            Some(g) => {        
                return Ok(g.group_name.clone());
            },

            None => {
                Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Group not created yet".to_string(),
                ))
            },
        }
    }

    /// Generate a commit to update self leaf node in the ratchet tree, merge the commit, and return the message
    /// to be sent to other group members. It also returns the epoch number after the update.
    pub fn update(&mut self) -> io::Result<(Vec<u8>, u64)> {
        if self.group.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Group not created yet".to_string(),
            ))
        }

        let group = self.group.as_mut().unwrap();

        // Set AAD
        let group_aad = group.group_name.clone() + " AAD";
        group.mls_group.set_aad(group_aad.as_bytes().to_vec());

        if let Some(proposal) = group.only_contact.as_mut().unwrap().update_proposal.take() {
            group
                .mls_group
                .store_pending_proposal(self.provider.storage(), proposal)
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        format!("FError: could not store proposal - {e}"),
                    )
                })?;
        }

        // FIXME: _welcome should be none, group_info should be some.
        // See openmls/src/group/mls_group/updates.rs.
        let commit_msg_bundle = group
            .mls_group
            .self_update(
                &self.provider,
                &self.identity.signer,
                LeafNodeParameters::default(),
            )
            .map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("Failed to self update - {e}"))
            })?;

        log::trace!("Generating update message");
        let group_recipients = Self::recipients(&group);
        // Generate the message to the group.
        let msg = GroupMessage::new(commit_msg_bundle.into_commit().into(), &group_recipients);

        // Merge pending commit.
        group
            .mls_group
            .merge_pending_commit(&self.provider)
            .expect("error merging pending commit");

        let mut msg_vec = Vec::new();
        msg.tls_serialize(&mut msg_vec).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("tls_serialize for msg failed ({e})"),
            )
        })?;

        let epoch = group
            .mls_group
            .epoch()
            .as_u64();

        Ok((msg_vec, epoch))
    }

    /// Generate an update proposal for the self leaf node in the ratchet tree and return the proposal message
    /// to be sent to other group members.
    pub fn update_proposal(&mut self) -> io::Result<Vec<u8>> {
        if self.group.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Group not created yet".to_string(),
            ))
        }

        let group = self.group.as_mut().unwrap();

        // Set AAD
        let group_aad = group.group_name.clone() + " AAD";
        group.mls_group.set_aad(group_aad.as_bytes().to_vec());
        
        let (proposal_msg, _) = group
            .mls_group
            .propose_self_update(
                &self.provider,
                &self.identity.signer,
                LeafNodeParameters::default(),
            )
            .map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("Failed to generate self update proposal message - {e}"))
            })?;

        let mut msg_vec = Vec::new();
        proposal_msg.tls_serialize(&mut msg_vec).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("tls_serialize for proposal_msg failed ({e})"),
            )
        })?;

        Ok(msg_vec)
    }

    /// Get the current group epoch
    pub fn get_epoch(&self) -> io::Result<u64> {
        if self.group.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Group not created yet".to_string(),
            ))
        }

        let group = self.group.as_ref().unwrap();

        let epoch = group
            .mls_group
            .epoch()
            .as_u64();

        Ok(epoch)
    }

    /// Returns how long the only contact has been offline
    /// It is recommended that this is checked before encrypting a message
    /// for groups used to send important data.
    /// If the only contact has been offline for more than a threshold,
    /// no new messages should be encrypted/sent.
    pub fn offline_period(&self) -> u64 {
        let now = Self::now_in_secs();
        let only_contact = self.group.as_ref().unwrap().only_contact.as_ref().unwrap();
        if now < only_contact.last_update_timestamp {
            return 0;
        }

        now - only_contact.last_update_timestamp
    }

    /// Encrypts a message and returns the ciphertext
    pub fn encrypt(&mut self, bytes: &[u8]) -> io::Result<Vec<u8>> {
        if self.group.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Group not created yet".to_string(),
            ))
        }

        let group = self.group.as_mut().unwrap();

        // Set AAD
        let group_aad = group.group_name.clone() + " AAD";
        group.mls_group.set_aad(group_aad.as_bytes().to_vec());

        let message_out = group
            .mls_group
            .create_message(&self.provider, &self.identity.signer, bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{e}")))?;

        let msg = GroupMessage::new(message_out.into(), &Self::recipients(&group));
        
        let mut msg_vec = Vec::new();
        msg.tls_serialize(&mut msg_vec).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("tls_serialize for msg failed ({e})"),
            )
        })?;

        Ok(msg_vec)
    }

    fn process_protocol_message(
        &mut self,
        message: ProtocolMessage,
        app_msg: bool,
    ) -> io::Result<Vec<u8>> {
        if self.group.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Group not created yet".to_string(),
            ))
        }
        let group = self.group.as_mut().unwrap();
        let mls_group = &mut group.mls_group;

        // Message validation performed within process_message below checks for this as well.
        // Then why do we explicitly check it here?
        // We might have a scenario where we might receive an outdated proposal.
        // We simply want to ignore that case.
        // If we pass it to process_message(), it prints an error message, which is not great.
        // Instead, we return an error here and leave it to the caller to decide if the error
        // needs to be printed or not.
        if mls_group.epoch() != message.epoch() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Error: message epoch ({}) must match the group epoch ({})", message.epoch(), mls_group.epoch()),
            ))
        }

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

        // Check AAD
        let group_aad = group.group_name.clone() + " AAD";

        if processed_message.aad().to_vec() != group_aad.into_bytes() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Error: received a message with an invalid AAD".to_string(),
            ));
        }

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
                if !app_msg {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "Error: expected a commit message, but received an application message",
                    ));
                }
                let application_message = application_message.into_bytes();

                return Ok(application_message);
            }
            ProcessedMessageContent::ProposalMessage(proposal) => {
                if app_msg {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "Error: expected an application message, but received a proposal message.",
                    ));
                }

                let only_contact = group.only_contact.as_mut().unwrap();

                if only_contact.update_proposal.is_none() {
                    only_contact.update_proposal = Some(*proposal);
                }

                only_contact.last_update_timestamp = Self::now_in_secs();

                return Ok(vec![]);
            }
            ProcessedMessageContent::ExternalJoinProposalMessage(_external_proposal) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Error: Unexpected external join proposal message!".to_string(),
                ));
            }
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                if app_msg {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "Error: expected an application message, but received a commit message.",
                    ));
                }

                // Restrict the type of staged commits that we'll merge: only one update/queued proposal!
                if !staged_commit.add_proposals().next().is_none() ||
                !staged_commit.remove_proposals().next().is_none() ||
                !(staged_commit.update_proposals().next().is_none() ||
                    staged_commit.update_proposals().collect::<Vec<_>>().len() == 1) ||                   
                !staged_commit.psk_proposals().next().is_none() ||
                !(staged_commit.queued_proposals().next().is_none() ||
                    staged_commit.queued_proposals().collect::<Vec<_>>().len() == 1) {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "Error: staged commit message must contain at most one update/queued proposal and no other proposals.",
                    ));
                }

                mls_group
                    .merge_staged_commit(&self.provider, *staged_commit)
                    .expect("error merging staged commit");

                // TODO: we can only do this here since we know there's only one path for
                // us to receive a staged commit and in that the only_contact has performed
                // a self update. However, ideally, we should check the staged commit itself
                // to see which other leaf nodes/contacts have been updated.
                group.only_contact.as_mut().unwrap().last_update_timestamp = Self::now_in_secs();

                return Ok(vec![]);
            }
        }
    }

    /// Decrypts an encrypted message and returns the plaintext message
    /// The caller should specify whether this is supposed to be an
    /// application message (app_msg = true) or a commit message (app_msg = false).
    /// This function will return an error if the message type is different from
    /// what was provided as input.
    pub fn decrypt(
        &mut self,
        msg: Vec<u8>,
        app_msg: bool,
    ) -> io::Result<Vec<u8>> {
        let mls_msg = match MlsMessageIn::tls_deserialize(&mut msg.as_slice()) {
            Ok(m) => m,
            Err(e) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Could not deserialize msg ({e})"),
                ));
            },
        };

        match mls_msg.extract() {
            MlsMessageBodyIn::Welcome(_welcome) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Error: Unexpected welcome message!".to_string(),
                ));
            }
            MlsMessageBodyIn::PrivateMessage(message) => {
                return self.process_protocol_message(message.into(), app_msg);
            }
            MlsMessageBodyIn::PublicMessage(_message) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Error: Unexpected public message!".to_string(),
                ));
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Error: Unsupported message type!".to_string(),
                ));
            }
        }
    }

    fn now_in_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Could not convert time")
            .as_secs()
    }

    fn now_in_nano_secs() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Could not convert time")
            .as_nanos()
    }
}
