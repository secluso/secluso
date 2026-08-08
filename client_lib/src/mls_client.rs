//! Secluso client.
//!
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Based on the OpenMLS client (openmls/cli).
//! MIT License.

use super::identity::Identity;
use super::openmls_rust_persistent_crypto::OpenMlsRustPersistentCrypto;
use openmls_traits::{storage::StorageProvider as StorageProviderTrait};
use crate::pairing;
use openmls::prelude::*;
use openmls::schedule::{ExternalPsk, PreSharedKeyId, Psk};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::io::{BufRead, BufReader, Write, Read};
use std::time::{SystemTime, UNIX_EPOCH};
use std::cmp;
use std::path::{Path, PathBuf};
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};

#[cfg(test)]
use openmls::treesync::RatchetTree;

// Post-quantum secure ciphersuite: https://blog.openmls.tech/posts/2024-04-11-pq-openmls/
const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;

const CURRENT_FILE: &str = "CURRENT";
const GROUP_STATE_FILENAME: &str = "group_state";
const KEY_STORE_FILENAME: &str = "key_store";

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Contact {
    // The contact name is only used to search through the contacts by a name.
    // It is not used by the MLS protocol.
    // We need it to be able to use a single name for all the MLS clients
    // used by a single node (camera or app).
    name: String,
    id: Vec<u8>,
    //FIXME: do we need to keep the key_package?
    key_package: KeyPackage,
    update_proposal: Option<QueuedProposal>,
    last_update_timestamp: u64,
    // Used by the camera. admin_contact is the first app that pairs
    // with the camera. Only the admin_contact can add other apps.
    admin_contact: bool,
}

impl Contact {
    pub fn get_credential(&self) -> Credential {
        self.key_package.leaf_node().credential().clone()
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
    contacts: Vec<Contact>,
    // Used by the app. True if we are the admin_contact of the camera.
    is_admin: bool,
}

/// MlsGroup in Group cannot be serialized, but it is stored in storage provider.
/// Therefore, we use GroupHelper to serialize other fields.
/// Upon deserialization, we read MlsGroup from the storage provider.
#[derive(Serialize, Deserialize)]
struct GroupHelper {
    group_name: String,
    // Needed in order to be able to read mls_group from storage upon
    // deserialization from files.
    group_id: Vec<u8>,
    contacts: Vec<Contact>,
    is_admin: bool,
}

impl Group {
    pub(self) fn from_deserialized(
        group_helper: GroupHelper,
        provider: &OpenMlsRustPersistentCrypto,
    ) -> io::Result<Self> {
        let mls_group_option = MlsGroup::load(
            provider.storage(),
            &GroupId::from_slice(&group_helper.group_id),
        )
        .map_err(|e| {
            io::Error::other(format!("Failed to load group from storage provider - {e}"))
        })?;

        if let Some(mls_group) = mls_group_option {
            Ok(Group {
                group_name: group_helper.group_name,
                contacts: group_helper.contacts,
                is_admin: group_helper.is_admin,
                mls_group,
            })
        } else {
            Err(io::Error::other("Group not found in storage provider."))
        }
    }
}

#[derive(PartialEq)]
pub enum ClientType {
    Camera,
    App,
}

pub struct MlsClient {
    pub(crate) group: Option<Group>,
    pub(crate) identity: Identity,
    provider: OpenMlsRustPersistentCrypto,
    file_dir: String,
    tag: String,
    client_type: ClientType,
}

impl MlsClient {
    fn load_group_from_file(
        path: &PathBuf,
        provider: &OpenMlsRustPersistentCrypto,
    ) -> io::Result<Option<Group>> {
        let file = File::open(path)?;
        let mut reader = BufReader::with_capacity(file.metadata()?.len().try_into().unwrap(), file);
        let data = reader.fill_buf()?;
        let group_helper_option: Option<GroupHelper> = bincode::deserialize(data)
            .map_err(|e| io::Error::other(format!("Failed to deserialize group state - {e}")))?;
        match group_helper_option {
            Some(group_helper) => Ok(Some(Group::from_deserialized(group_helper, provider)?)),
            None => Ok(None),
        }
    }

    /// if first_time, create a new user with the given name and a fresh set of credentials.
    /// else, restore existing client.
    /// user_credentials: the user credentials needed to authenticate with the server. Different from OpenMLS credentials.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        first_time: bool,
        file_dir: String,
        tag: String,
        client_type: ClientType,
    ) -> io::Result<Self> {
        let mut crypto = OpenMlsRustPersistentCrypto::default();
        let group = if first_time {
            let file_dir_path = Path::new(&file_dir);        
            let state_dir_path = file_dir_path.join(&tag);
            if !state_dir_path.exists() {
                fs::create_dir(&state_dir_path)?;
                Self::fsync_dir(&file_dir_path)?;
            }

            None
        } else {
            Self::restore_group_state(file_dir.clone(), tag.clone(), &mut crypto)?
        };

        let out = Self {
            group,
            identity: Identity::new(
                CIPHERSUITE,
                &crypto,
                id.as_bytes(),
                first_time,
                file_dir.clone(),
                tag.clone(),
            ),
            provider: crypto,
            file_dir,
            tag,
            client_type,
        };

        Ok(out)
    }

    pub fn clean(&mut self) -> io::Result<()> {
        self.identity
            .delete_signature_key(self.file_dir.clone(), self.tag.clone());

        let file_dir_path = Path::new(&self.file_dir);
        
        let state_dir_path = file_dir_path.join(&self.tag);
        if state_dir_path.exists() {
            fs::remove_dir_all(&state_dir_path)?;
            Self::fsync_dir(&file_dir_path)?;
        }

        Ok(())
    }

    pub fn get_file_dir(&self) -> String {
        self.file_dir.clone()
    }

    /// Get the key packages fo this user.
    pub fn key_package(&mut self) -> KeyPackage {
        let kp = self.identity.kp.clone();
        // Update the key_package after it's been used once.
        self.identity.update_key_package(CIPHERSUITE, &self.provider);

        kp
    }

    /// Create a group with the given name.
    pub fn create_group(&mut self, name: &str) -> io::Result<()> {
        if self.client_type != ClientType::Camera {
            return Err(io::Error::other("Only the camera can create a group."));
        }

        if self.group.is_some() {
            return Err(io::Error::other("Group previously created."));
        }

        log::debug!("About to create group");
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
            mls_group,
            contacts: vec![],
            is_admin: false, // irrelevant for the camera
        };

        self.group = Some(group);
        Ok(())
    }

    /// Invite a contact to a group.
    fn invite(
        &mut self,
        contact: &Contact,
        preshared_key_id: &PreSharedKeyId,
    ) -> io::Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        if self.group.is_none() {
            return Err(io::Error::other("Group not created yet".to_string()));
        }

        let group = self.group.as_mut().unwrap();

        // first is true if we're inviting the first app, i.e., the admin_app
        let first = group.contacts.len() == 0;

        if !first {
            // Set AAD for the commit message
            let group_aad = group.group_name.clone() + " AAD";
            group.mls_group.set_aad(group_aad.as_bytes().to_vec());
        }

        let (psk_proposal, _proposal_ref) = group
            .mls_group
            .propose_external_psk(&self.provider, &self.identity.signer, preshared_key_id.clone())
            .expect("Could not create PSK proposal");

        let mut psk_proposal_vec = Vec::new();
        psk_proposal
            .tls_serialize(&mut psk_proposal_vec)
            .map_err(|e| io::Error::other(format!("tls_serialize for psk_proposal failed ({e})")))?;

        if !first {
            // Set AAD for the commit message
            let group_aad = group.group_name.clone() + " AAD";
            group.mls_group.set_aad(group_aad.as_bytes().to_vec());
        }

        for contact in &mut group.contacts {
            if let Some(proposal) = contact.update_proposal.take() {
                group
                    .mls_group
                    .store_pending_proposal(self.provider.storage(), proposal)
                    .map_err(|e| io::Error::other(format!("Error: could not store proposal - {e}")))?;
            }
        }

        // Build a proposal with this key package and do the MLS bits.
        let joiner_key_package = contact.key_package.clone();

        // Note: commit is needed for other group members.
        let (commit, welcome, _group_info) = group
            .mls_group
            .add_members(&self.provider, &self.identity.signer, &[joiner_key_package])
            .map_err(|e| io::Error::other(format!("Failed to add member to group - {e}")))?;

        // First, generate and return the message to others.
        // This should be done before we merge the invitation commit.
        let commit_msg_vec = if first {
            vec![]
        } else {
            let mut msg_vec = Vec::new();
            commit
                .tls_serialize(&mut msg_vec)
                .map_err(|e| io::Error::other(format!("tls_serialize for out_messages failed ({e})")))?;

            msg_vec
        };

        // Second, process the invitation on our end.
        group
            .mls_group
            .merge_pending_commit(&self.provider)
            .expect("error merging pending commit");

        // Third, generate and return the Welcome message (to be sent to the joiner).
        let mut welcome_msg_vec = Vec::new();
        welcome
            .tls_serialize(&mut welcome_msg_vec)
            .map_err(|e| io::Error::other(format!("tls_serialize for welcome failed ({e})")))?;

        let mut contact_clone = contact.clone();

        if first {
            contact_clone.admin_contact = true;
        }
        
        group.contacts.push(contact_clone);

        Ok((welcome_msg_vec, psk_proposal_vec, commit_msg_vec))
    }

    pub fn invite_with_secret(
        &mut self,
        contact: &Contact,
        secret: Vec<u8>,
    ) -> io::Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        if self.client_type != ClientType::Camera {
            return Err(io::Error::other("Only the camera can invite a member to the group."));
        }

        let preshared_key_id = self.apply_secret(secret)?;

        let result = self.invite(contact, &preshared_key_id);

        self.delete_secret(&preshared_key_id);

        result
    }

    /// Join a group with the provided welcome message.
    fn join_group(
        &mut self,
        welcome: Welcome,
        expected_inviter: Contact,
        group_name: &str,
    ) -> io::Result<()> {
        if self.group.is_some() {
            return Err(io::Error::other("Joined a group already."));
        }

        log::debug!("Joining group");

        // NOTE: Since the DS doesn't distribute copies of the group's ratchet
        // tree, we need to include the ratchet_tree_extension.
        let group_config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();
        let mls_group =
            StagedWelcome::new_from_welcome(&self.provider, &group_config, welcome, None)
                .map_err(|e| io::Error::other(format!("Failed to create staged join - {e}")))?
                .into_group(&self.provider)
                .map_err(|e| io::Error::other(format!("Failed to create MlsGroup - {e}")))?;

        let is_admin = mls_group.members().count() == 2;

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
            return Err(io::Error::other("Unexpected inviter/invitee identity"));
        }

        let group = Group {
            group_name: group_name.to_string(),
            mls_group,
            contacts: vec![expected_inviter],
            is_admin,
        };

        log::trace!("   {}", group_name);

        self.group = Some(group);
        Ok(())
    }

    fn apply_secret(
        &mut self,
        secret: Vec<u8>,
    ) -> io::Result<PreSharedKeyId> {
        // Store the secret as an external psk.
        // This is used for mutual authentication.
        if secret.len() != pairing::NUM_SECRET_BYTES {
            return Err(io::Error::other("Invalid number of bytes in secret."));
        }

        let psk_id = vec![1u8, 2, 3];
        let external_psk = ExternalPsk::new(psk_id);
        let preshared_key_id = PreSharedKeyId::new(
            CIPHERSUITE,
            self.provider.rand(),
            Psk::External(external_psk),
        )
        .expect("An unexpected error occured.");
        preshared_key_id.store(&self.provider, &secret).unwrap();

        Ok(preshared_key_id)
    }

    fn delete_secret(
        &mut self,
        preshared_key_id: &PreSharedKeyId,
    ) {
        let _ = self.provider.storage().delete_psk(preshared_key_id.psk());
    }

    /// Process a welcome message
    fn process_welcome(
        &mut self,
        expected_inviter: Contact,
        welcome_msg_vec: Vec<u8>,
        group_name: &str,
    ) -> io::Result<()> {
        let welcome_msg = match MlsMessageIn::tls_deserialize(&mut welcome_msg_vec.as_slice()) {
            Ok(msg) => msg,
            Err(e) => return Err(io::Error::other(format!("{}", e))),
        };

        match welcome_msg.extract() {
            MlsMessageBodyIn::Welcome(welcome) => {
                self.join_group(welcome, expected_inviter, group_name)?;
            },
            _ => return Err(io::Error::other("Unsupported message type in process_welcome")),
        }

        Ok(())
    }

    pub fn process_welcome_with_secret(
        &mut self,
        expected_inviter: Contact,
        welcome_msg_vec: Vec<u8>,
        secret: Vec<u8>,
        group_name: &str,
    ) -> io::Result<()> {
        if self.client_type != ClientType::App {
            return Err(io::Error::other("Only an app can process a welcome message and join a group."));
        }

        let preshared_key_id = self.apply_secret(secret)?;

        let result = self.process_welcome(expected_inviter, welcome_msg_vec, group_name);

        self.delete_secret(&preshared_key_id);

        result
    }

    /// Write bytes to a file, truncating if it exists, and fsync the file.
    fn write_and_fsync(path: &Path, bytes: &[u8]) -> io::Result<()> {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        Ok(())
    }

    /// fsync a directory. This helps make renames durable across crashes.
    fn fsync_dir(dir: &Path) -> io::Result<()> {
        let d = File::open(dir)?;
        d.sync_all()?;
        Ok(())
    }

    /// Read the CURRENT pointer (e.g. "version000000123\n") and return the trimmed version string.
    fn read_current(file_dir: &Path) -> io::Result<String> {
        let mut s = String::new();
        File::open(file_dir.join(CURRENT_FILE))?.read_to_string(&mut s)?;
        Ok(s.trim().to_string())
    }

    /// Atomically write the CURRENT pointer via temp file + rename.
    fn write_current_atomic(file_dir: &Path, version: &str) -> io::Result<()> {
        let tmp = file_dir.join(format!(".{}.tmp", CURRENT_FILE));
        let dst = file_dir.join(CURRENT_FILE);

        Self::write_and_fsync(&tmp, format!("{version}\n").as_bytes())?;

        // Atomic replace of CURRENT
        fs::rename(&tmp, &dst)?;

        Self::fsync_dir(file_dir)?;
        Ok(())
    }

    /// Returns next monotonically increasing version string like "v000000001".
    fn next_version(file_dir: &Path) -> io::Result<String> {
        // If CURRENT doesn't exist yet, start at 1.
        let cur = match Self::read_current(file_dir) {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::NotFound => "v000000000".to_string(),
            Err(e) => return Err(e),
        };

        let n: u64 = cur
            .strip_prefix('v')
            .unwrap_or("0")
            .parse()
            .unwrap_or(0);

        Ok(format!("v{:09}", n + 1))
    }

    /// Saves the groups and key store in persistent storage, atomically.
    /// Layout:
    ///   self.file_dir/self.tag/v<version>/group_state
    ///   self.file_dir/self.tag/v<version>/key_store
    ///   self.file_dir/self.tag/CURRENT  (contains "v<version>")
    ///
    /// Atomicity guarantee:
    /// - The new version becomes visible only when CURRENT is switched.
    /// - If crash occurs before CURRENT rename, restore sees the old version.
    /// - If CURRENT is switched, both files are already written+fsynced in that version directory.
    pub fn save_group_state(
        &mut self
    ) -> io::Result<()> {
        let file_dir_path = Path::new(&self.file_dir); 
        let state_dir_path = file_dir_path.join(&self.tag);
        let version = Self::next_version(&state_dir_path)?;
        let new_dir = state_dir_path.join(&version);

        if !new_dir.exists() {
            fs::create_dir(&new_dir)?;
            Self::fsync_dir(&state_dir_path)?;
        }

        let g_path = new_dir.join(GROUP_STATE_FILENAME);
        let ks_path = new_dir.join(KEY_STORE_FILENAME);

        let group_helper_option = self.group.as_ref().map(|group| GroupHelper {
            group_name: group.group_name.clone(),
            group_id: group.mls_group.group_id().to_vec(),
            contacts: group.contacts.clone(),
            is_admin: group.is_admin,
        });

        let data = bincode::serialize(&group_helper_option)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let mut g_file = File::create(g_path)?;
        g_file.write_all(&data)?;
        g_file.flush()?;
        g_file.sync_all()?;

        #[cfg(test)]
        {
            if std::env::var("SAVE_GROUP_STATE_CRASH").is_ok() {
                return Ok(());
            }
        }

        let mut ks_file = File::create(ks_path)?;
        self.provider.save_keystore(&ks_file)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        ks_file.flush()?;
        ks_file.sync_all()?;

        Self::fsync_dir(&new_dir)?;

        Self::write_current_atomic(&state_dir_path, &version)?;

        //delete old state files
        Self::cleanup_old_versions(&state_dir_path, &version);

        Ok(())
    }

    fn restore_group_state(
        file_dir: String,
        tag: String,
        crypto: &mut OpenMlsRustPersistentCrypto,
    ) -> io::Result<Option<Group>> {
        let file_dir_path = Path::new(&file_dir);
        let state_dir_path = file_dir_path.join(&tag);
        let version = Self::read_current(&state_dir_path)?;
        let dir = state_dir_path.join(&version);

        let g_path = dir.join(GROUP_STATE_FILENAME);
        let ks_path = dir.join(KEY_STORE_FILENAME);

        // restore key store
        let ks_file = File::open(&ks_path)?;
        crypto.load_keystore(&ks_file)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        // restore group 
        let group = Self::load_group_from_file(&g_path, crypto)?;

        Ok(group)
    }

    fn cleanup_old_versions(file_dir: &Path, current: &str) {
        let keep: usize = 1; // Keep "keep" newest versions including current.
        let mut versions: Vec<String> = match fs::read_dir(file_dir) {
            Ok(rd) => rd
                .filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|name| name.starts_with('v'))
                .collect(),
            Err(_) => return,
        };

        versions.sort();

        if !versions.contains(&current.to_string()) {
            return;
        }

        // Keep the last `keep` entries
        let cutoff = versions.len().saturating_sub(keep);
        for v in &versions[..cutoff] {
            if v == current {
                continue;
            }
            // FIXME: what if this fails?
            let _ = fs::remove_dir_all(file_dir.join(v));
        }
    }

    pub fn create_contact(name: &str, key_package: KeyPackage) -> io::Result<Contact> {
        let id = key_package
            .leaf_node()
            .credential()
            .serialized_content()
            .to_vec();
        let contact = Contact {
            name: name.to_string(),
            key_package,
            id: id.clone(),
            update_proposal: None,
            last_update_timestamp: Self::now_in_secs(),
            admin_contact: false,
        };

        Ok(contact)
    }

    pub fn get_group_name(&self) -> io::Result<String> {
        match &self.group {
            Some(g) => Ok(g.group_name.clone()),

            None => Err(io::Error::other("Group not created yet".to_string())),
        }
    }

    /// Generate a commit to update self leaf node in the ratchet tree, merge the commit, and return the message
    /// to be sent to other group members. It also returns the epoch number after the update.
    pub fn update(&mut self) -> io::Result<(Vec<u8>, u64)> {
        if self.client_type != ClientType::Camera {
            return Err(io::Error::other("Only the camera can call update(). App should use update_proposal()."));
        }

        if self.group.is_none() {
            return Err(io::Error::other("Group not created yet".to_string()));
        }

        let group = self.group.as_mut().unwrap();

        // Set AAD
        let group_aad = group.group_name.clone() + " AAD";
        group.mls_group.set_aad(group_aad.as_bytes().to_vec());

        for contact in &mut group.contacts {
            if let Some(proposal) = contact.update_proposal.take() {
                group
                    .mls_group
                    .store_pending_proposal(self.provider.storage(), proposal)
                    .map_err(|e| io::Error::other(format!("Error: could not store proposal - {e}")))?;
            }
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
            .map_err(|e| io::Error::other(format!("Failed to self update - {e}")))?;

        log::trace!("Generating update message");
        // Generate the message to the group.
        let msg: MlsMessageOut = commit_msg_bundle.into_commit();

        // Merge pending commit.
        group
            .mls_group
            .merge_pending_commit(&self.provider)
            .expect("error merging pending commit");

        let mut msg_vec = Vec::new();
        msg.tls_serialize(&mut msg_vec)
            .map_err(|e| io::Error::other(format!("tls_serialize for msg failed ({e})")))?;

        let epoch = group.mls_group.epoch().as_u64();

        Ok((msg_vec, epoch))
    }

    /// Generate an update proposal for the self leaf node in the ratchet tree and return the proposal message
    /// to be sent to other group members.
    pub fn update_proposal(&mut self) -> io::Result<Vec<u8>> {
        if self.client_type != ClientType::App {
            return Err(io::Error::other("Only an app can call update_proposal(). Camera should use update()."));
        }

        if self.group.is_none() {
            return Err(io::Error::other("Group not created yet".to_string()));
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
                io::Error::other(format!(
                    "Failed to generate self update proposal message - {e}"
                ))
            })?;

        let mut msg_vec = Vec::new();
        proposal_msg.tls_serialize(&mut msg_vec).map_err(|e| {
            io::Error::other(format!("tls_serialize for proposal_msg failed ({e})"))
        })?;

        Ok(msg_vec)
    }

    pub fn get_update_proposals(&self) -> io::Result<Vec<QueuedProposal>> {
        let mut proposals: Vec<QueuedProposal> = vec![];

        let group = self.group.as_ref().unwrap();

        for contact in &group.contacts {
            if let Some(proposal) = &contact.update_proposal {
                proposals.push(proposal.clone());
            }
        }

        Ok(proposals)
    }

    pub fn store_update_proposals(&mut self, proposals: Vec<QueuedProposal>) -> io::Result<()> {
        let group = self.group.as_mut().unwrap();

        for proposal in proposals {
            group
                .mls_group
                .store_pending_proposal(self.provider.storage(), proposal)
                .map_err(|e| io::Error::other(format!("Error: could not store proposal - {e}")))?;
        }

        Ok(())
    }

    /// Get a member
    fn find_member_index(name: String, group: &mut Group) -> io::Result<LeafNodeIndex> {
        let id = group
        .contacts
        .iter()
        .find(|contact| contact.name == name)
        .map(|contact| contact.id.clone())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("Error: Found no contact named {name}"),
            )
        })?;

        let mls_group = &group.mls_group;
        for Member {
            index,
            encryption_key: _,
            signature_key: _,
            credential,
        } in mls_group.members()
        {
            let credential = BasicCredential::try_from(credential).unwrap();
            if credential.identity() == id {
                return Ok(index);
            }
        }
        Err(io::Error::other("Unknown member".to_string()))
    }

    /// Remove a contact from the group.
    pub fn remove(
        &mut self,
        contact_name: &str,
    ) -> io::Result<Vec<u8>> {
        let group = self.group.as_mut().unwrap();

        // Get the client leaf index
        let leaf_index = Self::find_member_index(contact_name.to_string(), group)?;

        // Set AAD for the commit message
        let group_aad = group.group_name.clone() + " AAD";
        group.mls_group.set_aad(group_aad.as_bytes().to_vec());

        // Remove operation on the mls group
        let (commit, _welcome, _group_info) = group
            .mls_group
            .remove_members(
                &self.provider,
                &self.identity.signer,
                &[leaf_index],
            )
            .map_err(|e| io::Error::other(format!("Failed to remove member from group - {e}")))?;

        let mut msg_vec = Vec::new();
        commit
            .tls_serialize(&mut msg_vec)
            .map_err(|e| io::Error::other(format!("tls_serialize for out_messages failed ({e})")))?;

        // Process the removal on our end.
        group
            .mls_group
            .merge_pending_commit(&self.provider)
            .expect("error merging pending commit");

        // Return the remove_message
        Ok(msg_vec)
    }

    /// Get the current group epoch
    pub fn get_epoch(&self) -> io::Result<u64> {
        if self.group.is_none() {
            return Err(io::Error::other("Group not created yet".to_string()));
        }

        let group = self.group.as_ref().unwrap();

        let epoch = group.mls_group.epoch().as_u64();

        Ok(epoch)
    }

    /* Not used for now. */
    /// Returns how long the only contact has been offline
    /// It is recommended that this is checked before encrypting a message
    /// for groups used to send important data.
    /// If the only contact has been offline for more than a threshold,
    /// no new messages should be encrypted/sent.
    pub fn offline_period(&self) -> u64 {
        /*
        let now = Self::now_in_secs();
        let first_contact = self.group.as_ref().unwrap().first_contact.as_ref().unwrap();
        if now < first_contact.last_update_timestamp {
            return 0;
        }

        now - first_contact.last_update_timestamp
        */
        0
    }

    /// Encrypts a message and returns the ciphertext
    pub fn encrypt(&mut self, bytes: &[u8]) -> io::Result<Vec<u8>> {
        if self.group.is_none() {
            return Err(io::Error::other("Group not created yet".to_string()));
        }

        let group = self.group.as_mut().unwrap();

        // Set AAD
        let group_aad = group.group_name.clone() + " AAD";
        group.mls_group.set_aad(group_aad.as_bytes().to_vec());

        let message_out = group
            .mls_group
            .create_message(&self.provider, &self.identity.signer, bytes)
            .map_err(|e| io::Error::other(format!("{e}")))?;

        let msg: MlsMessageOut = message_out;

        let mut msg_vec = Vec::new();
        msg.tls_serialize(&mut msg_vec)
            .map_err(|e| io::Error::other(format!("tls_serialize for msg failed ({e})")))?;

        Ok(msg_vec)
    }

    fn find_matching_contact<'a>(
        processed_message: &ProcessedMessage,
        contacts: &'a mut Vec<Contact>
    ) -> Option<&'a mut Contact> {
        let sender = processed_message.credential().clone();
        
        for contact in contacts {
            if sender == contact.get_credential() {
                return Some(contact);
            }
        }

        None
    }

    fn process_protocol_message(
        &mut self,
        message: ProtocolMessage,
        app_msg: bool,
    ) -> io::Result<Vec<u8>> {
        if self.group.is_none() {
            return Err(io::Error::other("Group not created yet".to_string()));
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
            return Err(io::Error::other(format!(
                "Error: message epoch ({}) must match the group epoch ({})",
                message.epoch(),
                mls_group.epoch()
            )));
        }

        let processed_message = match mls_group.process_message(&self.provider, message) {
            Ok(msg) => msg,
            Err(e) => {
                log::debug!("process_message returned: {e}");
                return Err(io::Error::other(format!(
                    "Error processing unverified message: {:?} -  Dropping message.",
                    e
                )));
            }
        };

        // Check AAD
        let group_aad = group.group_name.clone() + " AAD";

        if processed_message.aad().to_vec() != group_aad.into_bytes() {
            return Err(io::Error::other(
                "Error: received a message with an invalid AAD".to_string(),
            ));
        }

        // Only accepts messages from one of our contacts.
        // Note: in a ProcessedMessage, the credential of the message sender is already inspected.
        // See: openmls/src/framing/validation.rs
        // However, this is an additional check.
        // For example, it doesn't allow one app to send a message to another app,
        // which would otherwise be allowed.
        // In the camera, this also helps us determine if the message is coming from the admin_contact
        // or not.

        // It cannot be None if we're the camera. But it could be None if we're
        // the app since not all apps are in each others' contact list.
        let sender_contact: Option<&mut Contact> = Self::find_matching_contact(&processed_message, &mut group.contacts);
        if self.client_type == ClientType::Camera && sender_contact.is_none() {
            return Err(io::Error::other("Camera received a message from an unknown contact."));
        }

        match processed_message.into_content() {
            ProcessedMessageContent::ApplicationMessage(application_message) => {
                if !app_msg {
                    return Err(io::Error::other(
                        "Error: expected a commit message, but received an application message",
                    ));
                }
                let application_message = application_message.into_bytes();

                Ok(application_message)
            }
            ProcessedMessageContent::ProposalMessage(queued_proposal) => {
                if app_msg {
                    return Err(io::Error::other(
                        "Error: expected an application message, but received a proposal message.",
                    ));
                }

                if let Proposal::Update(_update_proposal) = queued_proposal.proposal() {
                    match self.client_type {
                        ClientType::Camera => {
                            // We've checked above and sender_contact is not None.
                            let sender = sender_contact.unwrap();
                            if sender.update_proposal.is_none() {
                                sender.update_proposal = Some(*queued_proposal);
                            }

                            sender.last_update_timestamp = Self::now_in_secs();
                        },

                        ClientType::App => {
                            group
                                .mls_group
                                .store_pending_proposal(self.provider.storage(), *queued_proposal)
                                .map_err(|e| io::Error::other(format!("Error: could not store proposal - {e}")))?;
                        },
                    }

                    return Ok(vec![]);
                } else if let Proposal::PreSharedKey(_psk_proposal) = queued_proposal.proposal() {
                    if self.client_type != ClientType::App {
                        return Err(io::Error::other("Only an app should receive a psk proposal."));
                    }

                    mls_group
                        .store_pending_proposal(self.provider.storage(), *queued_proposal)
                        .unwrap();

                    return Ok(vec![]);
                } else {
                    return Err(
                        io::Error::other("Error: Unexpected proposal type!".to_string()));
                }
            }
            ProcessedMessageContent::ExternalJoinProposalMessage(_external_proposal) => {
                return Err(
                    io::Error::other("Error: Unexpected external join proposal message!".to_string()));
            },
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                if app_msg {
                    return Err(io::Error::other(
                        "Error: expected an application message, but received a commit message.",
                    ));
                }

                if self.client_type != ClientType::App {
                    return Err(io::Error::other("Only an app should receive a staged commit message."));
                }

                if sender_contact.is_none() {
                    return Err(io::Error::other("Received a commit message from a member in the group other than the camera."));
                }

                let num_apps_in_group = mls_group.members().count() - 1;

                // Restrict the type of staged commits that we'll merge.
                // This is effectively a filter for the staged commit.
                // It's determined empirically and is best-effort.
                if !(staged_commit.add_proposals().next().is_none()
                    || staged_commit.add_proposals().collect::<Vec<_>>().len() == 1)
                    || !(staged_commit.remove_proposals().next().is_none()
                        || staged_commit.remove_proposals().collect::<Vec<_>>().len() == 1)
                    || !(staged_commit.update_proposals().next().is_none()
                        || staged_commit.update_proposals().collect::<Vec<_>>().len() <= num_apps_in_group)
                    || !(staged_commit.psk_proposals().next().is_none()
                        || staged_commit.psk_proposals().collect::<Vec<_>>().len() == 1)
                    || !(staged_commit.queued_proposals().next().is_none()
                        || staged_commit.queued_proposals().collect::<Vec<_>>().len() <= cmp::max(2, num_apps_in_group + 2)) // 1 psk, 1 add, 1 update per member
                {
                    return Err(io::Error::other(
                        "Error: staged commit message must contain at most one update/queued proposal and no other proposals.",
                    ));
                }

                mls_group
                    .merge_staged_commit(&self.provider, *staged_commit)
                    .expect("error merging staged commit");

                // We've checked above and sender_contact is not None.
                // TODO: we can only do this here since we know there's only one path for
                // us to receive a staged commit and in that the sender_contact has performed
                // a self update. However, ideally, we should check the staged commit itself
                // to see which other leaf nodes/contacts have been updated.
                sender_contact.unwrap().last_update_timestamp = Self::now_in_secs();

                Ok(vec![])
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
                return Err(io::Error::other(format!("Could not deserialize msg ({e})")));
            }
        };

        match mls_msg.extract() {
            MlsMessageBodyIn::Welcome(_welcome) => Err(io::Error::other(
                "Error: Unexpected welcome message!".to_string(),
            )),
            MlsMessageBodyIn::PrivateMessage(message) => {
                self.process_protocol_message(message.into(), app_msg)
            }
            MlsMessageBodyIn::PublicMessage(_message) => Err(io::Error::other(
                "Error: Unexpected public message!".to_string(),
            )),
            _ => Err(io::Error::other(
                "Error: Unsupported message type!".to_string(),
            )),
        }
    }

    pub fn decrypt_with_secret(
        &mut self,
        msg: Vec<u8>,
        app_msg: bool,
        secret: Vec<u8>,
    ) -> io::Result<Vec<u8>> {
        let preshared_key_id = self.apply_secret(secret)?;

        let result = self.decrypt(msg, app_msg);

        self.delete_secret(&preshared_key_id);

        result
    }

    fn now_in_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    #[cfg(test)]
    pub fn get_ratchet_tree(&self) -> RatchetTree {
        self.group.as_ref().unwrap().mls_group.export_ratchet_tree()
    }

    #[cfg(test)]
    pub fn get_own_leaf_node(&self) -> LeafNode {
        self.group.as_ref().unwrap().mls_group.own_leaf_node().unwrap().clone()
    }
}
