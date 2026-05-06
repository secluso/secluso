//! Secluso Config commands
//!
//! SPDX-License-Identifier: GPL-3.0-or-later

use crate::mls_clients::{MlsClients, MLS_CLIENT_TAGS, MOTION, NUM_MLS_CLIENTS, THUMBNAIL,
    MlsClientsCommon, MlsClientsDedicated, NUM_COMMON_MLS_CLIENTS, LIVESTREAM_DED};
use openmls::prelude::KeyPackage;
use log::{error, info};
use serde::{Deserialize, Serialize};
use std::io;

/// opcodes
pub const OPCODE_HEARTBEAT_REQUEST: u8 = 0;
pub const OPCODE_HEARTBEAT_RESPONSE: u8 = 1;
pub const OPCODE_ADD_APP_REQUEST: u8 = 2;
pub const OPCODE_ADD_APP_RESPONSE: u8 = 3;

pub enum HeartbeatResult {
    InvalidTimestamp,
    InvalidCiphertext,
    InvalidEpoch,
    HealthyHeartbeat(u64), //timestamp: u64
}

#[derive(Serialize, Deserialize)]
pub struct HeartbeatRequest {
    pub timestamp: u64,
    pub motion_epoch: u64,
    pub thumbnail_epoch: u64,
    pub update_proposals: Vec<Vec<u8>>, //for motion, livestream, and thumbnail clients
}

impl HeartbeatRequest {
    pub fn generate(clients: &mut MlsClients, timestamp: u64) -> io::Result<Self> {
        let motion_epoch = clients[MOTION].get_epoch()?;

        let thumbnail_epoch = clients[THUMBNAIL].get_epoch()?;

        let mut update_proposals: Vec<Vec<u8>> = vec![];
        for i in 0..NUM_MLS_CLIENTS {
            if MLS_CLIENT_TAGS[i] == "motion"
                || MLS_CLIENT_TAGS[i] == "livestream"
                || MLS_CLIENT_TAGS[i] == "thumbnail"
            {
                let update_proposal = clients[i].update_proposal()?;
                clients[i].save_group_state().unwrap();
                update_proposals.push(update_proposal);
            }
        }

        Ok(Self {
            timestamp,
            motion_epoch,
            thumbnail_epoch,
            update_proposals,
        })
    }

    pub fn process_update_proposals(
        &mut self,
        clients_com: &mut MlsClientsCommon,
        clients_ded: &mut MlsClientsDedicated,
    ) -> io::Result<()> {
        let mut proposals_i = 0;
        for i in 0..NUM_MLS_CLIENTS {
            if MLS_CLIENT_TAGS[i] == "motion"
                || MLS_CLIENT_TAGS[i] == "thumbnail"
            {
                let _ =
                    clients_com[i].decrypt(self.update_proposals[proposals_i].clone(), false)?;
                clients_com[i].save_group_state().unwrap();
                proposals_i += 1;
            } else if MLS_CLIENT_TAGS[i] == "livestream" {
                let _ =
                    clients_ded[i - NUM_COMMON_MLS_CLIENTS].decrypt(self.update_proposals[proposals_i].clone(), false)?;
                clients_ded[i - NUM_COMMON_MLS_CLIENTS].save_group_state().unwrap();
                proposals_i += 1;
            }
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CameraVersionInfo {
    pub firmware_version: String,
    pub os_version: u64,
}

#[derive(Serialize, Deserialize)]
pub struct Heartbeat {
    pub firmware_version: String,
    pub os_version: u64,
    pub timestamp: u64,
    pub epochs: Vec<u64>,          //for motion and livestream MLS clients
    pub ciphertexts: Vec<Vec<u8>>, //for all MLS clients except for config
}

impl Heartbeat {
    pub fn generate(
        clients_com: &mut MlsClientsCommon,
        clients_ded: &mut MlsClientsDedicated,
        timestamp: u64,
        version_info: CameraVersionInfo,
    ) -> io::Result<Self> {
        let mut ciphertexts: Vec<Vec<u8>> = vec![];
        let mut epochs: Vec<u64> = vec![];
        let timestamp_bytes: Vec<u8> = timestamp.to_le_bytes().to_vec();

        for i in 0..NUM_COMMON_MLS_CLIENTS {
            let ciphertext = clients_com[i].encrypt(&timestamp_bytes)?;
            clients_com[i].save_group_state().unwrap();
            ciphertexts.push(ciphertext);

            if MLS_CLIENT_TAGS[i] == "motion"
                || MLS_CLIENT_TAGS[i] == "thumbnail"
            {
                let epoch = clients_com[i].get_epoch()?;
                epochs.push(epoch);
            }
        }

        // livestream
        let ciphertext = clients_ded[LIVESTREAM_DED].encrypt(&timestamp_bytes)?;
        clients_ded[LIVESTREAM_DED].save_group_state().unwrap();
        ciphertexts.push(ciphertext);
    
        let epoch = clients_ded[LIVESTREAM_DED].get_epoch()?;
        epochs.push(epoch);

        Ok(Self {
            firmware_version: version_info.firmware_version,
            os_version: version_info.os_version,
            timestamp,
            epochs,
            ciphertexts,
        })
    }

    pub fn process(
        &self,
        clients: &mut MlsClients,
        expected_timestamp: u64,
    ) -> io::Result<HeartbeatResult> {
        info!("Going to process heartbeat");
        if expected_timestamp != self.timestamp {
            error!("Unexpected timestamp");
            return Ok(HeartbeatResult::InvalidTimestamp);
        }

        let mut ciphertexts_i = 0;
        let mut epoch_i = 0;
        for i in 0..NUM_MLS_CLIENTS {
            if MLS_CLIENT_TAGS[i] != "config" {
                if MLS_CLIENT_TAGS[i] == "motion"
                    || MLS_CLIENT_TAGS[i] == "livestream"
                    || MLS_CLIENT_TAGS[i] == "thumbnail"
                {
                    let epoch = match clients[i].get_epoch() {
                        Ok(e) => e,
                        Err(e) => {
                            // The mls client is most likely corrupted.
                            error!("Failed to get epoch of mls client: {:?}", e);
                            return Ok(HeartbeatResult::InvalidCiphertext);
                        }
                    };

                    // Ideally, we want the two epochs to be equal. However, there's a race condition
                    // between the heartbeat (which is initiated in the app) and video and thumbnail
                    // (which are generated in the camera). Therefore, there could be some corner
                    // cases that these epochs can be within 1 of each other (but not equal) without
                    // meaning that we have a corrupted channel.
                    if epoch.abs_diff(self.epochs[epoch_i]) > 1 {
                        error!("{}: group epoch = {epoch}, heartbeat epoch = {:?}", MLS_CLIENT_TAGS[i], self.epochs[epoch_i]);
                        return Ok(HeartbeatResult::InvalidEpoch);
                    } else if epoch != self.epochs[epoch_i] {
                        epoch_i += 1;
                        ciphertexts_i += 1;
                        continue;
                    }

                    epoch_i += 1;
                }
                let plaintext =
                    match clients[i].decrypt(self.ciphertexts[ciphertexts_i].clone(), true) {
                        Ok(p) => p,
                        Err(e) => {
                            error!("Failed to decrypt ciphertext: {:?}", e);
                            return Ok(HeartbeatResult::InvalidCiphertext);
                        }
                    };
                clients[i].save_group_state().unwrap();

                info!("Checking plaintext for {}", MLS_CLIENT_TAGS[i]);
                let timestamp_bytes: [u8; 8] = match plaintext.try_into() {
                    Ok(b) => b,
                    Err(e) => {
                        error!("Failed to get timestamp bytes: {:?}", e);
                        return Ok(HeartbeatResult::InvalidCiphertext);
                    }
                };
                let timestamp = u64::from_le_bytes(timestamp_bytes);
                if timestamp != self.timestamp {
                    error!(
                        "Decrypted timestamp from the {} client is not correct.",
                        MLS_CLIENT_TAGS[i]
                    );
                    return Ok(HeartbeatResult::InvalidCiphertext);
                }
                ciphertexts_i += 1;
            }
        }
        info!("Heartbeat successfully processed.");

        Ok(HeartbeatResult::HealthyHeartbeat(self.timestamp))
    }
}

#[derive(Serialize, Deserialize)]
pub struct AddAppRequest {
    pub secret: Vec<u8>,
    pub new_app_key_package: KeyPackage,
}

#[derive(Serialize, Deserialize)]
pub struct AddAppResponseCommon {
    pub camera_key_package: KeyPackage,
    pub welcome_msg_vec: Vec<u8>,
    pub psk_proposal_vec: Vec<u8>,
    pub commit_msg_vec: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct AddAppResponseDedicated {
    pub camera_key_package: KeyPackage,
    pub welcome_msg_vec: Vec<u8>,
    pub group_name: String,
}
