//! Secluso Config commands
//!
//! Copyright (C) 2025  Ardalan Amiri Sani
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

use crate::mls_clients::{MlsClients, MLS_CLIENT_TAGS, MOTION, NUM_MLS_CLIENTS, THUMBNAIL};
use log::{error, info};
use serde::{Deserialize, Serialize};
use std::io;

/// opcodes
pub const OPCODE_HEARTBEAT_REQUEST: u8 = 0;
pub const OPCODE_HEARTBEAT_RESPONSE: u8 = 1;

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
    pub fn generate(mls_clients: &mut MlsClients, timestamp: u64) -> io::Result<Self> {
        let motion_epoch = mls_clients[MOTION].get_epoch()?;

        let thumbnail_epoch = mls_clients[THUMBNAIL].get_epoch()?;

        let mut update_proposals: Vec<Vec<u8>> = vec![];
        for i in 0..NUM_MLS_CLIENTS {
            if MLS_CLIENT_TAGS[i] == "motion"
                || MLS_CLIENT_TAGS[i] == "livestream"
                || MLS_CLIENT_TAGS[i] == "thumbnail"
            {
                let update_proposal = mls_clients[i].update_proposal()?;
                mls_clients[i].save_group_state();
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

    pub fn process_update_proposals(&mut self, mls_clients: &mut MlsClients) -> io::Result<()> {
        let mut proposals_i = 0;
        for i in 0..NUM_MLS_CLIENTS {
            if MLS_CLIENT_TAGS[i] == "motion"
                || MLS_CLIENT_TAGS[i] == "livestream"
                || MLS_CLIENT_TAGS[i] == "thumbnail"
            {
                let _ =
                    mls_clients[i].decrypt(self.update_proposals[proposals_i].clone(), false)?;
                mls_clients[i].save_group_state();
                proposals_i += 1;
            }
        }

        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
pub struct Heartbeat {
    pub firmware_version: String,
    pub timestamp: u64,
    pub epochs: Vec<u64>,          //for motion and livestream MLS clients
    pub ciphertexts: Vec<Vec<u8>>, //for all MLS clients except for config
}

impl Heartbeat {
    pub fn generate(
        mls_clients: &mut MlsClients,
        timestamp: u64,
        firmware_version: String,
    ) -> io::Result<Self> {
        let mut ciphertexts: Vec<Vec<u8>> = vec![];
        let mut epochs: Vec<u64> = vec![];
        let timestamp_bytes: Vec<u8> = timestamp.to_le_bytes().to_vec();

        for i in 0..NUM_MLS_CLIENTS {
            if MLS_CLIENT_TAGS[i] != "config" {
                let ciphertext = mls_clients[i].encrypt(&timestamp_bytes)?;
                mls_clients[i].save_group_state();
                ciphertexts.push(ciphertext);
            }

            if MLS_CLIENT_TAGS[i] == "motion"
                || MLS_CLIENT_TAGS[i] == "livestream"
                || MLS_CLIENT_TAGS[i] == "thumbnail"
            {
                let epoch = mls_clients[i].get_epoch()?;
                epochs.push(epoch);
            }
        }

        Ok(Self {
            firmware_version,
            timestamp,
            epochs,
            ciphertexts,
        })
    }

    pub fn process(
        &self,
        mls_clients: &mut MlsClients,
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
                    let epoch = match mls_clients[i].get_epoch() {
                        Ok(e) => e,
                        Err(e) => {
                            // The mls client is most likely corrupted.
                            error!("Failed to get epoch of mls client: {:?}", e);
                            return Ok(HeartbeatResult::InvalidCiphertext);
                        }
                    };

                    if epoch != self.epochs[epoch_i] {
                        return Ok(HeartbeatResult::InvalidEpoch);
                    }

                    epoch_i += 1;
                }
                let plaintext =
                    match mls_clients[i].decrypt(self.ciphertexts[ciphertexts_i].clone(), true) {
                        Ok(p) => p,
                        Err(e) => {
                            error!("Failed to decrypt ciphertext: {:?}", e);
                            return Ok(HeartbeatResult::InvalidCiphertext);
                        }
                    };
                mls_clients[i].save_group_state();

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
