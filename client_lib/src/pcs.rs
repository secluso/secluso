//! Privastead Post-Compromise Security
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

use ds_lib::GroupMessage;
use openmls::prelude::tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};
use serde::{Deserialize, Serialize};
use std::io;

/// Protocol:
/// 1) The initiator determines when it's time for an MLS update. When so, before the next send, it
///    generates an update commit, sends it to the follower, and then merges it itself.
///    It also caches the update message.
/// 2) Upon receipt, the follower merges the commit and sends an ack to the initiator.
/// 3) After a configurable period, if the initiator has not yet received the ack,
///    it resends the cached message before the next send.

#[derive(Serialize, Deserialize, PartialEq)]
enum PcsInitiatorState {
    Synced,
    UpdatedButNotAcked,
}

#[derive(Serialize, Deserialize)]
pub struct PcsInitiator {
    state: PcsInitiatorState,
    pending_msg: Option<Vec<u8>>,
}

impl Default for PcsInitiator {
    fn default() -> Self {
        Self::new()
    }
}

impl PcsInitiator {
    pub fn new() -> Self {
        Self {
            state: PcsInitiatorState::Synced,
            pending_msg: None,
        }
    }

    pub fn updated(&mut self, msg: &GroupMessage) {
        self.state = PcsInitiatorState::UpdatedButNotAcked;

        let mut msg_vec = Vec::new();
        msg.tls_serialize(&mut msg_vec).unwrap();
        self.pending_msg = Some(msg_vec);
    }

    pub fn has_pending_update(&self) -> bool {
        if self.state == PcsInitiatorState::UpdatedButNotAcked {
            return true;
        }

        false
    }

    pub fn get_pending_update_msg(&mut self) -> io::Result<GroupMessage> {
        match &self.pending_msg {
            Some(m) => {
                let msg = GroupMessage::tls_deserialize(&mut m.as_slice()).unwrap();
                Ok(msg)
            }
            None => Err(io::Error::new(
                io::ErrorKind::Other,
                "No pending update msg.",
            )),
        }
    }

    pub fn message_received(&mut self) {
        if self.state == PcsInitiatorState::UpdatedButNotAcked {
            self.state = PcsInitiatorState::Synced;
        }
    }
}
