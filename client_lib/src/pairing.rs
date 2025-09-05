//! Secluso app-camera pairing protocol.
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

use crate::mls_client::KeyPackages;
use serde::{Deserialize, Serialize};

pub const NUM_SECRET_BYTES: usize = 72;

#[derive(Serialize, Deserialize, PartialEq)]
enum PairingMsgType {
    AppToCameraMsg,
    CameraToAppMsg,
}

#[derive(Serialize, Deserialize)]
struct PairingMsgContent {
    msg_type: PairingMsgType,
    key_packages: KeyPackages,
}

#[derive(Serialize, Deserialize)]
struct PairingMsg {
    content_vec: Vec<u8>,
}

pub struct App {
    key_packages: KeyPackages,
}

impl App {
    pub fn new(key_packages: KeyPackages) -> Self {
        Self {
            key_packages,
        }
    }

    pub fn generate_msg_to_camera(&self) -> Vec<u8> {
        let msg_content = PairingMsgContent {
            msg_type: PairingMsgType::AppToCameraMsg,
            key_packages: self.key_packages.clone(),
        };
        let msg_content_vec = bincode::serialize(&msg_content).unwrap();

        let msg = PairingMsg {
            content_vec: msg_content_vec,
        };

        bincode::serialize(&msg).unwrap()
    }

    pub fn process_camera_msg(&self, camera_msg_vec: Vec<u8>) -> anyhow::Result<KeyPackages> {
        let camera_msg: PairingMsg = bincode::deserialize(&camera_msg_vec)?;

        let camera_msg_content: PairingMsgContent =
            bincode::deserialize(&camera_msg.content_vec)?;
        // Check the message type
        if camera_msg_content.msg_type != PairingMsgType::CameraToAppMsg {
            panic!("Received invalid pairing message!");
        }

        Ok(camera_msg_content.key_packages)
    }
}

pub struct Camera {
    key_packages: KeyPackages,
}

impl Camera {
    // FIXME: identical to App::new()
    pub fn new(key_packages: KeyPackages) -> Self {
        Self {
            key_packages,
        }
    }

    pub fn process_app_msg_and_generate_msg_to_app(
        &self,
        app_msg_vec: Vec<u8>,
    ) -> anyhow::Result<(KeyPackages, Vec<u8>)> {
        let app_msg: PairingMsg = bincode::deserialize(&app_msg_vec).unwrap();

        let app_msg_content: PairingMsgContent =
            bincode::deserialize(&app_msg.content_vec).unwrap();
        // Check the message type
        if app_msg_content.msg_type != PairingMsgType::AppToCameraMsg {
            panic!("Received invalid pairing message!");
        }

        // Generate response
        let msg_content = PairingMsgContent {
            msg_type: PairingMsgType::CameraToAppMsg,
            key_packages: self.key_packages.clone(),
        };
        let msg_content_vec = bincode::serialize(&msg_content).unwrap();

        let resp_msg = PairingMsg {
            content_vec: msg_content_vec,
        };

        let resp_msg_vec = bincode::serialize(&resp_msg).unwrap();

        Ok((app_msg_content.key_packages, resp_msg_vec))
    }
}
