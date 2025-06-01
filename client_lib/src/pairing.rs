//! Privastead app-camera pairing protocol.
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

use crate::user::KeyPackages;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha3::Sha3_512;
use anyhow::{Context};

// Key size for HMAC-Sha3-512
// Same key size used here: https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.hmacsha3_512.-ctor?view=net-9.0
pub const NUM_SECRET_BYTES: usize = 72;
type HmacType = Hmac<Sha3_512>;

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
    tag: Vec<u8>,
}

//FIXME: get_hmac and verify_hmac almost identical to ones in auth.rs

// See https://docs.rs/hmac/0.12.1/hmac/index.html for how to use hmac crate.
fn get_hmac(secret: &[u8; NUM_SECRET_BYTES], msg: &[u8]) -> Vec<u8> {
    let mut mac = HmacType::new_from_slice(secret).unwrap();
    mac.update(msg);

    // `result` has type `CtOutput` which is a thin wrapper around array of
    // bytes for providing constant time equality check
    let result = mac.finalize();
    // To get underlying array use `into_bytes`, but be careful, since
    // incorrect use of the code value may permit timing attacks which defeats
    // the security provided by the `CtOutput`
    let code_bytes = result.into_bytes();

    //FIXME: safe to use to_vec() here?
    code_bytes[..].to_vec()
}

fn verify_hmac(secret: &[u8; NUM_SECRET_BYTES], msg: &[u8], code_bytes: &[u8]) -> anyhow::Result<()> {
    let mut mac = HmacType::new_from_slice(secret).unwrap();
    mac.update(msg);

    // `verify_slice` will return `Ok(())` if code is correct, `Err(MacError)` otherwise
    mac.verify_slice(code_bytes)?;

    Ok(())
}

pub struct App {
    secret: [u8; NUM_SECRET_BYTES],
    key_packages: KeyPackages,
}

impl App {
    pub fn new(secret: [u8; NUM_SECRET_BYTES], key_packages: KeyPackages) -> Self {
        Self {
            secret,
            key_packages,
        }
    }

    pub fn generate_msg_to_camera(&self) -> Vec<u8> {
        let msg_content = PairingMsgContent {
            msg_type: PairingMsgType::AppToCameraMsg,
            key_packages: self.key_packages.clone(),
        };
        let msg_content_vec = bincode::serialize(&msg_content).unwrap();

        let tag = get_hmac(&self.secret, &msg_content_vec);

        let msg = PairingMsg {
            content_vec: msg_content_vec,
            tag,
        };

        bincode::serialize(&msg).unwrap()
    }

    pub fn process_camera_msg(&self, camera_msg_vec: Vec<u8>) -> anyhow::Result<KeyPackages> {
        let camera_msg: PairingMsg = bincode::deserialize(&camera_msg_vec)?;

        // Check the msg tag
        verify_hmac(&self.secret, &camera_msg.content_vec, &camera_msg.tag)
            .context("Received invalid pairing message")?;

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
    secret: [u8; NUM_SECRET_BYTES],
    key_packages: KeyPackages,
}

impl Camera {
    // FIXME: identical to App::new()
    pub fn new(secret: [u8; NUM_SECRET_BYTES], key_packages: KeyPackages) -> Self {
        Self {
            secret,
            key_packages,
        }
    }

    pub fn process_app_msg_and_generate_msg_to_app(
        &self,
        app_msg_vec: Vec<u8>,
    ) -> anyhow::Result<(KeyPackages, Vec<u8>)> {
        let app_msg: PairingMsg = bincode::deserialize(&app_msg_vec).unwrap();

        // Check the msg tag
        verify_hmac(&self.secret, &app_msg.content_vec, &app_msg.tag)?;

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

        let tag = get_hmac(&self.secret, &msg_content_vec);

        let resp_msg = PairingMsg {
            content_vec: msg_content_vec,
            tag,
        };

        let resp_msg_vec = bincode::serialize(&resp_msg).unwrap();

        Ok((app_msg_content.key_packages, resp_msg_vec))
    }
}
