//! Privastead user authentication: user client side code.
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

use hmac::{Hmac, Mac};
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::random::OpenMlsRand;
use openmls_traits::OpenMlsProvider;
use serde::{Deserialize, Serialize};
use sha3::Sha3_512;
use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::rc::Rc;

// Key size for HMAC-Sha3-512
// Same key size used here: https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.hmacsha3_512.-ctor?view=net-9.0
pub const NUM_SECRET_BYTES: usize = 72;
type HmacType = Hmac<Sha3_512>;

// Nonce size
pub const NUM_NONCE_BYTES: usize = 64;

// Username size
pub const NUM_USERNAME_BYTES: usize = 64;

#[derive(Serialize, Deserialize)]
struct UserMsgContent {
    username: Vec<u8>,
    nonce: Vec<u8>,
}

//FIXME: get_hmac and verify_hmac almost identical to ones in pairing.rs

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

fn verify_hmac(secret: &[u8; NUM_SECRET_BYTES], msg: &[u8], code_bytes: &[u8]) -> io::Result<()> {
    let mut mac = HmacType::new_from_slice(secret)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{e}")))?;
    mac.update(msg);

    // `verify_slice` will return `Ok(())` if code is correct, `Err(MacError)` otherwise
    mac.verify_slice(code_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{e}")))?;

    Ok(())
}

#[derive(Serialize, Deserialize)]
struct UserMsg {
    content_vec: Vec<u8>,
    tag: Vec<u8>,
}

pub struct UserAuth {
    username: [u8; NUM_USERNAME_BYTES],
    secret: [u8; NUM_SECRET_BYTES],
}

impl UserAuth {
    pub fn new(username: [u8; NUM_USERNAME_BYTES], secret: [u8; NUM_SECRET_BYTES]) -> Self {
        Self { username, secret }
    }

    pub fn generate_msg_to_server(&self, nonce: Vec<u8>) -> Vec<u8> {
        assert!(nonce.len() == NUM_NONCE_BYTES);

        let msg_content = UserMsgContent {
            username: self.username.to_vec(),
            nonce,
        };
        let msg_content_vec = bincode::serialize(&msg_content).unwrap();

        let tag = get_hmac(&self.secret, &msg_content_vec);

        let msg = UserMsg {
            content_vec: msg_content_vec,
            tag,
        };

        bincode::serialize(&msg).unwrap()
    }
}

pub struct ServerAuth {
    users: Rc<RefCell<HashMap<[u8; NUM_USERNAME_BYTES], [u8; NUM_SECRET_BYTES]>>>,
    nonce: [u8; NUM_NONCE_BYTES],
}

impl ServerAuth {
    pub fn new(
        users: Rc<RefCell<HashMap<[u8; NUM_USERNAME_BYTES], [u8; NUM_SECRET_BYTES]>>>,
    ) -> Self {
        let crypto = OpenMlsRustCrypto::default();
        let nonce = crypto
            .crypto()
            .random_vec(NUM_NONCE_BYTES)
            .unwrap()
            .try_into()
            .unwrap();

        Self { users, nonce }
    }

    pub fn generate_msg_to_user(&self) -> Vec<u8> {
        self.nonce.to_vec()
    }

    pub fn authenticate_user_msg(
        &self,
        user_msg_vec: Vec<u8>,
    ) -> io::Result<[u8; NUM_USERNAME_BYTES]> {
        let user_msg: UserMsg = bincode::deserialize(&user_msg_vec).unwrap();

        let user_msg_content: UserMsgContent = bincode::deserialize(&user_msg.content_vec).unwrap();
        // Check username length
        if user_msg_content.username.len() != NUM_USERNAME_BYTES {
            log::debug!("Invalid username length!");
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Invalid username length!",
            ));
        }

        // Look up username
        let username: [u8; NUM_USERNAME_BYTES] = user_msg_content.username.try_into().unwrap();
        let users = self.users.borrow_mut();
        let secret = users.get(&username);
        if secret.is_none() {
            log::debug!("Invalid username!");
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Invalid username!",
            ));
        }

        // Check the msg tag
        let verify_result = verify_hmac(secret.unwrap(), &user_msg.content_vec, &user_msg.tag);
        if verify_result.is_err() {
            log::debug!("Invalid tag!");
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Invalid tag!",
            ));
        }

        // Check nonce length
        if user_msg_content.nonce.len() != NUM_NONCE_BYTES {
            log::debug!("Invalid nonce length!");
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Invalid nonce length!",
            ));
        }

        // Check nonce
        if user_msg_content.nonce != self.nonce.to_vec() {
            log::debug!("Invalid nonce!");
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Invalid nonce!",
            ));
        }

        // Successfully authenticated
        Ok(username)
    }
}
