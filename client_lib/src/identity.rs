//! Privastead client identity.
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

//! Based on the OpenMLS client (openmls/cli).
//! MIT License.

use std::collections::HashMap;

use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use std::fs;
use std::io::{BufRead, BufReader, Write};

use super::openmls_rust_persistent_crypto::OpenMlsRustPersistentCrypto;

pub struct Identity {
    pub(crate) kp: HashMap<Vec<u8>, KeyPackage>,
    pub(crate) credential_with_key: CredentialWithKey,
    pub(crate) signer: SignatureKeyPair,
}

impl Identity {
    pub(crate) fn new(
        ciphersuite: Ciphersuite,
        crypto: &OpenMlsRustPersistentCrypto,
        username: &[u8],
        first_time: bool,
        file_dir: String,
        tag: String,
    ) -> Self {
        let credential = BasicCredential::new(username.to_vec());
        let pathname = file_dir + "/signature_key_" + &tag;
        let signature_keys = if first_time {
            let sig_keys = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
            sig_keys.store(crypto.storage()).unwrap();
            let mut file = fs::File::create(pathname).expect("Could not create file");
            file.write_all(&bincode::serialize(&sig_keys.public()).unwrap())
                .unwrap();
            file.flush().unwrap();
            file.sync_all().unwrap();
            sig_keys
        } else {
            let file = fs::File::open(pathname).expect("Could not open file");
            let mut reader =
                BufReader::with_capacity(file.metadata().unwrap().len().try_into().unwrap(), file);
            let data = reader.fill_buf().unwrap();

            let public_key = bincode::deserialize(data).unwrap();
            let sig_keys = SignatureKeyPair::read(
                crypto.storage(),
                public_key,
                ciphersuite.signature_algorithm(),
            )
            .unwrap();
            sig_keys
        };

        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: signature_keys.to_public_vec().into(),
        };

        let key_package = KeyPackage::builder()
            .build(
                ciphersuite,
                crypto,
                &signature_keys,
                credential_with_key.clone(),
            )
            .unwrap();

        Self {
            kp: HashMap::from([(
                key_package
                    .key_package()
                    .hash_ref(crypto.crypto())
                    .unwrap()
                    .as_slice()
                    .to_vec(),
                key_package.key_package().clone(),
            )]),
            credential_with_key,
            signer: signature_keys,
        }
    }

    /// Create an additional key package using the credential_with_key/signer bound to this identity
    pub fn add_key_package(
        &mut self,
        ciphersuite: Ciphersuite,
        crypto: &OpenMlsRustPersistentCrypto,
    ) -> KeyPackage {
        let key_package = KeyPackage::builder()
            .build(
                ciphersuite,
                crypto,
                &self.signer,
                self.credential_with_key.clone(),
            )
            .unwrap();

        self.kp.insert(
            key_package
                .key_package()
                .hash_ref(crypto.crypto())
                .unwrap()
                .as_slice()
                .to_vec(),
            key_package.key_package().clone(),
        );
        key_package.key_package().clone()
    }

    /// Get the plain identity as byte vector.
    pub fn identity(&self) -> &[u8] {
        self.credential_with_key.credential.serialized_content()
    }

    /// Get the plain identity as byte vector.
    pub fn identity_as_string(&self) -> String {
        std::str::from_utf8(self.credential_with_key.credential.serialized_content())
            .unwrap()
            .to_string()
    }

    pub fn delete_signature_key(&self, file_dir: String, tag: String) {
        let pathname = file_dir + "/signature_key_" + &tag;
        let _ = fs::remove_file(pathname);
    }
}
