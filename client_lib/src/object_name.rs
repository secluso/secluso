//! SPDX-License-Identifier: GPL-3.0-or-later
//! Object names for the enterprise DS
//!
//! The DIY server stores a video at data/<username>/<group>/<epoch>
//! We use this instead to maintain some user anonymity (prepping for future):
//!
//!     name = BLAKE3(exporter_key | group_name | epoch)
//!
//! Key is dedicated 256-bit secret, generated once per camera and handed to each app over the encrypted pairing channel.
//!
//! Used separate secret rather than anything derived from MLS.
//!
//! TODO: a removed member keeps this secret until it is re-keyed.

use std::fs;
use std::io;
use std::path::Path;

/// Bytes in the per-camera naming secret.
pub const OBJECT_SECRET_LEN: usize = 32;

/// File the secret is persisted under
pub const OBJECT_SECRET_FILE: &str = "object_secret";

pub fn generate_object_secret() -> Vec<u8> {
    use rand::RngCore;

    let mut secret = vec![0u8; OBJECT_SECRET_LEN];
    rand::rng().fill_bytes(&mut secret);
    secret
}

pub fn save_object_secret(dir: &Path, secret: &[u8]) -> io::Result<()> {
    if secret.len() != OBJECT_SECRET_LEN {
        return Err(io::Error::other(format!(
            "Object secret must be {OBJECT_SECRET_LEN} bytes, got {}",
            secret.len()
        )));
    }

    fs::write(dir.join(OBJECT_SECRET_FILE), secret)
}

pub fn load_object_secret(dir: &Path) -> io::Result<Vec<u8>> {
    let secret = fs::read(dir.join(OBJECT_SECRET_FILE))?;

    if secret.len() != OBJECT_SECRET_LEN {
        return Err(io::Error::other(
            "Stored object secret is the wrong length".to_string(),
        ));
    }

    Ok(secret)
}

/// The camera's secret, minting and persisting one the first time.
pub fn load_or_create_object_secret(dir: &Path) -> io::Result<Vec<u8>> {
    match load_object_secret(dir) {
        Ok(secret) => Ok(secret),
        Err(_) => {
            let secret = generate_object_secret();
            save_object_secret(dir, &secret)?;
            Ok(secret)
        }
    }
}

/// Derive the name an object is stored under.
///
/// Fields are length-prefixed rather than concatenated.
/// Without that, ("cam", "1" + "0") and ("cam1", "0") would hash to the same name
pub fn object_name(object_secret: &[u8], group_name: &str, epoch: u64) -> io::Result<String> {
    if object_secret.is_empty() {
        return Err(io::Error::other(
            "Refusing to derive an object name from an empty key".to_string(),
        ));
    }

    let mut hasher = blake3::Hasher::new();
    for field in [object_secret, group_name.as_bytes(), &epoch.to_be_bytes()] {
        hasher.update(&(field.len() as u64).to_be_bytes());
        hasher.update(field);
    }

    Ok(hasher.finalize().to_hex().to_string())
}

/// Same w/ a suffix for objects that hang off an epoch rather than being it..
/// a thumbnail alongside its video, for instance.
pub fn object_name_with_kind(
    object_secret: &[u8],
    group_name: &str,
    epoch: u64,
    kind: &str,
) -> io::Result<String> {
    object_name(object_secret, &format!("{group_name}\u{1f}{kind}"), epoch)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"an exporter secret of some length";

    #[test]
    fn names_are_stable() {
        let first = object_name(KEY, "group", 7).unwrap();
        let second = object_name(KEY, "group", 7).unwrap();

        assert_eq!(first, second);
        // A BLAKE3 hash in hex (what the DS expects as a filename)
        assert_eq!(first.len(), 64);
        assert!(first.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn every_field_changes_the_name() {
        let base = object_name(KEY, "group", 7).unwrap();

        assert_ne!(base, object_name(b"a different secret entirely", "group", 7).unwrap());
        assert_ne!(base, object_name(KEY, "other", 7).unwrap());
        assert_ne!(base, object_name(KEY, "group", 8).unwrap());
    }

    #[test]
    fn fields_cannot_be_shifted_across_the_boundary() {
        // The reason for length prefixes.
        assert_ne!(
            object_name(KEY, "cam1", 0).unwrap(),
            object_name(KEY, "cam", 10).unwrap()
        );
    }

    #[test]
    fn a_kind_is_a_different_object() {
        assert_ne!(
            object_name(KEY, "group", 7).unwrap(),
            object_name_with_kind(KEY, "group", 7, "thumbnail").unwrap()
        );
    }

    #[test]
    fn a_generated_secret_is_the_right_size_and_random() {
        let first = generate_object_secret();
        let second = generate_object_secret();

        assert_eq!(first.len(), OBJECT_SECRET_LEN);
        assert_ne!(first, second);
    }

    #[test]
    fn a_secret_survives_a_round_trip() {
        let dir = std::env::temp_dir().join(format!("secluso_obj_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        // First call mints it, second call must return the same one
        let minted = load_or_create_object_secret(&dir).unwrap();
        let reloaded = load_or_create_object_secret(&dir).unwrap();

        assert_eq!(minted, reloaded);
        assert_eq!(minted.len(), OBJECT_SECRET_LEN);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_empty_key_is_refused() {
        // Would otherwise produce a name derived from public inputs alone
        assert!(object_name(&[], "group", 7).is_err());
    }
}
