//! SPDX-License-Identifier: GPL-3.0-or-later
//!
//! Startup diagnostic (microbench) for MLS on constrained hardware (right now, testing the Pi Zero W, ARMv6)
//! Runs the exact crypto the camera hub uses in a tight hot loop in an (otherwise) idle process.
//! Reports wall time, thread CPU time, throughput

use crate::openmls_rust_persistent_crypto::OpenMlsRustPersistentCrypto;
use anyhow::{anyhow, Context};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::signatures::Signer;
use openmls_traits::types::AeadType;
use openmls_traits::OpenMlsProvider;
use std::time::{Duration, Instant};

// Matches mls_client::CIPHERSUITE
const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;
const PAYLOAD_BYTES: usize = 64 * 1024;
const ITERS: usize = 20;

/// Thread CPU time consumed so far (not wall time).
/// Get the on-core cost, excluding time the scheduler gave to other threads.
pub fn thread_cpu_time() -> anyhow::Result<Duration> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &raw mut ts) };
    if rc != 0 {
        return Ok(Duration::ZERO);
    }
    Ok(Duration::new(ts.tv_sec.cast_unsigned(), u32::try_from(ts.tv_nsec)?))
}

fn report(name: &str, wall: Duration, cpu: Duration, bytes: usize) -> anyhow::Result<()> {
    let wall_ms = wall.as_secs_f64() * 1000.0f64 / f64::from(u32::try_from(ITERS)?);
    let cpu_ms = cpu.as_secs_f64() * 1000.0f64 / f64::from(u32::try_from(ITERS)?);
    let mb = f64::from(u32::try_from(bytes)?) / (1024.0f64 * 1024.0f64);
    let mbps = mb / (wall_ms / 1000.0f64);
    log::info!("{name} wall={wall_ms}ms  cpu={cpu_ms}ms  {mbps} MB/s");
    Ok(())
}

/// Run the diagnostic at process startup if the caller passes the env var.
pub fn run() -> anyhow::Result<()> {
    log::info!("payload={} kb, iters={}", PAYLOAD_BYTES / 1024, ITERS);

    let provider = OpenMlsRustPersistentCrypto::default();
    let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())?;
    signer.store(provider.storage())?;
    let credential = BasicCredential::new(b"secluso-selftest".to_vec());
    let credential_with_key = CredentialWithKey {
        credential: credential.into(),
        signature_key: signer.to_public_vec().into(),
    };
    let group_config = MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .build();
    let mut group = MlsGroup::new(&provider, &signer, &group_config, credential_with_key)?;

    let payload = vec![0xABu8; PAYLOAD_BYTES];

    // Raw ChaCha20Poly1305 seal
    {
        let key = vec![0u8; 32];
        let nonce = vec![0u8; 12];
        let aad = b"secluso-selftest";
        let _ =
            provider
                .crypto()
                .aead_encrypt(AeadType::ChaCha20Poly1305, &key, &payload, &nonce, aad);
        let w = Instant::now();
        let c = thread_cpu_time()?;
        for _ in 0..ITERS {
            let _ct = provider.crypto().aead_encrypt(
                AeadType::ChaCha20Poly1305,
                &key,
                &payload,
                &nonce,
                aad,
            )?;
        }
        report(
            "aead_seal",
            w.elapsed(),
            thread_cpu_time()?.checked_sub(c).context("failed to subtract s from thread cpu time")?,
            PAYLOAD_BYTES,
        )?;
    }

    // Ed25519 signature over the full payload
    {
        let _ = signer.sign(&payload);
        let w = Instant::now();
        let c = thread_cpu_time()?;
        for _ in 0..ITERS {
            // SignerError does not have StdError trait
            if let Err(e) = signer.sign(&payload) {
                println!("{e:?}");
                return Err(anyhow!("Signer error."));
            }
        }
        report(
            "ed25519_sign",
            w.elapsed(),
            thread_cpu_time()?.checked_sub(c).context("failed to subtract s from thread cpu time")?,
            PAYLOAD_BYTES,
        )?;
    }

    // MlsGroup::create_message
    {
        let _ = group.create_message(&provider, &signer, &payload);
        let w = Instant::now();
        let c = thread_cpu_time()?;
        for _ in 0..ITERS {
            let _m = group.create_message(&provider, &signer, &payload)?;
        }
        report(
            "create_message",
            w.elapsed(),
            thread_cpu_time()?.checked_sub(c).context("failed to subtract s from thread cpu time")?,
            PAYLOAD_BYTES,
        )?;
    }

    log::info!("done");
    Ok(())
}
