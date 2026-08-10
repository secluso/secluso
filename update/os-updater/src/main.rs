//! SPDX-License-Identifier: GPL-3.0-or-later

/// An updater client that uses TUF <https://theupdateframework.io> via AWS Labs implementation, tough <https://github.com/awslabs/tough>
/// Tough follows the TUF 1.0.0 specification <https://github.com/theupdateframework/specification/blob/9f148556ca15da2ec5c022c8b3e6f99a028e5fe5/tuf-spec.md>
/// Why this custom TUF updater over RAUC/Mender/SWUpdate? It allows support for quorums.
/// That means it enforces that M of N people have to sign for a target/metadata to be valid.
/// This prevents compromise of a singular key/person from attacking users.
///
/// Meant to be ran under a systemd timer service; simplifies the implementation.
///
/// TODO: We should get people from different jurisdictions to participate.
///       (they can check code that changed since last release + reproducible builds)
mod bootloader;

use anyhow::Context;
use semver::Version;
use std::fs::{File, read};
use std::io::Write;
use system_shutdown::force_reboot;
use tough::{IntoVec, Repository, RepositoryLoader, TargetName};
use url::Url;

// For now, we store the targets and metadata in Cloudflare R2 object storage.
// TODO: Support backup mirrors for both the repo and targets.
//       Postponed for now as tough doesn't come with a mirror role built in.
//       TUF 1.0.0 spec talks about it though.
const REPO_ROOT: &str = "https://mirror.secluso.net/tuf-repo";

// "root is the content of a TRUSTED root metadata file, which you must ship with your software using an out-of-band process."
// Given through an out-of-band process initially (initial .wic), and then updated when new .squashfs is downloaded.
// Therefore, it is NOT stored in a mutable place such as /data.
// This tells TUF the trusted keys (and is signed by such keys) and specifies trusted keys for other top-level roles.
// It also specifies thresholds for quorums for each role [root, snapshot, targets, timestamp]
const ROOT_FILE: &str = "root.json";

// tough requires async
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let current_slot = match bootloader::get_current()? {
        0 => "/slot-a",
        1 => "/slot-b",
        other => panic!("unexpected slot {other}"),
    };

    // Establish trust with the out-of-band root.
    let root_file_contents = read(format!("{current_slot}/{ROOT_FILE}"))
        .context("The root file is not in the expected place")?;

    // metadata_base_url and targets_base_url are the base URLs where the client can find metadata (such as root.json) and targets (as listed in targets.json).
    let metadata_base_url = Url::parse(&format!("{REPO_ROOT}/metadata"))?;
    let targets_base_url = Url::parse(&format!("{REPO_ROOT}/targets"))?;

    // https://docs.rs/tough/latest/tough/struct.RepositoryLoader.html
    let repository =
        RepositoryLoader::new(&root_file_contents, metadata_base_url, targets_base_url)
            .load()
            .await?;

    // We use the current crate version to indicate what version we're on (and tell if we're outdated)
    let current_version = Version::parse(env!("CARGO_PKG_VERSION"))?;

    // Find a valid target in the repo that meets the newer version and squashfs requirements.
    let valid_target = get_valid_target(&repository, &current_version);

    // TODO: If we're consistently <denied> updates for whatever reason, we should alert the user via the camera_hub (and perhaps by blinking the LED).
    //       An attacker may try to hold them on an older version.

    // If we find a viable target, then we fetch through TUF, overwrite the slot and call the bootloader backend.
    if let Some(target) = valid_target {
        perform_update(&repository, &target).await?;
    } else {
        println!("No new update found");
    }

    Ok(())
}

/// Fetch the bytes of the `target` from the `repository`, overwrite the other slot,
/// set the other slot as primary through the bootloader, and then reboot.
async fn perform_update(repository: &Repository, target: &TargetName) -> anyhow::Result<()> {
    let target_bytes = fetch_target_bytes(repository, target).await?;

    let opposite_slot = match bootloader::get_primary()? {
        0 => "/slot-b",
        1 => "/slot-a",
        other => panic!("unexpected slot {other}"),
    };

    let mut opposite_slot_block_device =
        File::open(opposite_slot).context("The slot partition does not exist")?;

    // Write the downloaded squashfs partition bytes into the other slot.
    opposite_slot_block_device
        .write_all(&target_bytes)
        .context("Failed to overwrite the other slot")?;

    bootloader::set_primary(opposite_slot)?;

    // Reboot into the new slot.
    force_reboot()?;

    // TODO: Check on the camera hub service and flip if necessary after reboot.
    Ok(())
}

/// Fetch and verify the requested `target` bytes from the `repository` into a Vec.
async fn fetch_target_bytes(
    repository: &Repository,
    target: &TargetName,
) -> anyhow::Result<Vec<u8>> {
    // Fetch a target's bytes into the heap.
    // TUF will validate hashes, signatures, etc. before giving us access to the data.
    // Alternatively, we could save to a file, e.g.: repository.save_target(target.0, "/data", Prefix::None).await?;
    // However, our only option would be /data. That would be putting it in a mutable vulnerable state.
    let valid_request = repository
        .read_target(target)
        .await
        .context("The repository metadata is expired or there was an issue making the request")?;
    let data_stream =
        valid_request.context("The requested target is not listed in the repository metadata")?;

    // "Consumers of this library must not use data from the stream if it returns an error."
    // into_vec consumes the entire stream (and will propagate errors)
    data_stream
        .into_vec()
        .await
        .context("The checksum of the requested target did not match")
}

/// Check the `repository`: is there a target that has a higher version than `current_version`?
fn get_valid_target(repository: &Repository, current_version: &Version) -> Option<TargetName> {
    // https://docs.rs/tough/latest/tough/struct.Repository.html
    for target in repository.all_targets() {
        // Check the custom metadata field within the target.
        // What version does it have? Is it higher than the current version?

        if let Some(value) = target.1.custom.get("version")
            && let Some(version) = value.as_str()
            && let Ok(parsed_version) = Version::parse(version)
            && *current_version < parsed_version
        {
            // TODO: Check: is the hash for the target we want in EAS?
            //       This will make updates immutable in the blockchain.
            //       https://github.com/secluso/core/issues/124

            return Some(target.0.to_owned());
        }
    }

    None
}
