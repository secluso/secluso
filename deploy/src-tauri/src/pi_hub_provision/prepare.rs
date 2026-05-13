//! SPDX-License-Identifier: GPL-3.0-or-later
use crate::pi_hub_provision::credentials::generate_secluso_credentials;
use crate::pi_hub_provision::events::{log_line, step_error, step_ok, step_start};
use crate::pi_hub_provision::image_inject::{inject_files, ConstructedFile};
use crate::pi_hub_provision::model::SigKey;
use crate::pi_hub_provision::temp::shared_temp_dir;
use crate::pi_hub_provision::{PrepareImageRequest, PrepareImageResponse};
use crate::release_config::{normalize_repo, resolve_signers};
use anyhow::{anyhow, bail, Context, Result};
use secluso_update::{
    build_github_client, download_and_verify_release_asset_to_path, fetch_latest_release,
    DEFAULT_OWNER_REPO,
};
use std::fs;
use std::path::{Path, PathBuf};
use tauri::AppHandle;
use uuid::Uuid;

fn download_verified_image(
    owner_repo: &str,
    sig_keys: Option<&[SigKey]>,
    github_token: Option<&str>,
    output_path: &Path,
) -> Result<(String, String)> {
    // The image is not something the deploy tool builds locally anymore. It's downloaded and then modified by the tool.
    // The updater library verifies the release immutability, the signed sha256sums file, the signer keys, the named WIC asset checksum, and GitHub's asset digest metadata before this function returns.
    // GitHub release assets API reference for release asset metadata and downloads: https://docs.github.com/en/rest/releases/assets?apiVersion=2022-11-28.
    let signers = resolve_signers(sig_keys);
    let client = build_github_client(20, github_token, "secluso-deploy")?;
    let release = fetch_latest_release(&client, owner_repo)
        .with_context(|| format!("Fetching latest release metadata for {owner_repo}"))?;
    let asset_name = format!("secluso-pi-image-{}.wic", release.tag_name);
    let verified = download_and_verify_release_asset_to_path(
        &client,
        &release,
        &asset_name,
        output_path,
        &signers,
    )
    .with_context(|| format!("Downloading and verifying {}", asset_name))?;

    Ok((verified.release_tag, verified.asset_name))
}

fn requested_custom_wic_source(req: &PrepareImageRequest) -> Option<PathBuf> {
    req.custom_wic_path
        .as_deref()
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
}

fn copy_custom_wic_image(source_path: &Path, output_path: &Path) -> Result<bool> {
    let source_canonical = source_path
        .canonicalize()
        .with_context(|| format!("resolving custom WIC image {}", source_path.display()))?;
    let same_file = output_path
        .canonicalize()
        .map(|output_canonical| output_canonical == source_canonical)
        .unwrap_or(false);

    if same_file {
        return Ok(true);
    }

    fs::copy(source_path, output_path).with_context(|| {
        format!(
            "copying custom WIC image from {} to {}",
            source_path.display(),
            output_path.display()
        )
    })?;
    Ok(false)
}

pub fn run_prepare_image(
    app: &AppHandle,
    run_id: Uuid,
    req: PrepareImageRequest,
) -> Result<PrepareImageResponse> {
    step_start(app, run_id, "validate", "Validating inputs");
    // I made this specifically for our Secluso OS WIC file (injection code expects our fixed image layout, not an arbitrary WIC layout)
    // partition 1 is /boot, partition 2 is /, and partition 3 is the 16MB FAT /provision partition.
    // The Yocto WIC image creation flow used by Secluso OS is documented at https://docs.yoctoproject.org/dev-manual/wic.html, https://github.com/secluso/os
    // Validation happens before any credential generation or network work
    if !req.image_output_path.ends_with(".wic") {
        step_error(app, run_id, "validate", "Output image must end with .wic.");
        bail!("Output image must end with .wic.");
    }
    if !req.qr_output_path.ends_with(".png") {
        step_error(app, run_id, "validate", "QR output must end with .png.");
        bail!("QR output must end with .png.");
    }
    let custom_wic_source = requested_custom_wic_source(&req);
    if let Some(custom_wic_path) = custom_wic_source.as_deref() {
        let custom_wic_display = custom_wic_path.display().to_string();
        if !custom_wic_display.ends_with(".wic") {
            step_error(
                app,
                run_id,
                "validate",
                "Custom WIC image must end with .wic.",
            );
            bail!("Custom WIC image must end with .wic.");
        }
        if !custom_wic_path.is_file() {
            let msg = format!("Custom WIC image not found: {}", custom_wic_path.display());
            step_error(app, run_id, "validate", &msg);
            bail!(msg);
        }
        log_line(
            app,
            run_id,
            "warn",
            Some("validate"),
            format!(
                "CUSTOM WIC OVERRIDE ENABLED: using {} as the base image. The released Secluso OS WIC will NOT be downloaded or verified.",
                custom_wic_path.display()
            ),
        );
    }
    step_ok(app, run_id, "validate");

    let output_path = PathBuf::from(&req.image_output_path);
    let out_dir = output_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(out_dir)
        .with_context(|| format!("creating output dir {}", out_dir.display()))?;

    let repo = req
        .binaries_repo
        .as_deref()
        .map(normalize_repo)
        .unwrap_or_else(|| DEFAULT_OWNER_REPO.to_string());
    let sig_keys = req.sig_keys.as_deref();
    let github_token = req.github_token.as_deref().filter(|v| !v.trim().is_empty());

    step_start(app, run_id, "credentials", "Generating pairing credentials");
    // The camera secret and hotspot password are generated before the image is downloaded
    // Both generated files are then copied into the partition 3 /provision FAT filesystem as plain files
    // The QR code is generated from the same pairing material in the temporary work directory, and later copied to the path the user wants after the image has been prepared
    let work_dir = shared_temp_dir("secluso-work").context("creating temp work dir")?;
    let work_path = work_dir.path();
    generate_secluso_credentials(app, run_id, work_path, &repo, sig_keys, github_token)?;
    let camera_secret = fs::read(work_path.join("camera_secret"))
        .with_context(|| format!("reading {}", work_path.join("camera_secret").display()))?;
    let wifi_password = fs::read(work_path.join("wifi_password"))
        .with_context(|| format!("reading {}", work_path.join("wifi_password").display()))?;
    step_ok(app, run_id, "credentials");

    if let Some(custom_wic_path) = custom_wic_source.as_deref() {
        step_start(app, run_id, "image_download", "Using custom WIC image");
        log_line(
            app,
            run_id,
            "warn",
            Some("image_download"),
            format!(
                "Using custom WIC image {}. This is NOT the released verified Secluso OS image.",
                custom_wic_path.display()
            ),
        );
        let in_place = copy_custom_wic_image(custom_wic_path, &output_path).map_err(|e| {
            let msg = format!("{e:#}");
            step_error(app, run_id, "image_download", &msg);
            anyhow!(msg)
        })?;
        let line = if in_place {
            format!(
                "Custom WIC source and output are the same file; injecting directly into {}.",
                output_path.display()
            )
        } else {
            format!(
                "Copied custom WIC image from {} to {}.",
                custom_wic_path.display(),
                output_path.display()
            )
        };
        log_line(app, run_id, "info", Some("image_download"), line);
    } else {
        step_start(
            app,
            run_id,
            "image_download",
            "Downloading verified released Secluso image",
        );
        // Fetch the latest immutable GitHub release metadata, derives the expected WIC asset name from the tag, verifies the signed release checksum file, and streams the WIC to the requested output path
        let (release_tag, image_asset_name) =
            download_verified_image(&repo, sig_keys, github_token, &output_path).map_err(|e| {
                let msg = format!("{e:#}");
                step_error(app, run_id, "image_download", &msg);
                anyhow!(msg)
            })?;
        log_line(
            app,
            run_id,
            "info",
            Some("image_download"),
            format!("Verified released image {image_asset_name} from {release_tag}."),
        );
    }
    step_ok(app, run_id, "image_download");

    step_start(app, run_id, "inject", "Injecting camera configuration");
    let files = vec![
        ConstructedFile::new("camera_secret", camera_secret),
        ConstructedFile::new("wifi_password", wifi_password),
    ];
    let partition = inject_files(&output_path, None, files).map_err(|e| {
        let msg = format!("{e:#}");
        step_error(app, run_id, "inject", &msg);
        anyhow!(msg)
    })?;
    log_line(
        app,
        run_id,
        "info",
        Some("inject"),
        format!(
            "Injected camera config into FAT partition {} at byte offset {}.",
            partition.index,
            partition.offset_bytes()
        ),
    );
    step_ok(app, run_id, "inject");

    step_start(app, run_id, "verify", "Verifying outputs");
    // At this point we confirm that the prepared WIC still exists and copy the QR code to its requested destination
    if !output_path.exists() {
        step_error(
            app,
            run_id,
            "verify",
            format!("Expected output image not found: {}", output_path.display()),
        );
        bail!("Expected output image not found: {}", output_path.display());
    }

    let qr_src = work_path.join("camera_secret_qrcode.png");
    if qr_src.exists() {
        fs::copy(&qr_src, &req.qr_output_path)
            .with_context(|| format!("copying QR code to {}", req.qr_output_path))?;
        log_line(
            app,
            run_id,
            "info",
            Some("verify"),
            format!("QR code saved at: {}", req.qr_output_path),
        );
    } else {
        log_line(
            app,
            run_id,
            "warn",
            Some("verify"),
            "QR code was not generated (missing camera_secret_qrcode.png).",
        );
    }
    step_ok(app, run_id, "verify");

    Ok(PrepareImageResponse {
        out_image: output_path.display().to_string(),
    })
}
