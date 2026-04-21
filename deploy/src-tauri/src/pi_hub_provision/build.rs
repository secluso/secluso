//! SPDX-License-Identifier: GPL-3.0-or-later
use crate::pi_hub_provision::credentials::generate_secluso_credentials;
use crate::pi_hub_provision::docker::{docker_ready, err_to_string, run_with_output, write_docker_context};
use crate::pi_hub_provision::events::{log_line, step_error, step_ok, step_start};
use crate::pi_hub_provision::model::{Apt, Config, RuntimeConfig, Secluso, SigKey, Ssh, User};
use crate::pi_hub_provision::temp::{shared_temp_root, shared_temp_dir};
use crate::pi_hub_provision::{BuildImageRequest, BuildImageResponse};
use anyhow::{anyhow, bail, Context, Result};
use secluso_update::{
    build_github_client, default_signers, download_and_verify_component, fetch_latest_release, Component as ReleaseComponent,
    Signer,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tauri::AppHandle;
use uuid::Uuid;

const DEFAULT_BASE_IMAGE: &str = "https://downloads.raspberrypi.com/raspios_lite_arm64/images/raspios_lite_arm64-2024-11-19/2024-11-19-raspios-bookworm-arm64-lite.img.xz";
const DEFAULT_USER_NAME: &str = "pi";
const DEFAULT_USER_PASSWORD: &str = "ChangeMe123!";
const DEFAULT_HOSTNAME_OFFICIAL: &str = "secluso-camera";
const DEFAULT_HOSTNAME_DIY: &str = "secluso-camera-diy";
const DEFAULT_PLATFORM: &str = "linux/arm64";
const DEFAULT_DOCKER_TAG: &str = "rpi-img-builder:local";
const RPICAM_APPS_COMMIT: &str = "9159a2b0f9ab0fd535189ca0364e0539deaef6a4";
const DEFAULT_PACKAGES: &[&str] = &[
    "ca-certificates",
    "curl",
    "jq",
    "net-tools",
    "vim",
    "htop",
];

const LIST_OF_BINARIES: &[&str] = &["rpicam-hello", "rpicam-jpeg", "rpicam-raw", "rpicam-still", "rpicam-vid"];


fn is_linux_x86() -> bool {
    std::env::consts::OS == "linux"
        && matches!(std::env::consts::ARCH, "x86" | "x86_64" | "i586" | "i686")
}

fn has_qemu_user_static() -> bool {
    let probe = Command::new("qemu-aarch64-static")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok();
    if probe {
        return true;
    }
    Command::new("qemu-user-static")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

fn normalize_repo(input: &str) -> String {
    let trimmed = input.trim().trim_end_matches('/');
    if let Some(idx) = trimmed.find("github.com/") {
        let repo = &trimmed[idx + "github.com/".len()..];
        return repo.trim_end_matches(".git").to_string();
    }
    trimmed.trim_end_matches(".git").to_string()
}

fn resolve_signers(sig_keys: Option<&[SigKey]>) -> Vec<Signer> {
    let Some(sig_keys) = sig_keys else {
        return default_signers();
    };

    if sig_keys.is_empty() {
        return default_signers();
    }

    sig_keys
        .iter()
        .map(|key| Signer {
            label: key.name.trim().to_string(),
            github_user: key.github_user.trim().to_string(),
            fingerprint: key
                .fingerprint
                .as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(ToOwned::to_owned),
        })
        .collect()
}

fn download_verified_bundle(owner_repo: &str, sig_keys: Option<&[SigKey]>, github_token: Option<&str>) -> Result<(String, Vec<u8>)> {
    let signers = resolve_signers(sig_keys);
    let client = build_github_client(20, github_token, "secluso-deploy")?;
    let release = fetch_latest_release(&client, owner_repo)
        .with_context(|| format!("Fetching latest release metadata for {owner_repo}"))?;
    let verified = download_and_verify_component(
        &client,
        &release,
        ReleaseComponent::RaspberryCameraHub,
        "aarch64",
        None,
        &signers,
    )
    .context("Downloading and verifying Raspberry Pi bundle")?;

    Ok((verified.release_tag, verified.bundle_bytes))
}

fn normalize_ssh_suffix(output_name: &str, ssh_enabled: bool) -> String {
    if !output_name.ends_with(".img") {
        return output_name.to_string();
    }
    if ssh_enabled {
        if output_name.ends_with("-ssh-enabled.img") {
            return output_name.to_string();
        }
        return format!("{}-ssh-enabled.img", &output_name[..output_name.len() - 4]);
    }
    if let Some(base) = output_name.strip_suffix("-ssh-enabled.img") {
        return format!("{base}.img");
    }
    output_name.to_string()
}

pub fn run_build_image(app: &AppHandle, run_id: Uuid, req: BuildImageRequest) -> Result<BuildImageResponse> {
    // input validation happens here so the ui can show a clear first failure
    step_start(app, run_id, "validate", "Validating inputs");
    if !req.image_output_path.ends_with(".img") {
        step_error(app, run_id, "validate", "Output image must end with .img.");
        bail!("Output image must end with .img.");
    }
    if !req.qr_output_path.ends_with(".png") {
        step_error(app, run_id, "validate", "QR output must end with .png.");
        bail!("QR output must end with .png.");
    }
    step_ok(app, run_id, "validate");

    // check docker early so we fail fast before doing work
    step_start(app, run_id, "docker_check", "Checking Docker");
    let docker_ver = match docker_ready() {
        Ok(version) => version,
        Err(e) => {
            let msg = err_to_string(e);
            step_error(app, run_id, "docker_check", &msg);
            return Err(anyhow!(msg));
        }
    };
    log_line(app, run_id, "info", Some("docker_check"), docker_ver);
    step_ok(app, run_id, "docker_check");

    if is_linux_x86() {
        step_start(app, run_id, "qemu_check", "Checking qemu-user-static");
        if !has_qemu_user_static() {
            let msg = "qemu-user-static is required on Linux x86 hosts to build ARM images. Install it (e.g. sudo apt-get install -y qemu-user-static) and retry.";
            step_error(app, run_id, "qemu_check", msg);
            bail!(msg);
        }
        step_ok(app, run_id, "qemu_check");
    }

    // resolve output paths and build a config used by the image builder script
    let output_path = PathBuf::from(&req.image_output_path);
    let output_name = output_path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow!("Invalid output image path: {}", req.image_output_path))?;
    let ssh_enabled = req.ssh_enabled.unwrap_or(false);
    let output_name = normalize_ssh_suffix(output_name, ssh_enabled);
    let out_dir = output_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(out_dir).with_context(|| format!("creating output dir {}", out_dir.display()))?;

    let variant = req.variant.as_deref().unwrap_or("diy");
    let hostname = if variant == "official" {
        DEFAULT_HOSTNAME_OFFICIAL
    } else {
        DEFAULT_HOSTNAME_DIY
    };


    // base config mirrors the test harness defaults
    let cfg = Config {
        output_name,
        hostname: hostname.to_string(),
        user: User {
            name: DEFAULT_USER_NAME.to_string(),
            password: DEFAULT_USER_PASSWORD.to_string(),
        },
        ssh: Ssh { enable: ssh_enabled, authorized_keys: vec![] },
        wifi: req.wifi.clone(),
        apt: Apt { packages: DEFAULT_PACKAGES.iter().map(|p| (*p).to_string()).collect() },
        secluso: Some(Secluso {
            server_url: None,
            camera_name: None,
            release_mode: None,
            release_tag: None,
            asset_name: None,
            asset_kind: None,
            install_dir: None,
            etc_dir: None,
            repo: req.binaries_repo.as_ref().map(|repo| normalize_repo(repo)),
            sig_keys: req.sig_keys.clone().map(|keys| {
                keys
                    .into_iter()
                    .map(|k| SigKey { name: k.name, github_user: k.github_user, fingerprint: k.fingerprint })
                    .collect()
            }),
            github_token: req.github_token.clone().filter(|v| !v.trim().is_empty()),
        }),
    };

    // build the image builder container from the embedded Dockerfile
    step_start(app, run_id, "docker_build", "Building image builder");
    let ctx = shared_temp_dir("secluso-docker-ctx").context("creating temp docker context")?;
    write_docker_context(ctx.path())?;

    let mut build_cmd = Command::new("docker");
    build_cmd.args(["build", "--no-cache"]);
    build_cmd
        .args(["--platform", DEFAULT_PLATFORM, "-t", DEFAULT_DOCKER_TAG])
        .arg(ctx.path());
    run_with_output(app, run_id, "docker_build", &mut build_cmd)
        .context("docker build failed")
        .map_err(|e| {
            let msg = err_to_string(e);
            step_error(app, run_id, "docker_build", &msg);
            anyhow!(msg)
        })?;
    step_ok(app, run_id, "docker_build");

    // generate pairing artifacts before building the image so we can inject them
    step_start(app, run_id, "credentials", "Generating pairing credentials");
    let work_dir = shared_temp_dir("secluso-work").context("creating temp work dir")?;
    let work_path = work_dir.path();

    if let Some(secluso) = &cfg.secluso {
        let repo = secluso
            .repo
            .clone()
            .unwrap_or_else(|| "secluso/secluso".to_string());
        let sig_keys = secluso.sig_keys.as_deref();
        let github_token = secluso.github_token.as_deref();
        generate_secluso_credentials(app, run_id, work_path, &repo, sig_keys, github_token)?;
    }
    step_ok(app, run_id, "credentials");

    if let Some(secluso) = &cfg.secluso {
        step_start(app, run_id, "artifacts", "Downloading verified bundle");
        let repo = secluso
            .repo
            .as_deref()
            .map(normalize_repo)
            .unwrap_or_else(|| "secluso/secluso".to_string());
        let sig_keys = secluso.sig_keys.as_deref();
        let github_token = secluso.github_token.as_deref();
        let (release_tag, bundle_bytes) = download_verified_bundle(&repo, sig_keys, github_token)
            .map_err(|e| {
                let msg = format!("{e:#}");
                step_error(app, run_id, "artifacts", &msg);
                anyhow!(msg)
            })?;
        fs::write(work_path.join("secluso_bundle.zip"), bundle_bytes)
            .with_context(|| format!("writing {}", work_path.join("secluso_bundle.zip").display()))
            .map_err(|e| {
                let msg = format!("{e:#}");
                step_error(app, run_id, "artifacts", &msg);
                anyhow!(msg)
            })?;
        log_line(
            app,
            run_id,
            "info",
            Some("artifacts"),
            format!("Verified Raspberry Pi bundle {release_tag} for {repo}."),
        );
        step_ok(app, run_id, "artifacts");
    }


    let mut base_image = DEFAULT_BASE_IMAGE;
    let mut search_image_name: &str = DEFAULT_BASE_IMAGE.split('/').last().unwrap();
    if search_image_name.ends_with(".xz") {
        search_image_name = search_image_name.strip_suffix(".xz").unwrap();
    }

    let images_folder = shared_temp_root().join("images");
    let rpicam_apps_folder = shared_temp_root().join("rpicam_apps");

    let expected_rpicam_apps_in = rpicam_apps_folder.join(RPICAM_APPS_COMMIT);
    let expected_rpicam_apps_out = work_path.join("rpicam_apps");
    let expected_image_in = images_folder.join(search_image_name);
    let expected_image_out = work_path.join(search_image_name);

    let mut found_image_cache: bool = false;
    let mut found_rpicam_apps_cache: bool = false;
    if req.cache {
        if !images_folder.exists() {
            fs::create_dir(&images_folder)?;
        } else {
            if !expected_image_in.exists() {
                // Clear out old caches
                fs::remove_dir_all(&images_folder)?;
                fs::create_dir(&images_folder)?;
            } else {
                found_image_cache = true;
                fs::copy(&expected_image_in, &expected_image_out)?;
                base_image = search_image_name;
            }
        }

        if !rpicam_apps_folder.exists() {
            fs::create_dir(&rpicam_apps_folder)?;
        } else {
            let exists = expected_rpicam_apps_in.exists() && LIST_OF_BINARIES.iter().all(|binary| expected_rpicam_apps_in.join(binary).exists());

            if !exists {
                // Clear out old caches
                fs::remove_dir_all(&rpicam_apps_folder)?;
                fs::create_dir(&rpicam_apps_folder)?;
            } else {
                found_rpicam_apps_cache = true;
                fs::create_dir(&expected_rpicam_apps_out)?;

                for binary in LIST_OF_BINARIES {
                    fs::copy(expected_rpicam_apps_in.join(binary), expected_rpicam_apps_out.join(binary))?;
                }
            }
        }
    }

    // write the config that build.sh reads inside the container
    step_start(app, run_id, "config", "Writing runtime config");
    let rt_cfg = RuntimeConfig {
        base_image: base_image.to_string(),
        rpicam_apps_commit: RPICAM_APPS_COMMIT.to_string(),
        output_name: cfg.output_name.clone(),
        hostname: cfg.hostname.clone(),
        variant: variant.to_string(),
        user: cfg.user.clone(),
        ssh: cfg.ssh.clone(),
        wifi: cfg.wifi.clone(),
        apt: cfg.apt.clone(),
        secluso: cfg.secluso.clone(),
    };
    let cfg_json = serde_json::to_string_pretty(&rt_cfg).context("serialize runtime config")?;
    fs::write(work_path.join("config.json"), cfg_json).context("write /work/config.json")?;
    step_ok(app, run_id, "config");

    // run the image builder container with the work and output mounts
    step_start(app, run_id, "docker_run", "Building image (Docker)");
    let mut cmd = Command::new("docker");
    cmd.args(["run", "--rm", "--platform", DEFAULT_PLATFORM, "--privileged"])
        .args(["--security-opt", "seccomp=unconfined"])
        .args(["--tmpfs", "/tmp:exec,mode=1777"])
        .arg("--mount")
        .arg(format!("type=bind,source={},target=/work", work_path.display()))
        .arg("--mount")
        .arg(format!("type=bind,source={},target=/out", out_dir.display()))
        .arg("-e").arg("LIBGUESTFS_BACKEND=direct")
        .arg("-e").arg("LIBGUESTFS_MEMSIZE=1024")
        .arg("-e").arg("LIBGUESTFS_QEMU_OPTIONS=-accel tcg")
        .arg(DEFAULT_DOCKER_TAG);

    if Path::new("/dev/kvm").exists() {
        cmd.args(["--device", "/dev/kvm"]);
    }

    run_with_output(app, run_id, "docker_run", &mut cmd)
        .context("docker run failed")
        .map_err(|e| {
            let msg = err_to_string(e);
            step_error(app, run_id, "docker_run", &msg);
            anyhow!(msg)
        })?;
    step_ok(app, run_id, "docker_run");

    // We want to cache; we didn't have it originally; we save it now.
    if req.cache && !found_image_cache {
        fs::copy(&expected_image_out, &expected_image_in)?;
    }

  if req.cache && !found_rpicam_apps_cache {
      fs::create_dir_all(&expected_rpicam_apps_in)?;
      for binary in LIST_OF_BINARIES {
            fs::copy(expected_rpicam_apps_out.join(binary), expected_rpicam_apps_in.join(binary))?;
      }
  }

    // verify the output and copy the qr code to the requested path
    step_start(app, run_id, "verify", "Verifying outputs");
    let out_img = out_dir.join(&cfg.output_name);
    if !out_img.exists() {
        step_error(app, run_id, "verify", format!("Expected output image not found: {}", out_img.display()));
        bail!("Expected output image not found: {}", out_img.display());
    }

    let qr_src = work_path.join("camera_secret_qrcode.png");
    if qr_src.exists() {
        fs::copy(&qr_src, &req.qr_output_path)
            .with_context(|| format!("copying QR code to {}", req.qr_output_path))?;
        log_line(app, run_id, "info", Some("verify"), format!("QR code saved at: {}", req.qr_output_path));
    } else {
        log_line(app, run_id, "warn", Some("verify"), "QR code was not generated (missing camera_secret_qrcode.png).");
    }
    step_ok(app, run_id, "verify");

    Ok(BuildImageResponse {
        out_image: out_img.display().to_string(),
    })
}
