//! SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{Context, Result};
use docopt::Docopt;
use semver::Version;
use serde::Deserialize;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, SystemTime, UNIX_EPOCH, Instant};

use secluso_update::{
    build_github_client, default_signers, download_and_verify_component, fetch_latest_release,
    get_current_version, github_token_from_env, parse_sig_keys,
    require_release_is_immutable, write_current_version, Component,
    DEFAULT_OWNER_REPO,
};

const USAGE: &str = r#"
Secluso updater.

Usage:
  secluso-update --component COMPONENT [--once] [--bundle-path PATH] [--interval-secs N] [--github-timeout-secs N] [--restart-unit UNIT] [--github-repo <OWNER/REPO>] [--sig-key <NAME:GITHUB_USER>]... [--update-hint-path PATH] [--hint-check-interval-secs N]
  secluso-update (--help | -h)
  secluso-update (--version | -v)

Options:
  --component COMPONENT         Which single binary to update:
                                server | updater | raspberry_camera_hub | config_tool
  --restart-unit UNIT           systemd unit to restart after install (optional).
                                If omitted, no service is restarted.
  --interval-secs N             Poll interval seconds [default: 60].
  --github-timeout-secs N       HTTP timeout seconds [default: 20].
  --github-repo <OWNER/REPO>    GitHub repo to poll for releases [default: secluso/secluso].
  --sig-key <NAME:GITHUB_USER>  Signature label + GitHub user (repeatable).
  --once                        Run a single update check then exit.
  --bundle-path PATH            Use a local bundle zip instead of downloading from GitHub.
  --update-hint-path PATH       Path for the local update hint file (optional).
  --hint-check-interval-secs N  Update hint poll interval seconds [default: 10].
  --version, -v                 Show tool version.
  --help, -h                    Show this screen.
"#;

#[derive(Debug, Deserialize)]
struct Args {
    flag_component: String,
    flag_restart_unit: Option<String>,
    flag_interval_secs: u64,
    flag_github_timeout_secs: u64,
    flag_github_repo: String,
    flag_sig_key: Vec<String>,
    flag_once: bool,
    flag_bundle_path: Option<String>,
    flag_update_hint_path: Option<String>,
    flag_hint_check_interval_secs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReleaseSource {
    LatestImmutableGitHub,
}

#[derive(Debug, Clone)]
struct SelectedRelease {
    release: secluso_update::GhRelease,
    source: ReleaseSource,
}

#[derive(Debug)]
// Represents a fully prepared binary that is ready to be atomically renamed into place.
// The install step should commit the exact file we created and filled here.
// We stage in the destination directory, use exclusive creation, and then rename that same inode into place.
struct PreparedInstall {
    tmp_path: PathBuf,
    final_path: PathBuf,
}

impl PreparedInstall {
    fn tmp_path(&self) -> &Path {
        &self.tmp_path
    }

    fn final_path(&self) -> &Path {
        &self.final_path
    }

    fn commit(self) -> Result<()> {
        // The rename is the only step that makes the prepared binary live.
        // Since tmp_path lives in the target directory, this stays on the same filesystem and keeps the swap atomic.
        fs::rename(&self.tmp_path, &self.final_path).with_context(|| {
            format!(
                "installing {} -> {}",
                self.tmp_path.display(),
                self.final_path.display()
            )
        })?;
        Ok(())
    }
}

impl Drop for PreparedInstall {
    fn drop(&mut self) {
        // If anything fails after preparation but before commit, we remove the temp file.
        // Leaving executable staging junk around isn't exactly great practice.
        let _ = fs::remove_file(&self.tmp_path);
    }
}

fn main() -> ! {
    let version = format!(
        "{}, version: {}",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION")
    );

    let args: Args = Docopt::new(USAGE)
        .map(|d| d.help(true))
        .map(|d| d.version(Some(version)))
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    if args.flag_once {
        println!("Going to check for updates.");
        if let Err(e) = check_update(&args) {
            eprintln!("Update check failed: {:#}", e);
            std::process::exit(1);
        }
        std::process::exit(0);
    }

    if let Some(ref update_hint_path) = args.flag_update_hint_path {
        if args.flag_interval_secs % args.flag_hint_check_interval_secs != 0 {
            eprintln!(
                "flag_interval_secs ({}) must be divisible by flag_update_hint_interval_secs ({})",
                args.flag_interval_secs,
                args.flag_hint_check_interval_secs
            );
            std::process::exit(1);
        }

        // We want to force a check in the beginning.
        let mut last_full_check = Instant::now() - Duration::from_secs(args.flag_interval_secs);

        loop {
            let elapsed = last_full_check.elapsed();
            if elapsed >= Duration::from_secs(args.flag_interval_secs) {
                println!("Scheduled update check.");
                if let Err(e) = check_update(&args) {
                    eprintln!("Update check failed: {:#}", e);
                }
                last_full_check = Instant::now();
                continue;
            }

            sleep(Duration::from_secs(args.flag_hint_check_interval_secs));

            if is_there_update_hint(&update_hint_path) {
                println!("Update hint received, triggering early check.");
                if let Err(e) = check_update(&args) {
                    eprintln!("Update check failed: {:#}", e);
                }
                last_full_check = Instant::now();
            }
        }
    } else {
        loop {
            println!("Going to check for updates.");
            if let Err(e) = check_update(&args) {
                eprintln!("Update check failed: {:#}", e);
            }
            sleep(Duration::from_secs(args.flag_interval_secs));
        }
    }
}

pub fn is_there_update_hint(path: &str) -> bool {
    let p = Path::new(path);

    if p.exists() {
        let _ = fs::remove_file(p);
        true
    } else {
        false
    }
}

fn check_update(args: &Args) -> Result<()> {
    // Parse component and signer policy first so we fail early on invalid operator input before
    // touching network or filesystem state.
    let component = Component::parse(&args.flag_component)?;
    let cli_signers = parse_sig_keys(&args.flag_sig_key)?;
    let signers = if cli_signers.is_empty() {
        default_signers()
    } else {
        cli_signers
    };

    // If no version marker exists yet, we use a default 0.0.0 that works as a placeholder
    let current_version = get_current_version(component).unwrap_or_else(|_| Version::new(0, 0, 0));
    println!("Current Version = {current_version}");

    let github_token = github_token_from_env();
    let client = build_github_client(
        args.flag_github_timeout_secs,
        github_token.as_deref(),
        "secluso-updater",
    )?;

    // Allow repo override but keep a safe default
    let github_repo = if args.flag_github_repo.trim().is_empty() {
        DEFAULT_OWNER_REPO.to_string()
    } else {
        args.flag_github_repo.clone()
    };

    let Some(selected_release) = select_release_for_component(
        component,
        &current_version,
        || fetch_latest_release(&client, &github_repo),
        require_release_is_immutable,
    )?
    else {
        return Ok(());
    };

    match selected_release.source {
        ReleaseSource::LatestImmutableGitHub => {
            println!("Using the latest immutable GitHub release.");
        }
    };

    let release = selected_release.release;

    // download_and_verify_component performs the full cryptographic verification pipeline and returns
    // only authenticated component bytes. allows focus below on atomic file placement.
    let bundle_path = args
        .flag_bundle_path
        .as_ref()
        .map(|v| v.trim())
        .filter(|v| !v.is_empty());

    let verified = download_and_verify_component(
        &client,
        &release,
        component,
        std::env::consts::ARCH,
        bundle_path,
        &signers,
    )?;

    println!(
        "Verified component={} from {} ({} bytes)",
        args.flag_component,
        verified.component_path,
        verified.component_bytes.len()
    );

    let final_path = component.install_path();
    // Prepare the binary before we stop the service.
    // This makes the verified bytes tied to one fresh staging file all the way until rename.
    let prepared_install =
        prepare_verified_component_install(Path::new(&final_path), &verified.component_bytes)?;

    if let Some(unit) = args.flag_restart_unit.as_deref() {
        println!("Stopping unit: {}", unit);
        run(&format!("systemctl stop {}", shell_escape(unit)));
    }

    println!(
        "Installing: {} -> {}",
        prepared_install.tmp_path().display(),
        prepared_install.final_path().display()
    );
    prepared_install.commit()?;

    if let Some(unit) = args.flag_restart_unit.as_deref() {
        println!("Starting unit: {}", unit);
        run(&format!("systemctl start {}", shell_escape(unit)));
    }

    // Persist version only after install has succeeded. Acts to gate future update checks (via the marker).
    write_current_version(component, verified.latest_version.clone())?;

    println!(
        "Update completed successfully (component={})",
        args.flag_component
    );
    Ok(())
}

fn prepare_verified_component_install(
    final_path: &Path,
    component_bytes: &[u8],
) -> Result<PreparedInstall> {
    // We prepare the exact file that will later be atomically renamed into the live install path here.
    // It creates a fresh staging file in the destination directory, writes the verified bytes, applies the executable mode, and syncs the result.
    // The idea behind this all is that commit later renames the same file we prepared here.
    let final_dir = final_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("invalid install path: {}", final_path.display()))?;

    fs::create_dir_all(final_dir)
        .with_context(|| format!("creating install dir {}", final_dir.display()))?;

    let target_name = final_path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "secluso-binary".to_string());

    // Create the temp inode ourselves in the protected target directory with exclusive creation.
    // *Even if the filename is predictable, create_new refuses to adopt a preexisting file*
    let (tmp_path, mut tmp_file) = create_secure_install_temp_file(final_dir, &target_name)?;

    let write_result = (|| -> Result<()> {
        // All writes happen through the file descriptor returned by the exclusive open above.
        // That keeps the verified bytes attached to the same inode we later rename.
        tmp_file
            .write_all(component_bytes)
            .with_context(|| format!("writing verified binary to {}", tmp_path.display()))?;
        // Start from 0600 and only mark the file executable after the verified bytes are fully written.
        // (this avoids exposing a half-written executable if something goes sideways)
        tmp_file
            .set_permissions(fs::Permissions::from_mode(0o755))
            .with_context(|| format!("setting executable mode on {}", tmp_path.display()))?;
        // Flush file contents and metadata before rename; keeps the final swap from depending on dirty cache state.
        tmp_file
            .sync_all()
            .with_context(|| format!("syncing prepared binary at {}", tmp_path.display()))?;
        Ok(())
    })();

    if let Err(err) = write_result {
        drop(tmp_file);
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }

    drop(tmp_file);

    Ok(PreparedInstall {
        tmp_path,
        final_path: final_path.to_path_buf(),
    })
}

fn create_secure_install_temp_file(
    final_dir: &Path,
    target_name: &str,
) -> Result<(PathBuf, fs::File)> {
    // We only generate a unique name here so retries do not trip over each other.
    // Actual safety comes from create_new in the target directory and then sticking with that fd for the whole write.
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    for attempt in 0..128u32 {
        let tmp_path = final_dir.join(format!(
            ".{target_name}.install.{}.{}.tmp",
            std::process::id(),
            seed + u128::from(attempt)
        ));

        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)
        {
            Ok(file) => return Ok((tmp_path, file)),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("creating temp install path {}", tmp_path.display()));
            }
        }
    }

    Err(anyhow::anyhow!(
        "failed to allocate a unique install temp path in {}",
        final_dir.display()
    ))
}

fn select_release_for_component<FLatest, FRequireImmutable>(
    component: Component,
    current_version: &Version,
    fetch_latest_release_fn: FLatest,
    require_release_is_immutable_fn: FRequireImmutable,
) -> Result<Option<SelectedRelease>>
where
    FLatest: FnOnce() -> Result<secluso_update::GhRelease>,
    FRequireImmutable: FnOnce(&secluso_update::GhRelease) -> Result<()>,
{
    match component {
        _ => {
            let release = fetch_latest_release_fn()?;
            require_release_is_immutable_fn(&release)?;

            let latest_version = release.parsed_version()?;
            if current_version >= &latest_version {
                println!("Already on the latest immutable GitHub release.");
                return Ok(None);
            }

            Ok(Some(SelectedRelease {
                release,
                source: ReleaseSource::LatestImmutableGitHub,
            }))
        }
    }
}

// "best-effort" command runner used for service stop/start so updater can still finish installation
fn run(cmd: &str) {
    let _ = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new(prefix: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "{prefix}-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            ));
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn prepared_install_commit_replaces_binary_without_temp_leftovers() {
        let root = TestDir::new("secluso-update-install");
        let final_path = root.path().join("bin").join("secluso-server");

        let prepared =
            prepare_verified_component_install(&final_path, b"verified-server-binary").unwrap();

        assert!(prepared.tmp_path().exists());
        assert_eq!(prepared.final_path(), final_path.as_path());

        prepared.commit().unwrap();

        // After commit, only the final binary should remain in the directory.
        assert_eq!(fs::read(&final_path).unwrap(), b"verified-server-binary");
        assert_eq!(
            fs::metadata(&final_path).unwrap().permissions().mode() & 0o777,
            0o755
        );

        let entries = fs::read_dir(final_path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(entries, vec!["secluso-server".to_string()]);
    }

    #[test]
    fn dropping_prepared_install_cleans_up_temp_file() {
        let root = TestDir::new("secluso-update-cleanup");
        let final_path = root.path().join("bin").join("secluso-server");

        let tmp_path = {
            let prepared =
                prepare_verified_component_install(&final_path, b"verified-server-binary").unwrap();
            let tmp_path = prepared.tmp_path().to_path_buf();
            assert!(tmp_path.exists());
            tmp_path
        };

        // If installation aborts after the temp inode is created, cleanup should remove it, so that we don't accumulate executable staging files in the protected install directory.
        assert!(!tmp_path.exists());
        assert!(!final_path.exists());
    }
}

// Minimal shell escaping helper to safely embed unit names into sh -c commands.
fn shell_escape(s: &str) -> String {
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '@'))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', r#"'\''"#))
    }
}
