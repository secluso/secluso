//! SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use semver::Version;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{Cursor, Read};
use std::path::Path;
use std::time::Duration;
use zip::ZipArchive;

use openpgp::cert::Cert;
use openpgp::parse::stream::{
    DetachedVerifierBuilder, GoodChecksum, MessageLayer, MessageStructure, VerificationHelper,
};
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::{Fingerprint, KeyHandle};
use sequoia_openpgp as openpgp;

// Binaries stored in INSTALL_ROOT/bin/BINARY_NAME
pub const INSTALL_ROOT: &str = "/opt/secluso";

// Where we store camera secrets, *user credentials*, etc.
pub const WORKING_DIRECTORY: &str = "/var/lib/secluso";

// Where we fetch releases from (unless changed by the program dev settings)
pub const DEFAULT_OWNER_REPO: &str = "secluso/secluso";

const MANIFEST_PATH: &str = "manifest.json";

pub const NUM_USERNAME_CHARS: usize = 14;
pub const NUM_PASSWORD_CHARS: usize = 14;

/// A signer entry: label controls signature filename, github_user controls accepted keyring source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Signer {
    pub label: String,
    pub github_user: String,
}

/// Primary use point here two signatures, two github contributors, two different keys.
const DEFAULT_SIGNERS: [(&str, &str); 2] = [("jkaczman", "jkaczman"), ("arrdalan", "arrdalan")];

#[derive(Debug, Deserialize, Clone)]
pub struct GhRelease {
    pub tag_name: String,
    pub assets: Vec<GhAsset>,
    pub published_at: Option<String>,

    #[serde(default)]
    pub draft: bool,

    #[serde(default)]
    pub immutable: bool,
}

impl GhRelease {
    // Parse the Git tag into semver once and share that logic for both updater and deploy.
    // This keeps version comparisons consistent across all callers
    pub fn parsed_version(&self) -> Result<Version> {
        Ok(Version::parse(self.tag_name.trim_start_matches('v'))?)
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct GhAsset {
    pub id: u64,
    pub name: String,
    pub browser_download_url: String,
    pub size: u64,
    pub digest: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub enum Component {
    Server,
    Updater,
    RaspberryCameraHub,
    ConfigTool,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Manifest {
    build: BuildInfo,
    artifacts: Vec<Artifact>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct BuildInfo {
    target: String,
    profile: String,
    run_id: String,
    timestamp: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Artifact {
    package: String,
    target: String,
    bin: String,
    bin_path: String,
    #[serde(rename = "crate")]
    crate_name: String,
    version: String,
    crate_lock_sha256: String,
    rust_digest: String,
    sha256: String,
}

#[derive(Debug, Clone)]
pub struct VerifiedComponent {
    pub release_tag: String,
    pub latest_version: Version,
    pub manifest_version: String,
    pub component_path: String,
    pub component_bytes: Vec<u8>,
    pub bundle_bytes: Vec<u8>,
}

impl Component {
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "server" => Ok(Self::Server),
            "updater" => Ok(Self::Updater),
            "raspberry_camera_hub" => Ok(Self::RaspberryCameraHub),
            "config_tool" => Ok(Self::ConfigTool),
            _ => bail!(
                "Unknown component {}. Use one of: server | updater | raspberry_camera_hub | config_tool",
                s
            ),
        }
    }

    /// Path to the binary inside the zip, per arch.
    pub fn zip_path(self, arch: &str) -> Result<&'static str> {
        match (self, arch) {
            (Self::Server, "x86_64") => Ok("x86_64-unknown-linux-gnu/secluso-server"),
            (Self::Server, "aarch64") => Ok("aarch64-unknown-linux-gnu/secluso-server"),
            (Self::Server, _) => bail!("component=server not supported on arch={}", arch),

            (Self::Updater, "x86_64") => Ok("x86_64-unknown-linux-gnu/secluso-update"),
            (Self::Updater, "aarch64") => Ok("aarch64-unknown-linux-gnu/secluso-update"),
            (Self::Updater, _) => bail!("component=updater not supported on arch={}", arch),

            (Self::RaspberryCameraHub, "aarch64") => {
                Ok("aarch64-unknown-linux-gnu/secluso-raspberry-camera-hub")
            }
            (Self::RaspberryCameraHub, _) => {
                bail!(
                    "component=raspberry_camera_hub not supported on arch={}",
                    arch
                )
            }

            (Self::ConfigTool, "x86_64") => Ok("x86_64-unknown-linux-gnu/secluso-config-tool"),
            (Self::ConfigTool, "aarch64") => Ok("aarch64-unknown-linux-gnu/secluso-config-tool"),
            (Self::ConfigTool, _) => bail!("component=config_tool not supported on arch={}", arch),
        }
    }

    /// Where to install on disk
    pub fn install_path(self) -> String {
        let bin = match self {
            Self::Server => "secluso-server",
            Self::Updater => "secluso-update",
            Self::RaspberryCameraHub => "secluso-raspberry-camera-hub",
            Self::ConfigTool => "secluso-config-tool",
        };

        format!("{}/bin/{}", INSTALL_ROOT.trim_end_matches('/'), bin)
    }

    /// The version file location maintained per-component.
    pub fn version_file(self) -> String {
        let name = match self {
            Self::Server => "server",
            Self::Updater => "updater",
            Self::RaspberryCameraHub => "raspberry_camera_hub",
            Self::ConfigTool => "config_tool",
        };

        format!(
            "{}/current_version/{}",
            INSTALL_ROOT.trim_end_matches('/'),
            name
        )
    }
}

pub fn default_signers() -> Vec<Signer> {
    DEFAULT_SIGNERS
        .iter()
        .map(|(label, github_user)| Signer {
            label: (*label).to_string(),
            github_user: (*github_user).to_string(),
        })
        .collect()
}

// Signer inputs are user-facing configuration, therefore intentionally strict parsing is used. We require
// NAME:GITHUB_USER format with both fields present... any ambiguity here would weaken signature
// file lookup and GitHub keyring binding later in the verification pipeline.
pub fn parse_sig_keys(values: &[String]) -> Result<Vec<Signer>> {
    let mut signers = Vec::with_capacity(values.len());
    for raw in values {
        let mut parts = raw.splitn(2, ':');
        let label = parts.next().unwrap_or("").trim();
        let github_user = parts.next().unwrap_or("").trim();
        if label.is_empty() || github_user.is_empty() {
            bail!(
                "Invalid --sig-key value {}. Expected NAME:GITHUB_USER with both parts non-empty.",
                raw
            );
        }
        signers.push(Signer {
            label: label.to_string(),
            github_user: github_user.to_string(),
        });
    }
    Ok(signers)
}

// We allow either environment variable name in case of a future change in the env variable used to secluso only
pub fn github_token_from_env() -> Option<String> {
    std::env::var("GITHUB_TOKEN")
        .or_else(|_| std::env::var("SECLUSO_GITHUB_TOKEN"))
        .ok()
        .and_then(|v| {
            let trimmed = v.trim().to_string();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        })
}

// We centralize client construction so all callers share the same redirect limits, timeout policy,
// and optional bearer auth wiring.
pub fn build_github_client(
    timeout_secs: u64,
    github_token: Option<&str>,
    user_agent: &str,
) -> Result<Client> {
    let mut headers = HeaderMap::new();
    if let Some(token) = github_token.map(str::trim).filter(|v| !v.is_empty()) {
        let value = format!("Bearer {}", token);
        if let Ok(hv) = HeaderValue::from_str(&value) {
            headers.insert(AUTHORIZATION, hv);
        }
    }

    Client::builder()
        .user_agent(user_agent)
        .redirect(reqwest::redirect::Policy::limited(10))
        .timeout(Duration::from_secs(timeout_secs))
        .default_headers(headers)
        .build()
        .context("building GitHub HTTP client")
}

// Fetches the latest release metadata from GitHub's API endpoint for the target repo.
// Callers are expected to apply additional policy checks (draft/published/immutable) before trusting
// the returned release for installation decisions.
pub fn fetch_latest_release(client: &Client, owner_repo: &str) -> Result<GhRelease> {
    let url = format!(
        "https://api.github.com/repos/{}/releases/latest",
        owner_repo
    );
    let resp = client.get(&url).send()?.error_for_status()?;
    Ok(resp.json::<GhRelease>()?)
}

// Enforces the full trust chain before returning any installable bytes.
// 1) release policy checks (published, non-draft, immutable)
// 2) bundle integrity check against GitHub asset digest
// 3) detached signature verification over manifest.json bound to GitHub users public keys
// 4) artifact hash validation against the signed manifest entry
// Returning both component bytes and bundle bytes allows deploy to reuse verified material without
// repeating network fetches in less controlled execution environments.
pub fn download_and_verify_component(
    client: &Client,
    release: &GhRelease,
    component: Component,
    arch: &str,
    bundle_path: Option<&str>,
    signers: &[Signer],
) -> Result<VerifiedComponent> {
    download_and_verify_component_with_key_base(
        client,
        release,
        component,
        arch,
        bundle_path,
        signers,
        "https://github.com",
    )
}

fn download_and_verify_component_with_key_base(
    client: &Client,
    release: &GhRelease,
    component: Component,
    arch: &str,
    bundle_path: Option<&str>,
    signers: &[Signer],
    key_base_url: &str,
) -> Result<VerifiedComponent> {
    // Refuse mutable or unpublished releases up front. This prevents installing from states that can
    // still change after metadata is fetched.
    require_release_is_immutable(release)?;

    let latest_version = release.parsed_version()?;
    let required_signers: Vec<Signer> = if signers.is_empty() {
        default_signers()
    } else {
        signers.to_vec()
    };

    // Source selection policy:
    // - If a local bundle path is provided, we trust only local file I/O and still perform full
    // manifest/signature/artifact verification below.
    // - Otherwise we download the release asset and first bind it to GitHub's digest metadata.
    let zip_bytes: Bytes = if let Some(path) = bundle_path.map(str::trim).filter(|v| !v.is_empty())
    {
        Bytes::from(fs::read(path).with_context(|| format!("Failed reading bundle at {}", path))?)
    } else {
        let bundle = release
            .assets
            .iter()
            .find(|a| is_bundle_zip_asset(&a.name))
            .cloned()
            .ok_or_else(|| anyhow!("could not find bundle zip asset in latest release"))?;

        let bundle_digest = bundle
            .digest
            .as_deref()
            .ok_or_else(|| anyhow!("github asset {} missing digest field", bundle.name))?;

        let downloaded = fetch_bytes(client, &bundle.browser_download_url)
            .with_context(|| format!("Failed downloading {}", bundle.name))?;

        require_asset_sha256_digest_matches_download(&bundle.name, bundle_digest, &downloaded)?;
        downloaded
    };

    // From this point forward, all trust decisions are based on archive contents plus detached
    // signatures and key material fetched from GitHub users configured in signer policy.
    let mut zip =
        ZipArchive::new(Cursor::new(zip_bytes.clone())).context("Failed to parse zip archive")?;

    let manifest_bytes =
        read_zip_file(&mut zip, MANIFEST_PATH).context("Missing manifest.json in bundle")?;

    let mut sigs: Vec<(Signer, Vec<u8>)> = Vec::with_capacity(required_signers.len());
    for signer in &required_signers {
        let sig_path = manifest_sig_path_for(&signer.label);
        let sig_bytes = read_zip_file(&mut zip, &sig_path)
            .with_context(|| format!("Missing signature file in zip: {}", sig_path))?;
        sigs.push((signer.clone(), sig_bytes));
    }

    // Keyring cache avoids refetching the same GitHub user's keys when multiple labels map to one user.
    let mut key_cache: HashMap<String, (Vec<Cert>, HashSet<Fingerprint>)> = HashMap::new();

    for (signer, sig_bytes) in &sigs {
        let (certs, allowed_fprs) = match key_cache.get(&signer.github_user) {
            Some(v) => v.clone(),
            None => {
                let v = fetch_github_user_keyring(client, &signer.github_user, key_base_url)?;
                key_cache.insert(signer.github_user.clone(), v.clone());
                v
            }
        };

        verify_manifest_sig_requires_user(
            &manifest_bytes,
            sig_bytes,
            &certs,
            &allowed_fprs,
            &signer.github_user,
            &signer.label,
        )
        .with_context(|| {
            format!(
                "Signature verification failed (label={}, github_user={})",
                signer.label, signer.github_user
            )
        })?;
    }

    // The manifest itself is signed, so version checks and artifact lookup operate on authenticated data.
    let manifest: Manifest =
        serde_json::from_slice(&manifest_bytes).context("manifest.json is not valid JSON")?;

    let tag_semver = release.tag_name.trim_start_matches('v');
    if manifest
        .artifacts
        .iter()
        .any(|a| a.version.trim() != tag_semver)
    {
        bail!(
            "manifest artifacts contain a version that doesn't match release tag {}",
            release.tag_name
        );
    }

    let target_rel = component.zip_path(arch)?;
    let target_path = format!("artifacts/{}", target_rel);

    let art = manifest
        .artifacts
        .iter()
        .find(|a| a.bin_path == target_path)
        .ok_or_else(|| anyhow!("manifest missing artifact entry for {}", target_path))?;

    let target_bytes = read_zip_file(&mut zip, &target_path)
        .with_context(|| format!("Missing target binary in zip: {}", target_path))?;

    let expected = normalize_hex(&art.sha256);
    let got = sha256_hex(&target_bytes);

    if expected != normalize_hex(&got) {
        bail!(
            "sha256 mismatch for {}: expected={}, got={}",
            art.bin_path,
            art.sha256,
            got
        );
    }

    Ok(VerifiedComponent {
        release_tag: release.tag_name.clone(),
        latest_version,
        manifest_version: art.version.trim().to_string(),
        component_path: target_path,
        component_bytes: target_bytes,
        bundle_bytes: zip_bytes.to_vec(),
    })
}

fn is_bundle_zip_asset(name: &str) -> bool {
    name.starts_with("secluso-v") && name.ends_with(".zip")
}

fn manifest_sig_path_for(label: &str) -> String {
    format!("{}.{}.asc", MANIFEST_PATH, label)
}

// enforcement:
// immutable=true plus non-draft/non-null published_at prevents update/install decisions from using
// mutable pre-release states. Essentially a defense against race conditions where release assets or
// metadata could change between discovery and installation.
pub fn require_release_is_immutable(release: &GhRelease) -> Result<()> {
    if release.draft {
        bail!(
            "Refusing update: latest release {} is a draft.",
            release.tag_name
        );
    }
    if release.published_at.is_none() {
        bail!(
            "Refusing update: latest release {} is not published (missing published_at).",
            release.tag_name
        );
    }
    if !release.immutable {
        bail!(
            "Refusing update: latest release {} is not marked immutable by GitHub (immutable=false).",
            release.tag_name
        );
    }
    Ok(())
}

// GitHub's asset digest is used as the first integrity check before we even parse zip contents.
// Currently accept only explicit "sha256:<hex>" digests to avoid algorithm confusion
fn require_asset_sha256_digest_matches_download(
    asset_name: &str,
    asset_digest: &str,
    downloaded_bytes: &[u8],
) -> Result<()> {
    let expected = normalize_hex(asset_digest);

    if !asset_digest
        .trim()
        .to_ascii_lowercase()
        .starts_with("sha256:")
    {
        bail!(
            "Refusing update: asset {} has unsupported digest format {}",
            asset_name,
            asset_digest
        );
    }

    let got = sha256_hex(downloaded_bytes);

    if expected != got {
        bail!(
            "Refusing update: GitHub asset digest mismatch for {}: expected={}, got=sha256:{}",
            asset_name,
            asset_digest,
            got
        );
    }

    Ok(())
}

fn fetch_bytes(client: &Client, url: &str) -> Result<Bytes> {
    Ok(client
        .get(url)
        .header("Accept", "application/octet-stream")
        .send()?
        .error_for_status()?
        .bytes()?)
}

fn zip_root_prefix(zip: &mut ZipArchive<Cursor<Bytes>>) -> Option<String> {
    let mut prefix: Option<String> = None;
    for i in 0..zip.len() {
        let name = match zip.by_index(i) {
            Ok(f) => f.name().to_string(),
            Err(_) => continue,
        };
        let mut parts = name.splitn(2, '/');
        let top = parts.next().unwrap_or("");
        let rest = parts.next();
        if rest.is_none() {
            return None;
        }
        if top.is_empty() {
            return None;
        }
        match &prefix {
            None => prefix = Some(top.to_string()),
            Some(existing) if existing != top => return None,
            _ => {}
        }
    }
    prefix.map(|p| format!("{}/", p))
}

// Reads a file from zip, tolerating both flat layout and single-root-folder layout.
fn read_zip_file(zip: &mut ZipArchive<Cursor<Bytes>>, path: &str) -> Result<Vec<u8>> {
    if let Ok(mut f) = zip.by_name(path) {
        let mut buf = Vec::with_capacity(f.size() as usize);
        f.read_to_end(&mut buf)?;
        return Ok(buf);
    }

    let prefix = zip_root_prefix(zip).ok_or_else(|| anyhow!("zip missing entry {}", path))?;
    let alt = format!("{}{}", prefix, path);
    let mut f = zip
        .by_name(&alt)
        .with_context(|| format!("zip missing entry {} (also tried {})", path, alt))?;
    let mut buf = Vec::with_capacity(f.size() as usize);
    f.read_to_end(&mut buf)?;
    Ok(buf)
}

// fetch the published armored keyring for each git user at https://github.com/<user>.gpg and
// parse all certs/fingerprints. Signature acceptance later requires both cryptographic validity and
// fingerprint membership in this keyset.
fn fetch_github_user_keyring(
    client: &Client,
    user: &str,
    key_base_url: &str,
) -> Result<(Vec<Cert>, HashSet<Fingerprint>)> {
    let url = format!("{}/{}.gpg", key_base_url.trim_end_matches('/'), user);
    let body = client.get(&url).send()?.error_for_status()?.bytes()?;

    let mut certs = Vec::new();
    let mut fps = HashSet::new();

    let mut parser = openpgp::cert::CertParser::from_bytes(&body)?;
    while let Some(cert) = parser.next().transpose()? {
        for ka in cert.keys() {
            fps.insert(ka.key().fingerprint());
        }
        certs.push(cert);
    }

    if certs.is_empty() {
        bail!("No OpenPGP certs found at {}", url);
    }

    Ok((certs, fps))
}

struct Helper {
    certs: Vec<Cert>,
    signer_fprs: Vec<Fingerprint>,
}

impl VerificationHelper for Helper {
    // We provide the full parsed cert set to Sequoia so it can evaluate detached signatures.
    fn get_certs(&mut self, _ids: &[KeyHandle]) -> openpgp::Result<Vec<Cert>> {
        Ok(self.certs.clone())
    }

    // Collect all successful signer fingerprints reported by Sequoia. caller will then enforce
    // that at least one signer fingerprint matches the allowed GitHub keyring for that signer policy.
    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        for layer in structure.iter() {
            if let MessageLayer::SignatureGroup { results } = layer {
                for r in results {
                    if let Ok(GoodChecksum { ka, .. }) = r {
                        self.signer_fprs.push(ka.key().fingerprint());
                    }
                }
            }
        }
        Ok(())
    }
}

// A signature is accepted only if:
// 1) Sequoia validates the detached signature over manifest bytes, and
// 2) at least one reported signing fingerprint belongs to the configured GitHub user's keyring.
// This ties signature validity to explicit signer identity rather than trusting any locally available key.
fn verify_manifest_sig_requires_user(
    manifest: &[u8],
    sig: &[u8],
    certs: &[Cert],
    allowed_fprs: &HashSet<Fingerprint>,
    github_user: &str,
    label: &str,
) -> Result<()> {
    let policy = &StandardPolicy::new();

    let helper = Helper {
        certs: certs.to_vec(),
        signer_fprs: Vec::new(),
    };

    let mut v = DetachedVerifierBuilder::from_bytes(sig)
        .context("Parsing detached signature failed")?
        .with_policy(policy, None, helper)
        .context("Building verifier failed")?;

    v.verify_bytes(manifest)
        .context("Feeding manifest into verifier failed")?;

    let helper = v.into_helper();

    if helper.signer_fprs.is_empty() {
        bail!(
            "Signature verified but no signer fingerprint reported (github_user={}, label={})",
            github_user,
            label
        );
    }

    if helper.signer_fprs.iter().any(|f| allowed_fprs.contains(f)) {
        Ok(())
    } else {
        bail!(
            "Signature verified, but signer fingerprint did not match {}'s GitHub keys (label={})",
            github_user,
            label
        );
    }
}

// lowercase hex SHA-256 helper used for all digest comparisons in this module.
fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let out = h.finalize();

    let mut s = String::with_capacity(out.len() * 2);
    for b in out {
        use std::fmt::Write;
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

// normalizes digest strings that may include a leading "sha256:" prefix.
fn normalize_hex(s: &str) -> String {
    s.trim().trim_start_matches("sha256:").to_ascii_lowercase()
}

// shared by updater/deploy code paths.
pub fn get_current_version(component: Component) -> Result<Version> {
    let p = component.version_file();
    let s =
        fs::read_to_string(&p).with_context(|| format!("reading current version file: {}", p))?;
    Ok(Version::parse(s.trim().trim_start_matches('v'))?)
}

// Writes the installed version marker only after successful install/verification.
pub fn write_current_version(component: Component, v: Version) -> Result<()> {
    let p = component.version_file();

    if let Some(parent) = Path::new(&p).parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating version dir: {}", parent.display()))?;
    }

    fs::write(&p, format!("v{}\n", v))
        .with_context(|| format!("writing current version file: {}", p))?;

    Ok(())
}
