# Secluso Reproducibility Guide

This folder is the release pipeline. It does three things: builds files, writes a manifest with hashes and build details, and compares two runs to check if they match.

If you just want to check a release, you can ignore most internals and do two quick steps: rebuild, then compare your run directory with the official one.

## Fast path: verify one release

Run a build for the same target and profile as the release you are checking:

    ./build.sh --target ipcamera --profile all

Then compare your run output against the official artifact directory:

    ./build.sh --compare ./builds/TIMESTAMP official-binaries

Use the run directory that directly contains manifest.json. Do not point compare at an inner artifacts folder.

When everything matches, the script prints:

    Reproducibility check PASSED

If it does not match, you get explicit mismatch lines such as version mismatch, lock digest mismatch, toolchain digest mismatch, or binary hash mismatch.

<details>
<summary><strong>Don't have an ARM64 machine for Raspberry Pi builds? Click here.</strong></summary>
Unfortunately, not everyone has an ARM64 machine. We wanted to provide a guide for people who don't, so that you're able to verify our builds as well.

There are a couple of ARM64 VPS providers. Most of them require that you do identity verification. One that doesn't, that I've personally tested, is https://servers.guru/arm-vps/. You can get a 2-core 4GB ARM VPS for $7/mo. Note that we are not affiliated with servers.guru whatsoever, and that is not an affiliate link. We like that they provide anonymous payment options and seem to try to respect your privacy. Any ARM64 VPS will work. Another option that's more popular is https://www.hetzner.com/cloud (Ampere option), but they'll likely require you to upload identity verification documents (such as your passport).

Below is a guide instructing how to get everything setup on the VPS and run from scratch.

1. Provision with Ubuntu 24.04
2. Use the credentials from the email to log in. Change your password to something secure after logging in (you will be prompted on the first login)
3. Install the latest Rust (https://www.rust-lang.org/tools/install)
4. Install Docker (https://docs.docker.com/engine/install/ubuntu/)
5. Update the list of available software packages by running `sudo apt-get update`
6. Install the command line utility jq (used for parsing JSON) by running `apt-get install jq`

The following steps assume you are using version v0.1.0. If we have a release after this and have not updated the version number here, please change the version number accordingly.
1. Acquire the code from our latest release: `wget https://github.com/secluso/secluso/archive/refs/tags/v0.1.0.zip` 
2. Unzip the zip file `apt install unzip` then `unzip v0.1.0.zip` (unzips into folder secluso-0.1.0) 
3. Change your directory into the releases folder in the secluso-0.1.0 directory: `cd secluso-0.1.0/releases`
4. Run the build.sh script: `./build.sh` with your preferred arguments, which are detailed in the description below.
5. Fetch our latest release's binary/manifest ZIP file via wget, `wget https://github.com/secluso/secluso/releases/download/v0.1.0/secluso-v0.1.0.zip`  
6. Verify the zip file: `echo "483a2e347bb0cd895e00c2434576849641097e8574ba6ceceb151e009c64e77b  secluso-v0.1.0.zip" | sha256sum -c -`
7. Unzip the zip file: `unzip secluso-v0.1.0.zip -d official-binaries` (unzips into folder official-binaries)
8. Run the compare check: `./build.sh --compare builds/<TIMESTAMP> official-binaries` (replace <TIMESTAMP> with the run folder that contains `manifest.json` and `artifacts/`)

If you see `REPRODUCIBILITY CHECK PASSED`, then you're all set! We do not recommend casually building with this in case your server is compromised, we only recommend using it as a verification against our released binaries.
</details>

## What is pinned, and where

Toolchain image digests are pinned in digests.lock.env in this directory. Current values include:

    RUST_DIGEST__AARCH64_UNKNOWN_LINUX_GNU=4c632e493dfa97f0fe014c3910d1690c149bba85ed8678d47d3563ec6f258ead
    RUST_DIGEST__X86_64_UNKNOWN_LINUX_GNU=3f6e6f8d8725a65a2db964bb828850f888d430c68784d661f753144e5d787207
    RUST_DIGEST__X86_64_APPLE_DARWIN=3f6e6f8d8725a65a2db964bb828850f888d430c68784d661f753144e5d787207
    RUST_DIGEST__AARCH64_APPLE_DARWIN=4c632e493dfa97f0fe014c3910d1690c149bba85ed8678d47d3563ec6f258ead

Rust binary builds run through Docker Buildx with a BuildKit builder pinned to moby/buildkit:v0.23.0. The builder is created for the run and removed when the script exits.

Dependencies are also kept fixed through lockfiles. For Rust crates, each crate lockfile hash is written to the manifest as crate_lock_sha256. In deploy mode, the lock hash is computed from both deploy/src-tauri/Cargo.lock and deploy/pnpm-lock.yaml.

## What build.sh actually does

The entrypoint is build.sh. It has two modes.

Build mode:

    ./build.sh --target TARGET --profile PROFILE

Optional two-run self-check:

    ./build.sh --target TARGET --profile PROFILE --test-reproduce

Compare mode:

    ./build.sh --compare RUN_A RUN_B

A normal build writes to builds/UNIX_TIMESTAMP. A self-check writes two sibling runs at builds/UNIX_TIMESTAMP/run1 and builds/UNIX_TIMESTAMP/run2, then compares them automatically.

Each completed run has this shape:

    RUN_DIR/
      manifest.json
      artifacts/TARGET_TRIPLE/...
      distribution/

The distribution folder includes a verification tarball and a checksum file. You can share that bundle so someone else can run the same compare step.

## Targets and profile map in this script

Targets:
raspberry, ipcamera, server, all, deploy

Profiles currently accepted:

raspberry:
all, core, camerahub, motion_ai_cli

ipcamera:
all, camerahub

server:
server

all:
all, release, test

deploy:
all, linux, macos, windows, linux-x64, linux-arm64, macos-x64, macos-arm64, windows-x64, windows-arm64

Two practical notes from the implementation:

Raspberry-only packages are skipped on non ARM Linux triples.

The all/test profile builds Raspberry core binaries (camera hub, config tool, update) on ARM64 and adds x86_64 config tool only.

Deploy can mix host-native bundling and Docker fallback in the same run, depending on what the local Tauri toolchain can package.

## Manifest contents and why hash is stored

Each artifact entry in manifest.json stores both build info and file hash. Example:

    {
      "package":"ip_camera_hub",
      "target":"x86_64-unknown-linux-gnu",
      "bin":"secluso-ip-camera-hub",
      "bin_path":"artifacts/x86_64-unknown-linux-gnu/secluso-ip-camera-hub",
      "sha256":"...",
      "crate":"camera_hub",
      "version":"...",
      "crate_lock_sha256":"...",
      "rust_digest":"..."
    }

The manifest hash is not trusted on its own. During compare, the script recomputes file hashes from disk and checks them against the manifest first. If a hash in the manifest is fake, compare fails right away with a manifest hash mismatch message.

So the stored hash is a record of what the run says it produced, and runtime hashing is what actually checks it.

## How compare decides pass versus fail

Compare keys are package, target, and binary name. From there, the script checks that the smaller run is fully contained in the larger one.

For each overlapping key, compare checks:

crate name and version
crate lock digest
toolchain digest
manifest hash presence
manifest hash equals on-disk file hash
run A file hash equals run B file hash

Compare is strict byte-for-byte. If file hashes differ, compare fails.

It checks metadata first on purpose, so you can quickly see if the two runs even used the same inputs. If metadata already differs, you are not comparing like-for-like. If metadata matches and the binary hashes still differ, that is the case to treat as a true reproducibility break.

## Deploy specifics you will probably hit

For Apple targets, deploy mode checks which bundle types the local Tauri CLI supports by parsing pnpm tauri build --help.
Non-Apple deploy targets always build in Docker fallback.
Apple deploy targets still require host-native bundling.
Docker Linux deploy builds also perform a single-pass deterministic post-bundle rewrite of wAppImage/deb/rpm outputs so normal one-run builds stay byte-stable. Set SECLUSO_CANONICALIZE_LINUX_BUNDLES=0 to disable.

Apple deploy bundles need host-native support. If the host cannot bundle a requested Apple triple, the run fails with a clear message instead of silently using another path.

Docker fallback logs are preserved per triple under artifacts/TARGET_TRIPLE as:

docker-buildx-TARGET_TRIPLE.log
docker-buildx-TARGET_TRIPLE-summary.log

Those logs are usually the fastest way to debug packaging failures.

## Common failure messages and what they mean

Missing manifest(s) for compare:
One or both compare inputs did not point at a run directory root containing manifest.json.

Larger run does not contain all artifacts of the smaller run:
The superset rule failed, usually because different target/profile scopes were compared.

crate Cargo.lock SHA mismatch:
Dependency lock state differs between runs.

toolchain digest mismatch:
Different toolchain identities were used.

manifest sha256 does not match file:
Run directory mismatch or local file tampering.

binary hash mismatch:
Inputs matched but outputs diverged.

## Limits of what this proves

If compare passes, you can treat it as strong evidence that the binaries match what should come out of that source revision and those build inputs. It still does not prove the source code itself is safe.

One caveat: if someone can rewrite both artifacts and manifest in one untrusted run directory, that directory alone is not a reliable reference point. The check is strongest when at least one side of compare comes from somewhere independent, like an official release bundle or a separate build machine you control.
