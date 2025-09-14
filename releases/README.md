# Secluso — Deterministic, Reproducible Builds

Secluso ships software for many different device classes (Raspberry Pi, IP cameras, x86 servers, ..).  
This repo includes a **deterministic build pipeline** with a **reproducibility checker** so anyone can verify that released artifacts correspond to source.

Note: You must have an ARM64 machine in order to build it yourself with this system. 

---

## Why Reproducible Builds?

- **Trust & security**  
  Reproducible builds allow you (or anyone else) to independently verify that the binaries we distribute are *exactly* what you’d get if you built from the source code in this repository.  
  - Without reproducibility, you’d have to take our word that the binaries match the source. In privacy-sensitive software like Secluso, that’s a big leap of faith: hidden code or malicious alterations could be introduced between source and release without easy detection.  
  - With reproducibility, you don’t need to trust our build environment, our release process, or even us as maintainers. You can rebuild on your own machine, compare the results, and **cryptographically confirm** the binaries are bit-for-bit identical.  
  - This is especially critical for privacy-related devices (like cameras). Verifying reproducibility ensures that the binaries you’re running to protect your home or workplace are free from backdoors, hidden telemetry, or any other logic not visible in the public source.

- **Supply-chain integrity**  
  Our builds are locked to specific versions of compilers, toolchains, and container images. By pinning these to immutable content digests (`sha256:...`), we eliminate the uncertainty of “version drift.”  
  - Normally, even small compiler updates or dependency changes can alter outputs subtly, making verification impossible.  
  - By fixing every input, we ensure that what you (and we) build today is the same as what will be built tomorrow, and the same as what was built last year.  
  - This makes supply-chain attacks (e.g. inserting malicious code into an upstream dependency) much easier to detect.

- **Debuggability & forensics**  
  Being able to reconstruct the exact build environment means bugs can be reproduced exactly as they occurred in the field.  
  - If a customer reports an issue, we can rebuild the exact same binary they are running, ensuring we are debugging the *same* artifact.  
  - This prevents “heisenbugs” caused by mismatches between developer builds and shipped binaries.  
  - For security audits or incident response, reproducibility means investigators can prove what code was actually running.

- **Longevity**  
  Years from now, you can rerun the build pipeline and produce the same outputs.  
  - This protects against “bit rot”, where environments, compilers, or dependencies disappear or change.  
  - For compliance, archival, or academic research, reproducibility means the software remains verifiable long after its release.  
  - Even if the original maintainers are gone, anyone can still prove the integrity of old releases by rebuilding them independently.

Read more about why reproducible builds are so important: [reproducible-builds.org](https://reproducible-builds.org)

---

## Quick Start (Most Common Use Case)

Most users will want to **verify our provided release against their own rebuild**.

1. Download one of our official release builds.
2. Build the matching target/profile locally, for example:  
   `./build.sh --target ipcamera --profile all`
3. Compare your local build against our provided release by passing the build folder that contains `manifest.json`:  
   `./build.sh --compare ./builds/<timestamp> ./release_build`

If everything matches, you’ll see:  
`Reproducibility check PASSED`

Note that you only need to build what you want checked; it'll just check the files that are present in both builds.

---

## Notes on Which Folder to Pass

- For a **normal single build**, pass in the timestamped build directory itself, e.g.:  
  `./builds/1725160000`

- For a **reproducibility self-test (`--test-reproduce`)**, two sub-runs are created:  
  - `./builds/<timestamp>/run1`  
  - `./builds/<timestamp>/run2`  
  Each contains its own `manifest.json`.  
  You should pass one of these run directories to `--compare`.

**Important:** Always pass the directory that directly contains a `manifest.json`, not the per-triple binary folders.

---

## Other Useful Commands

- **Rebuild everything for all devices**  
  `./build.sh --target all --profile all`
- 
- **Rebuild everything for our releases**  
  `./build.sh --target all --profile release`

- **Run a reproducibility self-test (two fresh local builds)**  
  `./build.sh --target raspberry --profile core --test-reproduce`

- **Build only Raspberry Pi camera hub core set**  
  `./build.sh --target raspberry --profile core`

- **Build only Raspberry Pi camera hub**  
  `./build.sh --target raspberry --profile camerahub`

---

## Where to Find Results

- **Binaries**: `builds/<timestamp>/<target-triple>/`  
- **Manifest**: `builds/<timestamp>/manifest.json`  
- **Self-test runs**: `builds/<timestamp>/run1/manifest.json`, `builds/<timestamp>/run2/manifest.json`

### Example Layout (building just the camera hubs)

- builds/1725160000/
  - manifest.json
  - aarch64-unknown-linux-gnu/
    - secluso-raspberry-camera-hub
    - secluso-ip-camera-hub
  - x86_64-unknown-linux-gnu/
    - secluso-ip-camera-hub

---

## How It Works (High Level)

1. **Pinned Rust toolchains (by content digest)**  
   We never rely on floating image tags like `rust:latest`, which can change silently over time. Instead:  
   - Each Rust target triple (e.g. `aarch64-unknown-linux-gnu`) has its own `sha256`-pinned Rust builder image digest recorded in `digests.lock.env`.  
   - This guarantees that the compiler, linker, and toolchain versions are **exactly** the same across builds, regardless of when or where they’re run.  
   - By pinning to immutable digests, we remove uncertainty about “version drift” and ensure long-term reproducibility.

2. **Ephemeral BuildKit builders (containerized & version-pinned)**  
   We build using Docker Buildx with a containerized BuildKit backend:  
   - At the start of a run, the script creates a new BuildKit builder, pinned to `moby/buildkit:v0.23.0`.  
   - All builds for that run (across all targets and packages) share the same builder.  
   - When the script exits, the builder is destroyed along with its cache.  
   - This ensures:  
     - Builds run in a **clean, isolated environment** for the duration of the pipeline.  
     - No contamination from host config or previous runs.  
     - Disk usage stays controlled, since caches don’t accumulate indefinitely across builds.  

3. **Machine-readable build manifests**  
   After a build finishes, we generate a `manifest.json` alongside the binaries. This manifest describes exactly what was built and with what inputs:  
   - `package`, `target`, `bin`, `bin_path` -> identify which binary belongs to which package and target triple.  
   - `crate`, `version` -> the source crate name and version (queried with `cargo metadata`).  
   - `crate_lock_sha256` -> the SHA-256 hash of the crate’s `Cargo.lock`, ensuring dependencies resolved identically.  
   - `rust_digest` -> the pinned Rust compiler container digest used during the build.  
   **Important:** We deliberately do **not** store the final binary hashes in the manifest. Instead, they are computed at comparison time to reduce surface area and keep manifests focused on build inputs.

4. **Reproducibility checker**  
   To prove two builds are identical, we use the `compare_runs` function:  
   - It enforces a **superset rule**: if one build produced fewer artifacts than the other, the smaller set must still exist entirely within the larger set.  
   - It compares metadata fields (`crate`, `version`, `crate_lock_sha256`, `rust_digest`) to ensure inputs truly match.  
   - Finally, it computes SHA-256 checksums of the binaries themselves on the fly, confirming that outputs are **bit-for-bit identical**.  
   - If everything matches, the tool prints:  
     `Reproducibility check PASSED`  
   - If not, it highlights mismatches (different versions, differing lockfile hashes, missing artifacts, or binary hash mismatches) so you can pinpoint exactly why a build diverged.

---

## Terminology: “Target Triples”

Rust **target triples** identify the compilation target: `arch-vendor-os-abi`.

- `aarch64-unknown-linux-gnu`: ARM64, Linux, GNU libc  
- `x86_64-unknown-linux-gnu`: x86_64, Linux, GNU libc

Secluso currently uses:

| Target | Triples                                   |
|--------|-------------------------------------------|
| raspberry | aarch64-unknown-linux-gnu                 |
| ipcamera | x86_64-unknown-linux-gnu, aarch64-unknown-linux-gnu |
| all    | both of the above                         |

---

## What Gets Built

**Profiles** map to sets of packages (crates) and features:

- raspberry
  - `all`: update, reset, raspberry_camera_hub, config_tool
  - `core`: raspberry_camera_hub, reset, update
  - `camerahub`: raspberry_camera_hub
- ipcamera
  - `all`: ip_camera_hub, config_tool, server
  - `camerahub`: ip_camera_hub
  
- all
  - `all`: all of the above for both architectures
  - `release`: only the packages that we distribute in releases

**Package -> crate/feature mapping** (done in the script):

- `raspberry_camera_hub` → crate camera_hub with `--features raspberry`
- `ip_camera_hub` → crate camera_hub with `--features ip`

Raspberry-only tools (`raspberry_camera_hub`, `reset`, `update`) are **skipped** for non-ARM64 triples.
