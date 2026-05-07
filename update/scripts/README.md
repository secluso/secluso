# Secluso release scripts — simple + real-world

These scripts build the zip you upload to GitHub Releases:

- secluso-runtime-vX.Y.Z.zip
- secluso-vX.Y.Z-sha256sums.txt
- secluso-vX.Y.Z-sha256sums.txt.<labelA>.asc
- secluso-vX.Y.Z-sha256sums.txt.<labelB>.asc

That zip contains:
- manifest.json
- binaries under artifacts/, like:
- artifacts/aarch64-unknown-linux-gnu/...
- artifacts/x86_64-unknown-linux-gnu/...

Updater does as follows...
- downloads the top-level secluso-vX.Y.Z-sha256sums.txt release asset
- downloads and verifies the top-level .asc signatures over that checksum file
- downloads the zip and checks its sha256 against the signed checksum file
- picks one binary (based on input), checks its sha256 against manifest.json inside the authenticated zip
- installs that one binary into the designated root subdirectory

---

## Real release (2 people sign, manual upload)

### Step 0 - Build artifacts (Docker builder)

Should end up with a folder like:

- /path/to/builder_out/
- manifest.json
- aarch64-unknown-linux-gnu/...
- x86_64-unknown-linux-gnu/...

This whole folder is your artifact dir (passed as --artifact-dir).

### Step 1 - Manager preps the manifest

We copy builder manifest.json into the release_work folder and write a manifest.sha256 for human sanity checks.

Run:
- ./secluso_prepare_release_dir.sh --tag v0.4.0 --workdir ./release_work --artifact-dir /path/to/builder_out

This creates:
- ./release_work/v0.4.0/manifest.json (copied from builder_out/manifest.json, unchanged)
- ./release_work/v0.4.0/manifest.sha256 (sha256 of manifest.json)

Review both files before building the final bundle:
- ./release_work/v0.4.0/manifest.json
- ./release_work/v0.4.0/manifest.sha256

### Step 2 - Manager builds the release zip and checksum file

Run:
- ./secluso_build_bundle.sh --tag v0.4.0 --workdir ./release_work --artifact-dir /path/to/builder_out --release-assets-dir /path/to/top_level_release_assets

Outputs:
- ./release_work/v0.4.0/out/secluso-runtime-v0.4.0.zip
- ./release_work/v0.4.0/out/secluso-v0.4.0-sha256sums.txt

The checksum file always includes the runtime zip and, when present in `--release-assets-dir`, this predefined top-level release set:
- Secluso-Deploy-0.4.0-macos-arm64.app.zip
- Secluso-Deploy-0.4.0-linux-arm64.AppImage
- Secluso-Deploy-0.4.0-linux-x64.AppImage
- Secluso-Deploy-0.4.0-windows-x64-setup.exe
- secluso-pi-image-v0.4.0.wic

### Step 3 - Sign the checksum file

Signer A runs:
- ./secluso_sign_checksums.sh --checksums ./release_work/v0.4.0/out/secluso-v0.4.0-sha256sums.txt --label jkaczman --key <YOUR_KEY_FPR> --outdir ./release_work/v0.4.0/out

Signer B runs:
- ./secluso_sign_checksums.sh --checksums ./release_work/v0.4.0/out/secluso-v0.4.0-sha256sums.txt --label arrdalan --key <YOUR_KEY_FPR> --outdir ./release_work/v0.4.0/out

### Step 4 - Upload manually

- GitHub -> Releases -> Draft new release
- tag v0.4.0
- upload secluso-runtime-v0.4.0.zip
- upload Secluso-Deploy-0.4.0-macos-arm64.app.zip
- upload Secluso-Deploy-0.4.0-linux-arm64.AppImage
- upload Secluso-Deploy-0.4.0-linux-x64.AppImage
- upload Secluso-Deploy-0.4.0-windows-x64-setup.exe
- upload secluso-pi-image-v0.4.0.wic
- upload secluso-v0.4.0-sha256sums.txt
- upload secluso-v0.4.0-sha256sums.txt.jkaczman.asc
- upload secluso-v0.4.0-sha256sums.txt.arrdalan.asc
- publish
