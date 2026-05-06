#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<EOF
Usage (artifact bundle only):
  $0 --tag vX.Y.Z --workdir ./release_work --artifact-dir /path/to/builder_bundle_dir \\
     [--release-assets-dir /path/to/top_level_release_assets]

Outputs:
  <workdir>/<tag>/bundle/
  <workdir>/<tag>/out/secluso-runtime-<tag>.zip
  <workdir>/<tag>/out/secluso-runtime-<tag>-sha256sums.txt
EOF
  exit 1
}

TAG=""
WORKDIR=""
ARTIFACT_DIR=""
RELEASE_ASSETS_DIR=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag) TAG="$2"; shift 2;;
    --workdir) WORKDIR="$2"; shift 2;;
    --artifact-dir) ARTIFACT_DIR="$2"; shift 2;;
    --release-assets-dir) RELEASE_ASSETS_DIR="$2"; shift 2;;
    -h|--help) usage;;
    *) echo "Unknown arg: $1" >&2; usage;;
  esac
done

[[ -n "$TAG" && -n "$WORKDIR" && -n "$ARTIFACT_DIR" ]] || usage

REL_DIR="$WORKDIR/$TAG"
MANIFEST="$REL_DIR/manifest.json"

[[ -f "$MANIFEST" ]] || { echo "Missing manifest: $MANIFEST" >&2; exit 1; }
[[ -d "$ARTIFACT_DIR" ]] || { echo "Missing --artifact-dir directory: $ARTIFACT_DIR" >&2; exit 1; }
[[ -f "$ARTIFACT_DIR/manifest.json" ]] || { echo "--artifact-dir must contain manifest.json" >&2; exit 1; }

hash_file() {
  local f="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$f" | awk '{print $1}'
  else
    shasum -a 256 "$f" | awk '{print $1}'
  fi
}

BUNDLE_DIR="$REL_DIR/bundle"
OUT_DIR="$REL_DIR/out"
rm -rf "$BUNDLE_DIR"
mkdir -p "$BUNDLE_DIR" "$OUT_DIR"

if [[ -z "$RELEASE_ASSETS_DIR" ]]; then
  RELEASE_ASSETS_DIR="$OUT_DIR"
fi
[[ -d "$RELEASE_ASSETS_DIR" ]] || { echo "Missing --release-assets-dir directory: $RELEASE_ASSETS_DIR" >&2; exit 1; }

echo "Copying builder artifacts from: $ARTIFACT_DIR"
cp -a "$ARTIFACT_DIR/." "$BUNDLE_DIR/"

# Overwrite manifest.json with the reviewed one
cp "$MANIFEST" "$BUNDLE_DIR/manifest.json"

# Enforce manifest sha256 matches the actual bundle bytes
if command -v jq >/dev/null 2>&1; then
  echo "Checking manifest sha256 fields vs bundle contents..."

  jq -r '.artifacts[] | @base64' "$BUNDLE_DIR/manifest.json" | while read -r row; do
    _jq() { echo "$row" | base64 --decode | jq -r "$1"; }

    bin_path="$(_jq '.bin_path')"
    sha="$(_jq '.sha256')"

    if [[ -z "$bin_path" || "$bin_path" == "null" ]]; then
      echo "ERROR: artifact missing bin_path" >&2
      exit 1
    fi
    if [[ -z "$sha" || "$sha" == "null" ]]; then
      echo "ERROR: artifact $bin_path missing sha256 field in manifest.json" >&2
      exit 1
    fi

    f="$BUNDLE_DIR/$bin_path"
    if [[ ! -f "$f" ]]; then
      echo "ERROR: manifest references missing file: $bin_path" >&2
      exit 1
    fi

    got="$(hash_file "$f")"
    want="$(echo "$sha" | tr -d ' \t\r\n' | sed 's/^sha256://I' | tr 'A-F' 'a-f')"

    if [[ "$got" != "$want" ]]; then
      echo "ERROR: sha256 mismatch for $bin_path" >&2
      echo "  manifest: $want" >&2
      echo "  actual:   $got" >&2
      exit 1
    fi
  done

  echo "OK: manifest sha256 matches all artifact files"
else
  echo "WARN: jq not found, skipping manifest sha256 verification"
fi

# Compute an absolute output path because we run zip from inside BUNDLE_DIR.
# Using a relative path here would be resolved from BUNDLE_DIR and can point to
# a non-existent nested location.
ABS_OUT_DIR="$(cd "$OUT_DIR" && pwd)"
ZIP_PATH="$ABS_OUT_DIR/secluso-runtime-${TAG}.zip"
SUMS_PATH="$ABS_OUT_DIR/secluso-runtime-${TAG}-sha256sums.txt"
rm -f "$ZIP_PATH"
rm -f "$SUMS_PATH"

( cd "$BUNDLE_DIR" && zip -qr "$ZIP_PATH" . )

VERSION="${TAG#v}"
RELEASE_ASSET_NAMES=(
  "Secluso-Deploy-${VERSION}-macos-arm64.app.zip"
  "Secluso-Deploy-${VERSION}-linux-arm64.AppImage"
  "Secluso-Deploy-${VERSION}-linux-x64.AppImage"
  "Secluso-Deploy-${VERSION}-windows-x64-setup.exe"
  "secluso-pi-image-${TAG}.img.xz"
)

{
  zip_name="$(basename "$ZIP_PATH")"
  printf '%s  %s\n' "$(hash_file "$ZIP_PATH")" "$zip_name"
  for asset_name in "${RELEASE_ASSET_NAMES[@]}"; do
    asset_path="$RELEASE_ASSETS_DIR/$asset_name"
    if [[ -f "$asset_path" ]]; then
      printf '%s  %s\n' "$(hash_file "$asset_path")" "$asset_name"
    else
      echo "WARN: predefined release asset not found, skipping checksum entry: $asset_name" >&2
    fi
  done
} > "$SUMS_PATH"

echo
echo "Bundle folder: $BUNDLE_DIR"
echo "Zip asset: $ZIP_PATH"
echo "Checksum asset: $SUMS_PATH"
echo "Upload the zip, checksum file, and checksum signatures as Release assets in GitHub UI."
