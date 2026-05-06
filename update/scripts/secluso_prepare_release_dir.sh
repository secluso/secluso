#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<EOF
Usage:
  $0 --tag vX.Y.Z --workdir ./release_work --artifact-dir /path/to/builder_out

What it does (manager step):
- copies the builder's manifest.json into <workdir>/<tag>/manifest.json (no rewriting)
- writes <workdir>/<tag>/manifest.sha256 (sha256 of manifest.json)
- prints what to review before bundling

Notes:
- The builder is the source of truth for manifest.json.
- This script does NOT generate any manifest fields.
EOF
  exit 1
}

TAG=""
WORKDIR=""
LABELS=""
ARTIFACT_DIR=""
MANIFEST_NAME="manifest.json"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag) TAG="$2"; shift 2;;
    --workdir) WORKDIR="$2"; shift 2;;
    --artifact-dir) ARTIFACT_DIR="$2"; shift 2;;
    --manifest-name) MANIFEST_NAME="$2"; shift 2;;
    -h|--help) usage;;
    *) echo "Unknown arg: $1" >&2; usage;;
  esac
done

[[ -n "$TAG" && -n "$WORKDIR" && -n "$ARTIFACT_DIR" ]] || usage
[[ -d "$ARTIFACT_DIR" ]] || { echo "Missing --artifact-dir directory: $ARTIFACT_DIR" >&2; exit 1; }

SRC_MANIFEST="$ARTIFACT_DIR/$MANIFEST_NAME"
[[ -f "$SRC_MANIFEST" ]] || { echo "--artifact-dir must contain $MANIFEST_NAME (missing: $SRC_MANIFEST)" >&2; exit 1; }

REL_DIR="$WORKDIR/$TAG"
mkdir -p "$REL_DIR"

DEST_MANIFEST="$REL_DIR/manifest.json"
SHA_FILE="$REL_DIR/manifest.sha256"

# Copy manifest exactly as produced by builder
cp -f "$SRC_MANIFEST" "$DEST_MANIFEST"

hash_file() {
  local f="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$f" | awk '{print $1}'
  else
    shasum -a 256 "$f" | awk '{print $1}'
  fi
}

SHA="$(hash_file "$DEST_MANIFEST")"
echo "$SHA  manifest.json" > "$SHA_FILE"

echo "Prepared release dir: $REL_DIR"
echo "Copied manifest from: $SRC_MANIFEST"
echo "Manifest: $DEST_MANIFEST"
echo "SHA256: $SHA"
echo
echo "Review these before building the release bundle:"
echo " - $DEST_MANIFEST"
echo " - $SHA_FILE"
