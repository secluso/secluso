#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<EOF
Usage:
  $0 --checksums /path/to/secluso-vX.Y.Z-sha256sums.txt \\
     --label LABEL --key KEYID_OR_FPR --outdir /path/to/output

Produces:
  <outdir>/secluso-vX.Y.Z-sha256sums.txt.<label>.asc

LABEL must match the updater's --sig-key label.
EOF
  exit 1
}

CHECKSUMS=""
LABEL=""
KEY=""
OUTDIR=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --checksums) CHECKSUMS="$2"; shift 2;;
    --label) LABEL="$2"; shift 2;;
    --key) KEY="$2"; shift 2;;
    --outdir) OUTDIR="$2"; shift 2;;
    -h|--help) usage;;
    *) echo "Unknown arg: $1" >&2; usage;;
  esac
done

[[ -n "$CHECKSUMS" && -n "$LABEL" && -n "$KEY" && -n "$OUTDIR" ]] || usage
[[ -f "$CHECKSUMS" ]] || { echo "Missing checksums file: $CHECKSUMS" >&2; exit 1; }

mkdir -p "$OUTDIR"
OUTSIG="$OUTDIR/$(basename "$CHECKSUMS").${LABEL}.asc"

echo "Signing checksum file..."
gpg --batch --yes --armor --detach-sign --local-user "$KEY" \
  -o "$OUTSIG" "$CHECKSUMS"

echo "Created signature: $OUTSIG"
