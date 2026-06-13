#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Manual Secluso relay installer.
#
# NOTE: If you do not wish to use a manual installer, the Deploy Tool can take care of this with ease and does not require terminal usage.
#
# Benefit of this: runs directly ON the target server; more or less secluso-deploy but without SSH (doesn't require SSH credentials)
# Fetches the latest immutable release, verifies checksums against the signers' GitHub-published GPG keys, and verifies the bundle and manifest hashes.
# Then generates user credentials, installs the binaries and systemd units, and pauses so you can test public reachability before finishing.
#
# Usage:
#   sudo ./secluso_manual_relay_install.sh --server-url https://example.com [options]
#
# Options:
#   --server-url URL        Public URL of this relay (required), e.g. https://cam.example.com OR http://1.2.3.4:8000 (or other port)
#   --port N                Listen port (default: 8000)
#   --service-account-key P Path to FCM service_account_key.json (optional). UnifiedPush is always an option. Don't need to use this.
#   --output-dir DIR        Where to save credentials + pairing QR (default: ./secluso-credentials)
#   --overwrite             Replace an existing install (required if one exists already)
#   --no-updater            Do not enable the auto-updater service

# https://gist.github.com/akrasic/380bda362e0420be08709152c91ca1f9
set -euo pipefail

# Binaries => /usr/bin, all runtime state => /var/lib/secluso
INSTALL_BIN_DIR="/usr/bin"
STATE_DIR="/var/lib/secluso"
VERSION_ROOT="$STATE_DIR/current_version"
SERVICE_USER="secluso"
SERVER_UNIT="secluso-server.service"
UPDATER_SERVICE="secluso-updater.service"
UPDATE_INTERVAL_SECS=1800
HINT_CHECK_INTERVAL_SECS=60
OWNER_REPO="secluso/secluso"

# Two pinned release signers (the maintainers of Secluso)
# Every release checksum file must carry a valid detached signature from BOTH of them before anything from the release is trusted.
# The fingerprints pin each signer to one exact OpenPGP primary key
# Means a compromised GitHub account cannot simply publish a new key and re-sign.
SIG_KEYS=(
  "jkaczman:jkaczman:7785755F1A24FF04CE0E12575DF5E79230C57C4A"
  "arrdalan:arrdalan:1A9A1BA3090FA78E946DC0C0301497925DCCE876"
)

SERVER_URL=""
LISTEN_PORT=8000
EXPOSURE=""
BIND_ADDRESS=""
SERVICE_ACCOUNT_KEY=""
OUTPUT_DIR="$PWD/secluso-credentials"
OVERWRITE=0
ENABLE_UPDATER=1

# Taken from https://gist.github.com/rene-d/9e584a7dd2935d0f461904b9f2950007
info() { printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --server-url) SERVER_URL="$2"; shift 2 ;;
    --port) LISTEN_PORT="$2"; shift 2 ;;
    --service-account-key) SERVICE_ACCOUNT_KEY="$2"; shift 2 ;;
    --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
    --overwrite) OVERWRITE=1; shift ;;
    --no-updater) ENABLE_UPDATER=0; shift ;;
    -h|--help) sed -n '4,21p' "$0"; exit 0 ;;
    *) die "Unknown option: $1 (see --help)" ;;
  esac
done

# Validate and normalize the user-supplied configuration before doing any work.
# The server URL is required because it gets put in the generated credentials that the mobile app scans.
[[ -n "$SERVER_URL" ]] || die "--server-url is required"
[[ "$SERVER_URL" =~ ^https?:// ]] || die "Invalid server URL scheme (need http:// or https://)"
SERVER_URL="${SERVER_URL%/}"

# stdin may be a pipe if the script was fetched and run in one go, so interactive prompts read from the controlling terminal when available.
PROMPT_IN=/dev/stdin
[[ -t 0 ]] || { [[ -r /dev/tty ]] && PROMPT_IN=/dev/tty; }

# Ask how the relay is exposed to the internet...
# Direct exposure means the Secluso server itself listens publicly, so it binds all interfaces and the public URL must point at the listen port.
# Proxy mode means a reverse proxy (e.g. nginx, caddy, etc.) forwards to the server on loopback, so the server binds 127.0.0.1
echo "How is this relay exposed to the internet?"
echo "  1) direct - the Secluso server itself listens publicly (your URL must include the port, e.g. http://1.2.3.4:$LISTEN_PORT)"
echo "  2) proxy  - a reverse proxy terminates TLS at $SERVER_URL and forwards to 127.0.0.1:$LISTEN_PORT"
while true; do
  printf 'Choose [1/2]: '
  read -r choice < "$PROMPT_IN" || die "No exposure mode chosen"
  case "$choice" in
    1|direct) EXPOSURE="direct"; break ;;
    2|proxy)  EXPOSURE="proxy"; break ;;
  esac
done

# In direct mode the public URL and the listen port have to agree, because clients connect straight to the URL
# The port is extracted from the URL, falling back to the scheme default of 80 for http or 443 for https when the URL has no explicit port.
# Ports below 1024 are also rejected in direct mode (the server runs as an unprivileged user that cannot bind them)
if [[ "$EXPOSURE" == "direct" ]]; then
  hostport="${SERVER_URL#*://}"
  hostport="${hostport%%/*}"
  url_port="${hostport##*:}"
  if [[ "$url_port" == "$hostport" ]]; then
    [[ "$SERVER_URL" == https://* ]] && url_port=443 || url_port=80
  fi
  if [[ "$url_port" != "$LISTEN_PORT" ]]; then
    die "Direct exposure, but the server URL points at port $url_port while the relay listens on $LISTEN_PORT. Use --server-url with the port included (e.g. ${SERVER_URL}:$LISTEN_PORT), pass --port $url_port, or choose proxy mode."
  fi
  if (( LISTEN_PORT < 1024 )); then
    die "Direct exposure on port $LISTEN_PORT is not supported because the server runs as an unprivileged user. Use a port >= 1024 or put a reverse proxy in front (proxy mode)."
  fi
fi

# Set bind address based on exposure (discussed in above comments)
if [[ -z "$BIND_ADDRESS" ]]; then
  if [[ "$EXPOSURE" == "direct" ]]; then
    BIND_ADDRESS="0.0.0.0"
  elif [[ "$EXPOSURE" == "proxy" ]]; then
    BIND_ADDRESS="127.0.0.1"
  fi
fi


# We need root (directly or via sudo) for package installs, service user creation, and systemd management.
# We require systemd because we use systemd units, and apt because dependencies are installed with apt-get.
# Strictly x86_64 and aarch64; those are the only targets the release bundle has server binaries for
if [[ $EUID -eq 0 ]]; then
  SUDO=""
else
  command -v sudo >/dev/null 2>&1 || die "Run as root or install sudo"
  SUDO="sudo"
fi

[[ -d /run/systemd/system ]] || die "systemd is required"
command -v apt-get >/dev/null 2>&1 || die "apt-get is required (Debian/Ubuntu server expected)"

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64) TARGET="x86_64-unknown-linux-gnu" ;;
  aarch64|arm64) ARCH="aarch64"; TARGET="aarch64-unknown-linux-gnu" ;;
  *) die "Unsupported architecture: $ARCH (need x86_64 or aarch64)" ;;
esac
info "Architecture: $ARCH"

# Detect any existing Secluso install exactly like the deploy tool's detect step does.
# The deploy tool refuses to provision over an existing install unless overwrite is explicitly enabled (a manual half-update could desync the binaries from the state directory)
# Same here. Either there is no install, or the user passed --overwrite to replace it
# A port collision from something other than Secluso is only a warning (user may intend to stop that service themselves)
REMOTE_HAS_BIN=0; [[ -x "$INSTALL_BIN_DIR/secluso-server" ]] && REMOTE_HAS_BIN=1
REMOTE_HAS_UNIT=0; [[ -f "/etc/systemd/system/$SERVER_UNIT" ]] && REMOTE_HAS_UNIT=1
if [[ $REMOTE_HAS_BIN -eq 1 || $REMOTE_HAS_UNIT -eq 1 ]]; then
  if [[ $OVERWRITE -ne 1 ]]; then
    die "Existing Secluso install detected. Re-run with --overwrite to replace it cleanly."
  fi
fi

if command -v ss >/dev/null 2>&1; then
  if ss -ltn "( sport = :$LISTEN_PORT )" 2>/dev/null | grep -q LISTEN && [[ $REMOTE_HAS_UNIT -ne 1 ]]; then
    warn "Port $LISTEN_PORT is already in use by something other than Secluso."
  fi
fi

# Install everything this script needs plus the runtime dependencies the server needs
# runtime: ca-certificates and libssl-dev
# release fetching / verif: curl, jq, unzip, and gnupg
# qrencode to generate credentails (doesn't rely on the config tool Rust code for simplicity)
# TODO: Why are the generated QRs from qrencode so much smaller, yet they have the same content?
info "Installing dependencies (apt-get)..."
${SUDO} apt-get update -qq
${SUDO} apt-get install -y -qq --no-install-recommends \
  ca-certificates curl jq unzip gnupg libssl-dev qrencode

# All downloads, keyrings, extracted artifacts, and generated secrets go in a private tmp dir
# Created mode 700 so other local users cannot read staged credentials, and it is removed on exit (whether the install succeeds or fails)
WORK="$(mktemp -d /tmp/secluso-manual-install.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
chmod 700 "$WORK"

# 1) Fetch the latest release metadata from the GitHub API.
# 2) Release must be published, must not be a draft, and must be marked immutable by GitHub.
gh_api() { curl -fsSL --retry 3 -H "Accept: application/vnd.github+json" "$1"; }

info "Fetching latest release metadata for $OWNER_REPO..."
RELEASE_JSON="$WORK/release.json"
gh_api "https://api.github.com/repos/$OWNER_REPO/releases/latest" > "$RELEASE_JSON"

RELEASE_TAG="$(jq -r '.tag_name' "$RELEASE_JSON")"
VERSION="${RELEASE_TAG#v}"
[[ "$(jq -r '.draft' "$RELEASE_JSON")" == "false" ]] || die "Latest release $RELEASE_TAG is a draft"
[[ "$(jq -r '.published_at // empty' "$RELEASE_JSON")" != "" ]] || die "Latest release $RELEASE_TAG is not published"
[[ "$(jq -r '.immutable // false' "$RELEASE_JSON")" == "true" ]] || die "Latest release $RELEASE_TAG is not marked immutable by GitHub"
info "Latest immutable release: $RELEASE_TAG"

# Locate the runtime bundle zip among the release assets and derive the checksum file name from it.
# secluso-runtime-vX.Y.Z.zip => secluso-vX.Y.Z-sha256sums.txt
# 2 required signers (john and ardalan) have signature files named secluso-vX.Y.Z-sha256sums.txt.<label>.asc
BUNDLE_NAME="$(jq -r '.assets[].name | select(startswith("secluso-runtime-v") and endswith(".zip"))' "$RELEASE_JSON" | head -n1)"
[[ -n "$BUNDLE_NAME" ]] || die "Could not find runtime bundle zip asset in latest release"
CHECKSUMS_NAME="secluso-${BUNDLE_NAME#secluso-runtime-}"
CHECKSUMS_NAME="${CHECKSUMS_NAME%.zip}-sha256sums.txt"

asset_url()    { jq -r --arg n "$1" '.assets[] | select(.name == $n) | .browser_download_url' "$RELEASE_JSON"; }
asset_digest() { jq -r --arg n "$1" '.assets[] | select(.name == $n) | .digest // empty' "$RELEASE_JSON"; }

# Download a release asset and verify it against the digest GitHub records
# GitHub publishes a digest for every release asset through API, and the updater checks it before any signature work
fetch_asset() {
  local name="$1" out="$2" url digest got
  url="$(asset_url "$name")"
  [[ -n "$url" ]] || die "Could not find release asset $name"
  digest="$(asset_digest "$name")"
  [[ "$digest" == sha256:* ]] || die "Asset $name has unsupported digest format: ${digest:-<missing>}"
  info "Downloading $name..."
  curl -fsSL --retry 3 -H "Accept: application/octet-stream" -o "$out" "$url"
  got="$(sha256sum "$out" | awk '{print $1}')"
  [[ "$got" == "${digest#sha256:}" ]] || die "GitHub asset digest mismatch for $name"
}

fetch_asset "$BUNDLE_NAME" "$WORK/$BUNDLE_NAME"
fetch_asset "$CHECKSUMS_NAME" "$WORK/$CHECKSUMS_NAME"

# Verify each required signer's detached signature over the checksum file.
# Key material trusted here is https://github.com/<user>.gpg, which ties signature validity to a live GitHub identity
# Fresh isolated GnuPG home so keyrings cannot contaminate each other between iterations
# Pinned fingerprint must exist in the fetched keyring
# VALIDSIG status line is parsed and its last field, which is the primary key fingerprint of the signing certificate, must equal the pinned fingerprint.
for entry in "${SIG_KEYS[@]}"; do
  IFS=':' read -r label gh_user pin <<< "$entry"
  sig_name="$CHECKSUMS_NAME.$label.asc"
  fetch_asset "$sig_name" "$WORK/$sig_name"

  info "Verifying signature from $gh_user (label=$label)..."
  keyring="$WORK/$gh_user.gpg"
  curl -fsSL --retry 3 "https://github.com/$gh_user.gpg" -o "$keyring"
  export GNUPGHOME="$WORK/gnupg-$label"
  mkdir -m 700 "$GNUPGHOME"
  gpg --quiet --import "$keyring" 2>/dev/null
  gpg --with-colons --list-keys 2>/dev/null | awk -F: '/^fpr:/ {print $10}' | grep -qx "$pin" \
    || die "Pinned fingerprint $pin was not found in $gh_user's GitHub keyring"

  status="$WORK/gpg-status-$label"
  gpg --status-file "$status" --verify "$WORK/$sig_name" "$WORK/$CHECKSUMS_NAME" 2>/dev/null \
    || die "Signature verification failed for $CHECKSUMS_NAME (label=$label)"
  primary_fpr="$(awk '/^\[GNUPG:\] VALIDSIG/ {print $NF}' "$status" | head -n1)"
  [[ "$primary_fpr" == "$pin" ]] || die "Signer fingerprint ${primary_fpr:-<none>} does not match pinned $pin (label=$label)"
  unset GNUPGHOME
done
info "All required signatures verified."

# Now that the checksum file is authenticated by both signers, use it to verify the bundle zip itself.
# Transitively... If the zip hash matches, every file inside the zip is considered authenticated.
expected_zip_sha="$(awk -v f="$BUNDLE_NAME" '$2 == f || $2 == "*"f || $2 == "./"f {print $1}' "$WORK/$CHECKSUMS_NAME" | head -n1)"
[[ -n "$expected_zip_sha" ]] || die "Checksum file missing entry for $BUNDLE_NAME"
got_zip_sha="$(sha256sum "$WORK/$BUNDLE_NAME" | awk '{print $1}')"
[[ "$got_zip_sha" == "$expected_zip_sha" ]] || die "sha256 mismatch for $BUNDLE_NAME"

# Extract the verified bundle and cross-check its manifest.
# Every artifact entry in manifest.json must carry a version equal to the release tag (guards against a bundle assembled from mismatched builds)
# Each binary we are about to install is then hashed and compared against its manifest entry.
info "Extracting verified bundle..."
EXTRACT="$WORK/bundle"
mkdir "$EXTRACT"
unzip -qq "$WORK/$BUNDLE_NAME" -d "$EXTRACT"
if [[ ! -f "$EXTRACT/manifest.json" ]]; then
  root="$(find "$EXTRACT" -mindepth 1 -maxdepth 1 -type d | head -n1)"
  [[ -n "$root" && -f "$root/manifest.json" ]] || die "Bundle missing manifest.json"
  EXTRACT="$root"
fi

MANIFEST="$EXTRACT/manifest.json"
bad_version="$(jq -r --arg v "$VERSION" '[.artifacts[] | select((.version | gsub("^\\s+|\\s+$"; "")) != $v)] | length' "$MANIFEST")"
[[ "$bad_version" == "0" ]] || die "Manifest artifacts contain a version that doesn't match release tag $RELEASE_TAG"

verify_artifact() {
  local rel="artifacts/$TARGET/$1" expected got
  expected="$(jq -r --arg p "artifacts/$TARGET/$1" '.artifacts[] | select(.bin_path == $p) | .sha256' "$MANIFEST" | tr '[:upper:]' '[:lower:]')"
  [[ -n "$expected" && "$expected" != "null" ]] || die "Manifest missing artifact entry for $rel"
  [[ -f "$EXTRACT/$rel" ]] || die "Bundle missing $rel"
  got="$(sha256sum "$EXTRACT/$rel" | awk '{print $1}')"
  [[ "$got" == "${expected#sha256:}" ]] || die "sha256 mismatch for $rel"
}
verify_artifact secluso-server
verify_artifact secluso-update
SERVER_BIN="$EXTRACT/artifacts/$TARGET/secluso-server"
UPDATER_BIN="$EXTRACT/artifacts/$TARGET/secluso-update"
info "Bundle $RELEASE_TAG verified for $ARCH."

# Reproduce what config_tool does here w/o Rust.
# Randomness comes from /dev/urandom filtered through tr, which is rejection sampling and therefore uniform over the charset.
CRED_CHARSET='A-Za-z0-9!@#$%^&*()_=+[]{}|;,.<>?-'
random_chars() {
  local n="$1" pool
  pool="$(head -c 4096 /dev/urandom | LC_ALL=C tr -dc "$CRED_CHARSET")"
  [[ ${#pool} -ge $n ]] || die "Not enough random characters generated"
  printf '%s' "${pool:0:$n}"
}

info "Generating user credentials..."
CREDS_DIR="$WORK/credentials"
mkdir -m 700 "$CREDS_DIR"
USERNAME="$(random_chars 14)"
PASSWORD="$(random_chars 14)"

# Bare 28 character concatenation with no trailing newline.
printf '%s%s' "$USERNAME" "$PASSWORD" > "$CREDS_DIR/user_credentials"

# Reproduced byte-for-byte: version, username, password, server address
printf '{"v":"uc-v1.0","u":"%s","p":"%s","sa":"%s"}' "$USERNAME" "$PASSWORD" "$SERVER_URL" \
  > "$CREDS_DIR/credentials_full"

# The mobile app pairs by scanning a QR code of credentials_full
# Render the JSON file into a PNG (mimic config tool)
qrencode -l M -o "$CREDS_DIR/user_credentials_qrcode.png" -r "$CREDS_DIR/credentials_full"
printf '%s%s%s' "$USERNAME" "$PASSWORD" "$SERVER_URL" > "$CREDS_DIR/user_credentials_for_testing"

# Copy the pairing QR code and the testing credentials out of the temp directory before clean-up.
# QR code is the one thing we must keep for the user
mkdir -p "$OUTPUT_DIR"
cp "$CREDS_DIR/user_credentials_qrcode.png" "$OUTPUT_DIR/user_credentials_qrcode.png"
cp "$CREDS_DIR/user_credentials_for_testing" "$OUTPUT_DIR/user_credentials_for_testing"
chmod 600 "$OUTPUT_DIR"/* 2>/dev/null || true

# When overwriting, both services are stopped and disabled, the installed binaries are removed, and the entire state directory is deleted (clean slate)
if [[ $OVERWRITE -eq 1 ]]; then
  warn "Overwrite enabled: stopping services and deleting Secluso install state"
  ${SUDO} systemctl stop "$UPDATER_SERVICE" 2>/dev/null || true
  ${SUDO} systemctl stop "$SERVER_UNIT" 2>/dev/null || true
  ${SUDO} systemctl disable "$UPDATER_SERVICE" 2>/dev/null || true
  ${SUDO} systemctl disable "$SERVER_UNIT" 2>/dev/null || true
  ${SUDO} rm -f "$INSTALL_BIN_DIR/secluso-server" "$INSTALL_BIN_DIR/secluso-update"
  ${SUDO} rm -rf "$STATE_DIR"
fi

# The server runs as a dedicated unprivileged system user, home is the state directory of it
# nologin shell prevents interactive use
if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
  info "Creating dedicated service user $SERVICE_USER"
  ${SUDO} useradd --system --home-dir "$STATE_DIR" --create-home --shell /usr/sbin/nologin "$SERVICE_USER"
fi

# Install the verified binaries into place and record the installed version markers
# Binaries only become executable at this point; everything staged in the temp directory stays non-executable until installed
# (Version markers under current_version are what the auto-updater compares against the latest release tag to decide whether to update)
info "Installing verified binaries..."
${SUDO} mkdir -p "$INSTALL_BIN_DIR" "$VERSION_ROOT" "$STATE_DIR" "$STATE_DIR/user_credentials"
${SUDO} install -m 0755 "$SERVER_BIN" "$INSTALL_BIN_DIR/secluso-server"
${SUDO} install -m 0755 "$UPDATER_BIN" "$INSTALL_BIN_DIR/secluso-update"
printf '%s\n' "$VERSION" | ${SUDO} tee "$VERSION_ROOT/server" >/dev/null
printf '%s\n' "$VERSION" | ${SUDO} tee "$VERSION_ROOT/updater" >/dev/null

# Optional FCM push notifs
if [[ -n "$SERVICE_ACCOUNT_KEY" ]]; then
  [[ -f "$SERVICE_ACCOUNT_KEY" ]] || die "Missing service account key at $SERVICE_ACCOUNT_KEY"
  info "Installing service account key"
  ${SUDO} install -m 0600 "$SERVICE_ACCOUNT_KEY" "$STATE_DIR/service_account_key.json"
else
  info "No service account key provided; installing without FCM support."
fi

# Install the generated secrets into the state directory with owner-only permissions
info "Installing freshly generated user credentials"
${SUDO} install -m 0600 "$CREDS_DIR/user_credentials" "$STATE_DIR/user_credentials/user_credentials"
${SUDO} install -m 0600 "$CREDS_DIR/credentials_full" "$STATE_DIR/credentials_full"
${SUDO} chown -R "$SERVICE_USER:$SERVICE_USER" "$STATE_DIR"

# Write the two systemd units (server, updater)
# Server unit: unprivileged service user with systemd hardening
# Updater unit: long-lived service that re-checks the latest release on an interval
info "Writing systemd units..."
${SUDO} tee "/etc/systemd/system/$SERVER_UNIT" >/dev/null <<EOFUNIT
[Unit]
Description=Secluso Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$STATE_DIR
ExecStart=$INSTALL_BIN_DIR/secluso-server --bind-address=$BIND_ADDRESS --port=$LISTEN_PORT
Restart=always
RestartSec=1
Environment=RUST_LOG=info
Environment=SECLUSO_USER_CREDENTIALS_DIR=$STATE_DIR/user_credentials
Environment=UPDATE_HINT_PATH=$STATE_DIR/update_hint
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
ReadWritePaths=$STATE_DIR

[Install]
WantedBy=multi-user.target
EOFUNIT

${SUDO} tee "/etc/systemd/system/$UPDATER_SERVICE" >/dev/null <<EOFUPD
[Unit]
Description=Secluso Auto Updater
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$INSTALL_BIN_DIR/secluso-update --component server --interval-secs $UPDATE_INTERVAL_SECS --github-timeout-secs 20 --restart-unit $SERVER_UNIT --github-repo $OWNER_REPO --update-hint-path $STATE_DIR/update_hint --hint-check-interval-secs $HINT_CHECK_INTERVAL_SECS
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOFUPD

info "Reloading systemd units and starting Secluso..."
${SUDO} systemctl daemon-reload
${SUDO} systemctl enable "$SERVER_UNIT"
${SUDO} systemctl restart "$SERVER_UNIT"

if [[ $ENABLE_UPDATER -eq 1 ]]; then
  ${SUDO} systemctl enable "$UPDATER_SERVICE"
  ${SUDO} systemctl restart "$UPDATER_SERVICE"
  info "Auto-updater enabled."
else
  ${SUDO} systemctl disable --now "$UPDATER_SERVICE" 2>/dev/null || true
  warn "Auto-updater disabled."
fi

# First probe the server locally over loopback
# The probe authenticates with the freshly generated credentials and sends the Client-Version header (server rejects requests from incompatible client versions)
# Must answer 200 and include an X-Server-Version response header
# Up to eight attempts are made two seconds apart (give the service time to finish starting)
# If works, we just need to check outside reachability (done below)
info "Checking local /status endpoint with generated credentials..."
LOCAL_OK=0
for attempt in $(seq 1 8); do
  headers="$(curl -fsS -o /dev/null -D - --max-time 15 \
      -u "$USERNAME:$PASSWORD" -H "Client-Version: $VERSION" \
      "http://127.0.0.1:$LISTEN_PORT/status" 2>/dev/null)" && { LOCAL_OK=1; break; }
  warn "Local /status probe not ready yet (attempt $attempt/8). Retrying..."
  sleep 2
done

LOCAL_SERVER_VERSION=""
if [[ $LOCAL_OK -eq 1 ]]; then
  LOCAL_SERVER_VERSION="$(printf '%s' "$headers" | tr -d '\r' | awk -F': ' 'tolower($1)=="x-server-version" {print $2}')"
  if [[ -z "$LOCAL_SERVER_VERSION" ]]; then
    die "Local /status succeeded, but the server did not return X-Server-Version. This does not look like a healthy Secluso server."
  fi
  info "Local health check OK (server version: $LOCAL_SERVER_VERSION)."
else
  warn "Local /status check failed. The service may still be starting; diagnostics below."
fi

# Print everything needed to figure out why the external check failed.
# incl. service state, whether anything is actually listening on the port, and the most recent server logs.
print_diagnostics() {
  echo
  warn "Self-diagnosis:"
  ${SUDO} systemctl --no-pager status "$SERVER_UNIT" 2>&1 | head -n 12 || true
  echo
  echo "Listening sockets on port $LISTEN_PORT:"
  ss -ltn "( sport = :$LISTEN_PORT )" 2>/dev/null || true
  echo
  echo "Recent server logs:"
  ${SUDO} journalctl -u "$SERVER_UNIT" --no-pager -n 20 2>/dev/null || true
  echo
  if [[ $LOCAL_OK -eq 1 ]]; then
    if [[ "$EXPOSURE" == "proxy" ]]; then
      echo "The server is healthy locally. Check your reverse proxy route, TLS setup,"
      echo "and whether it forwards to 127.0.0.1:$LISTEN_PORT."
    else
      echo "The server is healthy locally. Check that port $LISTEN_PORT is open in the"
      echo "server firewall and your provider security group."
    fi
  else
    echo "The server is not healthy locally yet; fix that before testing externally."
  fi
  echo
}

# Let user can verify public reachability from outside the server
# Curl command includes the real credentials and the expected version to test everything... DNS, TLS, proxy or firewall, and authentication
echo
echo "=============================================================="
echo " Secluso $RELEASE_TAG is installed and running."
echo
echo " Now verify it is reachable from OUTSIDE this server."
echo " From another machine (e.g. your laptop), run:"
echo
echo "   curl -i -u '$USERNAME:$PASSWORD' \\"
echo "        -H 'Client-Version: $VERSION' \\"
echo "        $SERVER_URL/status"
echo
echo " It should return HTTP 200 with header:  X-Server-Version: ${LOCAL_SERVER_VERSION:-v$VERSION}"
echo "=============================================================="
echo

while true; do
  printf 'Did the external check succeed? [y = continue / n = show diagnostics / q = abort] '
  read -r answer < "$PROMPT_IN" || answer=q
  case "$answer" in
    [Yy]*) break ;;
    [Qq]*) die "Aborted. Services are left running. Re-test with the curl command above once fixed." ;;
    *) print_diagnostics ;;
  esac
done

echo
info "Install complete."
echo
echo "  Pairing QR code:   $OUTPUT_DIR/user_credentials_qrcode.png"
echo "                     (scan it with the Secluso app, then delete it)"
echo "  Server unit:       $SERVER_UNIT"
echo "  Updater unit:      $UPDATER_SERVICE (enabled=$ENABLE_UPDATER)"
echo "  State directory:   $STATE_DIR"
echo
echo "Copy the QR code off this server securely, e.g.:"
echo "  scp $(whoami)@<this-server>:$OUTPUT_DIR/user_credentials_qrcode.png ."
