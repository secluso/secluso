#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail

# expected env vars
#   install_prefix, owner_repo
#   server_unit, updater_service, update_interval_secs
#   sudo_cmd ("" or "sudo -S -p ''" or "sudo"), enable_updater ("1"/"0")
#   bind_address, listen_port, first_install, overwrite
#   release_tag

emit() {
  local level="$1" step="$2" msg="$3"
  msg="${msg//\"/\\\"}"
  printf '::SECLUSO_EVENT::{"level":"%s","step":"%s","msg":"%s"}\n' "$level" "$step" "$msg"
}

trap 'emit "error" "trap" "Failed at line $LINENO (exit=$?)"' ERR

SUDO="${SUDO_CMD:-}"
if [[ -n "$SUDO" ]]; then
  emit "info" "sudo" "Using sudo wrapper: $SUDO"
else
  emit "info" "sudo" "No sudo wrapper (running as root)"
fi

INSTALL_PREFIX="${INSTALL_PREFIX:-/opt/secluso}"
STATE_DIR="${STATE_DIR:-/var/lib/secluso}"
SERVICE_USER="${SERVICE_USER:-secluso}"
RELEASE_TAG="${RELEASE_TAG:-unknown}"
UPDATE_INTERVAL_SECS="${UPDATE_INTERVAL_SECS:-1800}"
HINT_CHECK_INTERVAL_SECS="${HINT_CHECK_INTERVAL_SECS:-60}"
STAGING_DIR="${STAGING_DIR:-}"
SIG_ARGS=""
if [[ -n "${SIG_KEYS:-}" ]]; then
  IFS=',' read -r -a sig_list <<< "$SIG_KEYS"
  for key in "${sig_list[@]}"; do
    if [[ -n "$key" ]]; then
      SIG_ARGS="$SIG_ARGS --sig-key $key"
    fi
  done
fi

emit "info" "config" "INSTALL_PREFIX=$INSTALL_PREFIX"
emit "info" "config" "STATE_DIR=$STATE_DIR"
emit "info" "config" "OWNER_REPO=$OWNER_REPO"
emit "info" "config" "SERVER_UNIT=$SERVER_UNIT"
emit "info" "config" "UPDATER_SERVICE=$UPDATER_SERVICE"
emit "info" "config" "ENABLE_UPDATER=$ENABLE_UPDATER"
emit "info" "config" "OVERWRITE=$OVERWRITE"
emit "info" "config" "FIRST_INSTALL=$FIRST_INSTALL"
emit "info" "config" "BIND_ADDRESS=${BIND_ADDRESS:-127.0.0.1}"
emit "info" "config" "LISTEN_PORT=${LISTEN_PORT:-8000}"
emit "info" "config" "RELEASE_TAG=$RELEASE_TAG"
emit "info" "config" "GITHUB_TOKEN=${GITHUB_TOKEN:+set}"
emit "info" "config" "STAGING_DIR=${STAGING_DIR:+set}"

# Everything this installer trusts now comes from one per-run staging dir.
if [[ -z "$STAGING_DIR" || ! -d "$STAGING_DIR" ]]; then
  emit "error" "install" "Missing uploaded staging directory"
  exit 1
fi

SERVER_STAGE="$STAGING_DIR/secluso-server"
UPDATER_STAGE="$STAGING_DIR/secluso-update"
SERVICE_ACCOUNT_STAGE="$STAGING_DIR/service_account_key.json"
USER_CREDENTIALS_STAGE="$STAGING_DIR/user_credentials"
CREDENTIALS_FULL_STAGE="$STAGING_DIR/credentials_full"

if [[ "${OVERWRITE:-0}" == "1" ]]; then
  emit "warn" "overwrite" "Overwrite enabled: stopping services and deleting Secluso install directories"
  ${SUDO} systemctl stop "$UPDATER_SERVICE" 2>/dev/null || true
  ${SUDO} systemctl stop "$SERVER_UNIT" 2>/dev/null || true
  ${SUDO} systemctl disable "$UPDATER_SERVICE" 2>/dev/null || true
  ${SUDO} systemctl disable "$SERVER_UNIT" 2>/dev/null || true
  ${SUDO} rm -rf "$INSTALL_PREFIX" "$STATE_DIR"
fi

emit "info" "deps" "Installing minimal runtime dependencies (apt-get)..."
${SUDO} apt-get update
${SUDO} apt-get install -y --no-install-recommends ca-certificates libssl-dev

if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
  emit "info" "install" "Creating dedicated service user $SERVICE_USER"
  ${SUDO} useradd --system --home-dir "$STATE_DIR" --create-home --shell /usr/sbin/nologin "$SERVICE_USER"
fi

emit "info" "install" "Ensuring install and state directories..."
${SUDO} mkdir -p "$INSTALL_PREFIX/bin" "$INSTALL_PREFIX/current_version" "$STATE_DIR" "$STATE_DIR/user_credentials"

if [[ ! -f "$SERVER_STAGE" ]]; then
  emit "error" "install" "Missing staged server binary"
  exit 1
fi
if [[ ! -f "$UPDATER_STAGE" ]]; then
  emit "error" "install" "Missing staged updater binary"
  exit 1
fi

emit "info" "install" "Installing verified binaries..."
# The uploaded files only become live binaries here.
${SUDO} install -m 0755 "$SERVER_STAGE" "$INSTALL_PREFIX/bin/secluso-server"
${SUDO} install -m 0755 "$UPDATER_STAGE" "$INSTALL_PREFIX/bin/secluso-update"
printf '%s\n' "${RELEASE_TAG#v}" | ${SUDO} tee "$INSTALL_PREFIX/current_version/server" >/dev/null
printf '%s\n' "${RELEASE_TAG#v}" | ${SUDO} tee "$INSTALL_PREFIX/current_version/updater" >/dev/null

if [[ -f "$SERVICE_ACCOUNT_STAGE" ]]; then
  emit "info" "secrets" "Installing service account key"
  ${SUDO} install -m 0600 "$SERVICE_ACCOUNT_STAGE" "$STATE_DIR/service_account_key.json"
fi

if [[ "${FIRST_INSTALL:-0}" == "1" ]]; then
  emit "info" "secrets" "Installing freshly generated user credentials"
  ${SUDO} install -m 0600 "$USER_CREDENTIALS_STAGE" "$STATE_DIR/user_credentials/user_credentials"
  ${SUDO} install -m 0600 "$CREDENTIALS_FULL_STAGE" "$STATE_DIR/credentials_full"
fi

${SUDO} chown -R "$SERVICE_USER:$SERVICE_USER" "$STATE_DIR"

emit "info" "systemd" "Writing server unit..."
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
ExecStart=$INSTALL_PREFIX/bin/secluso-server --bind-address=${BIND_ADDRESS:-127.0.0.1} --port=${LISTEN_PORT:-8000}
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

emit "info" "systemd" "Writing updater service..."
${SUDO} tee "/etc/systemd/system/$UPDATER_SERVICE" >/dev/null <<EOFUPD
[Unit]
Description=Secluso Auto Updater
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$INSTALL_PREFIX/bin/secluso-update --component server --interval-secs $UPDATE_INTERVAL_SECS --github-timeout-secs 20 --restart-unit $SERVER_UNIT --github-repo $OWNER_REPO$SIG_ARGS --update-hint-path $STATE_DIR/update_hint --hint-check-interval-secs $HINT_CHECK_INTERVAL_SECS
Restart=always
RestartSec=2
${GITHUB_TOKEN:+Environment=GITHUB_TOKEN=$GITHUB_TOKEN}

[Install]
WantedBy=multi-user.target
EOFUPD

emit "info" "systemd" "Reloading systemd units and restarting Secluso..."
${SUDO} systemctl daemon-reload
${SUDO} systemctl enable "$SERVER_UNIT"
${SUDO} systemctl restart "$SERVER_UNIT"

if [[ "${ENABLE_UPDATER:-1}" == "1" ]]; then
  ${SUDO} systemctl enable "$UPDATER_SERVICE"
  ${SUDO} systemctl restart "$UPDATER_SERVICE"
  emit "info" "systemd" "updater service enabled"
else
  ${SUDO} systemctl disable --now "$UPDATER_SERVICE" 2>/dev/null || true
  emit "warn" "systemd" "updater disabled"
fi

# No reason to leave the staged payloads around once install is done.
rm -rf "$STAGING_DIR" 2>/dev/null || ${SUDO} rm -rf "$STAGING_DIR" 2>/dev/null || true

emit "info" "done" "DONE"
