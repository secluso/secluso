#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail

WORK=/work
OUT=/out
CFG="$WORK/config.json"

run() { echo "+ $*" >&2; "$@"; }
jqr() { jq -r "$1" "$CFG"; }

emit() {
  local level="$1" step="$2" msg="$3"
  msg="${msg//\"/\\\"}"
  printf '::SECLUSO_EVENT::{"level":"%s","step":"%s","msg":"%s"}\n' "$level" "$step" "$msg"
}

ensure_loop_devices() {
  # Fixes case where the host already had many loop devices 
  # in use (for example snap mounts), and a failed run could also leave stale mappings behind. This helper makes
  # sure loop support is present and that the container sees enough /dev/loopN device files to request a free slot.

  local loop_max="${LOOP_MAX:-63}"

  if command -v modprobe >/dev/null 2>&1; then
    modprobe loop "max_loop=$((loop_max + 1))" 2>/dev/null || modprobe loop 2>/dev/null || true
  fi

  if [[ ! -e /dev/loop-control ]]; then
    mknod -m 0600 /dev/loop-control c 10 237 2>/dev/null || true
  fi

  for i in $(seq 0 "$loop_max"); do
    [[ -b "/dev/loop$i" ]] || mknod -m 0660 "/dev/loop$i" b 7 "$i" 2>/dev/null || true
  done

  if [[ ! -e /dev/loop-control ]]; then
    echo "Missing /dev/loop-control. Run Docker with --privileged and ensure the host loop module is available." >&2
    exit 1
  fi

  if ! compgen -G "/dev/loop[0-9]*" > /dev/null; then
    echo "No /dev/loopN devices were found. Run Docker with --privileged and ensure the host loop module is loaded." >&2
    exit 1
  fi
}

cleanup_stale_work_loops() {
  # Old loop mappings for working.img from previous failed runs can keep
  # consuming loop slots even after the file is gone. We detach only mappings tied to this build path so we free
  # capacity for the current run without messing with unrelated loop devices.
  while read -r dev; do
    [[ -n "$dev" ]] || continue
    losetup -d "$dev" 2>/dev/null || true
  done < <(losetup -a 2>/dev/null | awk -F: '/\/work\/working\.img|\/working\.img/{print $1}')
}

BASE_IMAGE="$(jqr '.base_image')"
RPICAM_APPS_COMMIT="$(jqr '.rpicam_apps_commit')"
OUT_NAME="$(jqr '.output_name')"
HOSTNAME="$(jqr '.hostname')"

USER_NAME="$(jqr '.user.name')"
USER_PASS="$(jqr '.user.password')"

SSH_ENABLE="$(jqr '.ssh.enable // false')"
HAS_WIFI="$(jqr '.wifi != null')"
VARIANT="$(jqr '.variant // "diy"')"

HAS_SECLUSO="$(jqr '.secluso != null')"
if [[ "$HAS_SECLUSO" == "true" ]]; then
  SECLUSO_INSTALL_DIR="$(jqr '.secluso.install_dir // "/opt/secluso"')"
  SECLUSO_ETC_DIR="$(jqr '.secluso.etc_dir // "/etc/secluso"')"
  SECLUSO_REPO="$(jqr '.secluso.repo // "secluso/secluso"')"
fi

PKGS="$(jqr '(.apt.packages // []) | join(" ")')"

cd "$WORK"

emit "info" "base_image" "Preparing base image..."

# fetch base image
if [[ "$BASE_IMAGE" == http://* || "$BASE_IMAGE" == https://* ]]; then
  fname="$(basename "$BASE_IMAGE")"
  if [[ ! -f "$fname" ]]; then
    run curl -L -o "$fname" "$BASE_IMAGE"
  fi
  BASE_PATH="$WORK/$fname"
else
  if [[ -f "$BASE_IMAGE" ]]; then BASE_PATH="$BASE_IMAGE"
  elif [[ -f "$WORK/$BASE_IMAGE" ]]; then BASE_PATH="$WORK/$BASE_IMAGE"
  else echo "Base image not found: $BASE_IMAGE"; exit 1; fi
fi
IMG="$BASE_PATH"
if [[ "$IMG" == *.xz ]]; then
  if [[ ! -f "${IMG%.xz}" ]]; then run xz -dk "$IMG"; fi
  IMG="${IMG%.xz}"
fi

WORK_IMG="$WORK/working.img"
run cp -f "$IMG" "$WORK_IMG"

# grow image and root partition
# add 4g to the image file
run truncate -s +4G "$WORK_IMG"

# expand partition 2 to fill the image
run parted -s "$WORK_IMG" resizepart 2 100%

# mount partitions by offset
# read partition offsets and sizes
BOOT_OFF="$(parted -ms "$WORK_IMG" unit B print | awk -F: '$1=="1"{gsub("B","",$2); print $2}')"
BOOT_SIZE="$(parted -ms "$WORK_IMG" unit B print | awk -F: '$1=="1"{gsub("B","",$4); print $4}')"

ROOT_OFF="$(parted -ms "$WORK_IMG" unit B print | awk -F: '$1=="2"{gsub("B","",$2); print $2}')"
ROOT_SIZE="$(parted -ms "$WORK_IMG" unit B print | awk -F: '$1=="2"{gsub("B","",$4); print $4}')"

if [[ -z "$BOOT_OFF" || -z "$ROOT_OFF" || -z "$BOOT_SIZE" || -z "$ROOT_SIZE" ]]; then
  echo "Failed to parse partition offsets/sizes via parted" >&2
  parted -s "$WORK_IMG" print >&2 || true
  exit 1
fi

MNT="$WORK/mnt"
BOOT="$MNT/boot"
ROOT="$MNT/root"
run mkdir -p "$BOOT" "$ROOT"

# create loop devices for boot and root
if [[ ! -f "$WORK_IMG" ]]; then
  echo "Working image is missing: $WORK_IMG" >&2
  ls -la "$WORK" >&2 || true
  exit 1
fi

ensure_loop_devices
cleanup_stale_work_loops

if ! LOOP_ROOT="$(losetup --find --show --offset "$ROOT_OFF" --sizelimit "$ROOT_SIZE" "$WORK_IMG")"; then
  echo "Failed to attach root loop device from $WORK_IMG." >&2
  ls -l /dev/loop* /dev/loop-control >&2 || true
  losetup -a >&2 || true
  exit 1
fi

if ! LOOP_BOOT="$(losetup --find --show --offset "$BOOT_OFF" --sizelimit "$BOOT_SIZE" "$WORK_IMG")"; then
  echo "Failed to attach boot loop device from $WORK_IMG." >&2
  ls -l /dev/loop* /dev/loop-control >&2 || true
  losetup -a >&2 || true
  losetup -d "$LOOP_ROOT" 2>/dev/null || true
  exit 1
fi

echo "+ LOOP_ROOT=$LOOP_ROOT (rootfs)" >&2
echo "+ LOOP_BOOT=$LOOP_BOOT (bootfs)" >&2

# grow ext4 to fill the root partition
run e2fsck -f -y "$LOOP_ROOT"
run resize2fs "$LOOP_ROOT"
cleanup() {
  set +e
  run umount -R "$ROOT/dev" 2>/dev/null || true
  run umount -R "$ROOT/proc" 2>/dev/null || true
  run umount -R "$ROOT/sys" 2>/dev/null || true
  run umount "$BOOT" 2>/dev/null || true
  run umount "$ROOT" 2>/dev/null || true
  run losetup -d "$LOOP_BOOT" 2>/dev/null || true
  run losetup -d "$LOOP_ROOT" 2>/dev/null || true
}
trap cleanup EXIT

emit "info" "mount" "Mounting partitions..."

# mount root and boot
run mount "$LOOP_ROOT" "$ROOT"
run mount "$LOOP_BOOT" "$BOOT"

# enable ssh for headless setup
if [[ "$SSH_ENABLE" == "true" ]]; then
  run touch "$BOOT/ssh" || true
fi

if [[ "$HAS_WIFI" == "true" ]]; then
  WIFI_COUNTRY="$(jqr '.wifi.country')"
  WIFI_SSID="$(jqr '.wifi.ssid')"
  WIFI_PSK="$(jqr '.wifi.psk')"
fi

write_custom_toml() {
  # bookworm headless flow in bootfs
  cat > "$BOOT/custom.toml" <<EOF
config_version = 1

[system]
hostname = "${HOSTNAME}"

[user]
name = "${USER_NAME}"
password = "${USER_PASS}"
password_encrypted = false

[ssh]
enabled = ${SSH_ENABLE}
password_authentication = true
EOF

  # add authorized_keys if present
  if jq -e '.ssh.authorized_keys | length > 0' "$CFG" >/dev/null 2>&1; then
    # toml array of strings
    echo -n 'authorized_keys = [' >> "$BOOT/custom.toml"
    jq -r '.ssh.authorized_keys[]' "$CFG" | awk 'BEGIN{first=1}{gsub(/\\/,"\\\\"); gsub(/"/,"\\\""); if(!first) printf(", "); first=0; printf("\"%s\"", $0)} END{print "]"}' >> "$BOOT/custom.toml"
  fi

  if [[ "$HAS_WIFI" == "true" ]]; then
    cat >> "$BOOT/custom.toml" <<EOF

[wlan]
ssid = "${WIFI_SSID}"
password = "${WIFI_PSK}"
password_encrypted = false
hidden = false
country = "${WIFI_COUNTRY}"
EOF
  fi

  # keep /boot/ssh for older flows
  if [[ "$SSH_ENABLE" == "true" ]]; then
    touch "$BOOT/ssh" || true
  fi
}

write_custom_toml

emit "info" "system" "Configuring hostname and user..."

# hostname
echo "$HOSTNAME" > "$ROOT/etc/hostname"
if [[ -f "$ROOT/etc/hosts" ]]; then
  # keep 127.0.1.1 aligned
  sed -i "s/^127\.0\.1\.1.*/127.0.1.1\t$HOSTNAME/" "$ROOT/etc/hosts" || true
fi

# create user and password in chroot
# bind mounts for chroot
run mount --bind /dev "$ROOT/dev"
run mount --bind /proc "$ROOT/proc"
run mount --bind /sys "$ROOT/sys"

# copy dns settings into chroot
if [[ -f /etc/resolv.conf ]]; then
  run cp -f /etc/resolv.conf "$ROOT/etc/resolv.conf"
fi

# user and password
run chroot "$ROOT" bash -lc "id -u '$USER_NAME' >/dev/null 2>&1 || useradd -m -s /bin/bash -G sudo '$USER_NAME'"
run chroot "$ROOT" bash -lc "echo '$USER_NAME:$USER_PASS' | chpasswd"

# write a build marker for easy verification
build_stamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
cat > "$ROOT/etc/secluso-build.txt" <<EOF
build_time=$build_stamp
hostname=$HOSTNAME
EOF
if [[ -d "$ROOT/home/$USER_NAME" ]]; then
  cat > "$ROOT/home/$USER_NAME/secluso-build.txt" <<EOF
build_time=$build_stamp
hostname=$HOSTNAME
EOF
  run chroot "$ROOT" bash -lc "chown $USER_NAME:$USER_NAME /home/$USER_NAME/secluso-build.txt"
fi

# ssh authorized_keys
AUTH_KEYS="$WORK/authorized_keys"
jq -r '.ssh.authorized_keys[]? // empty' "$CFG" > "$AUTH_KEYS" || true
if [[ -s "$AUTH_KEYS" ]]; then
  run chroot "$ROOT" bash -lc "install -d -m 700 -o '$USER_NAME' -g '$USER_NAME' /home/'$USER_NAME'/.ssh"
  run install -m 600 "$AUTH_KEYS" "$ROOT/home/$USER_NAME/.ssh/authorized_keys"
  run chroot "$ROOT" bash -lc "chown '$USER_NAME:$USER_NAME' /home/'$USER_NAME'/.ssh/authorized_keys"
  # disable password ssh if keys exist
  if [[ -f "$ROOT/etc/ssh/sshd_config" ]]; then
    run chroot "$ROOT" bash -lc "sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config || true"
  fi
fi

# install apt packages inside image
if [[ -n "$PKGS" ]]; then
  emit "info" "packages" "Installing base packages..."
  run chroot "$ROOT" bash -lc "apt-get update"
  run chroot "$ROOT" bash -lc "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends $PKGS"
fi

if [[ "$VARIANT" == "official" ]]; then
  emit "info" "official" "Applying official variant customizations..."
  # official-only customization area. Keep extra setup that should not land in DIY images here
  :
fi

if [[ "$HAS_SECLUSO" == "true" ]]; then
  ARCHDIR_AARCH64="aarch64-unknown-linux-gnu"
  BUNDLE_ZIP="$WORK/secluso_bundle.zip"

  emit "info" "secluso" "Installing Secluso hub binaries and config..."
  # create dirs
  run mkdir -p "$ROOT${SECLUSO_INSTALL_DIR}/bin"
  run mkdir -p "$ROOT${SECLUSO_ETC_DIR}"
  run chmod 700 "$ROOT${SECLUSO_ETC_DIR}" || true
  run chroot "$ROOT" bash -lc "chmod 700 '${SECLUSO_ETC_DIR}' || true"

  # runtime dir for state and logs
  run mkdir -p "$ROOT/var/lib/secluso"
  run chmod 700 "$ROOT/var/lib/secluso"

  # copy camera secret into runtime dir
  if [[ -f "$WORK/camera_secret" ]]; then
    run install -m 600 "$WORK/camera_secret" "$ROOT/var/lib/secluso/camera_secret"
  fi

  # copy wifi password into runtime dir
  if [[ -f "$WORK/wifi_password" ]]; then
    run install -m 600 "$WORK/wifi_password" "$ROOT/var/lib/secluso/wifi_password"
  fi

  [[ -f "$BUNDLE_ZIP" ]] || {
    emit "error" "secluso" "Missing required bundle at $BUNDLE_ZIP"
    exit 1
  }

  emit "info" "secluso" "Installing updater and hub from provided bundle..."
  rm -rf /tmp/secluso_bundle && mkdir -p /tmp/secluso_bundle
  unzip -o "$BUNDLE_ZIP" -d /tmp/secluso_bundle >/dev/null
  root="/tmp/secluso_bundle"
  maybe="$(find /tmp/secluso_bundle -maxdepth 2 -type f -name manifest.json | head -n 1 || true)"
  if [[ -n "$maybe" ]]; then
    root="$(dirname "$maybe")"
  fi
  if [[ -x "$root/artifacts/$ARCHDIR_AARCH64/secluso-update" ]]; then
    run install -m 0755 "$root/artifacts/$ARCHDIR_AARCH64/secluso-update" "$ROOT${SECLUSO_INSTALL_DIR}/bin/secluso-update"
    updater_name="secluso-update"
  else
    echo "Missing secluso-update in provided bundle" >&2
    exit 1
  fi

  if [[ -x "$root/artifacts/$ARCHDIR_AARCH64/secluso-raspberry-camera-hub" ]]; then
    run install -m 0755 "$root/artifacts/$ARCHDIR_AARCH64/secluso-raspberry-camera-hub" "$ROOT${SECLUSO_INSTALL_DIR}/bin/secluso-raspberry-camera-hub"
  else
    echo "Missing secluso-raspberry-camera-hub in provided bundle" >&2
    exit 1
  fi

  SIG_ARGS=""
  if jq -e '.secluso.sig_keys | length > 0' "$CFG" >/dev/null 2>&1; then
    while read -r key; do
      SIG_ARGS="$SIG_ARGS --sig-key $key"
    done < <(jq -r '.secluso.sig_keys[] | "\(.name):\(.github_user)"' "$CFG")
  fi

  run chroot "$ROOT" bash -lc "cd '${SECLUSO_INSTALL_DIR}/bin' && './${updater_name}' --help 2>/dev/null | grep -q -- '--component' || exit 1"
  emit "info" "secluso" "Hub binary preinstalled from provided bundle; skipping one-shot updater run."

  if [[ ! -x "$ROOT${SECLUSO_INSTALL_DIR}/bin/secluso-raspberry-camera-hub" ]]; then
    emit "error" "secluso" "hub binary missing after install"
    exit 1
  fi

  emit "info" "secluso" "Bundled updater installed from provided bundle."

  # systemd unit
  cat > "$ROOT/etc/systemd/system/secluso_camera_hub.service" <<EOF
[Unit]
Description=secluso_camera_hub
RequiresMountsFor=/home
After=network-online.target
Wants=network-online.target

[Service]
User=root
WorkingDirectory=/var/lib/secluso
# fail fast if secrets or binary missing
ExecStartPre=/usr/bin/test -x ${SECLUSO_INSTALL_DIR}/bin/secluso-raspberry-camera-hub
ExecStartPre=/usr/bin/test -r /var/lib/secluso/camera_secret
ExecStartPre=/usr/bin/test -r /var/lib/secluso/wifi_password

ExecStart=${SECLUSO_INSTALL_DIR}/bin/secluso-raspberry-camera-hub
Environment="RUST_LOG=info"
Environment="LD_LIBRARY_PATH=/usr/local/lib/aarch64-linux-gnu/:/usr/local/lib:${LD_LIBRARY_PATH:-}"
Environment="UPDATE_HINT_PATH=/var/lib/secluso/update_hint"
Restart=always
RestartSec=1

[Install]
WantedBy=multi-user.target
EOF

  run chroot "$ROOT" bash -lc "mkdir -p /etc/systemd/system/multi-user.target.wants"
  run chroot "$ROOT" bash -lc "ln -sf /etc/systemd/system/secluso_camera_hub.service /etc/systemd/system/multi-user.target.wants/secluso_camera_hub.service"

  # enable wifi radio on boot
  cat > "$ROOT/etc/systemd/system/secluso-wifi-radio.service" <<EOF
[Unit]
Description=Secluso Wi-Fi Radio Enable
After=NetworkManager.service
Wants=NetworkManager.service

[Service]
Type=oneshot
ExecStart=/usr/sbin/rfkill unblock wifi
ExecStart=/usr/bin/nmcli radio wifi on

[Install]
WantedBy=multi-user.target
EOF
  run chroot "$ROOT" bash -lc "ln -sf /etc/systemd/system/secluso-wifi-radio.service /etc/systemd/system/multi-user.target.wants/secluso-wifi-radio.service"

  if [[ -x "$ROOT${SECLUSO_INSTALL_DIR}/bin/$updater_name" ]]; then
    UPDATE_INTERVAL_SECS="1800"
    HINT_CHECK_INTERVAL_SECS="60"
    UPDATE_HINT_PATH="/var/lib/secluso/update_hint"
    cat > "$ROOT/etc/systemd/system/secluso-updater.service" <<EOF
[Unit]
Description=Secluso Updater
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${SECLUSO_INSTALL_DIR}/bin/${updater_name} --component raspberry_camera_hub --interval-secs ${UPDATE_INTERVAL_SECS} --github-timeout-secs 20 --restart-unit secluso_camera_hub.service --github-repo ${SECLUSO_REPO}${SIG_ARGS} --update-hint-path ${UPDATE_HINT_PATH} --hint-check-interval-secs ${HINT_CHECK_INTERVAL_SECS}
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
    run chroot "$ROOT" bash -lc "ln -sf /etc/systemd/system/secluso-updater.service /etc/systemd/system/multi-user.target.wants/secluso-updater.service"
  else
    emit "warn" "updater" "secluso-updater not found, skipping auto updates"
  fi
fi

install_rpicam_apps() {
  local repo_url="$1"
  local repo_ref="$2"   # commit hash or tag/branch (optional; can be "main")
  local src_dir="/opt/rpicam-apps"

  echo "+ Installing custom rpicam-apps from $repo_url@$repo_ref" >&2

  # deps
  run chroot "$ROOT" bash -lc "apt-get update"

  install_pinned_libcamera() {
  local ver="0.4.0+rpt20250213-1"
  local arch="arm64"
  local base="https://mirror.fsmg.org.nz/pub/raspberrypi/debian/pool/main/libc/libcamera"

  echo "+ Pinning libcamera stack to $ver" >&2

  # make sure curl and ca certs exist
  run chroot "$ROOT" bash -lc "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates curl"

  # pin 0.4 to avoid apt pulling 0.5
  run chroot "$ROOT" bash -lc "cat > /etc/apt/preferences.d/secluso-libcamera <<'EOF'
Package: libcamera0.4 libcamera-ipa libcamera-dev libcamera-tools python3-libcamera
Pin: version 0.4.*
Pin-Priority: 1001

Package: libcamera0.5 libcamera-ipa
Pin: version 0.5.*
Pin-Priority: -10
EOF"

  # remove newer libcamera packages
  run chroot "$ROOT" bash -lc "DEBIAN_FRONTEND=noninteractive apt-get remove -y 'libcamera0.5*' 'libcamera-ipa' 'libcamera-tools' 'libcamera-dev' 'python3-libcamera*' || true; apt-get autoremove -y || true"

  # install deps needed for 0.4
  run chroot "$ROOT" bash -lc "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends libpisp1 liblttng-ust1 libunwind8 libevent-2.1-7 libevent-pthreads-2.1-7 libsdl2-2.0-0"

  # download pinned debs
  run chroot "$ROOT" bash -lc "set -eux;
    cd /tmp;
    curl -fsSL -O '$base/libcamera0.4_${ver}_${arch}.deb';
    curl -fsSL -O '$base/libcamera-ipa_${ver}_${arch}.deb';
    curl -fsSL -O '$base/libcamera-dev_${ver}_${arch}.deb';
    curl -fsSL -O '$base/libcamera-tools_${ver}_${arch}.deb' || true;
    curl -fsSL -O '$base/python3-libcamera_${ver}_${arch}.deb' || true;
  "

  # install debs
  run chroot "$ROOT" bash -lc "set -eux;
    dpkg -i /tmp/libcamera*_${ver}_${arch}.deb /tmp/python3-libcamera*_${ver}_${arch}.deb;
  " || {
    echo "libcamera install failed, dumping versions" >&2
    run chroot "$ROOT" bash -lc "dpkg -l | grep -E 'libcamera|libpisp|lttng|unwind|libevent|libsdl2' || true" >&2
    exit 1
  }

  # hold libcamera packages
  run chroot "$ROOT" bash -lc "apt-mark hold libcamera0.4 libcamera-ipa libcamera-dev libcamera-tools python3-libcamera || true"
}
  install_pinned_libcamera
  run chroot "$ROOT" bash -lc "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    git ca-certificates \
    libepoxy-dev libjpeg-dev libtiff5-dev libpng-dev \
    cmake libboost-program-options-dev libdrm-dev libexif-dev \
    meson ninja-build \
    pkg-config"

  if [[ ! -f "$WORK/rpicam_apps/rpicam-vid" ]]; then
    echo "rpicam-apps not cached"

    # clone for each build
    run chroot "$ROOT" bash -lc "rm -rf '$src_dir' && mkdir -p /opt"
    run chroot "$ROOT" bash -lc "git clone --depth 1 '$repo_url' '$src_dir'"

    # pin revision if provided
    if [[ -n "$repo_ref" && "$repo_ref" != "main" ]]; then
      run chroot "$ROOT" bash -lc "cd '$src_dir' && git fetch --depth 1 origin '$repo_ref' || true; git checkout '$repo_ref'"
    fi

    # build and install
    run chroot "$ROOT" bash -lc "cd '$src_dir' && rm -rf build"
    run chroot "$ROOT" bash -lc "cd '$src_dir' && meson setup build \
      -Denable_libav=disabled \
      -Denable_drm=enabled \
      -Denable_egl=disabled \
      -Denable_qt=disabled \
      -Denable_opencv=disabled \
      -Denable_tflite=disabled \
      -Denable_hailo=disabled"

    run chroot "$ROOT" bash -lc "cd '$src_dir' && meson compile -C build -j 1"
    if ! run chroot "$ROOT" bash -lc "test -s '$src_dir/build/apps/rpicam-vid'"; then
      emit "error" "rpicam" "rpicam-vid build failed or output is empty"
      run chroot "$ROOT" bash -lc "ls -la '$src_dir/build/apps' || true"
      exit 1
    fi
    run chroot "$ROOT" bash -lc "cd '$src_dir' && meson install -C build"
  else
    echo "Using cached rpicam-apps"
    run chroot "$ROOT" bash -lc "mkdir -p '$src_dir'/build/apps"
    run cp "$WORK"/rpicam_apps/* "$ROOT$src_dir"/build/apps
  fi

  # copy binaries if install did not place them in path
  run chroot "$ROOT" bash -lc "mkdir -p /usr/local/bin"
  if ! run chroot "$ROOT" bash -lc "command -v rpicam-vid >/dev/null 2>&1"; then
    emit "warn" "rpicam" "rpicam-vid not in path, copying from build/apps"
    run chroot "$ROOT" bash -lc "if [ -d '$src_dir/build/apps' ]; then install -m 0755 '$src_dir'/build/apps/rpicam-* /usr/local/bin/; fi"
  fi

  if [[ ! -f "$WORK/rpicam_apps/rpicam-vid" ]]; then
    # we want to save rpicam-hello, rpicam-jpeg, rpicam-raw, rpicam-still, rpicam-vid for re-use in caching
    run chroot "$ROOT" bash -lc "ls '$src_dir'/build/apps"
    mkdir "$WORK"/rpicam_apps
    cp "$ROOT$src_dir"/build/apps/rpicam-hello "$WORK"/rpicam_apps/.
    cp "$ROOT$src_dir"/build/apps/rpicam-jpeg "$WORK"/rpicam_apps/.
    cp "$ROOT$src_dir"/build/apps/rpicam-raw "$WORK"/rpicam_apps/.
    cp "$ROOT$src_dir"/build/apps/rpicam-still "$WORK"/rpicam_apps/.
    cp "$ROOT$src_dir"/build/apps/rpicam-vid "$WORK"/rpicam_apps/.
  fi
}

# run install
emit "info" "rpicam" "Building rpicam-apps..."
install_rpicam_apps "https://github.com/secluso/rpicam-apps.git" "${RPICAM_APPS_COMMIT}"
# pinned commit for repeatability

# done, flush and unmount before copying
emit "info" "output" "Finalizing filesystem..."
run sync
cleanup
trap - EXIT

emit "info" "output" "Writing final image..."
run cp -f "$WORK_IMG" "$OUT/$OUT_NAME"
echo "Wrote image: $OUT/$OUT_NAME"
