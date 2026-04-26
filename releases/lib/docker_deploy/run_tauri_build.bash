#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail

verify_sha256() {
  local path="$1"
  local expected_sha="$2"
  local label="$3"
  local actual_sha

  actual_sha="$(sha256sum "$path" | awk '{print $1}')"
  [[ "$actual_sha" == "$expected_sha" ]] || {
    echo "SHA-256 mismatch for $label" >&2
    echo "  expected: $expected_sha" >&2
    echo "  actual:   $actual_sha" >&2
    return 1
  }
}

download_verified_file() {
  local url="$1"
  local path="$2"
  local expected_sha="$3"
  local label="$4"
  local tmp_path="${path}.tmp"

  rm -f "$tmp_path"
  curl --fail --location \
    --retry 8 \
    --retry-delay 2 \
    --retry-all-errors \
    --connect-timeout 20 \
    --output "$tmp_path" \
    "$url" || {
      rm -f "$tmp_path"
      return 1
    }
  verify_sha256 "$tmp_path" "$expected_sha" "$label" || {
    rm -f "$tmp_path"
    return 1
  }
  mv "$tmp_path" "$path"
}

expected_apprun_sha256() {
  case "$1" in
    AppRun-x86_64) echo "f30140a43a0a59e46db21bdefdf749b9e9f2c6946e92afabbacf98b8ae73fb4f" ;;
    AppRun-aarch64) echo "072f17c0895a85c490282fe5395c5007e5fc75da727e553b3b8fb680feb11578" ;;
    *)
      echo "Unsupported AppRun helper: $1" >&2
      return 1
      ;;
  esac
}

expected_nsis_utils_sha256() {
  local version="$1"

  if [[ -n "${TAURI_NSIS_UTILS_SHA256:-}" ]]; then
    echo "$TAURI_NSIS_UTILS_SHA256"
    return
  fi

  case "$version" in
    0.5.3) echo "5ba143b5db4a87d32d6e7802e033330aae56cbceabe0d1e3ba41948385ad4709" ;;
    *)
      echo "TAURI_NSIS_UTILS_SHA256 must be set when overriding TAURI_NSIS_UTILS_VERSION (got ${version})" >&2
      return 1
      ;;
  esac
}

is_debug_enabled() {
  case "${DEBUG:-0}" in
    1|true|TRUE|yes|YES|on|ON) return 0 ;;
    *) return 1 ;;
  esac
}

configure_rust_log() {
  if is_debug_enabled; then
    # Keep bundler diagnostics detailed but avoid ureq hex dumps that can
    # overflow BuildKit step logs and hide the real failure signal.
    export RUST_LOG="${RUST_LOG:-tauri_bundler=debug,tauri_cli_node=debug,ureq=warn}"
  else
    export RUST_LOG="${RUST_LOG:-tauri_bundler=info,tauri_cli_node=info,ureq=warn}"
  fi
}

write_bundle_config() {
  printf '{ "bundle": { "targets": %s } }\n' "${TAURI_BUNDLE_TARGETS_JSON}" > /tmp/tauri-bundle-config.json
  echo "==> tauri bundle config"
  cat /tmp/tauri-bundle-config.json
}

configure_deterministic_build_env() {
  local source_date_epoch="${SOURCE_DATE_EPOCH:-1704067200}"
  local deterministic_rustflags="${RUSTFLAGS:-}"
  local remap_flag

  [[ "$source_date_epoch" =~ ^[0-9]+$ ]] || {
    echo "Invalid SOURCE_DATE_EPOCH: $source_date_epoch" >&2
    exit 1
  }

  export SOURCE_DATE_EPOCH="$source_date_epoch"
  export TZ=UTC
  export LC_ALL=C
  export LANG=C
  export ZERO_AR_DATE=1
  export PYTHONHASHSEED="${PYTHONHASHSEED:-0}"
  export GZIP="${GZIP:--n}"
  export DPKG_DEB_THREADS_MAX="${DPKG_DEB_THREADS_MAX:-1}"
  export XZ_DEFAULTS="${XZ_DEFAULTS:---threads=1}"
  export CARGO_INCREMENTAL=0
  export CARGO_BUILD_JOBS=1
  export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
  export CARGO_PROFILE_RELEASE_DEBUG=0
  export CARGO_PROFILE_RELEASE_STRIP=debuginfo

  for remap_flag in \
    "--remap-path-prefix=/app=." \
    "--remap-path-prefix=/root/.cargo=/cargo-home" \
    "--remap-path-prefix=/root=/home/user"
  do
    if [[ "$deterministic_rustflags" != *"$remap_flag"* ]]; then
      deterministic_rustflags="${deterministic_rustflags:+$deterministic_rustflags }$remap_flag"
    fi
  done

  if [[ "$TAURI_TARGET" == *"-pc-windows-"* ]]; then
    local brepro_flag="-C link-arg=/Brepro"
    if [[ "$deterministic_rustflags" != *"$brepro_flag"* ]]; then
      deterministic_rustflags="${deterministic_rustflags:+$deterministic_rustflags }$brepro_flag"
    fi
    local debug_none_flag="-C link-arg=/DEBUG:NONE"
    if [[ "$deterministic_rustflags" != *"$debug_none_flag"* ]]; then
      deterministic_rustflags="${deterministic_rustflags:+$deterministic_rustflags }$debug_none_flag"
    fi
  fi

  export RUSTFLAGS="$deterministic_rustflags"
}

prepare_linux_apprun_cache() {
  [[ "$TAURI_TARGET" == *"-unknown-linux-"* ]] || return

  local apprun_name=""
  case "$TAURI_TARGET" in
    x86_64-unknown-linux-gnu) apprun_name="AppRun-x86_64" ;;
    aarch64-unknown-linux-gnu) apprun_name="AppRun-aarch64" ;;
    *) return ;;
  esac

  local cache_dir="/root/.cache/tauri"
  local apprun_path="$cache_dir/$apprun_name"
  local download_url="https://github.com/tauri-apps/binary-releases/releases/download/apprun-old/${apprun_name}"
  local expected_sha

  expected_sha="$(expected_apprun_sha256 "$apprun_name")" || exit 1

  mkdir -p "$cache_dir"
  if [[ -f "$apprun_path" ]]; then
    verify_sha256 "$apprun_path" "$expected_sha" "$apprun_name" || {
      rm -f "$apprun_path"
    }
    [[ -f "$apprun_path" ]] && chmod +x "$apprun_path"
  fi
  if [[ ! -x "$apprun_path" ]]; then
    echo "==> prefetching ${apprun_name} for tauri linux bundle"
    # Fail closed here so the build never falls back to Tauri's own unverified download path.
    download_verified_file "$download_url" "$apprun_path" "$expected_sha" "$apprun_name"
    chmod +x "$apprun_path"
  fi

  if [[ -f "$apprun_path" ]]; then
    touch -h -d "@${SOURCE_DATE_EPOCH}" "$apprun_path" 2>/dev/null || true
  fi
}

prepare_windows_nsis_cache() {
  [[ "$TAURI_TARGET" == *"-pc-windows-"* ]] || return

  local cache_dir="/root/.cache/tauri"
  local nsis_utils_version="${TAURI_NSIS_UTILS_VERSION:-0.5.3}"
  local dll_path="$cache_dir/nsis_tauri_utils.dll"
  local download_url="https://github.com/tauri-apps/nsis-tauri-utils/releases/download/nsis_tauri_utils-v${nsis_utils_version}/nsis_tauri_utils.dll"
  local expected_sha

  expected_sha="$(expected_nsis_utils_sha256 "$nsis_utils_version")" || exit 1

  mkdir -p "$cache_dir"
  if [[ -f "$dll_path" ]]; then
    verify_sha256 "$dll_path" "$expected_sha" "nsis_tauri_utils.dll" || {
      rm -f "$dll_path"
    }
  fi
  if [[ ! -f "$dll_path" ]]; then
    echo "==> prefetching nsis_tauri_utils.dll (v${nsis_utils_version})"
    download_verified_file "$download_url" "$dll_path" "$expected_sha" "nsis_tauri_utils.dll"
  fi
  touch -h -d "@${SOURCE_DATE_EPOCH}" "$dll_path"
}

normalize_windows_bundle_inputs_once() {
  [[ "$TAURI_TARGET" == *"-pc-windows-"* ]] || return

  local release_dir="/app/deploy/src-tauri/target/${TAURI_TARGET}/release"
  [[ -d "$release_dir" ]] || return

  # NSIS can capture file metadata from staged bundle inputs. Keep mtime stable
  # while tauri is preparing bundle assets.
  while IFS= read -r -d '' path; do
    touch -h -d "@${SOURCE_DATE_EPOCH}" -- "$path" 2>/dev/null || true
  done < <(find "$release_dir" -mindepth 1 -print0 2>/dev/null | LC_ALL=C sort -z)

  touch -h -d "@${SOURCE_DATE_EPOCH}" /root/.cache/tauri/nsis_tauri_utils.dll 2>/dev/null || true
}

normalize_linux_bundle_inputs_once() {
  [[ "$TAURI_TARGET" == *"-unknown-linux-"* ]] || return

  local tauri_dir="/app/deploy/src-tauri"
  local release_dir="$tauri_dir/target/${TAURI_TARGET}/release"

  # The Tauri bundler  preserves source file mtimes into deb/rpm tar headers.
  # Docker COPY assigns fresh mtimes each run so we normalize source inputs.
  if [[ -d "$tauri_dir" ]]; then
    while IFS= read -r -d '' path; do
      touch -h -d "@${SOURCE_DATE_EPOCH}" -- "$path" 2>/dev/null || true
    done < <(find "$tauri_dir" \( -path "$tauri_dir/target" -o -path "$tauri_dir/target/*" \) -prune -o -mindepth 1 -print0 2>/dev/null | LC_ALL=C sort -z)
  fi

  # Also normalize compiled output timestamps used as package payload inputs.
  if [[ -d "$release_dir" ]]; then
    while IFS= read -r -d '' path; do
      touch -h -d "@${SOURCE_DATE_EPOCH}" -- "$path" 2>/dev/null || true
    done < <(find "$release_dir" -mindepth 1 -print0 2>/dev/null | LC_ALL=C sort -z)
  fi
}

normalize_tree_timestamps() {
  local root="$1"
  [[ -e "$root" ]] || return 0

  while IFS= read -r -d '' path; do
    touch -h -d "@${SOURCE_DATE_EPOCH}" -- "$path" 2>/dev/null || true
  done < <(find "$root" -mindepth 0 -print0 2>/dev/null | LC_ALL=C sort -z)
}

resolve_linuxdeploy_binary() {
  local linuxdeploy_bin=""
  linuxdeploy_bin="$(find /root/.cache/tauri -maxdepth 1 -type f -name 'linuxdeploy-*.AppImage' ! -name 'linuxdeploy-plugin-*' | LC_ALL=C sort | head -n 1)"
  if [[ -z "$linuxdeploy_bin" ]] && [[ -f /root/.cache/tauri/linuxdeploy-x86_64.AppImage ]]; then
    linuxdeploy_bin="/root/.cache/tauri/linuxdeploy-x86_64.AppImage"
  fi
  [[ -n "$linuxdeploy_bin" ]] && printf '%s\n' "$linuxdeploy_bin"
}

linux_apprun_name_for_target() {
  case "$TAURI_TARGET" in
    x86_64-unknown-linux-gnu) echo "AppRun-x86_64" ;;
    aarch64-unknown-linux-gnu) echo "AppRun-aarch64" ;;
    *) return 1 ;;
  esac
}

extract_deb_members_to_dirs() {
  local deb_path="$1"
  local out_control_dir="$2"
  local out_data_dir="$3"

  command -v ar >/dev/null 2>&1 || return 1
  command -v tar >/dev/null 2>&1 || return 1

  local tmp
  tmp="$(mktemp -d)"

  (
    set -euo pipefail
    mkdir -p "$tmp/in" "$out_control_dir" "$out_data_dir"
    cd "$tmp/in"
    ar x "$deb_path"

    local control_member=""
    local data_member=""
    local candidate
    for candidate in control.tar.gz control.tar.xz control.tar.zst control.tar.bz2 control.tar; do
      if [[ -f "$candidate" ]]; then
        control_member="$candidate"
        break
      fi
    done
    for candidate in data.tar.gz data.tar.xz data.tar.zst data.tar.bz2 data.tar; do
      if [[ -f "$candidate" ]]; then
        data_member="$candidate"
        break
      fi
    done

    [[ -n "$control_member" && -n "$data_member" ]] || exit 1

    tar -xf "$control_member" -C "$out_control_dir"
    tar -xf "$data_member" -C "$out_data_dir"
  ) || {
    rm -rf "$tmp"
    return 1
  }

  rm -rf "$tmp"
}

rebuild_deb_deterministically_in_place() {
  local deb_path="$1"
  command -v ar >/dev/null 2>&1 || return 1
  command -v tar >/dev/null 2>&1 || return 1
  command -v gzip >/dev/null 2>&1 || return 1

  local tmp
  tmp="$(mktemp -d)"
  local control_dir="$tmp/control"
  local data_dir="$tmp/data"
  local repack_dir="$tmp/repack"
  mkdir -p "$control_dir" "$data_dir" "$repack_dir"

  extract_deb_members_to_dirs "$deb_path" "$control_dir" "$data_dir" || {
    rm -rf "$tmp"
    return 1
  }

  normalize_tree_timestamps "$control_dir"
  normalize_tree_timestamps "$data_dir"

  (
    set -euo pipefail
    cd "$control_dir"
    tar --sort=name --mtime="@${SOURCE_DATE_EPOCH}" --owner=0 --group=0 --numeric-owner -cf - . | gzip -n -9 > "$repack_dir/control.tar.gz"
  )
  (
    set -euo pipefail
    cd "$data_dir"
    tar --sort=name --mtime="@${SOURCE_DATE_EPOCH}" --owner=0 --group=0 --numeric-owner -cf - . | gzip -n -9 > "$repack_dir/data.tar.gz"
  )

  printf '2.0\n' > "$repack_dir/debian-binary"

  if ! ( cd "$repack_dir" && ar rcD "$tmp/new.deb" debian-binary control.tar.gz data.tar.gz ); then
    ( cd "$repack_dir" && ar rc "$tmp/new.deb" debian-binary control.tar.gz data.tar.gz )
  fi

  mv -f "$tmp/new.deb" "$deb_path"
  touch -h -d "@${SOURCE_DATE_EPOCH}" "$deb_path" 2>/dev/null || true
  rm -rf "$tmp"
}

rpm_arch_for_target() {
  case "$TAURI_TARGET" in
    x86_64-unknown-linux-gnu) echo "x86_64" ;;
    aarch64-unknown-linux-gnu) echo "aarch64" ;;
    *) echo "${TAURI_TARGET%%-*}" ;;
  esac
}

control_field_value() {
  local field="$1"
  local control_file="$2"
  awk -v k="$field" '
    $0 ~ ("^" k ": ") {
      sub("^" k ": ", "", $0)
      print
      exit
    }
  ' "$control_file"
}

rebuild_rpm_from_deb_deterministically_in_place() {
  local deb_path="$1"
  local rpm_path="$2"
  command -v rpmbuild >/dev/null 2>&1 || return 1

  local tmp
  tmp="$(mktemp -d)"
  local control_dir="$tmp/control"
  local rootfs_dir="$tmp/rootfs"
  mkdir -p "$control_dir" "$rootfs_dir"

  extract_deb_members_to_dirs "$deb_path" "$control_dir" "$rootfs_dir" || {
    rm -rf "$tmp"
    return 1
  }

  normalize_tree_timestamps "$control_dir"
  normalize_tree_timestamps "$rootfs_dir"

  local control_file="$control_dir/control"
  local package_name version_field maintainer_field summary_line description_line
  package_name="$(control_field_value "Package" "$control_file")"
  version_field="$(control_field_value "Version" "$control_file")"
  maintainer_field="$(control_field_value "Maintainer" "$control_file")"
  summary_line="$(control_field_value "Description" "$control_file")"
  description_line="$summary_line"

  [[ -n "$package_name" ]] || package_name="secluso-deploy"
  [[ -n "$version_field" ]] || version_field="0.0.0-1"
  [[ -n "$summary_line" ]] || summary_line="Secluso deploy app"
  [[ -n "$description_line" ]] || description_line="$summary_line"

  summary_line="$(printf '%s' "$summary_line" | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g; s/^ //; s/ $//')"
  description_line="$(printf '%s' "$description_line" | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g; s/^ //; s/ $//')"
  summary_line="${summary_line//%/%%}"
  description_line="${description_line//%/%%}"

  local rpm_version="$version_field"
  local rpm_release="1"
  if [[ "$version_field" == *-* ]]; then
    rpm_version="${version_field%%-*}"
    rpm_release="${version_field#*-}"
  fi
  [[ -n "$rpm_version" ]] || rpm_version="0.0.0"
  [[ -n "$rpm_release" ]] || rpm_release="1"

  local rpm_arch
  rpm_arch="$(rpm_arch_for_target)"

  local topdir="$tmp/rpmbuild"
  mkdir -p "$topdir/BUILD" "$topdir/BUILDROOT" "$topdir/RPMS" "$topdir/SOURCES" "$topdir/SPECS" "$topdir/SRPMS"
  cp -a "$rootfs_dir/." "$topdir/SOURCES/rootfs/"
  normalize_tree_timestamps "$topdir/SOURCES/rootfs"

  {
    echo '%defattr(-,root,root,-)'
    (
      cd "$topdir/SOURCES/rootfs"
      find . -mindepth 1 -print0 | LC_ALL=C sort -z | while IFS= read -r -d '' entry; do
        rel="${entry#./}"
        [[ -n "$rel" ]] || continue
        if [[ -d "$entry" ]]; then
          printf '%%dir /%s\n' "$rel"
        else
          printf '/%s\n' "$rel"
        fi
      done
    )
  } > "$topdir/SOURCES/filelist.txt"

  local spec="$topdir/SPECS/${package_name}.spec"
  cat > "$spec" <<EOF
Name: ${package_name}
Version: ${rpm_version}
Release: ${rpm_release}
Summary: ${summary_line}
License: Proprietary
BuildArch: ${rpm_arch}

%description
${description_line}

%prep

%build

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}
cp -a %{_sourcedir}/rootfs/. %{buildroot}/
find %{buildroot} -mindepth 1 -print0 | xargs -0 touch -h -d "@${SOURCE_DATE_EPOCH}" 2>/dev/null || true

%files -f %{_sourcedir}/filelist.txt

%changelog
* Thu Jan 01 1970 ${maintainer_field:-Secluso Repro Builder <noreply@secluso.invalid>} - ${rpm_version}-${rpm_release}
- Deterministic rebuild
EOF

  RPM_BUILD_NCPUS=1 rpmbuild \
    --quiet \
    --define "_topdir ${topdir}" \
    --define "_buildhost reproducible" \
    --define "_build_id_links none" \
    --define "_source_date_epoch ${SOURCE_DATE_EPOCH}" \
    --define "use_source_date_epoch_as_buildtime 1" \
    --define "clamp_mtime_to_source_date_epoch 1" \
    --define "source_date_epoch_from_changelog 0" \
    --define "_binary_payload w9.gzdio" \
    --define "_build_name_fmt %%{NAME}-%%{VERSION}-%%{RELEASE}.%%{ARCH}.rpm" \
    -bb "$spec"

  local built_rpm=""
  built_rpm="$(find "$topdir/RPMS" -type f -name '*.rpm' | LC_ALL=C sort | head -n 1)"
  [[ -n "$built_rpm" && -f "$built_rpm" ]] || {
    rm -rf "$tmp"
    return 1
  }

  mv -f "$built_rpm" "$rpm_path"
  touch -h -d "@${SOURCE_DATE_EPOCH}" "$rpm_path" 2>/dev/null || true
  rm -rf "$tmp"
}

find_valid_appimage_squashfs_offset() {
  local appimage_path="$1"
  command -v unsquashfs >/dev/null 2>&1 || return 1
  command -v grep >/dev/null 2>&1 || return 1

  local offset
  while IFS=: read -r offset _; do
    [[ "$offset" =~ ^[0-9]+$ ]] || continue
    if unsquashfs -s -o "$offset" "$appimage_path" >/dev/null 2>&1; then
      printf '%s\n' "$offset"
      return 0
    fi
  done < <(grep -oba 'hsqs' "$appimage_path" 2>/dev/null | LC_ALL=C sort -n -t: -k1,1)

  return 1
}

escape_mksquashfs_sort_path() {
  local input="$1"
  local output=""
  local i ch

  # mksquashfs parses each -sort line as "<path> <priority>". It also does not understand shell-style quoting.
  # a path containing spaces/tabs is split into multiple fields unless we escape the whitespace in the generated sort file ourselves.
  #
  # keep -sort enabled on purpose instead of dropping it to "fix" paths with spaces.
  # The sort file is what gives us a deterministic inode/packing order inside the squashfs payload.
  # Removing it would make AppImage layout depend more heavily on traversal order (and would weaken reproducibility)
  # The right fix is therefore to preserve -sort and emit sort-file paths in the exact escaped format mksquashfs expects.
  for (( i = 0; i < ${#input}; i++ )); do
    ch="${input:i:1}"
    case "$ch" in
      [[:space:]]|\\) output+="\\$ch" ;;
      *) output+="$ch" ;;
    esac
  done

  printf '%s' "$output"
}

rebuild_appimage_deterministically_in_place() {
  local appimage_path="$1"
  local appdir="$2"
  command -v mksquashfs >/dev/null 2>&1 || return 1
  command -v unsquashfs >/dev/null 2>&1 || return 1

  normalize_tree_timestamps "$appdir"

  local tmp
  tmp="$(mktemp -d)"
  local staged_appdir="$tmp/appdir.staged"
  local runtime_path=""
  local apprun_name
  apprun_name="$(linux_apprun_name_for_target || true)"
  if [[ -n "$apprun_name" && -x "/root/.cache/tauri/${apprun_name}" ]]; then
    runtime_path="/root/.cache/tauri/${apprun_name}"
  fi

  if [[ -n "$runtime_path" ]]; then
    cp -f "$runtime_path" "$tmp/runtime"
  else
    local fallback_offset=""
    fallback_offset="$(find_valid_appimage_squashfs_offset "$appimage_path" || true)"
    [[ -n "$fallback_offset" ]] || {
      rm -rf "$tmp"
      return 1
    }
    dd if="$appimage_path" of="$tmp/runtime" bs=1 count="$fallback_offset" status=none
  fi

  # Lets re-stage AppDir via sorted tar stream so inode creation order is deterministic
  # across runs before we generate a new squashfs....
  mkdir -p "$staged_appdir"
  (
    cd "$appdir"
    tar \
      --sort=name \
      --mtime="@${SOURCE_DATE_EPOCH}" \
      --owner=0 \
      --group=0 \
      --numeric-owner \
      -cf - .
  ) | (
    cd "$staged_appdir"
    tar -xf -
  )
  normalize_tree_timestamps "$staged_appdir"

  local squash_order="$tmp/squashfs.sort"
  local priority_base=32000
  local rel escaped_rel
  while IFS= read -r rel; do
    [[ -n "$rel" ]] || continue
    escaped_rel="$(escape_mksquashfs_sort_path "$rel")"
    printf '%s %d\n' "$escaped_rel" "$priority_base" >> "$squash_order"
    if (( priority_base > -32000 )); then
      priority_base=$((priority_base - 1))
    fi
  done < <(
    cd "$staged_appdir"
    find . -mindepth 1 -printf '%P\n' | LC_ALL=C sort
  )

  mksquashfs "$staged_appdir" "$tmp/payload.squashfs" \
    -noappend \
    -all-root \
    -root-owned \
    -force-uid 0 \
    -force-gid 0 \
    -processors 1 \
    -no-duplicates \
    -no-fragments \
    -sort "$squash_order" \
    -quiet

  [[ -s "$tmp/payload.squashfs" ]] || {
    rm -rf "$tmp"
    return 1
  }

  local runtime_size
  runtime_size="$(stat -c '%s' "$tmp/runtime")"
  [[ "$runtime_size" =~ ^[0-9]+$ ]] || {
    rm -rf "$tmp"
    return 1
  }

  perl -e 'print pack("Q<", $ARGV[0]);' "$runtime_size" > "$tmp/runtime-offset.bin"
  dd if="$tmp/runtime-offset.bin" of="$tmp/runtime" bs=1 seek=8 conv=notrunc status=none

  local squash_sha id_hex
  squash_sha="$(sha256sum "$tmp/payload.squashfs" 2>/dev/null | awk '{print $1}' || true)"
  [[ -n "$squash_sha" ]] || {
    rm -rf "$tmp"
    return 1
  }
  id_hex="${squash_sha:0:32}"
  if [[ -n "$id_hex" && "$runtime_size" -ge 16 ]]; then
    perl -e 'print pack("H*", $ARGV[0]);' "$id_hex" > "$tmp/runtime-id.bin"
    dd if="$tmp/runtime-id.bin" of="$tmp/runtime" bs=1 seek="$((runtime_size - 16))" conv=notrunc status=none
  fi

  cat "$tmp/runtime" "$tmp/payload.squashfs" > "$tmp/new.AppImage" || {
    rm -rf "$tmp"
    return 1
  }
  chmod +x "$tmp/new.AppImage"

  if ! unsquashfs -s -o "$runtime_size" "$tmp/new.AppImage" >/dev/null 2>&1; then
    rm -rf "$tmp"
    return 1
  fi

  mv -f "$tmp/new.AppImage" "$appimage_path"
  touch -h -d "@${SOURCE_DATE_EPOCH}" "$appimage_path" 2>/dev/null || true
  rm -rf "$tmp"
}

canonicalize_linux_bundle_outputs_deterministically() {
  [[ "$TAURI_TARGET" == *"-unknown-linux-"* ]] || return 0

  case "${SECLUSO_CANONICALIZE_LINUX_BUNDLES:-1}" in
    0|false|FALSE|no|NO|off|OFF)
      echo "==> deterministic linux bundle canonicalization disabled (SECLUSO_CANONICALIZE_LINUX_BUNDLES=0)"
      return 0
      ;;
  esac

  local bundle_root="/app/deploy/src-tauri/target/${TAURI_TARGET}/release/bundle"
  [[ -d "$bundle_root" ]] || return 0

  echo "==> deterministic linux bundle canonicalization (single-pass)"

  local deb_path=""
  deb_path="$(find "$bundle_root/deb" -maxdepth 1 -type f -name '*.deb' 2>/dev/null | LC_ALL=C sort | head -n 1)"
  if [[ -n "$deb_path" ]]; then
    echo "==> canonicalizing deb: $deb_path"
    rebuild_deb_deterministically_in_place "$deb_path" || {
      echo "==> error: deterministic deb canonicalization failed: $deb_path" >&2
      return 1
    }
  fi

  local rpm_path
  while IFS= read -r rpm_path; do
    [[ -n "$rpm_path" ]] || continue
    if [[ -n "$deb_path" && -f "$deb_path" ]]; then
      echo "==> canonicalizing rpm from deb payload: $rpm_path"
      rebuild_rpm_from_deb_deterministically_in_place "$deb_path" "$rpm_path" || {
        echo "==> error: deterministic rpm canonicalization failed: $rpm_path" >&2
        return 1
      }
    else
      echo "==> warning: rpm canonicalization skipped (no deb payload available): $rpm_path" >&2
    fi
  done < <(find "$bundle_root/rpm" -maxdepth 1 -type f -name '*.rpm' 2>/dev/null | LC_ALL=C sort)

  local appdir=""
  appdir="$(find "$bundle_root/appimage" -maxdepth 1 -type d -name '*.AppDir' 2>/dev/null | LC_ALL=C sort | head -n 1)"
  local appimage_path
  while IFS= read -r appimage_path; do
    [[ -n "$appimage_path" ]] || continue
    if [[ -n "$appdir" && -d "$appdir" ]]; then
      echo "==> canonicalizing appimage: $appimage_path"
      rebuild_appimage_deterministically_in_place "$appimage_path" "$appdir" || {
        echo "==> error: deterministic appimage canonicalization failed: $appimage_path" >&2
        return 1
      }
    else
      echo "==> warning: appimage canonicalization skipped (AppDir missing): $appimage_path" >&2
    fi
  done < <(find "$bundle_root/appimage" -maxdepth 1 -type f \( -name '*.AppImage' -o -name '*.appimage' \) 2>/dev/null | LC_ALL=C sort)
}

resolve_libfaketime_so() {
  local lib=""

  if command -v dpkg-query >/dev/null 2>&1; then
    lib="$(dpkg-query -L libfaketime 2>/dev/null | awk '/libfaketime\.so(\.1)?$/ { print; exit }')"
  fi

  if [[ -z "$lib" ]]; then
    local candidate
    for candidate in \
      /usr/lib/*/faketime/libfaketime.so.1 \
      /usr/lib/*/faketime/libfaketime.so \
      /usr/lib/faketime/libfaketime.so.1 \
      /usr/lib/faketime/libfaketime.so
    do
      if [[ -f "$candidate" ]]; then
        lib="$candidate"
        break
      fi
    done
  fi

  [[ -n "$lib" ]] && printf '%s\n' "$lib"
}

run_with_faketime_if_enabled() {
  local run_cmd=("$@")

  # AppImage embeds squashfs payloads and upstream tools can default to
  # multi-core compression, but this is not good as they're not byte-stable across runs.
  if [[ "$TAURI_TARGET" == *"-unknown-linux-"* ]] \
    && [[ "${SECLUSO_FORCE_SINGLE_CPU_PACKAGING:-1}" != "0" ]] \
    && command -v taskset >/dev/null 2>&1; then
    echo "==> enforcing single-CPU affinity for linux packaging (taskset -c 0)"
    run_cmd=(taskset -c 0 "${run_cmd[@]}")
  fi

  if [[ "$TAURI_TARGET" == *"-unknown-linux-"* ]]; then
    local faketime_lib=""
    local faketime_value=""
    faketime_lib="$(resolve_libfaketime_so || true)"

    if [[ -z "$faketime_lib" ]]; then
      echo "==> error: libfaketime is required for linux packaging but was not found" >&2
      return 1
    fi

    # libfaketime does not accept raw epoch format like "@1704067200".
    # Convert SOURCE_DATE_EPOCH to a concrete UTC datetime.
    if ! faketime_value="$(date -u -d "@${SOURCE_DATE_EPOCH}" "+%Y-%m-%d %H:%M:%S" 2>/dev/null)"; then
      faketime_value="$(date -u -r "${SOURCE_DATE_EPOCH}" "+%Y-%m-%d %H:%M:%S" 2>/dev/null || true)"
    fi
    if [[ -z "$faketime_value" ]]; then
      echo "==> error: could not format SOURCE_DATE_EPOCH for libfaketime" >&2
      return 1
    fi

    echo "==> enabling libfaketime for linux bundling (SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}, mode=fixed-clock)"
    env \
      LD_PRELOAD="${LD_PRELOAD:+${LD_PRELOAD}:}${faketime_lib}" \
      FAKETIME="@${faketime_value}" \
      DONT_FAKE_MONOTONIC=1 \
      "${run_cmd[@]}"
    return
  fi

  "${run_cmd[@]}"
}

dump_bundle_failure_context() {
  local bundle_log="${1:-}"
  if [[ -n "$bundle_log" && -f "$bundle_log" ]]; then
    echo "==> tauri bundle log highlights"
    if command -v rg >/dev/null 2>&1; then
      rg -n -C 6 'No such file or directory|linuxdeploy|AppImage|plugin|os error|failed to run|ENOENT|desktop-file|mksquashfs' "$bundle_log" || true
    else
      grep -nE 'No such file or directory|linuxdeploy|AppImage|plugin|os error|failed to run|ENOENT|desktop-file|mksquashfs' "$bundle_log" || true
    fi
    echo "==> tauri bundle log tail"
    tail -n 220 "$bundle_log" || true
  fi
  dump_packaging_wrapper_logs
  dump_linux_bundle_artifact_forensics
}

run_tauri_bundle_with_faketime_linux() {
  echo "==> linux deterministic mode: compile without bundling, then bundle under faketime"
  local bundle_log="/tmp/tauri-bundle.log"
  rm -f "$bundle_log"

  pnpm tauri build \
    -v -v \
    --target "${TAURI_TARGET}" \
    --runner "${TAURI_RUNNER}" \
    --config /tmp/tauri-bundle-config.json \
    --ci \
    --no-sign \
    --no-bundle \
    -- \
    --locked

  normalize_linux_bundle_inputs_once

  if ! run_with_faketime_if_enabled \
    pnpm tauri bundle \
    -v -v \
    --target "${TAURI_TARGET}" \
    --config /tmp/tauri-bundle-config.json \
    --ci \
    --no-sign \
    2>&1 | tee "$bundle_log"; then
    echo "==> tauri bundle failed under libfaketime"
    dump_bundle_failure_context "$bundle_log"
    return 1
  fi

  if ! canonicalize_linux_bundle_outputs_deterministically; then
    echo "==> deterministic linux bundle canonicalization failed"
    dump_bundle_failure_context "$bundle_log"
    return 1
  fi
  if is_debug_enabled; then
    dump_packaging_wrapper_logs
    dump_linux_bundle_artifact_forensics
  fi
}

setup_windows_makensis_wrapper() {
  [[ "$TAURI_TARGET" == *"-pc-windows-"* ]] || return

  local real_makensis
  real_makensis="$(command -v makensis || true)"
  [[ -n "$real_makensis" ]] || return

  local wrapper_dir="/tmp/secluso-tool-overrides"
  local wrapper_path="$wrapper_dir/makensis"
  mkdir -p "$wrapper_dir"

  cat > "$wrapper_path" <<EOF
#!/bin/bash
set -euo pipefail
: "\${SOURCE_DATE_EPOCH:=1704067200}"
: "\${TAURI_TARGET:=x86_64-pc-windows-msvc}"

release_dir="/app/deploy/src-tauri/target/\${TAURI_TARGET}/release"
if [[ -d "\$release_dir" ]]; then
  if [[ -f "\$release_dir/secluso-deploy.exe" ]]; then
    if command -v llvm-strip >/dev/null 2>&1; then
      if llvm-strip --strip-debug "\$release_dir/secluso-deploy.exe" \
        || llvm-strip -g "\$release_dir/secluso-deploy.exe"; then
        touch -h -d "@\${SOURCE_DATE_EPOCH}" "\$release_dir/secluso-deploy.exe" 2>/dev/null || true
        echo "==> stripped debug from secluso-deploy.exe for reproducibility"
      else
        echo "==> warning: llvm-strip failed for secluso-deploy.exe; continuing without strip" >&2
      fi
    fi
  fi

  while IFS= read -r -d '' path; do
    touch -h -d "@\${SOURCE_DATE_EPOCH}" -- "\$path" 2>/dev/null || true
  done < <(find "\$release_dir" -mindepth 1 -print0 2>/dev/null | LC_ALL=C sort -z)
fi
touch -h -d "@\${SOURCE_DATE_EPOCH}" /root/.cache/tauri/nsis_tauri_utils.dll 2>/dev/null || true

snapshot_dir="\$release_dir/repro/windows-pre-nsis"
mkdir -p "\$snapshot_dir"
snapshot_file="\$snapshot_dir/input-manifest.tsv"
{
  printf 'type\tmode_hex\tmtime_epoch\tsize_bytes\tsha256\trel_path\n'

  while IFS= read -r -d '' path; do
    rel="\${path#\$release_dir/}"
    mode_hex="\$(stat -c '%f' -- "\$path" 2>/dev/null || echo '-')"
    mtime_epoch="\$(stat -c '%Y' -- "\$path" 2>/dev/null || echo '-')"
    size_bytes="\$(stat -c '%s' -- "\$path" 2>/dev/null || echo '-')"
    sha256="\$(sha256sum -- "\$path" 2>/dev/null | awk '{print \$1}')"
    printf 'file\t%s\t%s\t%s\t%s\t%s\n' "\$mode_hex" "\$mtime_epoch" "\$size_bytes" "\$sha256" "\$rel"
  done < <(find "\$release_dir/nsis" -type f -print0 2>/dev/null | LC_ALL=C sort -z)

  while IFS= read -r -d '' path; do
    rel="\${path#\$release_dir/}"
    mode_hex="\$(stat -c '%f' -- "\$path" 2>/dev/null || echo '-')"
    mtime_epoch="\$(stat -c '%Y' -- "\$path" 2>/dev/null || echo '-')"
    printf 'dir\t%s\t%s\t-\t-\t%s\n' "\$mode_hex" "\$mtime_epoch" "\$rel"
  done < <(find "\$release_dir/nsis" -type d -print0 2>/dev/null | LC_ALL=C sort -z)

  if [[ -f "\$release_dir/secluso-deploy.exe" ]]; then
    mode_hex="\$(stat -c '%f' -- "\$release_dir/secluso-deploy.exe" 2>/dev/null || echo '-')"
    mtime_epoch="\$(stat -c '%Y' -- "\$release_dir/secluso-deploy.exe" 2>/dev/null || echo '-')"
    size_bytes="\$(stat -c '%s' -- "\$release_dir/secluso-deploy.exe" 2>/dev/null || echo '-')"
    sha256="\$(sha256sum -- "\$release_dir/secluso-deploy.exe" 2>/dev/null | awk '{print \$1}')"
    printf 'file\t%s\t%s\t%s\t%s\t%s\n' "\$mode_hex" "\$mtime_epoch" "\$size_bytes" "\$sha256" "secluso-deploy.exe"
  fi
} > "\$snapshot_file"

exec "${real_makensis}" "\$@"
EOF

  chmod +x "$wrapper_path"
  export PATH="$wrapper_dir:$PATH"
}

setup_windows_arm64_clang_wrapper() {
  [[ "$TAURI_TARGET" == "aarch64-pc-windows-msvc" ]] || return
  [[ "${TAURI_RUNNER:-}" == "cargo-xwin" ]] || return

  local wrapper_dir="/tmp/secluso-tool-overrides"
  local clang_wrapper="$wrapper_dir/clang"
  local clang_cl_wrapper="$wrapper_dir/clang-cl"
  local real_clang
  local real_clang_escaped
  real_clang="$(type -P clang || true)"
  [[ -n "$real_clang" && -x "$real_clang" ]] || {
    echo "Unable to resolve real clang binary for arm64 windows wrapper" >&2
    exit 1
  }
  printf -v real_clang_escaped '%q' "$real_clang"
  mkdir -p "$wrapper_dir"

  cat > "$clang_wrapper" <<EOF
#!/bin/bash
set -euo pipefail

real_clang=${real_clang_escaped}

translated=()
while [[ "\$#" -gt 0 ]]; do
  case "\$1" in
    /imsvc)
      shift
      [[ "\$#" -gt 0 ]] || break
      translated+=("-isystem" "\$1")
      ;;
    *)
      translated+=("\$1")
      ;;
  esac
  shift
done

exec "\$real_clang" "\${translated[@]}"
EOF

  cat > "$clang_cl_wrapper" <<EOF
#!/bin/bash
set -euo pipefail

real_clang=${real_clang_escaped}

# Emulate clang-cl when cargo-xwin expects a clang-cl executable in PATH.
exec "\$real_clang" --driver-mode=cl "\$@"
EOF

  chmod +x "$clang_wrapper" "$clang_cl_wrapper"

  export PATH="$wrapper_dir:$PATH"
  hash -r
  command -v clang >/dev/null 2>&1 || {
    echo "clang wrapper not found in PATH after setup" >&2
    exit 1
  }
  command -v clang-cl >/dev/null 2>&1 || {
    echo "clang-cl wrapper not found in PATH after setup" >&2
    exit 1
  }
  "$clang_wrapper" --version >/dev/null 2>&1 || {
    echo "clang wrapper self-test failed" >&2
    "$clang_wrapper" --version || true
    exit 1
  }
  "$clang_cl_wrapper" --version >/dev/null 2>&1 || {
    echo "clang-cl wrapper self-test failed" >&2
    "$clang_cl_wrapper" --version || true
    exit 1
  }
  echo "==> arm64 windows clang wrapper active (real clang: $real_clang)"

  # cargo-xwin injects /imsvc-style include args, but ring/cc-rs still shells
  # out to "clang" for some arm64 Windows C objects. Intercept clang at PATH
  # level and normalize /imsvc include pairs to clang-compatible flags.
}

install_tool_wrapper_in_place() {
  local tool_path="$1"
  local wrapper_src="$2"
  local tool_backup="${tool_path}.secluso-real"

  [[ -n "$tool_path" && -n "$wrapper_src" ]] || return 1
  [[ -f "$wrapper_src" ]] || return 1
  [[ -e "$tool_path" ]] || return 1

  if [[ ! -e "$tool_backup" ]]; then
    mv -f "$tool_path" "$tool_backup"
  fi

  cp -f "$wrapper_src" "$tool_path"
  chmod +x "$tool_path"
  printf '%s\n' "$tool_backup"
}

setup_linux_mksquashfs_wrapper() {
  [[ "$TAURI_TARGET" == *"-unknown-linux-"* ]] || return

  local real_mksquashfs
  real_mksquashfs="$(command -v mksquashfs || true)"
  [[ -n "$real_mksquashfs" ]] || return

  local wrapper_dir="/tmp/secluso-tool-overrides"
  local wrapper_path="$wrapper_dir/mksquashfs"
  local wrapper_target="$real_mksquashfs"
  local wrapped_real_mksquashfs="$real_mksquashfs"
  local real_mksquashfs_escaped
  mkdir -p "$wrapper_dir"

  # appimagetool frequently invokes /usr/bin/mksquashfs directly, which is bypassing PATH.
  # Replace the real path in-place so absolute execs are intercepted too
  if [[ -w "$wrapper_target" && -w "$(dirname "$wrapper_target")" ]]; then
    local backup_path
    backup_path="${wrapper_target}.secluso-real"
    wrapped_real_mksquashfs="$backup_path"
  fi
  printf -v real_mksquashfs_escaped '%q' "$wrapped_real_mksquashfs"

  cat > "$wrapper_path" <<EOF
#!/bin/bash
set -euo pipefail

real_mksquashfs=${real_mksquashfs_escaped}
filtered_args=()
skip_next=0

for arg in "\$@"; do
  if [[ "\$skip_next" -eq 1 ]]; then
    skip_next=0
    continue
  fi
  case "\$arg" in
    -processors)
      skip_next=1
      ;;
    -processors=*)
      ;;
    *)
      filtered_args+=("\$arg")
      ;;
  esac
done

extra=()
# Force single-thread squashfs output for deterministic block ordering.
extra+=("-processors" "1")
# Do not add -all-time/-mkfs-time here... mksquashfs seems to already honors
# SOURCE_DATE_EPOCH and rejects mixed env plus CLI timestamp sources.

if [[ -n "\${SECLUSO_MKSQUASHFS_WRAPPER_LOG:-}" ]]; then
  {
    printf 'ts=%s cmd=%s args=' "\$(date -u +%Y-%m-%dT%H:%M:%SZ)" "\$real_mksquashfs"
    printf '%q ' "\${filtered_args[@]}"
    printf ' extra='
    printf '%q ' "\${extra[@]}"
    printf '\n'
  } >> "\${SECLUSO_MKSQUASHFS_WRAPPER_LOG}" 2>/dev/null || true
fi

exec "\$real_mksquashfs" "\${filtered_args[@]}" "\${extra[@]}"
EOF

  chmod +x "$wrapper_path"

  if [[ "$wrapped_real_mksquashfs" != "$wrapper_target" ]]; then
    local installed_real
    installed_real="$(install_tool_wrapper_in_place "$wrapper_target" "$wrapper_path" || true)"
    if [[ -n "$installed_real" ]]; then
      wrapped_real_mksquashfs="$installed_real"
      printf -v real_mksquashfs_escaped '%q' "$wrapped_real_mksquashfs"
      cat > "$wrapper_path" <<EOF
#!/bin/bash
set -euo pipefail

real_mksquashfs=${real_mksquashfs_escaped}
filtered_args=()
skip_next=0

for arg in "\$@"; do
  if [[ "\$skip_next" -eq 1 ]]; then
    skip_next=0
    continue
  fi
  case "\$arg" in
    -processors)
      skip_next=1
      ;;
    -processors=*)
      ;;
    *)
      filtered_args+=("\$arg")
      ;;
  esac
done

extra=("-processors" "1")
# Do not add -all-time/-mkfs-time here... mksquashfs already honors
# SOURCE_DATE_EPOCH and rejects mixed env plus CLI timestamp sources...

if [[ -n "\${SECLUSO_MKSQUASHFS_WRAPPER_LOG:-}" ]]; then
  {
    printf 'ts=%s cmd=%s args=' "\$(date -u +%Y-%m-%dT%H:%M:%SZ)" "\$real_mksquashfs"
    printf '%q ' "\${filtered_args[@]}"
    printf ' extra='
    printf '%q ' "\${extra[@]}"
    printf '\n'
  } >> "\${SECLUSO_MKSQUASHFS_WRAPPER_LOG}" 2>/dev/null || true
fi

exec "\$real_mksquashfs" "\${filtered_args[@]}" "\${extra[@]}"
EOF
      chmod +x "$wrapper_path"
      cp -f "$wrapper_path" "$wrapper_target"
      chmod +x "$wrapper_target"
    fi
  fi

  export PATH="$wrapper_dir:$PATH"
  hash -r
  export SECLUSO_MKSQUASHFS_WRAPPER_LOG="/tmp/mksquashfs-wrapper.log"
  : > "$SECLUSO_MKSQUASHFS_WRAPPER_LOG"
  echo "==> linux mksquashfs wrapper active (real: $wrapped_real_mksquashfs, target: $wrapper_target)"
}

setup_linux_dpkg_deb_wrapper() {
  [[ "$TAURI_TARGET" == *"-unknown-linux-"* ]] || return

  local real_dpkg_deb
  real_dpkg_deb="$(command -v dpkg-deb || true)"
  [[ -n "$real_dpkg_deb" ]] || return

  local wrapper_dir="/tmp/secluso-tool-overrides"
  local wrapper_path="$wrapper_dir/dpkg-deb"
  local wrapper_target="$real_dpkg_deb"
  local wrapped_real_dpkg_deb="$real_dpkg_deb"
  local real_dpkg_deb_escaped
  mkdir -p "$wrapper_dir"

  if [[ -w "$wrapper_target" && -w "$(dirname "$wrapper_target")" ]]; then
    local backup_path
    backup_path="${wrapper_target}.secluso-real"
    wrapped_real_dpkg_deb="$backup_path"
  fi
  printf -v real_dpkg_deb_escaped '%q' "$wrapped_real_dpkg_deb"

  cat > "$wrapper_path" <<EOF
#!/bin/bash
set -euo pipefail

real_dpkg_deb=${real_dpkg_deb_escaped}
log_file="/tmp/dpkg-deb-wrapper.log"
: "\${SOURCE_DATE_EPOCH:=1704067200}"

log_line() {
  {
    printf 'ts=%s pid=%s %s\n' "\$(date -u +%Y-%m-%dT%H:%M:%SZ)" "\$\$" "\$*"
  } >> "\$log_file" 2>/dev/null || true
}

emit_tree_stats() {
  local root="\$1"
  local label="\$2"
  [[ -d "\$root" ]] || {
    log_line "\${label}: root_missing=\$root"
    return
  }

  local files dirs links min_mtime max_mtime
  files="\$(find "\$root" -type f 2>/dev/null | wc -l | tr -d ' ')"
  dirs="\$(find "\$root" -type d 2>/dev/null | wc -l | tr -d ' ')"
  links="\$(find "\$root" -type l 2>/dev/null | wc -l | tr -d ' ')"
  min_mtime="\$(find "\$root" -mindepth 1 -printf '%T@\n' 2>/dev/null | LC_ALL=C sort -n | head -n 1 | cut -d. -f1)"
  max_mtime="\$(find "\$root" -mindepth 1 -printf '%T@\n' 2>/dev/null | LC_ALL=C sort -n | tail -n 1 | cut -d. -f1)"
  log_line "\${label}: root=\$root files=\${files:-0} dirs=\${dirs:-0} symlinks=\${links:-0} mtime_min_epoch=\${min_mtime:-na} mtime_max_epoch=\${max_mtime:-na}"
}

normalize_tree_timestamps() {
  local root="\$1"
  [[ -d "\$root" ]] || return 0
  while IFS= read -r -d '' path; do
    touch -h -d "@\${SOURCE_DATE_EPOCH}" -- "\$path" 2>/dev/null || true
  done < <(find "\$root" -mindepth 0 -print0 2>/dev/null | LC_ALL=C sort -z)
}

build_root=""
prev=""
for arg in "\$@"; do
  case "\$arg" in
    --build=*) build_root="\${arg#--build=}" ;;
    -b=*) build_root="\${arg#-b=}" ;;
    *)
      if [[ "\$prev" == "--build" || "\$prev" == "-b" ]]; then
        build_root="\$arg"
      fi
      ;;
  esac
  prev="\$arg"
done

log_line "exec cmd=\$real_dpkg_deb args=\$* source_date_epoch=\${SOURCE_DATE_EPOCH}"

if [[ -n "\$build_root" && -d "\$build_root" ]]; then
  emit_tree_stats "\$build_root" "pre-normalize-build-root"
  normalize_tree_timestamps "\$build_root"
  emit_tree_stats "\$build_root" "post-normalize-build-root"
fi

set +e
"\$real_dpkg_deb" "\$@"
status=\$?
set -e

log_line "exit status=\$status"
if [[ -n "\$build_root" && -d "\$build_root" ]]; then
  emit_tree_stats "\$build_root" "post-build-build-root"
fi

exit "\$status"
EOF

  chmod +x "$wrapper_path"

  if [[ "$wrapped_real_dpkg_deb" != "$wrapper_target" ]]; then
    local installed_real
    installed_real="$(install_tool_wrapper_in_place "$wrapper_target" "$wrapper_path" || true)"
    if [[ -n "$installed_real" ]]; then
      wrapped_real_dpkg_deb="$installed_real"
      printf -v real_dpkg_deb_escaped '%q' "$wrapped_real_dpkg_deb"
      cat > "$wrapper_path" <<EOF
#!/bin/bash
set -euo pipefail

real_dpkg_deb=${real_dpkg_deb_escaped}
log_file="/tmp/dpkg-deb-wrapper.log"
: "\${SOURCE_DATE_EPOCH:=1704067200}"

log_line() {
  {
    printf 'ts=%s pid=%s %s\n' "\$(date -u +%Y-%m-%dT%H:%M:%SZ)" "\$\$" "\$*"
  } >> "\$log_file" 2>/dev/null || true
}

emit_tree_stats() {
  local root="\$1"
  local label="\$2"
  [[ -d "\$root" ]] || {
    log_line "\${label}: root_missing=\$root"
    return
  }

  local files dirs links min_mtime max_mtime
  files="\$(find "\$root" -type f 2>/dev/null | wc -l | tr -d ' ')"
  dirs="\$(find "\$root" -type d 2>/dev/null | wc -l | tr -d ' ')"
  links="\$(find "\$root" -type l 2>/dev/null | wc -l | tr -d ' ')"
  min_mtime="\$(find "\$root" -mindepth 1 -printf '%T@\n' 2>/dev/null | LC_ALL=C sort -n | head -n 1 | cut -d. -f1)"
  max_mtime="\$(find "\$root" -mindepth 1 -printf '%T@\n' 2>/dev/null | LC_ALL=C sort -n | tail -n 1 | cut -d. -f1)"
  log_line "\${label}: root=\$root files=\${files:-0} dirs=\${dirs:-0} symlinks=\${links:-0} mtime_min_epoch=\${min_mtime:-na} mtime_max_epoch=\${max_mtime:-na}"
}

normalize_tree_timestamps() {
  local root="\$1"
  [[ -d "\$root" ]] || return 0
  while IFS= read -r -d '' path; do
    touch -h -d "@\${SOURCE_DATE_EPOCH}" -- "\$path" 2>/dev/null || true
  done < <(find "\$root" -mindepth 0 -print0 2>/dev/null | LC_ALL=C sort -z)
}

build_root=""
prev=""
for arg in "\$@"; do
  case "\$arg" in
    --build=*) build_root="\${arg#--build=}" ;;
    -b=*) build_root="\${arg#-b=}" ;;
    *)
      if [[ "\$prev" == "--build" || "\$prev" == "-b" ]]; then
        build_root="\$arg"
      fi
      ;;
  esac
  prev="\$arg"
done

log_line "exec cmd=\$real_dpkg_deb args=\$* source_date_epoch=\${SOURCE_DATE_EPOCH}"

if [[ -n "\$build_root" && -d "\$build_root" ]]; then
  emit_tree_stats "\$build_root" "pre-normalize-build-root"
  normalize_tree_timestamps "\$build_root"
  emit_tree_stats "\$build_root" "post-normalize-build-root"
fi

set +e
"\$real_dpkg_deb" "\$@"
status=\$?
set -e

log_line "exit status=\$status"
if [[ -n "\$build_root" && -d "\$build_root" ]]; then
  emit_tree_stats "\$build_root" "post-build-build-root"
fi

exit "\$status"
EOF
      chmod +x "$wrapper_path"
      cp -f "$wrapper_path" "$wrapper_target"
      chmod +x "$wrapper_target"
    fi
  fi

  export PATH="$wrapper_dir:$PATH"
  hash -r
  export SECLUSO_DPKG_DEB_WRAPPER_LOG="/tmp/dpkg-deb-wrapper.log"
  : > "$SECLUSO_DPKG_DEB_WRAPPER_LOG"
  echo "==> linux dpkg-deb wrapper active (real: $wrapped_real_dpkg_deb, target: $wrapper_target)"
}

setup_linux_rpmbuild_wrapper() {
  [[ "$TAURI_TARGET" == *"-unknown-linux-"* ]] || return

  local real_rpmbuild
  real_rpmbuild="$(command -v rpmbuild || true)"
  [[ -n "$real_rpmbuild" ]] || return

  local wrapper_dir="/tmp/secluso-tool-overrides"
  local wrapper_path="$wrapper_dir/rpmbuild"
  local wrapper_target="$real_rpmbuild"
  local wrapped_real_rpmbuild="$real_rpmbuild"
  local real_rpmbuild_escaped
  mkdir -p "$wrapper_dir"

  if [[ -w "$wrapper_target" && -w "$(dirname "$wrapper_target")" ]]; then
    local backup_path
    backup_path="${wrapper_target}.secluso-real"
    wrapped_real_rpmbuild="$backup_path"
  fi
  printf -v real_rpmbuild_escaped '%q' "$wrapped_real_rpmbuild"

  cat > "$wrapper_path" <<EOF
#!/bin/bash
set -euo pipefail

real_rpmbuild=${real_rpmbuild_escaped}
log_file="/tmp/rpmbuild-wrapper.log"
: "\${SOURCE_DATE_EPOCH:=1704067200}"

log_line() {
  {
    printf 'ts=%s pid=%s %s\n' "\$(date -u +%Y-%m-%dT%H:%M:%SZ)" "\$\$" "\$*"
  } >> "\$log_file" 2>/dev/null || true
}

emit_tree_stats() {
  local root="\$1"
  local label="\$2"
  [[ -d "\$root" ]] || {
    log_line "\${label}: root_missing=\$root"
    return
  }

  local files dirs links min_mtime max_mtime
  files="\$(find "\$root" -type f 2>/dev/null | wc -l | tr -d ' ')"
  dirs="\$(find "\$root" -type d 2>/dev/null | wc -l | tr -d ' ')"
  links="\$(find "\$root" -type l 2>/dev/null | wc -l | tr -d ' ')"
  min_mtime="\$(find "\$root" -mindepth 1 -printf '%T@\n' 2>/dev/null | LC_ALL=C sort -n | head -n 1 | cut -d. -f1)"
  max_mtime="\$(find "\$root" -mindepth 1 -printf '%T@\n' 2>/dev/null | LC_ALL=C sort -n | tail -n 1 | cut -d. -f1)"
  log_line "\${label}: root=\$root files=\${files:-0} dirs=\${dirs:-0} symlinks=\${links:-0} mtime_min_epoch=\${min_mtime:-na} mtime_max_epoch=\${max_mtime:-na}"
}

normalize_tree_timestamps() {
  local root="\$1"
  [[ -d "\$root" ]] || return 0
  while IFS= read -r -d '' path; do
    touch -h -d "@\${SOURCE_DATE_EPOCH}" -- "\$path" 2>/dev/null || true
  done < <(find "\$root" -mindepth 0 -print0 2>/dev/null | LC_ALL=C sort -z)
}

topdir=""
buildroot=""
want_define=0
want_buildroot=0

for arg in "\$@"; do
  if [[ "\$want_define" -eq 1 ]]; then
    def="\$arg"
    want_define=0
  else
    case "\$arg" in
      --define)
        want_define=1
        continue
        ;;
      --define=*)
        def="\${arg#--define=}"
        ;;
      --buildroot)
        want_buildroot=1
        continue
        ;;
      --buildroot=*)
        buildroot="\${arg#--buildroot=}"
        continue
        ;;
      *)
        if [[ "\$want_buildroot" -eq 1 ]]; then
          buildroot="\$arg"
          want_buildroot=0
        fi
        continue
        ;;
    esac
  fi

  case "\${def:-}" in
    _topdir\ *)
      topdir="\${def#_topdir }"
      ;;
  esac
  def=""
done

if [[ -z "\$buildroot" && -n "\$topdir" && -d "\$topdir/BUILDROOT" ]]; then
  buildroot="\$topdir/BUILDROOT"
fi

if [[ -n "\$buildroot" && -d "\$buildroot" ]]; then
  emit_tree_stats "\$buildroot" "pre-normalize-buildroot"
  normalize_tree_timestamps "\$buildroot"
  emit_tree_stats "\$buildroot" "post-normalize-buildroot"
fi

extra_defines=(
  --define "_buildhost reproducible"
  --define "_source_date_epoch \${SOURCE_DATE_EPOCH}"
  --define "use_source_date_epoch_as_buildtime 1"
  --define "clamp_mtime_to_source_date_epoch 1"
  --define "source_date_epoch_from_changelog 0"
)

log_line "exec cmd=\$real_rpmbuild args=\$* source_date_epoch=\${SOURCE_DATE_EPOCH} topdir=\${topdir:-<none>} buildroot=\${buildroot:-<none>}"
log_line "extra_defines=\${extra_defines[*]}"

set +e
RPM_BUILD_NCPUS=1 "\$real_rpmbuild" "\${extra_defines[@]}" "\$@"
status=\$?
set -e

log_line "exit status=\$status"
if [[ -n "\$buildroot" && -d "\$buildroot" ]]; then
  emit_tree_stats "\$buildroot" "post-build-buildroot"
fi
if [[ -n "\$topdir" && -d "\$topdir/RPMS" ]]; then
  while IFS= read -r rpm_file; do
    [[ -n "\$rpm_file" ]] || continue
    rpm_sha="\$(sha256sum "\$rpm_file" | awk '{print \$1}')"
    log_line "rpm_output=\$rpm_file sha256=\$rpm_sha"
    if command -v rpm >/dev/null 2>&1; then
      rpm -qp --qf 'name=%{NAME} version=%{VERSION} release=%{RELEASE} buildtime=%{BUILDTIME} buildhost=%{BUILDHOST}\n' "\$rpm_file" >> "\$log_file" 2>/dev/null || true
    fi
  done < <(find "\$topdir/RPMS" -type f -name '*.rpm' 2>/dev/null | LC_ALL=C sort)
fi

exit "\$status"
EOF

  chmod +x "$wrapper_path"

  if [[ "$wrapped_real_rpmbuild" != "$wrapper_target" ]]; then
    local installed_real
    installed_real="$(install_tool_wrapper_in_place "$wrapper_target" "$wrapper_path" || true)"
    if [[ -n "$installed_real" ]]; then
      wrapped_real_rpmbuild="$installed_real"
      printf -v real_rpmbuild_escaped '%q' "$wrapped_real_rpmbuild"
      cat > "$wrapper_path" <<EOF
#!/bin/bash
set -euo pipefail

real_rpmbuild=${real_rpmbuild_escaped}
log_file="/tmp/rpmbuild-wrapper.log"
: "\${SOURCE_DATE_EPOCH:=1704067200}"

log_line() {
  {
    printf 'ts=%s pid=%s %s\n' "\$(date -u +%Y-%m-%dT%H:%M:%SZ)" "\$\$" "\$*"
  } >> "\$log_file" 2>/dev/null || true
}

emit_tree_stats() {
  local root="\$1"
  local label="\$2"
  [[ -d "\$root" ]] || {
    log_line "\${label}: root_missing=\$root"
    return
  }

  local files dirs links min_mtime max_mtime
  files="\$(find "\$root" -type f 2>/dev/null | wc -l | tr -d ' ')"
  dirs="\$(find "\$root" -type d 2>/dev/null | wc -l | tr -d ' ')"
  links="\$(find "\$root" -type l 2>/dev/null | wc -l | tr -d ' ')"
  min_mtime="\$(find "\$root" -mindepth 1 -printf '%T@\n' 2>/dev/null | LC_ALL=C sort -n | head -n 1 | cut -d. -f1)"
  max_mtime="\$(find "\$root" -mindepth 1 -printf '%T@\n' 2>/dev/null | LC_ALL=C sort -n | tail -n 1 | cut -d. -f1)"
  log_line "\${label}: root=\$root files=\${files:-0} dirs=\${dirs:-0} symlinks=\${links:-0} mtime_min_epoch=\${min_mtime:-na} mtime_max_epoch=\${max_mtime:-na}"
}

normalize_tree_timestamps() {
  local root="\$1"
  [[ -d "\$root" ]] || return 0
  while IFS= read -r -d '' path; do
    touch -h -d "@\${SOURCE_DATE_EPOCH}" -- "\$path" 2>/dev/null || true
  done < <(find "\$root" -mindepth 0 -print0 2>/dev/null | LC_ALL=C sort -z)
}

topdir=""
buildroot=""
want_define=0
want_buildroot=0

for arg in "\$@"; do
  if [[ "\$want_define" -eq 1 ]]; then
    def="\$arg"
    want_define=0
  else
    case "\$arg" in
      --define)
        want_define=1
        continue
        ;;
      --define=*)
        def="\${arg#--define=}"
        ;;
      --buildroot)
        want_buildroot=1
        continue
        ;;
      --buildroot=*)
        buildroot="\${arg#--buildroot=}"
        continue
        ;;
      *)
        if [[ "\$want_buildroot" -eq 1 ]]; then
          buildroot="\$arg"
          want_buildroot=0
        fi
        continue
        ;;
    esac
  fi

  case "\${def:-}" in
    _topdir\ *)
      topdir="\${def#_topdir }"
      ;;
  esac
  def=""
done

if [[ -z "\$buildroot" && -n "\$topdir" && -d "\$topdir/BUILDROOT" ]]; then
  buildroot="\$topdir/BUILDROOT"
fi

if [[ -n "\$buildroot" && -d "\$buildroot" ]]; then
  emit_tree_stats "\$buildroot" "pre-normalize-buildroot"
  normalize_tree_timestamps "\$buildroot"
  emit_tree_stats "\$buildroot" "post-normalize-buildroot"
fi

extra_defines=(
  --define "_buildhost reproducible"
  --define "_source_date_epoch \${SOURCE_DATE_EPOCH}"
  --define "use_source_date_epoch_as_buildtime 1"
  --define "clamp_mtime_to_source_date_epoch 1"
  --define "source_date_epoch_from_changelog 0"
)

log_line "exec cmd=\$real_rpmbuild args=\$* source_date_epoch=\${SOURCE_DATE_EPOCH} topdir=\${topdir:-<none>} buildroot=\${buildroot:-<none>}"
log_line "extra_defines=\${extra_defines[*]}"

set +e
RPM_BUILD_NCPUS=1 "\$real_rpmbuild" "\${extra_defines[@]}" "\$@"
status=\$?
set -e

log_line "exit status=\$status"
if [[ -n "\$buildroot" && -d "\$buildroot" ]]; then
  emit_tree_stats "\$buildroot" "post-build-buildroot"
fi
if [[ -n "\$topdir" && -d "\$topdir/RPMS" ]]; then
  while IFS= read -r rpm_file; do
    [[ -n "\$rpm_file" ]] || continue
    rpm_sha="\$(sha256sum "\$rpm_file" | awk '{print \$1}')"
    log_line "rpm_output=\$rpm_file sha256=\$rpm_sha"
    if command -v rpm >/dev/null 2>&1; then
      rpm -qp --qf 'name=%{NAME} version=%{VERSION} release=%{RELEASE} buildtime=%{BUILDTIME} buildhost=%{BUILDHOST}\n' "\$rpm_file" >> "\$log_file" 2>/dev/null || true
    fi
  done < <(find "\$topdir/RPMS" -type f -name '*.rpm' 2>/dev/null | LC_ALL=C sort)
fi

exit "\$status"
EOF
      chmod +x "$wrapper_path"
      cp -f "$wrapper_path" "$wrapper_target"
      chmod +x "$wrapper_target"
    fi
  fi

  export PATH="$wrapper_dir:$PATH"
  hash -r
  export SECLUSO_RPMBUILD_WRAPPER_LOG="/tmp/rpmbuild-wrapper.log"
  : > "$SECLUSO_RPMBUILD_WRAPPER_LOG"
  echo "==> linux rpmbuild wrapper active (real: $wrapped_real_rpmbuild, target: $wrapper_target)"
}

dump_packaging_wrapper_logs() {
  local log_file
  for log_file in \
    /tmp/dpkg-deb-wrapper.log \
    /tmp/rpmbuild-wrapper.log \
    /tmp/mksquashfs-wrapper.log
  do
    if [[ -f "$log_file" ]]; then
      echo "==> $(basename "$log_file") (tail)"
      tail -n 200 "$log_file" || true
    else
      echo "==> $(basename "$log_file") missing"
    fi
  done
}

dump_linux_bundle_artifact_forensics() {
  [[ "$TAURI_TARGET" == *"-unknown-linux-"* ]] || return

  local bundle_root="/app/deploy/src-tauri/target/${TAURI_TARGET}/release/bundle"
  [[ -d "$bundle_root" ]] || {
    echo "==> bundle forensic snapshot skipped: missing $bundle_root"
    return
  }

  echo "==> linux bundle artifact forensic snapshot"
  while IFS= read -r artifact; do
    [[ -n "$artifact" ]] || continue

    local sha size mtime
    sha="$(sha256sum "$artifact" 2>/dev/null | awk '{print $1}')"
    size="$(stat -c '%s' -- "$artifact" 2>/dev/null || echo '-')"
    mtime="$(stat -c '%Y' -- "$artifact" 2>/dev/null || echo '-')"

    echo "-- artifact: $artifact"
    echo "   sha256=${sha:-<none>} size_bytes=${size} mtime_epoch=${mtime}"

    case "$artifact" in
      *.AppImage|*.appimage)
        if command -v grep >/dev/null 2>&1; then
          local sq_offset
          sq_offset="$(grep -oba 'hsqs' "$artifact" 2>/dev/null | head -n 1 | cut -d: -f1 || true)"
          echo "   squashfs_offset=${sq_offset:-<none>}"
        fi
        if command -v unsquashfs >/dev/null 2>&1; then
          unsquashfs -s "$artifact" 2>/dev/null | sed 's/^/   /' || true
        fi
        ;;
      *.deb)
        if command -v ar >/dev/null 2>&1; then
          local deb_tmp
          deb_tmp="$(mktemp -d)"
          (
            set -euo pipefail
            cd "$deb_tmp"
            ar x "$artifact"
            local member
            for member in debian-binary control.tar.gz control.tar.xz control.tar.zst data.tar.gz data.tar.xz data.tar.zst data.tar; do
              [[ -f "$member" ]] || continue
              printf '   deb_member=%s sha256=%s\n' "$member" "$(sha256sum "$member" | awk '{print $1}')"
            done
          ) || true
          rm -rf "$deb_tmp"
        fi
        ;;
      *.rpm)
        if command -v rpm >/dev/null 2>&1; then
          rpm -qp --qf '   rpm_name=%{NAME} rpm_version=%{VERSION} rpm_release=%{RELEASE} rpm_buildtime=%{BUILDTIME} rpm_buildhost=%{BUILDHOST}\n' "$artifact" || true
          rpm -qplv "$artifact" | sed -n '1,120p' | sed 's/^/   /' || true
        fi
        ;;
    esac
  done < <(
    find "$bundle_root" -maxdepth 4 -type f \( \
      -name '*.AppImage' -o \
      -name '*.appimage' -o \
      -name '*.deb' -o \
      -name '*.rpm' \
    \) | LC_ALL=C sort
  )
}

print_build_context_if_debug() {
  if ! is_debug_enabled; then
    return 0
  fi

  echo "==> build environment snapshot"
  uname -a || true
  cat /etc/os-release || true
  echo "==> tool versions"
  node --version || true
  pnpm --version || true
  pnpm tauri --version || true
  rustc --version || true
  cargo --version || true
  echo "==> linux bundle tools"
  command -v dpkg-deb || true
  command -v rpmbuild || true
  command -v mksquashfs || true
  command -v taskset || true
  ls -la /root/.cache/tauri || true
}

run_tauri_build() {
  prepare_linux_apprun_cache
  prepare_windows_nsis_cache
  setup_windows_makensis_wrapper
  setup_windows_arm64_clang_wrapper
  setup_linux_dpkg_deb_wrapper
  setup_linux_rpmbuild_wrapper
  setup_linux_mksquashfs_wrapper
  if [[ "$TAURI_TARGET" == *"-unknown-linux-"* ]]; then
    echo "==> linux packaging tool path resolution"
    echo "dpkg-deb=$(command -v dpkg-deb || true)"
    echo "rpmbuild=$(command -v rpmbuild || true)"
    echo "mksquashfs=$(command -v mksquashfs || true)"
    echo "taskset=$(command -v taskset || true)"
  fi
  normalize_windows_bundle_inputs_once

  if [[ "$TAURI_TARGET" == *"-unknown-linux-"* ]]; then
    run_tauri_bundle_with_faketime_linux
    return
  fi

  run_with_faketime_if_enabled \
    pnpm tauri build \
    -v -v \
    --target "${TAURI_TARGET}" \
    --runner "${TAURI_RUNNER}" \
    --config /tmp/tauri-bundle-config.json \
    --ci \
    --no-sign \
    -- \
    --locked

  if [[ "$TAURI_TARGET" == *"-unknown-linux-"* ]]; then
    if ! canonicalize_linux_bundle_outputs_deterministically; then
      echo "==> deterministic linux bundle canonicalization failed"
      dump_packaging_wrapper_logs
      dump_linux_bundle_artifact_forensics
      return 1
    fi
  fi
}

run_tauri_build_with_retry() {
  local attempt1_log="/tmp/tauri-build-attempt1.log"

  if run_tauri_build 2>&1 | tee "$attempt1_log"; then
    return 0
  fi

  if grep -qiE 'Temporary failure in name resolution|failed to lookup address information' "$attempt1_log"; then
    echo "==> tauri build hit transient DNS resolution error; retrying once"
    sleep 3
    run_tauri_build 2>&1 | tee /tmp/tauri-build-attempt2.log
    return $?
  fi

  return 1
}

dump_failure_snapshot() {
  echo "==> filesystem snapshot after failure"
  ls -la /app/deploy/src-tauri/target || true
  ls -la /app/deploy/src-tauri/target/"${TAURI_TARGET}" || true
  ls -la /app/deploy/src-tauri/target/"${TAURI_TARGET}"/release || true
  ls -la /app/deploy/src-tauri/target/"${TAURI_TARGET}"/release/bundle || true
  find /app/deploy/src-tauri/target/"${TAURI_TARGET}"/release/bundle -maxdepth 4 -mindepth 1 -print 2>/dev/null | sort || true
  ls -la /root/.cache/tauri || true

  if [[ -f /tmp/tauri-bundle.log ]]; then
    dump_bundle_failure_context /tmp/tauri-bundle.log
  else
    dump_packaging_wrapper_logs
    dump_linux_bundle_artifact_forensics
  fi
}

main() {
  : "${TAURI_TARGET:?TAURI_TARGET is required}"
  : "${TAURI_RUNNER:=cargo}"
  : "${TAURI_BUNDLE_TARGETS_JSON:=["appimage","deb","rpm"]}"

  configure_rust_log
  configure_deterministic_build_env
  write_bundle_config

  print_build_context_if_debug

  # This stage is intentionally strict: any packaging failure fails the build.
  if ! run_tauri_build_with_retry; then
    echo "==> tauri build failed"
    dump_failure_snapshot
    exit 1
  fi
}

main "$@"
