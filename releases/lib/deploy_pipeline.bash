#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later

# Deploy application pipeline
#
# Desktop app distribution has fundamentally different mechanics than raw Rust
# binaries... each different OS expects different packaging formats, and host tooling often
# determines what can be produced natively. This pipeline uses:
#
# 1) Native host bundling for Apple targets.
# 2) Docker builders for non-Apple targets.
#
# Regardless of path, all artifacts are normalized into:
#   artifacts/<triple>/...
# with ONE manifest schema for compare and verification tooling.

ensure_deploy_workspace_inputs() {
  local deploy_tauri_dir="$1"
  local deploy_cargo_lock="$2"
  local deploy_node_lock="$3"

  [[ -f "$deploy_tauri_dir/Cargo.toml" ]] || die "Missing deploy Cargo.toml at $deploy_tauri_dir/Cargo.toml"
  [[ -f "$deploy_cargo_lock" ]] || die "Missing deploy Cargo.lock at $deploy_cargo_lock"
  [[ -f "$deploy_node_lock" ]] || die "Missing deploy pnpm lockfile at $deploy_node_lock"
}

write_docker_diagnostic_summary() {
  local source_log="$1"
  local summary_log="$2"
  local triple="$3"

  # This summary is intentionally redundant with the full docker log, but it is
  # optimized for quickly sending to peoples in issues / chats. It preserves only the
  # lines that usually explain AppImage packaging failures (linuxdeploy command,
  # plugin probes, subprocess exit codes, and strace status correlation) plus a
  # short tail of the full log for surrounding context.

  {
    echo "Docker buildx diagnostic summary"
    echo "timestamp_utc=$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    echo "triple=$triple"
    echo "source_log=$source_log"
    echo
    echo "== Key failure signals (with context) =="
    if command -v rg >/dev/null 2>&1; then
      rg -n -C 6 \
        'failed to bundle project|failed to run .*linuxdeploy|No such file or directory \(os error 2\)|ERROR: Failed to run plugin|FATAL ERROR:SOURCE_DATE_EPOCH|mksquashfs .* exited with code|embedded plugin not found|Expected an AppImage bundle|Docker buildx failed' \
        "$source_log" || true
    else
      grep -nE \
        'failed to bundle project|failed to run .*linuxdeploy|No such file or directory \(os error 2\)|ERROR: Failed to run plugin|FATAL ERROR:SOURCE_DATE_EPOCH|mksquashfs .* exited with code|embedded plugin not found|Expected an AppImage bundle|Docker buildx failed' \
        "$source_log" || true
    fi
    echo
    echo "== Final 250 lines of full docker log =="
    tail -n 250 "$source_log" || true
  } > "$summary_log"
}

require_locked_host_version() {
  local var_name="$1"
  local actual_value="$2"
  local tool_label="$3"
  local expected_value="${!var_name:-}"
  local normalized_actual="$actual_value"

  if [[ -z "$normalized_actual" ]]; then
    normalized_actual="<unavailable>"
  fi

  [[ -n "$expected_value" ]] || die "Missing ${var_name} in ${DIGESTS_LOCK_FILE}. Deterministic macOS deploy builds require pinned host tool versions."
  if [[ "$actual_value" != "$expected_value" ]]; then
    die "Pinned host tool mismatch for ${tool_label}: expected '${expected_value}', got '${normalized_actual}'. Update host toolchain or intentionally rotate ${DIGESTS_LOCK_FILE}."
  fi
}

ensure_locked_macos_rustup_toolchain() {
  require_tool rustup

  [[ -n "${MACOS_HOST_RUSTC_VERSION:-}" ]] || die "Missing MACOS_HOST_RUSTC_VERSION in ${DIGESTS_LOCK_FILE}"

  # "stable-aarch64-apple-darwin" and "1.90.0-aarch64-apple-darwin" can compile with the same rustc version, but still come from different sysroot paths
  # Thus, we select the locked toolchain inside this process with RUSTUP_TOOLCHAIN
  echo "==> Selecting pinned Rust toolchain ${MACOS_HOST_RUSTC_VERSION} for macOS host build"

  local installed_toolchain=0
  local listed_toolchain
  while IFS= read -r listed_toolchain; do
    listed_toolchain="${listed_toolchain%% *}"
    case "$listed_toolchain" in
      "$MACOS_HOST_RUSTC_VERSION"|"$MACOS_HOST_RUSTC_VERSION"-*)
        installed_toolchain=1
        break
        ;;
    esac
  done < <(rustup toolchain list)

  if [[ "$installed_toolchain" -eq 0 ]]; then
    local install_args=( "$MACOS_HOST_RUSTC_VERSION" --profile minimal )
    local install_triple
    for install_triple in "$@"; do
      [[ -n "$install_triple" ]] || continue
      install_args+=( --target "$install_triple" )
    done
    rustup toolchain install "${install_args[@]}"
  fi

  export RUSTUP_TOOLCHAIN="$MACOS_HOST_RUSTC_VERSION"

  local active_toolchain
  active_toolchain="$(rustup show active-toolchain 2>/dev/null | awk '{print $1}' || true)"
  case "$active_toolchain" in
    "$MACOS_HOST_RUSTC_VERSION"|"$MACOS_HOST_RUSTC_VERSION"-*) ;;
    *)
      die "Pinned Rust toolchain was not selected: expected ${MACOS_HOST_RUSTC_VERSION}, got ${active_toolchain:-<unavailable>}"
      ;;
  esac

  for triple in "$@"; do
    [[ -n "$triple" ]] || continue
    if ! rustup target list --toolchain "$MACOS_HOST_RUSTC_VERSION" --installed | grep -Fx "$triple" >/dev/null 2>&1; then
      rustup target add --toolchain "$MACOS_HOST_RUSTC_VERSION" "$triple"
    fi
    if ! rustup target list --toolchain "$MACOS_HOST_RUSTC_VERSION" --installed | grep -Fx "$triple" >/dev/null 2>&1; then
      die "Pinned Rust toolchain ${MACOS_HOST_RUSTC_VERSION} is missing target ${triple}"
    fi
  done
}

append_rustflag_once() {
  local var_name="$1"
  local flag="$2"
  local current="${!var_name:-}"

  [[ -n "$flag" ]] || return
  if [[ " $current " != *" $flag "* ]]; then
    printf -v "$var_name" '%s' "${current:+$current }$flag"
  fi
}

deterministic_macos_deploy_target_dir() {
  local target_dir="${MACOS_DEPLOY_REPRO_TARGET_DIR:-/private/tmp/secluso-deploy-target}"
  case "$target_dir" in
    /*) ;;
    *) die "MACOS_DEPLOY_REPRO_TARGET_DIR must be an absolute path for reproducible builds: $target_dir" ;;
  esac

  printf '%s' "$target_dir"
}

deterministic_macos_rustflags() {
  local deterministic_rustflags="${RUSTFLAGS:-}"
  local cargo_home_path="${CARGO_HOME:-$HOME/.cargo}"
  local rustup_home_path="${RUSTUP_HOME:-$HOME/.rustup}"
  local macos_deploy_target_dir
  macos_deploy_target_dir="$(deterministic_macos_deploy_target_dir)"
  local rust_sysroot
  rust_sysroot="$(rustc --print sysroot)"
  local rust_commit
  rust_commit="$(rustc -Vv | awk '/^commit-hash:/{value=$2} END{print value}')"

  [[ -n "$rust_sysroot" ]] || die "Could not resolve rustc sysroot for deterministic remapping"
  [[ -n "$rust_commit" ]] || die "Could not resolve rustc commit hash for deterministic remapping"

  # Rust uses the last matching --remap-path-prefix.
  # So if the broad HOME remap comes after the project/cargo/rust-src remaps, it wins and leaves machine "shaped" paths in the binary
  # Thus we put broad paths first and specific paths later.
  append_rustflag_once deterministic_rustflags "--remap-path-prefix=${HOME}=/home/user"
  append_rustflag_once deterministic_rustflags "--remap-path-prefix=${rustup_home_path}=/rustup-home"
  append_rustflag_once deterministic_rustflags "--remap-path-prefix=${cargo_home_path}=/cargo-home"
  append_rustflag_once deterministic_rustflags "--remap-path-prefix=${rust_sysroot}/lib/rustlib/src/rust=/rustc/${rust_commit}"
  append_rustflag_once deterministic_rustflags "--remap-path-prefix=${PROJECT_ROOT}=."
  append_rustflag_once deterministic_rustflags "--remap-path-prefix=${macos_deploy_target_dir}=/cargo-target"

  printf '%s' "$deterministic_rustflags"
}

macos_host_toolchain_identity() {
  local deploy_dir="$1"
  shift

  local rustc_version rustc_commit rustc_host rustc_release rustc_llvm cargo_version node_version pnpm_version tauri_cli_version
  rustc_version="$(rustc -V 2>/dev/null | awk '{print $2}' || true)"
  rustc_commit="$(rustc -Vv 2>/dev/null | awk '/^commit-hash:/{value=$2} END{print value}' || true)"
  rustc_host="$(rustc -Vv 2>/dev/null | awk '/^host:/{value=$2} END{print value}' || true)"
  rustc_release="$(rustc -Vv 2>/dev/null | awk '/^release:/{value=$2} END{print value}' || true)"
  rustc_llvm="$(rustc -Vv 2>/dev/null | awk '/^LLVM version:/{value=$3} END{print value}' || true)"
  cargo_version="$(cargo -V 2>/dev/null | awk '{print $2}' || true)"
  node_version="$(node --version 2>/dev/null | sed 's/^v//' || true)"
  pnpm_version="$(pnpm --version 2>/dev/null || true)"
  tauri_cli_version="$({
    cd "$deploy_dir" || exit 1
    node -e 'try{process.stdout.write(require("@tauri-apps/cli/package.json").version || "")}catch(_){process.stdout.write("")}'
  } 2>/dev/null || true)"

  # Raw tool output can include local filesystem details like clang's InstalledDir or rustup's sysroot location.
  #
  # Thus, hash the pinned facts we care about.
  # If the locked contract changes, compare will see that and say so
  {
    printf 'rustup_toolchain=%s\n' "${RUSTUP_TOOLCHAIN:-}"
    printf 'rustc_version=%s\n' "$rustc_version"
    printf 'rustc_commit=%s\n' "$rustc_commit"
    printf 'rustc_host=%s\n' "$rustc_host"
    printf 'rustc_release=%s\n' "$rustc_release"
    printf 'rustc_llvm=%s\n' "$rustc_llvm"
    printf 'cargo_version=%s\n' "$cargo_version"
    printf 'node_version=%s\n' "$node_version"
    printf 'pnpm_version=%s\n' "$pnpm_version"
    printf 'tauri_cli_version=%s\n' "$tauri_cli_version"
    printf 'apple_clang_version=%s\n' "${MACOS_HOST_CLANG_VERSION:-}"
    printf 'xcode_version=%s\n' "${MACOS_HOST_XCODE_VERSION:-}"
    printf 'macos_sdk_version=%s\n' "${MACOS_HOST_SDK_VERSION:-}"
    printf 'apple_targets=%s\n' "$*"
  }
}

enforce_locked_macos_host_toolchain() {
  local deploy_dir="$1"
  shift

  local active_toolchain
  active_toolchain="$(rustup show active-toolchain 2>/dev/null | awk '{print $1}' || true)"
  case "$active_toolchain" in
    "$MACOS_HOST_RUSTC_VERSION"|"$MACOS_HOST_RUSTC_VERSION"-*) ;;
    *)
      die "Pinned Rust toolchain mismatch: expected ${MACOS_HOST_RUSTC_VERSION}, got ${active_toolchain:-<unavailable>}"
      ;;
  esac

  local rustc_version
  rustc_version="$(rustc -V 2>/dev/null | awk '{print $2}' || true)"
  local cargo_version
  cargo_version="$(cargo -V 2>/dev/null | awk '{print $2}' || true)"
  local node_version
  node_version="$(node --version 2>/dev/null | sed 's/^v//' || true)"
  local pnpm_version
  pnpm_version="$(pnpm --version 2>/dev/null || true)"
  local clang_version
  clang_version="$(clang --version 2>/dev/null | sed -nE 's/^Apple clang version ([0-9.]+).*/\1/p' | head -n 1 || true)"
  local xcode_version
  xcode_version="$(xcodebuild -version 2>/dev/null | awk '/^Xcode /{print $2; exit}' || true)"
  local sdk_version
  sdk_version="$(xcrun --show-sdk-version 2>/dev/null || true)"
  local tauri_cli_version
  tauri_cli_version="$({
    cd "$deploy_dir" || exit 1
    node -e 'try{process.stdout.write(require("@tauri-apps/cli/package.json").version || "")}catch(_){process.stdout.write("")}'
  } 2>/dev/null || true)"

  require_locked_host_version "MACOS_HOST_RUSTC_VERSION" "$rustc_version" "rustc"
  require_locked_host_version "MACOS_HOST_CARGO_VERSION" "$cargo_version" "cargo"
  require_locked_host_version "MACOS_HOST_NODE_VERSION" "$node_version" "node"
  require_locked_host_version "DEPLOY_PNPM_VERSION" "$pnpm_version" "pnpm"
  require_locked_host_version "MACOS_HOST_TAURI_CLI_VERSION" "$tauri_cli_version" "tauri-cli"
  require_locked_host_version "MACOS_HOST_CLANG_VERSION" "$clang_version" "apple-clang"
  require_locked_host_version "MACOS_HOST_XCODE_VERSION" "$xcode_version" "xcode"
  require_locked_host_version "MACOS_HOST_SDK_VERSION" "$sdk_version" "macOS SDK"

  local rust_sysroot
  rust_sysroot="$(rustc --print sysroot 2>/dev/null || true)"
  local rust_sysroot_name
  rust_sysroot_name="$(basename "$rust_sysroot")"
  case "$rust_sysroot_name" in
    "$MACOS_HOST_RUSTC_VERSION"|"$MACOS_HOST_RUSTC_VERSION"-*) ;;
    *)
      die "Pinned Rust sysroot mismatch: expected a ${MACOS_HOST_RUSTC_VERSION} sysroot, got ${rust_sysroot:-<unavailable>}"
      ;;
  esac

  local triple
  for triple in "$@"; do
    [[ -n "$triple" ]] || continue
    if ! rustup target list --toolchain "$MACOS_HOST_RUSTC_VERSION" --installed | grep -Fx "$triple" >/dev/null 2>&1; then
      die "Pinned Rust toolchain ${MACOS_HOST_RUSTC_VERSION} is missing target ${triple}"
    fi
  done
}

assert_no_macos_host_path_leaks() {
  local file_path="$1"
  [[ -f "$file_path" ]] || return
  require_tool strings

  local project_under_home=""
  if [[ "$PROJECT_ROOT" == "$HOME/"* ]]; then
    project_under_home="${PROJECT_ROOT#"$HOME"/}"
  fi
  local macos_deploy_target_dir
  macos_deploy_target_dir="$(deterministic_macos_deploy_target_dir)"

  # If these strings are present, source-path metadata is inside
  local patterns=(
    "$PROJECT_ROOT"
    "$HOME"
    "$macos_deploy_target_dir"
    "/Users/runner"
    "/home/runner/work"
    "/home/user/.cargo"
    "/home/user/.rustup"
    "/home/user/work/"
  )
  if [[ -n "$project_under_home" ]]; then
    patterns+=( "/home/user/$project_under_home" )
  fi

  local grep_args=()
  local pattern
  for pattern in "${patterns[@]}"; do
    [[ -n "$pattern" ]] || continue
    grep_args+=( -e "$pattern" )
  done

  local leak_report
  leak_report="$(mktemp)"
  if strings -a "$file_path" | LC_ALL=C grep -F "${grep_args[@]}" > "$leak_report"; then
    echo "FAIL: host-specific path strings leaked into $(basename "$file_path"):" >&2
    head -n 20 "$leak_report" >&2
    rm -f "$leak_report"
    die "Refusing to record non-reproducible macOS artifact with host-specific path leaks: $file_path"
  fi
  rm -f "$leak_report"
}

normalize_macos_vendored_openssl_paths() {
  local file_path="$1"
  [[ -f "$file_path" ]] || return
  require_tool strings

  if ! strings -a "$file_path" | LC_ALL=C grep -F '/openssl-build/install/lib/' >/dev/null; then
    return
  fi

  require_tool perl

  # openssl-src builds with --prefix=$OUT_DIR/openssl-build/install, and  OpenSSL 3 embeds ENGINESDIR/MODULESDIR from that prefix
  # normalize those runtime defaults
  perl -0777 -i -pe '
    sub padded_replacement {
      my ($original, $replacement) = @_;
      die "replacement is longer than original\n" if length($replacement) > length($original);
      return $replacement . ("\0" x (length($original) - length($replacement)));
    }

    s{/[^\0]*?/openssl-build/install/lib/engines-3}{padded_replacement($&, "/usr/local/ssl/lib/engines-3")}ge;
    s{/[^\0]*?/openssl-build/install/lib/ossl-modules}{padded_replacement($&, "/usr/local/ssl/lib/ossl-modules")}ge;
  ' "$file_path"
}

strip_macos_macho_symbols() {
  local file_path="$1"
  [[ -f "$file_path" ]] || return
  require_tool file

  if ! file -b "$file_path" | grep -q 'Mach-O'; then
    return
  fi

  require_tool strip

  # Rust/ld leave local and exported implementation symbols in the Mach-O.
  # The executable bytes can be identical while disassembly still differs because tools resolve branch targets through hash-suffixed symbol names.
  # Thus, we strip them out for reproducibility
  strip "$file_path"
}

sign_macos_app_payload() {
  local app_dir="$1"
  [[ -d "$app_dir" ]] || return
  require_tool codesign

  # Stripping and path normalization mutate bytes covered by Mach-O code directories.
  # Re-seal the complete copied bundle after every resource is in place so macOS can execute it
  codesign --force --deep --sign - "$app_dir"
}

record_macos_app_payload_artifacts() {
  local app_dir="$1"
  local art_dir="$2"
  local artifacts_json="$3"
  local triple="$4"
  local deploy_version="$5"
  local deploy_lock_sha="$6"
  local digest="$7"

  local app_name
  app_name="$(basename "$app_dir")"

  local contents_dir="$app_dir/Contents"
  [[ -d "$contents_dir" ]] || die "Missing macOS app Contents directory: $contents_dir"

  # Capture deterministic app payload files instead of dmg container bytes.
  # Keep the app bundle intact enough to launch locally by preserving resources such as icon.icns.
  # Exclude signing metadata from comparisons.
  local copied_any=0
  local copied_app_dir="$art_dir/app/$app_name"
  local info_plist="$contents_dir/Info.plist"
  if [[ -f "$info_plist" ]]; then
    copied_any=1
    local info_rel="app/${app_name}/Contents/Info.plist"
    mkdir -p "$art_dir/app/${app_name}/Contents"
    cp "$info_plist" "$art_dir/$info_rel"
  fi

  while IFS= read -r payload_file; do
    [[ -z "$payload_file" ]] && continue
    copied_any=1

    local rel_in_app="${payload_file#${app_dir}/}"
    local rel_path_within_triple="app/${app_name}/${rel_in_app}"
    local rel_dir
    rel_dir="$(dirname "$rel_path_within_triple")"
    mkdir -p "$art_dir/$rel_dir"
    cp "$payload_file" "$art_dir/$rel_path_within_triple"

    local copied_path="$art_dir/$rel_path_within_triple"
    strip_macos_macho_symbols "$copied_path"
    normalize_macos_vendored_openssl_paths "$copied_path"
  done < <(
    find "$contents_dir" -type f \
      ! -path '*/Info.plist' \
      ! -path '*/_CodeSignature/*' \
      ! -name 'CodeResources' \
      ! -name '.DS_Store' \
      | LC_ALL=C sort
  )

  [[ "$copied_any" -eq 1 ]] || die "No macOS app payload files found under $contents_dir"

  sign_macos_app_payload "$copied_app_dir"

  while IFS= read -r copied_path; do
    [[ -z "$copied_path" ]] && continue
    assert_no_macos_host_path_leaks "$copied_path"
  done < <(
    find "$copied_app_dir/Contents" -type f \
      | LC_ALL=C sort
  )

  while IFS= read -r copied_path; do
    [[ -z "$copied_path" ]] && continue

    local rel_path_within_triple="${copied_path#${art_dir}/}"
    local bin_sha
    bin_sha="$(sha256_file "$copied_path")"

    record_deploy_artifact \
      "$artifacts_json" \
      "$triple" \
      "$rel_path_within_triple" \
      "$bin_sha" \
      "$deploy_version" \
      "$deploy_lock_sha" \
      "$digest"
  done < <(
    find "$copied_app_dir/Contents" -type f \
      ! -path '*/_CodeSignature/*' \
      ! -name 'CodeResources' \
      ! -name '.DS_Store' \
      | LC_ALL=C sort
  )
}

run_host_deploy_bundle_for_triple() {
  local run_id="$1"
  local triple="$2"
  local selected_bundle="$3"
  local deploy_dir="$4"
  local deploy_tauri_dir="$5"
  local art_dir="$6"
  local artifacts_json="$7"
  local deploy_version="$8"
  local deploy_lock_sha="$9"
  local digest="${10}"
  local run_target_dir="${11}"
  local source_date_epoch="${12}"
  local deterministic_rustflags="${13}"
  local effective_rustflags="$deterministic_rustflags"

  # Keep build-output path stable across run1/run2 so build-script-generated
  # absolute paths do not introduce per-run entropy into the final binary.
  rm -rf "$run_target_dir"
  mkdir -p "$run_target_dir"

  local bundle_dir="$run_target_dir/$triple/release/bundle"

  echo "==> [run $run_id] deploy_tool for $triple (host bundle=$selected_bundle)"
  (
    cd "$deploy_dir" || exit 1
    SOURCE_DATE_EPOCH="$source_date_epoch" \
      RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-}" \
      TZ=UTC \
      LC_ALL=C \
      LANG=C \
      ZERO_AR_DATE=1 \
      CARGO_INCREMENTAL=0 \
      CARGO_BUILD_JOBS=1 \
      CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
      CARGO_TARGET_DIR="$run_target_dir" \
      TAURI_TARGET_DIR="$run_target_dir" \
      RUSTFLAGS="$effective_rustflags" \
      CI=true \
      pnpm tauri build -v -v --target "$triple" --bundles "$selected_bundle" --ci --no-sign -- --locked
  )

  [[ -d "$bundle_dir" ]] || die "Missing deploy bundle output directory: $bundle_dir"

  local found_bundle=0
  while IFS= read -r bundle_file; do
    [[ -z "$bundle_file" ]] && continue
    found_bundle=1

    local rel_path_within_triple="${bundle_file#${bundle_dir}/}"
    local rel_dir
    rel_dir="$(dirname "$rel_path_within_triple")"
    mkdir -p "$art_dir/$rel_dir"
    cp "$bundle_file" "$art_dir/$rel_path_within_triple"

    local copied_path="$art_dir/$rel_path_within_triple"
    local bin_sha
    bin_sha="$(sha256_file "$copied_path")"

    record_deploy_artifact \
      "$artifacts_json" \
      "$triple" \
      "$rel_path_within_triple" \
      "$bin_sha" \
      "$deploy_version" \
      "$deploy_lock_sha" \
      "$digest"
  done < <(
    find "$bundle_dir" -type f \( \
      -name "*.AppImage" -o \
      -name "*.appimage" -o \
      -name "*.deb" -o \
      -name "*.rpm" -o \
      -name "*.msi" -o \
      -name "*.exe" -o \
      -name "*.dmg" -o \
      -name "*.pkg" \
    \) | LC_ALL=C sort
  )

  if [[ "$found_bundle" -eq 0 && "$selected_bundle" == "app" ]]; then
    local found_app=0
    while IFS= read -r app_dir; do
      [[ -z "$app_dir" ]] && continue
      found_app=1
      record_macos_app_payload_artifacts \
        "$app_dir" \
        "$art_dir" \
        "$artifacts_json" \
        "$triple" \
        "$deploy_version" \
        "$deploy_lock_sha" \
        "$digest"
    done < <(find "$bundle_dir" -type d -name "*.app" | LC_ALL=C sort)

    [[ "$found_app" -eq 1 ]] || die "No macOS .app bundle was produced for $triple under $bundle_dir"
    found_bundle=1
  fi

  [[ "$found_bundle" -eq 1 ]] || die "No desktop bundle files were produced for $triple under $bundle_dir"
}

run_docker_deploy_bundle_for_triple() {
  local run_id="$1"
  local triple="$2"
  local deploy_version="$3"
  local deploy_lock_sha="$4"
  local art_dir="$5"
  local artifacts_json="$6"
  local source_date_epoch="$7"

  local docker_platform
  docker_platform="$(docker_platform_for_triple "$triple")"

  local docker_digest
  docker_digest="$(rust_digest_for_docker_platform "$docker_platform")"
  [[ -n "$docker_digest" ]] || die "No Rust digest configured for docker platform $docker_platform"

  local docker_runner
  docker_runner="$(deploy_runner_for_triple "$triple")"

  local docker_bundle_targets_json
  docker_bundle_targets_json="$(deploy_bundle_targets_json_for_triple "$triple")"

  [[ -n "${DEPLOY_PNPM_VERSION:-}" ]] || die "Missing DEPLOY_PNPM_VERSION in ${DIGESTS_LOCK_FILE}"
  [[ -n "${DEPLOY_PNPM_TARBALL_INTEGRITY:-}" ]] || die "Missing DEPLOY_PNPM_TARBALL_INTEGRITY in ${DIGESTS_LOCK_FILE}"

  local docker_debug="${DEBUG:-0}"

  local tmp_art_dir
  tmp_art_dir="$(mktemp -d)"

  # We store docker_digest as the effective toolchain identity for artifacts
  # built through fallback containers. This lets compare runs detect
  # toolchain drift even when the host machine itself did not compile the target natively.
  local effective_digest="$docker_digest"
  local docker_build_log="$art_dir/docker-buildx-${triple}.log"
  local docker_summary_log="$art_dir/docker-buildx-${triple}-summary.log"

  echo "==> [run $run_id] deploy_tool for $triple (docker $docker_platform, runner=$docker_runner)"
  echo "==> [run $run_id] docker buildx diagnostic log: $docker_build_log"
  echo "==> [run $run_id] docker buildx copy/paste summary: $docker_summary_log"
  {
    echo "==> docker preflight snapshot"
    echo "timestamp_utc=$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    echo "triple=$triple"
    echo "docker_platform=$docker_platform"
    echo "docker_runner=$docker_runner"
    echo "docker_bundle_targets_json=$docker_bundle_targets_json"
    echo "docker_debug=$docker_debug"
    echo "docker_digest=$docker_digest"
    echo ""
    docker --version || true
    docker buildx version || true
    docker version || true
    docker buildx inspect "$BUILDER" || true
  } > "$docker_build_log"
  # Docker build output can be very long and frequently contains the only
  # actionable failure clue when packaging tools abort internally. We always tee
  # the complete stream into artifacts/<triple>/ so the log is preserved for
  # "post-mortem" analysis even if terminal scrollback truncates for some reason
  if ! docker buildx build \
    --builder "$BUILDER" \
    --progress plain \
    --no-cache \
    --platform "$docker_platform" \
    --target artifact \
    --build-context "proj=${PROJECT_ROOT}" \
    --build-arg "RUST_HASH=${docker_digest}" \
    --build-arg "TAURI_TARGET=${triple}" \
    --build-arg "TAURI_RUNNER=${docker_runner}" \
    --build-arg "PNPM_VERSION=${DEPLOY_PNPM_VERSION}" \
    --build-arg "PNPM_TARBALL_INTEGRITY=${DEPLOY_PNPM_TARBALL_INTEGRITY}" \
    --build-arg "TAURI_BUNDLE_TARGETS_JSON=${docker_bundle_targets_json}" \
    --build-arg "SOURCE_DATE_EPOCH=${source_date_epoch}" \
    --build-arg "DEBUG=${docker_debug}" \
    --output "type=local,dest=${tmp_art_dir}" \
    -f "${RELEASES_DIR}/Dockerfile.deploy" \
    "${RELEASES_DIR}" \
    2>&1 | tee -a "$docker_build_log"; then
    write_docker_diagnostic_summary "$docker_build_log" "$docker_summary_log" "$triple"
    die "Docker buildx failed for $triple. Full diagnostic log: $docker_build_log. Copy/paste summary: $docker_summary_log"
  fi
  write_docker_diagnostic_summary "$docker_build_log" "$docker_summary_log" "$triple"

  local found_any=0
  local found_appimage=0
  local docker_bundle_dir="$tmp_art_dir/release/bundle"
  if [[ -d "$docker_bundle_dir" ]]; then
    while IFS= read -r bundle_file; do
      [[ -z "$bundle_file" ]] && continue
      found_any=1

      case "$bundle_file" in
        *.AppImage|*.appimage) found_appimage=1 ;;
      esac

      local rel_path_within_triple="bundle/${bundle_file#${docker_bundle_dir}/}"
      local rel_dir
      rel_dir="$(dirname "$rel_path_within_triple")"
      mkdir -p "$art_dir/$rel_dir"
      cp "$bundle_file" "$art_dir/$rel_path_within_triple"

      local copied_path="$art_dir/$rel_path_within_triple"
      local bin_sha
      bin_sha="$(sha256_file "$copied_path")"

      record_deploy_artifact \
        "$artifacts_json" \
        "$triple" \
        "$rel_path_within_triple" \
        "$bin_sha" \
        "$deploy_version" \
        "$deploy_lock_sha" \
        "$effective_digest"
    done < <(
      find "$docker_bundle_dir" -type f \( \
        -name "*.AppImage" -o \
        -name "*.appimage" -o \
        -name "*.deb" -o \
        -name "*.rpm" -o \
        -name "*.msi" -o \
        -name "*.exe" \
      \) | sort
    )
  fi

  if is_linux_triple "$triple" && [[ "$found_appimage" -eq 0 ]]; then
    die "Expected an AppImage bundle for $triple, but none was produced by Docker fallback. Inspect $docker_build_log and $docker_summary_log."
  fi

  # Some cross-build paths produce a portable binary without an installer. We
  # intentionally keep that binary because it is still valuable for internal
  # verification, and it remains verifiable through manifest
  # hashes like every other artifact.
  if [[ "$found_any" -eq 0 && -d "$tmp_art_dir/release" ]]; then
    local portable_bin=""
    if is_windows_triple "$triple" && [[ -f "$tmp_art_dir/release/secluso-deploy.exe" ]]; then
      portable_bin="$tmp_art_dir/release/secluso-deploy.exe"
    elif is_linux_triple "$triple" && [[ -f "$tmp_art_dir/release/secluso-deploy" ]]; then
      portable_bin="$tmp_art_dir/release/secluso-deploy"
    fi

    if [[ -n "$portable_bin" ]]; then
      found_any=1
      local rel_path_within_triple="portable/$(basename "$portable_bin")"
      mkdir -p "$art_dir/portable"
      cp "$portable_bin" "$art_dir/$rel_path_within_triple"
      local bin_sha
      bin_sha="$(sha256_file "$art_dir/$rel_path_within_triple")"

      record_deploy_artifact \
        "$artifacts_json" \
        "$triple" \
        "$rel_path_within_triple" \
        "$bin_sha" \
        "$deploy_version" \
        "$deploy_lock_sha" \
        "$effective_digest"
    fi
  fi

  # Preserve reproducibility diagnostics generated inside the Docker build
  # stage so run1/run2 can be compared without rerunning containers.
  if is_windows_triple "$triple" && [[ -d "$tmp_art_dir/release/repro" ]]; then
    mkdir -p "$art_dir/repro"
    cp -R "$tmp_art_dir/release/repro/." "$art_dir/repro/"
  fi

  rm -rf "$tmp_art_dir"

  if [[ "$found_any" -eq 0 ]]; then
    die "No deploy artifacts were produced for $triple via Docker fallback."
  fi
}

build_deploy_and_manifest() {
  local outdir="$1"
  local run_id="$2"

  mkdir -p "$outdir"

  local artifacts_json
  artifacts_json="$(mktemp)"
  : > "$artifacts_json"

  local deploy_dir="${PROJECT_ROOT}/deploy"
  local deploy_tauri_dir="$deploy_dir/src-tauri"
  local deploy_cargo_lock="$deploy_tauri_dir/Cargo.lock"
  local deploy_node_lock="$deploy_dir/pnpm-lock.yaml"

  ensure_deploy_workspace_inputs "$deploy_tauri_dir" "$deploy_cargo_lock" "$deploy_node_lock"

  local requires_apple_host=0
  local apple_triples=()
  local plan_triple
  for plan_triple in "${TRIPLES[@]}"; do
    if is_apple_triple "$plan_triple"; then
      requires_apple_host=1
      apple_triples+=( "$plan_triple" )
    fi
  done

  if [[ "$requires_apple_host" -eq 1 ]]; then
    ensure_locked_macos_rustup_toolchain "${apple_triples[@]}"
  fi

  local deploy_version
  deploy_version="$({
    cargo metadata --no-deps --format-version 1 --manifest-path "$deploy_tauri_dir/Cargo.toml"
  } | jq -r '.packages[0].version')"
  [[ -n "$deploy_version" && "$deploy_version" != "null" ]] || die "Could not get deploy version from $deploy_tauri_dir/Cargo.toml"

  local deploy_lock_sha
  deploy_lock_sha="$({ cat "$deploy_cargo_lock"; cat "$deploy_node_lock"; } | sha256_stdin)"

  local supported_bundles=""
  if [[ "$requires_apple_host" -eq 1 ]]; then
    echo "==> [run $run_id] Installing deploy UI deps (pnpm install --frozen-lockfile)"
    (
      cd "$deploy_dir" || exit 1
      CI=true pnpm install --frozen-lockfile
    )
    enforce_locked_macos_host_toolchain "$deploy_dir" "${apple_triples[@]}"
    supported_bundles="$(detect_supported_tauri_bundles "$deploy_dir")"
    [[ -n "$supported_bundles" ]] || die "Could not determine supported Tauri bundle types from local CLI after install. Run: cd ${deploy_dir} && pnpm tauri build --help"
  fi

  local deploy_source_date_epoch_file="$deploy_dir/release-source-date-epoch.txt"
  [[ -f "$deploy_source_date_epoch_file" ]] || die "Missing deploy source date epoch file: $deploy_source_date_epoch_file"
  local deploy_source_date_epoch
  deploy_source_date_epoch="$(
    awk '
      {
        gsub(/[[:space:]]/, "")
      }
      $0 !~ /^#/ && $0 != "" {
        print
        exit
      }
    ' "$deploy_source_date_epoch_file"
  )"
  [[ -n "$deploy_source_date_epoch" ]] || die "Empty deploy source date epoch file: $deploy_source_date_epoch_file"
  [[ "$deploy_source_date_epoch" =~ ^[0-9]+$ ]] || die "Invalid SOURCE_DATE_EPOCH value: $deploy_source_date_epoch"

  local deterministic_rustflags="${RUSTFLAGS:-}"
  local host_toolchain_sha=""
  if [[ "$requires_apple_host" -eq 1 ]]; then
    deterministic_rustflags="$(deterministic_macos_rustflags)"
    host_toolchain_sha="$(macos_host_toolchain_identity "$deploy_dir" "${apple_triples[@]}" | sha256_stdin)"
  fi

  if [[ "$BUILD_KIND" == "deploy" && "$DEPLOY_REQUIRES_DOCKER" -eq 1 && ! -f "${RELEASES_DIR}/Dockerfile.deploy" ]]; then
    die "Missing ${RELEASES_DIR}/Dockerfile.deploy required for deploy cross-platform builds."
  fi

  # This triple loop intentionally mixes native and fallback paths so one run
  # can produce a complete desktop matrix where possible (ideally always). Each triple is fully
  # self-contained in artifacts/<triple>, which makes post-build packaging and
  # compare operations straightforward and helps everyone here be less error-prone for operators.
  # Apple triples bundle on host; non-Apple triples bundle in Docker.
  local triple
  for triple in "${TRIPLES[@]}"; do
    local art_dir
    art_dir="$(artifact_dir_for_triple "$outdir" "$triple")"
    mkdir -p "$art_dir"

    local digest
    if is_apple_triple "$triple"; then
      digest="host-toolchain-${host_toolchain_sha}"
    else
      digest="$(lookup_rust_digest "$triple")"
      if [[ -z "$digest" ]]; then
        digest="host-toolchain-${host_toolchain_sha}"
      fi
    fi

    local bundle_candidates
    bundle_candidates="$(select_deploy_bundles_for_triple "$triple")"

    if is_apple_triple "$triple"; then
      local selected_bundle=""
      if ! selected_bundle="$(pick_supported_bundle "$bundle_candidates" "$supported_bundles" 2>/dev/null)"; then
        die "Target $triple requires macOS host bundling. Supported on this host: $supported_bundles"
      fi
      local run_target_dir
      run_target_dir="$(deterministic_macos_deploy_target_dir)"
      run_host_deploy_bundle_for_triple \
        "$run_id" \
        "$triple" \
        "$selected_bundle" \
        "$deploy_dir" \
        "$deploy_tauri_dir" \
        "$art_dir" \
        "$artifacts_json" \
        "$deploy_version" \
        "$deploy_lock_sha" \
        "$digest" \
        "$run_target_dir" \
        "$deploy_source_date_epoch" \
        "$deterministic_rustflags"
      continue
    elif [[ "$DEPLOY_REQUIRES_DOCKER" -ne 1 ]]; then
      die "Docker fallback is required for non-Apple target $triple but is not available."
    fi

    run_docker_deploy_bundle_for_triple \
      "$run_id" \
      "$triple" \
      "$deploy_version" \
      "$deploy_lock_sha" \
      "$art_dir" \
      "$artifacts_json" \
      "$deploy_source_date_epoch"
  done

  write_manifest "$outdir" "$run_id" "$artifacts_json"
  rm -f "$artifacts_json"
}
