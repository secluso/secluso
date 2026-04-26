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

enforce_locked_macos_host_toolchain() {
  local deploy_dir="$1"

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
  require_locked_host_version "MACOS_HOST_PNPM_VERSION" "$pnpm_version" "pnpm"
  require_locked_host_version "MACOS_HOST_TAURI_CLI_VERSION" "$tauri_cli_version" "tauri-cli"
  require_locked_host_version "MACOS_HOST_CLANG_VERSION" "$clang_version" "apple-clang"
  require_locked_host_version "MACOS_HOST_XCODE_VERSION" "$xcode_version" "xcode"
  require_locked_host_version "MACOS_HOST_SDK_VERSION" "$sdk_version" "macOS SDK"
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
  local info_plist="$contents_dir/Info.plist"
  if [[ -f "$info_plist" ]]; then
    copied_any=1
    local info_rel="app/${app_name}/Contents/Info.plist"
    mkdir -p "$art_dir/app/${app_name}/Contents"
    cp "$info_plist" "$art_dir/$info_rel"
    local info_sha
    info_sha="$(sha256_file "$art_dir/$info_rel")"

    record_deploy_artifact \
      "$artifacts_json" \
      "$triple" \
      "$info_rel" \
      "$info_sha" \
      "$deploy_version" \
      "$deploy_lock_sha" \
      "$digest"
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
    find "$contents_dir" -type f \
      ! -path '*/Info.plist' \
      ! -path '*/_CodeSignature/*' \
      ! -name 'CodeResources' \
      ! -name '.DS_Store' \
      | LC_ALL=C sort
  )

  [[ "$copied_any" -eq 1 ]] || die "No macOS app payload files found under $contents_dir"
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

  local deploy_version
  deploy_version="$({
    cargo metadata --no-deps --format-version 1 --manifest-path "$deploy_tauri_dir/Cargo.toml"
  } | jq -r '.packages[0].version')"
  [[ -n "$deploy_version" && "$deploy_version" != "null" ]] || die "Could not get deploy version from $deploy_tauri_dir/Cargo.toml"

  local deploy_lock_sha
  deploy_lock_sha="$({ cat "$deploy_cargo_lock"; cat "$deploy_node_lock"; } | sha256_stdin)"

  local requires_apple_host=0
  local plan_triple
  for plan_triple in "${TRIPLES[@]}"; do
    if is_apple_triple "$plan_triple"; then
      requires_apple_host=1
      break
    fi
  done
  local supported_bundles=""
  if [[ "$requires_apple_host" -eq 1 ]]; then
    echo "==> [run $run_id] Installing deploy UI deps (pnpm install --frozen-lockfile)"
    (
      cd "$deploy_dir" || exit 1
      CI=true pnpm install --frozen-lockfile
    )
    enforce_locked_macos_host_toolchain "$deploy_dir"
    supported_bundles="$(detect_supported_tauri_bundles "$deploy_dir")"
    [[ -n "$supported_bundles" ]] || die "Could not determine supported Tauri bundle types from local CLI after install. Run: cd ${deploy_dir} && pnpm tauri build --help"
  fi

  local deploy_source_date_epoch="${SOURCE_DATE_EPOCH:-}"
  if [[ -z "$deploy_source_date_epoch" ]]; then
    if command -v git >/dev/null 2>&1 && git -C "$PROJECT_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
      deploy_source_date_epoch="$(git -C "$PROJECT_ROOT" log -1 --pretty=%ct 2>/dev/null || true)"
    fi
  fi
  if [[ -z "$deploy_source_date_epoch" ]]; then
    deploy_source_date_epoch="1704067200"
  fi
  [[ "$deploy_source_date_epoch" =~ ^[0-9]+$ ]] || die "Invalid SOURCE_DATE_EPOCH value: $deploy_source_date_epoch"

  local deterministic_rustflags="${RUSTFLAGS:-}"
  local remap_flag="--remap-path-prefix=${PROJECT_ROOT}=."
  if [[ "$deterministic_rustflags" != *"$remap_flag"* ]]; then
    deterministic_rustflags="${deterministic_rustflags:+$deterministic_rustflags }$remap_flag"
  fi
  local cargo_home_path="${CARGO_HOME:-$HOME/.cargo}"
  local cargo_remap_flag="--remap-path-prefix=${cargo_home_path}=/cargo-home"
  if [[ "$deterministic_rustflags" != *"$cargo_remap_flag"* ]]; then
    deterministic_rustflags="${deterministic_rustflags:+$deterministic_rustflags }$cargo_remap_flag"
  fi
  local home_remap_flag="--remap-path-prefix=${HOME}=/home/user"
  if [[ "$deterministic_rustflags" != *"$home_remap_flag"* ]]; then
    deterministic_rustflags="${deterministic_rustflags:+$deterministic_rustflags }$home_remap_flag"
  fi

  local host_toolchain_sha
  host_toolchain_sha="$({
    rustc -Vv || true
    cargo -V || true
    node --version || true
    pnpm --version || true
    clang --version || true
    xcodebuild -version || true
    xcrun --show-sdk-version || true
  } | sha256_stdin)"

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
      local run_target_dir="${RELEASES_DIR}/.repro-work/deploy-target"
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
