#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later

# Deploy pipeline helper utilities
#
# These helpers isolate target-specific packaging decisions so the deploy
# pipeline can read like orchestration instead of a pile of conditionals. The
# core idea is that what to build and how to package are policy decisions,
# while the pipeline function should focus on execution order and error handling.

select_deploy_bundles_for_triple() {
  local triple="$1"

  case "$triple" in
    *windows*) echo "nsis msi" ;;
    # Prefer app bundles for reproducibility checks; dmg container metadata can
    # vary between runs even when the app payload is identical.
    *apple-darwin) echo "app dmg" ;;
    # TODO: RPM reproducibility canonicalization is currently brittle
    *linux*) echo "appimage deb" ;;
    *) echo "all" ;;
  esac
}

detect_supported_tauri_bundles() {
  local deploy_dir="$1"
  local help_output
  local values_line

  help_output="$({
    cd "$deploy_dir" || exit 1
    pnpm tauri build --help 2>&1 || true
  })"

  values_line="$(
    printf '%s\n' "$help_output" |
      tr -d '\r' |
      sed -nE 's/.*\[[Pp]ossible values:[[:space:]]*([^]]+)\].*/\1/p' |
      head -n 1
  )"

  if [[ -z "$values_line" ]]; then
    echo ""
    return
  fi

  echo "$values_line" | tr ',' ' ' | xargs
}

pick_supported_bundle() {
  local candidate_list="$1"
  local supported_list="$2"
  local candidate
  local supported
  local -a candidates=()
  local -a supported_values=()
  local IFS=$' \t\n'

  # build.sh sets IFS to newline/tab globally, so we must tokenize these
  # space-delimited lists explicitly to avoid treating the full list as 1 item.
  read -r -a candidates <<<"$candidate_list"
  read -r -a supported_values <<<"$supported_list"

  for candidate in "${candidates[@]}"; do
    for supported in "${supported_values[@]}"; do
      if [[ "$candidate" == "$supported" ]]; then
        echo "$candidate"
        return 0
      fi
    done
  done

  return 1
}

is_linux_triple() {
  [[ "$1" == *"-unknown-linux-"* ]]
}

is_windows_triple() {
  [[ "$1" == *"-pc-windows-"* ]]
}

docker_platform_for_triple() {
  local triple="$1"

  if is_windows_triple "$triple"; then
    # Windows NSIS cross-build currently runs from Linux container builders.
    echo "linux/amd64"
    return
  fi

  if [[ "$triple" == aarch64-* ]]; then
    echo "linux/arm64"
  else
    echo "linux/amd64"
  fi
}

deploy_bundle_targets_json_for_triple() {
  local triple="$1"

  if is_windows_triple "$triple"; then
    echo '["nsis"]'
  elif is_linux_triple "$triple"; then
    echo '["appimage","deb"]'
  else
    echo '["dmg","app"]'
  fi
}

deploy_runner_for_triple() {
  local triple="$1"

  if is_windows_triple "$triple"; then
    echo "cargo-xwin"
  else
    echo "cargo"
  fi
}

rust_digest_for_docker_platform() {
  local docker_platform="$1"

  case "$docker_platform" in
    linux/amd64) echo "${RUST_DIGEST__X86_64_UNKNOWN_LINUX_GNU:-}" ;;
    linux/arm64) echo "${RUST_DIGEST__AARCH64_UNKNOWN_LINUX_GNU:-}" ;;
    *) echo "" ;;
  esac
}

record_deploy_artifact() {
  local artifacts_json="$1"
  local triple="$2"
  local rel_path_within_triple="$3"
  local sha="$4"
  local deploy_version="$5"
  local deploy_lock_sha="$6"
  local digest="$7"

  local bin
  bin="$(basename "$rel_path_within_triple")"

  printf '    {"package":"%s","target":"%s","bin":"%s","bin_path":"%s","sha256":"%s","crate":"%s","version":"%s","crate_lock_sha256":"%s","rust_digest":"%s"}\n' \
    "deploy_tool" \
    "$triple" \
    "$bin" \
    "artifacts/$triple/$rel_path_within_triple" \
    "$sha" \
    "deploy/src-tauri" \
    "$deploy_version" \
    "$deploy_lock_sha" \
    "$digest" \
    >> "$artifacts_json"
}
