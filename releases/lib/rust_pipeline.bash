#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later

# Deterministic Rust binary pipeline.
#
# This pipeline is responsible for CLI/service binaries that are produced from
# Rust crates and distributed directly as executables. Every build runs inside a
# digest-pinned container image via Buildx, which gives us repeatability across
# hosts and time. we try to maintain same compiler toolchain, same linker environment, same
# dependency lock state.
#
# The manifest generated at the end of each run records enough metadata to prove
# provenance during compare operations (crate/version/Cargo.lock digest/toolchain digest)
# while also including output hashes for direct artifact integrity checks.

build_and_manifest() {
  local outdir="$1"
  local run_id="$2"

  mkdir -p "$outdir"

  local artifacts_json
  artifacts_json="$(mktemp)"
  : > "$artifacts_json"

  local triple
  for triple in "${TRIPLES[@]}"; do
    local digest
    digest="$(lookup_rust_digest "$triple")"
    if [[ -z "$digest" ]]; then
      rm -f "$artifacts_json"
      die "No digest set for $triple in ${DIGESTS_LOCK_FILE}"
    fi

    local pkg
    for pkg in "${PKGS[@]}"; do
      local features_args=()
      local crate_name="$pkg"

      if [[ "$pkg" == "raspberry_camera_hub" ]]; then
        features_args=( --build-arg "FEATURES=--features raspberry" )
        crate_name="camera_hub"
      elif [[ "$pkg" == "motion_ai_cli" ]]; then
        features_args=( --build-arg "FEATURES=--features raspberry" )
        crate_name="motion_ai/cli"
      fi

      # Some public profiles intentionally span multiple differing targets, which means a
      # profile can include packages that are valid only on a subset of triples...
      # We skip those invalid combinations explicitly so profile semantics stay pretty
      # simple for release managers while still also enforcing architecture rules.
      if [[ "$pkg" == "raspberry_camera_hub" || "$pkg" == "reset" ]]; then
        if [[ "$triple" != "aarch64-unknown-linux-gnu" ]]; then
          echo "==> [run $run_id] SKIP $pkg for $triple (raspberry-only)"
          continue
        fi
      fi
      if [[ "$TARGET" == "all" && "$PROFILE" == "test" && "$pkg" == "update" && "$triple" != "aarch64-unknown-linux-gnu" ]]; then
        echo "==> [run $run_id] SKIP $pkg for $triple (test profile keeps update on raspberry only)"
        continue
      fi

      local crate_lock="$PROJECT_ROOT/$crate_name/Cargo.lock"
      local crate_dir="$PROJECT_ROOT/$crate_name"

      [[ -f "$crate_lock" ]] || {
        rm -f "$artifacts_json"
        die "Cargo.lock not found at crate $crate_name"
      }
      [[ -f "$crate_dir/Cargo.toml" ]] || {
        rm -f "$artifacts_json"
        die "Missing $crate_dir/Cargo.toml to read version"
      }

      local crate_lock_sha
      crate_lock_sha="$(sha256_file "$crate_lock")"

      local crate_version
      crate_version="$({
        cargo metadata --no-deps --format-version 1 --manifest-path "$crate_dir/Cargo.toml"
      } | jq -r '.packages[0].version')"
      [[ -n "$crate_version" && "$crate_version" != "null" ]] || {
        rm -f "$artifacts_json"
        die "Could not get version from $crate_dir/Cargo.toml"
      }

      local bin
      bin="secluso-$(tr '_/' '-' <<<"$crate_name")"

      local art_dir
      art_dir="$(artifact_dir_for_triple "$outdir" "$triple")"
      mkdir -p "$art_dir"

      # Bash 3.2 + set -u treats empty array expansion as unbound unless a
      # default is provided.
      echo "==> [run $run_id] $pkg for $triple (crate=$crate_name bin=$bin) features=(${features_args[*]-})"
      docker buildx build \
        --builder "$BUILDER" \
        --no-cache \
        --target artifact \
        --build-context "proj=${PROJECT_ROOT}" \
        --build-arg "CRATE_NAME=${crate_name}" \
        --build-arg "BINARY_FILE_NAME=${bin}" \
        --build-arg "CARGO_TARGET=${triple}" \
        --build-arg "RUST_HASH=${digest}" \
        "${features_args[@]+"${features_args[@]}"}" \
        --output "type=local,dest=${art_dir}" \
        "$RELEASES_DIR"

      [[ -f "$art_dir/$bin" ]] || {
        rm -f "$artifacts_json"
        die "Missing bin file for $pkg in $art_dir"
      }

      case "$pkg" in
        raspberry_camera_hub)
          local new_bin="secluso-camera-hub"
          # crate_name is remapped to camera_hub above, so $bin is already secluso-camera-hub
          # only rename when the names actually differ to avoid a self-move
          if [[ "$bin" != "$new_bin" ]]; then
            mv "$art_dir/$bin" "$art_dir/$new_bin"
          fi
          bin="$new_bin"
          ;;
      esac

      local bin_sha
      bin_sha="$(sha256_file "$art_dir/$bin")"
      [[ -n "$bin_sha" ]] || {
        rm -f "$artifacts_json"
        die "Failed to compute sha256 for $art_dir/$bin"
      }

      printf '    {"package":"%s","target":"%s","bin":"%s","bin_path":"%s","sha256":"%s","crate":"%s","version":"%s","crate_lock_sha256":"%s","rust_digest":"%s"}\n' \
        "$pkg" \
        "$triple" \
        "$bin" \
        "artifacts/$triple/$bin" \
        "$bin_sha" \
        "$crate_name" \
        "$crate_version" \
        "$crate_lock_sha" \
        "$digest" \
        >> "$artifacts_json"
    done
  done

  write_manifest "$outdir" "$run_id" "$artifacts_json"
  rm -f "$artifacts_json"
}
