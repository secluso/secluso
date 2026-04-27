#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail
IFS=$'\n\t'

# Verify a macOS release directly against a local reproducible build.
#
# We do not use a published manifest.
# The trust model is to build it yourself, normalize the shipped signed app, and compare the two app trees directly.
#
# The comparison is also not a raw zip/app byte diff.
# Signed macOS releases pick up Apple-specific metadata that should differ from the unsigned reproducible build.
# We therefore materialize copies, strip bundle-level release metadata, normalize Mach-O binaries, and then compare the resulting stuff.

PROGRAM_NAME="$(basename "$0")"
RELEASES_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck disable=SC1091
source "${RELEASES_DIR}/lib/common.bash"

VERIFY_LOCAL_APP=""
VERIFY_LOCAL_RUN=""
VERIFY_TRIPLE=""
VERIFY_RELEASE_PATH=""
VERIFY_KEEP_TEMP=0
VERIFY_TMP_DIR=""
VERIFY_EXPECTED_TEAM_ID="${VERIFY_EXPECTED_TEAM_ID:-8PYH264TD9}"

verify_usage() {
  cat >&2 <<EOF
Usage:
  ${PROGRAM_NAME} --local-app /path/to/Secluso\\ Deploy.app --release /path/to/release.app.zip
  ${PROGRAM_NAME} --local-run RUN_DIR --triple {x86_64-apple-darwin|aarch64-apple-darwin} --release /path/to/release.app.zip

EOF
}

parse_verify_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --local-app)
        VERIFY_LOCAL_APP="${2:?}"
        shift 2
        ;;
      --local-run)
        VERIFY_LOCAL_RUN="${2:?}"
        shift 2
        ;;
      --triple)
        VERIFY_TRIPLE="${2:?}"
        shift 2
        ;;
      --release)
        VERIFY_RELEASE_PATH="${2:?}"
        shift 2
        ;;
      --keep-temp)
        VERIFY_KEEP_TEMP=1
        shift 1
        ;;
      -h|--help)
        verify_usage
        exit 0
        ;;
      *)
        verify_usage
        die "Unknown option: $1"
        ;;
    esac
  done
}

ensure_verify_tools() {
  require_tool codesign
  require_tool spctl
  require_tool file
  require_tool find
  require_tool diff
  require_tool ditto
  require_tool perl
  require_tool xattr
  init_sha256_tool
}

cleanup_verify_tmp_dir() {
  if [[ -n "${VERIFY_TMP_DIR:-}" ]]; then
    rm -rf "$VERIFY_TMP_DIR"
  fi
}

resolve_local_app() {
  if [[ -n "$VERIFY_LOCAL_APP" ]]; then
    [[ -d "$VERIFY_LOCAL_APP" ]] || die "Local app bundle not found: $VERIFY_LOCAL_APP"
    printf '%s\n' "$VERIFY_LOCAL_APP"
    return
  fi

  [[ -n "$VERIFY_LOCAL_RUN" ]] || die "Provide either --local-app or --local-run"
  [[ -n "$VERIFY_TRIPLE" ]] || die "--triple is required with --local-run"

  local app_path="${VERIFY_LOCAL_RUN}/artifacts/${VERIFY_TRIPLE}/app/Secluso Deploy.app"
  [[ -d "$app_path" ]] || die "Local app bundle not found in run dir: $app_path"
  printf '%s\n' "$app_path"
}

materialize_app_copy() {
  local source_path="$1"
  local dest_root="$2"

  if [[ -d "$source_path" ]]; then
    # Work on a copy so normalization never mutates the caller's original app.
    [[ "$source_path" == *.app ]] || die "Directory source must be a .app bundle: $source_path"
    local copied_app="${dest_root}/$(basename "$source_path")"
    ditto "$source_path" "$copied_app"
    printf '%s\n' "$copied_app"
    return
  fi

  [[ -f "$source_path" ]] || die "Release input not found: $source_path"
  case "$source_path" in
    *.zip)
      # Release assets are normally distributed as zip archives, so unwrap them into a temp directory and insist that exactly one .app bundle exists.
      local unpack_root="${dest_root}/unzipped"
      mkdir -p "$unpack_root"
      ditto -x -k "$source_path" "$unpack_root"
      local app_path=""
      while IFS= read -r candidate; do
        [[ -n "$candidate" ]] || continue
        if [[ -n "$app_path" ]]; then
          die "Zip contains more than one .app bundle: $source_path"
        fi
        app_path="$candidate"
      done < <(find "$unpack_root" -type d -name '*.app' | LC_ALL=C sort)
      [[ -n "$app_path" ]] || die "No .app bundle found inside zip: $source_path"
      printf '%s\n' "$app_path"
      ;;
    *)
      die "Unsupported release input: $source_path (expected .app or .zip)"
      ;;
  esac
}

verify_release_signing_policy() {
  local release_app="$1"
  local local_app="$2"
  [[ -d "$release_app" ]] || die "Release app bundle not found for signing-policy check: $release_app"
  [[ -d "$local_app" ]] || die "Local app bundle not found for signing-policy check: $local_app"

  # Enforce the Apple-side release policy before we do any signed-vs-unsigned equivalence work.
  # is the downloaded release still a valid Developer ID / notarized app with the identity and runtime properties we expect?
  codesign --verify --deep --strict --verbose=2 "$release_app"

  local release_meta release_identifier local_identifier release_team_id
  release_meta="$(codesign -dvvv "$release_app" 2>&1)" || die "Failed to inspect release signing metadata: $release_app"
  release_identifier="$(awk -F= '/^Identifier=/{print $2; exit}' <<<"$release_meta")"
  local_identifier="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$local_app/Contents/Info.plist" 2>/dev/null || true)"

  # The signed release should present the same bundle identifier as the local reproducible build rather than a differently labeled app.
  [[ -n "$release_identifier" ]] || die "Release signing metadata is missing Identifier: $release_app"
  [[ -n "$local_identifier" ]] || die "Local app Info.plist is missing CFBundleIdentifier: $local_app"
  [[ "$release_identifier" == "$local_identifier" ]] || die "Release identifier mismatch: expected $local_identifier, got $release_identifier"

  release_team_id="$(awk -F= '/^TeamIdentifier=/{print $2; exit}' <<<"$release_meta")"

  # Pin the signing team so a validly signed app from some other developer account does not pass this check.
  [[ -n "$release_team_id" ]] || die "Release signing metadata is missing TeamIdentifier: $release_app"
  [[ "$release_team_id" == "$VERIFY_EXPECTED_TEAM_ID" ]] || die "Release TeamIdentifier mismatch: expected $VERIFY_EXPECTED_TEAM_ID, got $release_team_id"

  # Require the core distribution properties Apple expects for outside-App-Store delivery: hardened runtime, a secure timestamp, and a stapled notarization ticket on the artifact being checked
  grep -q 'flags=0x10000(runtime)' <<<"$release_meta" || die "Release is missing hardened runtime flag: $release_app"
  grep -q '^Runtime Version=' <<<"$release_meta" || die "Release signing metadata is missing Runtime Version: $release_app"
  grep -q '^CMSDigest=' <<<"$release_meta" || die "Release signing metadata is missing CMSDigest: $release_app"
  grep -q '^Notarization Ticket=stapled' <<<"$release_meta" || die "Release is missing a stapled notarization ticket: $release_app"

  # complements codesign metadata checks by exercising Apple's execution policy layer rather than only the embedded signature structure itself.
  if ! spctl --assess --type execute --verbose=4 "$release_app"; then
    echo "WARN: spctl assessment did not succeed for release copy: $release_app" >&2
  fi
}

strip_bundle_signing() {
  local app_dir="$1"
  [[ -d "$app_dir" ]] || die "App bundle not found for normalization: $app_dir"

  # Public macOS release apps are expected to differ from the reproducible local build in exactly the places Apple signing and distribution tooling touch.
  # examples being extended attributes, code signature directories, CodeResources, and optional provisioning metadata.
  #
  # This removes those bundle-level release things here so the comparison answers what we care about, as in...
  # Does the shipped signed app reduce to the same underlying app payload as the reproducible unsigned build?
  #
  # The executable bytes themselves are handled separately below.
  # Mach-O files still contain signing- & linkedit-related differences after bundle-level stripping.
  # So normalized_file_hash() hashes a canonicalized Mach-O view instead of the raw bytes for those files only.
  xattr -cr "$app_dir" 2>/dev/null || true
  find "$app_dir" -name '.DS_Store' -type f -delete
  find "$app_dir" -name 'CodeResources' -type f -delete
  find "$app_dir" -name 'embedded.provisionprofile' -type f -delete

  while IFS= read -r code_sig_dir; do
    [[ -n "$code_sig_dir" ]] || continue
    rm -rf "$code_sig_dir"
  done < <(find "$app_dir" -type d -name '_CodeSignature' | LC_ALL=C sort)
}

normalized_file_hash() {
  local path="$1"

  if file -b "$path" | grep -q 'Mach-O'; then
    # Compare on a *narrowly* normalized Mach-O representation so Apple-added signature metadata does not outweigh payload equivalence.
    # Unsupported layouts fail inside normalized_macho_sha256_file().
    normalized_macho_sha256_file "$path"
    return
  fi

  sha256_file "$path"
}

write_app_inventory() {
  local app_dir="$1"
  local out_file="$2"
  : > "$out_file"

  # Each line captures file type, mode, relative path, & either a symlink target or a normalized file hash.
  # This makes the (eventual) diff readable and avoids requiring byte-for-byte archive identity at the zip/container level (due to what's discussed in the other functionality's comments).
  while IFS= read -r path; do
    [[ -n "$path" ]] || continue
    local rel="${path#${app_dir}/}"
    local mode
    mode="$(stat -f '%p' "$path")"

    if [[ -L "$path" ]]; then
      local target
      target="$(readlink "$path")"
      printf 'L\t%s\t%s\t%s\n' "$mode" "$rel" "$target" >> "$out_file"
      continue
    fi

    if [[ -f "$path" ]]; then
      local hash
      if ! hash="$(normalized_file_hash "$path")"; then
        die "Failed to normalize file for release verification: $path"
      fi
      printf 'F\t%s\t%s\t%s\n' "$mode" "$rel" "$hash" >> "$out_file"
    fi
  done < <(find "$app_dir" \( -type f -o -type l \) | LC_ALL=C sort)
}

main() {
  parse_verify_args "$@"
  [[ -n "$VERIFY_RELEASE_PATH" ]] || die "--release is required"
  ensure_verify_tools

  # local side is expected to be the unsigned app produced by a reproducible build
  # release side is the signed/notarized artifact someone downloaded
  local local_source_app
  local_source_app="$(resolve_local_app)"

  local tmp_dir
  tmp_dir="$(mktemp -d)"
  VERIFY_TMP_DIR="$tmp_dir"
  if [[ "$VERIFY_KEEP_TEMP" -eq 0 ]]; then
    trap cleanup_verify_tmp_dir EXIT
  fi

  local local_root="${tmp_dir}/local"
  local release_root="${tmp_dir}/release"
  mkdir -p "$local_root" "$release_root"

  local local_app
  local_app="$(materialize_app_copy "$local_source_app" "$local_root")"
  local release_app
  release_app="$(materialize_app_copy "$VERIFY_RELEASE_PATH" "$release_root")"

  verify_release_signing_policy "$release_app" "$local_app"

  # Strip bundle-level signing noise from both trees before inventorying them
  # The Mach-O-specific normalization happens inside normalized_file_hash
  strip_bundle_signing "$local_app"
  strip_bundle_signing "$release_app"

  local local_inv="${tmp_dir}/local.inventory.txt"
  local release_inv="${tmp_dir}/release.inventory.txt"
  write_app_inventory "$local_app" "$local_inv"
  write_app_inventory "$release_app" "$release_inv"

  if ! diff -u "$local_inv" "$release_inv"; then
    echo ""
    echo "macOS release verification FAILED"
    echo "- Local unsigned app : $local_source_app"
    echo "- Release input      : $VERIFY_RELEASE_PATH"
    if [[ "$VERIFY_KEEP_TEMP" -eq 1 ]]; then
      echo "- Temp dir           : $tmp_dir"
    fi
    exit 1
  fi

  echo "macOS release verification PASSED"
  echo "- Local unsigned app : $local_source_app"
  echo "- Release input      : $VERIFY_RELEASE_PATH"
  if [[ "$VERIFY_KEEP_TEMP" -eq 1 ]]; then
    echo "- Temp dir           : $tmp_dir"
  fi
}

main "$@"
