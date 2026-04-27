#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail
IFS=$'\n\t'

# Post-process a reproducible unsigned macOS app into a (release-shaped) artifact.
#
# This exists because macOS distribution requirements and reproducibility requirements go in different directions.
# Specifically,
#   [1] Reproducible build comparison wants the app before Apple signing/notarization
#   [2] End-user distribution wants the app after Apple signing/notarization
#
# We therefore keep this step out of build.sh.
# The reproducible pipeline produces the unsigned .app, compare verifies that payload, and only then do we copy that app here, sign it, notarize/staple it, and package the release zip.
# This keeps Apple-issued metadata from "polluting" the reproducible build outputs

PROGRAM_NAME="$(basename "$0")"
RELEASES_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck disable=SC1091
source "${RELEASES_DIR}/lib/common.bash"

SIGN_APP_PATH=""
SIGN_RUN_DIR=""
SIGN_TRIPLE=""
SIGN_IDENTITY=""
SIGN_NOTARY_PROFILE=""
SIGN_OUT_DIR=""
SIGN_ZIP_NAME=""
SIGN_TMP_DIR=""

sign_usage() {
  cat >&2 <<EOF
Usage:
  ${PROGRAM_NAME} --app /path/to/Secluso\\ Deploy.app --identity "Developer ID Application: ..." --outdir OUT_DIR [--notary-profile PROFILE] [--zip-name NAME.zip]
  ${PROGRAM_NAME} --run-dir RUN_DIR --triple {x86_64-apple-darwin|aarch64-apple-darwin} --identity "Developer ID Application: ..." --outdir OUT_DIR [--notary-profile PROFILE] [--zip-name NAME.zip]

EOF
}

parse_sign_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --app)
        SIGN_APP_PATH="${2:?}"
        shift 2
        ;;
      --run-dir)
        SIGN_RUN_DIR="${2:?}"
        shift 2
        ;;
      --triple)
        SIGN_TRIPLE="${2:?}"
        shift 2
        ;;
      --identity)
        SIGN_IDENTITY="${2:?}"
        shift 2
        ;;
      --notary-profile)
        SIGN_NOTARY_PROFILE="${2:?}"
        shift 2
        ;;
      --outdir)
        SIGN_OUT_DIR="${2:?}"
        shift 2
        ;;
      --zip-name)
        SIGN_ZIP_NAME="${2:?}"
        shift 2
        ;;
      -h|--help)
        sign_usage
        exit 0
        ;;
      *)
        sign_usage
        die "Unknown option: $1"
        ;;
    esac
  done
}

triple_release_arch() {
  case "$1" in
    x86_64-apple-darwin) printf '%s' "x64" ;;
    aarch64-apple-darwin) printf '%s' "arm64" ;;
    *) die "Unsupported macOS triple: $1" ;;
  esac
}

plist_read() {
  local plist_path="$1"
  local key="$2"
  /usr/libexec/PlistBuddy -c "Print :${key}" "$plist_path"
}

cleanup_sign_tmp_dir() {
  if [[ -n "${SIGN_TMP_DIR:-}" ]]; then
    rm -rf "$SIGN_TMP_DIR"
  fi
}

resolve_sign_app() {
  if [[ -n "$SIGN_APP_PATH" ]]; then
    [[ -d "$SIGN_APP_PATH" ]] || die "App bundle not found: $SIGN_APP_PATH"
    printf '%s\n' "$SIGN_APP_PATH"
    return
  fi

  [[ -n "$SIGN_RUN_DIR" ]] || die "Provide either --app or --run-dir"
  [[ -n "$SIGN_TRIPLE" ]] || die "--triple is required with --run-dir"

  local app_path="${SIGN_RUN_DIR}/artifacts/${SIGN_TRIPLE}/app/Secluso Deploy.app"
  [[ -d "$app_path" ]] || die "Signed source app not found in run dir: $app_path"
  printf '%s\n' "$app_path"
}

ensure_sign_tools() {
  # Use Apple-native tooling here instead of trying to keep signing inside the reproducible Docker environment.
  require_tool codesign
  require_tool ditto
  require_tool xattr
  require_tool plutil
  require_tool /usr/libexec/PlistBuddy
  init_sha256_tool
  if [[ -n "$SIGN_NOTARY_PROFILE" ]]; then
    require_tool xcrun
    require_tool spctl
  fi
}

main() {
  parse_sign_args "$@"
  [[ -n "$SIGN_IDENTITY" ]] || die "--identity is required"
  [[ -n "$SIGN_OUT_DIR" ]] || die "--outdir is required"
  ensure_sign_tools

  # Input resolution supports either a direct .app path or a reproducible run directory + target triple.
  local source_app
  source_app="$(resolve_sign_app)"
  local info_plist="${source_app}/Contents/Info.plist"
  [[ -f "$info_plist" ]] || die "Missing Info.plist: $info_plist"

  local product_name version
  product_name="$(plist_read "$info_plist" "CFBundleName")"
  version="$(plist_read "$info_plist" "CFBundleShortVersionString")"

  local zip_name="$SIGN_ZIP_NAME"
  if [[ -z "$zip_name" ]]; then
    local arch_label="macos"
    if [[ -n "$SIGN_TRIPLE" ]]; then
      arch_label="macos-$(triple_release_arch "$SIGN_TRIPLE")"
    fi
    zip_name="${product_name// /-}-${version}-${arch_label}.app.zip"
  fi
  [[ "$zip_name" == *.zip ]] || die "--zip-name must end with .zip"

  mkdir -p "$SIGN_OUT_DIR"

  local final_app="${SIGN_OUT_DIR}/$(basename "$source_app")"
  local final_zip="${SIGN_OUT_DIR}/${zip_name}"
  [[ ! -e "$final_app" ]] || die "Output already exists: $final_app"
  [[ ! -e "$final_zip" ]] || die "Output already exists: $final_zip"

  local tmp_dir
  tmp_dir="$(mktemp -d)"
  SIGN_TMP_DIR="$tmp_dir"
  trap cleanup_sign_tmp_dir EXIT

  # Always sign a temporary copy, never the source app in place.
  # That keeps the reproducible build artifact immutable and makes the side effect boundary very obvious.
  # Everything under OUT_DIR is release-mutated, everything in RUN_DIR stays as-built for later auditing.
  local work_app="${tmp_dir}/$(basename "$source_app")"
  ditto "$source_app" "$work_app"
  xattr -cr "$work_app" 2>/dev/null || true

  local codesign_args=(
    --force
    --deep
    --options runtime
    --timestamp
    --sign "$SIGN_IDENTITY"
    "$work_app"
  )

  echo "Signing ${work_app}"
  codesign "${codesign_args[@]}"
  # Verify immediately after signing so we fail before notarization/packaging if the identity/entitlements/nested code/bundle structure are wrong.
  codesign --verify --deep --strict --verbose=2 "$work_app"

  if [[ -n "$SIGN_NOTARY_PROFILE" ]]; then
    # notarytool works on an archive submission.
    # We submit a temporary zip for Apple's verdict, then staple the accepted ticket back onto the app bundle before copying the final release outputs into OUT_DIR.
    # Some interesting info on this process located here: https://developer.apple.com/documentation/security/customizing-the-notarization-workflow#Staple-the-ticket-to-your-distribution
    local submit_zip="${tmp_dir}/submit.zip"
    # Avoid AppleDouble/resource-fork sidecars in the notarization upload
    # Apple uses ditto for the notarization/distribution archive shape we need here (see cmd man ditto)
    # ditto preserves HFS metadata by default; --norsrc turns that off so the upload zip stays limited to the signed app payload instead of picking up AppleDouble ._* sidecars or other host metadata.
    ditto -c -k --keepParent --norsrc "$work_app" "$submit_zip"
    echo "Submitting for notarization with keychain profile ${SIGN_NOTARY_PROFILE}"
    xcrun notarytool submit "$submit_zip" --keychain-profile "$SIGN_NOTARY_PROFILE" --wait
    xcrun stapler staple -v "$work_app"
    spctl --assess --type execute --verbose=4 "$work_app"
  else
    echo "Skipping notarization: no --notary-profile provided"
  fi

  # Preserve the signed bundle exactly as-validated and avoid packaging AppleDouble/resource-fork sidecars that can invalidate the result app
  xattr -cr "$work_app" 2>/dev/null || true

  # Write both the final .app bundle and a zip containing that exact bundle.
  ditto "$work_app" "$final_app"
  # The copy into OUT_DIR can pick up host-specific extended attributes such as com.apple.provenance.
  # Clear them before the final verification/zip steps
  # xattrs are filesystem metadata attached separately from the bundle contents.
  # Clearing them here keeps the final artifact from inheriting host-specific metadata (that is outside the signed payload)
  xattr -cr "$final_app" 2>/dev/null || true
  # Re-verify after the final copy.
  # Catches cases where moving the bundle into OUT_DIR changed enough metadata to invalidate the signature
  # Apple treats post-signing bundle changes as signature-invalidating, so we verify again after the final copy rather than assuming from the earlier check
  # --deep --strict makes this check closer to the way Apple validates nested signed content during release handling.
  codesign --verify --deep --strict --verbose=2 "$final_app"
  # Zip without AppleDouble/resource-fork entries
  # The same --norsrc rule applies to the release zip: package the signed app bundle itself (not filesystem metadata tha can change across machines)
  ditto -c -k --keepParent --norsrc "$final_app" "$final_zip"

  local verify_tmp_dir verify_app
  verify_tmp_dir="$(mktemp -d)"
  ditto -x -k "$final_zip" "$verify_tmp_dir"
  verify_app="${verify_tmp_dir}/$(basename "$source_app")"
  # Verify the extracted payload (not just the source app/zip)
  # Proves the actual artifact users download can be expanded back into a valid signed app.
  codesign --verify --deep --strict --verbose=2 "$verify_app"
  rm -rf "$verify_tmp_dir"

  local zip_sha
  zip_sha="$(sha256_file "$final_zip")"

  echo "Signed macOS release output"
  echo "- App: $final_app"
  echo "- Zip: $final_zip"
  echo "- SHA256: $zip_sha"
  if [[ -n "$SIGN_NOTARY_PROFILE" ]]; then
    echo "- Status: signed, notarized, stapled"
  else
    echo "- Status: signed only (not notarized)"
  fi
}

main "$@"
