#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail
IFS=$'\n\t'

# Post-process reproducible unsigned Windows artifacts using Azure Artifact Signing.
#
# Mirrors the macOS split: reproducibility wants the unsigned build output, while end-user Windows distribution wants Authenticode-signed artifacts with a trusted timestamp.
# Therefore keep signing outside build.sh so the run dir remains the auditable unsigned source of truth.
#
# Must be run on Windows.

PROGRAM_NAME="$(basename "$0")"
RELEASES_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck disable=SC1091
source "${RELEASES_DIR}/lib/common.bash"

SIGN_FILE_PATH=""
SIGN_RUN_DIR=""
SIGN_TRIPLE=""
SIGN_OUT_DIR=""
SIGN_TIMESTAMP_URL="http://timestamp.acs.microsoft.com"
SIGN_DLIB_PATH=""
SIGN_METADATA_JSON=""
SIGN_SIGNTOOL_PATH=""
SIGN_TMP_DIR=""

sign_usage() {
  cat >&2 <<EOF
Usage:
  ${PROGRAM_NAME} --file /path/to/artifact.{exe|msi} --outdir OUT_DIR --dlib PATH --metadata-json PATH [--signtool PATH] [--timestamp-url URL]
  ${PROGRAM_NAME} --run-dir RUN_DIR --triple {x86_64-pc-windows-msvc|aarch64-pc-windows-msvc} --outdir OUT_DIR --dlib PATH --metadata-json PATH [--signtool PATH] [--timestamp-url URL]

Examples:
  ${PROGRAM_NAME} --file release.exe --outdir signed --dlib C:\\trusted-signing\\Azure.CodeSigning.Dlib.dll --metadata-json C:\\trusted-signing\\metadata.json
  ${PROGRAM_NAME} --run-dir builds/1777168488 --triple x86_64-pc-windows-msvc --outdir signed --dlib C:\\trusted-signing\\Azure.CodeSigning.Dlib.dll --metadata-json C:\\trusted-signing\\metadata.json

EOF
}

parse_sign_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --file)
        SIGN_FILE_PATH="${2:?}"
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
      --outdir)
        SIGN_OUT_DIR="${2:?}"
        shift 2
        ;;
      --timestamp-url)
        SIGN_TIMESTAMP_URL="${2:?}"
        shift 2
        ;;
      --dlib)
        SIGN_DLIB_PATH="${2:?}"
        shift 2
        ;;
      --metadata-json)
        SIGN_METADATA_JSON="${2:?}"
        shift 2
        ;;
      --signtool)
        SIGN_SIGNTOOL_PATH="${2:?}"
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

cleanup_sign_tmp_dir() {
  if [[ -n "${SIGN_TMP_DIR:-}" ]]; then
    rm -rf "$SIGN_TMP_DIR"
  fi
}

find_signtool() {
  if [[ -n "$SIGN_SIGNTOOL_PATH" ]]; then
    [[ -x "$SIGN_SIGNTOOL_PATH" ]] || die "signtool not executable: $SIGN_SIGNTOOL_PATH"
    return
  fi

  if command -v signtool >/dev/null 2>&1; then
    SIGN_SIGNTOOL_PATH="$(command -v signtool)"
    return
  fi

  die "Microsoft signtool not found. Provide --signtool or run this on a Windows machine with the Windows SDK installed."
}

ensure_sign_tools() {
  find_signtool
  init_sha256_tool
}

validate_sign_inputs() {
  [[ -n "$SIGN_OUT_DIR" ]] || die "--outdir is required"
  [[ -n "$SIGN_DLIB_PATH" ]] || die "--dlib is required"
  [[ -n "$SIGN_METADATA_JSON" ]] || die "--metadata-json is required"
  [[ -f "$SIGN_DLIB_PATH" ]] || die "Azure CodeSigning dlib not found: $SIGN_DLIB_PATH"
  [[ -f "$SIGN_METADATA_JSON" ]] || die "Artifact Signing metadata JSON not found: $SIGN_METADATA_JSON"

  if [[ -n "$SIGN_FILE_PATH" && -n "$SIGN_RUN_DIR" ]]; then
    die "Provide either --file or --run-dir, not both"
  fi

  if [[ -n "$SIGN_FILE_PATH" ]]; then
    return
  fi

  [[ -n "$SIGN_RUN_DIR" ]] || die "Provide either --file or --run-dir"
  [[ -n "$SIGN_TRIPLE" ]] || die "--triple is required with --run-dir"
}

is_supported_windows_artifact() {
  case "$1" in
    *.exe|*.msi) return 0 ;;
    *) return 1 ;;
  esac
}

resolve_sign_inputs() {
  if [[ -n "$SIGN_FILE_PATH" ]]; then
    [[ -f "$SIGN_FILE_PATH" ]] || die "Artifact not found: $SIGN_FILE_PATH"
    is_supported_windows_artifact "$SIGN_FILE_PATH" || die "Unsupported artifact type: $SIGN_FILE_PATH"
    printf '%s\n' "$SIGN_FILE_PATH"
    return
  fi

  local artifact_dir="${SIGN_RUN_DIR}/artifacts/${SIGN_TRIPLE}"
  [[ -d "$artifact_dir" ]] || die "Artifact directory not found: $artifact_dir"

  local found=0
  while IFS= read -r candidate; do
    [[ -n "$candidate" ]] || continue
    found=1
    printf '%s\n' "$candidate"
  done < <(find "$artifact_dir" -type f \( -name '*.exe' -o -name '*.msi' \) | LC_ALL=C sort)

  [[ "$found" -eq 1 ]] || die "No Windows .exe/.msi artifacts found under: $artifact_dir"
}

sign_one_artifact() {
  local source_path="$1"
  local out_dir="$2"

  local tmp_copy final_path
  tmp_copy="${SIGN_TMP_DIR}/$(basename "$source_path")"
  final_path="${out_dir}/$(basename "$source_path")"

  [[ ! -e "$final_path" ]] || die "Output already exists: $final_path"

  cp "$source_path" "$tmp_copy"

  echo "Signing ${tmp_copy} with Azure Artifact Signing"
  "$SIGN_SIGNTOOL_PATH" sign \
    /v \
    /debug \
    /fd SHA256 \
    /tr "$SIGN_TIMESTAMP_URL" \
    /td SHA256 \
    /dlib "$SIGN_DLIB_PATH" \
    /dmdf "$SIGN_METADATA_JSON" \
    "$tmp_copy"

  # Verify the signed copy immediately after
  "$SIGN_SIGNTOOL_PATH" verify /v /debug /pa "$tmp_copy"

  cp "$tmp_copy" "$final_path"
  "$SIGN_SIGNTOOL_PATH" verify /v /debug /pa "$final_path"

  local sha256
  sha256="$(sha256_file "$final_path")"
  echo "- Artifact: $final_path"
  echo "- SHA256: $sha256"
}

main() {
  parse_sign_args "$@"
  validate_sign_inputs
  ensure_sign_tools

  mkdir -p "$SIGN_OUT_DIR"

  local tmp_dir
  tmp_dir="$(mktemp -d)"
  SIGN_TMP_DIR="$tmp_dir"
  trap cleanup_sign_tmp_dir EXIT

  local inputs=()
  while IFS= read -r path; do
    [[ -n "$path" ]] || continue
    inputs+=( "$path" )
  done < <(resolve_sign_inputs)

  [[ "${#inputs[@]}" -gt 0 ]] || die "No artifacts resolved for signing"

  echo "Signed Windows release output"
  echo "- SignTool: $SIGN_SIGNTOOL_PATH"
  echo "- Dlib: $SIGN_DLIB_PATH"
  echo "- Metadata: $SIGN_METADATA_JSON"
  for artifact in "${inputs[@]}"; do
    sign_one_artifact "$artifact" "$SIGN_OUT_DIR"
  done
  echo "- Status: signed and timestamped via Azure Artifact Signing"
}

main "$@"
