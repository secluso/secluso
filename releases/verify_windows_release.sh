#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail
IFS=$'\n\t'

# Verify a Windows release directly against a local reproducible build.
#
# We do not use a published manifest.
# The trust model is to build it yourself, normalize the shipped signed Windows artifact, and compare the two executable payloads directly.
#
# The comparison this script performs is not a raw exe byte diff.
# Signed Windows releases pick up Authenticode-specific metadata that should differ from the unsigned reproducible build.
# We therefore materialize normalized copies, strip only the exact PE signing fields/blob that Authenticode is allowed to touch, and then compare the resulting files byte-for-byte.

PROGRAM_NAME="$(basename "$0")"
RELEASES_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck disable=SC1091
source "${RELEASES_DIR}/lib/common.bash"

VERIFY_LOCAL_FILE=""
VERIFY_LOCAL_RUN=""
VERIFY_TRIPLE=""
VERIFY_RELEASE_PATH=""
VERIFY_SIGNTOOL_PATH="${VERIFY_SIGNTOOL_PATH:-}"
VERIFY_POWERSHELL_PATH="${VERIFY_POWERSHELL_PATH:-}"
VERIFY_EXPECTED_SUBJECT="${VERIFY_EXPECTED_SUBJECT:-Secluso, Inc.}"

VERIFY_EXPECTED_CERT_SHA1="${VERIFY_EXPECTED_CERT_SHA1:-0B3B3AB560AB193B55C334EA619C716E57EAC4E5}"
VERIFY_KEEP_TEMP=0
VERIFY_TMP_DIR=""

verify_usage() {
  cat >&2 <<EOF
Usage:
  ${PROGRAM_NAME} --local-file /path/to/unsigned.exe --release /path/to/signed.exe [--signtool PATH] [--expected-cert-sha1 SHA1]
  ${PROGRAM_NAME} --local-run RUN_DIR --triple {x86_64-pc-windows-msvc|aarch64-pc-windows-msvc} --release /path/to/signed.exe [--signtool PATH] [--expected-cert-sha1 SHA1]

Environment:
  VERIFY_EXPECTED_SUBJECT   expected leaf signer subject common name (default: Secluso, Inc.)
  VERIFY_EXPECTED_CERT_SHA1 expected leaf signer certificate SHA-1 thumbprint
  VERIFY_SIGNTOOL_PATH      path to signtool.exe when it is not on PATH
  VERIFY_POWERSHELL_PATH    path to powershell.exe or pwsh when it is not on PATH

EOF
}

parse_verify_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --local-file)
        VERIFY_LOCAL_FILE="${2:?}"
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
      --signtool)
        VERIFY_SIGNTOOL_PATH="${2:?}"
        shift 2
        ;;
      --expected-cert-sha1)
        VERIFY_EXPECTED_CERT_SHA1="${2:?}"
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

cleanup_verify_tmp_dir() {
  if [[ -n "${VERIFY_TMP_DIR:-}" ]]; then
    rm -rf "$VERIFY_TMP_DIR"
  fi
}

find_signtool() {
  if [[ -n "$VERIFY_SIGNTOOL_PATH" ]]; then
    [[ -x "$VERIFY_SIGNTOOL_PATH" ]] || die "signtool not executable: $VERIFY_SIGNTOOL_PATH"
    return
  fi

  if command -v signtool >/dev/null 2>&1; then
    VERIFY_SIGNTOOL_PATH="$(command -v signtool)"
    return
  fi

  local candidate
  for candidate in \
    "/c/Program Files (x86)/Windows Kits/10/bin"/*/x64/signtool.exe \
    "/c/Program Files (x86)/Windows Kits/10/bin"/*/x86/signtool.exe
  do
    if [[ -x "$candidate" ]]; then
      VERIFY_SIGNTOOL_PATH="$candidate"
      return
    fi
  done

  die "Microsoft signtool not found. Provide --signtool or run this on a Windows machine with the Windows SDK installed."
}

find_powershell() {
  if [[ -n "$VERIFY_POWERSHELL_PATH" ]]; then
    [[ -x "$VERIFY_POWERSHELL_PATH" ]] || die "PowerShell not executable: $VERIFY_POWERSHELL_PATH"
    return
  fi

  local candidate
  for candidate in powershell.exe powershell pwsh.exe pwsh; do
    if command -v "$candidate" >/dev/null 2>&1; then
      VERIFY_POWERSHELL_PATH="$(command -v "$candidate")"
      return
    fi
  done

  die "PowerShell not found. It is required to extract the primary Authenticode signer certificate for certificate pinning."
}

ensure_verify_tools() {
  require_tool perl
  require_tool cmp
  require_tool diff
  find_signtool
  find_powershell
  # Keep Git Bash/MSYS from rewriting signtool's slash-prefixed options into filesystem paths when it launches the native Windows executable.
  export MSYS2_ARG_CONV_EXCL="${MSYS2_ARG_CONV_EXCL:-};/v;/debug;/pa"
  init_sha256_tool
}

is_supported_windows_artifact() {
  case "$1" in
    *.exe) return 0 ;;
    *) return 1 ;;
  esac
}

resolve_local_file() {
  if [[ -n "$VERIFY_LOCAL_FILE" ]]; then
    [[ -f "$VERIFY_LOCAL_FILE" ]] || die "Local unsigned artifact not found: $VERIFY_LOCAL_FILE"
    is_supported_windows_artifact "$VERIFY_LOCAL_FILE" || die "Unsupported local artifact type: $VERIFY_LOCAL_FILE (expected .exe)"
    printf '%s\n' "$VERIFY_LOCAL_FILE"
    return
  fi

  [[ -n "$VERIFY_LOCAL_RUN" ]] || die "Provide either --local-file or --local-run"
  [[ -n "$VERIFY_TRIPLE" ]] || die "--triple is required with --local-run"

  local artifact_dir="${VERIFY_LOCAL_RUN}/artifacts/${VERIFY_TRIPLE}"
  [[ -d "$artifact_dir" ]] || die "Artifact directory not found: $artifact_dir"

  local local_path=""
  while IFS= read -r candidate; do
    [[ -n "$candidate" ]] || continue
    if [[ -n "$local_path" ]]; then
      die "More than one Windows .exe artifact found under: $artifact_dir"
    fi
    local_path="$candidate"
  done < <(find "$artifact_dir" -type f -name '*.exe' | LC_ALL=C sort)

  [[ -n "$local_path" ]] || die "No Windows .exe artifacts found under: $artifact_dir"
  printf '%s\n' "$local_path"
}

normalize_cert_sha1() {
  local value="$1"
  printf '%s' "$value" | tr '[:lower:]' '[:upper:]' | tr -cd 'A-F0-9'
}

absolute_path() {
  local path="$1"
  local dir base
  dir="$(cd -- "$(dirname -- "$path")" && pwd -P)" || return 1
  base="$(basename -- "$path")"
  printf '%s/%s\n' "$dir" "$base"
}

path_for_powershell() {
  local path="$1"
  local abs_path
  abs_path="$(absolute_path "$path")" || return 1

  if command -v cygpath >/dev/null 2>&1; then
    cygpath -w "$abs_path"
    return
  fi

  printf '%s\n' "$abs_path"
}

primary_signer_certificate_info() {
  local release_path="$1"
  local ps_path ps_output
  ps_path="$(path_for_powershell "$release_path")" || die "Failed to resolve release path for PowerShell: $release_path"

  if ! ps_output="$(VERIFY_RELEASE_PATH_PS="$ps_path" "$VERIFY_POWERSHELL_PATH" -NoProfile -NonInteractive -Command '
    $ErrorActionPreference = "Stop"
    $sig = Get-AuthenticodeSignature -LiteralPath $env:VERIFY_RELEASE_PATH_PS
    if ($null -eq $sig.SignerCertificate) {
      throw "No primary signer certificate was returned by Get-AuthenticodeSignature"
    }
    $cert = $sig.SignerCertificate
    Write-Output ("status`t{0}" -f $sig.Status)
    Write-Output ("subject`t{0}" -f $cert.Subject)
    Write-Output ("simple_name`t{0}" -f $cert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false))
    Write-Output ("thumbprint`t{0}" -f $cert.Thumbprint)
  ' 2>&1)"; then
    printf '%s\n' "$ps_output" >&2
    die "Failed to inspect primary Authenticode signer certificate: $release_path"
  fi

  printf '%s\n' "$ps_output"
}

verify_primary_signer_certificate_pin() {
  local release_path="$1"
  local cert_info simple_name thumbprint expected_sha1
  cert_info="$(primary_signer_certificate_info "$release_path")"
  simple_name="$(awk -F'\t' '$1 == "simple_name" { print $2; exit }' <<<"$cert_info")"
  thumbprint="$(awk -F'\t' '$1 == "thumbprint" { print $2; exit }' <<<"$cert_info")"
  expected_sha1="$(normalize_cert_sha1 "$VERIFY_EXPECTED_CERT_SHA1")"
  thumbprint="$(normalize_cert_sha1 "$thumbprint")"

  [[ -n "$simple_name" ]] || die "Primary signer certificate is missing a subject common name: $release_path"
  [[ "$simple_name" == "$VERIFY_EXPECTED_SUBJECT" ]] || die "Release signer mismatch: expected ${VERIFY_EXPECTED_SUBJECT}, got ${simple_name}"
  [[ -n "$thumbprint" ]] || die "Primary signer certificate is missing a thumbprint: $release_path"
  [[ "$thumbprint" == "$expected_sha1" ]] || die "Release signer certificate thumbprint mismatch: expected ${expected_sha1}, got ${thumbprint}"
}

verify_release_signing_policy() {
  local release_path="$1"
  [[ -f "$release_path" ]] || die "Release artifact not found: $release_path"
  is_supported_windows_artifact "$release_path" || die "Unsupported release artifact type: $release_path (expected .exe)"

  local verify_output
  if ! verify_output="$("$VERIFY_SIGNTOOL_PATH" verify /v /debug /pa "$release_path" 2>&1)"; then
    printf '%s\n' "$verify_output" >&2
    die "Authenticode verification failed: $release_path"
  fi

  # Enforce the Windows-side release policy before we do any signed-vs-unsigned equivalence work.
  # is the downloaded release still a valid Authenticode-signed artifact with the identity and timestamp properties we expect?
  grep -q 'Successfully verified:' <<<"$verify_output" || die "signtool did not report successful verification: $release_path"
  grep -q 'Signature Index: 0 (Primary Signature)' <<<"$verify_output" || die "Release is missing a primary Authenticode signature: $release_path"
  grep -q 'The signature is timestamped:' <<<"$verify_output" || die "Release signature is missing a trusted timestamp: $release_path"
  grep -q 'Timestamp Verified by:' <<<"$verify_output" || die "Release timestamp chain was not verified: $release_path"

  # Pin the primary signer certificate structurally through the Windows Authenticode API, rather than by grepping signtool text output.
  verify_primary_signer_certificate_pin "$release_path"

  printf '%s\n' "$verify_output"
}

normalize_pe_file() {
  local file_path="$1"
  local out_file="$2"
  local info_file="$3"
  local expected_signature_state="$4"

  [[ -f "$file_path" ]] || die "PE file not found for normalization: $file_path"

  # Public Windows release installers are expected to differ from the reproducible local build in exactly the places Authenticode signing touches.
  #
  # examples: the PE checksum, the PE security directory, optional alignment padding immediately before the certificate table, and the WIN_CERTIFICATE blob itself.
  # Everything else is executable/installer payload and must persist after normalization unchanged.
  #
  # This is a (narrow) comparison helper for release verification, and it fails on layouts we do not explicitly understand.
  perl -e '
    use strict;
    use warnings;

    sub u16le { return unpack("v", substr($_[0], $_[1], 2)); }
    sub u32le { return unpack("V", substr($_[0], $_[1], 4)); }
    sub put_u32le { substr($_[0], $_[1], 4) = pack("V", $_[2]); }

    my ($path, $out_path, $info_path, $expected_signature_state) = @ARGV;
    open my $fh, "<", $path or die "open($path): $!";
    binmode $fh;
    local $/;
    my $data = <$fh>;
    my $file_len = length($data);

    die "file too small for MZ header: $path\n" if $file_len < 0x40;
    die "missing MZ header: $path\n" if substr($data, 0, 2) ne "MZ";

    my $pe_off = u32le($data, 0x3c);
    die "invalid PE header offset in $path\n" if $pe_off + 24 > $file_len;
    die "missing PE signature: $path\n" if substr($data, $pe_off, 4) ne "PE\0\0";

    my $coff_off = $pe_off + 4;
    my $optional_size = u16le($data, $coff_off + 16);
    my $optional_off = $coff_off + 20;
    die "truncated optional header in $path\n" if $optional_off + $optional_size > $file_len;

    my $magic = u16le($data, $optional_off);
    my ($checksum_off, $number_rva_off);
    if ($magic == 0x10b) {
      $checksum_off = $optional_off + 64;
      $number_rva_off = $optional_off + 92;
    } elsif ($magic == 0x20b) {
      $checksum_off = $optional_off + 64;
      $number_rva_off = $optional_off + 108;
    } else {
      die "unsupported PE optional-header magic in $path\n";
    }

    die "truncated PE data directories in $path\n" if $number_rva_off + 4 > $optional_off + $optional_size;
    my $number_rva = u32le($data, $number_rva_off);
    die "PE has no certificate directory in $path\n" if $number_rva < 5;

    my $cert_dir_off = $number_rva_off + 4 + (4 * 8);
    die "truncated certificate directory in $path\n" if $cert_dir_off + 8 > $optional_off + $optional_size;

    my $checksum = u32le($data, $checksum_off);
    my $cert_file_off = u32le($data, $cert_dir_off);
    my $cert_size = u32le($data, $cert_dir_off + 4);
    my $cert_pad_size = 0;

    # Authenticode rewrites the PE checksum and points the security directory at the appended WIN_CERTIFICATE.
    # Zero those bookkeeping fields in both views so they do not outweigh the payload comparison.
    put_u32le($data, $checksum_off, 0);
    put_u32le($data, $cert_dir_off, 0);
    put_u32le($data, $cert_dir_off + 4, 0);

    if ($cert_file_off != 0 || $cert_size != 0) {
      die "expected unsigned PE but found certificate table in $path\n"
        if $expected_signature_state eq "unsigned";
      die "invalid certificate table bounds in $path\n"
        if $cert_file_off <= 0 || $cert_size <= 0 || $cert_file_off + $cert_size > $file_len;
      die "certificate table is not at end of file in $path\n"
        if $cert_file_off + $cert_size != $file_len;
      die "certificate table is not 8-byte aligned in $path\n"
        if ($cert_file_off % 8) != 0;

      # The certificate table is intentionally a file offset rather than an RVA.
      # Require it to be the final structure in the file so there is no unchecked overlay after the signature.
      substr($data, $cert_file_off, $cert_size) = "";

      # Authenticode places WIN_CERTIFICATE on an 8-byte boundary.
      # Some installers therefore gain a small NUL pad immediately before the certificate table.
      # Drop at most that alignment pad, and only when it is literally NUL bytes at the end of the remaining file.
      for (my $i = 0; $i < 7 && length($data) > 0; $i++) {
        last if substr($data, length($data) - 1, 1) ne "\0";
        substr($data, length($data) - 1, 1) = "";
        $cert_pad_size++;
      }
    } elsif ($expected_signature_state eq "signed") {
      die "expected signed PE but certificate table is empty in $path\n";
    }

    open my $out, ">", $out_path or die "open($out_path): $!";
    binmode $out;
    print {$out} $data;
    close $out or die "close($out_path): $!";

    # Keep the normalization facts as an audit artifact.
    # If comparison fails, these lines make it obvious whether the difference was in normal payload bytes or in the PE signing envelope.
    open my $info, ">", $info_path or die "open($info_path): $!";
    print {$info} "path\t$path\n";
    print {$info} "file_size\t$file_len\n";
    print {$info} "pe_header_offset\t$pe_off\n";
    print {$info} "optional_header_magic\t", sprintf("0x%x", $magic), "\n";
    print {$info} "checksum_offset\t$checksum_off\n";
    print {$info} "checksum_value\t$checksum\n";
    print {$info} "cert_directory_offset\t$cert_dir_off\n";
    print {$info} "cert_file_offset\t$cert_file_off\n";
    print {$info} "cert_size\t$cert_size\n";
    print {$info} "cert_alignment_pad_size\t$cert_pad_size\n";
    print {$info} "normalized_size\t", length($data), "\n";
    close $info or die "close($info_path): $!";
  ' "$file_path" "$out_file" "$info_file" "$expected_signature_state"
}

write_artifact_inventory() {
  local label="$1"
  local file_path="$2"
  local normalized_path="$3"
  local pe_info_path="$4"
  local out_file="$5"

  local raw_sha normalized_sha size
  raw_sha="$(sha256_file "$file_path")"
  raw_sha="${raw_sha#\\}"
  normalized_sha="$(sha256_file "$normalized_path")"
  normalized_sha="${normalized_sha#\\}"
  size="$(wc -c < "$file_path" | awk '{print $1}')"

  # makes the failure diff readable while cmp remains the actual byte-for-byte payload check.
  {
    printf 'label\t%s\n' "$label"
    printf 'basename\t%s\n' "$(basename "$file_path")"
    printf 'size\t%s\n' "$size"
    printf 'raw_sha256\t%s\n' "$raw_sha"
    printf 'normalized_pe_sha256\t%s\n' "$normalized_sha"
    cat "$pe_info_path"
  } > "$out_file"
}

compare_normalized_payloads() {
  local local_normalized="$1"
  local release_normalized="$2"
  local diff_out="$3"

  # Above removes only the explicit Authenticode envelope.
  # This is the part that checks every remaining byte from the shipped release against the local reproducible build.
  if cmp -s "$local_normalized" "$release_normalized"; then
    return 0
  fi

  {
    echo "First differing normalized bytes:"
    # cmp reports 1-based byte offsets and octal byte values.
    # Keeping the first handful of differences is enough to see whether the mismatch is header-adjacent OR deep installer payload changes
    cmp -l "$local_normalized" "$release_normalized" | head -n 40
  } > "$diff_out" || true
  return 1
}

main() {
  parse_verify_args "$@"
  [[ -n "$VERIFY_RELEASE_PATH" ]] || die "--release is required"
  ensure_verify_tools

  local local_file
  local_file="$(resolve_local_file)"

  local tmp_dir
  tmp_dir="$(mktemp -d)"
  VERIFY_TMP_DIR="$tmp_dir"
  if [[ "$VERIFY_KEEP_TEMP" -eq 0 ]]; then
    trap cleanup_verify_tmp_dir EXIT
  fi

  # release side is the signed/timestamped artifact someone downloaded
  # local side is the unsigned artifact produced by a reproducible build
  local signing_report="${tmp_dir}/signtool-verify.txt"
  verify_release_signing_policy "$VERIFY_RELEASE_PATH" > "$signing_report"

  local local_normalized_file="${tmp_dir}/local.normalized.exe"
  local release_normalized_file="${tmp_dir}/release.normalized.exe"
  local local_pe_info="${tmp_dir}/local.pe-info.txt"
  local release_pe_info="${tmp_dir}/release.pe-info.txt"
  # Materialize normalized files before comparison instead of relying only on a hash.
  # That keeps the byte-for-byte claim concrete, and --keep-temp lets an auditor inspect the exact files compared.
  normalize_pe_file "$local_file" "$local_normalized_file" "$local_pe_info" "unsigned"
  normalize_pe_file "$VERIFY_RELEASE_PATH" "$release_normalized_file" "$release_pe_info" "signed"

  local local_inv="${tmp_dir}/local.inventory.txt"
  local release_inv="${tmp_dir}/release.inventory.txt"
  write_artifact_inventory "local" "$local_file" "$local_normalized_file" "$local_pe_info" "$local_inv"
  write_artifact_inventory "release" "$VERIFY_RELEASE_PATH" "$release_normalized_file" "$release_pe_info" "$release_inv"

  local normalized_diff="${tmp_dir}/normalized-byte-diff.txt"
  if ! compare_normalized_payloads "$local_normalized_file" "$release_normalized_file" "$normalized_diff"; then
    diff -u "$local_inv" "$release_inv" || true
    cat "$normalized_diff" >&2
    echo ""
    echo "Windows release verification FAILED"
    echo "- Local unsigned artifact : $local_file"
    echo "- Release input           : $VERIFY_RELEASE_PATH"
    if [[ "$VERIFY_KEEP_TEMP" -eq 1 ]]; then
      echo "- Temp dir                : $tmp_dir"
    fi
    exit 1
  fi

  local release_sha release_normalized
  release_sha="$(awk -F'\t' '$1 == "raw_sha256" { print $2; exit }' "$release_inv")"
  release_normalized="$(awk -F'\t' '$1 == "normalized_pe_sha256" { print $2; exit }' "$release_inv")"

  echo "Windows release verification PASSED"
  echo "- Local unsigned artifact : $local_file"
  echo "- Release input           : $VERIFY_RELEASE_PATH"
  echo "- Signer                  : $VERIFY_EXPECTED_SUBJECT"
  echo "- Signer cert SHA1        : $VERIFY_EXPECTED_CERT_SHA1"
  echo "- Release SHA256          : $release_sha"
  echo "- Normalized PE SHA256    : $release_normalized"
  echo "- Byte comparison         : all normalized bytes match"
  if [[ "$VERIFY_KEEP_TEMP" -eq 1 ]]; then
    echo "- Temp dir                : $tmp_dir"
  fi
}

main "$@"
