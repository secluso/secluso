#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later

# Shared primitives for the release build system
#
# Avoids build-mode policy. It only exposes generic
# utilities used by every pipeline path (rust binaries, deploy desktop app, and
# compare mode). Keeping these helpers centralized gives us consistent error
# behavior and consistent artifact metadata regardless of what is being built.
#
# our new Output "contract" is every build run now uses this shape:
#   <run-dir>/manifest.json
#   <run-dir>/artifacts/<target-triple>/...
#
# helps removes the ambiguity of some files in the run root and some in
# per-triple directories and makes it obvious what to archive and hand to
# auditors for independent verification.

usage() {
  echo "Usage:" >&2
  echo "  ${PROGRAM_NAME} --target {raspberry|ipcamera|server|all|deploy} --profile <profile> [--test-reproduce]" >&2
  echo "  ${PROGRAM_NAME} --compare <build_dir_run1> <build_dir_run2>" >&2
  echo "" >&2
  echo "Deploy profiles:" >&2
  echo "  all|linux|macos|windows|linux-x64|linux-arm64|macos-x64|macos-arm64|windows-x64|windows-arm64" >&2
}

die() {
  echo "$*" >&2
  exit 1
}

require_tool() {
  local tool="$1"
  if ! command -v "$tool" >/dev/null 2>&1; then
    die "Required tool missing: $tool"
  fi
}

init_sha256_tool() {
  if command -v sha256sum >/dev/null 2>&1; then
    SHA256_TOOL="sha256sum"
    SHA256_ARGS=()
    return
  fi

  if command -v shasum >/dev/null 2>&1; then
    SHA256_TOOL="shasum"
    SHA256_ARGS=( -a 256 )
    return
  fi

  die "Required tool missing: sha256sum (or shasum)"
}

sha256_file() {
  local file_path="$1"
  # Bash 3.2 + nounset treats an empty array expansion as unbound. Branch on
  # arg count so we can safely support both sha256sum (no extra args) and
  # shasum -a 256 (extra args) without passing empty argv entries.
  if [[ ${#SHA256_ARGS[@]} -gt 0 ]]; then
    "$SHA256_TOOL" "${SHA256_ARGS[@]}" "$file_path" | awk '{print $1}'
  else
    "$SHA256_TOOL" "$file_path" | awk '{print $1}'
  fi
}

sha256_stdin() {
  if [[ ${#SHA256_ARGS[@]} -gt 0 ]]; then
    "$SHA256_TOOL" "${SHA256_ARGS[@]}" | awk '{print $1}'
  else
    "$SHA256_TOOL" | awk '{print $1}'
  fi
}

normalized_macho_sha256_file() {
  local file_path="$1"

  # This is intentionally not a general-purpose Mach-O canonicalizer.
  # It is a (narrow) comparison helper for release verification, specifically for cases where the executable payload should match but Apple signing/related post-processing mutate some bytes in some (predictable) places.
  #
  # Current normalization policy we use here:
  # [1] zero LC_UUID because it is per-build identity metadata rather than payload
  # [2] zero LC_CODE_SIGNATURE and its detached blob because signing always rewrites that area
  # [3] zero selected __LINKEDIT size fields that move around with signing
  # [4] truncate from the earliest signature blob offset onward so trailing ignature-only bytes do not affect the comparison hash
  perl -MDigest::SHA=sha256_hex -e '
    use strict;
    use warnings;

    sub u32le {
      return unpack("V", substr($_[0], $_[1], 4));
    }

    my $path = shift @ARGV;
    open my $fh, "<", $path or die "open($path): $!";
    binmode $fh;
    local $/;
    my $data = <$fh>;

    my $magic = u32le($data, 0);
    if ($magic == 0xfeedfacf) {
      # Thin 64-bit little-endian Mach-O header. Load commands start at byte 32.
      my $ncmds = u32le($data, 16);
      my $offset = 32;
      my $signature_offset;

      for (my $i = 0; $i < $ncmds; $i++) {
        last if $offset + 8 > length($data);
        my $cmd = u32le($data, $offset);
        my $cmdsize = u32le($data, $offset + 4);
        last if $cmdsize < 8 || $offset + $cmdsize > length($data);

        if ($cmd == 0x19) {
          # LC_SEGMENT_64.
          # When the segment is __LINKEDIT, signing can move around bookkeeping in ways that change these size fields without changing the code/data payload we care about reproducing.
          my $segname = substr($data, $offset + 8, 16);
          $segname =~ s/\0.*$//s;
          if ($segname eq "__LINKEDIT") {
            # Zero vmsize and filesize within this load command.
            substr($data, $offset + 32, 8) = "\0" x 8;
            substr($data, $offset + 48, 8) = "\0" x 8;
          }
        } elsif ($cmd == 0x1b) {
          # LC_UUID is expected to vary between otherwise equivalent builds, so we drop the entire command from the comparison view.
          substr($data, $offset, $cmdsize) = "\0" x $cmdsize;
        } elsif ($cmd == 0x1d) {
          # LC_CODE_SIGNATURE points to the detached signature blob.
          # Release signing rewrites both the command metadata and the blob contents, so neither should participate in payload comparison.
          my $dataoff = u32le($data, $offset + 8);
          my $datasize = u32le($data, $offset + 12);
          if (!defined($signature_offset) || $dataoff < $signature_offset) {
            $signature_offset = $dataoff;
          }
          if ($dataoff + $datasize <= length($data)) {
            substr($data, $dataoff, $datasize) = "\0" x $datasize;
          }
          substr($data, $offset, $cmdsize) = "\0" x $cmdsize;
        }

        $offset += $cmdsize;
      }

      if (defined($signature_offset) && $signature_offset <= length($data)) {
        # Drop all bytes from the first signature blob onward.
        # In our current outputs that trailing region is signature-owned, so this prevents release signing noise from surviving the earlier load-command edits.
        # TODO: tighten this to discard only bytes we can prove belong to the code-signature region, instead of truncating the entire suffix from the first signature offset onward.
        substr($data, $signature_offset) = "";
      }
    }

    print sha256_hex($data);
  ' "$file_path"
}

lookup_rust_digest() {
  local triple="$1"
  local key
  key="$(printf '%s' "$triple" | tr '[:lower:]' '[:upper:]' | tr '-' '_')"
  local var="RUST_DIGEST__${key}"
  printf '%s' "${!var:-}"
}

artifact_dir_for_triple() {
  local run_dir="$1"
  local triple="$2"
  printf '%s/artifacts/%s' "$run_dir" "$triple"
}

write_manifest() {
  local outdir="$1"
  local run_id="$2"
  local artifacts_json="$3"
  local artifacts_joined

  artifacts_joined="$(paste -sd',' "$artifacts_json")"

  cat > "$outdir/manifest.json" <<JSON
{
  "build": {
    "target": "$TARGET",
    "profile": "$PROFILE",
    "run_id": "$run_id",
    "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  },
  "artifacts": [
$artifacts_joined
  ]
}
JSON
}

finalize_run_output() {
  local run_dir="$1"
  local _run_id="$2"

  echo "Run output"
  echo "- Manifest : $run_dir/manifest.json"
  echo "- Artifacts: $run_dir/artifacts"
  echo ""
}
