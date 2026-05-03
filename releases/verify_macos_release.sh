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
VERIFY_EXPECTED_ENTITLEMENTS_PLIST="${VERIFY_EXPECTED_ENTITLEMENTS_PLIST:-${RELEASES_DIR}/expected_macos_entitlements.plist}"

verify_usage() {
  cat >&2 <<EOF
Usage:
  ${PROGRAM_NAME} --local-app /path/to/Secluso\\ Deploy.app --release /path/to/release.app.zip [--expected-team-id TEAMID] [--expected-entitlements-plist PATH]
  ${PROGRAM_NAME} --local-run RUN_DIR --triple {x86_64-apple-darwin|aarch64-apple-darwin} --release /path/to/release.app.zip [--expected-team-id TEAMID] [--expected-entitlements-plist PATH]

Environment:
  VERIFY_EXPECTED_TEAM_ID             expected Apple Developer Team ID (default: 8PYH264TD9)
  VERIFY_EXPECTED_ENTITLEMENTS_PLIST  expected release entitlements plist

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
      --expected-team-id)
        VERIFY_EXPECTED_TEAM_ID="${2:?}"
        shift 2
        ;;
      --expected-entitlements-plist)
        VERIFY_EXPECTED_ENTITLEMENTS_PLIST="${2:?}"
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
  require_tool plutil
  require_tool xattr
  require_tool xcrun
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

  # Require the core distribution properties this release policy expects for outside-App-Store delivery (hardened runtime metadata, CMS signing metadata, and a stapled notarization ticket on the artifact being checked)
  grep -q 'flags=0x10000(runtime)' <<<"$release_meta" || die "Release is missing hardened runtime flag: $release_app"
  grep -q '^Runtime Version=' <<<"$release_meta" || die "Release signing metadata is missing Runtime Version: $release_app"
  grep -q '^CMSDigest=' <<<"$release_meta" || die "Release signing metadata is missing CMSDigest: $release_app"
  grep -q '^Notarization Ticket=stapled' <<<"$release_meta" || die "Release is missing a stapled notarization ticket: $release_app"

  # Stapler validates the ticket payload, while spctl exercises Apple's execution policy layer rather than only the embedded signature structure itself
  xcrun stapler validate "$release_app" || die "Stapled notarization ticket validation failed: $release_app"
  spctl --assess --type execute --verbose=4 "$release_app" || die "spctl execution-policy assessment failed: $release_app"
}

write_empty_plist() {
  local out_file="$1"
  # codesign prints nothing when a binary has no entitlements at all.
  # verifier wants a policy artifact either way, so we put together an empty plist to compare in that instance
  cat > "$out_file" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict/>
</plist>
EOF
}

app_main_executable_path() {
  local app_dir="$1"
  [[ -d "$app_dir" ]] || die "App bundle not found: $app_dir"

  local executable_name executable_path
  executable_name="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$app_dir/Contents/Info.plist" 2>/dev/null || true)"
  [[ -n "$executable_name" ]] || die "App Info.plist is missing CFBundleExecutable: $app_dir"
  executable_path="$app_dir/Contents/MacOS/$executable_name"
  [[ -f "$executable_path" ]] || die "App executable not found: $executable_path"
  printf '%s\n' "$executable_path"
}

release_main_executable_has_embedded_entitlements_blob() {
  local executable_path="$1"
  [[ -f "$executable_path" ]] || die "Executable not found for entitlements-blob check: $executable_path"

  perl -e '
    use strict;
    use warnings;

    sub u32le {
      return unpack("V", substr($_[0], $_[1], 4));
    }

    sub u32be {
      return unpack("N", substr($_[0], $_[1], 4));
    }

    my $path = shift @ARGV;
    open my $fh, "<", $path or die "open($path): $!";
    binmode $fh;
    local $/;
    my $data = <$fh>;
    my $file_len = length($data);

    die "unsupported Mach-O magic in $path\n" if u32le($data, 0) != 0xfeedfacf;

    my $ncmds = u32le($data, 16);
    my $offset = 32;
    my ($sig_dataoff, $sig_datasize);

    for (my $i = 0; $i < $ncmds; $i++) {
      die "truncated Mach-O load commands in $path\n" if $offset + 8 > $file_len;
      my $cmd = u32le($data, $offset);
      my $cmdsize = u32le($data, $offset + 4);
      die "invalid load command size in $path\n" if $cmdsize < 8 || $offset + $cmdsize > $file_len;

      if ($cmd == 0x1d) {
        die "unexpected LC_CODE_SIGNATURE size in $path\n" if $cmdsize < 16;
        die "multiple LC_CODE_SIGNATURE commands in $path\n" if defined $sig_dataoff;
        $sig_dataoff = u32le($data, $offset + 8);
        $sig_datasize = u32le($data, $offset + 12);
      }

      $offset += $cmdsize;
    }

    die "missing LC_CODE_SIGNATURE in $path\n" if !defined $sig_dataoff;
    die "empty LC_CODE_SIGNATURE in $path\n" if $sig_datasize == 0;
    die "LC_CODE_SIGNATURE exceeds file in $path\n" if $sig_dataoff + $sig_datasize > $file_len;
    die "LC_CODE_SIGNATURE too short for SuperBlob header in $path\n" if $sig_datasize < 12;

    my $sig = substr($data, $sig_dataoff, $sig_datasize);
    die "LC_CODE_SIGNATURE is not a SuperBlob in $path\n" if u32be($sig, 0) != 0xfade0cc0;

    my $superblob_len = u32be($sig, 4);
    my $count = u32be($sig, 8);
    my $index_end = 12 + ($count * 8);

    die "SuperBlob length too small in $path\n" if $superblob_len < $index_end;
    die "SuperBlob length exceeds LC_CODE_SIGNATURE size in $path\n" if $superblob_len > $sig_datasize;

    for (my $i = 0; $i < $count; $i++) {
      my $entry_off = 12 + ($i * 8);
      my $blob_off = u32be($sig, $entry_off + 4);
      die "SuperBlob index points outside SuperBlob in $path\n" if $blob_off + 8 > $superblob_len;
      my $blob_magic = u32be($sig, $blob_off);
      if ($blob_magic == 0xfade7171 || $blob_magic == 0xfade7172) {
        exit 0;
      }
    }

    exit 1;
  ' "$executable_path"
}

verify_release_entitlements_policy() {
  local release_app="$1"
  [[ -d "$release_app" ]] || die "Release app bundle not found for entitlements check: $release_app"
  [[ -f "$VERIFY_EXPECTED_ENTITLEMENTS_PLIST" ]] || die "Expected entitlements plist not found: $VERIFY_EXPECTED_ENTITLEMENTS_PLIST"

  local expected_xml actual_raw actual_xml release_main_executable
  expected_xml="$(mktemp)"
  actual_raw="$(mktemp)"
  actual_xml="$(mktemp)"
  release_main_executable="$(app_main_executable_path "$release_app")"

  # Explicitly policy check what powers does the signed app request from macOS at runtime because they live inside the signature blob we do not compare byte-for-byte
  plutil -convert xml1 -o "$expected_xml" "$VERIFY_EXPECTED_ENTITLEMENTS_PLIST"
  codesign -d --entitlements - "$release_app" >"$actual_raw" 2>/dev/null || die "Failed to extract entitlements from release app: $release_app"

  if [[ ! -s "$actual_raw" ]]; then
    # Do not treat empty extractor output as automatically safe.
    # Only default to an empty plist when the signed Mach-O structure itself has no embedded entitlement blobs at all.
    # If there is an entitlement blob but codesign does not give us a plist, fail.
    if release_main_executable_has_embedded_entitlements_blob "$release_main_executable"; then
      rm -f "$expected_xml" "$actual_raw" "$actual_xml"
      die "Release executable has embedded entitlement blobs, but no entitlement plist could be extracted: $release_main_executable"
    fi

    # No output from codesign and no embedded entitlement blobs
    # Convert that into the same empty-plist as expected_macos_entitlements so a normal diff can enforce the expectation.
    write_empty_plist "$actual_xml"
  else
    plutil -convert xml1 -o "$actual_xml" "$actual_raw"
  fi

  if ! diff -u "$expected_xml" "$actual_xml"; then
    rm -f "$expected_xml" "$actual_raw" "$actual_xml"
    die "Release entitlements do not match expected policy: $release_app"
  fi

  rm -f "$expected_xml" "$actual_raw" "$actual_xml"
}

verify_macho_signature_tail_matches_local() {
  local local_path="$1"
  local release_path="$2"
  [[ -f "$local_path" ]] || die "Local Mach-O file not found for signature-tail check: $local_path"
  [[ -f "$release_path" ]] || die "Release Mach-O file not found for signature-tail check: $release_path"

  # The normalized Mach-O comparison removes the full LC_CODE_SIGNATURE region from the signed release view.
  # Most of that region is Apple signing data, but we also see it leaves trailing bytes after the declared SuperBlob length.
  # Those bytes are not executable code, but we still want them checked somehow.
  #
  # So when the signed artifact has a tail beyond the parsed SuperBlob, require that tail to be inherited unchanged from the local build at the same file offsets and within the local build's own LC_CODE_SIGNATURE region.
  if ! perl -e '
    use strict;
    use warnings;

    sub u32le {
      return unpack("V", substr($_[0], $_[1], 4));
    }

    sub u64le {
      return unpack("Q<", substr($_[0], $_[1], 8));
    }

    sub u32be {
      return unpack("N", substr($_[0], $_[1], 4));
    }

    sub parse_macho_signature_region {
      my ($data, $path) = @_;
      my $file_len = length($data);
      die "unsupported Mach-O magic in $path\n" if u32le($data, 0) != 0xfeedfacf;

      my $ncmds = u32le($data, 16);
      my $offset = 32;
      my ($sig_dataoff, $sig_datasize);

      for (my $i = 0; $i < $ncmds; $i++) {
        die "truncated Mach-O load commands in $path\n" if $offset + 8 > $file_len;
        my $cmd = u32le($data, $offset);
        my $cmdsize = u32le($data, $offset + 4);
        die "invalid load command size in $path\n" if $cmdsize < 8 || $offset + $cmdsize > $file_len;

        if ($cmd == 0x1d) {
          die "unexpected LC_CODE_SIGNATURE size in $path\n" if $cmdsize < 16;
          die "multiple LC_CODE_SIGNATURE commands in $path\n" if defined $sig_dataoff;
          $sig_dataoff = u32le($data, $offset + 8);
          $sig_datasize = u32le($data, $offset + 12);
        }

        $offset += $cmdsize;
      }

      die "missing LC_CODE_SIGNATURE in $path\n" if !defined $sig_dataoff;
      die "empty LC_CODE_SIGNATURE in $path\n" if $sig_datasize == 0;
      die "LC_CODE_SIGNATURE exceeds file in $path\n" if $sig_dataoff + $sig_datasize > $file_len;

      return ($sig_dataoff, $sig_datasize, $file_len);
    }

    my ($local_path, $release_path) = @ARGV;

    open my $local_fh, "<", $local_path or die "open($local_path): $!";
    open my $release_fh, "<", $release_path or die "open($release_path): $!";
    binmode $local_fh;
    binmode $release_fh;
    local $/;
    my $local_data = <$local_fh>;
    my $release_data = <$release_fh>;

    my ($local_sig_off, $local_sig_size) = parse_macho_signature_region($local_data, $local_path);
    my ($release_sig_off, $release_sig_size) = parse_macho_signature_region($release_data, $release_path);

    die "release LC_CODE_SIGNATURE too short for SuperBlob header in $release_path\n"
      if $release_sig_size < 12;

    my $superblob_magic = u32be($release_data, $release_sig_off);
    die "release LC_CODE_SIGNATURE is not a SuperBlob in $release_path\n"
      if $superblob_magic != 0xfade0cc0;

    my $superblob_len = u32be($release_data, $release_sig_off + 4);
    my $superblob_count = u32be($release_data, $release_sig_off + 8);
    my $index_len = 12 + ($superblob_count * 8);

    die "release SuperBlob length too small in $release_path\n"
      if $superblob_len < $index_len;
    die "release SuperBlob length exceeds LC_CODE_SIGNATURE size in $release_path\n"
      if $superblob_len > $release_sig_size;

    my $tail_len = $release_sig_size - $superblob_len;
    exit 0 if $tail_len == 0;

    my $tail_off = $release_sig_off + $superblob_len;
    my $local_sig_end = $local_sig_off + $local_sig_size;
    my $release_sig_end = $release_sig_off + $release_sig_size;

    die "release signature tail starts before local LC_CODE_SIGNATURE in $release_path\n"
      if $tail_off < $local_sig_off;
    die "release signature tail exceeds local LC_CODE_SIGNATURE in $release_path\n"
      if $tail_off + $tail_len > $local_sig_end;

    my $release_tail = substr($release_data, $tail_off, $tail_len);
    my $local_tail = substr($local_data, $tail_off, $tail_len);

    die "release signature tail differs from local build bytes in $release_path\n"
      if $release_tail ne $local_tail;
  ' "$local_path" "$release_path"; then
    die "Mach-O signature tail check failed: $release_path"
  fi
}

verify_release_macho_signature_tails() {
  local local_app="$1"
  local release_app="$2"
  [[ -d "$local_app" ]] || die "Local app bundle not found for Mach-O signature-tail check: $local_app"
  [[ -d "$release_app" ]] || die "Release app bundle not found for Mach-O signature-tail check: $release_app"

  while IFS= read -r release_path; do
    [[ -n "$release_path" ]] || continue

    if ! file -b "$release_path" | grep -q 'Mach-O'; then
      continue
    fi

    local rel="${release_path#${release_app}/}"
    local local_path="${local_app}/${rel}"
    [[ -f "$local_path" ]] || die "Local Mach-O counterpart missing: $local_path"
    file -b "$local_path" | grep -q 'Mach-O' || die "Local counterpart is not Mach-O: $local_path"
    verify_macho_signature_tail_matches_local "$local_path" "$release_path"
  done < <(find "$release_app" -type f | LC_ALL=C sort)
}

# codesign --verify only says the signed release is internally consistent.
# It proves the CodeDirectory hashes match the bytes in that same signed app.
# It does NOT prove those signed executable pages match the user's local source build.
#
# The normalized Mach-O compare in normalized_macho_sha256_file() is our project-specific equivalence view for the first-page/load-command region that Apple signing mutates.
# This CodeDirectory check is not a replacement for that...
#
# This is the Apple-native complement for the stable pages AFTER slot 0.
# We take Apple's own signed CodeDirectory page hashes from the release app and recompute them from the local build.
# If those match, the bulk of the executable payload is no longer relying only on our custom normalization rules, while the normalized Mach-O compare is responsible for slot 0.
verify_macho_codedirectory_pages_match_local() {
  local local_path="$1"
  local release_path="$2"
  [[ -f "$local_path" ]] || die "Local Mach-O file not found for CodeDirectory page check: $local_path"
  [[ -f "$release_path" ]] || die "Release Mach-O file not found for CodeDirectory page check: $release_path"

  # Use Apple's own signed page-hash view for the stable post-header pages.
  if ! perl -MDigest::SHA=sha1,sha256,sha384 -e '
    use strict;
    use warnings;

    sub u32le {
      return unpack("V", substr($_[0], $_[1], 4));
    }

    sub u64le {
      return unpack("Q<", substr($_[0], $_[1], 8));
    }

    sub u32be {
      return unpack("N", substr($_[0], $_[1], 4));
    }

    sub u64be {
      return unpack("Q>", substr($_[0], $_[1], 8));
    }

    sub parse_macho_signature_region {
      my ($data, $path) = @_;
      my $file_len = length($data);
      die "unsupported Mach-O magic in $path\n" if u32le($data, 0) != 0xfeedfacf;

      my $ncmds = u32le($data, 16);
      my $offset = 32;
      my ($sig_dataoff, $sig_datasize);

      for (my $i = 0; $i < $ncmds; $i++) {
        die "truncated Mach-O load commands in $path\n" if $offset + 8 > $file_len;
        my $cmd = u32le($data, $offset);
        my $cmdsize = u32le($data, $offset + 4);
        die "invalid load command size in $path\n" if $cmdsize < 8 || $offset + $cmdsize > $file_len;

        if ($cmd == 0x1d) {
          die "unexpected LC_CODE_SIGNATURE size in $path\n" if $cmdsize < 16;
          die "multiple LC_CODE_SIGNATURE commands in $path\n" if defined $sig_dataoff;
          $sig_dataoff = u32le($data, $offset + 8);
          $sig_datasize = u32le($data, $offset + 12);
        }

        $offset += $cmdsize;
      }

      die "missing LC_CODE_SIGNATURE in $path\n" if !defined $sig_dataoff;
      die "empty LC_CODE_SIGNATURE in $path\n" if $sig_datasize == 0;
      die "LC_CODE_SIGNATURE exceeds file in $path\n" if $sig_dataoff + $sig_datasize > $file_len;

      return substr($data, $sig_dataoff, $sig_datasize);
    }

    sub find_codedirectory_blob {
      my ($sig, $path) = @_;
      die "LC_CODE_SIGNATURE too short for SuperBlob header in $path\n" if length($sig) < 12;
      die "LC_CODE_SIGNATURE is not a SuperBlob in $path\n" if u32be($sig, 0) != 0xfade0cc0;

      my $superblob_len = u32be($sig, 4);
      my $count = u32be($sig, 8);
      my $index_end = 12 + ($count * 8);

      die "SuperBlob length too small in $path\n" if $superblob_len < $index_end;
      die "SuperBlob length exceeds LC_CODE_SIGNATURE size in $path\n" if $superblob_len > length($sig);

      for (my $i = 0; $i < $count; $i++) {
        my $entry_off = 12 + ($i * 8);
        my $slot_type = u32be($sig, $entry_off);
        my $blob_off = u32be($sig, $entry_off + 4);
        die "SuperBlob index points outside SuperBlob in $path\n" if $blob_off + 8 > $superblob_len;
        my $blob_magic = u32be($sig, $blob_off);
        my $blob_len = u32be($sig, $blob_off + 4);
        die "SuperBlob entry exceeds SuperBlob in $path\n" if $blob_off + $blob_len > $superblob_len;
        if ($slot_type == 0) {
          die "slot 0 is not a CodeDirectory in $path\n" if $blob_magic != 0xfade0c02;
          return substr($sig, $blob_off, $blob_len);
        }
      }

      die "missing CodeDirectory slot in $path\n";
    }

    sub hash_bytes {
      my ($hash_type, $bytes) = @_;
      if ($hash_type == 1) {
        return sha1($bytes);
      }
      if ($hash_type == 2) {
        return sha256($bytes);
      }
      if ($hash_type == 3) {
        return substr(sha256($bytes), 0, 20);
      }
      if ($hash_type == 4) {
        return sha384($bytes);
      }
      die "unsupported CodeDirectory hash type $hash_type\n";
    }

    my ($local_path, $release_path) = @ARGV;

    open my $local_fh, "<", $local_path or die "open($local_path): $!";
    open my $release_fh, "<", $release_path or die "open($release_path): $!";
    binmode $local_fh;
    binmode $release_fh;
    local $/;
    my $local_data = <$local_fh>;
    my $release_data = <$release_fh>;

    my $sig = parse_macho_signature_region($release_data, $release_path);
    my $cd = find_codedirectory_blob($sig, $release_path);
    die "CodeDirectory header truncated in $release_path\n" if length($cd) < 44;

    my $cd_len = u32be($cd, 4);
    my $version = u32be($cd, 8);
    my $hash_offset = u32be($cd, 16);
    my $n_special = u32be($cd, 24);
    my $n_code = u32be($cd, 28);
    my $code_limit = u32be($cd, 32);
    my $hash_size = ord(substr($cd, 36, 1));
    my $hash_type = ord(substr($cd, 37, 1));
    my $page_exp = ord(substr($cd, 39, 1));

    die "CodeDirectory length mismatch in $release_path\n" if $cd_len != length($cd);
    die "unsupported scattered CodeDirectory in $release_path\n"
      if $version >= 0x20100 && u32be($cd, 44) != 0;

    if ($version >= 0x20300) {
      die "CodeDirectory v0x20300 header truncated in $release_path\n" if length($cd) < 64;
      my $code_limit64 = u64be($cd, 56);
      $code_limit = $code_limit64 if $code_limit64 != 0;
    }

    my $page_size = $page_exp == 0 ? 0 : (1 << $page_exp);
    my $expected_slots = $page_size == 0 ? 1 : int(($code_limit + $page_size - 1) / $page_size);
    die "unexpected CodeDirectory slot count in $release_path\n" if $n_code != $expected_slots;
    die "local file shorter than signed CodeDirectory codeLimit in $local_path\n"
      if length($local_data) < $code_limit;
    die "unsupported CodeDirectory page layout in $release_path\n" if $page_size == 0;

    my $hash_base = $hash_offset - ($n_special * $hash_size);
    die "CodeDirectory hash table starts before blob in $release_path\n" if $hash_base < 0;
    die "CodeDirectory hash table exceeds blob in $release_path\n"
      if $hash_offset + ($n_code * $hash_size) > length($cd);

    # Slot 0 covers the first page of the Mach-O, which includes the header and load commands that Apple signing mutates (UUID, the LC_CODE_SIGNATURE command, and LINKEDIT sizing bookkeeping)
    # We keep relying on the existing normalized Mach-O compare for that page and use CodeDirectory slot parity for the remaining stable pages
    for (my $slot = 1; $slot < $n_code; $slot++) {
      my $start = $slot * $page_size;
      my $length = $page_size;
      my $remaining = $code_limit - $start;
      $length = $remaining if $remaining < $length;
      my $page = substr($local_data, $start, $length);
      my $actual = hash_bytes($hash_type, $page);
      die "unexpected CodeDirectory hash size in $release_path\n" if length($actual) != $hash_size;
      my $expected = substr($cd, $hash_offset + ($slot * $hash_size), $hash_size);
      die "CodeDirectory page hash mismatch at slot $slot in $release_path\n" if $actual ne $expected;
    }
  ' "$local_path" "$release_path"; then
    die "Mach-O CodeDirectory page verification failed: $release_path"
  fi
}

verify_release_macho_codedirectory_pages() {
  local local_app="$1"
  local release_app="$2"
  [[ -d "$local_app" ]] || die "Local app bundle not found for CodeDirectory page check: $local_app"
  [[ -d "$release_app" ]] || die "Release app bundle not found for CodeDirectory page check: $release_app"

  while IFS= read -r release_path; do
    [[ -n "$release_path" ]] || continue

    if ! file -b "$release_path" | grep -q 'Mach-O'; then
      continue
    fi

    local rel="${release_path#${release_app}/}"
    local local_path="${local_app}/${rel}"
    [[ -f "$local_path" ]] || die "Local Mach-O counterpart missing: $local_path"
    file -b "$local_path" | grep -q 'Mach-O' || die "Local counterpart is not Mach-O: $local_path"
    verify_macho_codedirectory_pages_match_local "$local_path" "$release_path"
  done < <(find "$release_app" -type f | LC_ALL=C sort)
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
  verify_release_entitlements_policy "$release_app"
  verify_release_macho_codedirectory_pages "$local_app" "$release_app"
  verify_release_macho_signature_tails "$local_app" "$release_app"

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
