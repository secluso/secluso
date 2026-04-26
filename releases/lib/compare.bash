#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later

# "reproducibility comparison engine"
#
# We are intentionally strict about integrity but more flexible about
# scope. In release workflows, one side may contain a full release
# matrix while another side contains only a subset rebuilt by an auditor....
#
# The algorithm therefore enforces a superset rule, every artifact in the smaller
# set must exist in the larger set, and only overlapping keys are validated.
#
# For each overlapping artifact key we validate:
# 1) Build-input metadata (crate, version, lock digest, toolchain digest).
# 2) Manifest hash presence / correctness against on-disk files.
# 3) (Comparison-)hash equality between the two runs.
#
# Step 2 is intentionally raw-byte strict.
# A run directory is only trustworthy if the manifest sha256 still matches the file that is actually on disk.
#
# Step 3 is where format-aware normalization is now used.
# For right now, that mainly means Mach-O files, where release signing can rewrite LC_UUID / code-signature / __LINKEDIT details even when the underlying payload is otherwise equivalent.
# Therefore, the code compares a normalized hash for those files while still preserving raw manifest integrity checks above.
#
# Security caveat to consider: compare no longer proves raw-byte equivalence for normalized Mach-O files.
# If an attacker controlled an entire run directory, rewrote both the binary and its manifest, and managed to confine the malicious delta to bytes discarded by normalization, the cross-run compare step could miss it.
# In our expected outputs that discarded region is release-signing-related metadata, but the current truncate-from-signature-offset rule is broader than a narrowly parsed code-signature blob.
# Normalization must therefore stay very narrow, and Apple signature/notarization verification remains a separate required check.
# A TODO is in place to be done before this PR is merged to work on this more.
#
# This layered approach makes failures actionable because it distinguishes input
# drift from output drift, instead of collapsing everything into some very generic
# 'hash mismatch' kind of message that gives away explainability. It may be failing due to something
# very simple and fixable that isn't related to being invalid in itself.

compare_runs() {
  local run1="$1"
  local run2="$2"
  local m1="$run1/manifest.json"
  local m2="$run2/manifest.json"
  local tmp_cmp_dir
  tmp_cmp_dir="$(mktemp -d)"

  # Comparison should be non-invasive, we do not write scratch files into the
  # provided run directories. This keeps official artifacts immutable during
  # audits and avoids failures when compare inputs are read-only mounts.
  local run1_keys_json="$tmp_cmp_dir/run1.keys.json"
  local run2_keys_json="$tmp_cmp_dir/run2.keys.json"
  local small_keys_txt="$tmp_cmp_dir/small.keys.txt"
  local large_keys_txt="$tmp_cmp_dir/large.keys.txt"

  [[ -f "$m1" && -f "$m2" ]] || {
    echo "Missing manifest(s) for compare: $m1 and/or $m2" >&2
    rm -rf "$tmp_cmp_dir"
    return 1
  }

  jq -S '[.artifacts[]
        | {key: (.package + "|" + .target + "|" + .bin),
          package, target, bin, crate, version, bin_path, sha256,
          crate_lock_sha256, rust_digest}]' "$m1" > "$run1_keys_json"

  jq -S '[.artifacts[]
        | {key: (.package + "|" + .target + "|" + .bin),
          package, target, bin, crate, version, bin_path, sha256,
          crate_lock_sha256, rust_digest}]' "$m2" > "$run2_keys_json"

  local n1 n2 small_dir large_dir
  n1="$(jq 'length' "$run1_keys_json")"
  n2="$(jq 'length' "$run2_keys_json")"

  if (( n1 <= n2 )); then
    small_dir="run1"
    large_dir="run2"
  else
    small_dir="run2"
    large_dir="run1"
  fi

  local small_keys_json
  local large_keys_json
  if [[ "$small_dir" == "run1" ]]; then
    small_keys_json="$run1_keys_json"
    large_keys_json="$run2_keys_json"
  else
    small_keys_json="$run2_keys_json"
    large_keys_json="$run1_keys_json"
  fi

  jq -r '.[].key' "$small_keys_json" | sort -u > "$small_keys_txt"
  jq -r '.[].key' "$large_keys_json" | sort -u > "$large_keys_txt"

  local missing
  missing="$(comm -23 "$small_keys_txt" "$large_keys_txt" || true)"
  if [[ -n "$missing" ]]; then
    echo "FAIL: Larger run does not contain all artifacts of the smaller run."
    echo "$missing" | sed 's/^/  - /'
    rm -rf "$tmp_cmp_dir"
    return 1
  fi

  local status=0
  while IFS= read -r key; do
    local a b
    a="$(jq -c --arg k "$key" '.[] | select(.key==$k)' "$run1_keys_json")"
    b="$(jq -c --arg k "$key" '.[] | select(.key==$k)' "$run2_keys_json")"

    if [[ -z "$a" || -z "$b" ]]; then
      continue
    fi

    local pkg tgt bin crate1 ver1 p1 lock1 dig1 sha1 crate2 ver2 p2 lock2 dig2 sha2
    pkg="$(jq -r '.package' <<<"$a")"
    tgt="$(jq -r '.target' <<<"$a")"
    bin="$(jq -r '.bin' <<<"$a")"

    crate1="$(jq -r '.crate' <<<"$a")"
    ver1="$(jq -r '.version' <<<"$a")"
    local bin_path1
    bin_path1="$(jq -r '.bin_path' <<<"$a")"
    p1="$(validate_manifest_bin_path "$run1" "$bin_path1" "$tgt" "$bin")" || {
      echo "FAIL: invalid manifest bin_path for run1 $pkg | $tgt | $bin: $bin_path1"
      status=1
      continue
    }
    lock1="$(jq -r '.crate_lock_sha256' <<<"$a")"
    dig1="$(jq -r '.rust_digest' <<<"$a")"
    sha1="$(jq -r '.sha256 // empty' <<<"$a")"

    crate2="$(jq -r '.crate' <<<"$b")"
    ver2="$(jq -r '.version' <<<"$b")"
    local bin_path2
    bin_path2="$(jq -r '.bin_path' <<<"$b")"
    p2="$(validate_manifest_bin_path "$run2" "$bin_path2" "$tgt" "$bin")" || {
      echo "FAIL: invalid manifest bin_path for run2 $pkg | $tgt | $bin: $bin_path2"
      status=1
      continue
    }
    lock2="$(jq -r '.crate_lock_sha256' <<<"$b")"
    dig2="$(jq -r '.rust_digest' <<<"$b")"
    sha2="$(jq -r '.sha256 // empty' <<<"$b")"

    local meta_ok=1
    if [[ "$crate1" != "$crate2" ]]; then
      echo "DIFF: crate mismatch for $pkg | $tgt | $bin: $crate1 vs $crate2"
      meta_ok=0
    fi
    if [[ "$ver1" != "$ver2" ]]; then
      echo "DIFF: version mismatch for $pkg | $tgt | $bin: $ver1 vs $ver2"
      meta_ok=0
    fi
    if [[ -z "$lock1" || -z "$lock2" || "$lock1" != "$lock2" ]]; then
      echo "DIFF: crate Cargo.lock SHA mismatch for $pkg | $tgt | $bin:"
      echo "  run1: ${lock1:-<none>}"
      echo "  run2: ${lock2:-<none>}"
      meta_ok=0
    fi
    if [[ -z "$dig1" || -z "$dig2" || "$dig1" != "$dig2" ]]; then
      echo "DIFF: toolchain digest mismatch for $pkg | $tgt | $bin:"
      echo "  run1: ${dig1:-<none>}"
      echo "  run2: ${dig2:-<none>}"
      meta_ok=0
    fi
    if (( meta_ok == 0 )); then
      status=1
      continue
    fi

    if [[ ! -f "$p1" || ! -f "$p2" ]]; then
      echo "FAIL: missing binary file(s) for $pkg | $tgt | $bin"
      status=1
      continue
    fi

    # First prove that each run is internally self-consistent.
    # We always compare  the manifest's recorded raw sha256 against the real file bytes before any normalization logic is allowed to enter the picture.
    local raw_h1 raw_h2
    raw_h1="$(sha256_file "$p1")"
    raw_h2="$(sha256_file "$p2")"

    if [[ -z "$sha1" || -z "$sha2" ]]; then
      echo "FAIL: manifest missing sha256 for $pkg | $tgt | $bin"
      status=1
      continue
    fi

    if [[ "$raw_h1" != "$sha1" ]]; then
      echo "FAIL: run1 manifest sha256 does not match file for $pkg | $tgt | $bin"
      echo "  manifest: $sha1"
      echo "  file    : $raw_h1"
      status=1
      continue
    fi

    if [[ "$raw_h2" != "$sha2" ]]; then
      echo "FAIL: run2 manifest sha256 does not match file for $pkg | $tgt | $bin"
      echo "  manifest: $sha2"
      echo "  file    : $raw_h2"
      status=1
      continue
    fi

    # Only after both run directories pass raw integrity checks do we compare cross-run output hashes.
    # compare_hash_for_file() is usually just sha256, but it may normalize known release-only metadata for certain formats such as signed Mach-O binaries.
    local h1 h2
    h1="$(compare_hash_for_file "$p1")"
    h2="$(compare_hash_for_file "$p2")"

    if [[ "$h1" != "$h2" ]]; then
      echo "DIFF: binary hash mismatch for $pkg | $tgt | $bin"
      echo "  run1: $h1"
      echo "  run2: $h2"
      status=1
    else
      echo "OK   : $pkg | $tgt | $bin (crate=$crate1 v$ver1, sha=$h1)"
    fi
  done < "$small_keys_txt"

  local extras
  extras="$(comm -13 "$small_keys_txt" "$large_keys_txt" || true)"
  if [[ -n "$extras" ]]; then
    echo "INFO : Extra artifacts present only in larger run:"
    echo "$extras" | sed 's/^/  - /'
  fi

  rm -rf "$tmp_cmp_dir"

  echo ""
  if [[ "$status" -eq 0 ]]; then
    echo "Reproducibility check PASSED"
  else
    echo "Reproducibility check FAILED"
  fi

  return "$status"
}

validate_manifest_bin_path() {
  local run_dir="$1"
  local bin_path="$2"
  local expected_target="$3"
  local expected_bin="$4"

  # Compare should only read files from the run's artifacts tree.
  # Manifest data is treated as untrusted input here.
  # So reject any path that could escape the run directory or redirect hashing to an unrelated local file.
  [[ -n "$bin_path" ]] || return 1
  [[ "$bin_path" == "artifacts/$expected_target/"* ]] || return 1
  [[ "$bin_path" != /* ]] || return 1
  [[ "$(basename "$bin_path")" == "$expected_bin" ]] || return 1

  local old_ifs="$IFS"
  local component
  local current="$run_dir"
  IFS='/'
  for component in $bin_path; do
    if [[ -z "$component" || "$component" == "." || "$component" == ".." ]]; then
      IFS="$old_ifs"
      return 1
    fi
    current="$current/$component"
    # Reject symlinks anywhere on the manifest-controlled path so a manifest cannot redirect hashing outside the selected run through the filesystem.
    if [[ -L "$current" ]]; then
      IFS="$old_ifs"
      return 1
    fi
  done
  IFS="$old_ifs"

  printf '%s/%s' "$run_dir" "$bin_path"
}
