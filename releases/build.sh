#!/usr/bin/env bash

# A general build tool as well as a reproducibility tester for Secluso.

# Quick check to ensure necessary tools installed
for tool in cargo jq sha256sum; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "Required tool missing: $tool" >&2
    exit 1
  fi
done

# Arg parse the user input
TARGET=""
PROFILE=""
TEST_REPRODUCE=0
COMPARE_DIR1=""
COMPARE_DIR2=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)   TARGET="${2:?}"; shift 2 ;;
    --profile)  PROFILE="${2:?}"; shift 2 ;;
    --test-reproduce) TEST_REPRODUCE=1; shift 1 ;;
    --compare)  COMPARE_DIR1="${2:?}"; COMPARE_DIR2="${3:?}"; shift 3 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

if [[ -z "$COMPARE_DIR1" && ( -z "${TARGET}" || -z "${PROFILE}" ) ]]; then
  echo "Usage:" >&2
  echo "  $0 --target {raspberry|ipcamera|all} --profile {all|core|camerahub|release} [--test-reproduce]" >&2
  echo "  $0 --compare <build_dir_run1> <build_dir_run2>" >&2
  exit 1
fi

# Function to perform a build 
build_and_manifest() {
  local OUTDIR="$1"  
  local RUN_ID="$2"  # 1 or 2

  # Ensure directory exists
  mkdir -p "$OUTDIR"

  # We'll collect artifacts in a temp file, then wrap into JSON
  local artifacts_json="$(mktemp)"
  : > "$artifacts_json"

  for TRIPLE in "${TRIPLES[@]}"; do
    # Get digest for this triple
    local KEY=$(printf '%s' "$TRIPLE" | tr '[:lower:]' '[:upper:]' | tr '-' '_')
    local VAR="RUST_DIGEST__${KEY}"
    local DIGEST="${!VAR:-}"
    if [[ -z "$DIGEST" ]]; then
      echo "No digest set for $TRIPLE (expected $VAR) in digests.lock.env" >&2
      exit 1
    fi

    for PKG in "${PKGS[@]}"; do
      local FEATURES_ARGS=()
      local CRATE_NAME="$PKG"     # may be rewritten below

      # Map profile-specific pseudo-packages to real crates + features
      if [[ "$PKG" == "raspberry_camera_hub" ]]; then
        FEATURES_ARGS=( --build-arg "FEATURES=--features raspberry" )
        CRATE_NAME="camera_hub"
      elif [[ "$PKG" == "ip_camera_hub" ]]; then
        FEATURES_ARGS=( --build-arg "FEATURES=--features ip" )
        CRATE_NAME="camera_hub"
      fi

      # Skip raspberry-only tools (raspberry camera hub, reset, update) unless building the raspberry triple
      if [[ "$PKG" == "raspberry_camera_hub" || "$PKG" == "reset" || "$PKG" == "update" ]]; then
        if [[ "$TRIPLE" != "aarch64-unknown-linux-gnu" ]]; then
          echo "==> [run $RUN_ID] SKIP $PKG for $TRIPLE (raspberry-only)"
          continue
        fi
      fi

      # Ensure Cargo.lock exists
      local CRATE_LOCK="../$CRATE_NAME/Cargo.lock"
      if [[ ! -f  $CRATE_LOCK ]]; then
          echo "Cargo.lock not found at crate $CRATE_NAME" >&2
          
          exit 1
      fi

      # Compute the crate lock SHA. It's okay to do this because it doesn't affect security; we don't need to compute it at runtime when doing checks.
      local CRATE_LOCK_SHA="$(sha256sum "$CRATE_LOCK" | awk '{print $1}')"

      # Bin name convention
      local BIN="secluso-$(tr '_' '-' <<<"$CRATE_NAME")"

      # Per-arch output dir
      local ART_DIR="$OUTDIR/${TRIPLE}"
      mkdir -p "$ART_DIR"

      # Enforce Cargo.toml being present in the crate dir
      local CRATE_DIR="../$CRATE_NAME"
      if [[ ! -f "$CRATE_DIR/Cargo.toml" ]]; then
        echo "Missing $CRATE_DIR/Cargo.toml to read version" >&2
        exit 1
      fi

      # Fetch the crate version from Cargo.toml for sanity checks
      local CRATE_VERSION="$(
        cargo metadata --no-deps \
        --format-version 1 \
        --manifest-path "$CRATE_DIR/Cargo.toml" \
       | jq -r '.packages[0].version'
      )"

      if [[ -z "$CRATE_VERSION" || "$CRATE_VERSION" == "null" ]]; then
        echo "Could not get version from $CRATE_DIR/Cargo.toml" >&2
        exit 1
      fi

      # Perform the build
      echo "==> [run $RUN_ID] $PKG for $TRIPLE (crate=$CRATE_NAME bin=$BIN) features=(${FEATURES_ARGS[*]})"
      docker buildx build --builder "$BUILDER" --no-cache --target artifact --build-context proj=.. --build-arg "CRATE_NAME=${CRATE_NAME}" --build-arg "BINARY_FILE_NAME=${BIN}" --build-arg "CARGO_TARGET=${TRIPLE}" --build-arg "RUST_HASH=${DIGEST}" "${FEATURES_ARGS[@]}" --output "type=local,dest=${ART_DIR}" .

      # Expect bin file produced by hasher stage
      if [[ ! -f "$ART_DIR/$BIN" ]]; then
        echo "Missing bin file for $PKG in $ART_DIR" >&2
        exit 1
      fi

      # Rename IP vs Raspberry camera hub to avoid collisions on ARM64
      case "$PKG" in
        raspberry_camera_hub)
          NEW_BIN="secluso-raspberry-camera-hub"
          mv "$ART_DIR/$BIN" "$ART_DIR/$NEW_BIN"
          BIN="$NEW_BIN"
          ;;
        ip_camera_hub)
          NEW_BIN="secluso-ip-camera-hub"
          mv "$ART_DIR/$BIN" "$ART_DIR/$NEW_BIN"
          BIN="$NEW_BIN"
          ;;
      esac

      # Write all data to artifacts
      printf '    {"package":"%s","target":"%s","bin":"%s","bin_path":"%s","crate":"%s","version":"%s","crate_lock_sha256":"%s","rust_digest":"%s"}\n' \
        "$PKG" \
        "$TRIPLE" \
        "$BIN" \
        "$TRIPLE/$BIN" \
        "$CRATE_NAME" \
        "$CRATE_VERSION" \
        "$CRATE_LOCK_SHA" \
        "$DIGEST" \
        >> "$artifacts_json"
    done
  done

  # Join artifacts with commas
  local ARTIFACTS_JOINED="$(paste -sd',' "$artifacts_json")"

  # Write manifest with timestamp, run ID, target and profile
  cat > "$OUTDIR/manifest.json" <<EOF
{
  "build": {
    "target": "$TARGET",
    "profile": "$PROFILE",
    "run_id": "$RUN_ID",
    "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  },
  "artifacts": [
$ARTIFACTS_JOINED
  ]
}
EOF
  rm -f "$artifacts_json"
}

# Allows us to either compare runs with test reproducible functionality or allows independent testing against our releases
compare_runs() {
  local RUN1="$1" RUN2="$2"
  local M1="$RUN1/manifest.json" M2="$RUN2/manifest.json"

  if [[ ! -f "$M1" || ! -f "$M2" ]]; then
    echo "Missing manifest(s) for compare: $M1 and/or $M2" >&2
    return 1
  fi

  # Normalize to key = package|target|bin
  jq -S '[.artifacts[]
        | {key: (.package + "|" + .target + "|" + .bin),
          package, target, bin, crate, version, bin_path,
          crate_lock_sha256, rust_digest}]' "$M1" > "$RUN1/keys.json"

  jq -S '[.artifacts[]
        | {key: (.package + "|" + .target + "|" + .bin),
          package, target, bin, crate, version, bin_path,
          crate_lock_sha256, rust_digest}]' "$M2" > "$RUN2/keys.json"


  # Decide SMALL/LARGE for superset rule
  local N1 N2 SMALL_DIR LARGE_DIR
  N1="$(jq 'length' "$RUN1/keys.json")"
  N2="$(jq 'length' "$RUN2/keys.json")"

  if (( N1 <= N2 )); then SMALL_DIR="$RUN1"; LARGE_DIR="$RUN2"; else SMALL_DIR="$RUN2"; LARGE_DIR="$RUN1"; fi

  jq -r '.[].key' "$SMALL_DIR/keys.json" | sort -u > "$SMALL_DIR/keys.txt"
  jq -r '.[].key' "$LARGE_DIR/keys.json" | sort -u > "$LARGE_DIR/keys.txt"

  # Superset: large must contain all of small
  local MISSING
  MISSING="$(comm -23 "$SMALL_DIR/keys.txt" "$LARGE_DIR/keys.txt" || true)"
  if [[ -n "$MISSING" ]]; then
    echo "FAIL: Larger run does not contain all artifacts of the smaller run."
    echo "$MISSING" | sed 's/^/  - /'
    return 1
  fi

  # For each key in SMALL: check crate+version+per-crate-lock, then compare on-the-fly bin SHA256
  local status=0
  while IFS= read -r KEY; do
    local A B
    A="$(jq -c --arg k "$KEY" '.[] | select(.key==$k)' "$RUN1/keys.json")"
    B="$(jq -c --arg k "$KEY" '.[] | select(.key==$k)' "$RUN2/keys.json")"

    if [[ -z "$A" || -z "$B" ]]; then
      # key exists only in larger set — allowed as we may only want to check a few of the packages
      continue
    fi

    # Load in data from the manifest files relevant to our checks
    local PKG TGT BIN CRATE1 VER1 P1 LOCK1 DIG1 CRATE2 VER2 P2 LOCK2 DIG2 
    PKG="$(jq -r '.package' <<<"$A")"
    TGT="$(jq -r '.target'  <<<"$A")"
    BIN="$(jq -r '.bin'     <<<"$A")"

    CRATE1="$(jq -r '.crate'            <<<"$A")"
    VER1="$(jq -r '.version'            <<<"$A")"
    P1="$RUN1/$(jq -r '.bin_path'             <<<"$A")"
    LOCK1="$(jq -r '.crate_lock_sha256' <<<"$A")"
    DIG1="$(jq -r '.rust_digest'        <<<"$A")"

    CRATE2="$(jq -r '.crate'            <<<"$B")"
    VER2="$(jq -r '.version'            <<<"$B")"
    P2="$RUN2/$(jq -r '.bin_path'             <<<"$B")"
    LOCK2="$(jq -r '.crate_lock_sha256' <<<"$B")"
    DIG2="$(jq -r '.rust_digest'        <<<"$B")"

    # metadata checks
    local meta_ok=1
    if [[ "$CRATE1" != "$CRATE2" ]]; then
      echo "DIFF: crate mismatch for $PKG | $TGT | $BIN: $CRATE1 vs $CRATE2"
      meta_ok=0
    fi
    if [[ "$VER1" != "$VER2" ]]; then
      echo "DIFF: version mismatch for $PKG | $TGT | $BIN: $VER1 vs $VER2"
      meta_ok=0
    fi
    if [[ -z "$LOCK1" || -z "$LOCK2" || "$LOCK1" != "$LOCK2" ]]; then
      echo "DIFF: crate Cargo.lock SHA mismatch for $PKG | $TGT | $BIN:"
      echo "  run1: ${LOCK1:-<none>}"
      echo "  run2: ${LOCK2:-<none>}"
      meta_ok=0
    fi
    if [[ -z "$DIG1" || -z "$DIG2" || "$DIG1" != "$DIG2" ]]; then
      echo "DIFF: rust base image digest mismatch for $PKG | $TGT | $BIN:"
      echo "  run1: ${DIG1:-<none>}"
      echo "  run2: ${DIG2:-<none>}"
      meta_ok=0
    fi
    if (( meta_ok == 0 )); then status=1; continue; fi

    # binary hashes (computed now, not saved in the manifest file)
    if [[ ! -f "$P1" || ! -f "$P2" ]]; then
      echo "FAIL: missing binary file(s) for $PKG | $TGT | $BIN"
      status=1; continue
    fi
    H1="$(sha256sum "$P1" | awk '{print $1}')"
    H2="$(sha256sum "$P2" | awk '{print $1}')"

    if [[ "$H1" != "$H2" ]]; then
      echo "DIFF: binary hash mismatch for $PKG | $TGT | $BIN"
      echo "  run1: $H1"
      echo "  run2: $H2"
      status=1
    else
      echo "OK   : $PKG | $TGT | $BIN (crate=$CRATE1 v$VER1, sha=$H1)"
    fi
  done < "$SMALL_DIR/keys.txt"

  # Extras in the larger run
  local EXTRAS
  EXTRAS="$(comm -13 "$SMALL_DIR/keys.txt" "$LARGE_DIR/keys.txt" || true)"
  if [[ -n "$EXTRAS" ]]; then
    echo "INFO : Extra artifacts present only in larger run:"
    echo "$EXTRAS" | sed 's/^/  - /'
  fi

  # Clean up afterwards
  rm -rf $SMALL_DIR/keys.txt $LARGE_DIR/keys.txt $SMALL_DIR/keys.json $LARGE_DIR/keys.json

  echo ""

  if [[ $status -eq 0 ]]; then
    echo "Reproducibility check PASSED"
  else
    echo "Reproducibility check FAILED"
  fi
  return $status
}

if [[ -n "$COMPARE_DIR1" ]]; then
  # Compare-only mode: do not build; just diff two provided directories.
  echo "Compare-only mode:"
  echo "- run1: $COMPARE_DIR1"
  echo "- run2: $COMPARE_DIR2"
  echo ""
  compare_runs "$COMPARE_DIR1" "$COMPARE_DIR2"
  exit $?
fi

# If we reach here, we're not comparing.

# Choose triples + packages
TRIPLES=()
PKGS=()

# TODO: The use of triples here allow future expandability. We can add Mac + Windows support, or other Linux architectures, 
# but they'll need special containers to make this happen. 
if [[ "$TARGET" == "raspberry" ]]; then
  TRIPLES=( "aarch64-unknown-linux-gnu" )
  case "$PROFILE" in
    all)      PKGS=( "update" "reset" "raspberry_camera_hub" "config_tool" ) ;;
    core)     PKGS=( "raspberry_camera_hub" "reset" "update" ) ;;
    camerahub)PKGS=( "raspberry_camera_hub" ) ;;
    *) echo "Invalid profile for raspberry: $PROFILE" >&2; exit 1 ;;
  esac
elif [[ "$TARGET" == "ipcamera" ]]; then
  TRIPLES=( "x86_64-unknown-linux-gnu" "aarch64-unknown-linux-gnu" )
  case "$PROFILE" in
    all)      PKGS=( "ip_camera_hub" "config_tool" "server" ) ;;
    camerahub)PKGS=( "ip_camera_hub" ) ;;
    core)     echo "Profile 'core' not valid for ipcamera" >&2; exit 1 ;;
    *) echo "Invalid profile for ipcamera: $PROFILE" >&2; exit 1 ;;
  esac
elif [[ "$TARGET" == "all" ]]; then
  TRIPLES=( "aarch64-unknown-linux-gnu" "x86_64-unknown-linux-gnu" )
  case "$PROFILE" in
    all)      PKGS=( "update" "reset" "raspberry_camera_hub" "ip_camera_hub" "config_tool" "server" ) ;;
    release)  PKGS=( "raspberry_camera_hub" "ip_camera_hub" "config_tool" "server" ) ;;
    *) echo "Invalid profile for all: $PROFILE" >&2; exit 1 ;;
  esac
else
  echo "Unknown target: $TARGET" >&2
  exit 1
fi

# Display choices to user 
echo "Build configuration"
echo "- Target : $TARGET"
echo "- Profile: $PROFILE"
echo "- Triples: ${TRIPLES[*]}"
echo "- Packages: ${PKGS[*]}"
echo

if [[ ! -f digests.lock.env ]]; then
  echo "Missing digests.lock.env" >&2
  exit 1
fi

# Load in the proper Rust digests to check against
. digests.lock.env

# https://hub.docker.com/r/moby/buildkit 
# Create and use an ephemeral BuildKit builder instance for reproducible builds.
# Allows us to destroy after usage, prevent mass storage usage from multiple builds,
# pin the BuildKit image version, and run inside a containerized BuildKit
# backend rather than relying on the host Docker daemon.
BUILDER="secluso-builds"

# Take care of any leftover builder from a prior session that wasn't cleaned up properly (e.g. power cord removed from desktop computer)
docker buildx rm -f "$BUILDER" >/dev/null 2>&1 || true

docker buildx create \
  --name "$BUILDER" \
  --driver docker-container \
  --driver-opt image=moby/buildkit:v0.23.0 \
  --use >/dev/null

# Always clean up this builder (and all its cache) on exit
cleanup() {
  docker buildx rm -f "$BUILDER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Pick build directory to use based on current time (to prevent name conflict)
timestamp="$(date +%s)"
BASE_DIR="builds/$timestamp"

if [[ "$TEST_REPRODUCE" -eq 1 ]]; then
  echo "Reproducibility test: two builds"
  build_and_manifest "$BASE_DIR/run1" 1
  build_and_manifest "$BASE_DIR/run2" 2
  echo ""
  compare_runs "$BASE_DIR/run1" "$BASE_DIR/run2"
else
  build_and_manifest "$BASE_DIR" 1
  echo "Build complete. Output: $BASE_DIR"
fi
