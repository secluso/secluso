#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later

# Target/profile planning for release builds.
#
# This module is the policy layer for the build system. It answers questions
# like which triples should be built for this profile and does this plan
# need Docker Buildx. Pipeline modules should not encode those rules, because
# policy drift between build paths is one of the easiest ways to accidentally
# ship inconsistent releases.

is_apple_triple() {
  [[ "$1" == *"-apple-darwin" ]]
}

resolve_build_plan() {
  TRIPLES=()
  PKGS=()
  BUILD_KIND="rust"
  DEPLOY_REQUIRES_DOCKER=0

  case "$TARGET" in
    raspberry)
      TRIPLES=( "aarch64-unknown-linux-gnu" )
      case "$PROFILE" in
        all) PKGS=( "update" "reset" "raspberry_camera_hub" "config_tool" ) ;;
        core) PKGS=( "raspberry_camera_hub" "reset" "update" ) ;;
        camerahub) PKGS=( "raspberry_camera_hub" ) ;;
        motion_ai_cli) PKGS=( "motion_ai_cli" ) ;;
        *) die "Invalid profile for raspberry: $PROFILE" ;;
      esac
      ;;
    server)
      TRIPLES=( "x86_64-unknown-linux-gnu" )
      case "$PROFILE" in
        server) PKGS=( "server" ) ;;
        *) die "Invalid profile for server: $PROFILE" ;;
      esac
      ;;
    ipcamera)
      TRIPLES=( "x86_64-unknown-linux-gnu" "aarch64-unknown-linux-gnu" )
      case "$PROFILE" in
        all) PKGS=( "ip_camera_hub" "config_tool" "server" ) ;;
        camerahub) PKGS=( "ip_camera_hub" ) ;;
        core) die "Profile 'core' not valid for ipcamera" ;;
        *) die "Invalid profile for ipcamera: $PROFILE" ;;
      esac
      ;;
    all)
      TRIPLES=( "aarch64-unknown-linux-gnu" "x86_64-unknown-linux-gnu" )
      case "$PROFILE" in
        all) PKGS=( "update" "reset" "raspberry_camera_hub" "ip_camera_hub" "config_tool" "server" ) ;;
        release) PKGS=( "update" "raspberry_camera_hub" "config_tool" "server" ) ;;
        test) PKGS=( "update" "raspberry_camera_hub" "config_tool" ) ;;
        *) die "Invalid profile for all: $PROFILE" ;;
      esac
      ;;
    deploy)
      BUILD_KIND="deploy"
      PKGS=( "deploy_tool" )
      case "$PROFILE" in
        all)
          TRIPLES=(
            "x86_64-unknown-linux-gnu"
            "aarch64-unknown-linux-gnu"
            "x86_64-apple-darwin"
            "aarch64-apple-darwin"
            "x86_64-pc-windows-msvc"
            "aarch64-pc-windows-msvc"
          )
          ;;
        linux) TRIPLES=( "x86_64-unknown-linux-gnu" "aarch64-unknown-linux-gnu" ) ;;
        macos) TRIPLES=( "x86_64-apple-darwin" "aarch64-apple-darwin" ) ;;
        windows) TRIPLES=( "x86_64-pc-windows-msvc" "aarch64-pc-windows-msvc" ) ;;
        linux-x64) TRIPLES=( "x86_64-unknown-linux-gnu" ) ;;
        linux-arm64) TRIPLES=( "aarch64-unknown-linux-gnu" ) ;;
        macos-x64) TRIPLES=( "x86_64-apple-darwin" ) ;;
        macos-arm64) TRIPLES=( "aarch64-apple-darwin" ) ;;
        windows-x64) TRIPLES=( "x86_64-pc-windows-msvc" ) ;;
        windows-arm64) TRIPLES=( "aarch64-pc-windows-msvc" ) ;;
        *)
          usage
          die "Invalid profile for deploy: $PROFILE"
          ;;
      esac
      ;;
    *)
      usage
      die "Unknown target: $TARGET"
      ;;
  esac

  # Deploy builds can be mixed-mode in a single command... native host bundling
  # for Apple targets, Docker fallback for Linux/Windows targets. We decide once
  # here
  if [[ "$BUILD_KIND" == "deploy" ]]; then
    local plan_triple
    for plan_triple in "${TRIPLES[@]}"; do
      if ! is_apple_triple "$plan_triple"; then
        DEPLOY_REQUIRES_DOCKER=1
        break
      fi
    done
  fi
}

load_locked_digests_if_needed() {
  if [[ ! -f "$DIGESTS_LOCK_FILE" ]]; then
    if [[ "$BUILD_KIND" == "rust" || ( "$BUILD_KIND" == "deploy" && "$DEPLOY_REQUIRES_DOCKER" -eq 1 ) ]]; then
      die "Missing ${DIGESTS_LOCK_FILE}"
    fi
    return
  fi

  # shellcheck disable=SC1090
  . "$DIGESTS_LOCK_FILE"
}

ensure_required_tools_for_mode() {
  require_tool jq
  require_tool cargo

  if [[ "$BUILD_KIND" == "rust" ]]; then
    require_tool docker
    if ! docker buildx version >/dev/null 2>&1; then
      die "Docker Buildx is not available"
    fi
    return
  fi

  local requires_host_cc=0
  local plan_triple
  for plan_triple in "${TRIPLES[@]}"; do
    if is_apple_triple "$plan_triple"; then
      requires_host_cc=1
      break
    fi
  done

  require_tool rustc
  if [[ "$requires_host_cc" -eq 1 ]]; then
    require_tool cc
    require_tool node
    require_tool pnpm
  fi

  if [[ "$DEPLOY_REQUIRES_DOCKER" -eq 1 ]]; then
    require_tool docker
    if ! docker buildx version >/dev/null 2>&1; then
      die "Docker Buildx is not available"
    fi
  fi
}

print_build_configuration() {
  echo "Build configuration"
  echo "- Target : $TARGET"
  echo "- Profile: $PROFILE"
  echo "- Mode   : $BUILD_KIND"
  echo "- Triples: ${TRIPLES[*]}"
  echo "- Packages: ${PKGS[*]}"
  echo ""
}

setup_builder_if_needed() {
  if [[ "$BUILD_KIND" != "rust" && "$DEPLOY_REQUIRES_DOCKER" -ne 1 ]]; then
    return
  fi

  BUILDER="secluso-builds"

  docker buildx rm -f "$BUILDER" >/dev/null 2>&1 || true
  docker buildx create \
    --name "$BUILDER" \
    --driver docker-container \
    --driver-opt image=docker.io/moby/buildkit@sha256:a38cf64aa6415899097fac5bfcf6c07c95d5a68c67a21e3d254ba398a3c9187f \
    --use >/dev/null

  cleanup_builder() {
    docker buildx rm -f "$BUILDER" >/dev/null 2>&1 || true
  }
  trap cleanup_builder EXIT
}
