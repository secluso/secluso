# SPDX-License-Identifier: GPL-3.0-or-later
# Build arguments
ARG CRATE_NAME=""
ARG FEATURES=""
ARG RUST_HASH="5861091755a3298619c94a6cbf0534062cfeb9afcda9f698a13df3ef64e2dd8b" # Provided as default to quiet docker warning. This is never used (unless separately passed in).
ARG CARGO_TARGET=""
ARG BINARY_FILE_NAME=""
# Debian archive snapshot. Pins every apt package so they don't float when the builder is rebuilt.
ARG DEBIAN_SNAPSHOT="20260501T000000Z"

# Use a digest-locked Rust image as our builder
FROM docker.io/rust@sha256:${RUST_HASH} AS builder

ARG CRATE_NAME
ARG FEATURES
ARG CARGO_TARGET
ARG BINARY_FILE_NAME
ARG DEBIAN_SNAPSHOT

WORKDIR /app

# Repoint apt at the pinned Debian snapshot before any update/install.
RUN set -eux; \
    : "${DEBIAN_SNAPSHOT:?missing DEBIAN_SNAPSHOT build arg}"; \
    codename="$(. /etc/os-release && echo "$VERSION_CODENAME")"; \
    snap="https://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}"; \
    snap_sec="https://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT}"; \
    rm -f /etc/apt/sources.list.d/debian.sources; \
    { \
      echo "deb ${snap}/ ${codename} main"; \
      echo "deb ${snap}/ ${codename}-updates main"; \
      echo "deb ${snap_sec}/ ${codename}-security main"; \
    } > /etc/apt/sources.list; \
    printf 'Acquire::Check-Valid-Until "false";\nAcquire::Retries "8";\n' \
      > /etc/apt/apt.conf.d/99snapshot

# Install build deps for crates that rely on system crypto libs (e.g., nettle-sys).
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      clang pkg-config nettle-dev; \
    if [ "$CRATE_NAME" = "motion_ai/cli" ]; then \
      apt-get install -y --no-install-recommends \
        libavutil-dev libavcodec-dev libavformat-dev libavfilter-dev \
        libavdevice-dev libswscale-dev libswresample-dev; \
    fi; \
    rm -rf /var/lib/apt/lists/*

# Copy the files from host into the builder
COPY --from=proj . .
WORKDIR /app/${CRATE_NAME}

# Build the intended crate
ENV CARGO_INCREMENTAL=0
ENV TZ=UTC
ENV RUSTFLAGS="-C link-arg=-Wl,--build-id=none --remap-path-prefix=/app=."
RUN rustup target add ${CARGO_TARGET}
RUN cargo build --release ${FEATURES} --locked --target ${CARGO_TARGET}

# Copy the binary artifact into the host directory
FROM scratch AS artifact
ARG CRATE_NAME
ARG CARGO_TARGET
ARG BINARY_FILE_NAME

COPY --from=builder /app/${CRATE_NAME}/target/${CARGO_TARGET}/release/${BINARY_FILE_NAME} /${BINARY_FILE_NAME}
