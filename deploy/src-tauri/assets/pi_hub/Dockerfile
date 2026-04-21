# SPDX-License-Identifier: GPL-3.0-or-later
FROM docker.io/debian@sha256:1d6cd964917a13b547d1ea392dff9a000c3f36070686ebc5c8755d53fb374435

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      bash ca-certificates curl xz-utils jq \
      util-linux kmod udev \
      unzip \
      parted dosfstools e2fsprogs rsync \
    ; \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY build.sh /app/build.sh
ENTRYPOINT ["bash", "/app/build.sh"]
