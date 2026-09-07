# Zoltra public Opengrep SAST scanner image.
#
# Built and published from the dedicated public package source
# (PepBunny/zoltra-opengrep-action) as
#   ghcr.io/pepbunny/zoltra-opengrep-sast@sha256:<manifest image_digest>
# The customer workflow pins that digest; never a floating tag.
#
# Contents: the pinned Opengrep engine (same 1.29.0 line and digests as
# the Zoltra runtime images), the owned Zoltra rule pack (no third-party
# rules), and the bounded sanitizer entrypoint. The image never sees
# credentials: the workflow mounts the pinned checkout read-only and the
# image has no network access (`docker run --network none`).

FROM python:3.12-slim

# Pinned engine v1.29.0 (release commit
# 344509d693c852eaac4fc1eeffaf2f655c531b5a). Official release asset
# only, never the floating installer symlink or `latest`. Digest is
# verified before install and the build fails unless
# `opengrep --version` reports 1.29.0. Identical pin to the Zoltra
# runtime images (zoltra/hermes/Dockerfile, zoltra/infra/e2b/Dockerfile).
ARG TARGETARCH
ENV OPENGREP_VERSION=1.29.0
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
        amd64) OPENGREP_ASSET=opengrep_manylinux_x86; OPENGREP_DIGEST=3365ef49d04893e01338d85d9bbd49b2bd5261ad4c9c0df0a6a0f8d44232ae13 ;; \
        arm64) OPENGREP_ASSET=opengrep_manylinux_aarch64; OPENGREP_DIGEST=db3cda6e6e53251a3874e62b7c8493c281508480b3f3b4db554be41583b21174 ;; \
        *) echo "unsupported TARGETARCH for opengrep: ${TARGETARCH:-unset}"; exit 1 ;; \
    esac; \
    apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*; \
    curl -fsSL -o /tmp/opengrep "https://github.com/opengrep/opengrep/releases/download/v${OPENGREP_VERSION}/${OPENGREP_ASSET}"; \
    echo "${OPENGREP_DIGEST}  /tmp/opengrep" | sha256sum -c -; \
    install -m 0755 /tmp/opengrep /usr/local/bin/opengrep; \
    rm -f /tmp/opengrep; \
    opengrep --version | grep -q "1.29.0"

# Owned rule pack (Zoltra-authored, stable zoltra.sast.* ids).
COPY opengrep-rules/rules.yml /opt/zoltra-sast/rules.yml

# PyYAML for the rule-pack read (same pin as zoltra/backend/requirements.txt).
RUN pip install --no-cache-dir pyyaml==6.0.2

# Bounded sanitizer entrypoint (stdlib only; also validated by backend).
COPY sanitizer-entrypoint.py /opt/zoltra-sast/sanitizer-entrypoint.py

# The image runs as a non-root user; /scan is mounted read-only by the
# workflow and /out receives exactly one artifact file. The scanner
# engine needs a writable cache/temp location, but the workflow runs
# this image --read-only: HOME points at /tmp, which the workflow
# provides as a bounded tmpfs mount, so no layer is ever written.
ENV HOME=/tmp XDG_CACHE_HOME=/tmp/.cache
RUN useradd -m -u 10000 sast && mkdir -p /out /tmp/.cache && chown sast:sast /out /tmp/.cache
USER sast
WORKDIR /opt/zoltra-sast

ENTRYPOINT ["python3", "/opt/zoltra-sast/sanitizer-entrypoint.py"]
