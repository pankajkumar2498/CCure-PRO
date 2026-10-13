# syntax=docker/dockerfile:1
#
# One image, four roles: compose runs it as `api`, `worker`, `beat` and
# `web-worker`, choosing the role by command (and by `user: root` for the three
# that need raw sockets or write where ccure cannot). CI builds it once per
# commit and tags it with the commit SHA — see .github/workflows/images.yml and
# docs/ci/CONTAINER_IMAGES.md.
#
# Base images are pinned by digest, so a rebuild of the same commit starts from
# the same bytes. Dependabot (docker ecosystem, .github/dependabot.yml) opens a
# PR when the image behind the tag is rebuilt, which is how security updates to
# the base still arrive. It never moves the Python version: 3.11 -> 3.14 is an
# upgrade (no Pillow 10.3.0 or psycopg2-binary 2.9.9 wheels there), made by
# editing the tag deliberately.
# ── Base Image ─────────────────────────────────────────────────────────────
FROM python:3.11-slim@sha256:da047cb8f9d1d98e5c070f5300ba9f7274e33b8fc0e5be5ed88740aed1b95ba9 AS base

# Download Chrome Stable through Google's authenticated APT repository. GPG
# remains build-only; Chrome's runtime package separately requires wget/libcurl.
# The fixed browser uses Playwright's supported chrome channel rather than its
# vulnerable, separately bundled Chromium 153.
FROM base AS chrome-download
RUN apt-get update && apt-get install -y --no-install-recommends wget gnupg \
    && wget -qO /usr/share/keyrings/google.asc https://dl.google.com/linux/linux_signing_key.pub \
    && gpg --show-keys --with-colons /usr/share/keyrings/google.asc \
       | awk -F: '$1 == "fpr" && $10 == "EB4C1BFD4F042F6DDDCCEC917721F63BD38B4796" { found=1 } END { exit !found }' \
    && echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/google.asc] https://dl.google.com/linux/chrome/deb/ stable main' > /etc/apt/sources.list.d/google-chrome.list \
    && apt-get update \
    && mkdir /chrome \
    && cd /chrome && apt-get download google-chrome-stable

FROM base AS browser-runtime

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PATH="/home/ccure/.local/bin:${PATH}"
# BuildKit warns that PYTHONPATH is undefined here. Leave it: the expansion
# leaves a trailing ':', and an empty PYTHONPATH entry means "the current
# directory", i.e. /app. `python db/migrate_production_schema.py` (start.sh)
# puts db/ first on sys.path, not /app, and its `from db...` imports resolve
# only through that empty entry.
ENV PYTHONPATH="/home/ccure/.local/lib/python3.11/site-packages:${PYTHONPATH}"
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/playwright
ENV CCURE_BROWSER_CHANNEL=chrome

# Runtime system packages only — this stage is what ships.
# - nmap: essential for network scanning
# - libcap2-bin: to grant raw socket permissions to non-root users
# - chromium: Debian's package supplies the shared browser libraries. The
#   production Playwright channel executes fixed Chrome Stable, installed below.
#   This package and its dependencies are retained deliberately;
#   see docs/ci/CONTAINER_IMAGES.md.
#
# The compiler toolchain (gcc, python3-dev, libpq-dev) and the download tools
# (wget, unzip, curl) used to be installed here too, which put a C compiler and
# the kernel headers into every running container. linux-libc-dev alone, pulled
# in by python3-dev, carried 88 of the image's 191 HIGH advisories. Nothing
# at run time uses any of them: psycopg2-binary bundles its libpq, and the
# scanner builds `curl ...` reproduction commands as text without running curl.
# They now exist only in the stages that need them.
#
# sqlmap is deliberately NOT installed here: it comes from requirements.txt into
# /home/ccure/.local, which the runtime stage copies wholesale. It used to be
# apt-installed in the `tools` stage instead, where nothing copied it onward —
# an apt package spanning /usr/bin and /usr/share cannot ride along with the
# per-binary COPY that carries the Go tools — so the build verified sqlmap and
# then shipped an image without it. The verification gate in `runtime` is what
# now prevents that, for every tool.
# Chromium 155 fixes the reviewed Chromium/Chromium-common release blockers.
# Keep Debian's signed security repository and accept newer versions, but fail
# the build if a stale mirror supplies an older package. This RUN change also
# invalidates cached installs of Chromium 154 in same-day CI layer caches.
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    libcap2-bin \
    chromium \
    && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' chromium)" ge '155.0.8059.39-1~deb13u1' \
    && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' chromium-common)" ge '155.0.8059.39-1~deb13u1' \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# The pinned base image carries openssl and pcre2 builds that Debian has since
# fixed (CVE-2026-75804, CVE-2026-84782, CVE-2026-103111). Upgrade exactly
# those packages; --only-upgrade installs nothing new and leaves every other
# package at the base's version. Drop this once the digest moves to a base that
# already carries them.
RUN apt-get update && apt-get install -y --no-install-recommends --only-upgrade \
    libssl3t64 \
    openssl \
    openssl-provider-legacy \
    libpcre2-8-0 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=chrome-download /chrome/google-chrome-stable_*.deb /tmp/google-chrome-stable.deb
RUN apt-get update && apt-get install -y --no-install-recommends /tmp/google-chrome-stable.deb \
    && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' google-chrome-stable)" ge '155.0.8059.39-1' \
    && rm /tmp/google-chrome-stable.deb \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Debian stable's curl 8.14.1 still carries CVE-2026-12064, CVE-2026-8286,
# CVE-2026-8458 and CVE-2026-8927. Select only the signed official backports
# needed for curl 8.21.0; do not upgrade the distribution or remove packages.
# The new GnuTLS package alone no longer satisfies Chrome's legacy dependency,
# so install the fixed OpenSSL implementation too and retain Chrome unchanged.
RUN printf '%s\n' \
    'Types: deb' \
    'URIs: https://deb.debian.org/debian' \
    'Suites: trixie-backports' \
    'Components: main' \
    'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' \
    > /etc/apt/sources.list.d/curl-backports.sources \
    && chrome_version=$(dpkg-query -W -f='${Version}' google-chrome-stable) \
    && apt-get update \
    && apt-get install -y --no-install-recommends --no-remove \
       libcurl3t64-gnutls=8.21.0-2~bpo13+1 \
       libcurl4-gnutls=8.21.0-2~bpo13+1 \
       libcurl4t64=8.21.0-2~bpo13+1 \
       libnghttp3-9=1.15.0-1~bpo13+1 \
       libngtcp2-16=1.22.1-1~bpo13+1 \
       libngtcp2-crypto-gnutls8=1.22.1-1~bpo13+1 \
       libngtcp2-crypto-ossl0=1.22.1-1~bpo13+1 \
    && test "$chrome_version" = "$(dpkg-query -W -f='${Version}' google-chrome-stable)" \
    && rm /etc/apt/sources.list.d/curl-backports.sources \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# ── Dependency Stage ───────────────────────────────────────────────────────
FROM browser-runtime AS builder

# Build-only: compilers and headers for any requirement without a wheel.
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    libpq-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --user -r requirements.txt

# The driver remains installed. Production uses Chrome Stable installed above;
# do not ship the unused vulnerable Chromium/headless-shell download alongside it.

# ── Patched Scanner Build Stage ───────────────────────────────────────────
# Keep the scanner releases and CLI contracts, but rebuild their HTTP/TLS
# dependencies: upstream release binaries still carry CVE-2026-78667,
# CVE-2026-78669 and CVE-2026-97031. Go's checksum database verifies the pinned
# module sources and dependencies. The compiler never enters the runtime image.
FROM golang:1.26.9-alpine@sha256:3082400e369fa24d5fc60bca20edab3f6d604e0c5a690ec66b295eff4dd87ade AS scanner-builder

ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOMAXPROCS=2
WORKDIR /src
ARG NUCLEI_VERSION=v3.11.1
ARG SUBFINDER_VERSION=v2.6.7
ARG FFUF_VERSION=v2.3.0
ARG SCANNER_X_NET_VERSION=v0.60.0

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download github.com/projectdiscovery/nuclei/v3@${NUCLEI_VERSION} && \
    cp -R /go/pkg/mod/github.com/projectdiscovery/nuclei/v3@${NUCLEI_VERSION} /src/nuclei && \
    chmod -R u+w /src/nuclei && cd /src/nuclei && \
    go get golang.org/x/net@${SCANNER_X_NET_VERSION} && \
    go build -p 2 -trimpath -ldflags="-s -w" -o /out/nuclei ./cmd/nuclei

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download github.com/projectdiscovery/subfinder/v2@${SUBFINDER_VERSION} && \
    cp -R /go/pkg/mod/github.com/projectdiscovery/subfinder/v2@${SUBFINDER_VERSION} /src/subfinder && \
    chmod -R u+w /src/subfinder && cd /src/subfinder && \
    go get golang.org/x/net@${SCANNER_X_NET_VERSION} && \
    go build -p 2 -trimpath -ldflags="-s -w" -o /out/subfinder ./cmd/subfinder

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download github.com/ffuf/ffuf/v2@${FFUF_VERSION} && \
    cp -R /go/pkg/mod/github.com/ffuf/ffuf/v2@${FFUF_VERSION} /src/ffuf && \
    chmod -R u+w /src/ffuf && cd /src/ffuf && \
    go get golang.org/x/net@${SCANNER_X_NET_VERSION} && \
    go build -p 2 -trimpath \
    -ldflags="-s -w -X github.com/ffuf/ffuf/v2/pkg/ffuf.VERSION=${FFUF_VERSION#v} -X github.com/ffuf/ffuf/v2/pkg/ffuf.VERSION_APPENDIX=" \
    -o /out/ffuf .

# ── Security Tools Stage ──────────────────────────────────────────────────
FROM base AS tools

RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY --from=scanner-builder /out/ /usr/local/bin/

# Nuclei templates — provisioned once at build time into the image (NOT fetched
# per scan). This is a build-time snapshot; the runtime gate below refuses to
# ship without it, and the scanner does not re-download on every scan.
# It is the one input here that is deliberately not pinned: the templates are a
# detection feed, and freezing them trades new coverage for reproducibility.
# Which snapshot an image carries is the image's own record, fixed at the SHA.
RUN nuclei -update-templates 2>/dev/null || echo "Nuclei template update skipped"

# ffuf's wordlist, pinned to a SecLists commit and checked. It was fetched from
# `master` with `|| echo skipped`, so its contents changed with upstream and a
# failed download shipped an image whose ffuf had nothing to try. This commit's
# file is byte-identical to the one the image carried when it was pinned.
ARG SECLISTS_COMMIT=eccfbd405af82194e125a450a0076dbe4252d6f9
ARG WORDLIST_SHA256=47fb86ca6fb3f97e5491161581900d6d99851fb16764eacddf16aa85617c956a
RUN mkdir -p /opt/wordlists && \
    wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/${SECLISTS_COMMIT}/Discovery/Web-Content/common.txt" \
    -O /opt/wordlists/common.txt && \
    echo "${WORDLIST_SHA256}  /opt/wordlists/common.txt" | sha256sum -c -

# ── Final Runtime Image ────────────────────────────────────────────────────
FROM browser-runtime AS runtime

# Create a non-privileged user for the API process
RUN useradd -m -s /bin/bash ccure

# Ownership is set by COPY --chown, never by a later `RUN chown -R`. Changing
# ownership in a separate layer writes every file a second time, and the
# duplicates were 1.27 GB of a 5.27 GB image: 488 MB of Python packages, 690 MB
# of Playwright browser and 90 MB of application code.

# Copy installed python packages from builder
COPY --from=builder --chown=ccure:ccure /root/.local /home/ccure/.local

# Copy security tool binaries from tools stage
COPY --from=tools /usr/local/bin/nuclei /usr/local/bin/nuclei
COPY --from=tools /usr/local/bin/subfinder /usr/local/bin/subfinder
COPY --from=tools /usr/local/bin/ffuf /usr/local/bin/ffuf
COPY --from=tools /opt/wordlists /opt/wordlists

# Copy nuclei templates (may be in /root or /home)
COPY --from=tools /root/nuclei-templates /opt/nuclei-templates

# ── Verify the scanners actually made it into the shipped image ────────────
# This gate runs in `runtime`, not in `tools`, because `runtime` is what ships.
# Scanner source/dependency fetches and compilation fail the build on error.
# This additional runtime gate catches a missing COPY into the final image,
# which would otherwise produce scans that report nothing.
#
# Verifying in an earlier stage does not establish this. `runtime` inherits from
# `base` and copies named paths out of `tools`, so a tool present in `tools` and
# not copied passes an earlier check and is still missing at run time. The
# checks have to run against the final filesystem.
#
# nuclei, ffuf, sqlmap, the Playwright browser and the nuclei templates are all
# fatal (Phase 15): each is a primary detector (or the data it needs), and
# shipping without one produces scans that look clean but tested nothing —
# exactly the SQLi gap Phase 14 flagged. sqlmap in particular is now fatal
# rather than a warning. subfinder and nmap are reported, not fatal.
RUN set -e; \
    echo "=== Runtime tool verification ==="; \
    for tool in nuclei subfinder ffuf sqlmap nmap; do \
        if command -v "$tool" >/dev/null 2>&1; then \
            echo "  OK       $tool -> $(command -v $tool)"; \
        else \
            echo "  MISSING  $tool"; \
        fi; \
    done; \
    missing=""; \
    command -v nuclei >/dev/null 2>&1 || missing="$missing nuclei"; \
    command -v ffuf >/dev/null 2>&1 || missing="$missing ffuf"; \
    command -v sqlmap >/dev/null 2>&1 || missing="$missing sqlmap"; \
    if command -v google-chrome-stable >/dev/null 2>&1; then \
        echo "  OK       playwright chrome channel -> $(google-chrome-stable --version)"; \
    else \
        missing="$missing playwright-chrome"; \
        echo "  MISSING  playwright chrome stable browser"; \
    fi; \
    tmpl_count=$(find /opt/nuclei-templates -name '*.yaml' -o -name '*.yml' 2>/dev/null | head -501 | wc -l); \
    if [ "$tmpl_count" -gt 0 ]; then \
        echo "  OK       nuclei-templates ($tmpl_count+ template files)"; \
    else \
        missing="$missing nuclei-templates"; \
        echo "  MISSING  nuclei-templates"; \
    fi; \
    if [ -n "$missing" ]; then \
        echo "FATAL: required scanner component(s) missing:$missing" >&2; \
        echo "Refusing to ship a scanner image that cannot perform its primary checks." >&2; \
        echo "SQL injection (sqlmap) is now a required component: a missing sqlmap" >&2; \
        echo "would let a SQL-injectable application read as clean." >&2; \
        exit 1; \
    fi

# Copy application code. /app itself was created by WORKDIR as root, and
# --chown covers what is copied, not the directory copied into, so it is handed
# over explicitly (one directory, not a recursive rewrite). The old recursive
# chown covered it, and start.sh's `sed -i` below needs to create a file here.
RUN chown ccure:ccure /app
COPY --chown=ccure:ccure . .

# Grant nmap binary the ability to perform raw socket scans without root
# This allows the worker to run with fewer privileges if desired,
# though running worker as root in container is often acceptable.
RUN setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap

# Create directory for reports
RUN mkdir -p /app/reports && chown -R ccure:ccure /app/reports

# Default environment variables
ENV ENV=production
ENV PORT=8000
ENV NUCLEI_TEMPLATES_DIR=/opt/nuclei-templates

# Entrypoint script will handle switching between API and Worker roles
EXPOSE 8000

# Use ccure user by default (overridden for worker in docker-compose)
USER ccure

# Ensure start.sh has executable permissions and LF line endings
RUN sed -i 's/\r$//' /app/start.sh && chmod +x /app/start.sh

CMD ["/app/start.sh"]
