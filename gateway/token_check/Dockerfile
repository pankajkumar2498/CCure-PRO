# gateway-auth — the gateway's token check (Phase 10.2b).
#
# Build from the REPOSITORY ROOT; the context is restricted by
# Dockerfile.dockerignore to this directory and the three ccure_platform files
# the verification rules live in:
#
#   docker build -f gateway/token_check/Dockerfile -t ccure-gateway-auth .
#
# What the image must never contain, and why it cannot: Backend/.env, the JWT
# secret, the MFA key, any private key. Only public keys are ever held, fetched
# at run time from the core's JWKS. The ignore file is an allow-list, so a new
# file anywhere else in the repository cannot reach the context by accident.

# The core service's base image, by digest (Backend/Dockerfile).
FROM python:3.11-slim@sha256:da047cb8f9d1d98e5c070f5300ba9f7274e33b8fc0e5be5ed88740aed1b95ba9

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# The pinned base carries openssl and pcre2 builds that Debian has since fixed
# (CVE-2026-75804, CVE-2026-84782, CVE-2026-103111), the same upgrade
# Backend/Dockerfile makes on the same base. --only-upgrade installs nothing
# new and leaves every other package at the base's version. Drop it once the
# digest moves to a base that already carries them.
RUN apt-get update && apt-get install -y --no-install-recommends --only-upgrade \
    libssl3t64 \
    openssl \
    openssl-provider-legacy \
    libpcre2-8-0 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY gateway/token_check/requirements.txt /tmp/requirements.txt
RUN pip install --no-compile -r /tmp/requirements.txt && rm /tmp/requirements.txt \
    && useradd --uid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin gwauth

# The verification rules at their own import path, and nothing else of the core.
COPY Backend/ccure_platform/__init__.py          /srv/ccure_platform/__init__.py
COPY Backend/ccure_platform/identity/__init__.py /srv/ccure_platform/identity/__init__.py
COPY Backend/ccure_platform/identity/verification.py /srv/ccure_platform/identity/verification.py
COPY gateway/token_check/__init__.py gateway/token_check/config.py \
     gateway/token_check/jwks.py gateway/token_check/checker.py gateway/token_check/app.py \
     /srv/token_check/

WORKDIR /srv
USER 10001:10001
EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).status == 200 else 1)"]

CMD ["uvicorn", "--factory", "token_check.app:create_app", \
     "--host", "0.0.0.0", "--port", "8080", \
     "--no-server-header", "--no-access-log", "--no-proxy-headers", \
     "--timeout-keep-alive", "75"]
