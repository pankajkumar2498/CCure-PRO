"""
The MFA key is explicit and the workers hold no token or MFA secret (Phase 9, 3a/3b).

Running containers set SKIP_DOTENV_LOAD, so ``MFA_ENCRYPTION_KEY`` in Backend/.env is
never read and the effective key came from the JWT-secret fallback. The compose file
now passes it explicitly to the api — the only process that decrypts
``users.totp_secret`` — and keeps every secret away from the workers.

Source-only: reads docker-compose.yml, imports no application state.
"""

from __future__ import annotations

import pytest
import yaml
from cryptography.fernet import Fernet

from config import derive_mfa_fernet_key
from scripts.security import verify_mfa_key_continuity as cont
from testpaths import REPO_ROOT

_COMPOSE_FILE = REPO_ROOT / "docker-compose.yml"
# The api container mounts Backend/ only, so the compose file is invisible there;
# CI and a checkout see it.
needs_compose = pytest.mark.skipif(
    not _COMPOSE_FILE.exists(), reason="docker-compose.yml is not mounted here"
)
COMPOSE = (
    yaml.safe_load(_COMPOSE_FILE.read_text())["services"]
    if _COMPOSE_FILE.exists()
    else {}
)
WORKERS = ("worker", "beat", "web-worker")


def _env(service: str) -> dict[str, str]:
    raw = COMPOSE[service].get("environment", [])
    if isinstance(raw, dict):
        return {k: str(v) for k, v in raw.items()}
    return dict(item.split("=", 1) for item in raw)


def test_a_secret_stored_before_the_change_decrypts_after_it():
    secret = "x" * 48  # the JWT secret's value, which the explicit key repeats
    stored = Fernet(derive_mfa_fernet_key(secret)).encrypt(b"JBSWY3DPEHPK3PXP")
    assert Fernet(derive_mfa_fernet_key(secret)).decrypt(stored) == b"JBSWY3DPEHPK3PXP"
    assert cont.same_key(secret, secret)
    assert cont.undecryptable([stored.decode()], secret) == 0


def test_a_different_key_is_detected_not_assumed_equal():
    stored = Fernet(derive_mfa_fernet_key("old-secret")).encrypt(b"x").decode()
    assert not cont.same_key("old-secret", "new-secret")
    assert cont.undecryptable([stored], "new-secret") == 1


@needs_compose
def test_the_api_requires_an_explicit_mfa_key():
    value = _env("api")["MFA_ENCRYPTION_KEY"]
    assert value.startswith(
        "${MFA_ENCRYPTION_KEY:?"
    ), "unset must stop compose, not fall back"


@needs_compose
def test_workers_hold_no_token_or_mfa_secret():
    for service in WORKERS:
        env = _env(service)
        for name in ("JWT_SECRET_KEY", "MFA_ENCRYPTION_KEY", "CCURE_TOKEN_KEYS_DIR"):
            assert name not in env, f"{service} carries {name}"


@needs_compose
def test_workers_cannot_read_the_dotenv_file_through_the_backend_mount():
    for service in WORKERS:
        volumes = COMPOSE[service]["volumes"]
        assert "/dev/null:/app/.env:ro" in volumes, service
        assert volumes.index("./Backend:/app") < volumes.index("/dev/null:/app/.env:ro")
        assert _env(service)["SKIP_DOTENV_LOAD"] == "1"
