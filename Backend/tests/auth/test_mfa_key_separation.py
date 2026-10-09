"""
MFA encryption is separable from the JWT signing secret — Phase 9.2.

Stored MFA secrets (``users.totp_secret``) are Fernet-encrypted with a key
derived from ``MFA_ENCRYPTION_KEY``. Until Phase 9.2 that variable defaulted to
``JWT_SECRET_KEY`` and was set nowhere, so rotating the JWT secret would have made
every stored MFA secret undecryptable (finding F9-1).

These tests pin:

* the derivation formula, which must never change;
* **no fallback** (since 9.6c) — unset (or empty) yields no key, and the API refuses to
  start; it used to derive one from ``JWT_SECRET_KEY``, which is gone;
* **the separation** — the MFA key is derived from ``MFA_ENCRYPTION_KEY`` alone, and a
  JWT secret in the environment changes nothing;
* that the MFA endpoints encrypt and decrypt with the configured key.

Configurations are loaded in fresh interpreters with ``SKIP_DOTENV_LOAD=1``,
because ``config`` reads the environment once at import and a developer's
``Backend/.env`` must not decide the outcome.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys

import pytest
from cryptography.fernet import Fernet, InvalidToken

from config import derive_mfa_fernet_key
from testpaths import BACKEND_ROOT

JWT_A = "phase-9-2-test-jwt-secret-A"
JWT_B = "phase-9-2-test-jwt-secret-B-rotated"
MFA_M = "phase-9-2-test-mfa-secret-M"

_PROBE = (
    "import json; from config import AppConfig; "
    "print(json.dumps({'key': AppConfig.MFA_KEY.decode()}))"
)


def _config(jwt_secret: str, mfa_secret: str | None) -> dict:
    """The MFA key and its source, as a fresh process configured this way sees them."""
    env = {k: v for k, v in os.environ.items() if k != "MFA_ENCRYPTION_KEY"}
    env["SKIP_DOTENV_LOAD"] = "1"
    env["JWT_SECRET_KEY"] = jwt_secret
    if mfa_secret is not None:
        env["MFA_ENCRYPTION_KEY"] = mfa_secret
    result = subprocess.run(
        [sys.executable, "-c", _PROBE],
        cwd=BACKEND_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr[-2000:]
    return json.loads(result.stdout.strip().splitlines()[-1])


def test_the_derivation_formula_is_unchanged():
    expected = base64.urlsafe_b64encode(hashlib.sha256(b"any secret").digest())
    assert derive_mfa_fernet_key("any secret") == expected


def test_unset_means_no_key_not_a_derived_one():
    """There is no JWT-secret fallback (9.6c): unset yields no key at all, and the API
    refuses to start (main.py) rather than derive one from something else."""
    seen = _config(JWT_A, None)
    assert seen["key"] == ""
    assert seen["key"] != derive_mfa_fernet_key(JWT_A).decode()


def test_an_empty_value_is_not_the_empty_secret():
    seen = _config(JWT_A, "")
    assert seen["key"] == ""
    assert seen["key"] != derive_mfa_fernet_key("").decode()


def test_when_set_the_mfa_key_derives_from_it_alone():
    seen = _config(JWT_A, MFA_M)
    assert seen["key"] == derive_mfa_fernet_key(MFA_M).decode()


def test_a_jwt_secret_in_the_environment_changes_nothing():
    """The platform no longer reads JWT_SECRET_KEY; the MFA key cannot be tied to it."""
    assert _config(JWT_A, MFA_M)["key"] == _config(JWT_B, MFA_M)["key"]


def test_setting_it_to_the_retired_jwt_value_keeps_the_key_byte_identical():
    """The migration step that was taken: the explicit key repeats the old secret's
    value, so the derived key — and every stored secret — is unchanged."""
    assert _config(JWT_A, JWT_A)["key"] == derive_mfa_fernet_key(JWT_A).decode()


def test_a_secret_encrypted_under_the_old_fallback_decrypts_under_the_explicit_key():
    stored = Fernet(derive_mfa_fernet_key(JWT_A)).encrypt(b"JBSWY3DPEHPK3PXP")
    after = Fernet(_config(JWT_B, JWT_A)["key"].encode())
    assert after.decrypt(stored) == b"JBSWY3DPEHPK3PXP"
    with pytest.raises(InvalidToken):
        Fernet(derive_mfa_fernet_key(JWT_B)).decrypt(stored)


def test_the_api_refuses_to_start_without_an_mfa_key():
    source = (BACKEND_ROOT / "main.py").read_text()
    assert "Refusing to start: MFA_ENCRYPTION_KEY is not set" in source
    assert "MFA_KEY_SOURCE" not in source


def test_the_mfa_endpoints_use_the_configured_key(monkeypatch):
    from ccure_platform.identity import router
    from config import AppConfig

    monkeypatch.setattr(AppConfig, "MFA_KEY", derive_mfa_fernet_key(MFA_M))
    token = router.encrypt_secret("JBSWY3DPEHPK3PXP")
    assert (
        Fernet(derive_mfa_fernet_key(MFA_M)).decrypt(token.encode())
        == b"JBSWY3DPEHPK3PXP"
    )
    assert router.decrypt_secret(token) == "JBSWY3DPEHPK3PXP"


def test_the_test_session_derives_its_key_from_the_explicit_variable():
    """conftest sets MFA_ENCRYPTION_KEY to a fixed test value and removes any JWT secret."""
    from config import AppConfig, JWTConfig

    assert AppConfig.MFA_KEY == derive_mfa_fernet_key(JWTConfig.MFA_ENCRYPTION_KEY)
    assert "JWT_SECRET_KEY" not in os.environ
