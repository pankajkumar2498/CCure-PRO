"""
MFA encryption is separable from the JWT signing secret — Phase 9.2.

Stored MFA secrets (``users.totp_secret``) are Fernet-encrypted with a key
derived from ``MFA_ENCRYPTION_KEY``. Until Phase 9.2 that variable defaulted to
``JWT_SECRET_KEY`` and was set nowhere, so rotating the JWT secret would have made
every stored MFA secret undecryptable (finding F9-1).

These tests pin:

* the derivation formula, which must never change;
* the fallback — unset (or empty) still derives from ``JWT_SECRET_KEY``, so an
  installation that has not set the variable behaves exactly as before;
* **the separation** — with ``MFA_ENCRYPTION_KEY`` set, changing
  ``JWT_SECRET_KEY`` alone leaves the MFA key, and every secret it encrypted,
  unchanged;
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
    "import json; from config import AppConfig, JWTConfig; "
    "print(json.dumps({'key': AppConfig.MFA_KEY.decode(), "
    "'source': JWTConfig.MFA_KEY_SOURCE}))"
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


def test_unset_falls_back_to_the_jwt_secret_as_before():
    seen = _config(JWT_A, None)
    assert seen["key"] == derive_mfa_fernet_key(JWT_A).decode()
    assert seen["source"] == "JWT_SECRET_KEY (fallback)"


def test_an_empty_value_is_treated_as_unset_not_as_the_empty_secret():
    seen = _config(JWT_A, "")
    assert seen["key"] == derive_mfa_fernet_key(JWT_A).decode()
    assert seen["key"] != derive_mfa_fernet_key("").decode()
    assert seen["source"] == "JWT_SECRET_KEY (fallback)"


def test_when_set_the_mfa_key_derives_from_it_alone():
    seen = _config(JWT_A, MFA_M)
    assert seen["key"] == derive_mfa_fernet_key(MFA_M).decode()
    assert seen["source"] == "MFA_ENCRYPTION_KEY"


def test_changing_the_jwt_secret_alone_does_not_change_the_mfa_key():
    """The regression the separation exists for."""
    before = _config(JWT_A, MFA_M)
    after = _config(JWT_B, MFA_M)
    assert before["key"] == after["key"]


def test_without_the_separation_changing_the_jwt_secret_would_change_it():
    """Why 9.2 had to come first: the coupling F9-1 describes, demonstrated."""
    assert _config(JWT_A, None)["key"] != _config(JWT_B, None)["key"]


def test_setting_it_to_the_current_jwt_secret_keeps_the_key_byte_identical():
    """The migration step: separate without re-encrypting anything."""
    assert _config(JWT_A, None)["key"] == _config(JWT_A, JWT_A)["key"]


def test_a_secret_encrypted_before_the_separation_decrypts_after_a_jwt_rotation():
    before = Fernet(_config(JWT_A, None)["key"].encode())  # today: fallback
    stored = before.encrypt(b"JBSWY3DPEHPK3PXP")
    # separated at the current JWT value, then the JWT secret rotated
    after = Fernet(_config(JWT_B, JWT_A)["key"].encode())
    assert after.decrypt(stored) == b"JBSWY3DPEHPK3PXP"
    # and had it not been separated, the rotation would have lost it
    with pytest.raises(InvalidToken):
        Fernet(_config(JWT_B, None)["key"].encode()).decrypt(stored)


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


def test_the_test_session_derives_the_key_it_always_did():
    """conftest pins MFA_ENCRYPTION_KEY to the test JWT secret (see there)."""
    from config import AppConfig, JWTConfig

    assert AppConfig.MFA_KEY == derive_mfa_fernet_key(JWTConfig.SECRET_KEY)
