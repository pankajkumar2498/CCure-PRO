"""
Module: core.security_crypto
Purpose: Secure encryption and decryption utilities using AES-256-GCM.
Author:  Compliance Dev Team
"""

import base64
import hashlib
import logging
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

log = logging.getLogger("ccure.compliance.crypto")

_FALLBACK_KEY = "CCURE_AUDIT_PRO_DEFAULT_FALLBACK_KEY_DO_NOT_USE_IN_PRODUCTION"

#: Resolved on first use, not at import.
#:
#: Reading the environment at import time made the active key depend on import
#: order. ``config`` is what loads Backend/.env into ``os.environ``; any module
#: that reached security_crypto before it — which is easy to do from a Celery
#: worker, where the import graph is entered from a task module — silently got
#: the hardcoded fallback instead of the real key. The process then encrypted
#: credentials nothing else could read, with no error at the point of failure.
#:
#: That is the same defect as the API/worker key split, just triggered by import
#: order rather than by configuration, so it is closed the same way: the key is
#: resolved once, on demand, after the application has finished booting.
_key_digest: bytes | None = None
_using_fallback: bool | None = None


def _resolve_key() -> bytes:
    """The 32-byte AES key, derived from the configured master key."""
    global _key_digest, _using_fallback
    if _key_digest is not None:
        return _key_digest

    raw = os.environ.get("COMPLIANCE_ENCRYPTION_KEY")
    if not raw:
        # Importing config populates os.environ from the .env files. Done here
        # rather than at module scope to avoid a circular import.
        try:
            import config  # noqa: F401
        except Exception:  # pragma: no cover — config is optional for tooling
            pass
        raw = os.environ.get("COMPLIANCE_ENCRYPTION_KEY")

    _using_fallback = not raw
    if not raw:
        # Logged at ERROR, not WARNING: every credential written by this process
        # is encrypted under a key published in this file, so it protects
        # nothing — and any process holding the real key cannot read what this
        # one wrote.
        log.error(
            "COMPLIANCE_ENCRYPTION_KEY is not set — falling back to the key "
            "hardcoded in security_crypto.py. Stored credentials are NOT "
            "protected, and any other process holding the real key will be "
            "unable to decrypt them. Set COMPLIANCE_ENCRYPTION_KEY to the same "
            "value everywhere (API, workers, and Backend/.env)."
        )
        raw = _FALLBACK_KEY

    _key_digest = hashlib.sha256(raw.encode("utf-8")).digest()
    return _key_digest


def key_fingerprint() -> str:
    """
    Non-reversible fingerprint of the active key.

    Reported on a decryption failure so a key mismatch between two processes is
    diagnosable without ever putting the key itself in a log.
    """
    return hashlib.sha256(_resolve_key()).hexdigest()[:12]


def using_fallback_key() -> bool:
    """Whether this process fell back to the built-in (insecure) key."""
    _resolve_key()
    return bool(_using_fallback)


def encrypt_credential(plain_text: str) -> str:
    """
    Encrypts plain text using AES-256-GCM.

    Args:
        plain_text: The sensitive raw string to encrypt.

    Returns:
        Base64 encoded string containing the 12-byte nonce followed by ciphertext.
    """
    if not plain_text:
        return ""
    aesgcm = AESGCM(_resolve_key())
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plain_text.encode("utf-8"), None)
    return base64.b64encode(nonce + ciphertext).decode("utf-8")


def decrypt_credential(cipher_text_b64: str) -> str:
    """
    Decrypts AES-256-GCM encrypted base64 payload.

    Args:
        cipher_text_b64: Base64 encoded string (12-byte nonce + ciphertext).

    Returns:
        The decrypted plain text string.

    Raises:
        ValueError: When the encrypted payload is malformed.
    """
    if not cipher_text_b64:
        return ""
    try:
        data = base64.b64decode(cipher_text_b64.encode("utf-8"))
        if len(data) < 12:
            raise ValueError("Invalid encrypted payload size.")
        nonce = data[:12]
        ciphertext = data[12:]
        aesgcm = AESGCM(_resolve_key())
        decrypted = aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted.decode("utf-8")
    except InvalidTag as err:
        # An authentication-tag failure on a payload this application wrote
        # almost always means it was encrypted under a different key, not that
        # the data is corrupt. Naming that, with the fingerprint of the key
        # actually in use, turns a dead end into a one-line diagnosis.
        raise ValueError(
            "Invalid encrypted payload or authentication tag — the value was "
            "most likely encrypted with a different COMPLIANCE_ENCRYPTION_KEY. "
            f"This process is using key fingerprint {key_fingerprint()}"
            f"{' (INSECURE built-in fallback — the variable is unset)' if using_fallback_key() else ''}. "
            "Ensure the API, the workers and Backend/.env all share one value, "
            "then re-enter the stored credential."
        ) from err
    except (ValueError, Exception) as err:
        if isinstance(err, ValueError):
            raise
        raise ValueError(f"Invalid encrypted payload: {err}") from err
