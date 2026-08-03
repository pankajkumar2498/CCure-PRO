"""
core/web/auth/secrets.py
────────────────────────────────────────────────────────────────────────────
At-rest protection for web scan authentication credentials.

A web scan's auth_config holds the same class of secret the credentialed
scanner holds — an application password, a bearer token, a session cookie —
and the credentialed scanner already encrypts those with AES-256-GCM before
they touch the database. The web scan module stored them as plain JSON on the
web_scans row, so the password an operator supplied to scan their own
application sat readable to anyone with database access, in backups, and in
the Celery task payloads that carry it between phases through Redis.

This module closes that gap using the project's existing crypto, so both scan
types protect credentials the same way and with the same key.

Values are tagged with a version prefix rather than moved to new column names.
That keeps the change to a value transformation — rows written before this
existed are still plain and still decrypt correctly, and encrypting an already
encrypted config is a no-op — so no migration and no re-entry of credentials
is required.
"""

import logging
from typing import Any, Dict

log = logging.getLogger("ccure.web.auth.secrets")

#: Marks a value this module encrypted. Anything without it is read as plain
#: text, which is what makes rows predating encryption keep working.
_PREFIX = "enc:v1:"

#: auth_config keys whose values are credentials.
_SECRET_KEYS = ("password", "token")

#: auth_config keys holding a mapping whose *values* are credentials.
_SECRET_MAP_KEYS = ("cookies", "headers")


def _encrypt(value: str) -> str:
    if not value or value.startswith(_PREFIX):
        return value
    try:
        from core.security_crypto import encrypt_credential

        return _PREFIX + encrypt_credential(value)
    except Exception as exc:  # noqa: BLE001
        # Storing the secret in the clear because encryption broke would defeat
        # the point silently. Refuse instead — the scan cannot be launched with
        # credentials this system is unable to protect.
        log.error("Failed to encrypt web scan credential: %s", exc)
        raise ValueError(
            "Unable to encrypt the supplied scan credentials. Check that "
            "COMPLIANCE_ENCRYPTION_KEY is configured on the API."
        ) from exc


def _decrypt(value: str) -> str:
    if not value or not value.startswith(_PREFIX):
        return value
    try:
        from core.security_crypto import decrypt_credential

        return decrypt_credential(value[len(_PREFIX) :])
    except Exception as exc:  # noqa: BLE001
        log.error("Failed to decrypt web scan credential: %s", exc)
        return ""


def _transform(config: Dict[str, Any], fn) -> Dict[str, Any]:
    if not config:
        return config or {}
    result = dict(config)
    for key in _SECRET_KEYS:
        if isinstance(result.get(key), str):
            result[key] = fn(result[key])
    for key in _SECRET_MAP_KEYS:
        mapping = result.get(key)
        if isinstance(mapping, dict):
            result[key] = {
                k: fn(v) if isinstance(v, str) else v for k, v in mapping.items()
            }
    return result


def encrypt_auth_config(config: Dict[str, Any] | None) -> Dict[str, Any]:
    """Protect the credentials in an auth_config before it is persisted."""
    return _transform(config or {}, _encrypt)


def decrypt_auth_config(config: Dict[str, Any] | None) -> Dict[str, Any]:
    """Recover usable credentials from a stored auth_config."""
    return _transform(config or {}, _decrypt)


def redact_auth_config(config: Dict[str, Any] | None) -> Dict[str, Any]:
    """
    An auth_config safe to return over the API or write to a log.

    Whether a secret is present is useful to the reader; the secret itself
    never is.
    """
    if not config:
        return {}
    redacted = dict(config)
    for key in _SECRET_KEYS:
        if redacted.get(key):
            redacted[key] = "********"
    for key in _SECRET_MAP_KEYS:
        mapping = redacted.get(key)
        if isinstance(mapping, dict):
            redacted[key] = {k: "********" for k in mapping}
    return redacted
