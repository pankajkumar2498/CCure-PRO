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

#: auth_config keys whose values are credentials. Beyond form/bearer, this
#: covers the modern-token fields (jwt / api_key / oauth2 client secret and
#: their `value` alias) and the TOTP shared secret used to drive an MFA screen —
#: all long-lived credentials that must not sit in the clear in the scan row.
_SECRET_KEYS = (
    "password",
    "token",
    "jwt",
    "key",
    "value",
    "client_secret",
    "totp_secret",
)

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
    # Multi-step logins carry their credentials inside each step's `fields`
    # dict, under an application-specific name we cannot predict, so every
    # string value there is protected. Encryption round-trips a `{{token}}`
    # placeholder or a username unchanged, so this is safe for non-secret
    # fields too.
    steps = result.get("login_steps")
    if isinstance(steps, list):
        new_steps = []
        for step in steps:
            if isinstance(step, dict) and isinstance(step.get("fields"), dict):
                step = dict(step)
                step["fields"] = {
                    k: fn(v) if isinstance(v, str) else v
                    for k, v in step["fields"].items()
                }
            new_steps.append(step)
        result["login_steps"] = new_steps
    # Phase 13 workflows carry user-entered values (a password typed into a
    # field, a token) in each action's `value`. Protect every action value the
    # same way as login_steps — encryption round-trips a placeholder or a
    # non-secret unchanged, so this is safe for all of them.
    wf = result.get("workflow")
    _wf_actions = (
        wf.get("actions")
        if isinstance(wf, dict)
        else (wf if isinstance(wf, list) else None)
    )
    if isinstance(_wf_actions, list):
        new_actions = []
        for a in _wf_actions:
            if isinstance(a, dict) and isinstance(a.get("value"), str):
                a = dict(a)
                a["value"] = fn(a["value"])
            new_actions.append(a)
        result["workflow"] = (
            {**wf, "actions": new_actions} if isinstance(wf, dict) else new_actions
        )
    # Phase 4 access-control testing carries additional users (User B, admin),
    # each with their own auth config nested under access_control.users[].auth.
    # Those are the same class of secret as the main login and must be
    # protected the same way, recursively.
    access = result.get("access_control")
    if isinstance(access, dict) and isinstance(access.get("users"), list):
        access = dict(access)
        access["users"] = [
            (
                {**u, "auth": _transform(u["auth"], fn)}
                if isinstance(u, dict) and isinstance(u.get("auth"), dict)
                else u
            )
            for u in access["users"]
        ]
        result["access_control"] = access
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
    steps = redacted.get("login_steps")
    if isinstance(steps, list):
        red_steps = []
        for step in steps:
            if isinstance(step, dict) and isinstance(step.get("fields"), dict):
                step = dict(step)
                step["fields"] = {k: "********" for k in step["fields"]}
            red_steps.append(step)
        redacted["login_steps"] = red_steps
    wf = redacted.get("workflow")
    _wf_actions = (
        wf.get("actions")
        if isinstance(wf, dict)
        else (wf if isinstance(wf, list) else None)
    )
    if isinstance(_wf_actions, list):
        red_actions = []
        for a in _wf_actions:
            if isinstance(a, dict) and a.get("value") not in (None, ""):
                a = {**a, "value": "********"}
            red_actions.append(a)
        redacted["workflow"] = (
            {**wf, "actions": red_actions} if isinstance(wf, dict) else red_actions
        )
    access = redacted.get("access_control")
    if isinstance(access, dict) and isinstance(access.get("users"), list):
        access = dict(access)
        access["users"] = [
            (
                {**u, "auth": redact_auth_config(u["auth"])}
                if isinstance(u, dict) and isinstance(u.get("auth"), dict)
                else u
            )
            for u in access["users"]
        ]
        redacted["access_control"] = access
    return redacted
