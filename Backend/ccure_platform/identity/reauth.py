"""
ccure_platform/identity/reauth.py — step-up for sensitive governance operations.

RBAC-7. No second MFA system: this reuses the account's own TOTP secret and the same
verification the login challenge uses. A sensitive operation (changing a privileged
role, assigning or revoking one, retiring one, replacing system-level authority,
governing across organisations) needs a *current* authenticator code, sent as the
``X-Reauth-Code`` header with the request that performs it.

* An account **with** MFA enrolled must present a valid code: without one the request is
  refused (403, ``detail.code == "reauth_required"``), with a wrong one it is refused and
  the failure is audited (``rbac.reauth.failed``).
* An account **without** MFA enrolled has nothing to step up with; the existing
  infrastructure supports no other factor, so the operation is allowed and the audit
  event records ``reauth: "not_enrolled"`` — visible, not silent. (Enrolling MFA is the
  remedy; ``RBAC_REAUTH_MODE=require_enrolment`` refuses sensitive operations to an
  account that has none.)

``RBAC_REAUTH_MODE``: ``enforce`` (default — the rules above), ``require_enrolment``
(stricter) or ``off`` (tests and controlled environments only).
"""

from __future__ import annotations

import logging

from fastapi import HTTPException, status

logger = logging.getLogger("ccure.security")

HEADER = "x-reauth-code"
CODE_REQUIRED = "reauth_required"
ENROLMENT_REQUIRED = "mfa_enrolment_required"


def _mode() -> str:
    from config import AppConfig

    raw = (
        (getattr(AppConfig, "RBAC_REAUTH_MODE", "enforce") or "enforce").strip().lower()
    )
    return raw if raw in ("enforce", "require_enrolment", "off") else "enforce"


def _verify(user, code: str) -> bool:
    try:
        import pyotp

        from ccure_platform.identity.router import decrypt_secret

        secret = decrypt_secret(user.totp_secret)
        return bool(pyotp.TOTP(secret).verify(code.strip(), valid_window=1))
    except Exception:  # noqa: BLE001 - a verifier fault is a refusal, never a pass
        logger.error("re-authentication check failed for %s", getattr(user, "id", "?"))
        return False


def check(user, request) -> str:
    """
    Step-up for ``user`` on this request. Returns what was established —
    ``verified``, ``not_enrolled`` or ``not_required`` — for the audit event, or raises
    403. Never logs the code.
    """
    mode = _mode()
    if mode == "off":
        return "not_required"
    enrolled = bool(getattr(user, "mfa_enabled", False)) and bool(
        getattr(user, "totp_secret", None)
    )
    if not enrolled:
        if mode == "require_enrolment":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "code": ENROLMENT_REQUIRED,
                    "message": "Enrol MFA to perform this operation.",
                },
            )
        return "not_enrolled"
    code = ""
    if request is not None:
        code = request.headers.get(HEADER, "") or ""
    if not code:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "code": CODE_REQUIRED,
                "message": "Enter a current authenticator code to continue.",
            },
        )
    if not _verify(user, code):
        raise ReauthFailed()
    return "verified"


class ReauthFailed(HTTPException):
    def __init__(self) -> None:
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": CODE_REQUIRED, "message": "That code was not accepted."},
        )
