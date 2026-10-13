"""Deployment MFA modes use real encrypted TOTP secrets and fail closed on errors."""

from types import SimpleNamespace

from cryptography.fernet import Fernet
from fastapi import HTTPException
import pyotp
import pytest

from ccure_platform.identity import reauth
from ccure_platform.identity.router import encrypt_secret
from config import AppConfig


@pytest.fixture
def enrolled(monkeypatch):
    monkeypatch.setattr(AppConfig, "MFA_KEY", Fernet.generate_key())
    secret = pyotp.random_base32()
    user = SimpleNamespace(
        id="fixture-admin", mfa_enabled=True, totp_secret=encrypt_secret(secret)
    )
    return user, pyotp.TOTP(secret)


@pytest.mark.parametrize("mode", ["enforce", "require_enrolment"])
def test_step_up_requires_a_current_real_totp_in_both_enforcing_modes(
    monkeypatch, enrolled, mode
):
    monkeypatch.setattr(AppConfig, "RBAC_REAUTH_MODE", mode)
    user, totp = enrolled
    with pytest.raises(HTTPException) as missing:
        reauth.check(user, SimpleNamespace(headers={}))
    assert missing.value.status_code == 403
    assert missing.value.detail["code"] == "reauth_required"
    with pytest.raises(reauth.ReauthFailed):
        reauth.check(user, SimpleNamespace(headers={reauth.HEADER: "not-a-code"}))
    assert (
        reauth.check(user, SimpleNamespace(headers={reauth.HEADER: totp.now()}))
        == "verified"
    )


@pytest.mark.parametrize(
    "enabled,secret", [(False, None), (True, None), (False, "encrypted")]
)
def test_required_enrolment_refuses_absent_or_incomplete_mfa(
    monkeypatch, enabled, secret
):
    user = SimpleNamespace(mfa_enabled=enabled, totp_secret=secret)
    monkeypatch.setattr(AppConfig, "RBAC_REAUTH_MODE", "enforce")
    assert reauth.check(user, SimpleNamespace(headers={})) == "not_enrolled"
    monkeypatch.setattr(AppConfig, "RBAC_REAUTH_MODE", "require_enrolment")
    with pytest.raises(HTTPException) as refused:
        reauth.check(user, SimpleNamespace(headers={reauth.HEADER: "123456"}))
    assert refused.value.status_code == 403
    assert refused.value.detail["code"] == "mfa_enrolment_required"


def test_unrecognized_mode_uses_enforce_instead_of_disabling_step_up(
    monkeypatch, enrolled
):
    monkeypatch.setattr(AppConfig, "RBAC_REAUTH_MODE", "misspelled-mode")
    user, _ = enrolled
    with pytest.raises(HTTPException) as refused:
        reauth.check(user, SimpleNamespace(headers={}))
    assert refused.value.detail["code"] == "reauth_required"


def test_unreadable_totp_secret_is_refused_and_the_code_is_not_logged(
    monkeypatch, enrolled, caplog
):
    monkeypatch.setattr(AppConfig, "RBAC_REAUTH_MODE", "enforce")
    user, totp = enrolled
    code = totp.now()
    monkeypatch.setattr(AppConfig, "MFA_KEY", Fernet.generate_key())
    with pytest.raises(reauth.ReauthFailed):
        reauth.check(user, SimpleNamespace(headers={reauth.HEADER: code}))
    assert code not in caplog.text and user.totp_secret not in caplog.text


def test_off_is_an_explicit_operational_bypass(monkeypatch, enrolled):
    monkeypatch.setattr(AppConfig, "RBAC_REAUTH_MODE", "off")
    user, _ = enrolled
    assert reauth.check(user, SimpleNamespace(headers={})) == "not_required"
