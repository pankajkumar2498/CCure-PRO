"""
Platform authentication carries the platform's name, not a product's.

Sign-in, password reset, account mail and MFA enrolment are the platform's. They
used to say "CCure Audit PRO": in the subject, the body and the footer of every
account email, and as the issuer shown in an authenticator app. They say "CCure PRO"
now. Nothing else about authentication changed: the same five messages are sent
by the same functions to the same recipients, the TOTP secret and its
verification are untouched, and only the issuer label in the provisioning URI
differs (for new enrolments; entries already in an authenticator keep their
label, and verification does not depend on it).
"""

from __future__ import annotations

import pyotp
import pytest

from ccure_platform.identity import mail_service, router

MESSAGES = [
    ("send_password_reset_email", ("a@x.test", "alice", "https://x.test/reset?t=1")),
    ("send_mfa_otp_email", ("a@x.test", "alice", "123456")),
    ("send_verification_email", ("a@x.test", "alice", "https://x.test/verify?t=1")),
    (
        "send_password_changed_email",
        ("a@x.test", "alice", "2026-10-03 10:00 UTC", "10.0.0.1"),
    ),
    (
        "send_account_approved_email",
        ("a@x.test", "alice", "https://x.test/login", "analyst"),
    ),
]


class FakeSMTP:
    """Records what would have been sent; the password-reset and MFA messages
    open their own connection, so the seam is the SMTP client itself."""

    messages: list = []

    def __init__(self, *a, **kw):
        pass

    def ehlo(self):
        pass

    def has_extn(self, name):
        return False

    def starttls(self):
        pass

    def login(self, *a):
        pass

    def sendmail(self, sender, recipients, raw):
        FakeSMTP.messages.append((recipients, raw))

    def quit(self):
        pass


@pytest.fixture
def sent(monkeypatch):
    import email
    from email import policy

    FakeSMTP.messages = []
    monkeypatch.setattr(mail_service.smtplib, "SMTP", FakeSMTP)
    monkeypatch.setattr(mail_service.smtplib, "SMTP_SSL", FakeSMTP)

    class View(list):
        def parsed(self):
            out = []
            for recipients, raw in FakeSMTP.messages:
                msg = email.message_from_string(raw, policy=policy.default)
                out.append(
                    {
                        "to": recipients[0],
                        "subject": str(msg["Subject"]),
                        "text": msg.get_body(("plain",)).get_content(),
                        "html": msg.get_body(("html",)).get_content(),
                    }
                )
            return out

    return View()


@pytest.mark.parametrize("name, args", MESSAGES, ids=[m[0] for m in MESSAGES])
def test_account_email_names_the_platform_not_a_product(sent, name, args):
    getattr(mail_service, name)(*args)
    messages = sent.parsed()
    assert len(messages) == 1 and messages[0]["to"] == "a@x.test"
    message = messages[0]
    for part in ("subject", "text", "html"):
        assert "CCure PRO" in message[part], (name, part)
        assert "Audit" not in message[part], (name, part)
        assert "CCure" not in message[part].replace("CCure PRO", ""), (name, part)


def test_the_message_content_that_is_not_branding_is_unchanged(sent):
    mail_service.send_password_reset_email(*MESSAGES[0][1])
    message = sent.parsed()[0]
    assert "https://x.test/reset?t=1" in message["html"]
    assert "https://x.test/reset?t=1" in message["text"]
    assert message["subject"] == "Reset Your Password - CCure PRO"


def test_the_totp_issuer_is_the_platform_and_the_secret_still_verifies(
    db_session, test_user, monkeypatch
):
    seen = {}
    original = pyotp.totp.TOTP.provisioning_uri

    def spy(self, name=None, issuer_name=None, **kw):
        seen["issuer"], seen["name"] = issuer_name, name
        return original(self, name=name, issuer_name=issuer_name, **kw)

    monkeypatch.setattr(pyotp.totp.TOTP, "provisioning_uri", spy)
    test_user.mfa_enabled = False
    try:
        out = router.enable_mfa(current_user=test_user, db=db_session)
        assert seen == {"issuer": "CCure PRO", "name": test_user.email}
        assert set(out) == {"secret", "qr_code"}  # the response shape is unchanged
        assert out["qr_code"].startswith("data:image/png;base64,")
        # verification is independent of the issuer label
        assert pyotp.TOTP(out["secret"]).verify(pyotp.TOTP(out["secret"]).now())
    finally:
        test_user.totp_secret = None
        db_session.commit()


def test_no_platform_authentication_source_names_a_product_in_what_it_sends():
    from testpaths import BACKEND_ROOT

    for rel in ("ccure_platform/identity/mail_service.py",):
        text = (BACKEND_ROOT / rel).read_text(encoding="utf-8")
        assert "Audit PRO" not in text, rel
    router_text = (BACKEND_ROOT / "ccure_platform/identity/router.py").read_text()
    assert 'issuer_name="CCure Audit PRO"' not in router_text
