"""
auth/mail_service.py
───────────────────────────────────
Email sending service for password reset and other notifications.
Uses standard smtplib and MIME formats.
"""

import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from html import escape

from config import AppConfig

logger = logging.getLogger(__name__)


def send_password_reset_email(email_to: str, username: str, reset_link: str) -> None:
    """
    Sends a password reset link to the specified email address.
    """
    sender = AppConfig.SMTP_FROM_EMAIL
    subject = "Reset Your Password - CCure Audit PRO"

    # HTML Body Design (Premium Corporate Light/Indigo Theme matching CCure Audit PRO)
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Reset Your Password</title>
    </head>
    <body style="font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #f3f4f6; color: #374151; margin: 0; padding: 40px 10px;">
        <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border: 1px solid #e5e7eb; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.05);">
            <div style="background-color: #1e1b4b; padding: 30px; text-align: center; border-bottom: 1px solid #312e81;">
                <h1 style="color: #ffffff; font-size: 24px; margin: 0; font-weight: 700; letter-spacing: -0.025em;">CCure Audit PRO</h1>
            </div>
            <div style="padding: 40px 30px; line-height: 1.6;">
                <p style="color: #111827; font-size: 16px; font-weight: 600; margin: 0 0 16px 0;">Hello {username},</p>
                <p style="color: #4b5563; font-size: 16px; margin: 0 0 24px 0;">We received a request to reset the password associated with your CCure Audit PRO account. Click the button below to set a new password:</p>
                <div style="text-align: center; margin: 32px 0;">
                    <a href="{reset_link}" style="background-color: #4f46e5; color: #ffffff !important; text-decoration: none; padding: 12px 30px; border-radius: 6px; font-size: 15px; font-weight: 600; display: inline-block; box-shadow: 0 4px 12px rgba(79, 70, 229, 0.2);">Reset Password</a>
                </div>
                <p style="color: #4b5563; font-size: 16px; margin: 0 0 12px 0;">If you prefer, you can also copy and paste the following link directly into your browser:</p>
                <p style="word-break: break-all; font-size: 14px; color: #4f46e5; margin: 0 0 24px 0;"><a href="{reset_link}" style="color: #4f46e5; text-decoration: underline;">{reset_link}</a></p>
                <div style="font-size: 13px; color: #b45309; background-color: #fef3c7; padding: 16px; border-radius: 8px; border-left: 4px solid #f59e0b; margin-top: 24px;">
                    <strong>Note:</strong> This link is secure and will expire in <strong>15 minutes</strong>. If you did not make this request, you can safely ignore this email; your password will remain secure and unchanged.
                </div>
            </div>
            <div style="background-color: #f9fafb; padding: 20px 30px; text-align: center; border-top: 1px solid #e5e7eb;">
                <p style="color: #9ca3af; font-size: 12px; margin: 4px 0;">&copy; 2026 CCure Audit PRO. All rights reserved.</p>
                <p style="color: #9ca3af; font-size: 12px; margin: 4px 0;">This is an automated system message. Please do not reply directly to this email.</p>
            </div>
        </div>
    </body>
    </html>
    """

    text_content = f"""
Hello {username},

We received a request to reset the password associated with your CCure Audit PRO account.
Please visit the following link to set a new password:

{reset_link}

This link is secure and will expire in 15 minutes.
If you did not request this, you can safely ignore this email.

--
CCure Audit PRO Team
"""

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = email_to

    msg.attach(MIMEText(text_content, "plain"))
    msg.attach(MIMEText(html_content, "html"))

    host = AppConfig.SMTP_HOST
    port = AppConfig.SMTP_PORT
    user = AppConfig.SMTP_USER
    password = AppConfig.SMTP_PASSWORD
    secure = AppConfig.SMTP_SECURE

    logger.info(
        f"Connecting to SMTP server at {host}:{port} (secure={secure}) to send reset email to {email_to}"
    )

    # Connect to the SMTP Server
    try:
        if secure:
            server = smtplib.SMTP_SSL(host, port, timeout=10)
        else:
            server = smtplib.SMTP(host, port, timeout=10)
            # Try to upgrade the connection to secure if supported
            server.ehlo()
            if server.has_extn("STARTTLS"):
                try:
                    server.starttls()
                    server.ehlo()
                except Exception as e:
                    logger.error(f"STARTTLS negotiation failed: {e}", exc_info=True)
                    raise

        if user and password:
            server.login(user, password)

        server.sendmail(sender, [email_to], msg.as_string())
        server.quit()
        logger.info(f"Successfully sent password reset email to {email_to}")
    except Exception as e:
        logger.error(
            f"Failed to send password reset email to {email_to}: {e}", exc_info=True
        )
        raise


def send_mfa_otp_email(email_to: str, username: str, code: str) -> None:
    """
    Sends a 6-digit MFA OTP code to the specified email address.
    """
    sender = AppConfig.SMTP_FROM_EMAIL
    subject = "Your Multi-Factor Verification Code - CCure Audit PRO"

    # HTML Body Design (Premium Corporate Light/Indigo Theme matching CCure Audit PRO)
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Your Verification Code</title>
    </head>
    <body style="font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #f3f4f6; color: #374151; margin: 0; padding: 40px 10px;">
        <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border: 1px solid #e5e7eb; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.05);">
            <div style="background-color: #1e1b4b; padding: 30px; text-align: center; border-bottom: 1px solid #312e81;">
                <h1 style="color: #ffffff; font-size: 24px; margin: 0; font-weight: 700; letter-spacing: -0.025em;">CCure Audit PRO</h1>
            </div>
            <div style="padding: 40px 30px; line-height: 1.6;">
                <p style="color: #111827; font-size: 16px; font-weight: 600; margin: 0 0 16px 0;">Hello {username},</p>
                <p style="color: #4b5563; font-size: 16px; margin: 0 0 24px 0;">Your multi-factor authentication code is below. Enter this code to verify your identity and complete the login process:</p>
                <div style="text-align: center; margin: 32px 0;">
                    <div style="background-color: #f3f4f6; color: #111827; border: 1px solid #e5e7eb; padding: 18px 24px; border-radius: 8px; font-size: 32px; font-weight: 700; display: inline-block; letter-spacing: 0.25em; font-family: monospace;">{code}</div>
                </div>
                <div style="font-size: 13px; color: #b45309; background-color: #fef3c7; padding: 16px; border-radius: 8px; border-left: 4px solid #f59e0b; margin-top: 24px;">
                    <strong>Note:</strong> This verification code is single-use and will expire in <strong>5 minutes</strong>. If you did not make this request, you can safely ignore this email; your account remains secure.
                </div>
            </div>
            <div style="background-color: #f9fafb; padding: 20px 30px; text-align: center; border-top: 1px solid #e5e7eb;">
                <p style="color: #9ca3af; font-size: 12px; margin: 4px 0;">&copy; 2026 CCure Audit PRO. All rights reserved.</p>
                <p style="color: #9ca3af; font-size: 12px; margin: 4px 0;">This is an automated system message. Please do not reply directly to this email.</p>
            </div>
        </div>
    </body>
    </html>
    """

    text_content = f"""
Hello {username},

Your multi-factor verification code is: {code}

This code is single-use and will expire in 5 minutes.
If you did not request this, you can safely ignore this email.

--
CCure Audit PRO Team
"""

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = email_to

    msg.attach(MIMEText(text_content, "plain"))
    msg.attach(MIMEText(html_content, "html"))

    host = AppConfig.SMTP_HOST
    port = AppConfig.SMTP_PORT
    user = AppConfig.SMTP_USER
    password = AppConfig.SMTP_PASSWORD
    secure = AppConfig.SMTP_SECURE

    logger.info(
        f"Connecting to SMTP server at {host}:{port} (secure={secure}) to send MFA verification email to {email_to}"
    )

    try:
        if secure:
            server = smtplib.SMTP_SSL(host, port, timeout=10)
        else:
            server = smtplib.SMTP(host, port, timeout=10)
            server.ehlo()
            if server.has_extn("STARTTLS"):
                try:
                    server.starttls()
                    server.ehlo()
                except Exception as e:
                    logger.error(f"STARTTLS negotiation failed: {e}", exc_info=True)
                    raise

        if user and password:
            server.login(user, password)

        server.sendmail(sender, [email_to], msg.as_string())
        server.quit()
        logger.info(f"Successfully sent MFA verification email to {email_to}")
    except Exception as e:
        logger.error(
            f"Failed to send MFA verification email to {email_to}: {e}", exc_info=True
        )
        raise


# ── Shared delivery for newer senders ─────────────────────────────────────────
#
# The two senders above each carry their own copy of the SMTP connection logic.
# Rather than add a third and fourth copy, new senders go through _deliver().


def _deliver(
    email_to: str,
    subject: str,
    text_content: str,
    html_content: str,
    purpose: str,
) -> None:
    """Connect, authenticate if configured, and send one multipart message."""
    sender = AppConfig.SMTP_FROM_EMAIL

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = email_to
    msg.attach(MIMEText(text_content, "plain"))
    msg.attach(MIMEText(html_content, "html"))

    host = AppConfig.SMTP_HOST
    port = AppConfig.SMTP_PORT
    user = AppConfig.SMTP_USER
    password = AppConfig.SMTP_PASSWORD
    secure = AppConfig.SMTP_SECURE

    logger.info(
        "Connecting to SMTP server at %s:%s (secure=%s) to send %s to %s",
        host,
        port,
        secure,
        purpose,
        email_to,
    )

    try:
        if secure:
            server = smtplib.SMTP_SSL(host, port, timeout=10)
        else:
            server = smtplib.SMTP(host, port, timeout=10)
            server.ehlo()
            if server.has_extn("STARTTLS"):
                server.starttls()
                server.ehlo()

        if user and password:
            server.login(user, password)

        server.sendmail(sender, [email_to], msg.as_string())
        server.quit()
        logger.info("Successfully sent %s to %s", purpose, email_to)
    except (
        smtplib.SMTPRecipientsRefused,
        smtplib.SMTPSenderRefused,
    ) as exc:
        # A hard refusal at RCPT TO is the strongest signal this system has
        # about an email address: the receiving server states the mailbox does
        # not exist. Every other check here — blocklists, domain age, MX shape —
        # infers; this one observes.
        #
        # Caught separately because the generic handler below cannot tell it
        # apart from "the SMTP server is down", and those mean opposite things:
        # one says the address is fake, the other says nothing about the address
        # at all. Conflating them is why this signal was previously unavailable.
        logger.warning(
            "Recipient refused for %s to %s: %s — flagging the address",
            purpose,
            email_to,
            exc.__class__.__name__,
        )
        _record_hard_bounce(email_to, str(exc))
        raise
    except Exception as exc:
        logger.error(
            "Failed to send %s to %s: %s", purpose, email_to, exc, exc_info=True
        )
        raise


def _record_hard_bounce(email_to: str, detail: str) -> None:
    """
    Flag the account whose mailbox was refused.

    Flag, never delete or deactivate. A 550 can also be produced by a
    misconfigured relay, a greylisting appliance answering too eagerly, or a
    receiving domain that blocks this sender specifically — so it belongs in
    front of the administrator who approves the account, not wired directly to
    an irreversible action.

    Swallows every error: this runs inside a failing mail send, and a problem
    recording the flag must not replace the SMTP error the caller needs to see.
    """
    try:
        from auth.email_domain_guard import FLAG_HARD_BOUNCE
        from auth.email_utils import normalize_email
        from db.base import SessionLocal, utcnow
        from db.models import User

        db = SessionLocal()
        try:
            user = (
                db.query(User).filter(User.email == normalize_email(email_to)).first()
            )
            if not user:
                return
            risk = dict(user.email_risk or {})
            flags = sorted(set(risk.get("flags") or []) | {FLAG_HARD_BOUNCE})
            risk["flags"] = flags
            signals = dict(risk.get("signals") or {})
            signals["smtp_refusal"] = detail[:300]
            risk["signals"] = signals
            user.email_risk = risk
            if not user.is_email_flagged:
                user.is_email_flagged = True
                user.flagged_at = utcnow()
            db.commit()
        finally:
            db.close()
    except Exception:
        logger.debug("Could not record hard bounce for %s", email_to, exc_info=True)


def _shell(title: str, body_html: str) -> str:
    """Wrap body HTML in the shared CCure email chrome."""
    return f"""
    <!DOCTYPE html>
    <html>
    <head><meta charset="utf-8"><title>{escape(title)}</title></head>
    <body style="font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #f3f4f6; color: #374151; margin: 0; padding: 40px 10px;">
        <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border: 1px solid #e5e7eb; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.05);">
            <div style="background-color: #1e1b4b; padding: 30px; text-align: center; border-bottom: 1px solid #312e81;">
                <h1 style="color: #ffffff; font-size: 24px; margin: 0; font-weight: 700; letter-spacing: -0.025em;">CCure Audit PRO</h1>
            </div>
            <div style="padding: 40px 30px; line-height: 1.6;">{body_html}</div>
            <div style="background-color: #f9fafb; padding: 20px 30px; text-align: center; border-top: 1px solid #e5e7eb;">
                <p style="color: #9ca3af; font-size: 12px; margin: 4px 0;">&copy; 2026 CCure Audit PRO. All rights reserved.</p>
                <p style="color: #9ca3af; font-size: 12px; margin: 4px 0;">This is an automated system message. Please do not reply directly to this email.</p>
            </div>
        </div>
    </body>
    </html>
    """


def send_verification_email(email_to: str, username: str, verify_link: str) -> None:
    """
    Send an email-verification link.

    The link proves control of a mailbox and nothing more, so it does not
    activate the account — an administrator still has to approve it. The copy
    says so explicitly: an email promising access, followed by a login that
    refuses, generates support tickets and teaches users to distrust the flow.

    `username` is user-supplied and is HTML-escaped. It is not a script vector
    in a mail client, but unescaped it allows arbitrary markup in a message
    that carries this product's branding, which is a phishing primitive.
    """
    ttl = AppConfig.EMAIL_VERIFICATION_TTL_HOURS
    safe_user = escape(username)
    safe_link = escape(verify_link, quote=True)

    html_content = _shell(
        "Verify your email",
        f"""
        <p style="color: #111827; font-size: 16px; font-weight: 600; margin: 0 0 16px 0;">Hello {safe_user},</p>
        <p style="color: #4b5563; font-size: 16px; margin: 0 0 24px 0;">Confirm this email address to continue setting up your CCure Audit PRO account:</p>
        <div style="text-align: center; margin: 32px 0;">
            <a href="{safe_link}" style="background-color: #4f46e5; color: #ffffff !important; text-decoration: none; padding: 12px 30px; border-radius: 6px; font-size: 15px; font-weight: 600; display: inline-block; box-shadow: 0 4px 12px rgba(79, 70, 229, 0.2);">Verify Email</a>
        </div>
        <p style="color: #4b5563; font-size: 16px; margin: 0 0 12px 0;">Or paste this link into your browser:</p>
        <p style="word-break: break-all; font-size: 14px; color: #4f46e5; margin: 0 0 24px 0;"><a href="{safe_link}" style="color: #4f46e5; text-decoration: underline;">{safe_link}</a></p>
        <div style="font-size: 13px; color: #b45309; background-color: #fef3c7; padding: 16px; border-radius: 8px; border-left: 4px solid #f59e0b; margin-top: 24px;">
            <strong>Note:</strong> This link expires in <strong>{ttl} hours</strong> and can be used once.
            Verifying your email does not by itself grant access &mdash; an administrator reviews and approves new accounts before sign-in is enabled.
            If you did not create this account, ignore this email and it will be removed automatically.
        </div>
        """,
    )

    text_content = f"""
Hello {username},

Confirm this email address to continue setting up your CCure Audit PRO account:

{verify_link}

This link expires in {ttl} hours and can be used once.

Verifying your email does not by itself grant access - an administrator
reviews and approves new accounts before sign-in is enabled.

If you did not create this account, ignore this email and it will be removed
automatically.

--
CCure Audit PRO Team
"""
    _deliver(
        email_to,
        "Verify your email - CCure Audit PRO",
        text_content,
        html_content,
        "verification email",
    )


def send_password_changed_email(
    email_to: str,
    username: str,
    when: str,
    source_ip: str | None = None,
) -> None:
    """
    Notify a user that their password changed.

    This is what turns a silent account takeover into one the owner can see.
    It is sent after the change has already succeeded, so it must never be able
    to fail the request that triggered it — callers dispatch it via Celery.
    """
    safe_user = escape(username)
    safe_when = escape(when)
    origin_html = f" from {escape(source_ip)}" if source_ip else ""
    origin_text = f" from {source_ip}" if source_ip else ""

    html_content = _shell(
        "Your password was changed",
        f"""
        <p style="color: #111827; font-size: 16px; font-weight: 600; margin: 0 0 16px 0;">Hello {safe_user},</p>
        <p style="color: #4b5563; font-size: 16px; margin: 0 0 24px 0;">The password on your CCure Audit PRO account was changed on <strong>{safe_when}</strong>{origin_html}. All other active sessions have been signed out.</p>
        <div style="font-size: 13px; color: #991b1b; background-color: #fee2e2; padding: 16px; border-radius: 8px; border-left: 4px solid #ef4444; margin-top: 24px;">
            <strong>If this wasn't you</strong>, your account may be compromised. Reset your password immediately and contact your administrator.
        </div>
        """,
    )

    text_content = f"""
Hello {username},

The password on your CCure Audit PRO account was changed on {when}{origin_text}.
All other active sessions have been signed out.

If this wasn't you, your account may be compromised. Reset your password
immediately and contact your administrator.

--
CCure Audit PRO Team
"""
    _deliver(
        email_to,
        "Your password was changed - CCure Audit PRO",
        text_content,
        html_content,
        "password-change notification",
    )


def send_account_approved_email(
    email_to: str, username: str, login_url: str, role_name: str | None = None
) -> None:
    """
    Tell a user their pending account has been approved and they can sign in.

    This closes the one gap that made the pending-approval design unusable in
    practice. The account holder verifies their mailbox, is told the account is
    awaiting approval, and then has no way to learn that approval happened — the
    in-app notification the approve endpoint raises is only visible *after* a
    successful login, which is exactly what they cannot do yet. Without this
    email the only option is to retry the login page periodically.

    Deliberately does **not** restate the password. The administrator never sees
    it for a self-registered account (the user chose it at registration), and
    mailing credentials would put them in an inbox for as long as it is kept.
    """
    safe_user = escape(username)
    safe_link = escape(login_url, quote=True)
    role_line = (
        f'<p style="color: #4b5563; font-size: 15px; margin: 0 0 24px 0;">'
        f"Your access level is <strong>{escape(role_name)}</strong>. If you need "
        f"different permissions, ask your administrator.</p>"
        if role_name
        else ""
    )

    html_content = _shell(
        "Your account has been approved",
        f"""
        <p style="color: #111827; font-size: 16px; font-weight: 600; margin: 0 0 16px 0;">Hello {safe_user},</p>
        <p style="color: #4b5563; font-size: 16px; margin: 0 0 24px 0;">An administrator has approved your CCure Audit PRO account. You can now sign in with the email address and password you registered with.</p>
        {role_line}
        <div style="text-align: center; margin: 32px 0;">
            <a href="{safe_link}" style="background-color: #4f46e5; color: #ffffff !important; text-decoration: none; padding: 12px 30px; border-radius: 6px; font-size: 15px; font-weight: 600; display: inline-block; box-shadow: 0 4px 12px rgba(79, 70, 229, 0.2);">Sign in</a>
        </div>
        <p style="word-break: break-all; font-size: 14px; color: #4f46e5; margin: 0 0 24px 0;"><a href="{safe_link}" style="color: #4f46e5; text-decoration: underline;">{safe_link}</a></p>
        <div style="font-size: 13px; color: #b45309; background-color: #fef3c7; padding: 16px; border-radius: 8px; border-left: 4px solid #f59e0b; margin-top: 24px;">
            <strong>If you did not request an account</strong>, do not sign in &mdash; tell your administrator, who can disable it.
        </div>
        """,
    )

    text_content = f"""
Hello {username},

An administrator has approved your CCure Audit PRO account. You can now sign in
with the email address and password you registered with.
{f'Your access level is {role_name}.' if role_name else ''}

    {login_url}

If you did not request an account, do not sign in - tell your administrator,
who can disable it.

--
CCure Audit PRO Team
"""
    _deliver(
        email_to,
        "Your account has been approved - CCure Audit PRO",
        text_content,
        html_content,
        "account-approved notification",
    )
