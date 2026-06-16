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

    logger.info(f"Connecting to SMTP server at {host}:{port} (secure={secure}) to send reset email to {email_to}")

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
        logger.error(f"Failed to send password reset email to {email_to}: {e}", exc_info=True)
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

    logger.info(f"Connecting to SMTP server at {host}:{port} (secure={secure}) to send MFA verification email to {email_to}")

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
        logger.error(f"Failed to send MFA verification email to {email_to}: {e}", exc_info=True)
        raise

