"""
Celery tasks that deliver the application's email.

Moved here from ``core/tasks.py`` (Phase 3 of the modular-platform
programme). Mail dispatch had to import the scan task hub — and with it the
whole scanning stack — to reach five tasks that only ever call
``auth.mail_service``. Identity is a platform service and must not depend on
one module's scanner.

Behaviour is unchanged. The registered task names keep their
``ccure.tasks.`` prefix, so a message already sitting in Redis still routes to
a worker; the queue, the retry policy and the failure report are the same;
records still log under ``ccure.tasks``. ``core.tasks`` re-exports the five
tasks, so ``core.tasks.send_*_task`` is the same object as before.
"""

from __future__ import annotations

import logging

from core.celery_app import celery_app

log = logging.getLogger("ccure.tasks")


# ── Outgoing mail ─────────────────────────────────────────────────────────────
#
# Every one of these tasks used to wrap its send in `try/except: log.error(...)`.
# That looked defensive and was the opposite: swallowing the exception told
# Celery the task had *succeeded*, so a momentary SMTP failure — a dropped
# connection, a Gmail rate limit, a DNS blip — destroyed the message
# permanently. A user whose verification email hit a five-second outage simply
# never received it, and nothing retried.
#
# `autoretry_for=(Exception,)` with exponential backoff replaces that. The
# exception now propagates, Celery retries, and only after the retries are
# exhausted is the message given up on — at which point `on_failure` records it
# loudly, because at that point a promise made to a user has definitively been
# broken.
#
# Callers should not use `.delay()` on these directly. Go through
# `auth.mail_dispatch.dispatch_email`, which also handles the case where no
# worker is consuming the queue at all.

_MAIL_RETRY = dict(
    autoretry_for=(Exception,),
    retry_backoff=2,  # 2s, 4s, 8s, 16s …
    retry_backoff_max=300,
    retry_jitter=True,
    max_retries=5,
    queue="default",
)


class _MailTask(celery_app.Task):
    """Shared failure reporting for the mail tasks."""

    abstract = True

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        # args[0] is the recipient for every sender below. Logged so a
        # permanently undelivered message is findable, without dumping the body.
        recipient = args[0] if args else "<unknown>"
        log.error(
            "MAIL PERMANENTLY UNDELIVERED after %s retries: task=%s to=%s error=%s",
            self.max_retries,
            self.name,
            recipient,
            exc,
        )


@celery_app.task(
    name="ccure.tasks.send_password_reset_email",
    base=_MailTask,
    bind=True,
    **_MAIL_RETRY,
)
def send_password_reset_email_task(
    self, email_to: str, username: str, reset_link: str
) -> None:
    """Dispatch a password-reset link. Retried; see _MAIL_RETRY."""
    from auth.mail_service import send_password_reset_email as _send

    _send(email_to, username, reset_link)


@celery_app.task(
    name="ccure.tasks.send_mfa_otp",
    base=_MailTask,
    bind=True,
    **{**_MAIL_RETRY, "max_retries": 2, "retry_backoff_max": 20},
)
def send_mfa_otp_task(self, email_to: str, username: str, code: str) -> None:
    """
    Dispatch a 6-digit MFA code.

    Fewer, faster retries than the other senders: the code expires in five
    minutes, so a delivery arriving after a long backoff is useless to the
    person waiting for it and better replaced by them requesting a new one.
    """
    from auth.mail_service import send_mfa_otp_email as _send

    _send(email_to, username, code)


@celery_app.task(
    name="ccure.tasks.send_verification_email", base=_MailTask, bind=True, **_MAIL_RETRY
)
def send_verification_email_task(
    self, email_to: str, username: str, verify_link: str
) -> None:
    """Dispatch an email-verification link. Retried; see _MAIL_RETRY."""
    from auth.mail_service import send_verification_email as _send

    _send(email_to, username, verify_link)


@celery_app.task(
    name="ccure.tasks.send_password_changed_email",
    base=_MailTask,
    bind=True,
    **_MAIL_RETRY,
)
def send_password_changed_email_task(
    self, email_to: str, username: str, when: str, source_ip: str | None = None
) -> None:
    """
    Notify a user that their password changed.

    Worth retrying hard: this is the only signal the real owner gets during an
    account takeover, and it is useful whenever it arrives.
    """
    from auth.mail_service import send_password_changed_email as _send

    _send(email_to, username, when, source_ip)


@celery_app.task(
    name="ccure.tasks.send_account_approved_email",
    base=_MailTask,
    bind=True,
    **_MAIL_RETRY,
)
def send_account_approved_email_task(
    self, email_to: str, username: str, login_url: str, role_name: str | None = None
) -> None:
    """
    Tell a user their account was approved.

    Losing this one strands the user: they cannot see the in-app notification
    until they log in, which is what this email tells them they may now do.
    """
    from auth.mail_service import send_account_approved_email as _send

    _send(email_to, username, login_url, role_name)
