"""
ccure_platform/identity/mail_dispatch.py (was auth/mail_dispatch.py until Phase 8.2)
──────────────────────────────────────────────────────────────────────────────
One way to send an application email, which cannot silently do nothing.

The problem this exists to solve
────────────────────────────────
`CELERY_TASK_ALWAYS_EAGER` is False on this deployment, so the API published
mail tasks to Redis and the **host** Celery worker delivered them. `.delay()`
returning successfully only means Redis accepted the message — it says nothing
about whether any process will ever consume it. With the host worker stopped,
registration still answered `202 pending_verification`, the account was created,
the verification token was committed, and no email was ever sent. The user had a
link they never received, no error, and no way to tell the difference between
"slow mail" and "this will never arrive".

That is the worst shape a failure can take: invisible on both sides. The admin
sees a pending account, the user sees silence.

So dispatch now works out whether the queue is actually being served, and if it
is not, sends the message **in this process** instead. The API container can
reach SMTP perfectly well; using the worker is an optimisation, not a
requirement.

Delivery is attempted exactly once. The two paths are mutually exclusive: if a
worker is going to run the task, this does not also send inline.

What this does *not* try to be
──────────────────────────────
A transactional outbox. If the broker is up and a worker is consuming, the
message is Redis's responsibility from that point; if the worker dies mid-task,
Celery's retry (see the mail tasks in auth/mail_tasks.py) covers it. Building a
persisted outbox table would cover the remaining window — the process dying
between commit and publish — at a cost that is not justified for
"the verification email is late".
"""

from __future__ import annotations

from ccure_platform._legacy import adopt_legacy_name

adopt_legacy_name(__name__, "auth.mail_dispatch")

import logging
import time
from typing import Any, Callable

log = logging.getLogger("ccure.mail")

# Queue the mail tasks are routed to. Must match the `queue=` on the task
# decorators in auth/mail_tasks.py and the --queues= the host worker is started with.
_MAIL_QUEUE = "default"

# How long a worker-availability answer is trusted. A broadcast ping costs a
# round trip with a timeout, which is far too much to pay on every registration;
# 30s is short enough that a worker stopping is noticed promptly and long enough
# that a burst of signups does not each pay for it.
_WORKER_CHECK_TTL_SECONDS = 30.0
_worker_check: dict[str, Any] = {"checked_at": 0.0, "available": False}


def _queue_has_consumer() -> bool:
    """
    Whether some worker is consuming the mail queue right now.

    Any failure — broker unreachable, inspect timing out, unexpected reply shape
    — is reported as *no* consumer. That biases towards sending inline, i.e.
    towards the message actually going out. The opposite bias would reintroduce
    exactly the silent loss this module exists to prevent.
    """
    now = time.monotonic()
    if now - _worker_check["checked_at"] < _WORKER_CHECK_TTL_SECONDS:
        return bool(_worker_check["available"])

    available = False
    try:
        from core.celery_app import celery_app

        replies = celery_app.control.inspect(timeout=1.5).active_queues() or {}
        for queues in replies.values():
            for queue in queues or []:
                if queue.get("name") == _MAIL_QUEUE:
                    available = True
                    break
            if available:
                break
    except Exception:
        log.debug("Could not determine mail queue consumers", exc_info=True)
        available = False

    _worker_check["checked_at"] = now
    _worker_check["available"] = available
    return available


def reset_worker_cache() -> None:
    """Forget the cached availability answer. For tests and for after a restart."""
    _worker_check["checked_at"] = 0.0
    _worker_check["available"] = False


def _senders() -> dict[str, tuple[Callable[..., Any], Callable[..., None]]]:
    """
    Map a mail kind to (celery task, plain sender).

    Imported lazily and per call, as before the move. The tasks come from
    auth.mail_tasks rather than core.tasks: the scan task hub pulled in the
    whole scanning stack for five tasks that only call auth.mail_service.
    """
    from ccure_platform.identity import mail_service
    from ccure_platform.identity import mail_tasks as tasks

    return {
        "verification": (
            tasks.send_verification_email_task,
            mail_service.send_verification_email,
        ),
        "password_reset": (
            tasks.send_password_reset_email_task,
            mail_service.send_password_reset_email,
        ),
        "password_changed": (
            tasks.send_password_changed_email_task,
            mail_service.send_password_changed_email,
        ),
        "account_approved": (
            tasks.send_account_approved_email_task,
            mail_service.send_account_approved_email,
        ),
        "mfa_otp": (
            tasks.send_mfa_otp_task,
            mail_service.send_mfa_otp_email,
        ),
    }


def dispatch_email(kind: str, *args: Any) -> str:
    """
    Send an application email, by whichever route will actually deliver it.

    Returns one of:
        "queued"  — handed to a worker that is confirmed to be consuming
        "eager"   — task_always_eager is on, so .delay ran it in-process
        "inline"  — no worker available, sent directly from this process
        "failed"  — every route failed; logged at ERROR with the reason

    **Never raises.** Callers are past the point of no return — the account is
    created, the token is committed, the password is already changed — so a mail
    problem must not turn a completed operation into a 500.

    That guarantee is enforced here rather than left to the care of the body
    below. It was not, initially: the availability check sat outside any handler,
    so an unexpected failure inside it propagated into the request and would have
    500'd a registration whose account had already been written.
    """
    try:
        return _dispatch(kind, *args)
    except Exception:
        log.error(
            "Mail dispatch for %r raised unexpectedly; nothing was sent",
            kind,
            exc_info=True,
        )
        return "failed"


def _dispatch(kind: str, *args: Any) -> str:
    """Route selection. See dispatch_email, which owns the no-raise guarantee."""
    try:
        task, sender = _senders()[kind]
    except KeyError:
        log.error("Unknown email kind %r — nothing sent", kind)
        return "failed"
    except Exception:
        log.error("Could not load mail senders for %r", kind, exc_info=True)
        return "failed"

    from config import AppConfig

    # Escape hatch for tests and for deployments that want the old behaviour.
    # With this off, dispatch is exactly `.delay()` and nothing is ever sent
    # from the web process.
    if not getattr(AppConfig, "MAIL_INLINE_FALLBACK", True):
        try:
            task.delay(*args)
            return "queued"
        except Exception:
            log.error("Could not queue %s email", kind, exc_info=True)
            return "failed"

    from core.celery_app import celery_app

    if celery_app.conf.task_always_eager:
        # .delay executes the task body synchronously here; adding an inline
        # send on top would deliver the same message twice.
        try:
            task.delay(*args)
            return "eager"
        except Exception:
            log.error("Eager %s email failed", kind, exc_info=True)
            return "failed"

    if _queue_has_consumer():
        try:
            task.delay(*args)
            return "queued"
        except Exception:
            # Broker went away between the check and the publish. Fall through
            # to the inline path rather than dropping the message.
            log.warning(
                "Broker refused the %s email; sending inline instead",
                kind,
                exc_info=True,
            )
    else:
        log.warning(
            "No worker is consuming the %r queue — sending the %s email inline "
            "from this process. Start the host scanner worker to restore "
            "background delivery.",
            _MAIL_QUEUE,
            kind,
        )

    try:
        sender(*args)
        log.info("Sent %s email inline (no worker available)", kind)
        return "inline"
    except Exception:
        # Both routes exhausted. ERROR, not warning: an email the product
        # promised the user has definitively not been sent.
        log.error(
            "Could not send the %s email by any route. The recipient has not "
            "been contacted.",
            kind,
            exc_info=True,
        )
        return "failed"
