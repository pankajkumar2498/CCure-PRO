"""
tests/auth/test_mail_dispatch.py
─────────────────────────────────────────────────────────────────────────────
Mail delivery must not be able to silently do nothing.

The defect: CELERY_TASK_ALWAYS_EAGER is False in this deployment, so the API
published mail tasks to Redis and the host worker delivered them. `.delay()`
succeeds whenever Redis is reachable — it says nothing about whether anything
will consume the message. With the host worker stopped, registration returned
202, created the account, committed the verification token, and never sent the
email. Invisible on both sides: the admin saw a pending account, the user saw
silence.
"""

from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture(autouse=True)
def _fresh_worker_cache():
    """The availability answer is cached for 30s; don't leak it between tests."""
    from auth.mail_dispatch import reset_worker_cache

    reset_worker_cache()
    yield
    reset_worker_cache()


@pytest.fixture
def real_routing(monkeypatch):
    """
    Force dispatch_email down its real routing path.

    Two settings have to be pinned here, and neither may be inherited from the
    environment — otherwise these tests assert different things on a developer
    machine than they do in CI, which is exactly how they passed locally and
    failed in the pipeline.

    task_always_eager off
        conftest does `os.environ.setdefault("CELERY_TASK_ALWAYS_EAGER", "true")`.
        A docker-compose developer machine already exports it as False, so the
        setdefault does nothing and eager stays off; CI exports nothing, so the
        setdefault turns it *on*. In eager mode dispatch_email short-circuits —
        `.delay()` already runs the task in-process, so adding an inline send
        would deliver twice — and returns "eager" without ever reaching the
        queued/inline decision these tests exist to check. Every assertion here
        then read `assert 'eager' == 'inline'`.

    MAIL_INLINE_FALLBACK on
        conftest disables it suite-wide so dispatch stays assertable via
        `.delay`. These tests are specifically about the fallback.
    """
    from config import AppConfig
    from core.celery_app import celery_app

    monkeypatch.setattr(AppConfig, "MAIL_INLINE_FALLBACK", True)
    monkeypatch.setattr(celery_app.conf, "task_always_eager", False)


# ── The defect: no consumer on the queue ─────────────────────────────────────


def test_sends_inline_when_no_worker_is_consuming(real_routing):
    """
    This is the regression test for the whole module. No worker → the message
    must still go out, from this process.
    """
    from auth import mail_dispatch

    with patch.object(mail_dispatch, "_queue_has_consumer", return_value=False):
        with patch("auth.mail_service.send_verification_email") as sender:
            with patch("core.tasks.send_verification_email_task.delay") as delay:
                result = mail_dispatch.dispatch_email(
                    "verification", "a@b.test", "someone", "https://x/verify?token=t"
                )

    assert result == "inline"
    sender.assert_called_once_with("a@b.test", "someone", "https://x/verify?token=t")
    delay.assert_not_called(), "must not queue to a queue nobody is reading"


def test_queues_when_a_worker_is_consuming(real_routing):
    """With a worker present, use it — inline sending is the fallback, not the norm."""
    from auth import mail_dispatch

    with patch.object(mail_dispatch, "_queue_has_consumer", return_value=True):
        with patch("auth.mail_service.send_verification_email") as sender:
            with patch("core.tasks.send_verification_email_task.delay") as delay:
                result = mail_dispatch.dispatch_email(
                    "verification", "a@b.test", "someone", "https://x/verify?token=t"
                )

    assert result == "queued"
    delay.assert_called_once()
    sender.assert_not_called(), "must not also send inline — that is two emails"


def test_falls_back_inline_when_the_broker_refuses(real_routing):
    """
    The check and the publish are not atomic. If Redis dies in between, the
    message must not be lost.
    """
    from auth import mail_dispatch

    with patch.object(mail_dispatch, "_queue_has_consumer", return_value=True):
        with patch("auth.mail_service.send_verification_email") as sender:
            with patch(
                "core.tasks.send_verification_email_task.delay",
                side_effect=OSError("connection refused"),
            ):
                result = mail_dispatch.dispatch_email(
                    "verification", "a@b.test", "someone", "https://x/verify?token=t"
                )

    assert result == "inline"
    sender.assert_called_once()


def test_reports_failure_when_both_routes_fail(real_routing):
    """
    Never raises — the caller has already committed — but must report "failed"
    rather than a success it cannot support.
    """
    from auth import mail_dispatch

    with patch.object(mail_dispatch, "_queue_has_consumer", return_value=False):
        with patch(
            "auth.mail_service.send_verification_email",
            side_effect=RuntimeError("smtp down"),
        ):
            result = mail_dispatch.dispatch_email(
                "verification", "a@b.test", "someone", "https://x/verify?token=t"
            )

    assert result == "failed"


def test_never_raises_into_the_caller(real_routing):
    """
    Registration and password reset are past the point of no return when they
    dispatch. A mail problem must not convert a completed write into a 500.
    """
    from auth import mail_dispatch

    with patch.object(
        mail_dispatch, "_queue_has_consumer", side_effect=RuntimeError("boom")
    ):
        result = mail_dispatch.dispatch_email("verification", "a@b.test", "x", "y")
    assert result == "failed"


def test_eager_mode_sends_once_and_reports_eager(monkeypatch):
    """
    The branch CI actually runs by default, and which nothing covered.

    With task_always_eager on, `.delay()` executes the task in this process.
    dispatch_email must therefore NOT also send inline — that would deliver the
    same message twice — and must report "eager" so a caller can tell the two
    routes apart.

    This is the case the routing tests above deliberately opt out of, so it
    needs asserting somewhere or the short-circuit is untested.
    """
    from config import AppConfig
    from auth import mail_dispatch
    from core.celery_app import celery_app

    monkeypatch.setattr(AppConfig, "MAIL_INLINE_FALLBACK", True)
    monkeypatch.setattr(celery_app.conf, "task_always_eager", True)

    with patch("auth.mail_service.send_verification_email") as sender:
        with patch("core.tasks.send_verification_email_task.delay") as delay:
            result = mail_dispatch.dispatch_email(
                "verification", "a@b.test", "someone", "https://x/verify?token=t"
            )

    assert result == "eager"
    delay.assert_called_once()
    sender.assert_not_called(), "eager already ran the task; a second send is a duplicate"


def test_eager_mode_does_not_consult_the_broker(monkeypatch):
    """
    A broadcast ping costs a round trip and answers a question that cannot
    matter: in eager mode the task runs here regardless of who is consuming.
    """
    from config import AppConfig
    from auth import mail_dispatch
    from core.celery_app import celery_app

    monkeypatch.setattr(AppConfig, "MAIL_INLINE_FALLBACK", True)
    monkeypatch.setattr(celery_app.conf, "task_always_eager", True)

    with patch.object(mail_dispatch, "_queue_has_consumer") as check:
        with patch("core.tasks.send_verification_email_task.delay"):
            mail_dispatch.dispatch_email("verification", "a@b.test", "x", "y")
    check.assert_not_called()


def test_unknown_kind_is_reported_not_raised(real_routing):
    from auth.mail_dispatch import dispatch_email

    assert dispatch_email("no_such_kind", "a@b.test") == "failed"


# ── Availability detection ───────────────────────────────────────────────────


def test_consumer_check_requires_the_mail_queue_specifically():
    """
    A worker answering the ping is not enough — it has to be consuming the queue
    the mail tasks are routed to. The web-scanning worker consumes web_* queues
    and would otherwise be mistaken for a mail consumer.
    """
    from auth import mail_dispatch

    inspect = MagicMock()
    inspect.return_value.active_queues.return_value = {
        "celery@web": [{"name": "web_recon"}, {"name": "web_dast"}]
    }
    with patch("core.celery_app.celery_app.control.inspect", inspect):
        assert mail_dispatch._queue_has_consumer() is False

    mail_dispatch.reset_worker_cache()
    inspect.return_value.active_queues.return_value = {
        "host-scanner@box": [{"name": "scanner"}, {"name": "default"}]
    }
    with patch("core.celery_app.celery_app.control.inspect", inspect):
        assert mail_dispatch._queue_has_consumer() is True


def test_unreachable_broker_is_treated_as_no_consumer():
    """
    Fail towards sending. Guessing "a worker is probably there" would
    reintroduce exactly the silent loss this exists to prevent.
    """
    from auth import mail_dispatch

    with patch(
        "core.celery_app.celery_app.control.inspect",
        side_effect=OSError("no redis"),
    ):
        assert mail_dispatch._queue_has_consumer() is False


def test_availability_answer_is_cached():
    """A broadcast ping per registration would be an absurd cost."""
    from auth import mail_dispatch

    inspect = MagicMock()
    inspect.return_value.active_queues.return_value = {
        "host-scanner@box": [{"name": "default"}]
    }
    with patch("core.celery_app.celery_app.control.inspect", inspect):
        assert mail_dispatch._queue_has_consumer() is True
        assert mail_dispatch._queue_has_consumer() is True
        assert mail_dispatch._queue_has_consumer() is True
    assert inspect.call_count == 1


# ── Retry configuration on the tasks themselves ──────────────────────────────


@pytest.mark.parametrize(
    "task_name",
    [
        "send_verification_email_task",
        "send_password_reset_email_task",
        "send_password_changed_email_task",
        "send_account_approved_email_task",
        "send_mfa_otp_task",
    ],
)
def test_mail_tasks_retry_instead_of_swallowing(task_name):
    """
    Each of these used to catch Exception and log it, which told Celery the task
    had succeeded — so a momentary SMTP failure destroyed the message with no
    retry. Autoretry must be configured, or that returns.
    """
    from core import tasks

    task = getattr(tasks, task_name)
    assert (
        task.max_retries and task.max_retries >= 2
    ), f"{task_name} must retry; swallowing the exception loses the message"
    assert Exception in (
        task.autoretry_for or ()
    ), f"{task_name} must autoretry on failure"


def test_mail_task_failure_is_reported_permanently():
    """
    After the retries are exhausted the message really is gone; that has to be
    findable in the log, with the recipient.
    """
    from core import tasks

    task = tasks.send_verification_email_task
    with patch.object(tasks.log, "error") as log_error:
        task.on_failure(
            RuntimeError("smtp down"), "task-id", ("a@b.test", "u", "link"), {}, None
        )
    assert log_error.called
    message = " ".join(str(a) for a in log_error.call_args[0])
    assert "UNDELIVERED" in message
