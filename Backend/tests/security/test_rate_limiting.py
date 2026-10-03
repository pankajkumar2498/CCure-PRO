"""
tests/security/test_rate_limiting.py
────────────────────────────────────
Coverage for the anti-automation controls, written against the audit findings
that produced them.

Two things about how these are written:

* `conftest` sets `app.state.limiter.enabled = False` for the whole session,
  because the suite's own request volume would otherwise trip limits in tests
  that have nothing to do with rate limiting. So the tests that care about a
  *declared* per-route limit assert its registration in `Limiter._route_limits`
  rather than exercising a 429 — the same approach
  `test_upload_validation.py` uses, and for the same reason.

* The counters that are not slowapi's — the hourly ceilings in
  `core/throttle.py` — are exercised directly, because they are ordinary
  function calls rather than decorators and the whole point of the tests is
  what they do to the *response*.
"""

import hashlib
import logging
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from db.base import gen_user_id, utcnow
from db.models import Organization, PasswordResetToken, Role, User
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session


@contextmanager
def capture_logger(name, level=logging.INFO):
    """
    Collect records from one logger, without relying on global logging state.

    `caplog` attaches to the *root* logger, so what it sees depends on the root
    level, the propagate flag and whichever handlers happen to be installed when
    the test runs. All three are process-global, and any earlier test can change
    them. That is not hypothetical: the trust-boundary assertion below passed in
    isolation and on a developer machine, then failed in CI with an empty
    `caplog.text` purely because the two runs collect tests in different orders
    (`pytest-randomly` is installed locally and is absent from CI's install
    line, so "random" and "alphabetical" give it different neighbours).

    Attaching a handler straight to the logger under test removes every one of
    those dependencies. A test must not be able to fail because of what an
    unrelated test did to the root logger.
    """
    records = []

    class _Collector(logging.Handler):
        def emit(self, record):
            records.append(record)

    logger = logging.getLogger(name)
    handler = _Collector(level=level)
    previous_level = logger.level
    previous_disabled = logger.disabled
    previous_manager_disable = logging.root.manager.disable

    logger.addHandler(handler)
    logger.setLevel(level)

    # Both of these have to be cleared, and neither is reachable through
    # setLevel or through the handler.
    #
    # `Logger.isEnabledFor()` checks `self.disabled` and the module-wide
    # `manager.disable` threshold *before* it looks at levels or handlers, so
    # either one leaves this collector attached to a logger that emits nothing
    # and the assertion fails against an empty list with no clue why.
    #
    # `.disabled` is set wholesale by `logging.config.fileConfig` /
    # `dictConfig`, which default to `disable_existing_loggers=True` and switch
    # off every logger already in the process. alembic's env.py did exactly
    # that, several hundred tests before this one ran.
    logger.disabled = False
    logging.disable(logging.NOTSET)
    try:
        yield records
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous_level)
        logger.disabled = previous_disabled
        logging.disable(previous_manager_disable)


def logged_text(records):
    """Render captured records the way the handler would have formatted them."""
    return chr(10).join(r.getMessage() for r in records)


# ── Which endpoints declare a limit ──────────────────────────────────────────


def test_every_credential_endpoint_declares_a_rate_limit():
    """
    The finding this file exists for: `/auth/reset-password` carried no limit.

    It was the one unauthenticated write path in the API that could be driven
    without bound, and a comment in `test_rbac_routes.py` asserted in prose
    that it *was* limited — which is how it survived. This asserts it in code.

    The rest of the list is here so that removing any one of them fails a test
    rather than passing review.
    """
    import auth.router  # noqa: F401
    from scan_helpers import limiter

    registry = limiter._route_limits
    expected = (
        "auth.router.login",
        "auth.router.register",
        "auth.router.forgot_password",
        "auth.router.reset_password_endpoint",
        "auth.router.resend_verification",
        "auth.router.verify_email",
        "auth.router.send_email_otp",
        "auth.router.verify_mfa",
        "auth.router.check_email",
        "auth.router.check_username",
    )
    missing = [key for key in expected if not registry.get(key)]
    assert not missing, f"no @limiter.limit on: {', '.join(missing)}"


def test_login_is_protected_per_ip_and_per_account():
    """
    OWASP asks for two independent controls on login, and they answer different
    attacks: the per-IP limit stops one source hammering many accounts, the
    per-account lockout stops many sources hammering one account. Either alone
    leaves a gap you can drive credential stuffing through.

    The lockout is a column on `users`, not a limiter rule, so it is asserted
    where it lives.
    """
    import auth.router
    from scan_helpers import limiter

    assert limiter._route_limits.get("auth.router.login"), "login has no per-IP limit"

    source = __import__("inspect").getsource(auth.router.login)
    assert "failed_login_count" in source
    assert "locked_until" in source


# ── The limiter is keyed on a client the caller cannot choose ────────────────


def test_rate_limit_key_is_the_resolved_client_ip():
    """
    A rate limit is only as good as its key. If a caller can pick the bucket,
    the limit is decoration — so the key comes from `core.ip_resolver`, which
    only believes forwarding headers from a trusted proxy.
    """
    from scan_helpers import _rate_limit_key
    from starlette.requests import Request

    def make(peer, headers):
        return Request(
            {
                "type": "http",
                "headers": [(k.encode(), v.encode()) for k, v in headers.items()],
                "client": (peer, 1234),
            }
        )

    # Direct caller inventing a forwarded address: ignored.
    assert _rate_limit_key(make("203.0.113.9", {"x-forwarded-for": "8.8.8.8"})) == (
        "203.0.113.9"
    )

    # Two clients behind the real proxy get two different buckets. Host nginx
    # arrives as the compose network's gateway, 172.18.0.1 (Phase 10.3, F10-1:
    # a container such as 172.18.0.5 is a caller, not a proxy).
    proxied_a = _rate_limit_key(make("172.18.0.1", {"x-forwarded-for": "10.180.6.11"}))
    proxied_b = _rate_limit_key(make("172.18.0.1", {"x-forwarded-for": "10.180.6.12"}))
    assert proxied_a != proxied_b


# ── Password recovery: anti-automation ───────────────────────────────────────


@pytest.fixture
def reset_user(db_session: Session) -> User:
    org = Organization(
        name="Reset Org", slug="reset-org", max_assets=10, max_users=10, is_active=True
    )
    db_session.add(org)
    db_session.flush()

    role = db_session.query(Role).filter_by(name="analyst").first()
    user = User(
        id=gen_user_id(org.slug, "resetuser"),
        username="resetuser",
        email="resetuser@test.com",
        password_hash="oldhash",
        org_id=org.id,
        role_id=role.id,
        is_active=True,
        is_verified=True,
        approved_at=utcnow(),
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


def _issue_token(db_session: Session, user: User, minutes: int = 15) -> str:
    """Mint a reset token the way /auth/forgot-password does."""
    import secrets

    token = secrets.token_urlsafe(32)
    db_session.add(
        PasswordResetToken(
            user_id=user.id,
            token_hash=hashlib.sha256(token.encode("utf-8")).hexdigest(),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=minutes),
        )
    )
    db_session.commit()
    return token


def test_completing_a_reset_retires_every_outstanding_token(
    client: TestClient, db_session: Session, reset_user: User
):
    """
    Single-use was enforced for the token presented and for nothing else.

    A user who clicked "forgot password" three times held three live links. One
    was consumed; the other two stayed valid for the rest of their fifteen
    minutes — against a password that had already been changed. A link sitting
    in a mailbox or a proxy log must stop working at the moment the account
    owner completes a reset, which is exactly when it is most dangerous.
    """
    stale_one = _issue_token(db_session, reset_user)
    stale_two = _issue_token(db_session, reset_user)
    fresh = _issue_token(db_session, reset_user)

    assert (
        db_session.query(PasswordResetToken)
        .filter(PasswordResetToken.user_id == reset_user.id)
        .count()
        == 3
    )

    response = client.post(
        "/auth/reset-password", json={"token": fresh, "password": "NewPassw0rd!x"}
    )
    assert response.status_code == 200

    assert (
        db_session.query(PasswordResetToken)
        .filter(PasswordResetToken.user_id == reset_user.id)
        .count()
        == 0
    )

    for leftover in (stale_one, stale_two):
        again = client.post(
            "/auth/reset-password",
            json={"token": leftover, "password": "AnotherPass1!"},
        )
        assert again.status_code == 400


def test_requesting_a_new_link_invalidates_the_previous_one(
    client: TestClient, db_session: Session, reset_user: User
):
    """
    Each request used to add a token and leave the earlier ones redeemable, so
    asking three times produced three working links from three separate emails.
    The newest is the one the user is looking at.
    """
    old = _issue_token(db_session, reset_user)

    with patch("core.tasks.send_password_reset_email_task.delay"):
        response = client.post(
            "/auth/forgot-password", json={"email": "resetuser@test.com"}
        )
    assert response.status_code == 200

    rows = (
        db_session.query(PasswordResetToken)
        .filter(PasswordResetToken.user_id == reset_user.id)
        .all()
    )
    assert len(rows) == 1

    old_hash = hashlib.sha256(old.encode("utf-8")).hexdigest()
    assert rows[0].token_hash != old_hash


def test_bad_token_answers_uniformly_whatever_is_wrong_with_it(
    client: TestClient, db_session: Session, reset_user: User
):
    """
    Unknown, expired, and belonging-to-a-deleted-user must be indistinguishable.

    The third used to answer "User not found." — a different message on a
    different branch, which tells a caller holding a token something the other
    two do not.
    """
    expired = _issue_token(db_session, reset_user, minutes=-5)

    orphan = _issue_token(db_session, reset_user)
    # the account's RBAC assignments go with it (ON DELETE RESTRICT otherwise)
    from sqlalchemy import text

    db_session.execute(
        text("DELETE FROM rbac_user_roles WHERE user_id = :u"), {"u": reset_user.id}
    )
    db_session.query(User).filter(User.id == reset_user.id).delete()
    db_session.commit()

    bodies = set()
    for token in ("this-token-does-not-exist", expired, orphan):
        response = client.post(
            "/auth/reset-password", json={"token": token, "password": "NewPassw0rd!x"}
        )
        assert response.status_code == 400
        bodies.add(response.json().get("message") or response.json().get("detail"))

    assert len(bodies) == 1, f"reset failures are distinguishable: {bodies}"


def test_reset_submission_flood_is_refused_by_the_hourly_ceiling(
    client: TestClient, db_session: Session
):
    """
    The per-minute limiter stops a burst; this stops a patient script. Counts
    failures only, so legitimate users behind a shared NAT address are never
    pushed over it by their neighbours.
    """
    with patch("core.throttle.hit", return_value=True) as ceiling:
        response = client.post(
            "/auth/reset-password",
            json={"token": "wrong", "password": "NewPassw0rd!x"},
        )

    assert response.status_code == 429
    assert ceiling.called


def test_reset_ceiling_only_counts_failures(
    client: TestClient, db_session: Session, reset_user: User
):
    """A successful reset must not consume the failure budget."""
    token = _issue_token(db_session, reset_user)

    with patch("core.throttle.hit") as ceiling:
        response = client.post(
            "/auth/reset-password", json={"token": token, "password": "NewPassw0rd!x"}
        )

    assert response.status_code == 200
    ceiling.assert_not_called()


def test_mail_bomb_ceiling_does_not_become_an_account_oracle(
    client: TestClient, db_session: Session, reset_user: User
):
    """
    The per-account ceiling on /auth/forgot-password exists because the per-IP
    limit does nothing about a caller who rotates addresses, and the mail is
    sent to an address the caller names.

    It must not answer 429. Only a real account can exceed a per-account
    ceiling, so a distinct status code there would disclose exactly what the
    uniform 200 exists to hide. The request falls through to the same response
    having sent nothing.
    """
    unknown = client.post(
        "/auth/forgot-password", json={"email": "nobody-here@test.com"}
    )

    with patch("core.throttle.hit", return_value=True):
        with patch("core.tasks.send_password_reset_email_task.delay") as mail:
            throttled = client.post(
                "/auth/forgot-password", json={"email": "resetuser@test.com"}
            )

    assert throttled.status_code == unknown.status_code == 200
    assert throttled.json() == unknown.json()
    mail.assert_not_called()

    # ...and nothing was minted, so the ceiling really did stop the work.
    assert (
        db_session.query(PasswordResetToken)
        .filter(PasswordResetToken.user_id == reset_user.id)
        .count()
        == 0
    )


# ── The shared throttle primitive ────────────────────────────────────────────


def test_throttle_fails_open_by_default_and_closed_on_request():
    """
    Direction is a per-caller decision and both directions must work.

    Open is right for the recovery ceilings: they sit on top of controls that
    actually hold, and refusing every password reset in the estate because
    Redis is unwell is the worse outage. A caller that needs the opposite trade
    has to be able to ask for it.
    """
    from core.throttle import hit

    with patch("core.redis_client.get_redis_client", side_effect=RuntimeError("down")):
        assert hit("probe", "1.2.3.4", limit=1, window_seconds=60) is False
        assert (
            hit("probe", "1.2.3.4", limit=1, window_seconds=60, fail_open=False) is True
        )


def test_throttle_ignores_a_missing_identity():
    """
    An empty key would put every unidentifiable caller in one bucket, and the
    first of them would lock out the rest.
    """
    from core.throttle import hit

    assert hit("probe", "", limit=1, window_seconds=60) is False


# ── The baseline ceiling for everything else ─────────────────────────────────


def test_baseline_middleware_is_installed_inside_cors():
    """
    Order is load-bearing twice over. A browser cannot read a response without
    CORS headers, so a 429 emitted outside CORSMiddleware surfaces in the SPA
    as a network error rather than "slow down"; and the request-ID middleware
    further out is what stamps X-Request-ID and the security headers onto it.

    Starlette applies `user_middleware` outermost-first, so the baseline must
    appear *after* CORS in that list.
    """
    from core.rate_limit_middleware import BaselineRateLimitMiddleware
    from fastapi.middleware.cors import CORSMiddleware
    from main import app

    classes = [m.cls for m in app.user_middleware]
    assert BaselineRateLimitMiddleware in classes, "baseline middleware not installed"
    assert CORSMiddleware in classes
    assert classes.index(CORSMiddleware) < classes.index(BaselineRateLimitMiddleware)


def test_baseline_counts_and_then_refuses():
    """The ceiling has to actually refuse, not merely be installed."""
    from core.rate_limit_middleware import BaselineRateLimitMiddleware

    mw = BaselineRateLimitMiddleware(
        app=None, limit="3/minute", storage_uri="memory://"
    )
    verdicts = [mw._within_limit("unit-test-key") for _ in range(5)]
    assert verdicts == [True, True, True, False, False]


def test_baseline_degrades_to_local_counting_when_the_store_is_gone():
    """
    A rate limit that disappears when its backing store does is a rate limit an
    attacker can remove by disrupting the store. The fallback is weaker — its
    window is per worker process — but it is never absent.
    """
    from core.rate_limit_middleware import BaselineRateLimitMiddleware

    mw = BaselineRateLimitMiddleware(
        app=None, limit="2/minute", storage_uri="memory://"
    )

    with patch.object(mw._strategy, "hit", side_effect=RuntimeError("redis is gone")):
        verdicts = [mw._within_limit("outage-key") for _ in range(4)]

    assert verdicts == [True, True, False, False]


def test_baseline_never_raises_out_of_the_request_path():
    """Failing to *count* a request must not become failing to *serve* it."""
    from core.rate_limit_middleware import BaselineRateLimitMiddleware

    mw = BaselineRateLimitMiddleware(
        app=None, limit="1/minute", storage_uri="memory://"
    )
    with patch.object(mw._strategy, "hit", side_effect=RuntimeError("boom")):
        with patch.object(
            mw._fallback_strategy, "hit", side_effect=RuntimeError("also boom")
        ):
            assert mw._within_limit("both-dead") is True


def test_a_malformed_limit_disables_the_baseline_rather_than_the_application():
    """Bad configuration must not stop the API booting."""
    from core.rate_limit_middleware import BaselineRateLimitMiddleware

    mw = BaselineRateLimitMiddleware(
        app=None, limit="not-a-limit", storage_uri="memory://"
    )
    assert mw._item is None


def test_exemptions_are_exact_unless_marked_as_a_prefix():
    """
    The health endpoint on this API is "/", and the first version of the
    exemption list was prefix-matched. A prefix match on "/" exempts the entire
    application — a rate limit that is installed, configured, logged at startup,
    and covers nothing.

    That list also named /health, /healthz and /metrics, none of which exist
    here, so the exemption everyone would have relied on was not even in effect.
    """
    from core.rate_limit_middleware import BaselineRateLimitMiddleware

    mw = BaselineRateLimitMiddleware(
        app=None,
        limit="10/minute",
        storage_uri="memory://",
        exempt_paths=["/", "/docs*", "/openapi.json"],
    )

    assert "/" in mw._exempt_exact
    assert "/docs" in mw._exempt_prefix

    def exempt(path: str) -> bool:
        return path in mw._exempt_exact or path.startswith(mw._exempt_prefix)

    assert exempt("/")
    assert exempt("/openapi.json")
    assert exempt("/docs")
    assert exempt("/docs/oauth2-redirect")

    # The whole point: "/" must not carry the rest of the API with it.
    assert not exempt("/auth/login")
    assert not exempt("/scan/host-discovery")
    assert not exempt("/compliance/scans")


def test_the_configured_exemptions_name_paths_that_exist():
    """
    An exemption for a path no route serves is a comment, not a control.

    This is what caught the first version of the list, which named /health,
    /healthz and /metrics — none of which exist on this API. The health
    endpoint is "/".

    Only exact entries are checked. The interactive documentation routes are
    registered conditionally (`docs_url=None` when ENV=production, which is how
    this suite runs), so a prefix pointing at them is legitimately unmatched
    here and asserting otherwise would fail for the wrong reason.
    """
    from config import AppConfig
    from main import app

    served = {getattr(r, "path", "") for r in app.routes}
    optional_docs = ("/docs", "/redoc", "/openapi.json")

    for entry in AppConfig.API_RATE_LIMIT_EXEMPT_PATHS:
        if entry.endswith("*") or entry in optional_docs:
            continue
        assert entry in served, f"exempt path {entry!r} is not served by any route"


def test_slowapi_limiter_has_an_in_memory_fallback():
    """
    Before this, a Redis outage did not relax the limits — it broke every
    limited endpoint. slowapi is built with swallow_errors=False, so the
    storage error propagated straight out of the decorator and login,
    registration and every scan endpoint answered 500.
    """
    from scan_helpers import limiter

    assert limiter._in_memory_fallback_enabled
    assert limiter._in_memory_fallback


# ── The 429 itself: can a client act on it, and can an operator see it? ──────


def test_rate_limit_response_carries_retry_after():
    """
    Without Retry-After a refused client has no idea whether to come back in a
    second or an hour, so a well-behaved one busy-waits and becomes
    indistinguishable from the badly-behaved one the limit is aimed at.

    The value is read from the breached limit rather than hardcoded: a wrong
    Retry-After is worse than none, because clients act on it.
    """
    from slowapi.errors import RateLimitExceeded
    from limits import parse
    from slowapi.wrappers import Limit
    from main import _make_rate_limit_response

    item = parse("10/minute")
    exc = RateLimitExceeded(
        Limit(item, lambda: "k", None, False, None, None, None, 1, False)
    )

    class _Req:
        state = type("S", (), {"request_id": "req-1"})()
        headers = {}
        method = "POST"
        url = type("U", (), {"path": "/auth/login"})()
        client = None

    response = _make_rate_limit_response(_Req(), exc)
    assert response.status_code == 429
    assert response.headers["Retry-After"] == "60"

    import json

    body = json.loads(bytes(response.body))
    assert body["error_code"] == "RATE_LIMIT_EXCEEDED"
    assert body["retry_after_seconds"] == 60
    assert body["request_id"] == "req-1"


def test_rejections_are_logged_without_leaking_credentials():
    """
    A rate limit that refuses silently is a technical control; one that records
    what it refused is a security signal — it is what turns "some requests were
    dropped" into "one address made 1,000 login attempts in four minutes".

    What must never appear: the password, the token, or the Authorization
    header. The *attempted* account is also deliberately absent — writing it
    here would rebuild, in the log file, exactly the account-existence oracle
    that /auth/forgot-password refuses to create in its response.
    """
    import logging

    from core.rate_limit_audit import record_rejection

    class _Req:
        state = type("S", (), {"request_id": "req-9"})()
        headers = {"authorization": "Bearer sekrit-token-value"}
        method = "POST"
        url = type("U", (), {"path": "/auth/login"})()
        client = type("C", (), {"host": "198.51.100.4"})()

    with capture_logger("ccure.security.ratelimit", logging.WARNING) as records:
        record_rejection(
            _Req(), layer="endpoint", limit="10 per 1 minute", retry_after=60
        )

    text = logged_text(records)
    assert "RATE_LIMIT_REJECTED" in text
    assert "/auth/login" in text
    assert "198.51.100.4" in text
    assert "sekrit-token-value" not in text
    assert "Bearer" not in text


def test_rejections_are_attributed_through_the_decoder_main_registers():
    """
    Phase 3 moved token decoding out of core/rate_limit_audit.py: the module
    is infrastructure and must not import auth, so main.py registers
    auth.jwt_handler.decode_token at start-up. If that wiring were lost, 429
    records would silently stop naming the caller — this pins it.
    """
    import core.rate_limit_audit as audit
    import main  # noqa: F401  (the composition root does the registration)
    from auth.jwt_handler import decode_token

    assert audit._token_decoder is decode_token

    class _Req:
        headers = {"authorization": "Bearer not-a-real-token"}

    # An invalid token is still unattributed, as before.
    assert audit._caller_identity(_Req()) == (None, None)


def test_degradation_is_announced_once_per_transition():
    """
    The fallback path is invisible by design — when the shared store goes away
    the limiter keeps answering, so nothing in any response tells an operator
    that counters are now per-worker and the effective ceiling has been
    multiplied by the worker count.

    Logged on transition only: a long outage must produce two lines, not one
    per request, or the alert drowns in its own noise.
    """
    from core.rate_limit_audit import report_degradation, reset_degradation_state

    reset_degradation_state()
    with capture_logger("ccure.security.ratelimit", logging.WARNING) as records:
        report_degradation("unit", True)
        report_degradation("unit", True)
        report_degradation("unit", True)
        report_degradation("unit", False)

    text = logged_text(records)
    assert text.count("RATE_LIMIT_DEGRADED") == 1
    assert text.count("RATE_LIMIT_RECOVERED") == 1
    reset_degradation_state()


def test_the_trust_boundary_is_reported_at_startup():
    """
    An auditor asking "which hops may declare a client address here?" should
    get the answer from the running system, not from a config file that may not
    be the one in force.

    Called from the lifespan rather than at import: main.py imports every
    router before logging.basicConfig, so an import-time warning had no handler
    to reach and was effectively invisible.
    """
    from core.ip_resolver import log_trust_boundary

    with capture_logger("core.ip_resolver", logging.INFO) as records:
        too_wide = log_trust_boundary()

    assert "trusts" in logged_text(records)
    assert not too_wide, f"a trusted range is wide enough to hold users: {too_wide}"
