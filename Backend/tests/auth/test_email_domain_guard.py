"""
tests/test_email_domain_guard.py
──────────────────────────────────────────────────────────────────────────────
Regression tests for disposable / throwaway email screening.

The named domains are not invented. `hutdot.com` and `radiant-flow.org` are the
two addresses that actually reached this deployment's approval queue on
18 Aug 2026, and they are here because they fail in opposite directions:

  * `hutdot.com` is on two of three maintained blocklists → must be refused.
  * `radiant-flow.org` is on none of them, has valid MX, Cloudflare nameservers
    and a 17-month-old registration → must be **accepted**.

A test suite that only asserted the first would pass happily on a guard that
refuses every unfamiliar domain, which is the failure mode that costs real
customers. Both directions are load-bearing.
"""

import pytest
from auth.email_domain_guard import (
    MODE_ENFORCE,
    MODE_FLAG,
    MODE_OFF,
    domain_candidates,
    evaluate_email,
    extract_domain,
    invalidate_cache,
)
from auth.email_utils import canonicalize_email
from auth.jwt_handler import hash_password
from db.models.email_security import VERDICT_ALLOW, VERDICT_DENY, EmailDomainRule
from db.models.users import User
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session


@pytest.fixture
def enforcing(monkeypatch):
    """Put the guard in enforce mode for one test."""
    from config import AppConfig

    monkeypatch.setattr(AppConfig, "EMAIL_DOMAIN_GUARD_MODE", MODE_ENFORCE)
    invalidate_cache()
    yield
    invalidate_cache()


def _register(client: TestClient, email: str, username: str = "newuser"):
    return client.post(
        "/auth/register",
        json={
            "full_name": "New User",
            "username": username,
            "email": email,
            "password": "StrongP@ssw0rd!",
        },
    )


# ── Domain parsing ───────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "email,expected",
    [
        ("user@Example.COM", "example.com"),
        ("user@mail.example.co.uk", "mail.example.co.uk"),
        ("user@example.com.", "example.com"),
        ("no-at-sign", ""),
        ("user@", ""),
        ("user@localhost", ""),
        ("a@b@c.com", ""),
    ],
)
def test_extract_domain(email, expected):
    assert extract_domain(email) == expected


def test_domain_candidates_walk_parents_but_never_a_public_suffix():
    """
    A disposable service hands out `@bob.mailinator.com`, not `@mailinator.com`.

    Exact-string matching is defeated by one extra label, so the guard tests
    every parent — but it must stop before `co.uk`, or a corpus entry for a
    public suffix would blocklist an entire country.
    """
    assert domain_candidates("bob.mailinator.com") == [
        "bob.mailinator.com",
        "mailinator.com",
    ]
    assert domain_candidates("mail.example.co.uk") == [
        "mail.example.co.uk",
        "example.co.uk",
    ]
    assert "co.uk" not in domain_candidates("mail.example.co.uk")


# ── Canonicalization ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("P.Kumar+ops@Gmail.com", "pkumar@gmail.com"),
        ("pkumar@gmail.com", "pkumar@gmail.com"),
        ("p.k.u.m.a.r@googlemail.com", "pkumar@gmail.com"),
        ("a.b+tag@yahoo.com", "a.b@yahoo.com"),
        ("user-tag@yandex.com", "user@yandex.com"),
    ],
)
def test_canonicalize_folds_documented_provider_behaviour(raw, expected):
    assert canonicalize_email(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "sales+web@acme.com",
        "first.last@acme.com",
        "first.last@outlook.com",
    ],
)
def test_canonicalize_leaves_other_domains_alone(raw):
    """
    The restraint matters more than the folding.

    Most corporate mail systems do not implement subaddressing, and none of them
    ignore dots. Folding `sales+web@acme.com` into `sales@acme.com` would make
    one company's second signup collide with an unrelated colleague's, and the
    user has no way to work around a false "already registered".
    """
    assert canonicalize_email(raw) == raw.lower()


# ── Verdicts ─────────────────────────────────────────────────────────────────


def test_known_disposable_domain_is_blocked(db_session: Session, enforcing):
    verdict = evaluate_email(db_session, "safan76549@hutdot.com")
    assert verdict.blocked is True
    assert verdict.reason == "disposable"
    assert verdict.matched_domain == "hutdot.com"


def test_subdomain_of_disposable_service_is_blocked(db_session: Session, enforcing):
    verdict = evaluate_email(db_session, "someone@inbox.mailinator.com")
    assert verdict.blocked is True
    assert verdict.matched_domain == "mailinator.com"


def test_unknown_custom_domain_is_accepted(db_session: Session, enforcing):
    """
    The most important test here.

    `radiant-flow.org` is a real throwaway domain that appears on none of the
    93,000 merged blocklist entries. It must still be accepted: everything that
    distinguishes it from a small legitimate company needs a human, and a guard
    that refuses unfamiliar domains turns away real customers to catch this one.
    It is surfaced to the approval queue instead.
    """
    verdict = evaluate_email(db_session, "elliot.avalos.654@radiant-flow.org")
    assert verdict.blocked is False
    assert verdict.reason == "ok"


def test_major_provider_is_allowlisted(db_session: Session, enforcing):
    verdict = evaluate_email(db_session, "someone@gmail.com")
    assert verdict.blocked is False
    assert verdict.reason == "allowlisted"


def test_allow_rule_beats_the_blocklist_corpus(db_session: Session, enforcing):
    """
    `test.com` is genuinely on a published disposable blocklist *and* is used by
    106 registrations in this suite. The ALLOW override is the only thing that
    reconciles those two facts — and it is the same mechanism a deployment uses
    when an upstream list wrongly lists a customer.
    """
    verdict = evaluate_email(db_session, "admin@test.com")
    assert verdict.blocked is False
    assert verdict.reason == "allowlisted"


def test_explicit_deny_rule_blocks(db_session: Session, enforcing):
    # Created if absent rather than inserted unconditionally: the pytest
    # database persists between runs and `email_domain_rules` is reference data
    # that _purge_test_data deliberately leaves alone, so a bare INSERT passes
    # once and then fails on the unique constraint forever after.
    rule = (
        db_session.query(EmailDomainRule)
        .filter(EmailDomainRule.domain == "banned-partner.com")
        .first()
    )
    if rule is None:
        rule = EmailDomainRule(
            domain="banned-partner.com", verdict=VERDICT_DENY, source="admin"
        )
        db_session.add(rule)
    else:
        rule.verdict = VERDICT_DENY
    db_session.commit()
    invalidate_cache()

    verdict = evaluate_email(db_session, "someone@banned-partner.com")
    assert verdict.blocked is True
    assert verdict.reason == "denylisted"


def test_suspicious_name_flags_but_never_blocks(db_session: Session, enforcing):
    """A name that reads like a throwaway service is a hint, not a verdict."""
    verdict = evaluate_email(db_session, "someone@tempmail-services-ltd.com")
    assert verdict.blocked is False
    assert "suspicious_name" in verdict.flags


def test_guard_off_evaluates_nothing(db_session: Session, monkeypatch):
    from config import AppConfig

    monkeypatch.setattr(AppConfig, "EMAIL_DOMAIN_GUARD_MODE", MODE_OFF)
    invalidate_cache()
    verdict = evaluate_email(db_session, "safan76549@hutdot.com")
    assert verdict.blocked is False
    invalidate_cache()


# ── Fail-open ────────────────────────────────────────────────────────────────


def test_empty_corpus_fails_open(db_session: Session, enforcing, monkeypatch):
    """
    A blocklist that failed to load must not stop anyone registering.

    Refusing every signup because a data file was missing is a worse outage than
    the abuse it prevents, and it is the kind that arrives at 3am attached to a
    deploy nobody associates with email.
    """
    from auth import email_domain_guard

    monkeypatch.setattr(
        email_domain_guard._cache, "_disposable", frozenset(), raising=False
    )
    monkeypatch.setattr(email_domain_guard._cache, "_allow", frozenset(), raising=False)
    monkeypatch.setattr(email_domain_guard._cache, "_deny", frozenset(), raising=False)
    monkeypatch.setattr(email_domain_guard._cache, "_loaded_at", 9e18, raising=False)

    verdict = evaluate_email(db_session, "safan76549@hutdot.com")
    assert verdict.blocked is False

    invalidate_cache()


# ── Registration ─────────────────────────────────────────────────────────────


def test_register_refuses_disposable_domain(
    client: TestClient, self_registration_enabled, enforcing
):
    response = _register(client, "safan76549@hutdot.com", "tempuser")
    assert response.status_code == 400
    assert "disposable" in response.json()["detail"].lower()


def test_register_accepts_unknown_custom_domain(
    client: TestClient, db_session: Session, self_registration_enabled, enforcing
):
    response = _register(client, "elliot@radiant-flow.org", "customuser")
    assert response.status_code == 202
    assert response.json()["status"] == "pending_verification"

    user = db_session.query(User).filter(User.username == "customuser").first()
    assert user is not None
    assert user.approved_at is None


def test_register_in_flag_mode_records_but_does_not_refuse(
    client: TestClient, db_session: Session, self_registration_enabled, monkeypatch
):
    """
    Flag mode is what makes a staged rollout possible: run for a week, read the
    log, then enforce with evidence instead of hope.
    """
    from config import AppConfig

    monkeypatch.setattr(AppConfig, "EMAIL_DOMAIN_GUARD_MODE", MODE_FLAG)
    invalidate_cache()

    response = _register(client, "someone@hutdot.com", "flaggeduser")
    assert response.status_code == 202

    user = db_session.query(User).filter(User.username == "flaggeduser").first()
    assert user is not None
    assert user.is_email_flagged is True
    assert user.email_risk["reason"] == "disposable"

    invalidate_cache()


def test_register_treats_a_gmail_alias_as_the_same_mailbox(
    client: TestClient, db_session: Session, self_registration_enabled, enforcing
):
    """
    One Gmail mailbox must not yield unlimited accounts. The second attempt gets
    the ordinary uniform 202 — a collision is still not disclosed.
    """
    first = _register(client, "p.kumar@gmail.com", "pkumarone")
    assert first.status_code == 202

    second = _register(client, "pkumar+ccure@gmail.com", "pkumartwo")
    assert second.status_code == 202

    assert db_session.query(User).filter(User.username == "pkumartwo").first() is None


# ── Endpoints that must NOT screen ───────────────────────────────────────────


@pytest.fixture
def test_com_denied(db_session: Session):
    """
    Flip the suite's own `test.com` rule to DENY for one test, then restore it.

    Flipped rather than inserted: `domain` is unique and the fixture already
    seeded an ALLOW row, so a second INSERT raises IntegrityError. Restoring in
    a finally-equivalent teardown matters more than usual here — leaving
    `test.com` denied would poison every later test in the session.
    """
    rule = (
        db_session.query(EmailDomainRule)
        .filter(EmailDomainRule.domain == "test.com")
        .first()
    )
    previous = rule.verdict
    rule.verdict = VERDICT_DENY
    db_session.commit()
    invalidate_cache()
    try:
        yield
    finally:
        rule.verdict = previous
        db_session.commit()
        invalidate_cache()


def test_login_is_unaffected_by_a_deny_rule(
    client: TestClient, test_user: User, enforcing, test_com_denied
):
    """
    Screening at login would be both bypassable and dangerous: the endpoint
    accepts a username as well as an address, so a domain check there is evaded
    by typing a username — and when it does fire, a domain landing on a
    blocklist after somebody joined locks a real customer out with no
    self-service recovery.
    """
    response = client.post(
        "/auth/login",
        json={"email": "admin@test.com", "password": "securepassword123"},
    )
    assert response.status_code == 200


def test_forgot_password_is_unaffected_by_a_deny_rule(
    client: TestClient, test_user: User, enforcing, test_com_denied
):
    response = client.post("/auth/forgot-password", json={"email": "admin@test.com"})
    assert response.status_code == 200


# ── Advisory endpoint ────────────────────────────────────────────────────────


def test_check_email_reports_a_disposable_domain(
    client: TestClient, self_registration_enabled, enforcing
):
    response = client.get("/auth/check-email", params={"q": "x@hutdot.com"})
    assert response.status_code == 200
    body = response.json()
    assert body["available"] is False
    assert body["reason"] == "disposable"


def test_check_email_still_hides_whether_an_account_exists(
    client: TestClient, test_user: User, self_registration_enabled, enforcing
):
    """A registered address and a free one must remain indistinguishable."""
    taken = client.get("/auth/check-email", params={"q": "admin@test.com"}).json()
    free = client.get("/auth/check-email", params={"q": "nobody@test.com"}).json()
    assert taken["available"] is True
    assert free["available"] is True
