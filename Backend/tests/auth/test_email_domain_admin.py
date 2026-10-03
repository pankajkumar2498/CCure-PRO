"""
tests/test_email_domain_admin.py
──────────────────────────────────────────────────────────────────────────────
The admin API for email domain ALLOW / DENY rules.

The access-control tests here carry most of the weight. These rules are
platform-wide — one row changes what every organisation on the deployment can
register with — so an org_admin reaching them would be able to block a
different tenant's customers, or open the door for them. That is a
tenant-isolation boundary, not a nicety, and it is asserted rather than assumed.
"""

from native_rbac import system_role, create_user


import pytest
from auth.email_domain_guard import MODE_ENFORCE, evaluate_email, invalidate_cache
from auth.jwt_handler import create_access_token
from db.models import Organization, User
from db.models.email_security import EmailDomainRule
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

RULES = "/admin/email-domains"


def _headers(user: User) -> dict:
    token = create_access_token(
        user.id,
        user.username,
        org_id=user.org_id,
    )
    return {"Authorization": f"Bearer {token}"}


def _make_user(db_session: Session, role_name: str, username: str) -> User:
    from db.base import gen_user_id, utcnow

    org = db_session.query(Organization).first()
    if org is None:
        org = Organization(
            name="Rules Org",
            slug="rules-org",
            max_assets=10,
            max_users=10,
            is_active=True,
        )
        db_session.add(org)
        db_session.flush()

    role = system_role(db_session, role_name)
    user = create_user(
        db_session,
        id=gen_user_id(org.slug, username),
        username=username,
        email=f"{username}@test.com",
        password_hash="hash",
        org_id=org.id,
        role=role,
        is_active=True,
        is_verified=True,
        approved_at=utcnow(),
        approved_by="fixture",
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture
def superadmin(db_session: Session) -> User:
    return _make_user(db_session, "platform.superadmin", "rules-super")


@pytest.fixture
def org_admin(db_session: Session) -> User:
    return _make_user(db_session, "platform.org_admin", "rules-orgadmin")


@pytest.fixture
def enforcing(monkeypatch):
    from config import AppConfig

    monkeypatch.setattr(AppConfig, "EMAIL_DOMAIN_GUARD_MODE", MODE_ENFORCE)
    invalidate_cache()
    yield
    invalidate_cache()


@pytest.fixture
def cleanup_rules(db_session: Session):
    """Remove rules a test created. `email_domain_rules` is reference data that
    _purge_test_data deliberately leaves alone, so tests must tidy up after
    themselves or the next run collides on the unique domain index."""
    created: list[str] = []
    yield created
    if created:
        db_session.query(EmailDomainRule).filter(
            EmailDomainRule.domain.in_(created)
        ).delete(synchronize_session=False)
        db_session.commit()
        invalidate_cache()


# ── Access control ───────────────────────────────────────────────────────────


def test_org_admin_cannot_list_rules(client: TestClient, org_admin: User):
    """
    The tenant-isolation boundary.

    An org_admin administers one organisation. These rules are platform-wide, so
    granting access here would let one tenant's administrator block another
    tenant's customers.
    """
    response = client.get(RULES, headers=_headers(org_admin))
    assert response.status_code == 403


def test_org_admin_cannot_create_a_rule(client: TestClient, org_admin: User):
    response = client.post(
        RULES,
        json={"domain": "sneaky.com", "verdict": "deny"},
        headers=_headers(org_admin),
    )
    assert response.status_code == 403


def test_unauthenticated_is_refused(client: TestClient):
    assert client.get(RULES).status_code in (401, 403)


def test_superadmin_can_list_rules(client: TestClient, superadmin: User):
    response = client.get(RULES, headers=_headers(superadmin))
    assert response.status_code == 200
    body = response.json()
    assert "rules" in body and "counts" in body
    # The shipped never-block floor is present.
    assert body["counts"]["allow"] > 0


# ── Create ───────────────────────────────────────────────────────────────────


def test_create_deny_rule_blocks_the_domain(
    client: TestClient, db_session: Session, superadmin: User, enforcing, cleanup_rules
):
    response = client.post(
        RULES,
        json={"domain": "blocked-partner.com", "verdict": "deny", "reason": "Abuse"},
        headers=_headers(superadmin),
    )
    assert response.status_code == 201
    cleanup_rules.append("blocked-partner.com")

    body = response.json()
    assert body["verdict"] == "deny"
    assert body["source"] == "admin"
    assert body["created_by"] == str(superadmin.id)

    # Takes effect immediately — the endpoint invalidates the guard's cache
    # rather than leaving the admin to wait out a five-minute TTL.
    verdict = evaluate_email(db_session, "someone@blocked-partner.com")
    assert verdict.blocked is True
    assert verdict.reason == "denylisted"


def test_create_allow_rule_overrides_the_blocklist(
    client: TestClient, db_session: Session, superadmin: User, enforcing, cleanup_rules
):
    """ALLOW beating the corpus is the mechanism that makes enforcement safe."""
    before = evaluate_email(db_session, "someone@hutdot.com")
    assert before.blocked is True

    response = client.post(
        RULES,
        json={"domain": "hutdot.com", "verdict": "allow", "reason": "False positive"},
        headers=_headers(superadmin),
    )
    assert response.status_code == 201
    cleanup_rules.append("hutdot.com")

    after = evaluate_email(db_session, "someone@hutdot.com")
    assert after.blocked is False
    assert after.reason == "allowlisted"


@pytest.mark.parametrize(
    "supplied,stored",
    [
        # Deliberately not `acme.com`: conftest seeds that as an ALLOW rule for
        # the wider suite, so creating it here would 409 and the test would be
        # measuring the fixture rather than the normaliser.
        ("  NormCase.com  ", "normcase.com"),
        ("someone@normaddr.com", "normaddr.com"),
        ("https://normurl.com/signup", "normurl.com"),
        ("normdot.com.", "normdot.com"),
    ],
)
def test_domain_input_is_normalised(
    client: TestClient, superadmin: User, cleanup_rules, supplied, stored
):
    """People paste addresses and URLs. Rejecting those teaches them the form is
    fussy; normalising them is the same amount of code and kinder."""
    response = client.post(
        RULES,
        json={"domain": supplied, "verdict": "deny"},
        headers=_headers(superadmin),
    )
    assert response.status_code == 201
    assert response.json()["domain"] == stored
    cleanup_rules.append(stored)


@pytest.mark.parametrize("bad", ["", "   ", "notadomain", "-bad.com", "a..b.com"])
def test_malformed_domains_are_rejected(client: TestClient, superadmin: User, bad):
    """Storing junk creates a rule that matches nothing and looks like it works."""
    response = client.post(
        RULES, json={"domain": bad, "verdict": "deny"}, headers=_headers(superadmin)
    )
    assert response.status_code == 422


def test_invalid_verdict_is_rejected(client: TestClient, superadmin: User):
    response = client.post(
        RULES,
        json={"domain": "acme.com", "verdict": "maybe"},
        headers=_headers(superadmin),
    )
    assert response.status_code == 422


def test_duplicate_domain_returns_409_not_a_silent_overwrite(
    client: TestClient, superadmin: User, cleanup_rules
):
    """
    A seeded ALLOW must not be flippable by filling in the *add* form. Editing
    is a PATCH, where the intent is explicit.
    """
    response = client.post(
        RULES,
        json={"domain": "gmail.com", "verdict": "deny"},
        headers=_headers(superadmin),
    )
    assert response.status_code == 409
    assert "already exists" in response.json()["detail"].lower()


# ── Update ───────────────────────────────────────────────────────────────────


def test_patch_flips_the_verdict(
    client: TestClient, db_session: Session, superadmin: User, enforcing, cleanup_rules
):
    created = client.post(
        RULES,
        json={"domain": "flipme.com", "verdict": "deny"},
        headers=_headers(superadmin),
    ).json()
    cleanup_rules.append("flipme.com")

    assert evaluate_email(db_session, "x@flipme.com").blocked is True

    response = client.patch(
        f"{RULES}/{created['id']}",
        json={"verdict": "allow"},
        headers=_headers(superadmin),
    )
    assert response.status_code == 200
    assert response.json()["verdict"] == "allow"
    assert evaluate_email(db_session, "x@flipme.com").blocked is False


def test_patching_a_seeded_rule_reattributes_it(
    client: TestClient, db_session: Session, superadmin: User
):
    """A seeded rule a human edits is no longer what the application shipped,
    and leaving source='seed' would tell the next reader otherwise."""
    rule = (
        db_session.query(EmailDomainRule)
        .filter(EmailDomainRule.domain == "yahoo.com")
        .first()
    )
    assert rule is not None and rule.source == "seed"
    original_reason = rule.reason

    response = client.patch(
        f"{RULES}/{rule.id}",
        json={"reason": "Reviewed 18 Aug"},
        headers=_headers(superadmin),
    )
    assert response.status_code == 200
    assert response.json()["source"] == "admin"

    # Restore, so the session's seeded state is unchanged for later tests.
    rule.source = "seed"
    rule.reason = original_reason
    db_session.commit()
    invalidate_cache()


def test_patch_unknown_rule_is_404(client: TestClient, superadmin: User):
    response = client.patch(
        f"{RULES}/999999", json={"verdict": "allow"}, headers=_headers(superadmin)
    )
    assert response.status_code == 404


# ── Delete ───────────────────────────────────────────────────────────────────


def test_delete_reports_what_the_domain_does_next(
    client: TestClient, superadmin: User, enforcing
):
    """
    Removing an ALLOW does not return a domain to neutral if the corpus also
    lists it — it starts blocking. `hutdot.com` is a live example, and the
    response says so rather than leaving the admin to find out from a customer.
    """
    created = client.post(
        RULES,
        json={"domain": "hutdot.com", "verdict": "allow"},
        headers=_headers(superadmin),
    ).json()

    response = client.delete(f"{RULES}/{created['id']}", headers=_headers(superadmin))
    assert response.status_code == 200

    body = response.json()
    assert body["removed_verdict"] == "allow"
    assert body["now"]["blocked"] is True
    assert body["now"]["reason"] == "disposable"


def test_delete_unknown_rule_is_404(client: TestClient, superadmin: User):
    response = client.delete(f"{RULES}/999999", headers=_headers(superadmin))
    assert response.status_code == 404


def test_org_admin_cannot_delete_a_rule(
    client: TestClient, superadmin: User, org_admin: User, cleanup_rules
):
    created = client.post(
        RULES,
        json={"domain": "protected.com", "verdict": "deny"},
        headers=_headers(superadmin),
    ).json()
    cleanup_rules.append("protected.com")

    response = client.delete(f"{RULES}/{created['id']}", headers=_headers(org_admin))
    assert response.status_code == 403


# ── Lookup and stats ─────────────────────────────────────────────────────────


def test_lookup_explains_why_a_domain_is_blocked(
    client: TestClient, superadmin: User, enforcing
):
    response = client.get(
        f"{RULES}/lookup",
        params={"q": "someone@hutdot.com"},
        headers=_headers(superadmin),
    )
    assert response.status_code == 200
    body = response.json()
    assert body["blocked"] is True
    assert body["matched_domain"] == "hutdot.com"
    assert body["matched_source"] == "blocklist"
    assert body["would_block_registration"] is True


def test_lookup_accepts_a_bare_domain(client: TestClient, superadmin: User, enforcing):
    body = client.get(
        f"{RULES}/lookup", params={"q": "hutdot.com"}, headers=_headers(superadmin)
    ).json()
    assert body["domain"] == "hutdot.com"
    assert body["blocked"] is True


def test_lookup_in_flag_mode_separates_verdict_from_effect(
    client: TestClient, superadmin: User, monkeypatch
):
    """`blocked` is the verdict; `would_block_registration` is what happens."""
    from config import AppConfig

    monkeypatch.setattr(AppConfig, "EMAIL_DOMAIN_GUARD_MODE", "flag")
    invalidate_cache()

    body = client.get(
        f"{RULES}/lookup", params={"q": "hutdot.com"}, headers=_headers(superadmin)
    ).json()
    assert body["blocked"] is True
    assert body["would_block_registration"] is False

    invalidate_cache()


def test_stats_reports_corpus_health(client: TestClient, superadmin: User):
    response = client.get(f"{RULES}/stats", headers=_headers(superadmin))
    assert response.status_code == 200
    body = response.json()
    assert body["corpus_size"] > 0
    assert body["corpus_healthy"] is True
    assert body["allow_rules"] > 0


# ── Filtering ────────────────────────────────────────────────────────────────


def test_list_filters_by_verdict_and_search(
    client: TestClient, superadmin: User, cleanup_rules
):
    client.post(
        RULES,
        json={"domain": "findme-xyz.com", "verdict": "deny", "reason": "needle"},
        headers=_headers(superadmin),
    )
    cleanup_rules.append("findme-xyz.com")

    by_verdict = client.get(
        RULES, params={"verdict": "deny"}, headers=_headers(superadmin)
    ).json()
    assert all(r["verdict"] == "deny" for r in by_verdict["rules"])

    by_domain = client.get(
        RULES, params={"q": "findme-xyz"}, headers=_headers(superadmin)
    ).json()
    assert [r["domain"] for r in by_domain["rules"]] == ["findme-xyz.com"]

    by_reason = client.get(
        RULES, params={"q": "needle"}, headers=_headers(superadmin)
    ).json()
    assert by_reason["total"] == 1
