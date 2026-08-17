"""
tests/test_authz_hardening.py
─────────────────────────────────────────────────────────────────────────────
Regression tests for the cross-tenant and command-construction findings.

Each of these guards a specific defect, not a general principle:

  * compliance_rules is a *global* catalogue with no tenant_id. `org_admin`
    holds compliance:manage_rules, so a tenant administrator could rewrite the
    checks every other tenant on the installation is scored against.
  * InputValidator.is_safe() approved strings beginning with "-", which land in
    a scanner's argv as options rather than targets.
  * The credential-encryption fallback key is published in this repository.
"""

import pytest
from db.models import ComplianceRule, Organization, Role, User
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session


# ── Global compliance rule catalogue ──────────────────────────────────────────


@pytest.fixture
def a_rule(db_session: Session):
    rule = (
        db_session.query(ComplianceRule)
        .filter(ComplianceRule.status == "active")
        .first()
    )
    if rule is None:
        pytest.skip("no seeded compliance rules in this database")
    return rule


def test_org_admin_cannot_edit_the_global_rule_catalogue(
    client: TestClient, db_session: Session, auth_headers: dict, a_rule
):
    """
    `auth_headers` is an org_admin. It holds compliance:manage_rules, which is
    what made this reachable — the rule has no tenant_id to filter on, so the
    only possible fix is to gate the writer.
    """
    original = dict(a_rule.check_definition or {})
    original_weight = a_rule.severity_weight

    res = client.put(
        f"/compliance/rules/{a_rule.id}",
        headers=auth_headers,
        json={
            "check_definition": {"tampered": True},
            "severity": "info",
            "severity_weight": 0,
        },
    )
    assert res.status_code == 403
    assert "shared catalogue" in res.json()["detail"]

    db_session.refresh(a_rule)
    assert a_rule.check_definition == original
    assert a_rule.severity_weight == original_weight


def test_superadmin_can_edit_the_rule_catalogue(
    client: TestClient, db_session: Session, test_org: Organization, a_rule
):
    """The route must still work for the role that is allowed to use it."""
    from auth.jwt_handler import create_access_token

    superadmin_role = db_session.query(Role).filter(Role.name == "superadmin").first()
    from db.base import utcnow

    sa = User(
        username="rulesuperadmin",
        email="rulesuperadmin@test.com",
        password_hash="x",
        org_id=test_org.id,
        role_id=superadmin_role.id,
        is_active=True,
        is_verified=True,
        approved_at=utcnow(),
    )
    db_session.add(sa)
    db_session.commit()
    db_session.refresh(sa)

    token = create_access_token(sa.id, sa.username, role="superadmin", org_id=sa.org_id)
    res = client.put(
        f"/compliance/rules/{a_rule.id}",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "check_definition": dict(a_rule.check_definition or {}),
            "severity": a_rule.severity,
            "severity_weight": a_rule.severity_weight,
        },
    )
    assert res.status_code == 200


# ── Argument injection ────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "value",
    ["-oN", "-sS", "--iflist", "-iL/etc/passwd", "-oX/tmp/x", "--privileged"],
)
def test_is_safe_rejects_values_that_parse_as_options(value):
    """
    A value beginning with '-' becomes an option in the scanner's argv, not a
    target. is_safe() is the primitive that asserts a value may be passed on.
    """
    from core.utils import InputValidator

    assert InputValidator.is_safe(value) is False


@pytest.mark.parametrize(
    "value",
    [
        "10.180.6.14",
        "10.180.6.0/24",
        "10.180.6.1-50",
        "example.com",
        "host-name.local",
        "[2001:db8::1]",
    ],
)
def test_is_safe_still_accepts_real_targets(value):
    """Internal dashes are legitimate: ranges and hostnames both use them."""
    from core.utils import InputValidator

    assert InputValidator.is_safe(value) is True


def test_nmap_subprocess_refuses_option_shaped_target():
    """
    The guard at the argv boundary. Nmap has no '--' end-of-options separator
    and parses options after the target, so this cannot be solved by ordering.
    """
    from core.nmap.wrapper import NmapScanner

    scanner = NmapScanner()
    result = scanner._run_subprocess("-iL/etc/passwd", "-sS")
    assert result.state == "error"
    assert "must not begin with" in (result.error_message or "")


# ── Credential encryption ─────────────────────────────────────────────────────


def test_production_refuses_the_published_fallback_key(monkeypatch):
    """
    The fallback is a constant in a shared repository. Encrypting SSH/WinRM
    credentials under it produces a store that looks encrypted and is not, and
    the only signal was one ERROR line at startup.
    """
    import core.security_crypto as sc

    monkeypatch.setattr(sc, "_key_digest", None)
    monkeypatch.setattr(sc, "_using_fallback", None)
    monkeypatch.delenv("COMPLIANCE_ENCRYPTION_KEY", raising=False)
    monkeypatch.setenv("APP_ENV", "production")

    with pytest.raises(RuntimeError, match="COMPLIANCE_ENCRYPTION_KEY is not set"):
        sc.encrypt_credential("hunter2")


def test_development_still_tolerates_a_missing_key(monkeypatch):
    """Refusing to boot without a key would make local development miserable."""
    import core.security_crypto as sc

    monkeypatch.setattr(sc, "_key_digest", None)
    monkeypatch.setattr(sc, "_using_fallback", None)
    monkeypatch.delenv("COMPLIANCE_ENCRYPTION_KEY", raising=False)
    monkeypatch.setenv("APP_ENV", "development")

    blob = sc.encrypt_credential("hunter2")
    assert sc.decrypt_credential(blob) == "hunter2"
    assert sc.using_fallback_key() is True


def test_roundtrip_and_nonce_uniqueness(monkeypatch):
    """Same plaintext must not produce the same ciphertext twice."""
    import core.security_crypto as sc

    monkeypatch.setattr(sc, "_key_digest", None)
    monkeypatch.setattr(sc, "_using_fallback", None)
    monkeypatch.setenv("COMPLIANCE_ENCRYPTION_KEY", "a" * 44)

    a = sc.encrypt_credential("s3cret")
    b = sc.encrypt_credential("s3cret")
    assert a != b
    assert sc.decrypt_credential(a) == sc.decrypt_credential(b) == "s3cret"


def test_tampered_ciphertext_is_rejected(monkeypatch):
    """GCM's authentication tag must actually be checked."""
    import base64

    import core.security_crypto as sc

    monkeypatch.setattr(sc, "_key_digest", None)
    monkeypatch.setattr(sc, "_using_fallback", None)
    monkeypatch.setenv("COMPLIANCE_ENCRYPTION_KEY", "b" * 44)

    blob = sc.encrypt_credential("s3cret")
    raw = bytearray(base64.b64decode(blob))
    raw[-1] ^= 0xFF
    tampered = base64.b64encode(bytes(raw)).decode()

    with pytest.raises(ValueError):
        sc.decrypt_credential(tampered)
