"""
tests/test_scan_scope.py
─────────────────────────────────────────────────────────────────────────────
Per-organisation authorisation for scan targets.

Before this control the only checks on a target were "does it parse", "is it
loopback" and "is it under the host cap" — a typo filter, not an authorisation
boundary. Any authenticated user could aim Nmap, Scapy and Nuclei at any
routable address, including the public internet, from a worker running with
raw-socket privileges on the host.

The tests that matter here are the denials and the fail-closed behaviour.
"""

import ipaddress

import pytest
from ccure_platform.api import ScanScopeView
from ccure_platform.organisation_settings.scan_scope import normalise_scope
from core.scan_scope import (
    ScanScopeError,
    enforce_org_scan_scope,
    filter_to_scope,
    is_in_scope,
    parse_scope,
    scope_for_org,
)
from db.models import Organization, User
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session


def _Org(cidrs, id="org_test"):
    """
    The organisation's scope as the platform reports it (Phase 8.4): ``None``
    stored is "not configured", a list is the configured ranges.
    """
    return ScanScopeView(
        org_id=id, configured=cidrs is not None, cidrs=tuple(cidrs or ())
    )


# ── Parsing ───────────────────────────────────────────────────────────────────


def test_null_scope_means_unconfigured_not_empty():
    """NULL and [] must not be confused: one is 'undecided', one is 'none'."""
    assert parse_scope(None) is None
    assert parse_scope([]) == []


def test_unparseable_entries_are_dropped_not_expanded():
    """A malformed stored entry must narrow the scope, never widen it."""
    scope = parse_scope(["10.0.0.0/8", "garbage", "192.168.1.0/24"])
    assert scope == [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("192.168.1.0/24"),
    ]


def test_non_list_scope_is_treated_as_deny_all():
    assert parse_scope("10.0.0.0/8") == []


def test_normalise_rejects_bad_input_loudly():
    """The write path must reject typos rather than silently narrowing."""
    with pytest.raises(ValueError):
        normalise_scope(["10.0.0.0/8", "not-a-cidr"])


def test_normalise_canonicalises_and_dedupes():
    assert normalise_scope(["10.180.6.5/24", " 10.180.6.9/24 "]) == ["10.180.6.0/24"]


# ── Matching ──────────────────────────────────────────────────────────────────


def test_membership():
    scope = parse_scope(["10.180.6.0/24"])
    assert is_in_scope("10.180.6.14", scope) is True
    assert is_in_scope("10.180.7.14", scope) is False
    assert is_in_scope("8.8.8.8", scope) is False
    # Not an address at all — must not be treated as in scope.
    assert is_in_scope("not-an-ip", scope) is False


def test_none_scope_admits_everything():
    assert is_in_scope("8.8.8.8", None) is True
    assert filter_to_scope(["8.8.8.8"], None) == (["8.8.8.8"], [])


# ── Fail-open vs fail-closed ──────────────────────────────────────────────────


def test_unconfigured_org_is_unrestricted_by_default(monkeypatch):
    """
    Ships fail-open so the migration does not stop every existing org from
    scanning the moment it lands.
    """
    from config import AppConfig

    monkeypatch.setattr(AppConfig, "REQUIRE_SCAN_SCOPE", False)
    assert scope_for_org(_Org(None)) is None


def test_unconfigured_org_is_denied_when_enforcement_required(monkeypatch):
    from config import AppConfig

    monkeypatch.setattr(AppConfig, "REQUIRE_SCAN_SCOPE", True)
    assert scope_for_org(_Org(None)) == []


def test_missing_org_row_is_denied_when_enforcement_required(monkeypatch):
    """
    A dangling org_id must not become a way to scan without a scope. This is
    the case the _SCOPE_NOT_CHECKED sentinel in validate_scan_targets exists
    to keep distinct from "this caller does no scope check".
    """
    from config import AppConfig

    monkeypatch.setattr(AppConfig, "REQUIRE_SCAN_SCOPE", True)
    assert scope_for_org(None) == []


# ── Admission ─────────────────────────────────────────────────────────────────


def test_in_scope_target_is_admitted():
    enforce_org_scan_scope(["10.180.6.14"], _Org(["10.180.6.0/24"]))


def test_out_of_scope_target_is_denied():
    with pytest.raises(ScanScopeError) as exc:
        enforce_org_scan_scope(["8.8.8.8"], _Org(["10.180.6.0/24"]))
    assert "8.8.8.8" in exc.value.out_of_scope


def test_partially_out_of_scope_range_is_denied_whole():
    """
    A range straddling the boundary is a request to scan addresses the org is
    not authorised for. Silently trimming it would run a different scan than
    the one asked for and report success.
    """
    with pytest.raises(ScanScopeError):
        enforce_org_scan_scope(["10.180.6.250-10.180.7.5"], _Org(["10.180.6.0/24"]))


def test_empty_scope_denies_everything():
    with pytest.raises(ScanScopeError) as exc:
        enforce_org_scan_scope(["10.180.6.14"], _Org([]))
    assert "no authorised scan ranges" in exc.value.message


def test_unconfigured_scope_admits_everything(monkeypatch):
    from config import AppConfig

    monkeypatch.setattr(AppConfig, "REQUIRE_SCAN_SCOPE", False)
    enforce_org_scan_scope(["8.8.8.8"], _Org(None))


# ── API integration ───────────────────────────────────────────────────────────


def test_scan_endpoint_rejects_out_of_scope_target(
    client: TestClient, db_session: Session, auth_headers: dict, test_user: User
):
    """The admission check must reach the HTTP layer as a 403, not a 422."""
    org = (
        db_session.query(Organization)
        .filter(Organization.id == test_user.org_id)
        .first()
    )
    org.scan_scope_cidrs = ["10.180.6.0/24"]
    db_session.commit()

    res = client.post(
        "/scan/host-discovery",
        headers=auth_headers,
        json={"targets": ["8.8.8.8"], "scan_type": "ping"},
    )
    assert res.status_code == 403
    assert "authorised scan scope" in res.json()["detail"]


def test_scan_endpoint_admits_in_scope_target(
    client: TestClient, db_session: Session, auth_headers: dict, test_user: User
):
    org = (
        db_session.query(Organization)
        .filter(Organization.id == test_user.org_id)
        .first()
    )
    org.scan_scope_cidrs = ["10.180.6.0/24"]
    db_session.commit()

    res = client.post(
        "/scan/host-discovery",
        headers=auth_headers,
        json={"targets": ["10.180.6.14"], "scan_type": "ping"},
    )
    # The valid target must pass the organisation scope gate.
    assert res.status_code != 403


def test_org_admin_cannot_widen_own_scan_scope(
    client: TestClient, db_session: Session, auth_headers: dict, test_user: User
):
    """
    The subject of a restriction must not control it. This is why the value
    lives in its own column rather than the org_admin-writable settings bag.
    """
    res = client.put(
        f"/admin/organizations/{test_user.org_id}/scan-scope",
        headers=auth_headers,
        json={"cidrs": ["0.0.0.0/0"]},
    )
    assert res.status_code == 403

    db_session.refresh(test_user)
    org = (
        db_session.query(Organization)
        .filter(Organization.id == test_user.org_id)
        .first()
    )
    assert org.scan_scope_cidrs != ["0.0.0.0/0"]


# ── Worker-side layer ─────────────────────────────────────────────────────────


def test_orchestrator_drops_out_of_scope_addresses():
    """
    Second layer, applied to the addresses a hostname actually resolved to.
    Admission cannot know these, because DNS can change in between.
    """
    from orchestrator.scan_orchestrator import ScanOrchestrator

    orch = ScanOrchestrator(silent=True)
    orch.apply_scan_scope(_Org(["10.180.6.0/24"]))

    kept = orch._drop_out_of_scope(["10.180.6.14", "8.8.8.8", "10.180.7.1"])
    assert kept == ["10.180.6.14"]


def test_orchestrator_without_scope_keeps_everything():
    from orchestrator.scan_orchestrator import ScanOrchestrator

    orch = ScanOrchestrator(silent=True)
    assert orch.scan_scope is None
    assert orch._drop_out_of_scope(["8.8.8.8"]) == ["8.8.8.8"]
