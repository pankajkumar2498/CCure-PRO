"""
An authenticated host is recorded as authenticated.

The defect these exist for: the standalone credentialed audit set
``asset.custom_attributes['credentialed_status'] = 'success'`` inline, and the
Vulnerability Audit's credentialed pass — the path that actually runs on the
main pipeline — did not. So a host that was authenticated to, collected from and
configuration-audited still read as ``unknown``, and
``core.compliance_tasks._rule_applies`` routes every rule in
``CREDENTIALED_EVIDENCE_SOURCES`` to ``manual_review`` unless the value is
``success``. The evidence was gathered and the compliance register reported the
control as unassessed.

Measured on the live database before the fix: **zero** assets carried the
attribute, despite eight configuration and privilege findings having been
written by that path against a real Windows host.
"""

import pytest
from scans.asset_syncer import (
    CREDENTIALED_STATUS_FAILED,
    CREDENTIALED_STATUS_SUCCESS,
    set_credentialed_status,
)


class _Asset:
    """Just enough of the ORM object for the writer under test."""

    def __init__(self, attrs=None):
        self.custom_attributes = attrs


# ─────────────────────────────────────────────────────────────────────────────
# The shared writer
# ─────────────────────────────────────────────────────────────────────────────


def test_the_writer_records_success():
    asset = _Asset({})
    set_credentialed_status(asset, CREDENTIALED_STATUS_SUCCESS)
    assert asset.custom_attributes["credentialed_status"] == "success"


def test_the_writer_records_a_refused_attempt_distinctly():
    asset = _Asset({})
    set_credentialed_status(asset, CREDENTIALED_STATUS_FAILED)
    assert asset.custom_attributes["credentialed_status"] == "failed"


def test_the_writer_preserves_every_other_attribute():
    """``custom_attributes`` carries password policy, provenance and more."""
    asset = _Asset({"password_policy": {"min_length": 14}, "provenance": {"os": "x"}})
    set_credentialed_status(asset, CREDENTIALED_STATUS_SUCCESS)
    assert asset.custom_attributes["password_policy"] == {"min_length": 14}
    assert asset.custom_attributes["provenance"] == {"os": "x"}


def test_the_writer_handles_a_null_attribute_column():
    asset = _Asset(None)
    set_credentialed_status(asset, CREDENTIALED_STATUS_SUCCESS)
    assert asset.custom_attributes["credentialed_status"] == "success"


def test_the_writer_reassigns_rather_than_mutating_in_place():
    """
    ``custom_attributes`` is JSONB. SQLAlchemy does not track mutation of a
    plain dict, so an in-place write is silently dropped at flush — the change
    would appear correct in memory and never reach the database.
    """
    original = {"existing": True}
    asset = _Asset(original)
    set_credentialed_status(asset, CREDENTIALED_STATUS_SUCCESS)
    assert asset.custom_attributes is not original
    assert "credentialed_status" not in original


def test_the_status_is_what_the_compliance_engine_tests_for():
    """
    ``core.compliance_tasks`` compares against the literal ``"success"``. If
    these two ever drift, every credentialed rule silently becomes manual.
    """
    import inspect

    from core import compliance_tasks

    source = inspect.getsource(compliance_tasks)
    assert 'creds_status != "success"' in source
    assert CREDENTIALED_STATUS_SUCCESS == "success"


# ─────────────────────────────────────────────────────────────────────────────
# The enrichment path marks the asset
# ─────────────────────────────────────────────────────────────────────────────


def _host(ip="10.0.0.5", **kw):
    host = {
        "ip_address": ip,
        "is_active": True,
        "open_ports": [{"port": 22, "protocol": "tcp", "state": "open"}],
        "cves": [],
    }
    host.update(kw)
    return host


@pytest.fixture()
def sync_one_host(monkeypatch, db_session):
    """
    Drive ``sync_vulnerability_audit`` over one host against a real asset row.

    Only the finding-writing half is stubbed out — the asset resolution and the
    attribute write, which are what these assert, run for real.
    """
    import uuid

    from db.base import gen_asset_id
    from db.models import Asset, Organization
    from db.models.scans import Scan
    from scans import asset_syncer

    org = Organization(
        id=f"org_cs_{uuid.uuid4().hex[:8]}",
        name="cred-status",
        slug=f"credstatus{uuid.uuid4().hex[:6]}",
    )
    db_session.add(org)
    db_session.flush()

    # The syncer stamps ``assets.last_scan_id``, which is a real foreign key.
    scan_id = f"scn_cs_{uuid.uuid4().hex[:8]}"
    db_session.add(Scan(id=scan_id, org_id=org.id, target_str="10.77.0.5"))
    db_session.flush()

    ip = "10.77.0.5"
    asset = Asset(
        id=gen_asset_id(org.slug, ip),
        org_id=org.id,
        ip_address=ip,
        hostname="target-01",
        custom_attributes={},
    )
    db_session.add(asset)
    db_session.commit()

    monkeypatch.setattr(asset_syncer, "_enrich_findings_with_intel", lambda hosts: None)
    monkeypatch.setattr(
        asset_syncer, "_sync_host_vulnerabilities", lambda *a, **k: None, raising=False
    )

    def _run(host):
        # Point the host record at the asset this fixture created, whatever
        # address the caller's helper defaulted to.
        host["ip_address"] = ip
        asset_syncer.sync_vulnerability_audit(db_session, scan_id, org.id, None, [host])
        db_session.refresh(asset)
        return (asset.custom_attributes or {}).get("credentialed_status")

    return _run


def test_a_successfully_authenticated_host_is_marked_success(sync_one_host):
    """The regression. This path produced findings and marked nothing."""
    assert sync_one_host(_host(credentialed=True)) == "success"


def test_a_refused_authentication_is_marked_failed(sync_one_host):
    assert sync_one_host(_host(credentialed_status="failed")) == "failed"


def test_a_host_nothing_was_attempted_against_is_left_unmarked(sync_one_host):
    """
    "No credential was in scope" and "the credential was refused" are different
    facts. Writing a failure for the first would claim an attempt that never
    happened; both route to manual_review, so nothing is lost by the honesty.
    """
    assert sync_one_host(_host()) is None


def test_an_explicit_status_wins_over_the_credentialed_flag(sync_one_host):
    host = _host(credentialed=True, credentialed_status="failed")
    assert sync_one_host(host) == "failed"


# ─────────────────────────────────────────────────────────────────────────────
# The enrichment records a refusal on the host record
# ─────────────────────────────────────────────────────────────────────────────


def test_enrichment_records_a_failed_authentication_on_the_host(monkeypatch):
    """
    The other half: the enrichment must put the fact on the host dict for the
    syncer to find. A rejected credential used to leave no trace on the host at
    all — only a line in the scan's skipped list, which nothing persists.
    """
    import scans.tasks.credentialed as tasks_mod

    material = {
        "username": "root",
        "password": "pw",
        "key_content": None,
        "port": 22,
        "transport": "ssh",
        "credential_type": "ssh",
        "auth_method": "password",
        "domain": None,
        "options": {},
    }
    monkeypatch.setattr(
        tasks_mod,
        "_credentialed_plan_for_scan",
        lambda db, scan_row: [{"material": material, "networks": None}],
    )
    monkeypatch.setattr(
        tasks_mod,
        "audit_credentialed_host",
        lambda **kw: (_ for _ in ()).throw(RuntimeError("SSH authentication failed")),
    )

    hosts = [_host(open_ports=[{"port": 22, "protocol": "tcp", "state": "open"}])]
    tasks_mod._apply_credentialed_enrichment(None, object(), hosts)

    assert hosts[0]["credentialed_status"] == "failed"
    assert hosts[0].get("credentialed") is not True


def test_enrichment_leaves_a_skipped_host_unmarked(monkeypatch):
    """A host with no credential in scope was never attempted."""
    import scans.tasks.credentialed as tasks_mod

    monkeypatch.setattr(
        tasks_mod,
        "_credentialed_plan_for_scan",
        lambda db, scan_row: [{"material": {}, "networks": []}],
    )
    hosts = [_host()]
    tasks_mod._apply_credentialed_enrichment(None, object(), hosts)
    assert "credentialed_status" not in hosts[0]
