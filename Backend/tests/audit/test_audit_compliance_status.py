"""
tests/audit/test_audit_compliance_status.py
─────────────────────────────────────────────────────────────────────────────
Phase 1.1: the recorded *outcome* of a compliance action must be the outcome
that actually happened.

`routers/compliance.py` had 25 calls of the shape

    log_audit_event(db, user, "upload_evidence", "evidence", cid, "blocked_malware")

The sixth positional parameter is `changes`, not `status`. So the string landed
in the JSONB change set, `status` kept its `"success"` default, and **an upload
refused by the malware scanner was recorded as a successful one** — the single
most misleading row this module could write.

Fixing the argument alone is not enough. Both refusal paths write the event and
then `raise HTTPException`, and `get_db` closes the session without committing,
so the row is discarded with the transaction. That is the same failure
`auth/email_domain_guard.py` documents and solves with a separate committed
session; these tests assert the event actually survives.
"""

import pytest
from core.upload_guard import MalwareDetected, MalwareScanUnavailable
from db.models import AuditLog, User
from db.models.compliance import (
    ComplianceControl,
    ComplianceTenantFramework,
)
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

PDF_BYTES = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n%%EOF\n"


@pytest.fixture
def evidence_control(db_session: Session, test_user: User) -> ComplianceControl:
    """A control belonging to a framework this tenant has enabled."""
    ctrl = (
        db_session.query(ComplianceControl)
        .filter(ComplianceControl.framework_id == "cfw_iso27001_2022")
        .first()
    )
    if ctrl is None:
        pytest.skip("ISO 27001 catalogue is not seeded in this database")

    inst = (
        db_session.query(ComplianceTenantFramework)
        .filter(
            ComplianceTenantFramework.tenant_id == test_user.org_id,
            ComplianceTenantFramework.framework_id == ctrl.framework_id,
        )
        .first()
    )
    if inst is None:
        inst = ComplianceTenantFramework(
            id=f"ctf_{test_user.org_id}_{ctrl.framework_id}",
            tenant_id=test_user.org_id,
            framework_id=ctrl.framework_id,
            is_enabled=True,
        )
        db_session.add(inst)
    else:
        inst.is_enabled = True
    db_session.commit()
    return ctrl


def _evidence_post(client, auth_headers, control_id, payload=PDF_BYTES):
    return client.post(
        f"/compliance/controls/{control_id}/evidence",
        headers=auth_headers,
        files={"file": ("policy.pdf", payload, "application/pdf")},
    )


def _upload_events(db_session):
    """
    Read the events back through an **independent** session.

    This is load-bearing. The `client` fixture overrides `get_db` to yield the
    test's own `db_session` and never closes it, so a row that was merely
    flushed — never committed — is still visible to `db_session` inside the
    same transaction. Asserting through it would pass on code whose event is
    discarded the moment the real `get_db` closes its session in production.

    A separate session sees only committed data, so this asks the question the
    production path actually answers: did the event survive?
    """
    from db.base import SessionLocal

    probe = SessionLocal()
    try:
        return (
            probe.query(AuditLog)
            .filter(AuditLog.action == "upload_evidence")
            .order_by(AuditLog.created_at)
            .all()
        )
    finally:
        probe.close()


# ─── Outcome: success ────────────────────────────────────────────────────────


def test_successful_upload_is_recorded_as_success(
    client: TestClient,
    auth_headers: dict,
    evidence_control: ComplianceControl,
    db_session: Session,
):
    res = _evidence_post(client, auth_headers, evidence_control.id)
    assert res.status_code == 201, res.text

    events = _upload_events(db_session)
    assert len(events) == 1
    assert events[0].status == "success"
    # The defect put the status string here. Nothing status-shaped may remain.
    assert events[0].changes != "success"


# ─── Outcome: blocked (malware detected) ─────────────────────────────────────


def test_malware_block_is_recorded_as_blocked_not_success(
    client: TestClient,
    auth_headers: dict,
    evidence_control: ComplianceControl,
    db_session: Session,
    monkeypatch,
):
    """
    The headline regression. Before the fix this row read `status="success"`
    with `changes="blocked_malware"` — an audit trail stating that a file the
    scanner rejected was accepted.
    """
    import routers.compliance as compliance_router

    def _detect(*_a, **_kw):
        raise MalwareDetected("Eicar-Test-Signature")

    monkeypatch.setattr(compliance_router, "scan_for_malware", _detect)

    res = _evidence_post(client, auth_headers, evidence_control.id)
    assert res.status_code == 400, res.text

    events = _upload_events(db_session)
    assert len(events) == 1, (
        "a refused upload must still be audited — the event is written and then "
        "HTTPException is raised, so it is lost unless it is committed separately"
    )
    assert events[0].status == "blocked_malware"
    assert events[0].status != "success"


# ─── Outcome: unavailable (scanner could not answer) ─────────────────────────


def test_scanner_unavailable_is_recorded_as_unavailable(
    client: TestClient,
    auth_headers: dict,
    evidence_control: ComplianceControl,
    db_session: Session,
    monkeypatch,
):
    """
    Distinct from a detection on purpose: the file is not accused of anything,
    the scanner simply could not answer. An investigation has to be able to
    tell "refused because malicious" from "refused because unverifiable".
    """
    import routers.compliance as compliance_router

    def _unavailable(*_a, **_kw):
        raise MalwareScanUnavailable("clamd closed the connection without a reply")

    monkeypatch.setattr(compliance_router, "scan_for_malware", _unavailable)

    res = _evidence_post(client, auth_headers, evidence_control.id)
    assert res.status_code == 503, res.text

    events = _upload_events(db_session)
    assert len(events) == 1
    assert events[0].status == "scanner_unavailable"
    assert events[0].status != "success"


def test_the_three_outcomes_are_distinguishable(
    client: TestClient,
    auth_headers: dict,
    evidence_control: ComplianceControl,
    db_session: Session,
    monkeypatch,
):
    """
    All three land on the same action (`upload_evidence`), so `status` is the
    only field that separates them. If it collapses to "success" the trail
    cannot answer the question it exists for.
    """
    import routers.compliance as compliance_router

    _evidence_post(client, auth_headers, evidence_control.id)

    monkeypatch.setattr(
        compliance_router,
        "scan_for_malware",
        lambda *_a, **_k: (_ for _ in ()).throw(MalwareDetected("Eicar")),
    )
    _evidence_post(client, auth_headers, evidence_control.id)

    monkeypatch.setattr(
        compliance_router,
        "scan_for_malware",
        lambda *_a, **_k: (_ for _ in ()).throw(MalwareScanUnavailable("down")),
    )
    _evidence_post(client, auth_headers, evidence_control.id)

    statuses = [e.status for e in _upload_events(db_session)]
    assert sorted(statuses) == sorted(
        ["success", "blocked_malware", "scanner_unavailable"]
    ), f"outcomes not distinguishable: {statuses}"


# ─── Outcome: failure, on a different compliance action ──────────────────────


def test_status_survives_the_round_trip_for_a_failure(db_session: Session, test_user):
    """
    `status` is VARCHAR(20) and the longest value in use
    (`scanner_unavailable`, 19 characters) sits one character inside it. A
    truncation or a silent default here would be invisible in the response and
    only wrong in the table.
    """
    from core.audit import log_audit_event

    for status in ("success", "failure", "blocked_malware", "scanner_unavailable"):
        log_audit_event(
            db_session,
            test_user,
            "upload_evidence",
            "evidence",
            f"ctrl_{status}",
            status=status,
        )
    db_session.commit()

    stored = {e.resource_id: e.status for e in _upload_events(db_session)}
    assert stored == {
        "ctrl_success": "success",
        "ctrl_failure": "failure",
        "ctrl_blocked_malware": "blocked_malware",
        "ctrl_scanner_unavailable": "scanner_unavailable",
    }
