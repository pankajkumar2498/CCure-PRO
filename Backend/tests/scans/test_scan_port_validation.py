"""Invalid port settings must fail admission before any worker runs."""

import uuid

import pytest

from db.models import Scan, ScanPolicy


@pytest.mark.parametrize("source", ["request", "policy"])
@pytest.mark.parametrize("ports", ["0", "22,22"])
def test_invalid_ports_leave_no_scan_or_dispatched_task(
    client, auth_headers, db_session, test_org, monkeypatch, source, ports
):
    from unittest.mock import Mock

    from core.tasks import run_host_discovery_task

    dispatch = Mock()
    monkeypatch.setattr(run_host_discovery_task, "delay", dispatch)
    body = {"targets": ["192.0.2.1"], "pipeline_mode": "asset"}
    if source == "policy":
        policy = ScanPolicy(
            id=f"spol_{uuid.uuid4().hex[:8]}",
            org_id=test_org.id,
            name="Invalid port admission fixture",
            policy_family_code="invalid-port-admission",
            scan_kind="network",
            config={"custom_ports": ports},
            status="active",
            is_enabled=True,
        )
        db_session.add(policy)
        db_session.commit()
        body["policy_id"] = policy.id
    else:
        body["custom_ports"] = ports

    before = db_session.query(Scan).count()
    response = client.post("/scan/host-discovery", headers=auth_headers, json=body)

    assert response.status_code == 400, response.json()
    assert db_session.query(Scan).count() == before
    dispatch.assert_not_called()
