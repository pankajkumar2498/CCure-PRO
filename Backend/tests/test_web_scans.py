from types import SimpleNamespace

from db.models.web_scans import WebScan


def _web_scan_payload(target_url="https://example.com"):
    return {
        "scan_name": "Production Web Audit",
        "target_url": target_url,
        "authorization_confirmed": True,
        "scan_scope": {
            "include_subdomains": False,
            "exclude_paths": [],
            "max_depth": 3,
        },
        "auth": {"type": "none"},
        "options": {
            "enable_sqli": True,
            "enable_xss": True,
            "nuclei_severity": ["medium", "high", "critical"],
            "rate_limit": 10,
        },
    }


def test_web_scan_launch_is_idempotent(client, db_session, auth_headers, monkeypatch):
    calls = []

    def fake_delay(**kwargs):
        calls.append(kwargs)
        return SimpleNamespace(id=f"task-{len(calls)}")

    from core.web.tasks import run_web_recon_task

    monkeypatch.setattr(run_web_recon_task, "delay", fake_delay)

    headers = {
        **auth_headers,
        "Idempotency-Key": "launch-web-scan-001",
    }

    first = client.post("/web-scans", json=_web_scan_payload(), headers=headers)
    second = client.post("/web-scans", json=_web_scan_payload(), headers=headers)

    assert first.status_code == 201
    assert second.status_code == 201
    assert first.json()["web_scan_id"] == second.json()["web_scan_id"]
    assert first.json()["duplicate"] is False
    assert second.json()["duplicate"] is True
    assert len(calls) == 1

    scan = (
        db_session.query(WebScan)
        .filter(WebScan.id == first.json()["web_scan_id"])
        .first()
    )
    assert scan is not None
    assert scan.options["_launch"]["idempotency_key"] == "launch-web-scan-001"


def test_web_scan_launch_collapses_active_duplicate_target(
    client, auth_headers, monkeypatch
):
    calls = []

    def fake_delay(**kwargs):
        calls.append(kwargs)
        return SimpleNamespace(id=f"task-{len(calls)}")

    from core.web.tasks import run_web_recon_task

    monkeypatch.setattr(run_web_recon_task, "delay", fake_delay)

    first = client.post(
        "/web-scans",
        json=_web_scan_payload("https://duplicate.example.com"),
        headers={**auth_headers, "Idempotency-Key": "first-key"},
    )
    second = client.post(
        "/web-scans",
        json=_web_scan_payload("https://duplicate.example.com"),
        headers={**auth_headers, "Idempotency-Key": "second-key"},
    )

    assert first.status_code == 201
    assert second.status_code == 201
    assert first.json()["web_scan_id"] == second.json()["web_scan_id"]
    assert second.json()["duplicate"] is True
    assert len(calls) == 1
