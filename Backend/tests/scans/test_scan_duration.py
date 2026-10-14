"""
A finished scan's duration is the time it took.

Scan History listed a credentialed Vulnerability Audit (13 Oct 2026, scan #8)
as "Duration 2m 17s" beside "total scan duration 3m 53s", and its report said
3.9 minutes: the scan's duration was the sum of each phase's own
``scan_duration``, and the audit phase reports only its port re-check.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from db.models.scans import Scan
from scans.db_helpers import update_scan_phase


def test_the_final_phase_records_wall_clock_duration(db_session, test_org, test_user):
    started = datetime.now(timezone.utc) - timedelta(minutes=4)
    scan = Scan(
        id=f"scn_{uuid.uuid4().hex[:12]}",
        org_id=test_org.id,
        created_by=test_user.id,
        target_str="10.180.6.30",
        pipeline_mode="asset",
        status="running",
        started_at=started,
        duration_seconds=11.3,  # phase 1, already rolled in
    )
    db_session.add(scan)
    db_session.commit()

    with patch("core.celery_app.registered_task", return_value=MagicMock()):
        update_scan_phase(
            db_session,
            scan.id,
            test_user.id,
            phase=2,
            phase_data={"summary": {"scan_duration": 46.0}, "data": []},
            is_final=True,
            pipeline_mode="asset",
        )

    db_session.refresh(scan)
    assert scan.status == "complete"
    # About four minutes of wall clock, not 11.3 + 46.0 seconds of phases.
    assert 230 <= scan.duration_seconds <= 260


def test_stored_hosts_say_unknown_with_null_not_n_a():
    """The asset path's "N/A" placeholders reached the UI's MAC column."""
    from scans.db_helpers import _phase_summary_payload

    payload = _phase_summary_payload(
        {"phase": 1},
        [
            {
                "ip_address": "10.180.6.45",
                "mac_address": "N/A",
                "vendor": "N/A",
                "hostname": "h",
            }
        ],
    )
    host = payload["_phase_data"][0]
    assert host["mac_address"] is None and host["vendor"] is None
    assert host["hostname"] == "h"


def test_a_scan_is_complete_only_once_its_findings_are_written(
    db_session, test_org, test_user
):
    """
    Scan #22 (14 Oct 2026) read "complete" at 13:43:45 while its findings were
    written until 13:44:28, and every scan stamped completed_at before the
    findings it produced — all 2,270 that scan #17 first found carry a
    first_found_at after its own completion, which GAP-13's baseline
    reconstruction reads as new. CLAUDE.md: completed_at is stamped after the
    findings sync, not before.
    """
    from db.base import engine
    from sqlalchemy import text

    scan = Scan(
        id=f"scn_{uuid.uuid4().hex[:12]}",
        org_id=test_org.id,
        created_by=test_user.id,
        target_str="10.180.6.30",
        pipeline_mode="vulnerability_audit",
        status="running",
        started_at=datetime.now(timezone.utc) - timedelta(minutes=12),
    )
    db_session.add(scan)
    db_session.commit()

    seen = {}

    def sync_probe(db, scan_id, org_id, user_id, hosts):
        # What any other reader could see while the findings are being written.
        with engine.connect() as other:
            status, completed = other.execute(
                text("SELECT status, completed_at FROM scans WHERE id = :id"),
                {"id": scan_id},
            ).one()
        seen.update(status=status, completed_at=completed)
        seen["synced_at"] = datetime.now(timezone.utc)

    with patch("scans.db_helpers.sync_vulnerability_audit", sync_probe), patch(
        "core.celery_app.registered_task", return_value=MagicMock()
    ):
        update_scan_phase(
            db_session,
            scan.id,
            test_user.id,
            phase=3,
            phase_data={
                "summary": {"scan_duration": 600.0},
                "data": [{"ip_address": "10.180.6.30"}],
            },
            is_final=True,
            pipeline_mode="vulnerability_audit",
        )

    assert seen["status"] == "running" and seen["completed_at"] is None
    db_session.refresh(scan)
    assert scan.status == "complete"
    assert scan.completed_at >= seen["synced_at"]
