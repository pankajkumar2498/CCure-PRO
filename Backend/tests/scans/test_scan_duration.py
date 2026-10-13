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
