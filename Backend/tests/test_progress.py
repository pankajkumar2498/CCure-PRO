"""
tests/test_progress.py
─────────────────────────────────────────────────────────────────────────────
Unit tests for the DB-backed progress tracking logic.
"""

from db.models.scans import Scan
from scans.progress import (
    init_progress,
    update_progress,
    finish_progress,
    read_progress,
)
from sqlalchemy.orm import Session


def test_progress_lifecycle(db_session: Session, test_org, test_user):
    """Test the full lifecycle of scan progress tracking in the DB."""

    # 1. Setup a dummy scan record
    scan = Scan(
        org_id=test_org.id,
        created_by=str(test_user.id),
        scan_no=1,
        target_str="10.180.5.0/24",
        scan_type="adaptive",
        pipeline_mode="basic",
        status="pending",
    )
    db_session.add(scan)
    db_session.commit()
    scan_id = str(scan.id)
    user_id = str(test_user.id)

    # 2. Init progress
    init_progress(db_session, scan_id, total_ips=256)

    # Verify init state
    prog = read_progress(db_session, scan_id, user_id)
    assert prog["status"] == "running"
    assert prog["total_ips"] == 256
    assert prog["discovered"] == 0
    assert prog["percentage"] == 0.0

    # 3. Update progress
    update_progress(db_session, scan_id, discovered=128, active=10)

    prog = read_progress(db_session, scan_id, user_id)
    assert prog["discovered"] == 128
    assert prog["active"] == 10
    assert prog["percentage"] == 50.0  # 128/256

    # 4. Finish progress
    finish_progress(db_session, scan_id)

    prog = read_progress(db_session, scan_id, user_id)
    assert prog["status"] == "complete"
