"""
A compliance run over zero assets — Phase 1, finding F6.

`run_scan_task` recorded a run whose scope resolved to no assets as
`completed` with the message "No assets in scope." — a run that assessed
nothing stored as a finished assessment, which the workspace then announced as
"Compliance scan completed." It now ends `not_assessed` (migration
d6e7f8a9b0c2), carries the reason, and is never taken as the latest results.
"""

import uuid
from datetime import datetime, timezone

import pytest

from core.compliance_tasks import run_scan_task
from db.models.compliance import ComplianceScanRun
from routers.compliance import _latest_run_id

ISO_FW = "cfw_iso27001_2022"


@pytest.fixture
def run_ids(db_session):
    ids: list[str] = []
    yield ids
    db_session.rollback()
    if ids:
        db_session.query(ComplianceScanRun).filter(
            ComplianceScanRun.id.in_(ids)
        ).delete(synchronize_session=False)
        db_session.commit()


def _queued_run(db, org_id, run_ids, scope) -> str:
    run_id = f"csr_f6_{uuid.uuid4().hex[:10]}"
    db.add(
        ComplianceScanRun(
            id=run_id,
            tenant_id=org_id,
            framework_id=ISO_FW,
            scope=scope,
            status="queued",
            created_at=datetime.now(timezone.utc),
        )
    )
    db.commit()
    run_ids.append(run_id)
    return run_id


@pytest.mark.parametrize(
    "scope",
    [
        {"asset_ids": [], "asset_tags": []},  # the organisation has no assets
        {"asset_ids": ["ast_does_not_exist"], "asset_tags": []},
        {"asset_ids": [], "asset_tags": ["no-asset-carries-this-tag"]},
    ],
    ids=["empty-org", "unknown-asset-id", "unmatched-tag"],
)
def test_a_run_over_no_assets_is_not_assessed(db_session, test_org, run_ids, scope):
    run_id = _queued_run(db_session, test_org.id, run_ids, scope)

    result = run_scan_task(run_id, test_org.id)

    assert result["status"] == "not_assessed"
    db_session.expire_all()
    run = db_session.get(ComplianceScanRun, run_id)
    assert run.status == "not_assessed"
    assert run.finished_at is not None
    assert "nothing was assessed" in run.error_message


def test_a_not_assessed_run_is_never_the_latest_results(db_session, test_org, run_ids):
    run_id = _queued_run(
        db_session, test_org.id, run_ids, {"asset_ids": [], "asset_tags": []}
    )
    run_scan_task(run_id, test_org.id)

    assert _latest_run_id(db_session, test_org.id, ISO_FW) is None
