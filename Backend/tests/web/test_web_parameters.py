"""
Phase 23b — attack-surface relational model (WebParameter).

The attack surface was queryable only through a JSONB blob and a per-scan
coverage ledger in scans.options. This proves the relational model: the DETECT
phase's finalised coverage exports to first-class ``web_parameters`` rows that
carry each parameter's coverage, are idempotent by (asset, location, name),
update coverage when a parameter is re-seen, and never orphan a parameter onto a
missing endpoint.
"""

import pytest

from core.web.coverage import CoverageLedger
from core.web.tasks import _persist_web_assets, _persist_web_parameters
from db.base import SessionLocal, gen_web_asset_id, utcnow
from db.models.web_scans import WebAsset, WebParameter, WebScan

_PREFIX = "wsc_wpa_"


@pytest.fixture
def session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.query(WebParameter).filter(
            WebParameter.web_scan_id.like(f"{_PREFIX}%")
        ).delete(synchronize_session=False)
        db.query(WebAsset).filter(WebAsset.web_scan_id.like(f"{_PREFIX}%")).delete(
            synchronize_session=False
        )
        db.query(WebScan).filter(WebScan.id.like(f"{_PREFIX}%")).delete(
            synchronize_session=False
        )
        db.commit()
        db.close()


def _mk_scan(session, suffix):
    from db.models.rbac import Organization

    org = session.query(Organization).first()
    scan = WebScan(
        id=f"{_PREFIX}{suffix}",
        org_id=org.id,
        target_url="http://target.invalid/",
        target_domain="target.invalid",
        authorization_confirmed=True,
        scan_name="param test",
        status="running",
        created_at=utcnow(),
        started_at=utcnow(),
    )
    session.add(scan)
    session.commit()
    return scan, org.id


def _ledger_export():
    """A ledger with one tested and one untested query param on one endpoint."""
    lg = CoverageLedger()
    lg.discover("http://target.invalid/search?q=1", "query", "q")
    lg.discover("http://target.invalid/search", "query", "page")
    lg.mark("http://target.invalid/search", "query", "q", "sqlmap")
    lg.mark_skipped(
        "sqlmap", "engine not selected", predicate=lambda n: n["param"] == "page"
    )
    return lg.export_parameters()


def test_persist_populates_rows_with_coverage(session):
    scan, org_id = _mk_scan(session, "cov")
    ep = {
        "url": "http://target.invalid/search?q=1",
        "method": "GET",
        "parameters": {"query": ["q", "page"]},
    }
    _persist_web_assets(session, scan.id, [ep])
    session.commit()

    _persist_web_parameters(session, scan.id, org_id, _ledger_export())
    session.commit()

    rows = (
        session.query(WebParameter)
        .filter(WebParameter.web_scan_id == scan.id)
        .order_by(WebParameter.name)
        .all()
    )
    assert len(rows) == 2
    by_name = {r.name: r for r in rows}
    assert by_name["q"].tested is True
    assert by_name["q"].tested_by == ["sqlmap"]
    assert by_name["q"].location == "query"
    assert by_name["page"].tested is False
    assert by_name["page"].skipped_reason == "engine not selected"
    # every row joins to the real asset and carries the org
    asset_id = gen_web_asset_id(scan.id, ep["url"] + "GET")
    assert all(r.web_asset_id == asset_id and r.org_id == org_id for r in rows)


def test_persist_is_idempotent_and_updates_coverage(session):
    scan, org_id = _mk_scan(session, "idem")
    ep = {
        "url": "http://target.invalid/search",
        "method": "GET",
        "parameters": {"query": ["page"]},
    }
    _persist_web_assets(session, scan.id, [ep])
    session.commit()

    # First seen untested.
    lg = CoverageLedger()
    lg.discover("http://target.invalid/search", "query", "page")
    _persist_web_parameters(session, scan.id, org_id, lg.export_parameters())
    session.commit()
    row = session.query(WebParameter).filter(WebParameter.web_scan_id == scan.id).one()
    assert row.tested is False

    # Re-seen after an engine tested it — same row, updated coverage, no dup.
    lg.mark("http://target.invalid/search", "query", "page", "xss")
    _persist_web_parameters(session, scan.id, org_id, lg.export_parameters())
    session.commit()
    rows = session.query(WebParameter).filter(WebParameter.web_scan_id == scan.id).all()
    assert len(rows) == 1
    assert rows[0].tested is True and rows[0].tested_by == ["xss"]


def test_parameter_without_asset_is_skipped_not_orphaned(session):
    """A parameter whose endpoint was never persisted must not break the write."""
    scan, org_id = _mk_scan(session, "noasset")
    # No _persist_web_assets call — the ledger references an endpoint with no row.
    lg = CoverageLedger()
    lg.discover("http://target.invalid/ghost", "query", "x")
    _persist_web_parameters(session, scan.id, org_id, lg.export_parameters())
    session.commit()
    assert (
        session.query(WebParameter).filter(WebParameter.web_scan_id == scan.id).count()
        == 0
    )


def test_empty_export_is_a_noop(session):
    scan, org_id = _mk_scan(session, "empty")
    _persist_web_parameters(session, scan.id, org_id, [])
    session.commit()
    assert (
        session.query(WebParameter).filter(WebParameter.web_scan_id == scan.id).count()
        == 0
    )
