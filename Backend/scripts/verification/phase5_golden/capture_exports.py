"""
Golden capture of every export surface Phase 5.4/5.5 could affect.

Procedure (never against the live database):

1. Restore the newest full dump into a scratch database::

       docker exec ccure-db psql -U postgres -c "CREATE DATABASE ccure_phase5_golden OWNER ccure_user"
       docker exec -i ccure-db pg_restore -U postgres -d ccure_phase5_golden \
           --exit-on-error --no-owner --role=ccure_user < backups/ccure_db_<stamp>_full.dump

2. Add the synthetic scans that cover every walker path (payload shapes,
   multi-host dedupe, unassessed host, mixed outcomes, mapped checks, policy
   narrowing), and give one ISO control a profile so the profile filter bites::

       docker exec -i -w /app ccure-api python - < scripts/verification/phase5_golden/add_synthetic_scans.py

3. Capture before the change (twice — the two must be identical), change the
   code, capture again, and ``cmp`` the files::

       docker exec -i -w /app ccure-api python - < scripts/verification/phase5_golden/capture_exports.py > before.json

Drop the scratch database afterwards.

Declared exclusion, fixed before the first capture: ``exported_at`` (and the
Summary sheet's "Exported At" row) is wall-clock time and is masked. Nothing
else is masked.
"""

import json
import os
import sys
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

SCRATCH = "ccure_phase5_golden"

live = urlsplit(os.environ["DATABASE_URL"])
url = urlunsplit(live._replace(path="/" + SCRATCH))
if urlsplit(url).path.strip("/") != SCRATCH:
    sys.exit("refusing: not the scratch database")

engine = create_engine(
    url, connect_args={"options": "-c default_transaction_read_only=on"}
)
db = sessionmaker(bind=engine)()
assert (
    db.execute(__import__("sqlalchemy").text("select current_database()")).scalar()
    == SCRATCH
)

from core.findings import compare_scans  # noqa: E402
from core.findings.comparison import previous_scan_for  # noqa: E402
from db.models.compliance import ComplianceTenantFramework  # noqa: E402
from db.models.scans import Scan  # noqa: E402
from reporting import exports  # noqa: E402

MASK = "<masked:exported_at>"


def mask(payload):
    payload = json.loads(json.dumps(payload, default=str))
    if isinstance(payload.get("scan"), dict) and "exported_at" in payload["scan"]:
        payload["scan"]["exported_at"] = MASK
    return payload


def mask_sheets(sheets):
    out = []
    for name, header, rows in sheets:
        rows = [list(r) for r in rows]
        if name == "Summary":
            rows = [[r[0], MASK] if r and r[0] == "Exported At" else r for r in rows]
        out.append([name, list(header), rows])
    return out


capture = {}
scans = db.query(Scan).order_by(Scan.id).all()
for scan in scans:
    key = scan.id
    entry = {}
    baseline = previous_scan_for(db, scan)
    comparison = (
        compare_scans(db, current=scan, baseline=baseline, limit_findings=None)
        if baseline is not None
        else None
    )
    full = exports.export_payload(db, scan, comparison=comparison)
    entry["payload"] = mask(full)
    entry["workbook"] = mask_sheets(exports.workbook_sheets(full))

    variants = {
        "scope_asset": {"scope": "asset"},
        "verdict_fail": {"verdict": ["FAIL"]},
        "verdict_na": {"verdict": ["NOT_ASSESSED"]},
        "severity_high": {"severity": ["high"]},
        "overdue": {"overdue_only": True},
    }
    enabled = [
        r[0]
        for r in db.query(ComplianceTenantFramework.framework_id)
        .filter(ComplianceTenantFramework.tenant_id == scan.org_id)
        .all()
    ]
    for fid in sorted(enabled):
        variants[f"framework_{fid}"] = {"framework_id": fid}
    rows = full["datasets"]["compliance"]["rows"]
    host_idx = exports.CONFIG_VERDICT_COLUMNS.index("Host")
    asset_idx = exports.CONFIG_VERDICT_COLUMNS.index("Asset ID")
    hosts = sorted({r[host_idx] for r in rows if r[host_idx]})
    assets = sorted({r[asset_idx] for r in rows if r[asset_idx]})
    if hosts:
        variants["host_first"] = {"host": hosts[0]}
    if assets:
        variants["asset_first"] = {"asset_id": assets[0]}
    variants["profile_IG1"] = {"profile": "IG1"}
    variants["profile_IG2"] = {"profile": "IG2"}
    for name, filters in variants.items():
        entry[f"variant:{name}"] = mask(
            exports.export_payload(db, scan, comparison=comparison, **filters)
        )

    ctx = exports.finding_context_map(db, scan)
    entry["finding_context_map"] = sorted([[list(k), v] for k, v in ctx.items()])
    check_idx = exports.CONFIG_VERDICT_COLUMNS.index("Check ID")
    checks = sorted({r[check_idx] for r in rows if r[check_idx]})
    cmap = exports.control_map_for_checks(db, org_id=scan.org_id, check_ids=checks)
    entry["control_map"] = {k: [repr(c) for c in v] for k, v in sorted(cmap.items())}
    entry["scan_context"] = mask({"scan": exports.scan_context(db, scan)})
    capture[key] = entry

assert not db.new and not db.dirty and not db.deleted
db.rollback()
db.close()
summary = {
    k: {
        "compliance_rows": v["payload"]["datasets"]["compliance"]["row_count"],
        "finding_rows": v["payload"]["datasets"]["findings"]["row_count"],
        "comparison_rows": v["payload"]["datasets"]["comparison"]["row_count"],
        "variants": sum(1 for x in v if x.startswith("variant:")),
    }
    for k, v in capture.items()
}
print(
    json.dumps(
        {"summary": summary, "capture": capture}, sort_keys=True, indent=1, default=str
    )
)
