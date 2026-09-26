"""
Phase 5 golden-export harness, step 2 of 3. See capture_exports.py.

Add synthetic scans to the SCRATCH restore so the golden capture exercises every
path of the configuration-verdict walker. Writes to ccure_phase5_golden only.
Built from the real scan's own 56 results, so the check ids map to real controls.
"""

import copy
import os
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy import MetaData, create_engine, select, text

SCRATCH = "ccure_phase5_golden"
REAL = "scn_test_f88fc2f1_25sep26_f0q6"

url = urlunsplit(urlsplit(os.environ["DATABASE_URL"])._replace(path="/" + SCRATCH))
engine = create_engine(url)
with engine.begin() as conn:
    assert conn.execute(text("select current_database()")).scalar() == SCRATCH
    meta = MetaData()
    meta.reflect(bind=conn, only=["scans", "scan_phases"])
    scans, phases = meta.tables["scans"], meta.tables["scan_phases"]

    real = dict(conn.execute(select(scans).where(scans.c.id == REAL)).mappings().one())
    real_phase = dict(
        conn.execute(select(phases).where(phases.c.scan_id == REAL)).mappings().first()
    )
    report = real["options"]["credentialed_report"]
    audit = report["config_audit"]
    host = str(report.get("target") or "10.180.6.30")

    mixed = copy.deepcopy(audit)
    res = mixed["results"]
    res[0]["outcome"] = "error"
    res[0]["error"] = "Collector unavailable: registry read refused"
    res[1]["outcome"] = "not_applicable"
    res[1].setdefault("metadata", {})["not_applicable_reason"] = "Feature not installed"
    res[2]["outcome"] = "manual_review"
    ev = res[3].get("evidence") or [{}]
    res[3]["evidence"] = [
        dict(ev[0], raw="same line"),
        dict(ev[0], raw="same line"),
        dict(ev[0], raw="other line"),
    ]
    res[4]["references"] = ["https://example.test/a", "", "https://example.test/b"]
    res[5]["outcome"] = ""
    res[6]["outcome"] = "unexpected_state"
    res[7]["severity"] = "HIGH"
    # Real rules crosswalked to 21-22 controls across ISO, CIS and NIST CSF,
    # so the control-mapping path (multiple controls, narrowing, profiles) runs.
    res[8]["check_id"] = "crl_iso_log_retention_v1"
    res[9]["check_id"] = "crl_firewall_active_v1"
    res[10]["check_id"] = "crl_port_http_v1"
    mapped_audit = copy.deepcopy(audit)
    for i, rid in (
        (8, "crl_iso_log_retention_v1"),
        (9, "crl_firewall_active_v1"),
        (10, "crl_port_http_v1"),
    ):
        mapped_audit["results"][i]["check_id"] = rid

    not_assessed = {
        "assessed": False,
        "reason": "Authentication rejected; the configuration audit did not run.",
        "results": [],
    }

    def add(scan_id, scan_no, options, phase_summary=None, pipeline="credentialed"):
        row = dict(real)
        row.update(id=scan_id, scan_no=scan_no, options=options, pipeline_mode=pipeline)
        conn.execute(scans.insert().values(**row))
        ph = dict(real_phase)
        ph.update(id=f"sph_{scan_id}_p", scan_id=scan_id)
        if phase_summary is not None:
            ph["summary"] = phase_summary
        conn.execute(phases.insert().values(**ph))

    base_opts = {k: v for k, v in real["options"].items() if k != "credentialed_report"}

    # Shape 1: vulnerability-audit pipeline, nested under _phase_data.
    add(
        "scn_golden_shape1",
        9001,
        dict(base_opts),
        phase_summary={
            "_phase_data": [
                {"credentialed_report": {"target": host, "config_audit": mixed}}
            ]
        },
        pipeline="vulnerability_audit",
    )
    # Shape 3: multi-host, first host stored twice (report + reports[0]) plus an unassessed host.
    add(
        "scn_golden_multihost",
        9002,
        dict(
            base_opts,
            credentialed_report={
                "target": host,
                "report": {"target": host, "config_audit": mapped_audit},
                "reports": [
                    {"target": host, "config_audit": mapped_audit},
                    {"target": "10.180.6.31", "config_audit": not_assessed},
                ],
            },
        ),
    )
    # Shape 2 with mixed outcomes, and a policy snapshot narrowed to ISO.
    narrowed = copy.deepcopy(real["options"])
    narrowed["credentialed_report"] = dict(report, config_audit=mixed)
    snap = narrowed.get("scan_policy") or {}
    if isinstance(snap.get("effective"), dict):
        snap["effective"]["framework_ids"] = ["cfw_iso27001_2022"]
    snap["framework_ids"] = ["cfw_iso27001_2022"]
    narrowed["scan_policy"] = snap
    add("scn_golden_narrowed", 9003, narrowed)

print("synthetic scans added: 3")
