"""
A workbook carries the hosts its scan found, and a readable policy.

From the 13 Oct 2026 run: the XLSX of a Basic Network Scan or Asset Discovery
held a summary and three empty sheets — the hosts, MACs, operating systems and
open services the scan had found appeared nowhere in it. Its summary wrote the
policy snapshot as a Python dict repr in one cell, and that snapshot said
"Benchmarks: Every framework installed" / "Built-in checks: Included" for a
scan that runs no checks.
"""

from __future__ import annotations

import uuid

import pytest
from db.models.rbac import Organization
from db.models.scans import Scan, ScanPhase
from reporting.exports import (
    _NO_CHECKS,
    _scoped_policy,
    export_payload,
    scan_context_rows,
    workbook_sheets,
)

HOSTS = [
    {
        "ip_address": "10.180.6.30",
        "hostname": "PANKAJM-HPNEW",
        "mac_address": "2c:58:b9:15:74:70",
        "vendor": "HP Inc.",
        "os_guess": "Microsoft Windows 11 Pro",
        "is_active": True,
        "open_ports": [{"port": 445, "protocol": "tcp", "service": "microsoft-ds"}],
    }
]


@pytest.fixture()
def scan_with_hosts(db_session):
    def make(mode, phase_key, order):
        org = Organization(
            id=f"org_{uuid.uuid4().hex[:8]}",
            name="Hosts",
            slug=f"hosts-{uuid.uuid4().hex[:8]}",
            is_active=True,
            settings={},
        )
        db_session.add(org)
        db_session.flush()
        scan = Scan(
            id=f"scn_{uuid.uuid4().hex[:12]}",
            org_id=org.id,
            target_str="10.180.6.30",
            pipeline_mode=mode,
            status="complete",
        )
        db_session.add(scan)
        db_session.flush()
        db_session.add(
            ScanPhase(
                id=f"sph_{uuid.uuid4().hex[:12]}",
                scan_id=scan.id,
                phase_key=phase_key,
                phase_order=order,
                status="complete",
                summary={"phase": order, "_phase_data": HOSTS},
            )
        )
        db_session.commit()
        return scan

    return make


def test_an_asset_scan_workbook_has_its_hosts(db_session, scan_with_hosts):
    scan = scan_with_hosts("asset", "asset_discovery", 2)
    payload = export_payload(db_session, scan, datasets=("hosts",))
    hosts = payload["datasets"]["hosts"]
    assert hosts["row_count"] == 1
    row = dict(zip(hosts["columns"], hosts["rows"][0]))
    assert row["IP Address"] == "10.180.6.30"
    assert row["MAC Address"] == "2c:58:b9:15:74:70"
    assert row["Open Port Count"] == "1"

    names = [name for name, _cols, _rows in workbook_sheets(payload)]
    assert names == ["Summary", "Hosts"]


def test_a_basic_scan_workbook_says_ports_were_not_scanned(db_session, scan_with_hosts):
    scan = scan_with_hosts("basic", "host_discovery", 1)
    payload = export_payload(db_session, scan, datasets=("hosts",))
    row = dict(
        zip(
            payload["datasets"]["hosts"]["columns"],
            payload["datasets"]["hosts"]["rows"][0],
        )
    )
    assert row["Open Port Count"] == "Not scanned"


def test_the_policy_summary_is_one_row_per_setting():
    rows = scan_context_rows(
        {
            "policy": {
                "recorded": True,
                "fingerprint": "abc",
                "summary": {
                    "Benchmarks": "cfw_bm_stig_ubuntu2404",
                    "Built-in checks": "Included",
                },
            }
        }
    )
    assert ["Policy: Benchmarks", "cfw_bm_stig_ubuntu2404"] in rows
    assert ["Policy: Built-in checks", "Included"] in rows
    assert not any(cell.startswith("{") for row in rows for cell in row)


@pytest.mark.parametrize("mode", ["basic", "asset"])
def test_a_discovery_scan_does_not_claim_check_settings(mode):
    policy = {
        "recorded": True,
        "summary": {
            "Benchmarks": "Every framework installed for this organisation",
            "Built-in checks": "Included",
            "Port selection": "Scanner default",
        },
    }
    scoped = _scoped_policy(policy, mode)["summary"]
    assert scoped["Benchmarks"] == _NO_CHECKS
    assert scoped["Built-in checks"] == _NO_CHECKS
    assert (scoped["Port selection"] == "Scanner default") is (mode == "asset")


def test_an_audit_keeps_its_check_settings():
    policy = {"recorded": True, "summary": {"Built-in checks": "Included"}}
    assert _scoped_policy(policy, "vulnerability_audit")["summary"] == {
        "Built-in checks": "Included"
    }
