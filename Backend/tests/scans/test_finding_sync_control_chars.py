"""
A NUL byte in probe output must not cost a scan its findings.

On 13 Oct 2026 two Vulnerability Audits of 10.180.6.45 (one unauthenticated,
one credentialed) wrote no findings at all. The host answers SNMP with the
community ``public``; the SNMP probe turned the IP address table into raw
octets, one evidence line carried ``\\x00``, and psycopg2 refused the INSERT
with "A string literal cannot contain NUL (0x00) characters". The inline sync
and its asynchronous retry failed identically, and the scan stayed "complete"
with 14 and 824 findings in its payload and none in ``asset_vulnerabilities``.

Three properties are pinned here:

1. ``scans.db_text`` removes exactly what PostgreSQL refuses, and cleans host
   records in place so the syncer's callers keep their references.
2. ``sync_vulnerability_audit`` stores a finding whose evidence and host record
   carry NUL and other control bytes.
3. If the sync still fails, the scan stops claiming to be complete.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from core.scan_control import record_findings_sync_failure
from db.models.findings import AssetVulnerability
from db.models.rbac import Organization
from db.models.scans import Scan
from scans.db_text import (
    UNSAFE_DB_CHARS,
    clean_db_text,
    sanitize_for_db,
    sanitize_for_db_in_place,
)

# What the SNMP probe actually produced for 10.180.6.45's ipAddrTable.
RAW_SNMP_ADDRESS = "\x01\x01\x01\x05\x00"


# ── scans.db_text ────────────────────────────────────────────────────────────


def test_nul_and_c0_controls_are_removed_but_whitespace_is_kept():
    text = "line one\tcol\r\nline two\x00\x01\x1f end"
    assert clean_db_text(text) == "line one\tcol\r\nline two end"
    assert 0 in UNSAFE_DB_CHARS
    assert (
        9 not in UNSAFE_DB_CHARS
        and 10 not in UNSAFE_DB_CHARS
        and 13 not in UNSAFE_DB_CHARS
    )


def test_the_copying_form_handles_every_shape_jsonb_stores():
    value = {
        "k\x00": [b"bytes\x00", ("tuple\x00",), {"set\x00"}],
        "n": 5,
        "none": None,
    }
    cleaned = sanitize_for_db(value)
    assert cleaned == {"k": ["bytes", ["tuple"], ["set"]], "n": 5, "none": None}
    # The original is untouched.
    assert "k\x00" in value


def test_the_in_place_form_keeps_object_identity():
    """
    The syncer annotates the host records it is handed and its callers hold
    references to the same dicts. Replacing them with copies would silently
    detach those references.
    """
    finding = {"evidence": f"IP address table:\n {RAW_SNMP_ADDRESS}"}
    host = {"cves": [finding], "snmp_info": {"sys_name\x00": "host\x00"}}
    hosts = [host]

    returned = sanitize_for_db_in_place(hosts)

    assert returned is hosts
    assert hosts[0] is host
    assert host["cves"][0] is finding
    assert "\x00" not in finding["evidence"]
    assert host["snmp_info"] == {"sys_name": "host"}


# ── the sync itself ──────────────────────────────────────────────────────────


@pytest.fixture()
def org_and_scan(db_session):
    org = Organization(
        id=f"org_nul_{uuid.uuid4().hex[:8]}",
        name="nul-sync",
        slug=f"nulsync{uuid.uuid4().hex[:6]}",
    )
    db_session.add(org)
    db_session.flush()
    scan_id = f"scn_nul_{uuid.uuid4().hex[:8]}"
    db_session.add(
        Scan(
            id=scan_id,
            org_id=org.id,
            target_str="10.77.9.45",
            pipeline_mode="vulnerability_audit",
            status="complete",
        )
    )
    db_session.flush()
    # Phase 3 updates the asset phases 1 and 2 created; it never creates one.
    from db.base import gen_asset_id, gen_service_id
    from db.models import Asset
    from db.models.findings import Service

    asset_id = gen_asset_id(org.slug, "10.77.9.45")
    db_session.add(
        Asset(
            id=asset_id,
            org_id=org.id,
            ip_address="10.77.9.45",
            hostname="superusr-HP3",
            custom_attributes={},
        )
    )
    db_session.flush()
    # The finding binds to this service, and only a bound finding has its
    # probe output copied into the stored evidence — the path that failed.
    db_session.add(
        Service(
            id=gen_service_id(asset_id, 161, "udp"),
            scan_id=scan_id,
            asset_id=asset_id,
            port=161,
            protocol="udp",
            state="open",
            service_name="snmp",
        )
    )
    db_session.commit()
    return org.id, scan_id


def _snmp_host() -> dict:
    """The shape of the 10.180.6.45 host record, NUL bytes included."""
    return {
        "ip_address": "10.77.9.45",
        "hostname": "superusr-HP3",
        "is_active": True,
        "open_ports": [
            {"port": 161, "protocol": "udp", "state": "open", "service": "snmp"}
        ],
        "snmp_info": {
            "community": "public",
            "sys_descr": "Linux superusr-HP3 6.8.0-146-generic\x00",
            "ip_addresses": [{"address": RAW_SNMP_ADDRESS, "netmask": "\x00"}],
        },
        "cves": [
            {
                "cve_id": "CCURE-CHK-SNMP-INFORMATION-DISCLOSURE",
                "cve": "CCURE-CHK-SNMP-INFORMATION-DISCLOSURE",
                "title": "SNMP discloses system and network detail without authentication",
                "severity": "Medium",
                "cvss": 0.0,
                "cvss_score": 0.0,
                "port": 161,
                "protocol": "udp",
                "definition_type": "plugin_check",
                "detection_method": "config_check",
                "confidence": "Confirmed",
                "qod": 99,
                "plugin_family": "network_service",
                "description": "The agent returned system detail to an unauthenticated query.",
                "evidence": (
                    "Returned to an unauthenticated query:\n"
                    "IP address table: 1 address(es)\n"
                    f"                  {RAW_SNMP_ADDRESS}"
                ),
            }
        ],
    }


def test_a_finding_with_nul_in_its_evidence_is_stored(
    db_session, org_and_scan, monkeypatch
):
    from scans import asset_syncer

    org_id, scan_id = org_and_scan
    # The intel annotation reads the CVE catalogue; it changes no verdict and
    # this finding is not a CVE.
    monkeypatch.setattr(asset_syncer, "_enrich_findings_with_intel", lambda hosts: None)

    asset_syncer.sync_vulnerability_audit(
        db_session, scan_id, org_id, None, [_snmp_host()]
    )
    db_session.commit()

    rows = (
        db_session.query(AssetVulnerability)
        .filter(AssetVulnerability.scan_id == scan_id)
        .all()
    )
    assert [r.vuln_id for r in rows] == ["CCURE-CHK-SNMP-INFORMATION-DISCLOSURE"]
    stored = str(rows[0].evidence or "") + str(rows[0].plugin_output or "")
    assert "\x00" not in stored


# ── a sync that still fails must not read as complete ───────────────────────


def _scan(db_session, org_id, status):
    now = datetime.now(timezone.utc)
    row = Scan(
        id=f"scn_{uuid.uuid4().hex[:12]}",
        org_id=org_id,
        target_str="10.77.9.45",
        pipeline_mode="vulnerability_audit",
        status=status,
        started_at=now - timedelta(minutes=5),
        completed_at=now,
    )
    db_session.add(row)
    db_session.commit()
    return row.id


def test_a_complete_scan_whose_findings_were_lost_is_marked_failed(
    db_session, org_and_scan
):
    org_id, _ = org_and_scan
    scan_id = _scan(db_session, org_id, "complete")

    assert record_findings_sync_failure(scan_id, "Findings could not be saved") is True

    db_session.expire_all()
    row = db_session.query(Scan).filter(Scan.id == scan_id).one()
    assert row.status == "failed"
    assert row.failure_reason == "Findings could not be saved"


@pytest.mark.parametrize("status", ["cancelled", "failed", "unreachable", "running"])
def test_no_other_status_is_overwritten(db_session, org_and_scan, status):
    """Only a scan that claims completion is demoted; every other outcome stands."""
    org_id, _ = org_and_scan
    scan_id = _scan(db_session, org_id, status)

    assert record_findings_sync_failure(scan_id, "x") is False

    db_session.expire_all()
    assert db_session.query(Scan).filter(Scan.id == scan_id).one().status == status


def test_the_async_sync_task_records_its_failure(monkeypatch, db_session, org_and_scan):
    """The task is the retry of the inline sync; its failure is the final word."""
    from core import tasks
    from scans import asset_syncer

    org_id, _ = org_and_scan
    scan_id = _scan(db_session, org_id, "complete")

    def _boom(*_a, **_k):
        raise ValueError("A string literal cannot contain NUL (0x00) characters.")

    monkeypatch.setattr(asset_syncer, "sync_vulnerability_audit", _boom)
    tasks.sync_vulnerability_audit_task.run(scan_id, org_id, None, [_snmp_host()])

    db_session.expire_all()
    row = db_session.query(Scan).filter(Scan.id == scan_id).one()
    assert row.status == "failed"
    assert "could not be saved" in row.failure_reason
    assert "ValueError" in row.failure_reason
