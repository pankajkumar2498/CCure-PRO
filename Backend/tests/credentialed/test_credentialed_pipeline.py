"""
tests/test_credentialed_pipeline.py
────────────────────────────────────────────────────────────────────────────
Credentialed scanning: coverage disclosure, exposure correlation, service
provenance, multi-host audits, and credentials as a policy option on the
Vulnerability Audit pipeline.

The behaviour these cover has one theme. An authenticated audit and a port
scan each see half of what matters, and every failure mode here is the same
mistake in a different place: presenting one half as if it were the whole. A
loopback listener recorded as an open port, a report with no network findings
read as a host with no network exposure, a scan labelled with a pipeline whose
phases never ran.
"""

import uuid

import pytest
from db.base import utcnow
from db.models.assets import Asset
from db.models.findings import (
    OBSERVED_SERVICE_STATES,
    SOURCE_CREDENTIALED,
    SOURCE_NETWORK_SCAN,
    STATE_HOST_ONLY,
    STATE_LISTENING,
    STATE_OPEN,
    Service,
)
from db.models.rbac import Organization
from db.models.scans import Scan
from engines.credentialed.coverage import (
    BIND_ALL,
    BIND_LOOPBACK,
    BIND_SPECIFIC,
    bind_scope,
    correlate_listeners,
    credentialed_coverage,
    mark_credentialed_confirmed,
    network_port_keys,
)
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

# ─────────────────────────────────────────────────────────────────────────────
# Bind-scope classification
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "local_addr,expected",
    [
        ("0.0.0.0:22", BIND_ALL),
        ("*:80", BIND_ALL),
        (":::22", BIND_ALL),
        ("[::]:8080", BIND_ALL),
        ("127.0.0.1:5432", BIND_LOOPBACK),
        ("127.0.0.53:53", BIND_LOOPBACK),
        ("[::1]:631", BIND_LOOPBACK),
        ("192.168.1.5:8080", BIND_SPECIFIC),
    ],
)
def test_bind_scope_classifies_every_collector_format(local_addr, expected):
    """Both collectors' socket formats must resolve to the same vocabulary."""
    assert bind_scope(local_addr) == expected


def test_bind_scope_unknown_when_address_absent():
    assert bind_scope("") == "unknown"
    assert bind_scope(None) == "unknown"
    assert bind_scope("22") == "unknown"


# ─────────────────────────────────────────────────────────────────────────────
# Exposure correlation
# ─────────────────────────────────────────────────────────────────────────────


LISTENERS = [
    {"state": "LISTEN", "local_addr": "0.0.0.0:22", "port": "22", "process": "sshd"},
    {
        "state": "LISTEN",
        "local_addr": "127.0.0.1:5432",
        "port": "5432",
        "process": "postgres",
    },
    {"state": "LISTEN", "local_addr": "0.0.0.0:9090", "port": "9090", "process": "app"},
]


def test_correlation_separates_exposed_from_filtered_and_host_only():
    annotated, summary = correlate_listeners(
        LISTENERS,
        network_ports=[{"port": 22, "protocol": "tcp", "state": "open"}],
        network_scanned=True,
        scanned_ports=[22, 5432, 9090],
    )
    by_port = {r["port"]: r for r in annotated}

    # Answered a probe → genuinely exposed.
    assert by_port["22"]["exposure"] == "exposed"
    assert by_port["22"]["network_reachable"] is True

    # Loopback bind → provably not reachable off-box.
    assert by_port["5432"]["exposure"] == "host_only"
    assert by_port["5432"]["network_reachable"] is False

    # Listening on all interfaces but the scan could not reach it.
    assert by_port["9090"]["exposure"] == "filtered"
    assert by_port["9090"]["network_reachable"] is False

    assert summary["listeners_exposed"] == 1
    assert summary["listeners_host_only"] == 1
    assert summary["listeners_filtered"] == 1
    assert summary["correlated_with_port_scan"] is True


def test_without_a_port_scan_reachability_is_undetermined_not_false():
    """
    "We did not look" must never render as "not reachable".

    Only the loopback verdict survives, because the host's own bind address
    settles that one without any help from the network.
    """
    annotated, summary = correlate_listeners(LISTENERS, network_scanned=False)
    by_port = {r["port"]: r for r in annotated}

    assert by_port["22"]["network_reachable"] is None
    assert by_port["22"]["exposure"] == "undetermined"
    assert by_port["9090"]["network_reachable"] is None

    assert by_port["5432"]["exposure"] == "host_only"
    assert by_port["5432"]["network_reachable"] is False

    assert summary["listeners_undetermined"] == 2
    assert summary["correlated_with_port_scan"] is False


def test_a_port_outside_the_scanned_range_is_undetermined_not_filtered():
    """
    A port scan reports what it found open, not what it tried. Treating the
    difference as "filtered" tells the reader a firewall is blocking a service
    the scanner never probed.

    Found on real data: an 8-port scan against a host with 101 listeners
    labelled 92 of them "not reachable from the scanner".
    """
    annotated, summary = correlate_listeners(
        LISTENERS,
        network_ports=[{"port": 22, "protocol": "tcp", "state": "open"}],
        network_scanned=True,
        scanned_ports=[22],  # 9090 was never probed
    )
    by_port = {r["port"]: r for r in annotated}

    assert by_port["22"]["exposure"] == "exposed"
    assert by_port["9090"]["exposure"] == "undetermined"
    assert by_port["9090"]["network_reachable"] is None
    # The loopback verdict never depended on the scan.
    assert by_port["5432"]["exposure"] == "host_only"
    assert summary["listeners_filtered"] == 0


def test_without_a_known_probed_set_nothing_is_claimed_filtered():
    """A scan that did not record its port set cannot support that claim."""
    annotated, summary = correlate_listeners(
        LISTENERS,
        network_ports=[{"port": 22, "protocol": "tcp", "state": "open"}],
        network_scanned=True,
    )
    by_port = {r["port"]: r for r in annotated}
    assert by_port["22"]["exposure"] == "exposed"
    assert by_port["9090"]["exposure"] == "undetermined"
    assert summary["listeners_filtered"] == 0


def test_probed_port_set_round_trips_through_the_scan_record():
    """
    The engine publishes the probed set; the credentialed pass reads it back.
    A lossy spec would silently reintroduce the bug above.
    """
    from core.utils import InputValidator
    from engines.port.port_engine import _ports_spec

    ports = [22, 80, 443] + list(range(1000, 1025)) + [8080]
    spec = _ports_spec(ports)
    assert spec == "22,80,443,1000-1024,8080"
    assert sorted(InputValidator.parse_custom_ports(spec)) == sorted(ports)


def test_correlation_does_not_mutate_the_collector_output():
    """The raw socket table is still stored verbatim, so it must survive intact."""
    original = [dict(r) for r in LISTENERS]
    correlate_listeners(LISTENERS, network_scanned=False)
    assert LISTENERS == original


def test_closed_and_filtered_ports_do_not_count_as_reachable():
    """A port the scan found closed is evidence against reachability, not for it."""
    keys = network_port_keys(
        [
            {"port": 22, "protocol": "tcp", "state": "open"},
            {"port": 80, "protocol": "tcp", "state": "closed"},
            {"port": 443, "protocol": "tcp", "state": "filtered"},
        ]
    )
    assert keys == {(22, "tcp")}


def test_mark_credentialed_confirmed_flags_both_directions():
    ports = mark_credentialed_confirmed(
        [{"port": 22, "protocol": "tcp"}, {"port": 443, "protocol": "tcp"}],
        LISTENERS,
    )
    by_port = {p["port"]: p for p in ports}
    assert by_port[22]["credentialed_confirmed"] is True
    # Answered a probe but the host has no matching listener — a forwarded port
    # or a namespace the collector could not see. Worth surfacing, not hiding.
    assert by_port[443]["credentialed_confirmed"] is False


# ─────────────────────────────────────────────────────────────────────────────
# Coverage disclosure
# ─────────────────────────────────────────────────────────────────────────────


def test_host_only_coverage_states_what_was_not_examined():
    coverage = credentialed_coverage(network_scanned=False)
    assert "Not scanned" in coverage["port_range"]
    assert "Not performed" in coverage["unauthenticated_checks"]
    assert "Not determined" in coverage["network_reachability"]
    # An unset key renders as "Not recorded", which invites the reader to
    # assume the check ran and found nothing.
    for key in ("port_range", "service_detection", "os_detection", "scanner"):
        assert coverage[key]


def test_pipeline_coverage_claims_the_checks_that_actually_ran():
    coverage = credentialed_coverage(network_scanned=True)
    assert "Performed" in coverage["unauthenticated_checks"]
    assert "Determined" in coverage["network_reachability"]
    # The host-only disclaimers must not leak into a scan that did scan ports.
    assert "port_range" not in coverage


# ─────────────────────────────────────────────────────────────────────────────
# Service provenance
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def org_and_asset(db_session: Session):
    org_id = f"org_test_{uuid.uuid4().hex[:8]}"
    org = Organization(
        id=org_id,
        name=f"Cred Org {uuid.uuid4().hex[:8]}",
        slug=f"cred-org-{uuid.uuid4().hex[:8]}",
        is_active=True,
        settings={},
    )
    db_session.add(org)
    db_session.commit()

    asset = Asset(
        id=f"ast_{org_id}_10_0_0_5",
        org_id=org.id,
        ip_address="10.0.0.5",
        hostname="cred-host",
        last_seen_at=utcnow(),
    )
    db_session.add(asset)

    scan_id = f"scn_{uuid.uuid4().hex[:8]}"
    db_session.add(
        Scan(
            id=scan_id,
            org_id=org.id,
            created_by=None,
            target_str="10.0.0.5",
            scan_type="credentialed",
            pipeline_mode="credentialed",
        )
    )
    db_session.commit()
    return org, asset, scan_id


def test_loopback_listener_is_not_recorded_as_an_open_port(
    db_session: Session, org_and_asset
):
    """
    The defect this whole change exists to fix.

    A service bound to 127.0.0.1 used to be written with state "open",
    indistinguishable from a port a scan had confirmed reachable — so it
    counted toward exposure on the dashboard and in compliance evidence.
    """
    from core.findings.writer import upsert_credentialed_services

    _org, asset, scan_id = org_and_asset
    annotated, _ = correlate_listeners(LISTENERS, network_scanned=False)
    upsert_credentialed_services(db_session, asset.id, scan_id, annotated, [])
    db_session.commit()

    rows = {
        r.port: r
        for r in db_session.query(Service).filter(Service.asset_id == asset.id).all()
    }

    assert rows[5432].state == STATE_HOST_ONLY
    assert rows[5432].network_reachable is False
    assert rows[5432].bind_scope == BIND_LOOPBACK
    # Excluded from every "what is this asset serving" query.
    assert rows[5432].state not in OBSERVED_SERVICE_STATES

    # Reachability untested is recorded as listening, not as open.
    assert rows[22].state == STATE_LISTENING
    assert rows[22].network_reachable is None
    assert rows[22].state in OBSERVED_SERVICE_STATES

    for row in rows.values():
        assert row.discovery_source == SOURCE_CREDENTIALED
        assert row.credentialed_confirmed is True


def test_correlated_listener_is_recorded_as_open(db_session: Session, org_and_asset):
    from core.findings.writer import upsert_credentialed_services

    _org, asset, scan_id = org_and_asset
    annotated, _ = correlate_listeners(
        LISTENERS,
        network_ports=[{"port": 22, "protocol": "tcp", "state": "open"}],
        network_scanned=True,
    )
    upsert_credentialed_services(db_session, asset.id, scan_id, annotated, [])
    db_session.commit()

    row = (
        db_session.query(Service)
        .filter(Service.asset_id == asset.id, Service.port == 22)
        .one()
    )
    assert row.state == STATE_OPEN
    assert row.network_reachable is True


def test_credentialed_pass_never_downgrades_a_network_confirmed_port(
    db_session: Session, org_and_asset
):
    """
    The port scan reached it; the host cannot see the firewall in front of it.

    Where the two disagree the direct observation wins, and the credentialed
    pass contributes only what it alone knows.
    """
    from core.findings.writer import (
        upsert_credentialed_services,
        upsert_network_service,
    )

    _org, asset, scan_id = org_and_asset

    upsert_network_service(
        db_session,
        asset.id,
        scan_id,
        {"port": 22, "protocol": "tcp", "service": "ssh", "product": "OpenSSH"},
    )
    db_session.commit()

    # The host reports the same port as loopback-bound — contradictory, and the
    # network observation is the one backed by evidence.
    upsert_credentialed_services(
        db_session,
        asset.id,
        scan_id,
        [
            {
                "port": "22",
                "local_addr": "127.0.0.1:22",
                "bind_scope": BIND_LOOPBACK,
                "network_reachable": False,
                "process": 'users:(("sshd",pid=1,fd=3))',
            }
        ],
        [{"name": "sshd", "version": "8.9p1"}],
    )
    db_session.commit()

    row = (
        db_session.query(Service)
        .filter(Service.asset_id == asset.id, Service.port == 22)
        .one()
    )
    assert row.state == STATE_OPEN
    assert row.network_reachable is True
    assert row.discovery_source == SOURCE_NETWORK_SCAN
    # …but the host's contribution is kept.
    assert row.credentialed_confirmed is True
    assert row.bind_scope == BIND_LOOPBACK
    assert row.service_version == "8.9p1"


def test_network_scan_preserves_an_earlier_credentialed_confirmation(
    db_session: Session, org_and_asset
):
    from core.findings.writer import (
        upsert_credentialed_services,
        upsert_network_service,
    )

    _org, asset, scan_id = org_and_asset

    upsert_credentialed_services(
        db_session,
        asset.id,
        scan_id,
        [{"port": "443", "local_addr": "0.0.0.0:443", "process": "nginx"}],
        [],
    )
    db_session.commit()

    upsert_network_service(
        db_session,
        asset.id,
        scan_id,
        {"port": 443, "protocol": "tcp", "service": "https"},
    )
    db_session.commit()

    row = (
        db_session.query(Service)
        .filter(Service.asset_id == asset.id, Service.port == 443)
        .one()
    )
    assert row.state == STATE_OPEN
    assert row.network_reachable is True
    assert row.credentialed_confirmed is True


# ─────────────────────────────────────────────────────────────────────────────
# Merging authenticated findings into a network-scanned host
# ─────────────────────────────────────────────────────────────────────────────


def test_package_findings_are_stamped_so_verification_keeps_them():
    """
    Verification asserts credentialed origin from the record and never infers
    it. An unmarked package finding arriving on a host that also has
    fingerprinted services is read as a network claim about a product the host
    does not appear to run — and suppressed.
    """
    from scans.tasks.credentialed import _as_credentialed_findings

    prepared = _as_credentialed_findings(
        [
            {"cve_id": "CVE-2024-0001", "package": "openssl", "installed_ver": "3.0.2"},
            {"cve_id": "CVE-2024-0002", "package": "curl"},
        ],
        [{"name": "curl", "version": "7.81.0"}],
    )

    assert all(f["detection_method"] == "credentialed" for f in prepared)
    # The matcher emits `installed_ver`, which the version check does not read.
    assert prepared[0]["installed_version"] == "3.0.2"
    # Recovered from the package inventory when the record carried none.
    assert prepared[1]["installed_version"] == "7.81.0"


def test_credentialed_findings_survive_verification_on_a_scanned_host():
    """End-to-end of the above: the merged finding must reach the report."""
    from scans.finding_normalizer import verify_host_findings

    from scans.tasks.credentialed import _as_credentialed_findings

    host = {
        "ip_address": "10.0.0.5",
        "os_guess": "Ubuntu 22.04",
        "open_ports": [
            {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh"}
        ],
        "cves": _as_credentialed_findings(
            [
                {
                    "cve_id": "CVE-2024-0001",
                    "package": "libxml2",
                    "installed_ver": "2.9.13",
                    "severity": "High",
                }
            ],
            [{"name": "libxml2", "version": "2.9.13"}],
        ),
    }

    verification = verify_host_findings(host)
    assert len(verification.verified) == 1
    assert verification.suppressed == []


def test_credential_scope_selects_the_right_host():
    from scans.tasks.credentialed import _credential_for_host

    scoped = {"username": "svc-a", "port": 22}
    fallback = {"username": "svc-b", "port": 2222}
    plan = [
        {
            "material": scoped,
            "networks": [__import__("ipaddress").ip_network("10.0.1.0/24")],
        },
        {"material": fallback, "networks": None},
    ]

    assert _credential_for_host(plan, "10.0.1.7") is scoped
    # No scope means every host, so it is the catch-all.
    assert _credential_for_host(plan, "10.9.9.9") is fallback


def test_credential_with_no_matching_scope_is_not_applied():
    from scans.tasks.credentialed import _credential_for_host

    plan = [
        {
            "material": {"username": "svc"},
            "networks": [__import__("ipaddress").ip_network("10.0.1.0/24")],
        }
    ]
    assert _credential_for_host(plan, "192.168.0.1") is None


# ─────────────────────────────────────────────────────────────────────────────
# Report assembly
# ─────────────────────────────────────────────────────────────────────────────


def _credentialed_report(target: str, cve_id: str) -> dict:
    return {
        "scan_type": "credentialed",
        "target": target,
        "system_info": {"os_name": "Ubuntu 22.04", "hostname": f"host-{target}"},
        "packages": [{"name": "libxml2", "version": "2.9.13"}],
        "open_ports_credentialed": [],
        "cves": [
            {
                "cve_id": cve_id,
                "package": "libxml2",
                "installed_version": "2.9.13",
                "severity": "High",
                "detection_method": "credentialed",
            }
        ],
        "suppressed_cves": [
            {"identifier": "CVE-2000-9999", "host": target, "reason": "Not applicable"}
        ],
        "candidates_evaluated": 2,
    }


def test_report_covers_every_audited_host_without_double_counting():
    """
    `reports` holds all hosts and `report` repeats the first for consumers
    written before multi-host audits — reading both would count it twice.
    """
    from scans.finding_normalizer import build_scan_report

    reports = [
        _credentialed_report("10.0.0.5", "CVE-2024-0001"),
        _credentialed_report("10.0.0.6", "CVE-2024-0002"),
    ]
    findings = build_scan_report(
        {"data": {"credentialed": {"report": reports[0], "reports": reports}}}
    )

    assert sorted(h.ip for h in findings.hosts) == ["10.0.0.5", "10.0.0.6"]
    assert all(h.credentialed for h in findings.hosts)


def test_single_host_payload_still_reads_from_report_alone():
    """Scans stored before multi-host support have no `reports` key."""
    from scans.finding_normalizer import build_scan_report

    findings = build_scan_report(
        {
            "data": {
                "credentialed": {"report": _credentialed_report("10.0.0.5", "CVE-1")}
            }
        }
    )
    assert [h.ip for h in findings.hosts] == ["10.0.0.5"]


def test_suppressed_candidates_reach_the_report():
    """
    Withheld candidates are no longer among the audit's findings, so the report
    can only account for them if they travel with the host record.
    """
    from scans.finding_normalizer import build_scan_report

    findings = build_scan_report(
        {
            "data": {
                "credentialed": {"report": _credentialed_report("10.0.0.5", "CVE-1")}
            }
        }
    )
    assert [e.identifier for e in findings.excluded] == ["CVE-2000-9999"]


def test_methodology_appendix_prints_the_coverage_the_scan_recorded():
    from reporting.pdf_generator import _scan_configuration
    from scans.finding_normalizer import ScanFindings
    from scans.report_inputs import report_inputs

    coverage = credentialed_coverage(network_scanned=False)
    meta = {**coverage, "listeners_exposed": 0, "listeners_host_only": 3}
    rows = dict(
        _scan_configuration(
            meta, {}, ScanFindings(), "credentialed", report_inputs(meta, {})
        )
    )

    assert "Not scanned" in rows["Port selection"]
    assert "Not performed" in rows["Unauthenticated checks"]
    assert "Not determined" in rows["Network reachability"]
    assert "3 bound to loopback" in rows["Service exposure"]


def test_appendix_omits_credentialed_rows_for_an_ordinary_scan():
    """
    Printing "Not recorded" against network reachability on a port scan would
    imply the question applied to it.
    """
    from reporting.pdf_generator import _scan_configuration
    from scans.finding_normalizer import ScanFindings
    from scans.report_inputs import report_inputs

    meta = {"port_range": "1-1000"}
    rows = dict(
        _scan_configuration(meta, {}, ScanFindings(), "asset", report_inputs(meta, {}))
    )
    assert "Network reachability" not in rows
    assert "Unauthenticated checks" not in rows
    assert "Service exposure" not in rows


# ─────────────────────────────────────────────────────────────────────────────
# API surface
# ─────────────────────────────────────────────────────────────────────────────


def test_scan_records_the_pipeline_it_actually_ran(
    client: TestClient, auth_headers: dict, db_session: Session, monkeypatch
):
    """
    A standalone credentialed audit runs no discovery and no port scan.
    Recording it as a vulnerability_audit claimed three phases that never
    executed.
    """
    from core.celery_app import registered_task
    from core.task_names import RUN_CREDENTIALED_SCAN
    from engines.credentialed.ssh_scanner import SSHScanner

    # The router's pre-flight check resolves the endpoint rather than probing
    # one fixed port, and reaches SSHScanner.test_connectivity through the
    # resolver. Patching the class attribute is still what stands the socket
    # down; the router no longer imports the class, so this names it directly.
    monkeypatch.setattr(SSHScanner, "test_connectivity", lambda *a, **k: True)
    captured = {}

    class _Task:
        id = "task-1"

    def _fake_delay(**kwargs):
        captured.update(kwargs)
        return _Task()

    # The route dispatches by registered name (G1); this is the task it finds.
    monkeypatch.setattr(registered_task(RUN_CREDENTIALED_SCAN), "delay", _fake_delay)

    response = client.post(
        "/scan/credentialed",
        headers=auth_headers,
        json={"ip": "10.180.6.140", "username": "root", "password": "secret"},
    )
    assert response.status_code == 200, response.text

    scan = db_session.query(Scan).filter(Scan.id == response.json()["scan_id"]).one()
    assert scan.pipeline_mode == "credentialed"
    assert captured["targets"] == ["10.180.6.140"]


def test_multiple_targets_are_expanded_into_one_scan(
    client: TestClient, auth_headers: dict, db_session: Session, monkeypatch
):
    from core.celery_app import registered_task
    from core.task_names import RUN_CREDENTIALED_SCAN
    from engines.credentialed.ssh_scanner import SSHScanner

    # The router's pre-flight check resolves the endpoint rather than probing
    # one fixed port, and reaches SSHScanner.test_connectivity through the
    # resolver. Patching the class attribute is still what stands the socket
    # down; the router no longer imports the class, so this names it directly.
    monkeypatch.setattr(SSHScanner, "test_connectivity", lambda *a, **k: True)
    captured = {}

    class _Task:
        id = "task-2"

    def _fake_delay(**kwargs):
        captured.update(kwargs)
        return _Task()

    # The route dispatches by registered name (G1); this is the task it finds.
    monkeypatch.setattr(registered_task(RUN_CREDENTIALED_SCAN), "delay", _fake_delay)

    response = client.post(
        "/scan/credentialed",
        headers=auth_headers,
        json={
            "targets": ["10.180.6.140", "10.180.6.150-152"],
            "username": "root",
            "password": "secret",
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()

    assert body["hosts_queued"] == 4
    assert captured["targets"] == [
        "10.180.6.140",
        "10.180.6.150",
        "10.180.6.151",
        "10.180.6.152",
    ]

    scan = db_session.query(Scan).filter(Scan.id == body["scan_id"]).one()
    assert len(scan.target_hosts) == 4


def test_oversized_target_set_is_rejected_before_the_scan_starts(
    client: TestClient, auth_headers: dict
):
    """Authenticating to every address in a /23 in turn is not a scan, it is an outage."""
    response = client.post(
        "/scan/credentialed",
        headers=auth_headers,
        json={"targets": ["10.180.0.0/23"], "username": "root", "password": "secret"},
    )
    assert response.status_code == 400
    assert "limited to" in response.json()["detail"]


def test_a_target_is_required(client: TestClient, auth_headers: dict):
    response = client.post(
        "/scan/credentialed",
        headers=auth_headers,
        json={"username": "root", "password": "secret"},
    )
    assert response.status_code == 422


def test_single_unreachable_target_still_fails_fast(
    client: TestClient, auth_headers: dict, monkeypatch
):
    """
    With one target an unreachable host means the scan has nothing to do, so
    the operator is told immediately rather than after a queued job fails.
    """
    from engines.credentialed.ssh_scanner import SSHScanner

    monkeypatch.setattr(SSHScanner, "test_connectivity", lambda *a, **k: False)

    response = client.post(
        "/scan/credentialed",
        headers=auth_headers,
        json={"ip": "10.180.6.140", "username": "root", "password": "secret"},
    )
    assert response.status_code == 400
    assert "Cannot reach" in response.json()["detail"]


# ─────────────────────────────────────────────────────────────────────────────
# Authenticated readings supersede remote guesses
# ─────────────────────────────────────────────────────────────────────────────


def test_an_exact_host_version_replaces_an_open_ended_remote_guess():
    """
    Nmap reads PostgreSQL's handshake and can only conclude "9.6.0 or later" —
    an open-ended bound, which by design cannot disprove any CVE fixed after
    9.6. On a real host that left 34 CVEs reported against PostgreSQL 18.3,
    none of which affect it.
    """
    from scans.tasks.credentialed import _upgrade_network_fingerprints

    ports = [
        {
            "port": 5432,
            "protocol": "tcp",
            "product": "PostgreSQL DB",
            "version": "9.6.0 or later",
            "version_precision": "floor",
        }
    ]
    corrected = _upgrade_network_fingerprints(
        ports, [{"port": "5432", "product": "PostgreSQL", "version": "18.3"}]
    )

    assert corrected == {(5432, "tcp"): "18.3"}
    assert ports[0]["version"] == "18.3"
    assert ports[0]["version_precision"] == "exact"
    assert ports[0]["fingerprint_source"] == "credentialed"


def test_a_precise_remote_version_is_left_alone():
    """The scan already measured it exactly; there is nothing to improve."""
    from scans.tasks.credentialed import _upgrade_network_fingerprints

    ports = [
        {
            "port": 3306,
            "protocol": "tcp",
            "product": "MySQL",
            "version": "8.0.40",
            "version_precision": "exact",
        }
    ]
    corrected = _upgrade_network_fingerprints(
        ports, [{"port": "3306", "product": "MySQL Server", "version": "8.0.40.0"}]
    )

    assert corrected == {}
    assert ports[0]["version"] == "8.0.40"


def test_disagreeing_products_are_never_merged():
    """
    A forwarded port or a middlebox can put something else entirely behind the
    port the scanner reached. Stamping the local binary's version onto it would
    be worse than the imprecise fingerprint it replaced.
    """
    from scans.tasks.credentialed import _upgrade_network_fingerprints

    ports = [
        {
            "port": 8080,
            "protocol": "tcp",
            "product": "Apache Tomcat",
            "version": "9.0 or later",
        }
    ]
    corrected = _upgrade_network_fingerprints(
        ports, [{"port": "8080", "product": "Oracle XML DB", "version": "11.2.0.2"}]
    )

    assert corrected == {}
    assert ports[0]["version"] == "9.0 or later"


def test_an_inexact_host_version_is_not_promoted():
    """Only an exact host-side reading is better than the remote guess."""
    from scans.tasks.credentialed import _upgrade_network_fingerprints

    ports = [
        {
            "port": 5432,
            "protocol": "tcp",
            "product": "PostgreSQL",
            "version": "9.6.0 or later",
        }
    ]
    assert (
        _upgrade_network_fingerprints(
            ports, [{"port": "5432", "product": "PostgreSQL", "version": "18 or later"}]
        )
        == {}
    )


def test_findings_are_restated_only_on_the_corrected_port():
    """
    Verification reads the version recorded on the finding before it looks at
    the host's inventory, so correcting the inventory alone changes nothing.
    """
    from scans.tasks.credentialed import _restate_findings_for_corrected_ports

    findings = [
        {"cve_id": "CVE-A", "port": 5432, "detected_version": "9.6.0 or later"},
        {"cve_id": "CVE-B", "port": 22, "detected_version": "for_Windows_9.5"},
        {
            "cve_id": "CVE-C",
            "port": 5432,
            "protocol": "udp",
            "detected_version": "9.6.0 or later",
        },
    ]
    restated = _restate_findings_for_corrected_ports(findings, {(5432, "tcp"): "18.3"})

    assert restated == 1
    assert findings[0]["detected_version"] == "18.3"
    assert findings[1]["detected_version"] == "for_Windows_9.5"  # different port
    assert findings[2]["detected_version"] == "9.6.0 or later"  # different protocol


def test_correction_rules_out_the_inapplicable_and_keeps_the_real():
    """
    End to end through the real verifier: with the authenticated version in
    hand, a CVE fixed long before it is ruled out, and one that genuinely
    covers it survives — and is promoted from unverifiable to confirmed.
    """
    from scans.finding_normalizer import verify_host_findings

    from scans.tasks.credentialed import (
        _restate_findings_for_corrected_ports,
        _upgrade_network_fingerprints,
    )

    def cpe(end_excluding):
        return [
            {
                "criteria": "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*",
                "versionEndExcluding": end_excluding,
                "vulnerable": True,
            }
        ]

    host = {
        "ip_address": "10.0.0.5",
        "os_guess": "Microsoft Windows 11 Pro",
        "open_ports": [
            {
                "port": 5432,
                "protocol": "tcp",
                "product": "PostgreSQL DB",
                "version": "9.6.0 or later",
                "version_precision": "floor",
                "cpe": ["cpe:2.3:a:postgresql:postgresql:9.6:*:*:*:*:*:*:*"],
            }
        ],
        "cves": [
            {
                "cve_id": "CVE-2017-7546",
                "port": 5432,
                "severity": "Critical",
                "detected_version": "9.6.0 or later",
                "affected_software": cpe("9.6.4"),
            },
            {
                "cve_id": "CVE-2026-6473",
                "port": 5432,
                "severity": "High",
                "detected_version": "9.6.0 or later",
                "affected_software": cpe("18.4"),
            },
        ],
    }

    before = verify_host_findings(host)
    kept_before = {c["cve_id"] for c in before.verified}

    listeners = [{"port": "5432", "product": "PostgreSQL", "version": "18.3"}]
    corrected = _upgrade_network_fingerprints(host["open_ports"], listeners)
    _restate_findings_for_corrected_ports(host["cves"], corrected)
    after = verify_host_findings(host)
    kept_after = {c["cve_id"] for c in after.verified}

    # Fixed in 9.6.4 — 18.3 is far beyond it, so it does not apply here.
    assert "CVE-2017-7546" in kept_before
    assert "CVE-2017-7546" not in kept_after
    assert any("18.3" in item.reason for item in after.suppressed)

    # Fixed in 18.4 — 18.3 is inside the vulnerable range. A genuine finding
    # must survive the correction, not be swept up with the false ones.
    assert "CVE-2026-6473" in kept_after


def test_restating_a_finding_drops_what_was_derived_from_the_old_version():
    """
    The first verification pass derives a fixed version and an evidence block
    from the version it was given. Kept after the correction, "fixed in 14.23"
    — chosen while the version was only "9.6.0 or later" — was read back as if
    the feed had published it, and an 18.3 server was told to upgrade to 14.23.
    """
    from scans.tasks.credentialed import _restate_findings_for_corrected_ports

    derived = {
        "cve_id": "CVE-2026-6473",
        "port": 5432,
        "detected_version": "9.6.0 or later",
        "fixed_version": "14.23",
        "evidence": "Detected version  : 9.6.0 or later",
        "evidence_captured": False,
    }
    captured = {
        "cve_id": "CCURE-CHK-PG-SSL",
        "port": 5432,
        "detected_version": "9.6.0 or later",
        "evidence": "server answered N to SSLRequest",
        "evidence_captured": True,
    }
    _restate_findings_for_corrected_ports([derived, captured], {(5432, "tcp"): "18.3"})

    assert derived["detected_version"] == "18.3"
    assert "fixed_version" not in derived
    assert "evidence" not in derived
    # Scanner output is not ours to discard.
    assert captured["evidence"] == "server answered N to SSLRequest"


def test_a_corrected_version_gets_its_own_branchs_fixed_release():
    """End to end: scan #9's PostgreSQL record, before and after correction."""
    from scans.finding_normalizer import build_scan_report, verify_host_findings

    from scans.tasks.credentialed import (
        _restate_findings_for_corrected_ports,
        _upgrade_network_fingerprints,
    )

    branches = [
        {
            "criteria": "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*",
            "versionStartIncluding": start,
            "versionEndExcluding": end,
            "vulnerable": True,
        }
        for start, end in (
            (None, "14.23"),
            ("15.0", "15.18"),
            ("16.0", "16.14"),
            ("17.0", "17.10"),
            ("18.0", "18.4"),
        )
    ]
    host = {
        "ip_address": "10.180.6.30",
        "os_guess": "Microsoft Windows 11 Pro",
        "open_ports": [
            {
                "port": 5432,
                "protocol": "tcp",
                "product": "PostgreSQL DB",
                "version": "9.6.0 or later",
                "version_precision": "floor",
                "cpe": ["cpe:2.3:a:postgresql:postgresql:9.6:*:*:*:*:*:*:*"],
            }
        ],
        "cves": [
            {
                "cve_id": "CVE-2026-6473",
                "port": 5432,
                "severity": "High",
                "detected_version": "9.6.0 or later",
                "affected_software": [{"nodes": [{"cpeMatch": branches}]}],
            }
        ],
    }

    host.update(verify_host_findings(host).as_host_fields())
    listeners = [{"port": "5432", "product": "PostgreSQL", "version": "18.3"}]
    corrected = _upgrade_network_fingerprints(host["open_ports"], listeners)
    _restate_findings_for_corrected_ports(host["cves"], corrected)
    host.update(verify_host_findings(host).as_host_fields())

    (record,) = host["cves"]
    assert record["fixed_version"] == "18.4"
    assert "9.6.0 or later" not in (record.get("evidence") or "")

    (finding,) = build_scan_report({"data": [host]}).vulnerabilities
    assert finding.remediation.fixed_version == "18.4"
    assert "14.23" not in finding.remediation.summary
