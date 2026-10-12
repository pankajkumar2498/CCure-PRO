"""
tests/test_credentialed_end_to_end.py
────────────────────────────────────────────────────────────────────────────
The credentialed audit driven end to end against a stand-in SSH session, and
credentials used as a policy option on the Vulnerability Audit pipeline.

Everything the network touches is replaced with a deterministic double, so
these exercise the orchestration decisions — which hosts get authenticated to,
what happens when one is unreachable, how the two views are merged — rather
than the collectors, which have their own tests.
"""

import pytest
from engines.credentialed.coverage import bind_scope

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


class _FakeSSH:
    """Stands in for a live SSH session."""

    def __init__(self, *_a, **kw):
        self.ip = kw.get("ip")

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def run(self, command, timeout=None):
        from engines.credentialed.ssh_scanner import CommandResult

        if command == "uname -s":
            return CommandResult(stdout="Linux", exit_code=0, success=True)
        return CommandResult(stdout="", exit_code=1, success=False)


class _FakeMatcher:
    #: Records what the audit passed through, so a test can assert that the
    #: host's own release reached the matcher — without it OSV advisories are
    #: matched against every distribution in the database.
    last_os_id: str = ""
    last_os_version_id: str = ""

    def match_packages(self, packages, os_id: str = "", os_version_id: str = ""):
        type(self).last_os_id = os_id
        type(self).last_os_version_id = os_version_id
        self._seen = len(packages)
        return list(packages)

    def coverage(self):
        """Mirror of VulnMatcher.coverage() — how much was assessable."""
        seen = getattr(self, "_seen", 0)
        return {
            "packages_collected": seen,
            "packages_assessable": seen,
            "packages_cpe_resolved": seen,
            "advisory_source": None,
            "coverage_pct": 100.0 if seen else 0.0,
        }

    def to_report_format(self, findings):
        return [
            {
                "cve_id": f"CVE-2024-{1000 + i}",
                "package": f.get("name"),
                "installed_ver": f.get("version"),
                "severity": "High",
            }
            for i, f in enumerate(findings)
        ]


@pytest.fixture
def fake_scanner(monkeypatch):
    """Replace the SSH session, collector and matcher with doubles."""
    import core.tasks as tasks_mod
    from engines.credentialed import linux_collector, ssh_scanner, vuln_matcher

    monkeypatch.setattr(ssh_scanner, "PARAMIKO_AVAILABLE", True, raising=False)
    monkeypatch.setattr(ssh_scanner, "SSHScanner", _FakeSSH)

    class _FakeCollector:
        def __init__(self, ssh):
            self.ssh = ssh

        def collect_all(self, sections=None, on_section_complete=None):
            return {
                "os_name": "Ubuntu 22.04.4 LTS",
                "hostname": "web-01",
                "kernel_version": "5.15.0-91-generic",
                "packages": [{"name": "libxml2", "version": "2.9.13"}],
                "running_services": [{"name": "ufw"}],
                "open_ports_credentialed": [dict(r) for r in LISTENERS],
                "collection_errors": {},
            }

    monkeypatch.setattr(linux_collector, "LinuxCollector", _FakeCollector)
    monkeypatch.setattr(vuln_matcher, "VulnMatcher", _FakeMatcher)
    return tasks_mod


# ─────────────────────────────────────────────────────────────────────────────
# The audit itself
# ─────────────────────────────────────────────────────────────────────────────


def test_audit_states_its_coverage_and_settles_loopback_alone(fake_scanner):
    """
    The host-only audit resolves one exposure question without any help — a
    loopback bind — and must say plainly that it answered no others.
    """
    report, _system_data, os_type = fake_scanner.audit_credentialed_host(
        ip="10.0.0.5", username="root", password="pw", os_type_req="linux"
    )

    assert os_type == "linux"
    assert "Not scanned" in report["coverage"]["port_range"]
    assert "Not performed" in report["coverage"]["unauthenticated_checks"]

    by_port = {p["port"]: p for p in report["open_ports_credentialed"]}
    assert by_port["5432"]["exposure"] == "host_only"
    assert by_port["5432"]["bind_scope"] == bind_scope("127.0.0.1:5432")
    assert by_port["22"]["exposure"] == "undetermined"
    assert report["exposure_summary"]["listeners_host_only"] == 1


def test_audit_with_a_port_scan_reports_real_exposure(fake_scanner):
    report, _system_data, _os = fake_scanner.audit_credentialed_host(
        ip="10.0.0.5",
        username="root",
        password="pw",
        os_type_req="linux",
        network_ports=[{"port": 22, "protocol": "tcp", "state": "open"}],
        network_scanned=True,
        scanned_ports=[22, 5432, 9090],
    )

    assert "Determined" in report["coverage"]["network_reachability"]
    assert report["exposure_summary"]["listeners_exposed"] == 1
    assert report["exposure_summary"]["listeners_filtered"] == 1
    assert report["exposure_summary"]["listeners_host_only"] == 1


def test_audit_will_not_call_an_unprobed_port_filtered(fake_scanner):
    """
    Without the probed set, 9090 was never tested and must not be reported as
    blocked. Only the loopback verdict and the confirmed-open one survive.
    """
    report, _system_data, _os = fake_scanner.audit_credentialed_host(
        ip="10.0.0.5",
        username="root",
        password="pw",
        os_type_req="linux",
        network_ports=[{"port": 22, "protocol": "tcp", "state": "open"}],
        network_scanned=True,
    )

    assert report["exposure_summary"]["listeners_exposed"] == 1
    assert report["exposure_summary"]["listeners_filtered"] == 0
    assert report["exposure_summary"]["listeners_host_only"] == 1
    assert report["exposure_summary"]["listeners_undetermined"] == 1


# ─────────────────────────────────────────────────────────────────────────────
# Multi-host orchestration
# ─────────────────────────────────────────────────────────────────────────────


def _stub_persistence(monkeypatch, tasks_mod, captured):
    def _fake_completed_scan(**kwargs):
        captured.update(kwargs)

        class _Scan:
            id = "scn_fake"
            org_id = "org_fake"

        return _Scan()

    class _Orchestrator:
        def generate_phase_report(self, *_a):
            return {}

    monkeypatch.setattr(tasks_mod, "create_completed_scan", _fake_completed_scan)
    monkeypatch.setattr(
        tasks_mod, "_sync_credentialed_asset_identity", lambda *a, **k: None
    )
    monkeypatch.setattr(tasks_mod, "_new_orchestrator", lambda: _Orchestrator())


def test_an_unreachable_host_does_not_abandon_the_others(fake_scanner, monkeypatch):
    """
    A dead host must not discard the ones that were audited successfully — and
    must still be reported, because an omitted host reads as a clean one.
    """
    tasks_mod = fake_scanner
    real = tasks_mod.audit_credentialed_host

    def _flaky(**kwargs):
        if kwargs["ip"] == "10.0.0.6":
            raise RuntimeError(f"Cannot reach {kwargs['ip']}:22 — host is down")
        return real(**kwargs)

    monkeypatch.setattr(tasks_mod, "audit_credentialed_host", _flaky)
    captured = {}
    _stub_persistence(monkeypatch, tasks_mod, captured)

    result = tasks_mod.run_credentialed_scan_task(
        user_id="usr_1",
        targets=["10.0.0.5", "10.0.0.6", "10.0.0.7"],
        username="root",
        password="pw",
        os_type_req="linux",
    )

    assert result["success"] is True
    credentialed = captured["results"]["credentialed"]
    assert [r["target"] for r in credentialed["reports"]] == ["10.0.0.5", "10.0.0.7"]
    assert credentialed["hosts_failed"] == [
        {
            "target": "10.0.0.6",
            "status": "unreachable",
            "reason": "Cannot reach 10.0.0.6:22 — host is down",
        }
    ]
    # `report` repeats the first host for consumers predating multi-host audits.
    assert credentialed["report"] is credentialed["reports"][0]
    assert captured["summary"]["total_hosts"] == 3
    assert captured["summary"]["active_hosts"] == 2
    assert captured["summary"]["hosts_failed"] == 1
    assert captured["pipeline_mode"] == "credentialed"
    assert captured["targets"] == ["10.0.0.5", "10.0.0.6", "10.0.0.7"]


def test_every_host_failing_marks_the_scan_failed(fake_scanner, monkeypatch):
    """For a single target this is the same outcome the task always produced."""
    tasks_mod = fake_scanner

    def _always_fail(**kwargs):
        raise RuntimeError("SSH authentication failed for root@10.0.0.5")

    monkeypatch.setattr(tasks_mod, "audit_credentialed_host", _always_fail)
    marked = {}
    monkeypatch.setattr(
        tasks_mod,
        "mark_scan_failed",
        lambda db, sid, uid, reason, status=None: marked.update(
            {"reason": reason, "status": status}
        ),
    )

    result = tasks_mod.run_credentialed_scan_task(
        user_id="usr_1",
        targets=["10.0.0.5"],
        username="root",
        password="pw",
        scan_id="scn_x",
    )

    assert result["success"] is False
    assert "authentication failed" in result["error"]
    assert marked["status"] == "failed"


def test_unreachable_single_host_keeps_its_distinct_status(fake_scanner, monkeypatch):
    """ "Unreachable" and "failed" drive different UI, so they must stay apart."""
    tasks_mod = fake_scanner

    def _unreachable(**kwargs):
        raise RuntimeError("Cannot reach 10.0.0.5:22 — no route to host")

    monkeypatch.setattr(tasks_mod, "audit_credentialed_host", _unreachable)
    marked = {}
    monkeypatch.setattr(
        tasks_mod,
        "mark_scan_failed",
        lambda db, sid, uid, reason, status=None: marked.update({"status": status}),
    )

    tasks_mod.run_credentialed_scan_task(
        user_id="usr_1",
        targets=["10.0.0.5"],
        username="root",
        password="pw",
        scan_id="scn_y",
    )
    assert marked["status"] == "unreachable"


# ─────────────────────────────────────────────────────────────────────────────
# Credentials as a policy option on the Vulnerability Audit
# ─────────────────────────────────────────────────────────────────────────────


def test_credentials_enrich_the_audit_pipeline_in_place(
    fake_scanner, monkeypatch, db_session
):
    """
    The industry model: one scan, both views. The authenticated findings land
    on the same host record the port scan produced, and the host's ports gain
    the confirmation from both sides.
    """
    tasks_mod = fake_scanner
    material = {"username": "root", "password": "pw", "port": 22, "key_content": None}
    monkeypatch.setattr(
        tasks_mod,
        "_credentialed_plan_for_scan",
        lambda db, scan_row: [{"material": material, "networks": None}],
    )

    hosts = [
        {
            "ip_address": "10.0.0.5",
            "is_active": True,
            "os_guess": "Linux (generic)",
            "os_confidence": "Low",
            "open_ports": [
                {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh"}
            ],
            "cves": [],
            "suppressed_cves": [
                {
                    "identifier": "CVE-1999-0001",
                    "host": "10.0.0.5",
                    "reason": "Ruled out",
                }
            ],
            "candidates_evaluated": 4,
        },
        # Inactive hosts are never authenticated to.
        {"ip_address": "10.0.0.9", "is_active": False, "open_ports": []},
    ]

    summary = tasks_mod._apply_credentialed_enrichment(db_session, object(), hosts)
    host = hosts[0]

    assert host["credentialed"] is True
    assert summary["credentialed_hosts"] == 1
    assert "Determined" in summary["network_reachability"]

    # An OS read from inside the machine outranks a stack fingerprint.
    assert host["os_guess"] == "Ubuntu 22.04.4 LTS"
    assert host["os_confidence"] == "High"

    # The package finding survived verification on a host that also has
    # fingerprinted network services.
    assert [c["cve_id"] for c in host["cves"]] == ["CVE-2024-1000"]

    # Both correlation directions are recorded.
    assert host["open_ports"][0]["credentialed_confirmed"] is True
    assert host["exposure_summary"]["listeners_exposed"] == 1

    # Re-verification must not erase what phase 3 already ruled out.
    assert any(s["identifier"] == "CVE-1999-0001" for s in host["suppressed_cves"])
    assert host["candidates_evaluated"] == 5

    assert "credentialed" not in hosts[1]


def test_enriched_host_carries_posture_not_the_package_inventory(
    fake_scanner, monkeypatch, db_session
):
    """
    A few thousand package rows per host would be carried in the stored scan
    payload for no reader. The findings already hold what the packages proved,
    so the enrichment resolves each listening process to its package up front
    and keeps only what nothing else carries.
    """
    tasks_mod = fake_scanner
    material = {"username": "root", "password": "pw", "port": 22, "key_content": None}
    monkeypatch.setattr(
        tasks_mod,
        "_credentialed_plan_for_scan",
        lambda db, scan_row: [{"material": material, "networks": None}],
    )

    hosts = [
        {
            "ip_address": "10.0.0.5",
            "is_active": True,
            "open_ports": [{"port": 22, "protocol": "tcp", "state": "open"}],
            "cves": [],
        }
    ]
    tasks_mod._apply_credentialed_enrichment(db_session, object(), hosts)

    stored = hosts[0]["credentialed_report"]
    assert "packages" not in stored
    assert stored["package_count"] == 1
    assert stored["system_info"]["os_name"] == "Ubuntu 22.04.4 LTS"
    assert stored["coverage"] and stored["hardening_audits"]


def test_prepared_listener_product_survives_to_the_service_row(db_session):
    """
    The asset sync must use the product the enrichment already resolved rather
    than silently dropping it because no package list reached it.
    """
    import uuid

    from db.base import utcnow
    from db.models.assets import Asset
    from db.models.findings import Service
    from db.models.rbac import Organization
    from db.models.scans import Scan
    from scans.asset_syncer import upsert_credentialed_services

    org_id = f"org_test_{uuid.uuid4().hex[:8]}"
    db_session.add(
        Organization(
            id=org_id,
            name="P",
            slug=f"p-{uuid.uuid4().hex[:8]}",
            is_active=True,
            settings={},
        )
    )
    db_session.commit()
    asset = Asset(
        id=f"ast_{org_id}_10_0_0_5",
        org_id=org_id,
        ip_address="10.0.0.5",
        last_seen_at=utcnow(),
    )
    db_session.add(asset)
    scan_id = f"scn_{uuid.uuid4().hex[:8]}"
    db_session.add(
        Scan(
            id=scan_id,
            org_id=org_id,
            target_str="10.0.0.5",
            scan_type="credentialed",
            pipeline_mode="credentialed",
        )
    )
    db_session.commit()

    upsert_credentialed_services(
        db_session,
        asset.id,
        scan_id,
        [
            {
                "port": "22",
                "local_addr": "0.0.0.0:22",
                "process": "sshd",
                "product": "openssh-server",
                "version": "8.9p1",
            }
        ],
    )
    db_session.commit()

    row = (
        db_session.query(Service)
        .filter(Service.asset_id == asset.id, Service.port == 22)
        .one()
    )
    assert row.service_product == "openssh-server"
    assert row.service_version == "8.9p1"


def test_enrichment_skips_hosts_whose_ssh_port_is_closed(
    fake_scanner, monkeypatch, db_session
):
    """
    The port scan already established what is reachable. Spending a 20-second
    handshake per host to relearn it would add minutes to a large scan.
    """
    tasks_mod = fake_scanner
    material = {"username": "root", "password": "pw", "port": 22, "key_content": None}
    monkeypatch.setattr(
        tasks_mod,
        "_credentialed_plan_for_scan",
        lambda db, scan_row: [{"material": material, "networks": None}],
    )

    attempted = []
    monkeypatch.setattr(
        tasks_mod,
        "audit_credentialed_host",
        lambda **kw: attempted.append(kw["ip"]),
    )

    hosts = [
        {
            "ip_address": "10.0.0.8",
            "is_active": True,
            "open_ports": [{"port": 443, "protocol": "tcp", "state": "open"}],
        }
    ]
    summary = tasks_mod._apply_credentialed_enrichment(db_session, object(), hosts)

    assert attempted == []
    assert summary["credentialed_hosts"] == 0
    assert "not open" in summary["credentialed_skipped"][0]["reason"]


def test_a_failed_login_does_not_fail_the_scan(fake_scanner, monkeypatch, db_session):
    """
    The unauthenticated results are valid and worth delivering. A credential
    that does not work is recorded in coverage, not raised.
    """
    tasks_mod = fake_scanner
    material = {"username": "root", "password": "pw", "port": 22, "key_content": None}
    monkeypatch.setattr(
        tasks_mod,
        "_credentialed_plan_for_scan",
        lambda db, scan_row: [{"material": material, "networks": None}],
    )
    monkeypatch.setattr(
        tasks_mod,
        "audit_credentialed_host",
        lambda **kw: (_ for _ in ()).throw(RuntimeError("SSH authentication failed")),
    )

    hosts = [
        {
            "ip_address": "10.0.0.5",
            "is_active": True,
            "open_ports": [{"port": 22, "protocol": "tcp", "state": "open"}],
            "cves": [],
        }
    ]
    summary = tasks_mod._apply_credentialed_enrichment(db_session, object(), hosts)

    assert summary["credentialed_hosts"] == 0
    assert "authentication failed" in summary["credentialed_skipped"][0]["reason"]
    assert "credentialed" not in hosts[0]


def test_no_credentials_configured_leaves_the_scan_untouched(db_session):
    """An ordinary unauthenticated audit must be unaffected by any of this."""
    import core.tasks as tasks_mod

    class _ScanRow:
        id = "scn_1"
        options = {}

    hosts = [{"ip_address": "10.0.0.5", "is_active": True, "open_ports": []}]
    assert (
        tasks_mod._apply_credentialed_enrichment(db_session, _ScanRow(), hosts) is None
    )
    assert "credentialed" not in hosts[0]


def test_a_malformed_credential_entry_is_skipped_not_fatal(db_session):
    """One unusable credential must not take the whole scan down with it."""
    import core.tasks as tasks_mod

    class _ScanRow:
        id = "scn_1"
        options = {"credentials": [{"no_credential_id": True}, "  "]}

    assert tasks_mod._credentialed_plan_for_scan(db_session, _ScanRow()) == []
