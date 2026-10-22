"""
tests/credentialed/test_enrichment_suppressions.py
─────────────────────────────────────────────────────────────────────────────
What a credentialed audit rules out must reach the vulnerability audit's
suppressed-candidates appendix.

The audit verifies its own findings and keeps only the survivors; the ones it
withheld travel in the stored report's ``suppressed_cves``. Credentialed
enrichment merged the survivors into the host record and dropped that list, so
on 10.180.6.30 (scan #10, 12 Oct 2026) 410 Chrome CVEs published for other
platforms were withheld with nothing in the report to say so.
"""

from testpaths import BACKEND_ROOT

import sys

sys.path.insert(0, str(BACKEND_ROOT))


def test_the_audits_own_suppressions_reach_the_host(monkeypatch, db_session):
    import scans.tasks.credentialed as tasks_mod

    material = {"username": "root", "password": "pw", "port": 22}
    monkeypatch.setattr(
        tasks_mod,
        "_credentialed_plan_for_scan",
        lambda db, scan_row: [{"material": material, "networks": None}],
    )

    withheld = {
        "identifier": "CVE-2026-0906",
        "host": "10.0.0.5",
        "reason": "Ruled out: this record is published for Android only, and "
        "this host runs Windows.",
    }
    stored_report = {
        "target": "10.0.0.5",
        "system_info": {"os_name": "Microsoft Windows 11 Pro"},
        "cves": [
            {
                "cve_id": "CVE-2025-10585",
                "severity": "Critical",
                "description": "Type confusion in V8 in Google Chrome prior to 140.0",
                "package": "Google Chrome",
                "installed_ver": "138.0.7204.184",
                "affected_software": [
                    {
                        "vendor": "google",
                        "product": "chrome",
                        "cpe_uri": "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
                        "version_end_excluding": "140.0.7339.185",
                    }
                ],
            }
        ],
        "packages": [{"name": "Google Chrome", "version": "138.0.7204.184"}],
        "suppressed_cves": [withheld],
        "candidates_evaluated": 2,
    }
    monkeypatch.setattr(
        tasks_mod,
        "audit_credentialed_host",
        lambda **_kw: (dict(stored_report), {}, "windows"),
    )

    hosts = [
        {
            "ip_address": "10.0.0.5",
            "is_active": True,
            "open_ports": [
                {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh"}
            ],
            "cves": [],
            "suppressed_cves": [
                {"identifier": "CVE-1999-0001", "host": "10.0.0.5", "reason": "x"}
            ],
            "candidates_evaluated": 4,
        }
    ]

    tasks_mod._apply_credentialed_enrichment(db_session, object(), hosts)
    host = hosts[0]

    assert [c["cve_id"] for c in host["cves"]] == ["CVE-2025-10585"]
    suppressed = {s["identifier"]: s for s in host["suppressed_cves"]}
    # The network phase's and the audit's, each once.
    assert set(suppressed) == {"CVE-1999-0001", "CVE-2026-0906"}
    assert suppressed["CVE-2026-0906"]["reason"] == withheld["reason"]
    assert len(host["suppressed_cves"]) == 2
    # Everything the audit evaluated — its survivor and what it withheld.
    assert host["candidates_evaluated"] == 4 + 2
