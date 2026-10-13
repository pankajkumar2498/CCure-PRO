"""
A failed vulnerability-feed lookup is an unassessed host, never a clean one.

13 Oct 2026, scan #15: a credentialed audit of an Ubuntu 24.04 host
(10.180.6.45) collected 2,699 packages, the feed query failed with
"PGRES_TUPLES_OK and no message from the libpq", and the matcher caught it,
logged a warning and returned nothing. The scan completed with 17 findings —
all configuration and network — and a package coverage of
``packages_collected: 0``. The previous credentialed audit of the same host had
reported 824 package vulnerabilities. Nothing in the result said the inventory
had never been checked.
"""

from __future__ import annotations

from unittest.mock import patch

from engines.credentialed.vuln_matcher import VulnMatcher
from sqlalchemy.exc import OperationalError

PACKAGES = [
    {"name": "openssl", "version": "3.0.13-0ubuntu3.5", "source": "openssl"},
    {"name": "git", "version": "1:2.43.0-1ubuntu7.3", "source": "git"},
]


class _BrokenEngine:
    def connect(self):
        raise OperationalError(
            "SELECT …", {}, Exception('insufficient data in "D" message')
        )


def _failed_match():
    matcher = VulnMatcher()
    matcher.engine = _BrokenEngine()
    findings = matcher.match_packages(PACKAGES, os_id="ubuntu", os_version_id="24.04")
    return matcher, findings


def test_the_matcher_records_the_failure():
    matcher, findings = _failed_match()
    assert findings == []
    assert matcher.lookup_failures
    assert 'insufficient data in "D" message' in matcher.lookup_failures[0]


def test_coverage_counts_the_inventory_and_assesses_none_of_it():
    matcher, _ = _failed_match()
    coverage = matcher.coverage()
    # The inventory was collected: 2, not 0.
    assert coverage["packages_collected"] == 2
    # And none of it was checked against the feed.
    assert coverage["packages_assessable"] == 0
    assert coverage["coverage_pct"] == 0.0
    assert coverage["lookup_failures"] == matcher.lookup_failures


def test_a_successful_matcher_reports_no_failure():
    matcher = VulnMatcher()
    assert matcher.lookup_failures == []
    assert matcher.coverage()["lookup_failures"] == []


def _audit(coverage: dict):
    from core import tasks

    class StubConnection:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

    class StubCollector:
        def __init__(self, _ssh):
            pass

        def collect_all(self, sections=None, on_section_complete=None):
            return {
                "packages": list(PACKAGES),
                "os_id": "ubuntu",
                "os_version_id": "24.04",
            }

    class StubMatcher:
        def match_packages(self, *_args, **_kwargs):
            return []

        def coverage(self):
            return dict(coverage)

        def to_report_format(self, _findings):
            return []

    # The enrichment paths open connections to vuln_intel; this test is about
    # what the task does with a failure, so they are stubbed out.
    with patch(
        "engines.credentialed.ssh_scanner.SSHScanner", return_value=StubConnection()
    ), patch(
        "engines.credentialed.linux_collector.LinuxCollector", StubCollector
    ), patch(
        "engines.credentialed.vuln_matcher.VulnMatcher", StubMatcher
    ), patch(
        "engines.credentialed.os_detection.detect_os", return_value="linux"
    ), patch(
        "core.vuln_intel.csaf_advisories_for", return_value={}
    ), patch(
        "core.vuln_intel.exploit_intel_for", return_value={}
    ), patch(
        "engines.credentialed.csaf_matcher.CsafProductMatcher"
    ) as csaf, patch.object(
        tasks,
        "_run_configuration_audit",
        return_value=({"assessed": True, "results": []}, []),
    ):
        csaf.return_value.match.return_value = []
        csaf.return_value.coverage.return_value = {}
        report, _system_data, _os = tasks.audit_credentialed_host(
            ip="10.0.0.1", username="u", password="p", port=22
        )
    return {f.get("cve_id"): f for f in report["cves"]}


def test_the_audit_reports_the_packages_as_not_assessed():
    findings = _audit(
        {"packages_collected": 2, "lookup_failures": ["Batch OSV query: lost"]}
    )
    gap = findings["MISC-CREDENTIALED-PACKAGES-NOT-ASSESSED"]
    assert "2 installed packages were collected" in gap["description"]
    assert "unassessed, not clean" in gap["description"]
    assert "Batch OSV query: lost" in gap["description"]


def test_a_successful_lookup_raises_no_gap():
    findings = _audit({"packages_collected": 2, "lookup_failures": []})
    assert "MISC-CREDENTIALED-PACKAGES-NOT-ASSESSED" not in findings
