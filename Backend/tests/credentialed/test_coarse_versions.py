"""
tests/credentialed/test_coarse_versions.py
─────────────────────────────────────────────────────────────────────────────
An installed version that names only a release line cannot confirm a fix that
lands inside the line.

On 10.180.6.30 (12 Oct 2026) the inventory read Siemens TIA Portal as "V19".
CVE-2023-46280 is fixed in V19 Update 2 (19.0.2); reading "V19" as 19.0.0
reported it as Confirmed without knowing the update installed. TIA
Administrator "V3.0" against a fix in 3.0.6 had the same shape.
"""

from testpaths import BACKEND_ROOT

import sys

sys.path.insert(0, str(BACKEND_ROOT))

from engines.credentialed.csaf_matcher import CsafProductMatcher  # noqa: E402
from engines.credentialed.vuln_matcher import (  # noqa: E402
    CredentialedCVE,
    VulnMatcher,
    version_too_coarse,
)
from scans.finding_normalizer import Confidence, verify_host_findings  # noqa: E402


def test_a_version_shorter_than_its_bound_and_agreeing_with_it_is_too_coarse():
    assert version_too_coarse("V19", "19.0.2")
    assert version_too_coarse("V3.0", "3.0.6")
    # Decidable: they disagree on a component both state.
    assert not version_too_coarse("V2.12 Sp0 Upd0", "2.15.1.3")
    assert not version_too_coarse("V17", "18.0.1")
    # Decidable: as precise as the bound, or the bound adds only zeros.
    assert not version_too_coarse("19.00.0000", "19.0.4")
    assert not version_too_coarse("138.0.7204.184", "140.0.7339.185")
    assert not version_too_coarse("V3.0", "3.0.0")
    # Nothing to read.
    assert not version_too_coarse("", "19.0.2")
    assert not version_too_coarse("V19", "")


def test_the_cpe_matcher_marks_a_coarse_match():
    row = {"version_end_excluding": "3.0.6"}
    assert VulnMatcher._coarse_against("V3.0", row)
    assert not VulnMatcher._coarse_against("3.0.4", row)
    finding = CredentialedCVE(
        cve_id="CVE-2025-23365",
        severity="High",
        cvss_score=7.8,
        description="TIA Administrator.",
        package_name="TIA Administrator V3",
        installed_ver="V3.0",
        installed_version_precision="coarse",
    )
    (record,) = VulnMatcher.__new__(VulnMatcher).to_report_format([finding])
    assert record["installed_version_precision"] == "coarse"


def _csaf(constraint):
    return {
        "product_name": "Totally Integrated Automation Portal (TIA Portal) V19",
        "version_constraint": constraint,
        "cve_id": "CVE-2023-46280",
        "cvss_score": 6.5,
        "advisory_id": "SSA-962515",
        "provider": "siemens",
        "title": "SSA-962515",
        "url": "https://cert-portal.siemens.com/productcert/csaf/ssa-962515.json",
        "remediation": "Update to V19 Update 2 or later version",
    }


def test_the_csaf_matcher_marks_a_coarse_match_and_only_that(monkeypatch):
    matcher = CsafProductMatcher()
    monkeypatch.setattr(
        matcher,
        "_load_catalogue",
        lambda: [
            _csaf("vers:intdot/<19.0.2"),
            {**_csaf("vers:all/*"), "cve_id": "CVE-2024-49775"},
        ],
    )
    findings = {
        f["cve_id"]: f
        for f in matcher.match(
            [
                {
                    "name": "Siemens Totally Integrated Automation Portal V19",
                    "version": "V19",
                }
            ]
        )
    }
    assert findings["CVE-2023-46280"]["installed_version_precision"] == "coarse"
    # "Every version of V19" needs no update level to be true.
    assert findings["CVE-2024-49775"]["installed_version_precision"] == ""


def _credentialed(precision):
    return {
        "ip_address": "10.180.6.30",
        "os_guess": "Microsoft Windows 11 Pro",
        "cves": [
            {
                "cve_id": "CVE-2023-46280",
                "severity": "Medium",
                "description": "TIA Portal.",
                "package": "Siemens Totally Integrated Automation Portal V19",
                "installed_version": "V19",
                "detection_method": "credentialed_package",
                "installed_version_precision": precision,
            }
        ],
    }


def test_a_coarse_credentialed_match_is_potential_not_confirmed():
    (record,) = verify_host_findings(_credentialed("coarse")).verified
    assert record["confidence"] == Confidence.POTENTIAL.value
    assert record["detection_method"] == "version_imprecise"

    (record,) = verify_host_findings(_credentialed("")).verified
    assert record["confidence"] == Confidence.CONFIRMED.value
