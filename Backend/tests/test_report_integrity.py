"""
tests/test_report_integrity.py
─────────────────────────────────────────────────────────────────────────────
Regression tests asserting that the report pipeline never fabricates data.

These lock in the behaviours that separate a defensible audit report from a
plausible-looking one:

  * CVSS scores are recomputed from the published vector, and disagreements
    with the feed are disclosed.
  * A CVE is only bound to a port the scan actually observed carrying the
    affected product.
  * A detected version outside the vulnerable range suppresses the finding.
  * Remediation text is never invented for a CVE with no published fix.
  * Evidence is never synthesized to look like captured plugin output.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scans.cvss import parse_cvss_vector, severity_from_score  # noqa: E402
from scans.finding_normalizer import (  # noqa: E402
    Confidence,
    DetectionMethod,
    RemediationConfidence,
    build_scan_report,
)

# ─────────────────────────────────────────────────────────────────────────────
# CVSS correctness
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "vector,expected",
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0),
        ("AV:N/AC:L/Au:N/C:P/I:P/A:P", 7.5),
    ],
)
def test_cvss_base_scores_match_published_values(vector, expected):
    parsed = parse_cvss_vector(vector)
    assert parsed is not None
    assert parsed.computed_score == expected


def test_absent_vector_is_not_scored():
    """No vector must yield no score — never a substituted value."""
    assert parse_cvss_vector("") is None
    assert parse_cvss_vector(None) is None
    assert severity_from_score(None) == "Unscored"


def test_score_vector_mismatch_is_disclosed():
    """
    The old generator emitted a 9.9 alongside a vector that evaluates to 10.0.
    That contradiction must now surface as an explicit warning.
    """
    parsed = parse_cvss_vector(
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", feed_score=9.9
    )
    assert parsed.computed_score == 10.0
    assert any("mismatch" in w.lower() for w in parsed.integrity_warnings)


def test_network_vector_on_local_only_cve_is_flagged():
    parsed = parse_cvss_vector(
        "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", feed_score=9.3
    )
    assert parsed.is_local_only
    assert any("local or physical" in w for w in parsed.integrity_warnings)


# ─────────────────────────────────────────────────────────────────────────────
# Detection accuracy
# ─────────────────────────────────────────────────────────────────────────────


def _payload(services, cves):
    return {
        "metadata": {"target": "10.0.0.5", "scan_no": "SCAN-TEST-1"},
        "data": [
            {
                "ip_address": "10.0.0.5",
                "hostname": "db-01",
                "os_guess": "Ubuntu 22.04",
                "open_ports": services,
                "cves": cves,
            }
        ],
    }


POSTGRES_CPE = [
    {
        "vendor": "postgresql",
        "product": "postgresql",
        "versionEndExcluding": "9.6.6",
        "cpe23Uri": "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*",
    }
]


def test_version_inside_range_is_confirmed():
    result = _payload(
        [
            {
                "port": 5432,
                "protocol": "tcp",
                "service": "postgresql",
                "product": "PostgreSQL DB",
                "version": "9.6.2",
            }
        ],
        [
            {
                "cve_id": "CVE-2017-7546",
                "title": "PostgreSQL Authentication Bypass",
                "description": "Empty password accepted.",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "cvss_v3_score": 9.8,
                "affected_software": POSTGRES_CPE,
                "port": 5432,
            }
        ],
    )
    report = build_scan_report(result)
    findings = report.vulnerabilities

    assert len(findings) == 1
    assert findings[0].confidence == Confidence.CONFIRMED
    assert findings[0].detection_method == DetectionMethod.VERSION_MATCH
    assert findings[0].port == 5432
    assert findings[0].cvss_score == 9.8


def test_version_outside_range_is_suppressed():
    """
    A patched PostgreSQL 16 host must not inherit 2005-era PostgreSQL CVEs.
    This is the check that eliminated the bulk of the old false positives.
    """
    result = _payload(
        [
            {
                "port": 5432,
                "protocol": "tcp",
                "service": "postgresql",
                "product": "PostgreSQL DB",
                "version": "16.2",
            }
        ],
        [
            {
                "cve_id": "CVE-2017-7546",
                "title": "PostgreSQL Authentication Bypass",
                "description": "Empty password accepted.",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "affected_software": POSTGRES_CPE,
                "port": 5432,
            }
        ],
    )
    report = build_scan_report(result)

    assert report.vulnerabilities == []
    assert len(report.excluded) == 1
    reason = report.excluded[0].reason
    assert "outside the vulnerable range" in reason
    # The reason must name the version that disproved it, so the suppression
    # can be audited rather than taken on trust.
    assert "16.2" in reason


def test_unrelated_product_is_not_bound_to_open_port():
    """
    A PuTTY (SSH client) CVE must not attach itself to an open SSH port, which
    is what naive product-name matching against CVE prose produced.
    """
    result = _payload(
        [
            {
                "port": 22,
                "protocol": "tcp",
                "service": "ssh",
                "product": "OpenSSH",
                "version": "8.9p1",
            }
        ],
        [
            {
                "cve_id": "CVE-2004-1440",
                "title": "PuTTY modpow Buffer Overflow",
                "description": "Heap overflow in the modpow function in PuTTY before 0.55 "
                "allows remote attackers to execute arbitrary code via SSH2.",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "affected_software": [
                    {
                        "vendor": "putty",
                        "product": "putty",
                        "versionEndExcluding": "0.55",
                    }
                ],
            }
        ],
    )
    report = build_scan_report(result)

    assert report.vulnerabilities == []
    assert any(e.identifier == "CVE-2004-1440" for e in report.excluded)


#: CPE shaped exactly as core/cve_database.py returns it: cpe_uri plus
#: snake_case version bounds, with an inclusive upper bound.
DB_SHAPED_CPE = [
    {
        "cpe_uri": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
        "vendor": "openbsd",
        "product": "openssh",
        "version_start_including": "6.2",
        "version_end_including": "8.7",
    }
]


def _ssh_payload(version):
    return _payload(
        [
            {
                "port": 22,
                "protocol": "tcp",
                "service": "ssh",
                "product": "OpenSSH",
                "version": version,
            }
        ],
        [
            {
                "cve_id": "CVE-2021-41617",
                "title": "OpenSSH privilege escalation",
                "description": "sshd in OpenSSH 6.2 through 8.7 allows privilege escalation.",
                "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H",
                "affected_software": DB_SHAPED_CPE,
                "port": 22,
                "protocol": "tcp",
                "detected_version": version,
                # The scanner asserts it verified the version. That claim must not
                # be allowed to bypass the published range check.
                "evidence_source": "version_match",
            }
        ],
    )


#: The shape the CVE database actually stores for ~98% of records: the raw
#: NVD `configurations` tree rather than flat CPE dicts.
NVD_NESTED_CONFIGURATIONS = [
    {
        "nodes": [
            {
                "operator": "OR",
                "negate": False,
                "cpeMatch": [
                    {
                        "vulnerable": True,
                        "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                        "versionStartIncluding": "6.2",
                        "versionEndIncluding": "8.7",
                    },
                    {
                        # Platform context, not an affected product. Treating
                        # this as vulnerable would manufacture false positives.
                        "vulnerable": False,
                        "criteria": "cpe:2.3:o:canonical:ubuntu_linux:20.04:*:*:*:*:*:*:*",
                    },
                ],
            }
        ]
    }
]


def test_nested_nvd_configurations_are_flattened():
    """
    Version matching must understand the raw NVD configurations tree. If it
    does not, CPE matching silently does nothing on real data and every
    finding degrades to unverified.
    """
    from scans.finding_normalizer import _cpe_products

    cpes = _cpe_products(NVD_NESTED_CONFIGURATIONS)

    # The non-vulnerable platform entry must be excluded.
    assert len(cpes) == 1
    assert cpes[0]["product"] == "openssh"
    assert cpes[0]["vendor"] == "openbsd"
    assert cpes[0]["versionEndIncluding"] == "8.7"


def test_nested_nvd_configurations_drive_confirmation_and_suppression():
    def payload(version):
        return _payload(
            [
                {
                    "port": 22,
                    "protocol": "tcp",
                    "service": "ssh",
                    "product": "OpenSSH",
                    "version": version,
                }
            ],
            [
                {
                    "cve_id": "CVE-2021-41617",
                    "title": "OpenSSH privilege escalation",
                    "description": "sshd in OpenSSH 6.2 through 8.7 allows privilege escalation.",
                    "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H",
                    "affected_software": NVD_NESTED_CONFIGURATIONS,
                    "port": 22,
                }
            ],
        )

    assert len(build_scan_report(payload("8.2p1")).vulnerabilities) == 1
    assert build_scan_report(payload("9.6p1")).vulnerabilities == []


def test_scanner_claim_cannot_bypass_version_range_check():
    """
    A scanner-supplied 'version_match' hint is a claim, not a verification.
    Honouring it blindly would keep findings alive on hosts the published
    range disproves.
    """
    report = build_scan_report(_ssh_payload("9.6p1"))
    assert report.vulnerabilities == []
    assert "9.6p1" in report.excluded[0].reason


def _mysql_payload(affected):
    return _payload(
        [
            {
                "port": 3306,
                "protocol": "tcp",
                "service": "mysql",
                "product": "MySQL",
                "version": "8.0.40",
            }
        ],
        [
            {
                "cve_id": "CVE-2025-30722",
                "title": "MySQL Server unspecified vulnerability",
                "description": "Difficult to exploit vulnerability in MySQL Server.",
                "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "affected_software": affected,
                "port": 3306,
            }
        ],
    )


def _pinned(version):
    return {
        "vendor": "oracle",
        "product": "mysql",
        "cpe23Uri": f"cpe:2.3:a:oracle:mysql:{version}:*:*:*:*:*:*:*",
    }


def test_matching_affected_entry_is_found_wherever_it_sits_in_the_list():
    """
    Oracle publishes one pinned CPE per released version, and F5 publishes one
    range per supported nginx branch, so a CVE's affected list routinely holds
    dozens of entries of which exactly one covers the detected version. Ruling
    the record out on the first entry that does not match discarded real
    findings purely on feed ordering — MySQL 8.0.40 produced zero findings
    while every one of its CVEs sat in the suppressed appendix.
    """
    report = build_scan_report(
        _mysql_payload([_pinned("5.7.1"), _pinned("8.0.39"), _pinned("8.0.40")])
    )

    assert len(report.vulnerabilities) == 1
    assert report.vulnerabilities[0].confidence == Confidence.CONFIRMED
    assert report.excluded == []


def test_affected_entry_order_does_not_change_the_verdict():
    """The same feed data must confirm regardless of the order it arrives in."""
    entries = [_pinned("5.7.1"), _pinned("8.0.40")]
    forward = build_scan_report(_mysql_payload(entries))
    reversed_ = build_scan_report(_mysql_payload(list(reversed(entries))))

    assert len(forward.vulnerabilities) == len(reversed_.vulnerabilities) == 1
    assert (
        forward.vulnerabilities[0].detection_method
        == reversed_.vulnerabilities[0].detection_method
        == DetectionMethod.VERSION_MATCH
    )


def test_branch_range_that_excludes_the_host_does_not_hide_the_one_that_covers_it():
    """
    nginx CVEs are published as one range per supported branch. 1.26.3 is
    outside the 1.28.x branch range but inside the 1.25-1.27 one, and the
    finding must survive the first range being tested first.
    """
    report = build_scan_report(
        _payload(
            [
                {
                    "port": 80,
                    "protocol": "tcp",
                    "service": "http",
                    "product": "nginx",
                    "version": "1.26.3",
                }
            ],
            [
                {
                    "cve_id": "CVE-2026-40701",
                    "title": "nginx ngx_http_ssl_module use-after-free",
                    "description": "Heap use-after-free in the NGINX worker process.",
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L",
                    "affected_software": [
                        {
                            "vendor": "f5",
                            "product": "nginx",
                            "versionStartIncluding": "1.28.0",
                            "versionEndExcluding": "1.28.2",
                            "cpe23Uri": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
                        },
                        {
                            "vendor": "f5",
                            "product": "nginx",
                            "versionStartIncluding": "1.25.0",
                            "versionEndExcluding": "1.27.4",
                            "cpe23Uri": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
                        },
                    ],
                    "port": 80,
                }
            ],
        )
    )

    assert len(report.vulnerabilities) == 1
    assert report.vulnerabilities[0].confidence == Confidence.CONFIRMED


def test_record_is_still_disproved_when_no_affected_entry_covers_the_host():
    """
    Evaluating the whole affected list must not weaken the disproof: when every
    entry excludes the detected version the finding is still suppressed, and the
    reason still names the version that ruled it out.
    """
    report = build_scan_report(
        _mysql_payload([_pinned("5.7.1"), _pinned("8.0.39"), _pinned("8.4.0")])
    )

    assert report.vulnerabilities == []
    assert len(report.excluded) == 1
    assert "outside the vulnerable range" in report.excluded[0].reason
    assert "8.0.40" in report.excluded[0].reason


def test_db_shaped_cpe_keys_are_understood():
    """cpe_uri + snake_case bounds is the shape the CVE database emits."""
    report = build_scan_report(_ssh_payload("8.2p1"))
    assert len(report.vulnerabilities) == 1
    assert report.vulnerabilities[0].confidence == Confidence.CONFIRMED


def test_version_below_start_of_range_is_suppressed():
    report = build_scan_report(_ssh_payload("5.9p1"))
    assert report.vulnerabilities == []


def test_inclusive_upper_bound_produces_upgrade_past_wording():
    """
    versionEndIncluding names the last *vulnerable* release, so the guidance
    must say "later than", not "upgrade to" that same version.
    """
    remediation = (
        build_scan_report(_ssh_payload("8.2p1")).vulnerabilities[0].remediation
    )
    assert remediation.fixed_version == "8.7"
    assert "later than 8.7" in remediation.summary


def test_finding_without_cpe_data_is_withheld_but_retained():
    """
    A finding with no CPE range cannot be verified against the detected
    version. Following the OpenVAS QoD model (and Nessus's default of hiding
    potential false alarms), it is kept out of the report body but retained in
    the suppressed-candidates list so the suppression stays auditable.
    """
    result = _payload(
        [
            {
                "port": 22,
                "protocol": "tcp",
                "service": "ssh",
                "product": "OpenSSH",
                "version": "8.2p1",
            }
        ],
        [
            {
                "cve_id": "CVE-2021-41617",
                "title": "OpenSSH privilege escalation",
                "description": "sshd in OpenSSH 6.2 through 8.7 allows privilege escalation.",
                "severity": "High",
                "cvss_score": 7.0,
                "affected_software": [],
                "evidence_source": "vulnerability_audit",
                "plugin_output": "OpenSSH 8.2p1 detected on port 22",
            }
        ],
    )
    report = build_scan_report(result)

    assert report.vulnerabilities == []
    assert len(report.excluded) == 1
    # Withheld for low confidence, not because it was disproved.
    assert "confidence threshold" in report.excluded[0].reason


def test_kev_findings_are_shown_even_below_the_qod_threshold():
    """
    Missing an actively-exploited vulnerability is worse than showing one
    unverified line, so KEV entries bypass the confidence gate.
    """
    result = _payload(
        [
            {
                "port": 3389,
                "protocol": "tcp",
                "service": "ms-wbt-server",
                "product": "Microsoft Terminal Services",
            }
        ],
        [
            {
                "cve_id": "CVE-2019-0708",
                "title": "BlueKeep RDP RCE",
                "description": "Remote code execution in Remote Desktop Services.",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "affected_software": [],
                "in_kev": True,
                "kev_due_date": "2026-08-01",
            }
        ],
    )
    report = build_scan_report(result)

    assert len(report.vulnerabilities) == 1
    finding = report.vulnerabilities[0]
    assert finding.in_kev
    assert finding.qod < 70  # would normally be withheld


def test_host_with_no_service_inventory_is_withheld_not_ruled_out():
    """Applicability cannot be disproved when nothing was enumerated."""
    result = _payload(
        [],
        [
            {
                "cve_id": "CVE-2017-7546",
                "title": "PostgreSQL Authentication Bypass",
                "description": "Empty password accepted.",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "affected_software": POSTGRES_CPE,
            }
        ],
    )
    report = build_scan_report(result)

    assert report.vulnerabilities == []
    assert "confidence threshold" in report.excluded[0].reason
    assert "Ruled out" not in report.excluded[0].reason


def test_zero_score_without_vector_is_unscored_not_none():
    """
    A 0.0 with no vector means the feed published no score. Treating it as a
    genuine zero produced reports where every finding read '0.0 / NONE' and the
    severity columns were all zero.
    """
    result = _payload(
        [
            {
                "port": 5432,
                "protocol": "tcp",
                "service": "postgresql",
                "product": "PostgreSQL DB",
                "version": "9.6.2",
            }
        ],
        [
            {
                "cve_id": "CVE-2017-7546",
                "title": "PostgreSQL Authentication Bypass",
                "description": "Empty password accepted.",
                "cvss_score": 0.0,
                "affected_software": POSTGRES_CPE,
                "port": 5432,
            }
        ],
    )
    finding = build_scan_report(result).vulnerabilities[0]

    assert finding.severity == "Unscored"
    assert finding.cvss_score is None


def test_confirmation_works_without_recorded_port_binding():
    """
    asset_syncer does not persist service_id, so findings arrive with no port.
    Matching must still fall back to the host's service inventory.
    """
    result = _payload(
        [
            {
                "port": 5432,
                "protocol": "tcp",
                "service": "postgresql",
                "product": "PostgreSQL DB",
                "version": "9.6.2",
            }
        ],
        [
            {
                "cve_id": "CVE-2017-7546",
                "title": "PostgreSQL Authentication Bypass",
                "description": "Empty password accepted.",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "affected_software": POSTGRES_CPE,
                # no port / service_id recorded
            }
        ],
    )
    report = build_scan_report(result)

    assert len(report.vulnerabilities) == 1
    assert report.vulnerabilities[0].confidence == Confidence.CONFIRMED


def test_product_present_without_version_is_withheld():
    """
    The product is present but its version is unknown, so the finding cannot be
    checked against the vulnerable range. It is classed Potential and, being
    below the QoD threshold, kept out of the report body.
    """
    result = _payload(
        [
            {
                "port": 5432,
                "protocol": "tcp",
                "service": "postgresql",
                "product": "PostgreSQL DB",
                "version": "",
            }
        ],
        [
            {
                "cve_id": "CVE-2017-7546",
                "title": "PostgreSQL Authentication Bypass",
                "description": "Empty password accepted.",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "affected_software": POSTGRES_CPE,
                "port": 5432,
            }
        ],
    )
    report = build_scan_report(result)

    assert report.vulnerabilities == []
    assert len(report.excluded) == 1
    assert "confidence threshold" in report.excluded[0].reason


# ─────────────────────────────────────────────────────────────────────────────
# Content honesty
# ─────────────────────────────────────────────────────────────────────────────


def test_remediation_is_not_invented_when_no_fix_published():
    result = _payload(
        [
            {
                "port": 5432,
                "protocol": "tcp",
                "service": "postgresql",
                "product": "PostgreSQL DB",
                "version": "9.6.2",
            }
        ],
        [
            {
                "cve_id": "CVE-2017-7546",
                "title": "PostgreSQL Authentication Bypass",
                "description": "Empty password accepted.",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                # A lower bound only: the detected version confirms as in-range,
                # but no fixed version is published to derive remediation from.
                "affected_software": [
                    {
                        "vendor": "postgresql",
                        "product": "postgresql",
                        "versionStartIncluding": "9.0",
                    }
                ],
                "references": [],
                "port": 5432,
            }
        ],
    )
    report = build_scan_report(result)
    remediation = report.vulnerabilities[0].remediation

    assert remediation.confidence == RemediationConfidence.NONE_PUBLISHED
    assert "No fixed version" in remediation.summary
    assert not remediation.is_actionable


def test_remediation_uses_real_cpe_boundary():
    result = _payload(
        [
            {
                "port": 5432,
                "protocol": "tcp",
                "service": "postgresql",
                "product": "PostgreSQL DB",
                "version": "9.6.2",
            }
        ],
        [
            {
                "cve_id": "CVE-2017-7546",
                "title": "PostgreSQL Authentication Bypass",
                "description": "Empty password accepted.",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "affected_software": POSTGRES_CPE,
                "port": 5432,
            }
        ],
    )
    remediation = build_scan_report(result).vulnerabilities[0].remediation

    assert remediation.confidence == RemediationConfidence.VERSION_BOUNDARY
    assert remediation.fixed_version == "9.6.6"
    assert "9.6.6" in remediation.summary


def test_evidence_is_not_synthesized_as_plugin_output():
    """
    With no scanner output, evidence may summarise observed facts but must not
    claim to be captured plugin output.
    """
    result = _payload(
        [
            {
                "port": 5432,
                "protocol": "tcp",
                "service": "postgresql",
                "product": "PostgreSQL DB",
                "version": "9.6.2",
            }
        ],
        [
            {
                "cve_id": "CVE-2017-7546",
                "title": "PostgreSQL Authentication Bypass",
                "description": "Empty password accepted.",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "affected_software": POSTGRES_CPE,
                "port": 5432,
            }
        ],
    )
    finding = build_scan_report(result).vulnerabilities[0]

    assert finding.evidence_available is False
    assert "Vulnerable component matching" not in finding.evidence
    assert "9.6.2" in finding.evidence


def test_real_plugin_output_is_preserved_and_marked():
    result = _payload(
        [
            {
                "port": 5432,
                "protocol": "tcp",
                "service": "postgresql",
                "product": "PostgreSQL DB",
                "version": "9.6.2",
            }
        ],
        [
            {
                "cve_id": "CVE-2017-7546",
                "title": "PostgreSQL Authentication Bypass",
                "description": "Empty password accepted.",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "affected_software": POSTGRES_CPE,
                "plugin_output": "  Installed : 9.6.2\n  Fixed in  : 9.6.6",
                "port": 5432,
            }
        ],
    )
    finding = build_scan_report(result).vulnerabilities[0]

    assert finding.evidence_available is True
    assert "Installed : 9.6.2" in finding.evidence


def test_titles_are_taken_from_feed_not_regex_derived():
    result = _payload(
        [
            {
                "port": 5432,
                "protocol": "tcp",
                "service": "postgresql",
                "product": "PostgreSQL DB",
                "version": "9.6.2",
            }
        ],
        [
            {
                "cve_id": "CVE-2017-7546",
                "title": "PostgreSQL Postgresql Authentication Bypass",
                "description": "Unknown vulnerability in something before entering a chroot jail.",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "affected_software": POSTGRES_CPE,
                "port": 5432,
            }
        ],
    )
    finding = build_scan_report(result).vulnerabilities[0]

    assert finding.plugin_name == "PostgreSQL Postgresql Authentication Bypass"
    assert "Vulnerabil Vulnerability" not in finding.plugin_name
    assert "version entering" not in (finding.remediation.summary or "")


def test_credentials_not_claimed_without_evidence():
    """A host is only labelled credentialed when the payload says it was."""
    result = _payload([{"port": 22, "protocol": "tcp", "service": "ssh"}], [])
    report = build_scan_report(result)
    assert report.hosts[0].credentialed is False


def test_unresolved_os_is_not_reported_as_dual_boot():
    result = {
        "metadata": {"target": "10.0.0.5"},
        "data": [{"ip_address": "10.0.0.5", "open_ports": [], "cves": []}],
    }
    host = build_scan_report(result).hosts[0]

    assert host.os_label == "Not determined"
    # Absent hostname must not print the IP twice.
    assert host.display_name == "10.0.0.5"


def test_open_ports_are_informational_not_low_severity():
    result = _payload(
        [
            {"port": 22, "protocol": "tcp", "service": "ssh"},
            {"port": 80, "protocol": "tcp", "service": "http"},
        ],
        [],
    )
    report = build_scan_report(result)

    assert report.vulnerabilities == []
    inventory = [
        f
        for f in report.active
        if f.detection_method == DetectionMethod.PORT_OBSERVATION
    ]
    assert len(inventory) == 2
    assert all(f.severity == "None" for f in inventory)
    assert all(f.confidence == Confidence.INFORMATIONAL for f in inventory)


def test_multiple_hosts_are_reported_separately():
    result = {
        "metadata": {"target": "10.0.0.0/29"},
        "data": [
            {
                "ip_address": "10.0.0.5",
                "hostname": "web-01",
                "open_ports": [{"port": 80, "service": "http"}],
                "cves": [],
            },
            {
                "ip_address": "10.0.0.6",
                "hostname": "db-01",
                "open_ports": [{"port": 5432, "service": "postgresql"}],
                "cves": [],
            },
        ],
    }
    report = build_scan_report(result)

    assert len(report.hosts) == 2
    assert {h.ip for h in report.hosts} == {"10.0.0.5", "10.0.0.6"}
    assert report.hosts[0].display_name.endswith(")")


def test_secrets_are_redacted_from_evidence():
    result = _payload(
        [
            {
                "port": 80,
                "protocol": "tcp",
                "service": "http",
                "product": "nginx",
                "version": "1.18.0",
            }
        ],
        [
            {
                "cve_id": "CVE-2021-23017",
                "title": "nginx resolver off-by-one",
                "description": "Off-by-one in the resolver.",
                "plugin_output": "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc\npassword=hunter2",
                "affected_software": [
                    {
                        "vendor": "f5",
                        "product": "nginx",
                        "versionEndExcluding": "1.20.1",
                    }
                ],
                "port": 80,
            }
        ],
    )
    finding = build_scan_report(result).vulnerabilities[0]

    assert "eyJhbGciOiJIUzI1NiJ9" not in finding.evidence
    assert "hunter2" not in finding.evidence
    assert "[REDACTED]" in finding.evidence


# ─────────────────────────────────────────────────────────────────────────────
# Presenting findings that one upgrade resolves
# ─────────────────────────────────────────────────────────────────────────────


def _chrome_payload(count, extra_cves=()):
    """A host well behind on a browser, plus whatever else is given."""
    cves = [
        {
            "cve_id": f"CVE-2026-{9000 + i}",
            "description": "Chrome flaw.",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            "affected": [
                {
                    "vendor": "google",
                    "product": "chrome",
                    "versionEndExcluding": f"14{i % 5}.0.100",
                    "cpe23Uri": "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
                }
            ],
            "port": 443,
        }
        for i in range(count)
    ]
    cves.extend(extra_cves)
    return {
        "data": [
            {
                "ip_address": "10.0.0.40",
                "os_guess": "Windows 11",
                "open_ports": [
                    {
                        "port": 443,
                        "service": "https",
                        "product": "Chrome",
                        "version": "138.0.7204.184",
                    }
                ],
                "cves": cves,
            }
        ]
    }


def test_findings_one_upgrade_resolves_are_presented_as_one_item():
    from scans.finding_normalizer import group_findings_for_report

    report = build_scan_report(_chrome_payload(40))
    groups = group_findings_for_report(report.vulnerabilities)

    assert len(report.vulnerabilities) == 40
    assert len(groups) == 1
    assert groups[0].is_group
    assert len(groups[0].findings) == 40


def test_the_group_names_the_highest_upgrade_its_findings_require():
    """
    An administrator performs one upgrade. Grouping per fixed version produced
    a card per version — 76 of them for one product — when the answer is a
    single action to the highest boundary required.
    """
    from scans.finding_normalizer import group_findings_for_report

    report = build_scan_report(_chrome_payload(40))
    group = group_findings_for_report(report.vulnerabilities)[0]

    assert group.fixed_version == "144.0.100"


def test_a_high_volume_product_cannot_bury_a_more_severe_finding():
    """
    The report renders a bounded number of finding cards. With one card per CVE
    a browser's thousand findings pushed an ICS component carrying a Critical
    out of the document entirely.
    """
    from scans.finding_normalizer import group_findings_for_report

    # A credentialed package finding, as the audit of a real host produces it.
    ics = {
        "cve_id": "CVE-2025-40795",
        "description": "Siemens UMC remote code execution.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "detection_method": "credentialed",
        "package": "User Management Component",
        "installed_version": "2.12",
        "affected": [
            {
                "vendor": "siemens",
                "product": "user_management_component",
                "versionEndExcluding": "2.15.2.1",
                "cpe23Uri": "cpe:2.3:a:siemens:user_management_component:*:*:*:*:*:*:*:*",
            }
        ],
    }
    report = build_scan_report(_chrome_payload(500, extra_cves=[ics]))
    groups = group_findings_for_report(report.vulnerabilities)

    assert len(report.vulnerabilities) == 501
    assert len(groups) <= 3
    # The ICS finding is present and near the top, not past a card cap.
    products = [g.product or g.representative.primary_cve for g in groups]
    assert any("User Management" in p or "CVE-2025-40795" in p for p in products)


def test_a_pair_of_findings_is_not_dressed_up_as_a_group():
    from scans.finding_normalizer import group_findings_for_report

    report = build_scan_report(_chrome_payload(2))
    groups = group_findings_for_report(report.vulnerabilities)

    assert len(groups) == 2
    assert all(not g.is_group for g in groups)


def test_grouping_changes_presentation_only():
    """Every finding is still present and counted; none is merged away."""
    from scans.finding_normalizer import group_findings_for_report

    report = build_scan_report(_chrome_payload(40))
    groups = group_findings_for_report(report.vulnerabilities)

    regrouped = [f for g in groups for f in g.findings]
    assert len(regrouped) == len(report.vulnerabilities)
    assert {f.primary_cve for f in regrouped} == {
        f.primary_cve for f in report.vulnerabilities
    }
