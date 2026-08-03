"""
tests/test_scan_time_verification.py
─────────────────────────────────────────────────────────────────────────────
Verification runs during the vulnerability phase, not at report time.

These lock in the contract that makes that safe:

  * A host leaving the vulnerability engine carries verified findings in
    ``cves`` and the ruled-out candidates, with reasons, in ``suppressed_cves``.
  * Risk is scored from the verified set, so the score ranks hosts instead of
    saturating at 100 for anything with a recognisable banner.
  * The report built from a pre-verified payload reports the same findings and
    still accounts for every candidate the scan evaluated.
  * A payload written before verification moved — and a credentialed audit,
    which never runs this engine — normalizes exactly as it always did.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engines.vulnerability.vulnerability_engine import VulnerabilityEngine  # noqa: E402
from scans.finding_normalizer import (  # noqa: E402
    Confidence,
    DetectionMethod,
    build_scan_report,
    verify_host_findings,
)

NGINX_CPE = [
    {
        "vendor": "f5",
        "product": "nginx",
        "versionEndExcluding": "1.27.4",
        "cpe23Uri": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
    }
]

OPENSSH_CPE = [
    {
        "vendor": "openbsd",
        "product": "openssh",
        "versionEndExcluding": "7.3",
        "cpe23Uri": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
    }
]


def _host():
    """A host as the plugin phase leaves it: real services, candidate CVEs."""
    return {
        "ip_address": "10.0.0.7",
        "hostname": "web-01",
        "is_active": True,
        "os_guess": "Ubuntu 22.04",
        "open_ports": [
            {
                "port": 80,
                "protocol": "tcp",
                "state": "open",
                "service": "http",
                "product": "nginx",
                "version": "1.26.3",
                "risk": "Info",
            },
            {
                "port": 22,
                "protocol": "tcp",
                "state": "open",
                "service": "ssh",
                "product": "OpenSSH",
                "version": "9.5",
                "risk": "Info",
            },
        ],
        "cves": [
            {
                # Applies: 1.26.3 is inside the published range.
                "cve_id": "CVE-2026-40701",
                "description": "Heap use-after-free in the NGINX worker process.",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "affected": NGINX_CPE,
                "port": 80,
            },
            {
                # Does not apply: the host runs OpenSSH 9.5, this is < 7.3.
                "cve_id": "CVE-2016-6210",
                "description": "User enumeration in OpenSSH before 7.3.",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "affected": OPENSSH_CPE,
                "port": 22,
            },
            {
                # Does not apply: no service on this host is the affected
                # product. This is the bulk of what a name-keyed lookup returns.
                "cve_id": "CVE-2021-44228",
                "description": "Log4Shell.",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "affected": [
                    {
                        "vendor": "apache",
                        "product": "log4j",
                        "versionEndExcluding": "2.15.0",
                        "cpe23Uri": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                    }
                ],
            },
        ],
    }


# ─────────────────────────────────────────────────────────────────────────────
# The engine stage
# ─────────────────────────────────────────────────────────────────────────────


def test_engine_leaves_only_verified_findings_on_the_host():
    host = _host()
    VulnerabilityEngine._verify_host(host)

    assert [c["cve_id"] for c in host["cves"]] == ["CVE-2026-40701"]
    assert host["candidates_evaluated"] == 3
    assert host["vulnerability_counts"]["Critical"] == 1


def test_ruled_out_candidates_are_kept_with_their_reasons():
    """Filtering early must not mean losing the audit trail."""
    host = _host()
    VulnerabilityEngine._verify_host(host)

    withheld = {item["identifier"]: item["reason"] for item in host["suppressed_cves"]}
    assert set(withheld) == {"CVE-2016-6210", "CVE-2021-44228"}
    assert "outside the vulnerable range" in withheld["CVE-2016-6210"]
    assert "9.5" in withheld["CVE-2016-6210"]
    assert "do not include the affected product" in withheld["CVE-2021-44228"]


def test_verification_does_not_mutate_the_host_it_reads():
    host = _host()
    before = len(host["cves"])
    verify_host_findings(host)
    assert len(host["cves"]) == before


def test_verification_is_idempotent():
    """Re-running the stage on its own output must change nothing."""
    host = _host()
    VulnerabilityEngine._verify_host(host)
    first = ([c["cve_id"] for c in host["cves"]], host["candidates_evaluated"])

    VulnerabilityEngine._verify_host(host)
    assert ([c["cve_id"] for c in host["cves"]], host["candidates_evaluated"]) == (
        first[0],
        1,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Risk scoring
# ─────────────────────────────────────────────────────────────────────────────


def _noise(count):
    return [
        {
            "cve_id": f"CVE-2019-{9000 + i}",
            "description": "Unrelated product.",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "affected": [
                {
                    "vendor": "apache",
                    "product": "log4j",
                    "versionEndExcluding": "2.15.0",
                    "cpe23Uri": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                }
            ],
        }
        for i in range(count)
    ]


def test_candidates_that_do_not_apply_carry_no_risk_weight():
    """
    Scoring the candidate pool saturated the score: 20 points per
    critical-rated candidate against a cap of 100 puts any host with five of
    them at 100/Critical, which cannot rank hosts and was written straight
    through to the asset registry. Noise must now move the score by nothing.
    """
    clean, noisy = _host(), _host()
    noisy["cves"].extend(_noise(40))

    for host in (clean, noisy):
        VulnerabilityEngine._verify_host(host)
        VulnerabilityEngine._score_host(host)

    assert noisy["host_risk_score"] == clean["host_risk_score"]
    assert noisy["host_risk_score"] < 100


def test_risk_level_reflects_the_worst_verified_finding():
    """
    The score ranks hosts; the level classifies the worst thing found on one.
    A verified Critical scores 20 points, which the raw thresholds would call
    "Low" — those thresholds were set when the score saturated at 100.
    """
    host = _host()
    VulnerabilityEngine._verify_host(host)
    VulnerabilityEngine._score_host(host)

    assert host["vulnerability_counts"]["Critical"] == 1
    assert host["host_risk_level"] == "Critical"


def test_a_host_with_no_verified_findings_is_not_flagged():
    host = _host()
    host["cves"] = _noise(40)
    VulnerabilityEngine._verify_host(host)
    VulnerabilityEngine._score_host(host)

    assert host["cves"] == []
    assert host["host_risk_level"] == "Info"
    assert len(host["suppressed_cves"]) == 40


# ─────────────────────────────────────────────────────────────────────────────
# Active checks
# ─────────────────────────────────────────────────────────────────────────────


def test_active_check_findings_survive_verification():
    """
    A probe that observed the condition carries its own evidence. It has no CPE
    range to test, so without the active-check tag it reads as unverifiable and
    an actively confirmed MS17-010 would be withheld from the report.
    """
    host = {
        "ip_address": "10.0.0.8",
        "os_guess": "Windows Server 2012 R2",
        "open_ports": [
            {"port": 445, "protocol": "tcp", "state": "open", "service": "smb"}
        ],
        "cves": [
            {
                "cve_id": "CVE-2017-0144-ACTIVE",
                "detection_method": "active_check",
                "severity": "Critical",
                "description": "MS17-010 fingerprint confirmed on 10.0.0.8:445.",
            }
        ],
    }

    VulnerabilityEngine._verify_host(host)
    assert [c["cve_id"] for c in host["cves"]] == ["CVE-2017-0144-ACTIVE"]
    assert host["suppressed_cves"] == []

    finding = build_scan_report({"data": [host]}).vulnerabilities[0]
    assert finding.confidence == Confidence.CONFIRMED
    assert finding.detection_method == DetectionMethod.CONFIG_CHECK


def test_plugins_tag_their_active_findings():
    """The tag is what the engine relies on, so assert the plugins still set it."""
    from engines.vulnerability.plugins import (
        default_creds,
        dns_probe,
        eternalblue_probe,
        heartbleed_probe,
        ldap_probe,
    )

    import inspect

    for module in (
        heartbleed_probe,
        eternalblue_probe,
        default_creds,
        dns_probe,
        ldap_probe,
    ):
        source = inspect.getsource(module)
        tagged = source.count('"detection_method": "active_check"')
        emitted = source.count('"cve_id": "')
        assert (
            tagged == emitted
        ), f"{module.__name__} emits {emitted} finding(s) but tags {tagged}"


# ─────────────────────────────────────────────────────────────────────────────
# The report reading a pre-verified payload
# ─────────────────────────────────────────────────────────────────────────────


def test_report_on_a_verified_payload_matches_the_unverified_one():
    """
    Moving the filter earlier must not change what the report says. The same
    scan reported before and after verification must contain the same findings
    and account for the same number of candidates.
    """
    legacy = _host()
    verified = _host()
    VulnerabilityEngine._verify_host(verified)

    from_legacy = build_scan_report({"data": [legacy]})
    from_verified = build_scan_report({"data": [verified]})

    assert [f.primary_cve for f in from_legacy.vulnerabilities] == [
        f.primary_cve for f in from_verified.vulnerabilities
    ]
    assert {e.identifier for e in from_legacy.excluded} == {
        e.identifier for e in from_verified.excluded
    }
    assert {e.reason for e in from_legacy.excluded} == {
        e.reason for e in from_verified.excluded
    }


def test_suppressed_candidates_are_not_double_counted():
    """
    "Candidate matches evaluated" in the methodology appendix is derived from
    findings + exclusions, so a replayed exclusion must not also be re-derived.
    """
    host = _host()
    VulnerabilityEngine._verify_host(host)
    # A payload where a suppressed candidate was also left in place.
    host["cves"] = host["cves"] + [
        {
            "cve_id": "CVE-2016-6210",
            "description": "User enumeration in OpenSSH before 7.3.",
            "affected": OPENSSH_CPE,
            "port": 22,
        }
    ]

    report = build_scan_report({"data": [host]})
    identifiers = [e.identifier for e in report.excluded]
    assert identifiers.count("CVE-2016-6210") == 1


def test_legacy_payload_without_verification_fields_is_unchanged():
    """Scans stored before this moved still normalize the old way."""
    report = build_scan_report({"data": [_host()]})

    assert [f.primary_cve for f in report.vulnerabilities] == ["CVE-2026-40701"]
    assert len(report.excluded) == 2


def test_verification_survives_the_host_result_serialization():
    """
    Phase-3 results are stored as HostResult.to_phase3_dict(), which is built
    from the dataclass fields — anything not declared there is dropped on the
    way to the database. The audit trail has to make that trip, or a report
    generated from the stored scan would show no suppressed candidates at all.
    """
    from core.models import HostResult

    host = _host()
    VulnerabilityEngine._verify_host(host)

    stored = HostResult(
        ip_address=host["ip_address"],
        cves=host["cves"],
        suppressed_cves=host["suppressed_cves"],
        vulnerability_counts=host["vulnerability_counts"],
        candidates_evaluated=host["candidates_evaluated"],
    ).to_phase3_dict()
    # to_phase3_dict drops open_ports because phase 2 already reported them;
    # _merge_host_identity restores them from the previous phase before the
    # payload reaches the report, so the report sees a host with both.
    stored["open_ports"] = host["open_ports"]

    assert stored["candidates_evaluated"] == 3
    assert {item["identifier"] for item in stored["suppressed_cves"]} == {
        "CVE-2016-6210",
        "CVE-2021-44228",
    }

    report = build_scan_report({"data": [stored]})
    assert len(report.excluded) == 2
    assert [f.primary_cve for f in report.vulnerabilities] == ["CVE-2026-40701"]
