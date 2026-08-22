"""
tests/test_pipeline_contracts.py
─────────────────────────────────────────────────────────────────────────────
Each pipeline stage guarantees something to the stage after it. These tests
hold those guarantees, so a later stage never has to compensate for an earlier
one.

  Discovery       → reports what it observed; makes no vulnerability claims.
  Port scan       → identifies services structurally (product / version /
                    precision / CPE) and keeps the best-evidenced observation
                    of a port, whatever order observations arrive in.
  Candidates      → selects by scanner-assigned product identity where it
                    exists, and says so when enumeration was truncated.
  Verification    → decides identity by identifier before interpreting banners,
                    and trusts the precision recorded at measurement.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.discovery.enrichment import _register_open_port  # noqa: E402
from core.models import PortResult  # noqa: E402
from core.vuln_intel import (  # noqa: E402
    build_cpe_identity_clauses,
    parse_cpe_identities,
)
from engines.port.port_engine import _record_port  # noqa: E402
from scans.finding_normalizer import (  # noqa: E402
    Confidence,
    DetectionMethod,
    _parse_services,
    build_scan_report,
    effective_precision,
)

# ─────────────────────────────────────────────────────────────────────────────
# Stage 1 — Discovery
# ─────────────────────────────────────────────────────────────────────────────


def test_discovery_reports_observations_not_vulnerabilities():
    """
    Host discovery has no version evidence and cannot verify anything, so it
    must not emit CVE claims. It used to, and on a discovery-only scan those
    unverified candidates reached the asset registry as findings.
    """
    result = {"port_states": {}, "open_ports": [], "confirmations": []}
    _register_open_port(result, port=445, service="microsoft-ds", banner="SMB")

    assert result["open_ports"][0]["cves"] == []
    assert "cves" not in result or not result.get("cves")


def test_discovery_labels_its_identification_as_weak():
    """Its fingerprint is a connect-and-read, and downstream must be able to tell."""
    result = {"port_states": {}, "open_ports": []}
    _register_open_port(result, port=502, service="modbus")

    assert result["open_ports"][0]["fingerprint_source"] == "connect_probe"


# ─────────────────────────────────────────────────────────────────────────────
# Stage 2 — Port scan
# ─────────────────────────────────────────────────────────────────────────────


def _nmap_record(**overrides):
    base = {
        "port": 445,
        "protocol": "tcp",
        "service": "microsoft-ds",
        "state": "open",
        "product": "Microsoft Windows Server 2019 microsoft-ds",
        "version": "10.0.17763",
        "extra": "workgroup: WORKGROUP",
        "cpe": ["cpe:/o:microsoft:windows_server_2019"],
        "version_precision": "exact",
        "fingerprint_source": "version_detection",
    }
    base.update(overrides)
    return PortResult(**base).to_dict()


def _discovery_record(port=445):
    return {
        "port": port,
        "protocol": "tcp",
        "service": "microsoft-ds",
        "state": "open",
        "banner": "",
        "version": "",
        "product": "",
        "fingerprint_source": "connect_probe",
        "cves": [],
    }


def test_service_detection_replaces_a_discovery_guess():
    """
    The defect this prevents: discovery registers port 445 first, the port
    engine skips it as already known, and the version Nmap found is discarded.
    Verification then has nothing to compare and withholds every finding on
    that service — a false negative created purely by arrival order.
    """
    host = {"open_ports": [_discovery_record()]}
    _record_port(host, _nmap_record())

    assert len(host["open_ports"]) == 1
    kept = host["open_ports"][0]
    assert kept["version"] == "10.0.17763"
    assert kept["cpe"] == ["cpe:/o:microsoft:windows_server_2019"]
    assert kept["fingerprint_source"] == "version_detection"


def test_a_weaker_observation_never_overwrites_a_stronger_one():
    """The rule is best evidence, not last writer — it has to hold both ways."""
    host = {"open_ports": [_nmap_record()]}
    _record_port(host, _discovery_record())

    kept = host["open_ports"][0]
    assert kept["version"] == "10.0.17763"
    assert kept["product"].startswith("Microsoft Windows Server 2019")


def test_merging_keeps_evidence_from_both_observations():
    host = {"open_ports": [_discovery_record()]}
    host["open_ports"][0]["banner"] = "SMB banner text"
    _record_port(host, _nmap_record(banner=""))

    kept = host["open_ports"][0]
    assert kept["banner"] == "SMB banner text"  # only the weak record had it
    assert kept["version"] == "10.0.17763"  # identification from the strong one


def test_distinct_ports_are_not_merged():
    host = {"open_ports": [_discovery_record(port=139)]}
    _record_port(host, _nmap_record(port=445))
    assert {p["port"] for p in host["open_ports"]} == {139, 445}


def test_port_record_keeps_identification_structured():
    """
    Product, version and extra stay in separate fields. Concatenating them into
    one display string forced every consumer to parse the version back out.
    """
    record = _nmap_record()
    assert record["product"].startswith("Microsoft")
    assert record["version"] == "10.0.17763"
    assert record["extra"] == "workgroup: WORKGROUP"
    assert PortResult(**{k: v for k, v in record.items()}).product_label == (
        "Microsoft Windows Server 2019 microsoft-ds 10.0.17763 workgroup: WORKGROUP"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Stage 3 — Candidate generation
# ─────────────────────────────────────────────────────────────────────────────


def test_cpe_identities_parse_both_formats():
    identities = parse_cpe_identities(
        [
            "cpe:/a:openbsd:openssh:9.5",  # CPE 2.2, what Nmap emits
            "cpe:2.3:a:f5:nginx:1.26.3:*:*:*:*:*:*:*",  # CPE 2.3
            "not-a-cpe",
            "",
        ]
    )
    assert identities == [("openbsd", "openssh"), ("f5", "nginx")]


def test_candidate_selection_keys_on_product_not_vendor():
    """
    Nmap calls nginx ``igor_sysoev``; NVD reassigned it to ``f5``. Requiring
    both to agree would drop every nginx CVE, so the key is the product.
    """
    where, params = build_cpe_identity_clauses(
        parse_cpe_identities(["cpe:/a:igor_sysoev:nginx:1.26.3"])
    )
    assert "LOWER(cpe.product) = :cpe_p_0" in where
    assert "vendor" not in where
    assert params == {"cpe_p_0": "nginx"}


def test_candidate_selection_uses_equality_not_substring():
    where, _ = build_cpe_identity_clauses([("openbsd", "openssh")])
    assert "LIKE" not in where
    assert "=" in where


# ─────────────────────────────────────────────────────────────────────────────
# Stage 4 — Verification consuming the contract
# ─────────────────────────────────────────────────────────────────────────────


def _payload(service_extra, cve_cpe):
    service = {
        "port": 80,
        "protocol": "tcp",
        "state": "open",
        "service": "http",
        "version": "1.26.3",
        "version_precision": "exact",
    }
    service.update(service_extra)
    return {
        "data": [
            {
                "ip_address": "10.0.0.9",
                "os_guess": "Ubuntu 22.04",
                "open_ports": [service],
                "cves": [
                    {
                        "cve_id": "CVE-2026-40701",
                        "description": "NGINX worker heap use-after-free.",
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "affected": [cve_cpe],
                        "port": 80,
                    }
                ],
            }
        ]
    }


NGINX_FEED_CPE = {
    "vendor": "f5",
    "product": "nginx",
    "versionEndExcluding": "1.27.4",
    "cpe23Uri": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
}


def test_identity_match_confirms_where_banner_text_says_nothing():
    """
    The service is identified only by its CPE — no product string, no banner to
    tokenise. Token matching cannot bind the CVE to it; the identifier can.
    """
    report = build_scan_report(
        _payload({"cpe": ["cpe:/a:igor_sysoev:nginx:1.26.3"]}, NGINX_FEED_CPE)
    )

    assert len(report.vulnerabilities) == 1
    assert report.vulnerabilities[0].confidence == Confidence.CONFIRMED
    assert report.vulnerabilities[0].detection_method == DetectionMethod.VERSION_MATCH


def test_token_matching_still_applies_when_no_cpe_was_recorded():
    """Services the scanner could not identify that precisely must still match."""
    report = build_scan_report(_payload({"product": "nginx"}, NGINX_FEED_CPE))

    assert len(report.vulnerabilities) == 1
    assert report.vulnerabilities[0].confidence == Confidence.CONFIRMED


def test_identity_mismatch_falls_back_rather_than_disproving():
    """
    A CPE list is not exhaustive and NVD names products more specifically than
    Nmap does, so a missing identity match must not be read as "not this
    product" — it falls through to token matching.
    """
    report = build_scan_report(
        _payload(
            {"cpe": ["cpe:/a:igor_sysoev:nginx:1.26.3"], "product": "nginx"},
            {**NGINX_FEED_CPE, "product": "nginx_open_source"},
        )
    )

    assert len(report.vulnerabilities) == 1


def test_recorded_precision_is_preferred_over_re_deriving_it():
    assert effective_precision("9.6.0", "floor") == "floor"
    assert effective_precision("9.6.0 or later", "") == "floor"
    assert effective_precision("9.6.0", "") == "exact"
    assert effective_precision("9.6.0", "unknown") == "exact"


def test_service_precision_reaches_the_version_comparison():
    """
    A version recorded as a lower bound cannot clear an upper bound, whatever
    the string looks like by the time it is compared.
    """
    payload = _payload({"product": "nginx"}, NGINX_FEED_CPE)
    payload["data"][0]["open_ports"][0]["version_precision"] = "floor"

    report = build_scan_report(payload)

    assert len(report.vulnerabilities) == 1
    assert report.vulnerabilities[0].confidence == Confidence.POTENTIAL
    assert report.vulnerabilities[0].detection_method == (
        DetectionMethod.VERSION_IMPRECISE
    )


def test_service_contract_survives_normalization():
    services = _parse_services(
        {
            "open_ports": [
                {
                    "port": 22,
                    "service": "ssh",
                    "product": "OpenSSH",
                    "version": "9.5",
                    "extra": "protocol 2.0",
                    "cpe": ["cpe:/a:openbsd:openssh:9.5"],
                    "version_precision": "exact",
                }
            ]
        }
    )

    assert services[0].cpe_identities == (("openbsd", "openssh"),)
    assert services[0].version == "9.5"
    assert services[0].version_precision == "exact"
    assert services[0].product_label == "OpenSSH 9.5 protocol 2.0"


# ─────────────────────────────────────────────────────────────────────────────
# Credentialed pipeline — verified at the audit, not at the report
# ─────────────────────────────────────────────────────────────────────────────


def _credentialed_report(cves):
    return {
        "target": "10.0.0.20",
        "system_info": {"hostname": "db-01", "os_name": "Ubuntu 22.04"},
        "open_ports_credentialed": [
            {
                "port": 5432,
                "protocol": "tcp",
                "state": "LISTEN",
                "service": "postgresql",
            }
        ],
        "packages": [{"name": "postgresql", "version": "9.6.2"}],
        "cves": cves,
    }


POSTGRES_PACKAGE_CVE = {
    "cve_id": "CVE-2017-7546",
    "package": "postgresql",
    "severity": "Critical",
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "affected_software": [
        {
            "vendor": "postgresql",
            "product": "postgresql",
            "versionEndExcluding": "9.6.6",
            "cpe23Uri": "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*",
        }
    ],
}


def test_credentialed_package_finding_survives_a_port_inventory():
    """
    A package finding is a package finding whether or not the host also has
    listening services. Treating it as a network finding meant a package that
    is not exposed on any port looked like a product the host does not run, and
    every version-matched finding from the audit was suppressed.
    """
    from scans.finding_normalizer import verify_credentialed_report

    verification = verify_credentialed_report(
        _credentialed_report([POSTGRES_PACKAGE_CVE])
    )

    assert [c["cve_id"] for c in verification.verified] == ["CVE-2017-7546"]
    assert verification.suppressed == []


def test_credentialed_audit_still_rules_out_what_does_not_apply():
    from scans.finding_normalizer import verify_credentialed_report

    not_applicable = dict(POSTGRES_PACKAGE_CVE)
    not_applicable["cve_id"] = "CVE-2999-0001"
    not_applicable["affected_software"] = [
        {
            "vendor": "postgresql",
            "product": "postgresql",
            "versionStartIncluding": "15.0",
            "cpe23Uri": "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*",
        }
    ]

    verification = verify_credentialed_report(_credentialed_report([not_applicable]))

    assert verification.verified == []
    assert "outside the vulnerable range" in verification.suppressed[0].reason


# ─────────────────────────────────────────────────────────────────────────────
# Suppression reasons state what actually happened
# ─────────────────────────────────────────────────────────────────────────────


def test_a_product_that_is_absent_is_not_reported_as_a_version_mismatch():
    """
    A finding can carry a detected version and still have been ruled out
    because the product was never found on the host. Inferring the reason from
    which fields are populated told the reader the wrong thing.
    """
    report = build_scan_report(
        {
            "data": [
                {
                    "ip_address": "10.0.0.11",
                    "os_guess": "Ubuntu 22.04",
                    "open_ports": [
                        {
                            "port": 80,
                            "service": "http",
                            "product": "nginx",
                            "version": "1.26.3",
                        }
                    ],
                    "cves": [
                        {
                            "cve_id": "CVE-2021-44228",
                            "description": "Log4Shell.",
                            "detected_version": "1.26.3",
                            "affected": [
                                {
                                    "vendor": "apache",
                                    "product": "log4j",
                                    "versionEndExcluding": "2.15.0",
                                    "cpe23Uri": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                                }
                            ],
                        }
                    ],
                }
            ]
        }
    )

    reason = report.excluded[0].reason
    assert "do not include the affected product" in reason
    assert "falls outside the vulnerable range" not in reason


# ─────────────────────────────────────────────────────────────────────────────
# Dashboard counters read the verified severities
# ─────────────────────────────────────────────────────────────────────────────


def test_scan_counters_use_verified_severities_not_the_raw_field():
    """
    The denormalized counts on the scan row drive the dashboard. Tallying the
    feed-supplied ``severity`` string made them disagree with the report, which
    recomputes severity from each CVE's vector.
    """
    from engines.vulnerability.vulnerability_engine import VulnerabilityEngine

    host = {
        "ip_address": "10.0.0.12",
        "os_guess": "Ubuntu 22.04",
        "open_ports": [
            {
                "port": 80,
                "protocol": "tcp",
                "state": "open",
                "service": "http",
                "product": "nginx",
                "version": "1.26.3",
            }
        ],
        "cves": [
            {
                # Vector says Critical (9.8); the feed's own label says Low.
                "cve_id": "CVE-2026-40701",
                "severity": "Low",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "affected": [
                    {
                        "vendor": "f5",
                        "product": "nginx",
                        "versionEndExcluding": "1.27.4",
                        "cpe23Uri": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
                    }
                ],
                "port": 80,
            }
        ],
    }
    VulnerabilityEngine._verify_host(host)

    assert host["vulnerability_counts"]["Critical"] == 1
    assert host["vulnerability_counts"]["Low"] == 0


# ─────────────────────────────────────────────────────────────────────────────
# Scan coverage — what the scan examined must be recorded, never assumed
# ─────────────────────────────────────────────────────────────────────────────


def test_port_engine_publishes_the_configuration_it_ran_with():
    from core.models import ScanIntensity
    from engines.port.port_engine import PortEngine

    config = PortEngine(
        intensity=ScanIntensity.NORMAL, os_detection=True
    ).scan_configuration()

    assert "1-1024" in config["port_range"]
    assert config["service_detection"].startswith("Enabled")
    assert config["os_detection"] == "Enabled"
    assert config["scanner"]
    assert config["timing_template"]


def test_a_port_state_only_scan_does_not_claim_service_detection():
    """LIGHT intensity reports port state; claiming otherwise overstates coverage."""
    from core.models import ScanIntensity
    from engines.port.port_engine import PortEngine

    config = PortEngine(intensity=ScanIntensity.LIGHT).scan_configuration()

    assert config["service_detection"] == "Not performed (port state only)"
    assert config["os_detection"] == "Not performed"


def test_custom_ports_are_recorded_as_the_scanned_range():
    from core.models import ScanIntensity
    from engines.port.port_engine import PortEngine

    config = PortEngine(
        intensity=ScanIntensity.NORMAL, custom_ports=[22, 80, 443]
    ).scan_configuration()

    assert "22, 80, 443" in config["port_range"]


def test_report_does_not_invent_scan_configuration():
    """
    The methodology appendix bounds every conclusion in the report. A default
    that reads as a statement of fact ("Enabled (banner and probe
    fingerprinting)") was printed for scans that performed no service detection
    at all.
    """
    from pdf_generator import _scan_configuration
    from scans.finding_normalizer import build_scan_report

    findings = build_scan_report({"data": []})
    rows = dict(_scan_configuration({}, {}, findings, "phase1"))

    assert rows["Service detection"] == "Not recorded"
    assert rows["OS fingerprinting"] == "Not recorded"
    assert rows["Port selection"] == "Not recorded"


def test_recorded_configuration_reaches_the_report():
    from pdf_generator import _scan_configuration
    from scans.finding_normalizer import build_scan_report

    findings = build_scan_report({"data": []})
    summary = {
        "port_range": "System ports 1-1024 plus curated high ports (1111 ports)",
        "service_detection": "Enabled (banner and probe fingerprinting)",
        "os_detection": "Enabled",
        "timing_template": "Nmap -T4 (normal intensity)",
        "scanner": "Nmap 7.94",
    }
    rows = dict(_scan_configuration({}, summary, findings, "phase3"))

    assert rows["Port selection"].startswith("System ports 1-1024")
    assert rows["Scanner engine"] == "Nmap 7.94"
    assert rows["Timing profile"] == "Nmap -T4 (normal intensity)"


def test_coverage_carries_from_the_discovery_phase_to_the_assessment():
    """
    A vulnerability assessment does not choose ports. Its report still has to
    state which ports were examined, and only the phase that scanned them knows.
    """
    from scan_helpers import carry_scan_coverage

    result = {"summary": {"phase": 3}, "metadata": {}}
    carry_scan_coverage(result, {"port_range": "1-1024", "scanner": "Nmap 7.94"})

    assert result["summary"]["port_range"] == "1-1024"
    assert result["metadata"]["scanner"] == "Nmap 7.94"


# ─────────────────────────────────────────────────────────────────────────────
# Credentialed audit — an unassessed host is not a clean host
# ─────────────────────────────────────────────────────────────────────────────


def test_collectors_record_which_sections_failed():
    """
    A swallowed section failure reads downstream as "nothing found". For the
    package inventory that is the difference between "could not assess" and
    "clean".
    """
    import inspect

    from engines.credentialed import linux_collector, windows_collector

    for module in (linux_collector, windows_collector):
        source = inspect.getsource(
            module.__dict__["LinuxCollector"]
            if module is linux_collector
            else module.__dict__["WindowsCollector"]
        )
        assert 'result.setdefault("collection_errors", {})' in source, module.__name__


def test_an_unreadable_inventory_is_reported_as_incomplete_not_clean():
    from scans.finding_normalizer import build_scan_report

    report = {
        "target": "10.0.0.30",
        "system_info": {"hostname": "srv-01", "os_name": "Ubuntu 22.04"},
        "open_ports_credentialed": [],
        "packages": [],
        "collection_errors": {"packages": "dpkg-query: permission denied"},
        "cves": [
            {
                "cve_id": "MISC-CREDENTIALED-INVENTORY-UNAVAILABLE",
                "detection_method": "active_check",
                "severity": "Medium",
                "title": "Credentialed audit incomplete — software inventory unavailable",
                "description": (
                    "The credentialed session succeeded, but the installed "
                    "software inventory could not be collected, so no package "
                    "was assessed. This host is unassessed, not clean."
                ),
            }
        ],
    }

    findings = build_scan_report({"data": {"credentialed": {"report": report}}})

    assert len(findings.vulnerabilities) == 1
    finding = findings.vulnerabilities[0]
    assert finding.confidence == Confidence.CONFIRMED
    assert "unassessed, not clean" in finding.description
