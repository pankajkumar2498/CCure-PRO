"""
The network check path end to end, and the coverage cross-check.

GAP-06. Two jobs:

1. **The full path for a promoted finding** — detection, evidence, typed
   definition, finding, severity, risk, remediation, report — asserted on the
   real pipeline objects rather than on the plugin's return value alone.

2. **The coverage cross-check.** ``scripts/measure_network_check_coverage.py``
   counts an area as tested when a test names it. This module names every
   declared area *and* asserts that a behavioural test in
   ``test_network_check_promotion.py`` exercises that area's identifier — so
   "tested" cannot come to mean "mentioned in a docstring". Delete a
   behavioural test and the area loses its coverage credit here, loudly.
"""

import json
from pathlib import Path

import pytest

from core.checks.definitions import (
    DEFINITION_TYPE_CVE,
    DEFINITION_TYPE_PLUGIN_CHECK,
    definition_type_for_id,
)
from engines.vulnerability.network_checks import (
    NETWORK_CHECKS,
    check_for_area,
    network_finding,
)
from engines.vulnerability.vulnerability_engine import VulnerabilityEngine
from scans.finding_normalizer import (
    Confidence,
    DetectionMethod,
    parse_raw_finding,
    verify_host_findings,
)

#: The behavioural suites an area's identifier may be proven by.
#:
#: ``test_tls_deep.py`` was added by GAP-07 (Phase 11), which declared sixteen
#: further TLS areas. Their behavioural tests live there rather than in the
#: promotion suite, so without this the contract below would demand they be
#: written twice — and the honest reading of "something exercises this area" is
#: that a test drives it, not that it sits in one particular file.
_PROMOTION_SOURCE = "".join(
    Path(__file__).with_name(name).read_text(encoding="utf-8")
    for name in (
        "test_network_check_promotion.py",
        "test_tls_deep.py",
    )
)

#: Areas whose identifiers are minted per finding, so no fixed identifier can
#: be searched for. Each is covered by its own test below instead.
_DYNAMIC_AREAS = {c.area for c in NETWORK_CHECKS if c.dynamic}


# ─────────────────────────────────────────────────────────────────────────────
# Coverage cross-check — every declared area, named
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "area",
    [
        # Named individually so the coverage harness can see them and so a
        # failure names the area rather than a row number.
        "tls.deprecated_protocol",
        "tls.no_secure_protocol",
        "tls.weak_cipher_suite",
        "tls.certificate_expired",
        "tls.certificate_self_signed",
        "tls.certificate_weak_signature",
        "tls.certificate_hostname_mismatch",
        "tls.heartbleed",
        "tls.robot",
        "tls.compression_crime",
        # ── GAP-07 (Phase 11) ────────────────────────────────────────────────
        "tls.certificate_expiring_soon",
        "tls.weak_dh_parameters",
        "tls.insecure_renegotiation",
        "tls.certificate_untrusted_chain",
        "tls.certificate_chain_order",
        "tls.certificate_sha1_chain",
        "tls.certificate_not_yet_valid",
        "tls.certificate_weak_key",
        "tls.ocsp_stapling_absent",
        "tls.must_staple_unhonoured",
        "tls.fallback_scsv_unsupported",
        "tls.client_renegotiation_dos",
        "tls.weak_ecdh_curve",
        "tls.no_forward_secrecy",
        "tls.ccs_injection",
        "tls.early_data_enabled",
        "tls.extended_master_secret_absent",
        "http.missing_security_headers",
        "http.cleartext_service",
        "http.insecure_cookie_flags",
        "http.sensitive_path_exposed",
        "http.directory_listing",
        "http.dangerous_methods",
        "http.server_version_disclosure",
        "http.default_credentials",
        "http.shellshock",
        "ftp.anonymous_login",
        "ftp.anonymous_write",
        "ftp.weak_credentials",
        "ftp.cleartext_protocol",
        "smb.v1_enabled",
        "smb.signing_disabled",
        "smb.eternalblue",
        "snmp.default_community",
        "snmp.v1_v2c_in_use",
        "snmp.information_disclosure",
        "ssh.weak_algorithms",
        "telnet.cleartext_exposed",
        "redis.no_authentication",
        "mongodb.no_authentication",
        "mqtt.no_authentication",
        "memcached.no_authentication",
        "ldap.anonymous_bind",
        "dns.zone_transfer",
        "dns.open_recursion",
    ],
)
def test_every_declared_area_has_a_behavioural_test(area):
    """
    The area is declared, and something actually exercises it.

    Naming the area alone would be a tautology — the list below is written by
    the same person who wrote the catalogue. The assertion that matters is the
    second one: a behavioural test in the promotion suite must reference this
    check's catalogue identifier, which it can only do by driving the plugin.
    """
    check = check_for_area(area)
    assert not check.dynamic
    assert check.definition_id in _PROMOTION_SOURCE, (
        f"{area} is declared in the catalogue but no behavioural test names "
        f"{check.definition_id}. Implemented is not proven."
    )


def test_the_parametrised_list_covers_every_declared_area():
    """
    Guards the list above against the catalogue growing past it.

    Without this, adding a check to ``NETWORK_CHECKS`` and forgetting to add it
    here would leave the new area untested *and* silently uncounted, which is
    the quiet direction to be wrong in.
    """
    declared = {c.area for c in NETWORK_CHECKS} - _DYNAMIC_AREAS
    params = test_every_declared_area_has_a_behavioural_test.pytestmark[0].args[1]
    assert set(params) == declared, (
        f"missing from the list: {sorted(declared - set(params))}; "
        f"listed but not declared: {sorted(set(params) - declared)}"
    )


class TestDynamicAreas:
    """The two areas whose identifiers come from the evidence, not a declaration."""

    def test_cve_version_inference_still_produces_real_cve_identifiers(self):
        # cve.version_inference — the CVE engine's candidates keep their own
        # published identifiers and their CVE typing.
        from engines.vulnerability.plugins import cve_engine

        result = cve_engine.run("10.0.0.1", [], [])
        assert "cves" in result
        for candidate in result["cves"]:
            identifier = candidate.get("cve_id", "")
            if identifier:
                assert definition_type_for_id(identifier) == DEFINITION_TYPE_CVE

    def test_nuclei_template_verification_mints_a_typed_identifier(self):
        # nuclei.template_verification — a CVE-tagged template files under the
        # CVE; an untagged one under a minted CCURE-CHK- identifier rather than
        # the old MISC-NUCLEI- string.
        from engines.vulnerability.plugins import nuclei_probe

        tagged = nuclei_probe._parse_result(
            json.dumps(
                {
                    "template-id": "cve-2021-44228",
                    "info": {
                        "name": "Log4j",
                        "severity": "critical",
                        "classification": {"cve-id": ["CVE-2021-44228"]},
                    },
                    "matched-at": "http://10.0.0.1:8080/",
                }
            ),
            "10.0.0.1",
        )
        assert tagged["cve_id"] == "CVE-2021-44228"

        untagged = nuclei_probe._parse_result(
            json.dumps(
                {
                    "template-id": "wordpress-directory-listing",
                    "info": {"name": "Listing", "severity": "medium"},
                    "matched-at": "http://10.0.0.1:8080/",
                }
            ),
            "10.0.0.1",
        )
        assert untagged["cve_id"] == "CCURE-CHK-NUCLEI-WORDPRESS-DIRECTORY-LISTING"
        assert (
            definition_type_for_id(untagged["cve_id"]) == DEFINITION_TYPE_PLUGIN_CHECK
        )

    def test_a_long_template_id_no_longer_exceeds_the_cve_id_column(self):
        """
        ``vulnerability_definitions.cve_id`` is varchar(30). The old
        ``MISC-NUCLEI-<template>`` identifier was written into it, so any
        template id over eighteen characters raised StringDataRightTruncation
        during the finding sync — aborting it for the whole scan.
        ``wordpress-directory-listing`` is one such template.

        The minted identifier goes into ``id``, which is varchar(120), and
        ``cve_id`` stays NULL, so the limit no longer applies.
        """
        from engines.vulnerability.plugins import nuclei_probe

        record = nuclei_probe._parse_result(
            json.dumps(
                {
                    "template-id": "wordpress-directory-listing",
                    "info": {"name": "Listing", "severity": "medium"},
                    "matched-at": "http://10.0.0.1:8080/",
                }
            ),
            "10.0.0.1",
        )
        assert len(f"MISC-NUCLEI-{'wordpress-directory-listing'.upper()}") > 30
        assert definition_type_for_id(record["cve_id"]) != DEFINITION_TYPE_CVE


# ─────────────────────────────────────────────────────────────────────────────
# The full path
# ─────────────────────────────────────────────────────────────────────────────
class TestTheFullPath:
    """Detection → evidence → typed definition → finding → severity → risk →
    remediation → report, on the real pipeline objects."""

    def _host_with_finding(self):
        finding = network_finding(
            "ssh.weak_algorithms",
            "Server banner     : SSH-2.0-OpenSSH_7.4\n"
            "Weak algorithms offered:\n"
            "  Weak KEX: diffie-hellman-group1-sha1",
            target="10.0.0.1:22",
            port=22,
        )
        return {
            "ip_address": "10.0.0.1",
            "hostname": "target",
            "is_active": True,
            "open_ports": [{"port": 22, "protocol": "tcp", "service": "ssh"}],
            "cves": [finding],
        }

    def test_the_engine_merge_promotes_it_to_the_host(self):
        host: dict = {"cves": []}
        VulnerabilityEngine._merge(
            host, {"ssh_info": {}, "cves": [network_finding("smb.v1_enabled", "e")]}
        )
        assert [f["cve_id"] for f in host["cves"]] == ["CCURE-CHK-SMB-V1-ENABLED"]

    def test_a_nested_finding_is_not_promoted(self):
        """
        The defect this phase repairs, asserted directly. ``_merge`` copies a
        nested dict wholesale under its own key and looks no further, so a
        finding inside ``http_audit`` never reaches ``host["cves"]``.
        """
        host: dict = {}
        VulnerabilityEngine._merge(
            host, {"http_audit": {"cves": [{"cve_id": "X"}], "issues": ["y"]}}
        )
        assert host.get("cves") is None

    def test_it_survives_verification_as_a_confirmed_finding(self):
        host = self._host_with_finding()
        verification = verify_host_findings(host)
        assert len(verification.verified) == 1
        assert not verification.suppressed

    def test_it_is_graded_confirmed_at_qod_99(self):
        host = self._host_with_finding()
        finding = parse_raw_finding(host["cves"][0], host="10.0.0.1", hostname="target")
        assert finding.detection_method is DetectionMethod.CONFIG_CHECK
        assert finding.confidence is Confidence.CONFIRMED
        assert finding.qod == 99
        assert finding.is_reportable

    def test_the_evidence_is_kept_as_real_scanner_output(self):
        host = self._host_with_finding()
        finding = parse_raw_finding(host["cves"][0], host="10.0.0.1")
        assert "diffie-hellman-group1-sha1" in finding.evidence
        assert finding.evidence_available is True

    def test_severity_and_remediation_reach_the_report_object(self):
        host = self._host_with_finding()
        finding = parse_raw_finding(host["cves"][0], host="10.0.0.1")
        assert finding.severity == "Medium"
        assert finding.remediation is not None
        # CONFIGURATION_GUIDANCE is actionable: it names an edit to make, not
        # "no published fix -- compensating controls only", which is what a
        # NONE_PUBLISHED remediation renders as and is false of a hardening
        # control.
        assert finding.remediation.is_actionable

    def test_a_check_finding_gets_no_nvd_link(self):
        """
        ``parse_raw_finding`` appends an NVD URL only when a real CVE was
        extracted. A minted identifier does not match the CVE pattern, so no
        link is produced — a reader is never sent to NVD to look up something
        NVD has never heard of.
        """
        host = self._host_with_finding()
        finding = parse_raw_finding(host["cves"][0], host="10.0.0.1")
        assert finding.cve_ids == []
        assert not any("nvd.nist.gov" in ref for ref in finding.references)

    def test_a_check_finding_carries_no_kev_or_epss(self):
        host = self._host_with_finding()
        finding = parse_raw_finding(host["cves"][0], host="10.0.0.1")
        assert finding.in_kev is False
        assert not finding.kev_due_date
        assert finding.epss_score is None

    def test_a_real_cve_finding_still_gets_its_nvd_link(self):
        """The other direction: correcting the check path must not strip a CVE."""
        finding = parse_raw_finding(
            network_finding("tls.heartbleed", "heartbeat overread", port=443),
            host="10.0.0.1",
        )
        assert finding.cve_ids == ["CVE-2014-0160"]
        assert any("nvd.nist.gov" in ref for ref in finding.references)

    def test_the_risk_engine_scores_the_host_from_it(self):
        from core.risk import calculate_risk

        host = self._host_with_finding()
        host.update(verify_host_findings(host).as_host_fields())
        score, level = calculate_risk(
            open_ports=host["open_ports"],
            cves=host["cves"],
            http_audit={},
            tls_info={},
        )
        assert score > 0, "a promoted finding must move the host's risk score"
        assert level

    def test_two_probes_reporting_one_condition_deduplicate(self):
        """
        ``default_creds`` and ``ftp_checker`` both test anonymous FTP. Because
        they mint the same identifier, ``deduplicate_cves`` collapses them —
        the reader sees one finding, not the same problem twice.
        """
        from core.risk import deduplicate_cves

        a = network_finding("ftp.anonymous_login", "230 from default_creds", port=21)
        b = network_finding("ftp.anonymous_login", "230 from ftp_checker", port=21)
        assert len(deduplicate_cves([a, b])) == 1
