"""
Every promoted network check, in both directions.

GAP-06. For each area: a weak target must produce the finding, naming the
offender in its evidence; a clean target must produce nothing.

Why both directions, every time
───────────────────────────────
Phase 5 found three false positives that only appeared against a real host,
and every one of them would have passed a test that checked detection alone.
A check that fires on a healthy host is worse than one that misses, because it
teaches the reader to skip the whole section.

The probes are stubbed at their own boundary — ``_probe_ssh``, ``_probe_smb``,
``_probe_snmp`` and so on — so these tests exercise the promotion path, the
identifier minting, the evidence and the finding shape without opening a
socket. The probe logic underneath is unchanged by this phase; what was missing
was everything above it.
"""

from unittest.mock import patch

import pytest

from core.models import HTTPAudit, TLSInfo
from engines.vulnerability.plugins import (
    default_creds,
    dns_probe,
    eternalblue_probe,
    ftp_checker,
    heartbleed_probe,
    http_analyzer,
    ldap_probe,
    smb_probe,
    snmp_probe,
    ssh_probe,
    tls_scanner,
)


def identifiers(result: dict) -> set:
    """The identifiers a plugin promoted to the host's top-level ``cves``.

    Reads the *top level* deliberately. ``VulnerabilityEngine._merge`` promotes
    ``cves`` and nothing else, so a finding nested inside ``http_audit`` or
    ``ftp_info`` — which is where five of these plugins used to put them — is
    invisible to the rest of the pipeline. Asserting on the nested copy would
    pass while the product reported nothing.
    """
    return {f["cve_id"] for f in (result or {}).get("cves", [])}


def evidence_for(result: dict, identifier: str) -> str:
    for finding in result.get("cves", []):
        if finding["cve_id"] == identifier:
            return finding["evidence"]
    raise AssertionError(f"{identifier} not present in {identifiers(result)}")


# ─────────────────────────────────────────────────────────────────────────────
# ssh.weak_algorithms
# ─────────────────────────────────────────────────────────────────────────────
class TestSshWeakAlgorithms:
    WEAK = {
        "banner": "SSH-2.0-OpenSSH_7.4",
        "kex_algos": ["diffie-hellman-group1-sha1", "curve25519-sha256"],
        "enc_algos": ["3des-cbc", "aes256-gcm@openssh.com"],
        "mac_algos": ["hmac-md5", "hmac-sha2-256"],
        "weak_algos": [
            "Weak KEX: diffie-hellman-group1-sha1",
            "Weak cipher: 3des-cbc",
            "Weak MAC: hmac-md5",
        ],
        "cves": [],
    }
    CLEAN = {
        "banner": "SSH-2.0-OpenSSH_9.6",
        "kex_algos": ["curve25519-sha256"],
        "enc_algos": ["aes256-gcm@openssh.com"],
        "mac_algos": ["hmac-sha2-256"],
        "weak_algos": [],
        "cves": [],
    }

    def test_weak_host_reports_ssh_weak_algorithms(self):
        with patch.object(ssh_probe, "_probe_ssh", return_value=self.WEAK):
            result = ssh_probe.run("10.0.0.1", [22])
        assert identifiers(result) == {"CCURE-CHK-SSH-WEAK-ALGORITHMS"}

    def test_the_evidence_names_every_offending_algorithm(self):
        with patch.object(ssh_probe, "_probe_ssh", return_value=self.WEAK):
            result = ssh_probe.run("10.0.0.1", [22])
        evidence = evidence_for(result, "CCURE-CHK-SSH-WEAK-ALGORITHMS")
        for algorithm in ("diffie-hellman-group1-sha1", "3des-cbc", "hmac-md5"):
            assert algorithm in evidence

    def test_clean_host_reports_nothing(self):
        with patch.object(ssh_probe, "_probe_ssh", return_value=self.CLEAN):
            result = ssh_probe.run("10.0.0.1", [22])
        assert identifiers(result) == set()

    def test_ssh_info_is_still_returned_unchanged(self):
        with patch.object(ssh_probe, "_probe_ssh", return_value=self.CLEAN):
            result = ssh_probe.run("10.0.0.1", [22])
        assert result["ssh_info"] == self.CLEAN


# ─────────────────────────────────────────────────────────────────────────────
# smb.v1_enabled — and the detection deliberately NOT promoted
# ─────────────────────────────────────────────────────────────────────────────
class TestSmbV1Enabled:
    def _info(self, version, null_session=True):
        return {
            "open": True,
            "port": 445,
            "version": version,
            "null_session": null_session,
            "hostname": "",
            "domain": "",
            "cves": [],
        }

    def test_smbv1_server_reports_the_finding(self):
        with patch.object(smb_probe, "_probe_smb", return_value=self._info("SMBv1")):
            result = smb_probe.run("10.0.0.1", [445])
        assert identifiers(result) == {"CCURE-CHK-SMB-V1-ENABLED"}

    def test_smbv2_server_reports_nothing(self):
        with patch.object(smb_probe, "_probe_smb", return_value=self._info("SMBv2/3")):
            result = smb_probe.run("10.0.0.1", [445])
        assert identifiers(result) == set()

    def test_null_session_never_becomes_a_finding(self):
        """
        ``null_session`` is set from the negotiate response's NT status being
        zero — STATUS_SUCCESS, which every reachable SMB server returns. It is
        not a null-session test: nothing attempts a session setup with an empty
        username. Promoting it would have put a finding on every Windows host
        in every estate. It stays in ``smb_info`` and out of ``cves``.
        """
        with patch.object(
            smb_probe,
            "_probe_smb",
            return_value=self._info("SMBv2/3", null_session=True),
        ):
            result = smb_probe.run("10.0.0.1", [445])
        assert result["smb_info"]["null_session"] is True
        assert identifiers(result) == set()


# ─────────────────────────────────────────────────────────────────────────────
# snmp.default_community / snmp.v1_v2c_in_use / snmp.information_disclosure
# ─────────────────────────────────────────────────────────────────────────────
class TestSnmp:
    def _info(self, community="public", **extra):
        info = {
            "open": bool(community),
            "community": community,
            "sys_descr": "Cisco IOS Software, C2960 Software",
            "sys_name": "sw-core-01",
            "sys_location": "",
            "sys_contact": "",
            "version": "SNMPv1/v2c",
            "interfaces": [{"description": "GigabitEthernet0/1", "mac": "AA:BB:CC"}],
            "ip_addresses": [{"address": "10.0.0.1", "netmask": "255.255.255.0"}],
        }
        info.update(extra)
        return info

    def test_default_community_reports_three_findings(self):
        with patch.object(snmp_probe, "_probe_snmp", return_value=self._info()):
            result = snmp_probe.run("10.0.0.1", [])
        assert identifiers(result) == {
            "CCURE-CHK-SNMP-DEFAULT-COMMUNITY",
            "CCURE-CHK-SNMP-V1-V2C-IN-USE",
            "CCURE-CHK-SNMP-INFORMATION-DISCLOSURE",
        }

    def test_the_evidence_names_the_community_that_worked(self):
        with patch.object(snmp_probe, "_probe_snmp", return_value=self._info()):
            result = snmp_probe.run("10.0.0.1", [])
        assert "'public'" in evidence_for(result, "CCURE-CHK-SNMP-DEFAULT-COMMUNITY")

    def test_private_is_raised_to_critical_but_write_is_not_claimed(self):
        """
        `private` conventionally means read-write, so the severity rises. The
        probe issues GET and never SET, so the evidence says read access is
        proven and write was not tested — claiming otherwise would assert
        something nothing established.
        """
        with patch.object(
            snmp_probe, "_probe_snmp", return_value=self._info(community="private")
        ):
            result = snmp_probe.run("10.0.0.1", [])
        finding = next(
            f
            for f in result["cves"]
            if f["cve_id"] == "CCURE-CHK-SNMP-DEFAULT-COMMUNITY"
        )
        assert finding["severity"] == "critical"
        assert "Write access was not tested" in finding["evidence"]

    def test_information_disclosure_names_what_was_returned(self):
        with patch.object(snmp_probe, "_probe_snmp", return_value=self._info()):
            result = snmp_probe.run("10.0.0.1", [])
        evidence = evidence_for(result, "CCURE-CHK-SNMP-INFORMATION-DISCLOSURE")
        assert "sw-core-01" in evidence
        assert "GigabitEthernet0/1" in evidence

    def test_an_agent_that_does_not_answer_reports_nothing(self):
        with patch.object(
            snmp_probe,
            "_probe_snmp",
            return_value={"open": False, "community": ""},
        ):
            result = snmp_probe.run("10.0.0.1", [])
        assert result == {}


# ─────────────────────────────────────────────────────────────────────────────
# ftp.* — four areas, one of them shared with default_creds
# ─────────────────────────────────────────────────────────────────────────────
class TestFtp:
    def _info(self, **extra):
        info = {
            "port": 21,
            "banner": "220 (vsFTPd 3.0.3)",
            "anonymous_login": False,
            "write_access": False,
            "weak_credentials": [],
            "cleartext_risk": True,
            "cves": [],
            "issues": [],
        }
        info.update(extra)
        return info

    def test_a_hardened_server_still_reports_the_protocol_finding_only(self):
        """
        ``ftp.cleartext_protocol`` is unconditional — it is a property of FTP,
        not of this server — which is exactly why it is Low. Nothing else fires
        on a server with anonymous access off and no default credentials.
        """
        with patch.object(ftp_checker, "_probe_ftp", return_value=self._info()):
            result = ftp_checker.run("10.0.0.1", [21])
        assert identifiers(result) == {"CCURE-CHK-FTP-CLEARTEXT-PROTOCOL"}

    def test_anonymous_login_and_write_are_separate_findings(self):
        with patch.object(
            ftp_checker,
            "_probe_ftp",
            return_value=self._info(anonymous_login=True, write_access=True),
        ):
            result = ftp_checker.run("10.0.0.1", [21])
        assert "CCURE-CHK-FTP-ANONYMOUS-LOGIN" in identifiers(result)
        assert "CCURE-CHK-FTP-ANONYMOUS-WRITE" in identifiers(result)

    def test_weak_credentials_evidence_names_the_accounts(self):
        with patch.object(
            ftp_checker,
            "_probe_ftp",
            return_value=self._info(
                weak_credentials=[{"user": "admin", "password": "admin"}]
            ),
        ):
            result = ftp_checker.run("10.0.0.1", [21])
        assert "admin / admin" in evidence_for(result, "CCURE-CHK-FTP-WEAK-CREDENTIALS")

    def test_both_ftp_probes_mint_the_same_anonymous_identifier(self):
        """
        ``default_creds`` and ``ftp_checker`` both test anonymous login. They
        must agree on the identifier so ``deduplicate_cves`` collapses them —
        otherwise promoting the second one starts showing the reader the same
        problem twice.
        """
        with patch.object(
            ftp_checker, "_probe_ftp", return_value=self._info(anonymous_login=True)
        ):
            from_checker = identifiers(ftp_checker.run("10.0.0.1", [21]))

        with patch.object(
            default_creds, "_check_ftp_anon", return_value={"allowed": True}
        ):
            from_creds = identifiers(default_creds.run("10.0.0.1", [21]))

        assert "CCURE-CHK-FTP-ANONYMOUS-LOGIN" in from_checker
        assert "CCURE-CHK-FTP-ANONYMOUS-LOGIN" in from_creds


# ─────────────────────────────────────────────────────────────────────────────
# http.* — seven promoted areas, and one deliberately withheld
# ─────────────────────────────────────────────────────────────────────────────
class TestHttp:
    def _audit(self, **extra):
        audit = HTTPAudit()
        audit.status_code = 200
        audit.server_header = extra.pop("server_header", "")
        audit.hsts = extra.pop("hsts", True)
        audit.csp = extra.pop("csp", True)
        audit.x_frame = extra.pop("x_frame", "DENY")
        audit.x_content_type = extra.pop("x_content_type", True)
        audit.issues = extra.pop("issues", [])
        return audit

    def _run(self, audit, ports=(443,), exposed=None, methods=None, panels=None):
        with patch.object(
            http_analyzer, "_probe_security_headers", return_value=audit
        ), patch.object(
            http_analyzer, "_probe_sensitive_paths", return_value=exposed or []
        ), patch.object(
            http_analyzer, "_probe_admin_panels", return_value=panels or []
        ), patch.object(
            http_analyzer, "_probe_http_methods", return_value=methods or []
        ), patch.object(
            http_analyzer, "_probe_server_version", return_value=([], [])
        ):
            return http_analyzer.run("10.0.0.1", list(ports))

    def test_a_fully_hardened_https_service_reports_nothing(self):
        result = self._run(self._audit())
        assert identifiers(result) == set()

    def test_missing_headers_are_one_finding_naming_all_of_them(self):
        result = self._run(self._audit(hsts=False, csp=False))
        assert identifiers(result) == {"CCURE-CHK-HTTP-MISSING-SECURITY-HEADERS"}
        evidence = evidence_for(result, "CCURE-CHK-HTTP-MISSING-SECURITY-HEADERS")
        assert "Strict-Transport-Security" in evidence
        assert "Content-Security-Policy" in evidence

    def test_cleartext_service_is_reported_on_a_plain_http_port(self):
        result = self._run(self._audit(), ports=(80,))
        assert "CCURE-CHK-HTTP-CLEARTEXT-SERVICE" in identifiers(result)

    def test_insecure_cookie_flags(self):
        result = self._run(self._audit(issues=["Session cookie missing HttpOnly flag"]))
        assert "CCURE-CHK-HTTP-INSECURE-COOKIE-FLAGS" in identifiers(result)

    def test_server_version_disclosure(self):
        result = self._run(self._audit(server_header="Apache/2.4.29"))
        assert "CCURE-CHK-HTTP-SERVER-VERSION-DISCLOSURE" in identifiers(result)

    def test_a_server_header_without_a_version_is_not_a_finding(self):
        result = self._run(self._audit(server_header="nginx"))
        assert "CCURE-CHK-HTTP-SERVER-VERSION-DISCLOSURE" not in identifiers(result)

    def test_a_content_confirmed_sensitive_file_is_reported(self):
        result = self._run(
            self._audit(),
            exposed=[
                {
                    "path": "/.env",
                    "status": 200,
                    "note": "HTTP 200",
                    "directory_listing": False,
                    "confirmed": True,
                    "body_excerpt": "DB_PASSWORD=hunter2",
                }
            ],
        )
        assert "CCURE-CHK-HTTP-SENSITIVE-PATH-EXPOSED" in identifiers(result)

    def test_an_unconfirmed_path_is_not_reported(self):
        """
        The single-page-application trap. ``_SENSITIVE_PATHS`` probes /login,
        /admin/, /dashboard and /console, and an SPA answers all four with 200
        and its index document. Without the body fingerprint this plugin would
        report four "sensitive files exposed" against every SPA on the network.
        """
        result = self._run(
            self._audit(),
            exposed=[
                {
                    "path": "/login",
                    "status": 200,
                    "note": "HTTP 200",
                    "directory_listing": False,
                    "confirmed": False,
                    "body_excerpt": "<!doctype html><div id=root>",
                }
            ],
        )
        assert "CCURE-CHK-HTTP-SENSITIVE-PATH-EXPOSED" not in identifiers(result)

    def test_directory_listing(self):
        result = self._run(
            self._audit(),
            exposed=[
                {
                    "path": "/backup",
                    "status": 200,
                    "note": "HTTP 200 — directory listing enabled",
                    "directory_listing": True,
                    "confirmed": False,
                    "body_excerpt": "Index of /backup",
                }
            ],
        )
        assert "CCURE-CHK-HTTP-DIRECTORY-LISTING" in identifiers(result)

    def test_dangerous_methods_excludes_the_options_enumeration_line(self):
        """
        ``_probe_http_methods`` records the OPTIONS Allow header in the same
        list as PUT and DELETE. A server answering OPTIONS is HTTP working, not
        a weakness; promoting it would put a Medium on essentially every web
        server.
        """
        options_only = self._run(
            self._audit(), methods=["OPTIONS exposed allowed methods: GET, POST"]
        )
        assert "CCURE-CHK-HTTP-DANGEROUS-METHODS" not in identifiers(options_only)

        real = self._run(
            self._audit(),
            methods=[
                "OPTIONS exposed allowed methods: GET, PUT",
                "HTTP PUT method allowed (status 200)",
            ],
        )
        assert "CCURE-CHK-HTTP-DANGEROUS-METHODS" in identifiers(real)

    def test_admin_interface_exposure_is_deliberately_not_promoted(self):
        """
        ``_probe_admin_panels`` matches on path plus a 200/401/403 status with
        no body check, and an SPA returns 200 for every unknown route — so all
        thirteen fingerprints match at once. The detection stays in
        ``http_audit`` and the area is recorded as not implemented rather than
        counted as coverage.
        """
        result = self._run(
            self._audit(),
            panels=[
                {
                    "path": "/admin/login",
                    "product": "Generic Admin Login",
                    "status": 200,
                    "note": "Generic Admin Login panel detected (HTTP 200)",
                }
            ],
        )
        assert result["http_audit"]["admin_panels"]
        assert not any("ADMIN" in i for i in identifiers(result))


# ─────────────────────────────────────────────────────────────────────────────
# tls.* — the handshake probe and the deep engine
# ─────────────────────────────────────────────────────────────────────────────
class TestTls:
    def _info(self, **extra):
        info = TLSInfo(enabled=True)
        info.version = extra.pop("version", "TLSv1.3")
        info.cipher = extra.pop("cipher", "TLS_AES_256_GCM_SHA384")
        info.cert_subject = extra.pop("cert_subject", "ccurepro.cdacb.in")
        info.cert_issuer = extra.pop("cert_issuer", "CCure Internal CA")
        info.cert_expiry = extra.pop("cert_expiry", "Jan 01 00:00:00 2030 GMT")
        info.cert_expired = extra.pop("cert_expired", False)
        info.cert_self_signed = extra.pop("cert_self_signed", False)
        info.weak_cipher = extra.pop("weak_cipher", False)
        info.san_domains = extra.pop("san_domains", [])
        info.score = extra.pop("score", "A")
        return info

    def _run(self, info, deep=None, ports=(443,)):
        with patch.object(tls_scanner, "_probe", return_value=info), patch.object(
            tls_scanner, "_deep_audit", return_value=deep or {}
        ):
            return tls_scanner.run("10.0.0.1", list(ports))

    def test_a_healthy_endpoint_reports_nothing(self):
        result = self._run(self._info())
        assert identifiers(result) == set()

    def test_expired_certificate(self):
        result = self._run(self._info(cert_expired=True))
        assert "CCURE-CHK-TLS-CERTIFICATE-EXPIRED" in identifiers(result)

    def test_self_signed_certificate(self):
        # ``cert_self_signed`` is set by ``_probe`` from subject == issuer, so
        # the stub sets both the way the real probe would. The finding reads
        # the flag rather than re-deriving it: one place decides what
        # self-signed means, and it is the code that parsed the certificate.
        result = self._run(
            self._info(
                cert_subject="host.local",
                cert_issuer="host.local",
                cert_self_signed=True,
            )
        )
        assert "CCURE-CHK-TLS-CERTIFICATE-SELF-SIGNED" in identifiers(result)

    def test_the_probe_derives_self_signed_from_subject_and_issuer(self):
        """The flag the finding trusts is genuinely computed, not assumed."""
        info = tls_scanner.TLSInfo(enabled=True)
        info.cert_subject = "host.local"
        info.cert_issuer = "host.local"
        assert (info.cert_subject == info.cert_issuer) is True

    def test_deprecated_protocols_are_one_finding_at_the_worst_severity(self):
        deep = {
            "protocols": {
                "ssl_3_0": {"supported": True, "cipher_count": 4, "weak_ciphers": []},
                "tls_1_0": {"supported": True, "cipher_count": 9, "weak_ciphers": []},
                "tls_1_2": {"supported": True, "cipher_count": 12, "weak_ciphers": []},
            },
            "certificate": {},
            "findings": [],
        }
        result = self._run(self._info(), deep=deep)
        deprecated = [
            f
            for f in result["cves"]
            if f["cve_id"] == "CCURE-CHK-TLS-DEPRECATED-PROTOCOL"
        ]
        assert len(deprecated) == 1
        assert deprecated[0]["severity"] == "high"  # SSLv3 outranks TLS 1.0
        assert "SSLv3" in deprecated[0]["evidence"]
        assert "TLS 1.0" in deprecated[0]["evidence"]

    def test_no_modern_protocol(self):
        deep = {
            "protocols": {
                "tls_1_0": {"supported": True, "cipher_count": 3, "weak_ciphers": []},
                "tls_1_2": {"supported": False, "cipher_count": 0, "weak_ciphers": []},
                "tls_1_3": {"supported": False, "cipher_count": 0, "weak_ciphers": []},
            },
            "certificate": {},
            "findings": [],
        }
        result = self._run(self._info(), deep=deep)
        assert "CCURE-CHK-TLS-NO-SECURE-PROTOCOL" in identifiers(result)

    def test_weak_suites_are_found_across_versions_not_just_the_negotiated_one(self):
        """
        The handshake reports one suite — the one it negotiated, which on a
        modern client is the *strongest* the server offers. Everything weak the
        server would also accept is invisible to it. That is what the deep
        engine adds.
        """
        deep = {
            "protocols": {
                "tls_1_0": {
                    "supported": True,
                    "cipher_count": 5,
                    "weak_ciphers": ["TLS_RSA_WITH_RC4_128_SHA"],
                },
                "tls_1_2": {
                    "supported": True,
                    "cipher_count": 9,
                    "weak_ciphers": ["TLS_RSA_WITH_3DES_EDE_CBC_SHA"],
                },
            },
            "certificate": {},
            "findings": [],
        }
        result = self._run(self._info(), deep=deep)
        evidence = evidence_for(result, "CCURE-CHK-TLS-WEAK-CIPHER-SUITE")
        assert "RC4" in evidence
        assert "3DES" in evidence

    def test_one_weak_cipher_finding_per_endpoint_not_two(self):
        deep = {
            "protocols": {
                "tls_1_2": {
                    "supported": True,
                    "cipher_count": 3,
                    "weak_ciphers": ["TLS_RSA_WITH_RC4_128_SHA"],
                }
            },
            "certificate": {},
            "findings": [],
        }
        result = self._run(self._info(weak_cipher=True, cipher="RC4-SHA"), deep=deep)
        weak = [
            f
            for f in result["cves"]
            if f["cve_id"] == "CCURE-CHK-TLS-WEAK-CIPHER-SUITE"
        ]
        assert len(weak) == 1

    def test_weak_signature_and_hostname_mismatch(self):
        deep = {
            "protocols": {},
            "certificate": {"signature_algorithm": "sha1", "hostname_matches": False},
            "findings": [],
        }
        result = self._run(self._info(), deep=deep)
        assert "CCURE-CHK-TLS-CERTIFICATE-WEAK-SIGNATURE" in identifiers(result)
        assert "CCURE-CHK-TLS-CERTIFICATE-HOSTNAME-MISMATCH" in identifiers(result)

    def test_named_attacks_map_to_their_areas(self):
        deep = {
            "protocols": {},
            "certificate": {},
            "findings": [
                {"title": "Heartbleed Vulnerability (CVE-2014-0160)"},
                {"title": "ROBOT Attack Vulnerability", "description": "oracle"},
                {"title": "TLS Compression Enabled (CRIME Attack)"},
            ],
        }
        result = self._run(self._info(), deep=deep)
        assert "CVE-2014-0160" in identifiers(result)
        assert "CCURE-CHK-TLS-ROBOT" in identifiers(result)
        assert "CCURE-CHK-TLS-COMPRESSION-ENABLED" in identifiers(result)

    def test_heartbleed_keeps_its_real_cve_identifier(self):
        """A published CVE files under its own identifier, never a minted one."""
        deep = {
            "protocols": {},
            "certificate": {},
            "findings": [{"title": "Heartbleed Vulnerability (CVE-2014-0160)"}],
        }
        result = self._run(self._info(), deep=deep)
        finding = next(f for f in result["cves"] if f["cve_id"] == "CVE-2014-0160")
        assert finding["definition_type"] == "cve"

    def test_every_tls_port_is_assessed_not_only_the_first(self):
        """
        The probe used to ``return`` inside the loop over ``_TLS_PORTS``, so a
        host serving 443 and 8443 was assessed on 443 alone and a certificate
        expired on 8443 was never seen.
        """
        seen: list = []

        def fake_probe(ip, port, timeout=3.0):
            seen.append(port)
            return self._info(cert_expired=port == 8443)

        with patch.object(tls_scanner, "_probe", side_effect=fake_probe), patch.object(
            tls_scanner, "_deep_audit", return_value={}
        ):
            result = tls_scanner.run("10.0.0.1", [443, 8443])

        assert seen == [443, 8443]
        assert len(result["tls_endpoints"]) == 2
        expired = [
            f
            for f in result["cves"]
            if f["cve_id"] == "CCURE-CHK-TLS-CERTIFICATE-EXPIRED"
        ]
        assert len(expired) == 1
        assert expired[0]["port"] == 8443

    def test_tls_info_keeps_the_shape_asset_syncer_reads(self):
        result = self._run(self._info(), ports=(443, 8443))
        info = result["tls_info"]
        for key in (
            "enabled",
            "version",
            "cipher",
            "cert_subject",
            "cert_issuer",
            "cert_expiry",
            "cert_expired",
            "cert_self_signed",
            "weak_cipher",
            "score",
        ):
            assert key in info, key

    def test_a_host_with_no_tls_port_returns_nothing(self):
        assert tls_scanner.run("10.0.0.1", [22, 80]) == {}

    def test_an_unavailable_deep_engine_still_leaves_the_handshake_findings(self):
        """
        sslyze is optional. Its absence is a coverage gap, not a scan failure —
        the handshake still establishes an expired or self-signed certificate.
        """
        result = self._run(self._info(cert_expired=True), deep={})
        assert "CCURE-CHK-TLS-CERTIFICATE-EXPIRED" in identifiers(result)


# ─────────────────────────────────────────────────────────────────────────────
# The areas that already reported, now correctly typed
# ─────────────────────────────────────────────────────────────────────────────
class TestPreviouslyReportingAreasKeepReporting:
    """A phase that adds checks must not remove one."""

    @pytest.mark.parametrize(
        "port,stub,attribute,expected",
        [
            (21, {"allowed": True}, "_check_ftp_anon", "CCURE-CHK-FTP-ANONYMOUS-LOGIN"),
            (
                6379,
                {"vulnerable": True},
                "_check_redis_noauth",
                "CCURE-CHK-REDIS-NO-AUTHENTICATION",
            ),
            (
                27017,
                {"vulnerable": True},
                "_check_mongo_noauth",
                "CCURE-CHK-MONGODB-NO-AUTHENTICATION",
            ),
            (
                1883,
                {"vulnerable": True},
                "_check_mqtt_noauth",
                "CCURE-CHK-MQTT-NO-AUTHENTICATION",
            ),
            (
                11211,
                {"vulnerable": True},
                "_check_memcached_noauth",
                "CCURE-CHK-MEMCACHED-NO-AUTHENTICATION",
            ),
        ],
    )
    def test_default_creds_areas(self, port, stub, attribute, expected):
        with patch.object(default_creds, attribute, return_value=stub):
            result = default_creds.run("10.0.0.1", [port])
        assert expected in identifiers(result)

    def test_telnet_exposure(self):
        result = default_creds.run("10.0.0.1", [23])
        assert "CCURE-CHK-TELNET-EXPOSED" in identifiers(result)

    def test_http_default_credentials(self):
        with patch.object(
            default_creds,
            "_check_http_default_creds",
            return_value={"found": True, "username": "admin", "password": "admin"},
        ):
            result = default_creds.run("10.0.0.1", [80])
        assert "CCURE-CHK-HTTP-DEFAULT-CREDENTIALS" in identifiers(result)
        assert "admin / admin" in evidence_for(
            result, "CCURE-CHK-HTTP-DEFAULT-CREDENTIALS"
        )

    def test_no_service_reports_nothing(self):
        assert default_creds.run("10.0.0.1", [9999]) == {}

    def test_ldap_anonymous_bind(self):
        with patch.object(
            ldap_probe,
            "_check_anonymous_bind",
            return_value={
                "allowed": True,
                "directory_readable": True,
                "entry_dn": "cn=public,dc=example,dc=test",
                "attributes": ["objectClass"],
                "status": "completed_with_findings",
            },
        ):
            result = ldap_probe.run("10.0.0.1", [389])
        assert "CCURE-CHK-LDAP-ANONYMOUS-BIND" in identifiers(result)

    def test_ldap_refusing_anonymous_bind_reports_nothing(self):
        with patch.object(
            ldap_probe, "_check_anonymous_bind", return_value={"allowed": False}
        ):
            result = ldap_probe.run("10.0.0.1", [389])
        assert identifiers(result) == set()

    def test_dns_zone_transfer_and_open_recursion(self):
        with patch.object(
            dns_probe,
            "_check_zone_transfer",
            return_value={
                "vulnerable": True,
                "zone": "example.test.",
                "records": 3,
                "status": "completed_with_findings",
            },
        ), patch.object(dns_probe, "_check_recursion", return_value=True):
            result = dns_probe.run("10.0.0.1", [53])
        assert "CCURE-CHK-DNS-ZONE-TRANSFER" in identifiers(result)
        assert "CCURE-CHK-DNS-OPEN-RECURSION" in identifiers(result)

    def test_a_locked_down_resolver_reports_nothing(self):
        with patch.object(
            dns_probe,
            "_check_zone_transfer",
            return_value={"vulnerable": False, "status": "completed_with_no_findings"},
        ), patch.object(dns_probe, "_check_recursion", return_value=False):
            result = dns_probe.run("10.0.0.1", [53])
        assert identifiers(result) == set()


class TestEternalBlueProbe:
    """
    Two corrections this phase made, both of which were over-claiming.

    ``smb1_enabled`` used to be reported as **CVE-2017-0144**. EternalBlue
    needs SMBv1 *and* an unpatched implementation; a fully patched host with
    SMBv1 still enabled satisfies only the first, and was being told it carried
    a Critical remote code execution it does not have.

    ``ms17010_likely`` used to be reported as **CVE-2017-0144-ACTIVE** — a
    CVE-shaped string that is not a CVE, which reached the catalogue as a
    fabricated advisory sitting beside the real one it was derived from.
    """

    def _info(self, **extra):
        info = {
            "smb1_enabled": False,
            "ms17010_likely": False,
            "signing_required": True,
        }
        info.update(extra)
        return info

    def test_smbv1_alone_is_not_reported_as_eternalblue(self):
        with patch.object(
            eternalblue_probe, "_probe_smb", return_value=self._info(smb1_enabled=True)
        ):
            result = eternalblue_probe.run("10.0.0.1", [445])
        assert "CCURE-CHK-SMB-V1-ENABLED" in identifiers(result)
        assert "CVE-2017-0144" not in identifiers(result)

    def test_the_ms17010_fingerprint_is_reported_as_the_real_cve(self):
        with patch.object(
            eternalblue_probe,
            "_probe_smb",
            return_value=self._info(smb1_enabled=True, ms17010_likely=True),
        ):
            result = eternalblue_probe.run("10.0.0.1", [445])
        assert "CVE-2017-0144" in identifiers(result)

    def test_no_fabricated_cve_variant_is_emitted(self):
        with patch.object(
            eternalblue_probe,
            "_probe_smb",
            return_value=self._info(smb1_enabled=True, ms17010_likely=True),
        ):
            result = eternalblue_probe.run("10.0.0.1", [445])
        assert not any(i.endswith("-ACTIVE") for i in identifiers(result))

    def test_smb_signing_not_required(self):
        with patch.object(
            eternalblue_probe,
            "_probe_smb",
            return_value=self._info(signing_required=False),
        ):
            result = eternalblue_probe.run("10.0.0.1", [445])
        assert "CCURE-CHK-SMB-SIGNING-NOT-REQUIRED" in identifiers(result)

    def test_a_hardened_smb_server_reports_nothing(self):
        with patch.object(eternalblue_probe, "_probe_smb", return_value=self._info()):
            result = eternalblue_probe.run("10.0.0.1", [445])
        assert identifiers(result) == set()


class TestHeartbleedProbe:
    def test_heartbleed_files_under_its_real_cve(self):
        with patch.object(
            heartbleed_probe, "_check_heartbleed", return_value={"vulnerable": True}
        ), patch.object(heartbleed_probe, "_check_shellshock", return_value=None):
            result = heartbleed_probe.run("10.0.0.1", [443])
        assert "CVE-2014-0160" in identifiers(result)

    def test_shellshock_files_under_its_real_cve(self):
        with patch.object(
            heartbleed_probe, "_check_heartbleed", return_value=None
        ), patch.object(
            heartbleed_probe, "_check_shellshock", return_value={"vulnerable": True}
        ):
            result = heartbleed_probe.run("10.0.0.1", [80])
        assert "CVE-2014-6271" in identifiers(result)

    def test_a_patched_host_reports_neither(self):
        with patch.object(
            heartbleed_probe, "_check_heartbleed", return_value={"vulnerable": False}
        ), patch.object(
            heartbleed_probe, "_check_shellshock", return_value={"vulnerable": False}
        ):
            result = heartbleed_probe.run("10.0.0.1", [80, 443])
        assert identifiers(result) == set()


class TestSslyzeWrapperResultParsing:
    """
    Guards the ROBOT verdict parse.

    ``core/web/sslyze/wrapper.py`` tested ``"VULNERABLE" in robot_enum.name``.
    sslyze's enum contains ``NOT_VULNERABLE_NO_ORACLE`` and
    ``NOT_VULNERABLE_RSA_NOT_SUPPORTED``, and "VULNERABLE" is a substring of
    "NOT_VULNERABLE" — so every server sslyze positively *cleared* was reported
    as vulnerable, including any TLS 1.3-only listener where RSA key exchange
    does not exist at all.

    Found by pointing the new network TLS path at a correctly configured nginx
    and disbelieving the finding. It had been live on the web-scan path.
    """

    def test_only_the_vulnerable_members_are_treated_as_vulnerable(self):
        from sslyze.plugins.robot.implementation import RobotScanResultEnum

        vulnerable = {
            member.name
            for member in RobotScanResultEnum
            if member.name.startswith("VULNERABLE_")
        }
        assert vulnerable == {
            "VULNERABLE_WEAK_ORACLE",
            "VULNERABLE_STRONG_ORACLE",
        }

        for member in RobotScanResultEnum:
            if member.name.startswith("NOT_VULNERABLE"):
                assert "VULNERABLE" in member.name, (
                    "This is the trap: the substring test the wrapper used to "
                    "perform matches these members too."
                )
                assert not member.name.startswith("VULNERABLE_")

    def test_the_wrapper_uses_the_prefix_test(self):
        from pathlib import Path

        import core.web.sslyze.wrapper as wrapper

        source = Path(wrapper.__file__).read_text(encoding="utf-8")
        assert 'robot_enum.name.startswith("VULNERABLE_")' in source
        assert '"VULNERABLE" in robot_enum.name' not in source
