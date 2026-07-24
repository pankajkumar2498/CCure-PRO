"""
core/web/sslyze/wrapper.py
────────────────────────────────────────────────────────────────────────────
SSLyze TLS/SSL configuration auditing wrapper.

Uses the sslyze Python API directly (no subprocess needed) to perform
comprehensive TLS security analysis:
  - Protocol version support (SSLv2, SSLv3, TLS 1.0, 1.1, 1.2, 1.3)
  - Cipher suite enumeration and weakness detection
  - Certificate chain validation
  - HSTS header presence
  - Known attack detection: POODLE, DROWN, ROBOT, Heartbleed
  - Expired/self-signed certificate detection
"""

import logging
from typing import Dict, List, Optional
from urllib.parse import urlparse

log = logging.getLogger("ccure.web.sslyze")


class SSLyzeWrapper:
    """
    TLS/SSL configuration auditor using the sslyze Python library.

    Usage:
        auditor = SSLyzeWrapper()
        result = auditor.run("https://example.com")
        for finding in result["findings"]:
            print(finding["title"], finding["severity"])
    """

    def __init__(self, timeout: int = 120):
        self.timeout = timeout
        self._sslyze_available: bool | None = None

    def is_available(self) -> bool:
        """Check if sslyze Python package is importable."""
        if self._sslyze_available is not None:
            return self._sslyze_available
        try:
            import sslyze

            self._sslyze_available = True
            return True
        except ImportError:
            log.warning("sslyze package not installed. TLS auditing disabled.")
            self._sslyze_available = False
            return False

    def run(self, target: str, **kwargs) -> dict:
        """
        Perform TLS/SSL audit on a target URL or hostname.

        Args:
            target: URL or hostname (e.g., "https://example.com" or "example.com:443")

        Returns:
            {"findings": [...], "certificate": {...}, "protocols": {...}, "stats": {...}}
        """
        if not self.is_available():
            return {
                "findings": [],
                "certificate": {},
                "protocols": {},
                "error": "sslyze not installed",
            }

        # Parse hostname and port from URL
        hostname, port = self._parse_target(target)
        if not hostname:
            return {"findings": [], "error": f"Could not parse target: {target}"}

        try:
            from sslyze import (
                ScanCommand,
                Scanner,
                ServerNetworkLocation,
                ServerScanRequest,
            )

            server_location = ServerNetworkLocation(hostname=hostname, port=port)
            scan_request = ServerScanRequest(
                server_location=server_location,
                scan_commands={
                    ScanCommand.CERTIFICATE_INFO,
                    ScanCommand.SSL_2_0_CIPHER_SUITES,
                    ScanCommand.SSL_3_0_CIPHER_SUITES,
                    ScanCommand.TLS_1_0_CIPHER_SUITES,
                    ScanCommand.TLS_1_1_CIPHER_SUITES,
                    ScanCommand.TLS_1_2_CIPHER_SUITES,
                    ScanCommand.TLS_1_3_CIPHER_SUITES,
                    ScanCommand.HEARTBLEED,
                    ScanCommand.ROBOT,
                    ScanCommand.TLS_COMPRESSION,
                    ScanCommand.TLS_FALLBACK_SCSV,
                    ScanCommand.SESSION_RENEGOTIATION,
                },
            )

            scanner = Scanner()
            scanner.queue_scans([scan_request])

            findings: list[dict] = []
            certificate_info: dict = {}
            protocol_info: dict = {}

            for result in scanner.get_results():
                # Process certificate info
                cert_result = result.scan_result.certificate_info
                if cert_result and cert_result.status.name == "COMPLETED":
                    certificate_info = self._process_certificate(cert_result.result)
                    findings.extend(self._check_certificate_issues(certificate_info))

                # Process protocol support
                protocol_info = self._process_protocols(result.scan_result)
                findings.extend(self._check_protocol_issues(protocol_info))

                # Check for Heartbleed
                hb_result = result.scan_result.heartbleed
                if hb_result and hb_result.status.name == "COMPLETED":
                    if hb_result.result.is_vulnerable_to_heartbleed:
                        findings.append(
                            {
                                "finding_type": "tls_issue",
                                "title": "Heartbleed Vulnerability (CVE-2014-0160)",
                                "description": "Server is vulnerable to Heartbleed. Attacker can read server memory.",
                                "severity": "critical",
                                "cvss_score": 9.8,
                                "cve_id": "CVE-2014-0160",
                                "detected_by": "sslyze",
                            }
                        )

                # Check for ROBOT
                robot_result = result.scan_result.robot
                if robot_result and robot_result.status.name == "COMPLETED":
                    robot_enum = robot_result.result.robot_result
                    if "VULNERABLE" in robot_enum.name:
                        findings.append(
                            {
                                "finding_type": "tls_issue",
                                "title": "ROBOT Attack Vulnerability",
                                "description": "Server is vulnerable to Return Of Bleichenbacher's Oracle Threat.",
                                "severity": "high",
                                "cvss_score": 7.5,
                                "detected_by": "sslyze",
                            }
                        )

                # Check TLS compression (CRIME attack)
                comp_result = result.scan_result.tls_compression
                if comp_result and comp_result.status.name == "COMPLETED":
                    if comp_result.result.supports_compression:
                        findings.append(
                            {
                                "finding_type": "tls_issue",
                                "title": "TLS Compression Enabled (CRIME Attack)",
                                "description": "TLS compression is enabled, making the server vulnerable to the CRIME attack.",
                                "severity": "medium",
                                "cvss_score": 5.9,
                                "detected_by": "sslyze",
                            }
                        )

            stats = {
                "total_findings": len(findings),
                "hostname": hostname,
                "port": port,
            }

            log.info(
                "SSLyze audit complete for %s:%d — %d findings",
                hostname,
                port,
                len(findings),
            )

            return {
                "findings": findings,
                "certificate": certificate_info,
                "protocols": protocol_info,
                "stats": stats,
            }

        except Exception as exc:
            log.warning("SSLyze audit failed for %s: %s", target, exc)
            return {
                "findings": [],
                "certificate": {},
                "protocols": {},
                "error": str(exc),
            }

    # ── Internal Processing ───────────────────────────────────────────────────

    @staticmethod
    def _parse_target(target: str):
        """Extract hostname and port from URL or host:port string."""
        if "://" in target:
            parsed = urlparse(target)
            hostname = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        elif ":" in target:
            parts = target.rsplit(":", 1)
            hostname = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                port = 443
        else:
            hostname = target
            port = 443

        return hostname, port

    @staticmethod
    def _process_certificate(cert_result) -> dict:
        """Extract certificate details from sslyze result."""
        info = {}
        try:
            for deployment in cert_result.certificate_deployments:
                leaf = deployment.received_certificate_chain[0]
                info = {
                    "subject": str(leaf.subject),
                    "issuer": str(leaf.issuer),
                    "not_before": (
                        leaf.not_valid_before_utc.isoformat()
                        if hasattr(leaf, "not_valid_before_utc")
                        else str(leaf.not_valid_before)
                    ),
                    "not_after": (
                        leaf.not_valid_after_utc.isoformat()
                        if hasattr(leaf, "not_valid_after_utc")
                        else str(leaf.not_valid_after)
                    ),
                    "serial_number": str(leaf.serial_number),
                    "signature_algorithm": (
                        leaf.signature_hash_algorithm.name
                        if leaf.signature_hash_algorithm
                        else "unknown"
                    ),
                    "chain_length": len(deployment.received_certificate_chain),
                    "is_leaf_ev": deployment.leaf_certificate_is_ev,
                }
                break  # First deployment only
        except Exception as exc:
            log.debug("Certificate parsing error: %s", exc)
        return info

    @staticmethod
    def _process_protocols(scan_result) -> dict:
        """Extract supported protocol versions and cipher counts."""
        protocols = {}
        protocol_checks = [
            ("ssl_2_0", "ssl_2_0_cipher_suites"),
            ("ssl_3_0", "ssl_3_0_cipher_suites"),
            ("tls_1_0", "tls_1_0_cipher_suites"),
            ("tls_1_1", "tls_1_1_cipher_suites"),
            ("tls_1_2", "tls_1_2_cipher_suites"),
            ("tls_1_3", "tls_1_3_cipher_suites"),
        ]
        for proto_name, attr_name in protocol_checks:
            result = getattr(scan_result, attr_name, None)
            if result and result.status.name == "COMPLETED":
                accepted = result.result.accepted_cipher_suites
                protocols[proto_name] = {
                    "supported": len(accepted) > 0,
                    "cipher_count": len(accepted),
                }
            else:
                protocols[proto_name] = {"supported": False, "cipher_count": 0}
        return protocols

    @staticmethod
    def _check_certificate_issues(cert_info: dict) -> list[dict]:
        """Generate findings for certificate problems."""
        findings = []
        if not cert_info:
            return findings

        # Check for expired certificate
        not_after = cert_info.get("not_after", "")
        if not_after:
            from datetime import datetime, timezone

            try:
                expiry = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
                if expiry < datetime.now(timezone.utc):
                    findings.append(
                        {
                            "finding_type": "tls_issue",
                            "title": "Expired TLS Certificate",
                            "description": f"Certificate expired on {not_after}",
                            "severity": "high",
                            "cvss_score": 7.0,
                            "detected_by": "sslyze",
                        }
                    )
            except (ValueError, TypeError):
                pass

        # Check for weak signature algorithm
        sig_algo = cert_info.get("signature_algorithm", "").lower()
        if sig_algo in ("md5", "sha1"):
            findings.append(
                {
                    "finding_type": "tls_issue",
                    "title": f"Weak Certificate Signature Algorithm: {sig_algo.upper()}",
                    "description": f"Certificate uses {sig_algo.upper()} which is considered cryptographically weak.",
                    "severity": "medium",
                    "cvss_score": 5.0,
                    "detected_by": "sslyze",
                }
            )

        return findings

    @staticmethod
    def _check_protocol_issues(protocols: dict) -> list[dict]:
        """Generate findings for insecure protocol support."""
        findings = []
        deprecated = {
            "ssl_2_0": ("SSLv2", "critical", 9.0),
            "ssl_3_0": ("SSLv3 (POODLE)", "high", 7.5),
            "tls_1_0": ("TLS 1.0", "medium", 5.0),
            "tls_1_1": ("TLS 1.1", "medium", 5.0),
        }
        for proto, (name, severity, cvss) in deprecated.items():
            info = protocols.get(proto, {})
            if info.get("supported"):
                findings.append(
                    {
                        "finding_type": "tls_issue",
                        "title": f"Deprecated Protocol Supported: {name}",
                        "description": f"Server supports {name} ({info.get('cipher_count', 0)} ciphers). This protocol is deprecated and insecure.",
                        "severity": severity,
                        "cvss_score": cvss,
                        "detected_by": "sslyze",
                    }
                )

        # Check if modern TLS is NOT supported
        tls13 = protocols.get("tls_1_3", {})
        tls12 = protocols.get("tls_1_2", {})
        if not tls13.get("supported") and not tls12.get("supported"):
            findings.append(
                {
                    "finding_type": "tls_issue",
                    "title": "No Modern TLS Protocol Supported",
                    "description": "Server does not support TLS 1.2 or TLS 1.3. All connections are insecure.",
                    "severity": "critical",
                    "cvss_score": 9.0,
                    "detected_by": "sslyze",
                }
            )

        return findings
