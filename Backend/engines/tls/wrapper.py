"""
engines/tls/wrapper.py (was core/web/sslyze/wrapper.py until B9)
────────────────────────────────────────────────────────────────────────────
SSLyze TLS/SSL configuration auditing wrapper: the TLS engine the network
checks' TLS plugin and the web scanner's audit phase both use.

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

# The logger keeps its name from core/web/sslyze/: log filters match on it,
# and moving the file (B9) is not a reason to change what the logs say.
log = logging.getLogger("ccure.web.sslyze")


def _describe_public_key(leaf) -> dict:
    """
    The leaf's public key algorithm and size.

    ``{}`` rather than a guess when the key type is one this does not
    recognise: a size compared against the wrong floor is worse than no
    comparison, because it produces a confident finding about a key that may be
    perfectly strong.
    """
    try:
        key = leaf.public_key()
    except Exception:  # pragma: no cover - malformed certificate
        return {}
    # ``isinstance`` against the abstract types, not a substring of the class
    # name. ``cryptography`` spells the concrete classes differently across
    # versions and backends — this build returns ``ECPublicKey``, older ones
    # ``_EllipticCurvePublicKey`` — and a name test that misses returns {},
    # which silently removes the key-strength check for that whole algorithm.
    # Measured: every EC certificate went unclassified until this was fixed.
    try:
        from cryptography.hazmat.primitives.asymmetric import (
            dsa,
            ec,
            ed448,
            ed25519,
            rsa,
        )
    except Exception:  # pragma: no cover - cryptography is a hard dependency
        return {}

    size = getattr(key, "key_size", None)
    if isinstance(key, rsa.RSAPublicKey):
        algorithm = "rsa"
    elif isinstance(key, ec.EllipticCurvePublicKey):
        algorithm = "ec"
        size = getattr(getattr(key, "curve", None), "key_size", size)
    elif isinstance(key, dsa.DSAPublicKey):
        algorithm = "dsa"
    elif isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        # Edwards keys expose no key_size and need none: both sit at or above
        # the 112-bit security level the floors are expressed for, so there is
        # no comparison to make.
        return {"algorithm": "eddsa", "bits": None}
    else:
        # An algorithm this does not recognise. Returning {} withholds the
        # check rather than comparing a size against the wrong floor, which
        # would produce a confident finding about a key that may be strong.
        return {}
    return {"algorithm": algorithm, "bits": int(size) if size else None}


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

    def run(self, target: str, starttls: str = "", **kwargs) -> dict:
        """
        Perform a TLS/SSL audit on a target URL, hostname, or STARTTLS service.

        Args:
            target: URL or hostname (e.g. "https://example.com" or "host:443")
            starttls: an opportunistic-TLS protocol name — ``smtp``, ``imap``,
                ``pop3``, ``ldap``, ``postgres``, ``ftp``. Empty means the port
                speaks TLS immediately, which is every caller that existed
                before GAP-07.

        Returns:
            ``{"findings", "certificate", "protocols", "renegotiation",
            "downgrade", "protocol_features", "key_exchange", "stats"}``

        The four keys after ``protocols`` are GAP-07's. Three of the underlying
        scan commands were **already being requested and their results thrown
        away** — ``TLS_FALLBACK_SCSV`` and ``SESSION_RENEGOTIATION`` since
        before Phase 6, and ``path_validation_results`` was parsed into
        ``chain_trusted`` that nothing read. The cost was already being paid;
        only the reading is new.

        ``findings`` is deliberately unchanged. ``/web-scans`` renders that list
        and this phase is not about altering what an existing report says; the
        network path builds its own findings from the structured data below.
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
                ServerNetworkConfiguration,
                ServerNetworkLocation,
                ServerScanRequest,
            )

            server_location = ServerNetworkLocation(hostname=hostname, port=port)

            network_configuration = None
            if starttls:
                protocol = self._opportunistic_protocol(starttls)
                if protocol is None:
                    return {
                        "findings": [],
                        "certificate": {},
                        "protocols": {},
                        "error": (
                            f"sslyze {self._sslyze_version()} has no "
                            f"opportunistic-TLS handler for {starttls!r}"
                        ),
                    }
                network_configuration = ServerNetworkConfiguration(
                    tls_server_name_indication=hostname,
                    tls_opportunistic_encryption=protocol,
                )

            scan_request = ServerScanRequest(
                server_location=server_location,
                network_configuration=network_configuration,
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
                    # GAP-07. Each is one extra handshake against a listener
                    # whose cipher suites are already being enumerated across
                    # six protocol versions, so the marginal cost is small
                    # beside what this scan already does.
                    ScanCommand.OPENSSL_CCS_INJECTION,
                    ScanCommand.TLS_1_3_EARLY_DATA,
                    ScanCommand.TLS_EXTENDED_MASTER_SECRET,
                },
            )

            scanner = Scanner()
            scanner.queue_scans([scan_request])

            findings: list[dict] = []
            certificate_info: dict = {}
            protocol_info: dict = {}
            renegotiation: dict = {}
            downgrade: dict = {}
            protocol_features: dict = {}
            key_exchange: dict = {}

            for result in scanner.get_results():
                # sslyze leaves ``scan_result`` as None when it could not
                # connect or complete the handshake at all — a port that speaks
                # something else, a STARTTLS negotiation the service refused, a
                # timeout. Reaching through it raises AttributeError, which the
                # outer handler then reports as an opaque
                # "'NoneType' object has no attribute 'certificate_info'".
                #
                # That matters more here than it looks: this is the *normal*
                # outcome for a STARTTLS probe of a service that does not offer
                # it, so it has to say so plainly rather than read as a broken
                # scanner. It is emphatically not evidence that the endpoint's
                # TLS is fine.
                if getattr(result, "scan_result", None) is None:
                    status = getattr(
                        getattr(result, "connectivity_status", None), "name", "?"
                    )
                    return {
                        "findings": [],
                        "certificate": {},
                        "protocols": {},
                        "error": (
                            f"no TLS handshake with {hostname}:{port}"
                            f"{f' via {starttls} STARTTLS' if starttls else ''} "
                            f"(connectivity: {status})"
                        ),
                    }

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
                    # `startswith`, not `in`. sslyze's enum members are
                    # VULNERABLE_WEAK_ORACLE, VULNERABLE_STRONG_ORACLE,
                    # NOT_VULNERABLE_NO_ORACLE, NOT_VULNERABLE_RSA_NOT_SUPPORTED
                    # and UNKNOWN_INCONSISTENT_RESULTS — and the substring test
                    # this used to perform matched the two NOT_VULNERABLE
                    # members as well, because "VULNERABLE" is a substring of
                    # "NOT_VULNERABLE".
                    #
                    # So every server sslyze positively cleared was reported as
                    # vulnerable to ROBOT, including any modern TLS 1.3-only
                    # listener, where RSA key exchange does not exist. Found by
                    # pointing this at a correctly configured nginx and
                    # disbelieving the result.
                    #
                    # UNKNOWN_INCONSISTENT_RESULTS is deliberately not a finding
                    # either: "could not determine" is not a verdict.
                    if robot_enum.name.startswith("VULNERABLE_"):
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

                # ── GAP-07: results already collected and never read ──
                renegotiation = self._process_renegotiation(result.scan_result)
                downgrade = self._process_downgrade(result.scan_result)
                protocol_features = self._process_protocol_features(result.scan_result)
                key_exchange = self._process_key_exchange(result.scan_result)

            stats = {
                "total_findings": len(findings),
                "hostname": hostname,
                "port": port,
                "starttls": starttls or "",
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
                "renegotiation": renegotiation,
                "downgrade": downgrade,
                "protocol_features": protocol_features,
                "key_exchange": key_exchange,
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
        """
        Extract certificate details from sslyze result.

        ``self_signed``, ``hostname_matches`` and ``days_until_expiry`` are
        recorded but deliberately produce **no finding here**. The network scan
        path (``engines/vulnerability/plugins/tls_scanner.py``) builds its own
        findings from them; adding them to ``_check_certificate_issues`` would
        change what every existing web-scan report says, which is not this
        phase's business. Collect once, let each consumer decide.
        """
        info = {}
        try:
            for deployment in cert_result.certificate_deployments:
                leaf = deployment.received_certificate_chain[0]
                info = {
                    "subject": str(leaf.subject),
                    "issuer": str(leaf.issuer),
                    # A self-signed certificate is one that vouches for itself.
                    # sslyze exposes the chain but never compared these two, so
                    # the condition the raw-socket probe had always detected was
                    # absent from the deeper engine.
                    "self_signed": str(leaf.subject) == str(leaf.issuer),
                    "hostname_matches": getattr(
                        deployment, "leaf_certificate_subject_matches_hostname", None
                    ),
                    "chain_trusted": any(
                        getattr(r, "was_validation_successful", False)
                        for r in getattr(deployment, "path_validation_results", [])
                    ),
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
                    # ── GAP-07 ────────────────────────────────────────────
                    # `chain_trusted` above is a bare bool that nothing read.
                    # These say *why*, which is the difference between a
                    # finding somebody can act on and one they cannot.
                    "trust_failures": [
                        {
                            "store": getattr(
                                getattr(r, "trust_store", None), "name", "?"
                            ),
                            "error": str(getattr(r, "validation_error", "") or ""),
                        }
                        for r in getattr(deployment, "path_validation_results", [])
                        if not getattr(r, "was_validation_successful", False)
                    ],
                    "chain_in_valid_order": getattr(
                        deployment, "received_chain_has_valid_order", None
                    ),
                    "chain_has_sha1": getattr(
                        deployment, "verified_chain_has_sha1_signature", None
                    ),
                    "has_must_staple": getattr(
                        deployment, "leaf_certificate_has_must_staple_extension", None
                    ),
                    "ocsp_stapled": getattr(deployment, "ocsp_response", None)
                    is not None,
                    "ocsp_trusted": getattr(
                        deployment, "ocsp_response_is_trusted", None
                    ),
                    "public_key": _describe_public_key(leaf),
                }
                break  # First deployment only
        except Exception as exc:
            log.debug("Certificate parsing error: %s", exc)
        return info

    @staticmethod
    def _sslyze_version() -> str:
        try:
            from sslyze.__version__ import __version__

            return str(__version__)
        except Exception:  # pragma: no cover
            return "?"

    @staticmethod
    def _opportunistic_protocol(name: str):
        """
        The sslyze enum member for a STARTTLS protocol name, or None.

        None rather than a guess: a name this build of sslyze has no handler
        for must surface as "not assessed", never as a connection that failed —
        those look identical in a report and mean opposite things.
        """
        try:
            from sslyze import ProtocolWithOpportunisticTlsEnum
        except Exception:  # pragma: no cover
            return None
        return getattr(
            ProtocolWithOpportunisticTlsEnum, str(name).strip().upper(), None
        )

    @staticmethod
    def _completed(scan_result, attribute):
        """The ``.result`` of a scan command that completed, else None."""
        entry = getattr(scan_result, attribute, None)
        if entry is None or getattr(entry, "status", None) is None:
            return None
        if entry.status.name != "COMPLETED":
            return None
        return entry.result

    @classmethod
    def _process_renegotiation(cls, scan_result) -> dict:
        """
        Secure renegotiation support, and whether a client may drive it.

        The command has been requested since before Phase 6 and its result was
        never read. Two separate conditions live in it: a server that does not
        support RFC 5746 secure renegotiation (the 2009 MITM), and one that
        permits *client-initiated* renegotiation (asymmetric CPU cost, a
        denial-of-service lever). They have different remediations.

        ``{}`` when the command did not complete — an absent reading, never a
        clean bill of health.
        """
        result = cls._completed(scan_result, "session_renegotiation")
        if result is None:
            return {}
        return {
            "supports_secure_renegotiation": bool(
                getattr(result, "supports_secure_renegotiation", False)
            ),
            "client_renegotiation_dos": bool(
                getattr(result, "is_vulnerable_to_client_renegotiation_dos", False)
            ),
            "client_renegotiations_succeeded": int(
                getattr(result, "client_renegotiations_success_count", 0) or 0
            ),
        }

    @classmethod
    def _process_downgrade(cls, scan_result) -> dict:
        """
        Whether the listener honours TLS_FALLBACK_SCSV.

        Also requested since before Phase 6 and never read. A server that
        ignores the signalling suite cannot refuse a downgrade dance, which is
        what makes POODLE-over-TLS reachable on a listener that still offers an
        older version.
        """
        result = cls._completed(scan_result, "tls_fallback_scsv")
        if result is None:
            return {}
        return {
            "supports_fallback_scsv": bool(
                getattr(result, "supports_fallback_scsv", False)
            )
        }

    @classmethod
    def _process_protocol_features(cls, scan_result) -> dict:
        """CCS injection, 0-RTT early data, extended master secret."""
        features: dict = {}

        ccs = cls._completed(scan_result, "openssl_ccs_injection")
        if ccs is not None:
            features["ccs_injection"] = bool(
                getattr(ccs, "is_vulnerable_to_ccs_injection", False)
            )

        early = cls._completed(scan_result, "tls_1_3_early_data")
        if early is not None:
            features["early_data"] = bool(getattr(early, "supports_early_data", False))

        ems = cls._completed(scan_result, "tls_extended_master_secret")
        if ems is not None:
            features["extended_master_secret"] = bool(
                getattr(ems, "supports_ems_extension", False)
            )
        return features

    @classmethod
    def _process_key_exchange(cls, scan_result) -> dict:
        """
        Forward secrecy, and the size of the ephemeral groups actually offered.

        Read from the ``ephemeral_key`` on each accepted suite rather than from
        the suite name: a name says ECDHE, and only the key says whether the
        group behind it is 256 bits or 128. Logjam is a *parameter* weakness,
        so a check that reads the name alone cannot see it at all.
        """
        smallest_dh = None
        smallest_ecdh = None
        forward_secrecy = False
        assessed = False

        for attribute in (
            "tls_1_2_cipher_suites",
            "tls_1_3_cipher_suites",
            "tls_1_1_cipher_suites",
            "tls_1_0_cipher_suites",
        ):
            result = cls._completed(scan_result, attribute)
            if result is None:
                continue
            assessed = True
            for accepted in getattr(result, "accepted_cipher_suites", []) or []:
                name = (
                    getattr(getattr(accepted, "cipher_suite", None), "name", "") or ""
                )
                if "ECDHE" in name or "DHE" in name:
                    forward_secrecy = True
                key = getattr(accepted, "ephemeral_key", None)
                size = getattr(key, "size", None)
                if not size:
                    continue
                kind = type(key).__name__.lower()
                if (
                    "ecdh" in kind
                    or "ecdhe" in kind
                    or "x25519" in kind
                    or "x448" in kind
                ):
                    smallest_ecdh = (
                        size if smallest_ecdh is None else min(smallest_ecdh, size)
                    )
                elif "dh" in kind:
                    smallest_dh = (
                        size if smallest_dh is None else min(smallest_dh, size)
                    )

        if not assessed:
            return {}
        return {
            "forward_secrecy": forward_secrecy,
            "smallest_dh_bits": smallest_dh,
            "smallest_ecdh_bits": smallest_ecdh,
        }

    #: Substrings that mark a cipher suite as offering no useful security.
    #: Matched against the IANA suite name, upper-cased.
    #:
    #: ``DES`` deliberately matches ``3DES`` as well — Sweet32 applies to both,
    #: and the finding names every suite it matched so a reader can see which.
    #: ``_ANON`` rather than ``ANON``: ``DH_anon`` appears as ``TLS_DH_anon_…``
    #: and the underscore keeps the marker from matching an unrelated product
    #: name inside a suite string.
    WEAK_CIPHER_MARKERS = (
        "RC4",
        "DES",
        "NULL",
        "EXPORT",
        "_ANON",
        "MD5",
        "IDEA",
        "SEED",
    )

    @classmethod
    def _process_protocols(cls, scan_result) -> dict:
        """
        Extract supported protocol versions, cipher counts and weak suites.

        ``weak_ciphers`` is new. The wrapper previously counted accepted suites
        and never looked at their names, so a server offering RC4 and one
        offering only AES-GCM were indistinguishable in its output — which is
        why the shallow raw-socket probe was the only thing in the product that
        could report a weak cipher, and it could only report the *one* suite it
        happened to negotiate.
        """
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
                names = []
                for entry in accepted:
                    suite = getattr(entry, "cipher_suite", None)
                    name = getattr(suite, "name", "") or str(entry)
                    if name:
                        names.append(name)
                protocols[proto_name] = {
                    "supported": len(accepted) > 0,
                    "cipher_count": len(accepted),
                    "weak_ciphers": sorted(
                        {
                            name
                            for name in names
                            if any(
                                marker in name.upper()
                                for marker in cls.WEAK_CIPHER_MARKERS
                            )
                        }
                    ),
                }
            else:
                protocols[proto_name] = {
                    "supported": False,
                    "cipher_count": 0,
                    "weak_ciphers": [],
                }
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
