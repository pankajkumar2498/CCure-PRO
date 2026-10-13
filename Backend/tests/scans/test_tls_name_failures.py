"""
tests/scans/test_tls_name_failures.py
─────────────────────────────────────────────────────────────────────────────
A certificate whose names do not cover the address it was reached on is a
hostname mismatch, not an untrusted chain.

On 10.180.6.30 (12 Oct 2026) the certificate named ccurepro.cdacb.in and the
host's old address, 10.180.6.14. Every trust store failed with "leaf
certificate has no matching subjectAltName" — the validator stops at the name,
so the chain was never judged — and the scan reported "Server certificate does
not chain to a trusted root", while sslyze's own hostname flag came back empty
and the real problem went unreported.
"""

from testpaths import BACKEND_ROOT

import sys

sys.path.insert(0, str(BACKEND_ROOT))

from core.models import TLSInfo  # noqa: E402
from engines.vulnerability.plugins import tls_scanner  # noqa: E402

NAME_ERROR = (
    "validation failed: leaf certificate has no matching subjectAltName "
    "(encountered processing <Certificate(subject=<Name(CN=ccurepro.cdacb.in)>, ...)>)"
)
STORES = ("Android", "Apple", "Java", "Mozilla", "Windows")


def _info():
    return TLSInfo(
        enabled=True,
        version="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        cert_subject="ccurepro.cdacb.in",
        cert_issuer="CCure Audit PRO Internal Root CA",
        san_domains=[
            "DNS:ccurepro.cdacb.in",
            "DNS:localhost",
            "IP:10.180.6.14",
            "IP:127.0.0.1",
        ],
    )


def _endpoint(certificate):
    return tls_scanner._findings_for_endpoint(
        "10.180.6.30", 443, _info(), {"certificate": certificate}
    )


def _by_area(findings):
    return {f["check_area"]: f for f in findings}


def test_a_name_failure_in_every_store_is_a_hostname_mismatch():
    found = _by_area(
        _endpoint(
            {
                "hostname_matches": None,  # what sslyze actually returned
                "chain_trusted": False,
                "trust_failures": [{"store": s, "error": NAME_ERROR} for s in STORES],
            }
        )
    )

    assert "tls.certificate_untrusted_chain" not in found
    evidence = found["tls.certificate_hostname_mismatch"]["evidence"]
    assert "IP:10.180.6.14" in evidence
    assert "Reached as        : 10.180.6.30" in evidence
    assert "whether the chain itself is trusted was not established" in evidence


def test_a_genuine_chain_error_is_still_an_untrusted_chain():
    found = _by_area(
        _endpoint(
            {
                "hostname_matches": True,
                "chain_trusted": False,
                "trust_failures": [
                    {
                        "store": "Mozilla",
                        "error": "unable to get local issuer certificate",
                    }
                ],
            }
        )
    )
    assert "tls.certificate_untrusted_chain" in found
    assert "tls.certificate_hostname_mismatch" not in found


def test_mixed_failures_report_both_and_list_only_the_chain_errors_as_chain():
    found = _by_area(
        _endpoint(
            {
                "hostname_matches": None,
                "chain_trusted": False,
                "trust_failures": [
                    {"store": "Mozilla", "error": NAME_ERROR},
                    {
                        "store": "Java",
                        "error": "unable to get local issuer certificate",
                    },
                ],
            }
        )
    )
    chain = found["tls.certificate_untrusted_chain"]["evidence"]
    assert "Java" in chain and "subjectAltName" not in chain
    # Not every store stopped at the name, so the name is not established as
    # the reason; sslyze's flag was empty, so no mismatch is asserted either.
    assert "tls.certificate_hostname_mismatch" not in found


def test_sslyzes_own_mismatch_flag_is_still_honoured():
    found = _by_area(_endpoint({"hostname_matches": False, "chain_trusted": True}))
    evidence = found["tls.certificate_hostname_mismatch"]["evidence"]
    assert "not established" not in evidence


def test_a_trusted_certificate_reports_neither():
    found = _by_area(_endpoint({"hostname_matches": True, "chain_trusted": True}))
    assert "tls.certificate_untrusted_chain" not in found
    assert "tls.certificate_hostname_mismatch" not in found
