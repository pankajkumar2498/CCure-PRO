"""
tests/scans/test_tls_deep.py
─────────────────────────────────────────────────────────────────────────────
The fourteen deep-TLS conditions GAP-07 added, and the tri-state discipline
that keeps them from inventing verdicts. Phase 11.

Why these are mostly about ``None``
───────────────────────────────────
Every finding here reads a field sslyze returns, and each of those fields has
three states: True, False, and **absent because the scan command did not
complete**. A command can fail to complete for entirely ordinary reasons — the
handshake timed out, the service does not speak the protocol, the port closed
mid-scan.

Reading that absence as False reports a clean server as broken. Reading it as
True hides a real condition. Neither is a reading, so every guard in
``tls_scanner`` is ``is True`` / ``is False`` rather than truthiness, and the
bulk of this file exists to pin that — a truthiness test would pass most of
these by accident today and stop passing the moment a default changed.

The findings are built from dictionaries rather than by scanning a listener,
so the truth table is exercised exhaustively and without a network. The real
listeners are what proved the *readings*; these prove the *decisions*.
"""

import pytest

from engines.vulnerability.network_checks import NETWORK_CHECKS
from engines.vulnerability.plugins import tls_scanner
from scripts.measure_tls_coverage import NOT_PLANNED, OWNED_BY_GAP06, SCOPE

SCOPE_AREAS = {area for area, _t, _d in SCOPE}

#: The areas this phase adds to the catalogue, as opposed to the transports.
GAP07_FINDING_AREAS = {
    area for area, theme, _d in SCOPE if theme != "starttls" and area not in NOT_PLANNED
}

IDENTITY = "Subject           : test\nIssuer            : test"
COMMON = {"target": "192.0.2.10:443", "port": 443}


def areas(findings):
    return sorted(f.get("check_area") for f in findings)


# ── Catalogue ────────────────────────────────────────────────────────────────


def test_every_planned_finding_area_has_a_catalogue_entry():
    declared = {c.area for c in NETWORK_CHECKS}
    missing = GAP07_FINDING_AREAS - declared
    assert not missing, f"no NetworkCheck declares {sorted(missing)}"


def test_the_three_areas_gap06_froze_are_now_declared():
    """
    ``tls.certificate_expiring_soon``, ``tls.weak_dh_parameters`` and
    ``tls.insecure_renegotiation`` sat in GAP-06's frozen scope unimplemented.
    This phase implements them; the coverage credit is GAP-06's, whose harness
    reads the same catalogue.
    """
    declared = {c.area for c in NETWORK_CHECKS}
    for area in (
        "tls.certificate_expiring_soon",
        "tls.weak_dh_parameters",
        "tls.insecure_renegotiation",
    ):
        assert area in declared, area
        assert area in OWNED_BY_GAP06
        assert area not in SCOPE_AREAS, (
            f"{area} belongs to GAP-06's denominator; naming it in GAP-07's "
            f"would count one area towards two percentages"
        )


@pytest.mark.parametrize(
    "check",
    [c for c in NETWORK_CHECKS if c.domain == "tls"],
    ids=lambda c: c.area,
)
def test_every_tls_check_is_actionable(check):
    assert check.description.strip()
    assert check.remediation.strip()
    assert check.severity in ("critical", "high", "medium", "low", "info")


def test_only_published_cves_carry_a_cve_id():
    """
    A network condition must never become a fabricated CVE. Two TLS checks
    carry one and both are real published identifiers.
    """
    with_cve = {
        c.area: c.cve_id for c in NETWORK_CHECKS if c.domain == "tls" and c.cve_id
    }
    assert with_cve == {
        "tls.heartbleed": "CVE-2014-0160",
        "tls.ccs_injection": "CVE-2014-0224",
    }


def test_no_tls_check_is_marked_intrusive():
    """
    Nothing GAP-07 added writes to a target. Every command it reads was already
    being sent; only the reading is new. If a TLS check ever needs the
    intrusive gate, that is a deliberate decision and this test is where it is
    made.
    """
    assert not [c for c in NETWORK_CHECKS if c.domain == "tls" and c.intrusive]


# ── Chain and certificate ────────────────────────────────────────────────────


def test_an_untrusted_chain_reports_why_not_merely_that():
    """
    ``chain_trusted`` was already being computed and nothing read it. A bare
    "untrusted" is not actionable; the store and the validation error are what
    tell an operator whether an intermediate is missing or the CA is private.
    """
    found = tls_scanner._chain_findings(
        IDENTITY,
        {
            "chain_trusted": False,
            "trust_failures": [
                {"store": "Mozilla", "error": "unable to get local issuer certificate"}
            ],
        },
        COMMON,
    )
    assert "tls.certificate_untrusted_chain" in areas(found)
    evidence = next(
        f for f in found if f["check_area"] == "tls.certificate_untrusted_chain"
    )["evidence"]
    assert "Mozilla" in evidence and "local issuer" in evidence


def test_a_trusted_chain_reports_nothing_and_neither_does_an_unknown_one():
    assert "tls.certificate_untrusted_chain" not in areas(
        tls_scanner._chain_findings(IDENTITY, {"chain_trusted": True}, COMMON)
    )
    assert "tls.certificate_untrusted_chain" not in areas(
        tls_scanner._chain_findings(IDENTITY, {"chain_trusted": None}, COMMON)
    )
    assert tls_scanner._chain_findings(IDENTITY, {}, COMMON) == []


@pytest.mark.parametrize(
    "value,expected",
    [(False, True), (True, False), (None, False)],
)
def test_chain_order_fires_only_on_a_positive_reading(value, expected):
    found = areas(
        tls_scanner._chain_findings(IDENTITY, {"chain_in_valid_order": value}, COMMON)
    )
    assert ("tls.certificate_chain_order" in found) is expected


@pytest.mark.parametrize(
    "value,expected",
    [(True, True), (False, False), (None, False)],
)
def test_sha1_in_the_verified_chain_fires_only_on_a_positive_reading(value, expected):
    found = areas(
        tls_scanner._chain_findings(IDENTITY, {"chain_has_sha1": value}, COMMON)
    )
    assert ("tls.certificate_sha1_chain" in found) is expected


def test_a_certificate_that_is_not_yet_valid_is_reported():
    from datetime import datetime, timedelta, timezone

    future = (datetime.now(timezone.utc) + timedelta(days=5)).isoformat()
    past = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
    assert "tls.certificate_not_yet_valid" in areas(
        tls_scanner._chain_findings(IDENTITY, {"not_before": future}, COMMON)
    )
    assert "tls.certificate_not_yet_valid" not in areas(
        tls_scanner._chain_findings(IDENTITY, {"not_before": past}, COMMON)
    )


def test_an_unparseable_not_before_is_not_a_finding():
    """A timestamp this cannot read establishes nothing about validity."""
    for value in ("", None, "not a date", 12345):
        assert "tls.certificate_not_yet_valid" not in areas(
            tls_scanner._chain_findings(IDENTITY, {"not_before": value}, COMMON)
        )


@pytest.mark.parametrize(
    "key,expected",
    [
        ({"algorithm": "rsa", "bits": 1024}, True),
        ({"algorithm": "rsa", "bits": 2048}, False),
        ({"algorithm": "rsa", "bits": 4096}, False),
        ({"algorithm": "dsa", "bits": 1024}, True),
        ({"algorithm": "ec", "bits": 192}, True),
        ({"algorithm": "ec", "bits": 256}, False),
        ({"algorithm": "ec", "bits": 384}, False),
        # Edwards keys have no size and need none.
        ({"algorithm": "eddsa", "bits": None}, False),
        # An algorithm the classifier did not recognise: withheld, never
        # compared against the wrong floor.
        ({}, False),
        ({"algorithm": "rsa", "bits": None}, False),
    ],
)
def test_the_key_strength_floor(key, expected):
    found = areas(tls_scanner._chain_findings(IDENTITY, {"public_key": key}, COMMON))
    assert ("tls.certificate_weak_key" in found) is expected


def test_must_staple_outranks_plain_missing_stapling():
    """
    Both conditions are "nothing was stapled". Only one is an outage for
    correct clients, and reporting both would put two findings in front of a
    reader for one fix.
    """
    strict = areas(
        tls_scanner._chain_findings(
            IDENTITY, {"has_must_staple": True, "ocsp_stapled": False}, COMMON
        )
    )
    assert "tls.must_staple_unhonoured" in strict
    assert "tls.ocsp_stapling_absent" not in strict

    ordinary = areas(
        tls_scanner._chain_findings(
            IDENTITY, {"has_must_staple": False, "ocsp_stapled": False}, COMMON
        )
    )
    assert ordinary == ["tls.ocsp_stapling_absent"]

    stapled = areas(
        tls_scanner._chain_findings(
            IDENTITY, {"has_must_staple": True, "ocsp_stapled": True}, COMMON
        )
    )
    assert stapled == []


# ── Downgrade and renegotiation ──────────────────────────────────────────────


@pytest.mark.parametrize(
    "downgrade,expected",
    [
        ({"supports_fallback_scsv": False}, True),
        ({"supports_fallback_scsv": True}, False),
        ({}, False),
    ],
)
def test_fallback_scsv(downgrade, expected):
    """
    The command has been requested since before Phase 6 and its result was
    thrown away. ``{}`` means it did not complete — not that the server is fine.
    """
    found = areas(
        tls_scanner._downgrade_findings(IDENTITY, {"downgrade": downgrade}, COMMON)
    )
    assert ("tls.fallback_scsv_unsupported" in found) is expected


@pytest.mark.parametrize(
    "renegotiation,expected",
    [
        ({"supports_secure_renegotiation": False}, ["tls.insecure_renegotiation"]),
        ({"supports_secure_renegotiation": True}, []),
        ({}, []),
        (
            {"supports_secure_renegotiation": True, "client_renegotiation_dos": True},
            ["tls.client_renegotiation_dos"],
        ),
        (
            {"supports_secure_renegotiation": False, "client_renegotiation_dos": True},
            ["tls.client_renegotiation_dos", "tls.insecure_renegotiation"],
        ),
    ],
)
def test_renegotiation_reports_two_distinct_conditions(renegotiation, expected):
    """
    RFC 5746 support and client-initiated renegotiation live in one sslyze
    result and have different remediations. A server can have either, both or
    neither — measured on real listeners, Dovecot had the second and not the
    first.
    """
    found = areas(
        tls_scanner._downgrade_findings(
            IDENTITY, {"renegotiation": renegotiation}, COMMON
        )
    )
    assert found == sorted(expected)


def test_the_renegotiation_count_reaches_the_evidence():
    found = tls_scanner._downgrade_findings(
        IDENTITY,
        {
            "renegotiation": {
                "supports_secure_renegotiation": True,
                "client_renegotiation_dos": True,
                "client_renegotiations_succeeded": 10,
            }
        },
        COMMON,
    )
    assert "10" in found[0]["evidence"]


# ── Key exchange ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "kex,expected",
    [
        ({"smallest_dh_bits": 1024}, ["tls.weak_dh_parameters"]),
        ({"smallest_dh_bits": 512}, ["tls.weak_dh_parameters"]),
        ({"smallest_dh_bits": 2048}, []),
        ({"smallest_ecdh_bits": 163}, ["tls.weak_ecdh_curve"]),
        ({"smallest_ecdh_bits": 256}, []),
        ({"smallest_ecdh_bits": 253}, []),  # X25519
        ({"forward_secrecy": False}, ["tls.no_forward_secrecy"]),
        ({"forward_secrecy": True}, []),
        # None means the group size was never established.
        ({"smallest_dh_bits": None, "smallest_ecdh_bits": None}, []),
    ],
)
def test_key_exchange_floors(kex, expected):
    """
    Read from the ephemeral key, not the suite name. A suite called ECDHE says
    nothing about whether the group behind it is 256 bits or 128, which is
    exactly what Logjam turns on.
    """
    found = areas(
        tls_scanner._key_exchange_findings(IDENTITY, {"key_exchange": kex}, COMMON)
    )
    assert found == sorted(expected)


def test_an_unassessed_key_exchange_reports_nothing():
    assert tls_scanner._key_exchange_findings(IDENTITY, {}, COMMON) == []
    assert (
        tls_scanner._key_exchange_findings(IDENTITY, {"key_exchange": {}}, COMMON) == []
    )


# ── Protocol behaviour ───────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "features,expected",
    [
        ({"ccs_injection": True}, ["tls.ccs_injection"]),
        ({"ccs_injection": False}, []),
        ({"early_data": True}, ["tls.early_data_enabled"]),
        ({"early_data": False}, []),
        ({"extended_master_secret": False}, ["tls.extended_master_secret_absent"]),
        ({"extended_master_secret": True}, []),
        ({}, []),
    ],
)
def test_protocol_features(features, expected):
    found = areas(
        tls_scanner._protocol_feature_findings(
            IDENTITY, {"protocol_features": features}, COMMON
        )
    )
    assert found == sorted(expected)


# ── The wrapper's own readings ───────────────────────────────────────────────


def test_a_scan_command_that_did_not_complete_yields_no_reading():
    """
    ``_completed`` is the single gate every new reading passes through. A
    command in any state but COMPLETED must produce ``{}``, because the
    alternative is a finding derived from a result sslyze never obtained.
    """
    from core.web.sslyze.wrapper import SSLyzeWrapper

    class Attempt:
        def __init__(self, status_name, result=None):
            self.status = type("S", (), {"name": status_name})()
            self.result = result

    class ScanResult:
        session_renegotiation = Attempt("ERROR")
        tls_fallback_scsv = Attempt("NOT_SCHEDULED")
        openssl_ccs_injection = Attempt("ERROR")
        tls_1_3_early_data = Attempt("ERROR")
        tls_extended_master_secret = Attempt("ERROR")

    assert SSLyzeWrapper._process_renegotiation(ScanResult()) == {}
    assert SSLyzeWrapper._process_downgrade(ScanResult()) == {}
    assert SSLyzeWrapper._process_protocol_features(ScanResult()) == {}
    assert SSLyzeWrapper._process_key_exchange(ScanResult()) == {}


def test_public_key_classification_uses_types_not_class_names():
    """
    The concrete class is ``ECPublicKey`` in this build of ``cryptography`` and
    ``_EllipticCurvePublicKey`` in others. A substring test on the name missed
    the first, so every EC certificate went unclassified and could never be
    reported as weak — found against a real LDAP listener.
    """
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

    from core.web.sslyze.wrapper import _describe_public_key

    class Leaf:
        def __init__(self, key):
            self._key = key

        def public_key(self):
            return self._key

    rsa_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    ).public_key()
    assert _describe_public_key(Leaf(rsa_key)) == {"algorithm": "rsa", "bits": 2048}

    ec_key = ec.generate_private_key(ec.SECP384R1()).public_key()
    assert _describe_public_key(Leaf(ec_key)) == {"algorithm": "ec", "bits": 384}

    ed_key = ed25519.Ed25519PrivateKey.generate().public_key()
    assert _describe_public_key(Leaf(ed_key)) == {"algorithm": "eddsa", "bits": None}


def test_a_leaf_whose_key_cannot_be_read_is_withheld_not_guessed():
    from core.web.sslyze.wrapper import _describe_public_key

    class Broken:
        def public_key(self):
            raise ValueError("malformed")

    class Unknown:
        def public_key(self):
            return object()

    assert _describe_public_key(Broken()) == {}
    assert _describe_public_key(Unknown()) == {}


# ── The denominator ──────────────────────────────────────────────────────────


def test_the_frozen_denominator_and_gap06s_do_not_overlap():
    """
    The boundary this phase turns on. An area counted in both denominators
    inflates two percentages from one piece of work — the mistake Phase 8 and
    Phase 9 each had to correct.
    """
    assert not (SCOPE_AREAS & set(OWNED_BY_GAP06))


def test_every_not_planned_area_is_in_the_denominator_and_says_why():
    assert set(NOT_PLANNED) <= SCOPE_AREAS
    for area, reason in NOT_PLANNED.items():
        assert len(reason) > 40, f"{area} does not say why"


def test_the_denominator_has_no_duplicates():
    listed = [area for area, _t, _d in SCOPE]
    assert len(listed) == len(set(listed))


# ── The behavioural contract Phase 6 established ─────────────────────────────
#
# ``test_network_check_pipeline`` requires every declared catalogue area to be
# named, by its *minted identifier*, in a test that drives the plugin. Naming
# the area alone would be a tautology — the same person writes both lists. The
# identifier can only be produced by actually building the finding.


@pytest.mark.parametrize(
    "identifier,deep",
    [
        (
            "CCURE-CHK-TLS-CERTIFICATE-UNTRUSTED-CHAIN",
            {
                "certificate": {
                    "chain_trusted": False,
                    "trust_failures": [{"store": "M", "error": "e"}],
                }
            },
        ),
        (
            "CCURE-CHK-TLS-CERTIFICATE-CHAIN-ORDER",
            {"certificate": {"chain_in_valid_order": False}},
        ),
        (
            "CCURE-CHK-TLS-CERTIFICATE-SHA1-CHAIN",
            {"certificate": {"chain_has_sha1": True}},
        ),
        (
            "CCURE-CHK-TLS-CERTIFICATE-NOT-YET-VALID",
            {"certificate": {"not_before": "2999-01-01T00:00:00+00:00"}},
        ),
        (
            "CCURE-CHK-TLS-CERTIFICATE-WEAK-KEY",
            {"certificate": {"public_key": {"algorithm": "rsa", "bits": 1024}}},
        ),
        (
            "CCURE-CHK-TLS-OCSP-STAPLING-ABSENT",
            {"certificate": {"ocsp_stapled": False}},
        ),
        (
            "CCURE-CHK-TLS-MUST-STAPLE-UNHONOURED",
            {"certificate": {"has_must_staple": True, "ocsp_stapled": False}},
        ),
        (
            "CCURE-CHK-TLS-FALLBACK-SCSV-UNSUPPORTED",
            {"downgrade": {"supports_fallback_scsv": False}},
        ),
        (
            "CCURE-CHK-TLS-INSECURE-RENEGOTIATION",
            {"renegotiation": {"supports_secure_renegotiation": False}},
        ),
        (
            "CCURE-CHK-TLS-CLIENT-RENEGOTIATION-DOS",
            {"renegotiation": {"client_renegotiation_dos": True}},
        ),
        (
            "CCURE-CHK-TLS-WEAK-DH-PARAMETERS",
            {"key_exchange": {"smallest_dh_bits": 1024}},
        ),
        (
            "CCURE-CHK-TLS-WEAK-ECDH-CURVE",
            {"key_exchange": {"smallest_ecdh_bits": 163}},
        ),
        (
            "CCURE-CHK-TLS-NO-FORWARD-SECRECY",
            {"key_exchange": {"forward_secrecy": False}},
        ),
        (
            # A published CVE keeps its own identifier — the same rule
            # Heartbleed follows. A minted CCURE- key here would claim NVD had
            # never heard of a vulnerability it has an entry for.
            "CVE-2014-0224",
            {"protocol_features": {"ccs_injection": True}},
        ),
        (
            "CCURE-CHK-TLS-EARLY-DATA-ENABLED",
            {"protocol_features": {"early_data": True}},
        ),
        (
            "CCURE-CHK-TLS-EXTENDED-MASTER-SECRET-ABSENT",
            {"protocol_features": {"extended_master_secret": False}},
        ),
    ],
)
def test_each_new_area_produces_its_catalogue_identifier(identifier, deep):
    """
    Drive the plugin's finding builders with the reading that should trigger
    the condition, and assert the minted identifier reaches the finding.
    """
    from core.models import TLSInfo

    info = TLSInfo(enabled=True)
    info.version = "TLSv1.2"
    payload = {"protocols": {"tls_1_2": {"supported": True}}}
    payload.update(deep)
    findings = tls_scanner._findings_for_endpoint("192.0.2.10", 443, info, payload)
    assert identifier in {f.get("cve_id") for f in findings}


def test_certificate_expiring_soon_produces_its_identifier():
    """
    The sixteenth. It is driven from the handshake's own expiry rather than
    from sslyze's structured output, so it needs its own case.
    """
    from datetime import datetime, timedelta, timezone

    from core.models import TLSInfo

    info = TLSInfo(enabled=True)
    info.version = "TLSv1.2"
    soon = datetime.now(timezone.utc) + timedelta(days=5)
    info.cert_expiry = soon.strftime("%b %d %H:%M:%S %Y GMT")
    findings = tls_scanner._findings_for_endpoint("192.0.2.10", 443, info, {})
    assert "CCURE-CHK-TLS-CERTIFICATE-EXPIRING-SOON" in {
        f.get("cve_id") for f in findings
    }
