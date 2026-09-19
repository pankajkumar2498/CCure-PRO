"""
Phase 8 — CWE and finding intelligence.

CWE for a web finding is decided in one place (core/web/standards_mapping.py):
a well-formed CWE an engine or source tool supplied wins, the centralized
finding_type default fills the rest, a fabricated identifier is dropped, and a
finding_type with no defensible CWE stays None. These tests pin that behaviour
end to end — pure resolution, the nuclei source-CWE preservation, the
consistency of the newer engines' own constants with the central table, an
audit that every emitted finding_type is a deliberate decision, and the
round-trip through _persist_web_findings into the database.
"""

import pytest

from core.web.standards_mapping import (
    CWE_MAP,
    CWE_UNMAPPED,
    cwe_for,
    map_compliance,
    normalize_cwe,
    resolve_cwe,
)


# ── normalization / fabrication guard ────────────────────────────────────────
def test_normalize_accepts_canonical_and_variants():
    assert normalize_cwe("CWE-79") == "CWE-79"
    assert normalize_cwe("cwe-79") == "CWE-79"
    assert normalize_cwe("CWE-0079") == "CWE-79"  # canonicalised
    assert normalize_cwe("79") == "CWE-79"  # bare number
    assert normalize_cwe(89) == "CWE-89"
    # nuclei publishes cwe-id as a list; first well-formed entry wins.
    assert normalize_cwe(["CWE-79", "CWE-80"]) == "CWE-79"
    assert normalize_cwe(["junk", "CWE-89"]) == "CWE-89"


def test_normalize_rejects_fabricated_or_malformed():
    for bad in (
        None,
        "",
        "   ",
        "XSS",
        "CWE-",
        "CWE-abc",
        "CWE_79",
        "junk",
        "CWE-79-extra",
        [],
        ["nope", "also-nope"],
    ):
        assert normalize_cwe(bad) is None, bad


# ── central lookup ───────────────────────────────────────────────────────────
def test_cwe_for_known_and_unknown():
    assert cwe_for("sqli") == "CWE-89"
    assert cwe_for("SQLI") == "CWE-89"  # case-insensitive
    assert cwe_for("xss") == "CWE-79"
    assert cwe_for("cors") == "CWE-942"
    assert cwe_for("open_redirect") == "CWE-601"
    assert cwe_for("tls_issue") == "CWE-326"
    assert cwe_for("information_disclosure") == "CWE-200"
    assert cwe_for("vulnerable_js_library") == "CWE-1395"
    # deliberately unmapped → None, never a guess
    assert cwe_for("misconfig") is None
    assert cwe_for("cve") is None
    assert cwe_for("technology_detected") is None
    assert cwe_for("something_new") is None


def test_map_compliance_surfaces_cwe():
    assert map_compliance("sqli")["cwe"] == "CWE-89"
    assert map_compliance("misconfig")["cwe"] is None


# ── resolution order ─────────────────────────────────────────────────────────
def test_resolve_prefers_engine_supplied_cwe():
    # A more specific CWE the engine set wins over the per-type default:
    # insecure_http_method defaults to CWE-693 (TRACE) but is CWE-650 for a
    # dangerous verb, and that specific value must survive.
    f = {"finding_type": "insecure_http_method", "cwe_id": "CWE-650"}
    assert resolve_cwe(f) == "CWE-650"


def test_resolve_falls_back_to_central_default():
    assert resolve_cwe({"finding_type": "sqli"}) == "CWE-89"
    assert resolve_cwe({"finding_type": "cors", "cwe_id": None}) == "CWE-942"


def test_resolve_drops_fabricated_then_falls_back():
    # A fabricated supplied CWE is dropped, and the central default fills in.
    f = {"finding_type": "sqli", "cwe_id": "not-a-cwe"}
    assert resolve_cwe(f) == "CWE-89"


def test_resolve_none_when_unmapped_and_unsupplied():
    assert resolve_cwe({"finding_type": "misconfig"}) is None
    assert resolve_cwe({"finding_type": "cve"}) is None


def test_resolve_keeps_source_cwe_for_unmapped_type():
    # A raw CVE finding whose source classified it keeps that CWE even though
    # "cve" has no central default.
    f = {"finding_type": "cve", "cwe_id": "CWE-79"}
    assert resolve_cwe(f) == "CWE-79"


# ── the map itself cannot contain a fabricated identifier ─────────────────────
def test_every_map_entry_is_wellformed():
    for ftype, cwe in CWE_MAP.items():
        assert normalize_cwe(cwe) == cwe, f"{ftype} -> {cwe} is not canonical"


def test_map_and_unmapped_do_not_overlap():
    assert not (set(CWE_MAP) & set(CWE_UNMAPPED))


# ── completeness audit: every emitted finding_type is a deliberate decision ───
# The authoritative set of finding_type values the web pipeline can produce,
# gathered from every emitter (nuclei/sqlmap/sslyze/ffuf wrappers, the
# orchestrator header/CORS/redirect checks, and the Phase 1–7 engines). A type
# here that is neither mapped nor explicitly recorded as unmapped is a silent
# CWE gap — the failure this test exists to prevent.
_EMITTED_FINDING_TYPES = {
    # nuclei classifier
    "misconfig",
    "cve",
    "xss",
    "sqli",
    "ssrf",
    "rce",
    "lfi",
    "rfi",
    "xxe",
    "idor",
    "default_creds",
    "exposed_panel",
    "technology_detected",
    # ffuf / sslyze / orchestrator
    "information_disclosure",
    "tls_issue",
    "cors",
    "open_redirect",
    # active engines (Phase 1–7)
    "command_injection",
    "ssti",
    "ldap_injection",
    "xpath_injection",
    "broken_access_control",
    "privilege_escalation",
    "insecure_http_method",
    "http_method_auth_bypass",
    "api_missing_auth",
    "graphql_introspection",
    "excessive_data_exposure",
    "vulnerable_js_library",
}


def test_every_emitted_finding_type_is_mapped_or_recorded_unmapped():
    known = set(CWE_MAP) | set(CWE_UNMAPPED)
    missing = _EMITTED_FINDING_TYPES - known
    assert not missing, f"finding_types with no CWE decision: {sorted(missing)}"


# ── the newer engines' own constants agree with the central table ────────────
def test_xss_engine_constant_matches_central_map():
    from core.web.xss import payloads as xss_payloads

    assert xss_payloads.CWE_ID == CWE_MAP["xss"]


def test_injection_engine_constants_match_central_map():
    from core.web.injection import payloads as inj

    for ftype, cwe in inj.CWE.items():
        assert cwe == CWE_MAP[ftype], f"{ftype}: {cwe} != {CWE_MAP[ftype]}"


# ── nuclei preserves its template classification CWE ─────────────────────────
def test_nuclei_preserves_classification_cwe():
    from core.web.nuclei.wrapper import NucleiWrapper

    raw = {
        "template-id": "some-xss",
        "matched-at": "http://t/",
        "info": {
            "name": "Reflected XSS",
            "severity": "high",
            "tags": ["xss"],
            "classification": {"cwe-id": ["CWE-79"]},
        },
    }
    f = NucleiWrapper._normalize_finding(raw)
    assert f is not None
    assert f["cwe_id"] == "CWE-79"


def test_nuclei_drops_fabricated_classification_cwe():
    from core.web.nuclei.wrapper import NucleiWrapper

    raw = {
        "template-id": "weird",
        "matched-at": "http://t/",
        "info": {
            "name": "Weird",
            "severity": "info",
            "tags": [],
            "classification": {"cwe-id": ["NOT-A-CWE"]},
        },
    }
    f = NucleiWrapper._normalize_finding(raw)
    assert f is not None
    assert f["cwe_id"] is None  # fabricated dropped; misconfig has no default


# ── database round-trip through _persist_web_findings ────────────────────────
from db.base import SessionLocal, utcnow  # noqa: E402
from db.models.web_scans import WebFinding, WebScan  # noqa: E402

_PREFIX = "wsc_cwemap_"


@pytest.fixture
def session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.query(WebFinding).filter(WebFinding.web_scan_id.like(f"{_PREFIX}%")).delete(
            synchronize_session=False
        )
        db.query(WebScan).filter(WebScan.id.like(f"{_PREFIX}%")).delete(
            synchronize_session=False
        )
        db.commit()
        db.close()


def _scan(session, suffix):
    from db.models.rbac import Organization

    org = session.query(Organization).first()
    assert org is not None
    scan = WebScan(
        id=f"{_PREFIX}{suffix}",
        org_id=org.id,
        target_url="http://target.invalid/",
        target_domain="target.invalid",
        authorization_confirmed=True,
        scan_name="cwe map test",
        status="complete",
        created_at=utcnow(),
    )
    session.add(scan)
    session.commit()
    return scan, org.id


def test_persist_fills_central_cwe_for_legacy_finding(session):
    from core.web.tasks import _persist_web_findings

    scan, org_id = _scan(session, "sqli")
    # A sqlmap-style finding that carried no CWE (the legacy path never set one).
    findings = [
        {
            "finding_type": "sqli",
            "title": "SQL Injection in 'id'",
            "severity": "critical",
            "detected_by": "sqlmap",
            "matched_at": "http://target.invalid/?id=1",
        }
    ]
    _persist_web_findings(session, scan.id, org_id, findings)
    session.commit()
    row = session.query(WebFinding).filter(WebFinding.web_scan_id == scan.id).first()
    assert row.cwe_id == "CWE-89"


def test_persist_drops_fabricated_cwe(session):
    from core.web.tasks import _persist_web_findings

    scan, org_id = _scan(session, "fab")
    findings = [
        {
            "finding_type": "xss",
            "title": "XSS",
            "severity": "high",
            "detected_by": "x",
            "matched_at": "http://target.invalid/?q=1",
            "cwe_id": "totally-made-up",
        }
    ]
    _persist_web_findings(session, scan.id, org_id, findings)
    session.commit()
    row = session.query(WebFinding).filter(WebFinding.web_scan_id == scan.id).first()
    assert row.cwe_id == "CWE-79"  # fabricated dropped, central default filled


def test_persist_leaves_unmapped_type_without_cwe(session):
    from core.web.tasks import _persist_web_findings

    scan, org_id = _scan(session, "misc")
    findings = [
        {
            "finding_type": "misconfig",
            "title": "Some nuclei misconfig",
            "severity": "low",
            "detected_by": "nuclei",
            "matched_at": "http://target.invalid/x",
        }
    ]
    _persist_web_findings(session, scan.id, org_id, findings)
    session.commit()
    row = session.query(WebFinding).filter(WebFinding.web_scan_id == scan.id).first()
    assert row.cwe_id is None  # honest absence, never a guess
