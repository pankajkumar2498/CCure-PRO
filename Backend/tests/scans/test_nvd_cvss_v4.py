"""
test_nvd_cvss_v4.py
─────────────────────────────────────────────────────────────────────────────
CVSS revision handling in the NVD parser.

`_extract_best_cvss` knew v3.1, v3.0 and v2.0. A CVE published with only CVSS
4.0 metrics therefore produced no vector, and `_parse_cve_item` discarded the
whole record — measured on the live feed as 4,220 CVEs carrying v4 alone, of
which 124 had reached the catalogue by other routes. Unlike a CVE NVD has not
analysed yet, it never recovered: re-fetching yields the same v4-only metrics
and drops it again.

The rule these tests pin: v4 support is *additive*. The v3.1 → v3.0 → v2.0
selection that decides which score every existing row reports is untouched, and
v4 only becomes the primary score when there is nothing else.
"""

from __future__ import annotations

import pytest

from scans.cve_engine.nvd_client import NvdClient


def _metric(key: str, data: dict) -> dict:
    return {key: [{"cvssData": data}]}


_V31 = {
    "version": "3.1",
    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "baseScore": 9.8,
    "attackVector": "NETWORK",
    "attackComplexity": "LOW",
    "privilegesRequired": "NONE",
    "userInteraction": "NONE",
    "scope": "UNCHANGED",
    "confidentialityImpact": "HIGH",
    "integrityImpact": "HIGH",
    "availabilityImpact": "HIGH",
}

_V30 = dict(_V31, version="3.0", baseScore=8.1)

_V2 = {
    "version": "2.0",
    "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
    "baseScore": 7.5,
}

_V40 = {
    "version": "4.0",
    "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "baseScore": 9.3,
    "attackVector": "NETWORK",
    "attackComplexity": "LOW",
    "attackRequirements": "NONE",
    "privilegesRequired": "NONE",
    "userInteraction": "NONE",
    "vulnConfidentialityImpact": "HIGH",
    "vulnIntegrityImpact": "HIGH",
    "vulnAvailabilityImpact": "HIGH",
    "subConfidentialityImpact": "NONE",
    "subIntegrityImpact": "NONE",
    "subAvailabilityImpact": "NONE",
}


def _cve_json(metrics: dict, cve_id: str = "CVE-2026-9001") -> dict:
    return {
        "id": cve_id,
        "published": "2026-01-01T00:00:00.000",
        "lastModified": "2026-02-01T00:00:00.000",
        "descriptions": [{"lang": "en", "value": "A description."}],
        "metrics": metrics,
        "configurations": [],
        "references": [],
        "weaknesses": [],
    }


# ── Existing selection is unchanged ──────────────────────────────────────────


@pytest.mark.parametrize(
    "metrics,version,score",
    [
        (_metric("cvssMetricV31", _V31), "3.1", 9.8),
        (_metric("cvssMetricV30", _V30), "3.0", 8.1),
        (_metric("cvssMetricV2", _V2), "2.0", 7.5),
    ],
)
def test_v2_and_v3_selection_is_unchanged(metrics, version, score):
    vector = NvdClient._extract_best_cvss(metrics)

    assert vector is not None
    assert vector.version == version
    assert vector.base_score == score


def test_v31_still_outranks_v30_and_v2():
    metrics = {}
    metrics.update(_metric("cvssMetricV2", _V2))
    metrics.update(_metric("cvssMetricV30", _V30))
    metrics.update(_metric("cvssMetricV31", _V31))

    assert NvdClient._extract_best_cvss(metrics).version == "3.1"


def test_v4_does_not_displace_an_existing_v3_primary_score():
    """
    Re-ordering the selection would silently rewrite the score on every row that
    has both, across the whole catalogue. v4 is stored beside it instead.
    """
    metrics = {}
    metrics.update(_metric("cvssMetricV31", _V31))
    metrics.update(_metric("cvssMetricV40", _V40))

    record = NvdClient()._parse_cve_item(_cve_json(metrics))

    assert record is not None
    assert record.cvss.version == "3.1"
    assert record.cvss.base_score == 9.8
    assert record.cvss_v4 is not None
    assert record.cvss_v4.base_score == 9.3


# ── v4 parsing ───────────────────────────────────────────────────────────────


def test_v4_metrics_are_parsed():
    vector = NvdClient._extract_cvss_v40(_metric("cvssMetricV40", _V40))

    assert vector is not None
    assert vector.version == "4.0"
    assert vector.base_score == 9.3
    assert vector.attack_vector == "N"
    assert vector.confidentiality == "H"
    assert vector.integrity == "H"
    assert vector.availability == "H"


def test_v4_scope_is_derived_from_subsequent_system_impact():
    """CVSS 4.0 has no Scope; SC/SI/SA replaced it and the mapping is explicit."""
    unchanged = NvdClient._extract_cvss_v40(_metric("cvssMetricV40", _V40))
    assert unchanged.scope == "U"

    reaching_further = dict(_V40, subIntegrityImpact="HIGH")
    changed = NvdClient._extract_cvss_v40(_metric("cvssMetricV40", reaching_further))
    assert changed.scope == "C"


def test_v4_tolerates_an_empty_enum_value():
    """`d.get("attackVector", "N")[0]` raises IndexError on a present-but-empty key."""
    vector = NvdClient._extract_cvss_v40(
        _metric("cvssMetricV40", dict(_V40, attackVector=""))
    )

    assert vector is not None
    assert vector.attack_vector == "N"


def test_no_v4_metrics_yields_none():
    assert NvdClient._extract_cvss_v40({}) is None
    assert NvdClient._extract_cvss_v40({"cvssMetricV40": []}) is None


# ── The record is retained ───────────────────────────────────────────────────


def test_v4_only_cve_is_retained():
    """The whole point: this record used to be dropped, permanently."""
    record = NvdClient()._parse_cve_item(_cve_json(_metric("cvssMetricV40", _V40)))

    assert record is not None, "A v4-only CVE must not be discarded"
    assert record.cvss.version == "4.0"
    assert record.cvss.base_score == 9.3
    assert record.cvss_v4 is not None


def test_genuinely_unscored_cve_is_still_skipped():
    """
    A CVE NVD has not analysed yet carries no metrics at all. Skipping it is
    correct and self-healing — scoring it bumps lastModified, so the next
    incremental window fetches it.
    """
    assert NvdClient()._parse_cve_item(_cve_json({})) is None


# ── What reaches the catalogue row ───────────────────────────────────────────


def test_row_records_the_version_and_the_v4_score():
    from scans.nvd_sync import _row_for_cve

    metrics = {}
    metrics.update(_metric("cvssMetricV31", _V31))
    metrics.update(_metric("cvssMetricV40", _V40))
    record = NvdClient()._parse_cve_item(_cve_json(metrics))

    row = _row_for_cve(record)

    assert row["cvss_v3_score"] == 9.8
    assert row["cvss_v4_score"] == 9.3, "A v4 metric is not lost to the ordering"
    assert row["cvss_version"] == "3.1", "cvss_version describes cvss_vector"
    assert row["cvss_v2_score"] is None
    assert row["severity"] == "critical"


def test_v4_only_row_carries_the_v4_score_and_version():
    from scans.nvd_sync import _row_for_cve

    record = NvdClient()._parse_cve_item(_cve_json(_metric("cvssMetricV40", _V40)))

    row = _row_for_cve(record)

    assert row["cvss_version"] == "4.0"
    assert row["cvss_v4_score"] == 9.3
    assert row["cvss_v3_score"] is None
    assert row["cvss_v2_score"] is None
    assert row["severity"] == "critical"


def test_v2_row_still_lands_in_the_v2_column():
    from scans.nvd_sync import _row_for_cve

    record = NvdClient()._parse_cve_item(_cve_json(_metric("cvssMetricV2", _V2)))

    row = _row_for_cve(record)

    assert row["cvss_v2_score"] == 7.5
    assert row["cvss_v3_score"] is None
    assert row["cvss_v4_score"] is None
    assert row["cvss_version"] == "2.0"
