"""
tests/test_web_scan_findings.py
─────────────────────────────────────────────────────────────────────────────
The web pipeline is a separate scanner with its own report path, but it feeds
the same asset registry, dashboards and compliance evidence as the network
scans — so it is held to the same rule: a number that was not measured is not
reported as if it were.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.web.nuclei.wrapper import NucleiWrapper  # noqa: E402


def _raw(**overrides):
    raw = {
        "template-id": "exposed-panel",
        "info": {"name": "Exposed admin panel", "severity": "high", "tags": ["panel"]},
        "matched-at": "https://example.test/admin",
        "host": "example.test",
    }
    raw.update(overrides)
    return raw


def test_a_finding_without_a_published_score_is_not_given_one():
    """
    A severity-to-score table ("high" → 7.5) manufactures a measurement: it
    reads downstream as a computed CVSS, aggregates into risk scores, and lands
    in compliance evidence as though it had been derived from a vector.
    """
    finding = NucleiWrapper._normalize_finding(_raw())

    assert finding["severity"] == "high"
    assert finding["cvss_score"] is None
    assert finding["cvss_scored"] is False


def test_a_published_score_is_carried_through_unchanged():
    raw = _raw()
    raw["info"]["classification"] = {
        "cvss-score": 9.8,
        "cvss-metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    }

    finding = NucleiWrapper._normalize_finding(raw)

    assert finding["cvss_score"] == 9.8
    assert finding["cvss_scored"] is True
    assert finding["cvss_vector"].startswith("CVSS:3.1/")


def test_severity_from_the_template_is_preserved():
    """The template's rating is real evidence; only the invented score was not."""
    for level in ("info", "low", "medium", "high", "critical"):
        raw = _raw()
        raw["info"]["severity"] = level
        finding = NucleiWrapper._normalize_finding(raw)
        assert finding["severity"] == level
