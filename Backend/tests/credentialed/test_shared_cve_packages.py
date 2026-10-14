"""
A CVE that affects several installed packages is reported against each one.

The matcher merged on the CVE alone, so a CVE named by two source packages
kept whichever record ranked higher and dropped the other. On 10.180.6.45
(13 Oct 2026) 45 such CVEs (xorg-server/xwayland, libsoup2.4/libsoup3, …)
each named one package — which one depended on row order — while remediation
needed both updated. The package is part of a finding's identity since
migration a7c9e1b3d5f8, so the merge is now per (CVE, package) and its order is
fixed.
"""

from __future__ import annotations

import random

from engines.credentialed.vuln_matcher import CredentialedCVE, VulnMatcher

CVE = "CVE-2025-49175"


def _finding(package, *, priority=50.0, matched_by="osv:Ubuntu:24.04:LTS", cve=CVE):
    return CredentialedCVE(
        cve_id=cve,
        severity="High",
        cvss_score=7.8,
        description="X server",
        package_name=package,
        installed_ver="2:21.1.12-1ubuntu1.4",
        fixed_ver="2:21.1.12-1ubuntu1.5",
        priority_score=priority,
        matched_by=matched_by,
    )


def _matcher(sources=None):
    matcher = VulnMatcher.__new__(VulnMatcher)
    matcher._package_sources = dict(sources or {})
    return matcher


SOURCES = {
    "xserver-common": "xorg-server",
    "xserver-xorg-core": "xorg-server",
    "xwayland": "xwayland",
    "libssl3t64": "openssl",
    "openssl": "openssl",
}


def test_two_source_packages_are_two_findings():
    merged = _matcher(SOURCES)._merge_by_package(
        [_finding("xserver-common"), _finding("xwayland")]
    )
    assert sorted(f.package_name for f in merged) == ["xserver-common", "xwayland"]


def test_binaries_of_one_source_are_one_finding():
    merged = _matcher(SOURCES)._merge_by_package(
        [_finding("xserver-common"), _finding("xserver-xorg-core")]
    )
    assert [f.package_name for f in merged] == ["xserver-common"]


def test_a_cpe_and_an_osv_match_on_one_package_merge_keeping_the_higher():
    merged = _matcher(SOURCES)._merge_by_package(
        [
            _finding("openssl", priority=40.0, matched_by="cpe"),
            _finding("libssl3t64", priority=60.0),
        ]
    )
    assert len(merged) == 1 and merged[0].priority_score == 60.0


def test_without_a_recorded_source_each_installed_package_is_its_own():
    # Windows: no source packages. Two installed Python versions share a CVE.
    merged = _matcher()._merge_by_package(
        [
            _finding("Python 3.12.4 (64-bit)", matched_by="cpe"),
            _finding("Python 3.11.9 (64-bit)", matched_by="cpe"),
        ]
    )
    assert len(merged) == 2


def test_the_result_does_not_depend_on_input_order():
    findings = [
        _finding("xserver-common", priority=50.0),
        _finding("xwayland", priority=50.0),
        _finding("libssl3t64", priority=70.0, cve="CVE-2024-0727"),
        _finding("openssl", priority=70.0, cve="CVE-2024-0727", matched_by="cpe"),
        _finding("xserver-xorg-core", priority=50.0, cve="CVE-2024-9632"),
    ]
    expected = None
    rng = random.Random(14)
    for _ in range(20):
        shuffled = findings[:]
        rng.shuffle(shuffled)
        # Ties between equal records are first-seen; the batch path's input
        # order is fixed, so compare the keys the order cannot change.
        result = [
            (f.cve_id, _matcher(SOURCES)._package_unit(f.package_name))
            for f in _matcher(SOURCES)._merge_by_package(shuffled)
        ]
        expected = expected or result
        assert result == expected
    assert expected == [
        ("CVE-2024-0727", "openssl"),
        ("CVE-2024-9632", "xorg-server"),
        ("CVE-2025-49175", "xorg-server"),
        ("CVE-2025-49175", "xwayland"),
    ]
