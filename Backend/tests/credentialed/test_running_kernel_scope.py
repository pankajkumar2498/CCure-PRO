"""
Kernel advisories are matched against the kernel that runs.

10.180.6.45 (Ubuntu 24.04, 13 Oct 2026) runs 6.8.0-146 and still has 6.8.0-142
installed beside it, plus the header files of 6.8.0-58 with no image. With the
OSV row limit lifted, 3,391 kernel CVEs were reported against
linux-headers-6.8.0-58, and the running kernel's own unfixed CVEs were filed
under 6.8.0-142, which sorts first. A kernel that is installed but not running
is now counted and named as not assessed — never reported as clean.

The OSV row limit is covered here too: ``LIMIT 5000`` dropped 12,676 of that
host's 17,676 advisory rows without saying so.
"""

from __future__ import annotations

import pytest
from engines.credentialed import vuln_matcher
from engines.credentialed.vuln_matcher import (
    VulnMatcher,
    kernel_abi,
    package_kernel_abi,
)

INVENTORY = [
    ("linux-headers-6.8.0-58", "6.8.0-58.60"),
    ("linux-headers-6.8.0-58-generic", "6.8.0-58.60"),
    ("linux-headers-6.8.0-142", "6.8.0-142.142"),
    ("linux-image-6.8.0-142-generic", "6.8.0-142.142"),
    ("linux-modules-extra-6.8.0-142-generic", "6.8.0-142.142"),
    ("linux-headers-6.8.0-146", "6.8.0-146.146"),
    ("linux-image-6.8.0-146-generic", "6.8.0-146.146"),
    ("linux-image-generic", "6.8.0-146.146"),
    ("linux-firmware", "20240318.git3b128b60-0ubuntu2.17"),
    ("linux-libc-dev", "6.8.0-146.146"),
    ("openssl", "3.0.13-0ubuntu3.5"),
]


@pytest.mark.parametrize(
    "name,abi",
    [
        ("linux-headers-6.8.0-58", "6.8.0-58"),
        ("linux-modules-extra-6.8.0-142-generic", "6.8.0-142"),
        ("linux-hwe-6.8-headers-6.8.0-58", "6.8.0-58"),
        ("linux-image-generic", ""),
        ("linux-firmware", ""),
        ("linux-libc-dev", ""),
        ("openssl", ""),
    ],
)
def test_a_packages_kernel_abi(name, abi):
    assert package_kernel_abi(name) == abi


def test_the_running_kernels_abi():
    assert kernel_abi("6.8.0-146-generic") == "6.8.0-146"
    assert kernel_abi("") == ""
    assert kernel_abi("10.0.26200") == ""  # what a Windows host reports


def _match(running_kernel, sources=None):
    matcher = VulnMatcher()
    matched: dict[str, str] = {}

    def batch(package_data):
        matched.update(package_data)
        return []

    matcher._match_packages_batch = batch
    packages = [
        {
            "name": name,
            "version": version,
            **({"source": sources[name]} if sources and name in sources else {}),
        }
        for name, version in INVENTORY
    ]
    matcher.match_packages(
        packages, os_id="ubuntu", os_version_id="24.04", running_kernel=running_kernel
    )
    return matcher, matched


def test_only_the_running_kernels_packages_are_matched():
    matcher, matched = _match("6.8.0-146-generic")
    assert not any("6.8.0-58" in name or "6.8.0-142" in name for name in matched)
    assert {
        "linux-headers-6.8.0-146",
        "linux-image-6.8.0-146-generic",
        "linux-image-generic",
        "linux-firmware",
        "linux-libc-dev",
        "openssl",
    } <= set(matched)

    coverage = matcher.coverage()
    assert coverage["running_kernel"] == "6.8.0-146"
    assert coverage["inactive_kernels"] == ["6.8.0-142", "6.8.0-58"]
    assert coverage["packages_inactive_kernel"] == 5
    # Collected is the whole inventory; assessed leaves the five out.
    assert coverage["packages_collected"] == len(INVENTORY)
    assert coverage["packages_assessable"] == len(INVENTORY) - 5


def test_without_a_running_kernel_everything_is_matched():
    matcher, matched = _match("")
    assert len(matched) == len(INVENTORY)
    assert matcher.coverage()["packages_inactive_kernel"] == 0
    assert matcher.coverage()["running_kernel"] is None


def test_a_non_kernel_source_is_never_scoped_out():
    _matcher, matched = _match(
        "6.8.0-146-generic", sources={"linux-headers-6.8.0-58": "not-a-kernel"}
    )
    assert "linux-headers-6.8.0-58" in matched


class _Rows:
    def __init__(self, rows):
        self._rows = rows

    def mappings(self):
        return self

    def all(self):
        return self._rows


class _Conn:
    def __init__(self, rows):
        self._rows = rows

    def execute(self, _query, _params):
        return _Rows(self._rows)


def test_reaching_the_osv_row_cap_is_recorded(monkeypatch):
    monkeypatch.setattr(vuln_matcher, "OSV_ROW_CAP", 2)
    matcher = VulnMatcher()
    matcher._package_sources = {}
    matcher._osv_ecosystems = ["Ubuntu:24.04:LTS"]
    row = {
        "cve_id": "CVE-2026-0001",
        "package_name": "unrelated",
        "ecosystem": "Ubuntu:24.04:LTS",
        "introduced": "0",
        "fixed": "1.0",
    }
    matcher._batch_query_osv(_Conn([row, row, row]), ["openssl"], {"openssl": "3.0"})
    assert matcher.lookup_failures
    assert "were not assessed" in matcher.lookup_failures[0]


def test_the_osv_query_is_not_silently_limited():
    import inspect

    source = inspect.getsource(VulnMatcher._batch_query_osv)
    assert "LIMIT 5000" not in source
    assert vuln_matcher.OSV_ROW_CAP >= 100_000


def test_the_osv_order_is_total():
    # A CVE two source packages share must land on the same package every
    # scan; the package is part of the finding's identity.
    import inspect

    source = inspect.getsource(VulnMatcher._batch_query_osv)
    order_by = source[source.index("ORDER BY") : source.index("LIMIT {OSV_ROW_CAP")]
    for key in ("oa.cve_id", "LOWER(aff.package_name)", "aff.ecosystem"):
        assert key in order_by
