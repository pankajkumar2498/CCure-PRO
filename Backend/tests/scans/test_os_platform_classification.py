"""
OS-level CVEs are judged against the right kind of version, as host findings.

An unauthenticated scan of an Ubuntu 24.04 host whose SNMP agent reported
"Linux superusr-HP3 6.8.0-146-generic … Ubuntu" (10.180.6.45, 13 Oct 2026)
reported, among others:

* CVE-2021-3493 — published only against ``ubuntu_linux`` releases before
  20.10. The kernel version 6.8.0 was compared with release numbers, and 6.8 is
  "before 20.10".
* CVE-2024-1086 — affected through 6.7.3 and in the ``6.8:rc1`` pre-release
  only. The pinned CPE's version field equals 6.8, and its ``rc1`` was ignored.
* Both bound to "22/tcp ssh · Product OpenSSH · Detected version 6.8.0",
  because nmap attaches the OS CPE to the ssh service.

The CPE rows below are NVD's, as stored in vuln_intel.
"""

from __future__ import annotations

import pytest
from core.checks.finding_normalizer import (
    DetectionMethod,
    ServiceRecord,
    _build_evidence,
    _classify_platform_finding,
    version_in_cpe_range,
)

SNMP_OS = "Ubuntu Linux (kernel 6.8.0-146-generic)"


def _cpe(product, version="*", update="*", vendor=None, **bounds):
    vendor = vendor or {"linux_kernel": "linux", "ubuntu_linux": "canonical"}[product]
    row = {
        "product": product,
        "cpe23Uri": f"cpe:2.3:o:{vendor}:{product}:{version}:{update}:*:*:*:*:*:*",
    }
    row.update(bounds)
    return row


CVE_2021_3493 = [
    _cpe("ubuntu_linux", version_end_excluding="20.10"),
    _cpe(
        "ubuntu_linux", version_start_including="18.04.1", version_end_excluding="20.04"
    ),
    _cpe("ubuntu_linux", version_end_excluding="18.04"),
]

CVE_2024_1086 = [
    _cpe(
        "linux_kernel", version_start_including="3.15", version_end_excluding="5.15.149"
    ),
    _cpe("linux_kernel", version_start_including="6.1", version_end_excluding="6.1.76"),
    _cpe("linux_kernel", version_start_including="6.2", version_end_excluding="6.6.15"),
    _cpe("linux_kernel", version_start_including="6.7", version_end_excluding="6.7.3"),
    _cpe("linux_kernel", version="6.8", update="rc1"),
]

CVE_2024_53104 = [
    _cpe("linux_kernel", version_start_including="6.7", version_end_excluding="6.11.8"),
]


# ── distribution CPEs need a distribution release ───────────────────────────


def test_a_kernel_version_is_never_compared_with_distribution_releases():
    method, version, _, basis = _classify_platform_finding(CVE_2021_3493, SNMP_OS, "")
    assert method is DetectionMethod.UNVERIFIED
    assert basis == "os_version_unknown"
    assert version == ""


def test_a_known_release_past_the_range_is_ruled_out():
    method, version, _, basis = _classify_platform_finding(
        CVE_2021_3493, "Ubuntu 24.04.5 LTS", ""
    )
    assert (method, basis, version) == (
        DetectionMethod.UNVERIFIED,
        "version_outside_range",
        "24.04.5",
    )


def test_a_known_release_inside_the_range_is_reported():
    method, version, _, _ = _classify_platform_finding(
        CVE_2021_3493, "Ubuntu 18.04.6 LTS", ""
    )
    assert method is DetectionMethod.OS_REPORTED
    assert version == "18.04.6"


# ── kernel CPEs need a kernel version ───────────────────────────────────────


def test_a_pinned_pre_release_does_not_match_the_release():
    method, _, _, basis = _classify_platform_finding(CVE_2024_1086, SNMP_OS, "")
    assert method is DetectionMethod.UNVERIFIED
    assert basis == "version_outside_range"


def test_a_range_that_does_cover_the_kernel_is_still_reported():
    method, version, _, _ = _classify_platform_finding(CVE_2024_53104, SNMP_OS, "")
    assert method is DetectionMethod.OS_REPORTED
    assert version == "6.8.0"


def test_a_distribution_release_is_not_read_as_a_kernel_version():
    """'Ubuntu 24.04.5 LTS' carries no kernel version; 24.04.5 is not one."""
    method, _, _, basis = _classify_platform_finding(
        CVE_2024_53104, "Ubuntu 24.04.5 LTS", ""
    )
    assert (method, basis) == (DetectionMethod.UNVERIFIED, "os_version_unknown")


# ── the pinned-version comparison ───────────────────────────────────────────


@pytest.mark.parametrize(
    "detected,expected",
    [("6.8.0", False), ("6.8", False), ("6.8-rc1", True)],
)
def test_pre_release_pins(detected, expected):
    pinned = _cpe("linux_kernel", version="6.8", update="rc1")
    assert version_in_cpe_range(detected, pinned) is expected


def test_a_non_pre_release_update_keeps_the_version_comparison():
    pinned = {
        "cpe23Uri": "cpe:2.3:a:openbsd:openssh:9.6:p1:*:*:*:*:*:*",
        "product": "openssh",
    }
    assert version_in_cpe_range("9.6", pinned) is True


# ── evidence for an OS-level finding ───────────────────────────────────────


def test_os_level_evidence_names_the_host_not_the_service():
    ssh = ServiceRecord(port=22, protocol="tcp", service_name="ssh", product="OpenSSH")
    text, captured = _build_evidence(
        {}, ssh, "6.8.0", DetectionMethod.OS_REPORTED, "CVE-2024-53104", SNMP_OS
    )
    assert captured is False
    assert "Scope             : host (operating system)" in text
    assert SNMP_OS in text
    assert "6.8.0" in text
    assert "22/tcp" not in text and "OpenSSH" not in text
