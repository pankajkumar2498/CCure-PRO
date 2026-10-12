"""
tests/scans/test_vendor_builds.py
─────────────────────────────────────────────────────────────────────────────
A vendor's own build of a product, and countermeasures observed on the wire.

On 10.180.6.30 (Windows 11, scans #9 and #10, 12 Oct 2026) the SSH banner read
"OpenSSH_for_Windows_9.5" and twenty upstream OpenSSH CVEs were reported as
Confirmed against it. But the host reads its sshd.exe as 9.5.6.3: Microsoft
services the build with backported fixes and the banner does not move. Two of
the twenty were disproved outright — the server advertised Terrapin's
strict-KEX countermeasure, and Microsoft publishes that regreSSHion does not
affect its build — and the rest could not be confirmed from a version.
"""

from testpaths import BACKEND_ROOT

import sys

sys.path.insert(0, str(BACKEND_ROOT))

from scans.finding_normalizer import (  # noqa: E402
    Confidence,
    build_scan_report,
    effective_precision,
    vendor_build_for,
    verify_host_findings,
    version_precision,
)

OPENSSH = "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"
STRICT_KEX = [
    "curve25519-sha256",
    "diffie-hellman-group14-sha256",
    "kex-strict-s-v00@openssh.com",
]


def _ssh_port(version="for_Windows_9.5", product="OpenSSH", port=22):
    return {
        "port": port,
        "protocol": "tcp",
        "service": "ssh",
        "product": product,
        "version": version,
        "version_precision": "exact",
        "cpe": ["cpe:/a:openbsd:openssh:for_windows_9.5"],
    }


def _cve(cve_id, version, port=22, **bounds):
    return {
        "cve_id": cve_id,
        "description": f"{cve_id} in OpenSSH.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "affected": [
            {"vendor": "openbsd", "product": "openssh", "cpe_uri": OPENSSH, **bounds}
        ],
        "port": port,
        "protocol": "tcp",
        "detected_version": version,
    }


def _host(ports, cves, kex=None):
    host = {
        "ip_address": "10.180.6.30",
        "os_guess": "Microsoft Windows 11 Pro",
        "open_ports": ports,
        "cves": cves,
    }
    if kex is not None:
        host["ssh_info"] = {
            "banner": "SSH-2.0-OpenSSH_for_Windows_9.5",
            "kex_algos": kex,
        }
    return host


def _by_id(verification):
    kept = {c["cve_id"]: c for c in verification.verified}
    withheld = {s.identifier: s.reason for s in verification.suppressed}
    return kept, withheld


# ── Identifying the build ───────────────────────────────────────────────────


def test_the_build_is_named_by_version_banner_or_product():
    for text in (
        "for_Windows_9.5",  # nmap's version field
        "SSH-2.0-OpenSSH_for_Windows_9.5",  # the banner
        "OpenSSH for Windows",  # the authenticated listener's product
    ):
        assert vendor_build_for(text) is not None, text
    for text in ("9.5p1", "OpenSSH 9.6p1", "Platform for Windows Server", ""):
        assert vendor_build_for(text) is None, text


def test_a_vendor_build_version_is_a_floor_whatever_was_recorded():
    """nmap records "for_Windows_9.5" as exact, because as a string it is."""
    assert version_precision("for_Windows_9.5") == "floor"
    assert effective_precision("for_Windows_9.5", "exact") == "floor"
    assert effective_precision("9.5p1", "exact") == "exact"


# ── Judging CVEs against it ─────────────────────────────────────────────────


def test_upstream_cves_against_the_build_are_potential_not_confirmed():
    kept, withheld = _by_id(
        verify_host_findings(
            _host(
                [_ssh_port()],
                [
                    _cve(
                        "CVE-2026-60002",
                        "for_Windows_9.5",
                        version_end_excluding="10.4",
                    ),
                    # Fixed in 7.8, long before the release the build was cut from.
                    _cve(
                        "CVE-2018-15473", "for_Windows_9.5", version_end_excluding="7.8"
                    ),
                ],
            )
        )
    )
    assert kept["CVE-2026-60002"]["confidence"] == Confidence.POTENTIAL.value
    assert kept["CVE-2026-60002"]["detection_method"] == "version_imprecise"
    # A floor still disproves what was fixed below it.
    assert "CVE-2018-15473" in withheld


def test_a_corrected_file_version_does_not_make_the_build_upstream():
    """9.5.6.3 is Microsoft's file version, no more an upstream release than 9.5."""
    kept, _ = _by_id(
        verify_host_findings(
            _host(
                [_ssh_port(version="9.5.6.3", product="OpenSSH for Windows")],
                [_cve("CVE-2026-60002", "9.5.6.3", version_end_excluding="10.4")],
            )
        )
    )
    assert kept["CVE-2026-60002"]["confidence"] == Confidence.POTENTIAL.value


def test_the_remediation_names_the_build_and_where_its_fix_comes_from():
    host = _host(
        [_ssh_port()],
        [_cve("CVE-2026-60002", "for_Windows_9.5", version_end_excluding="10.4")],
    )
    (finding,) = build_scan_report({"data": [host]}).vulnerabilities
    assert finding.remediation.product == "OpenSSH for Windows"
    assert "Openbsd" not in finding.remediation.summary
    assert "Windows cumulative update" in finding.remediation.summary


def test_the_vendors_own_statement_rules_a_cve_out():
    _, withheld = _by_id(
        verify_host_findings(
            _host(
                [_ssh_port()],
                [
                    _cve(
                        "CVE-2024-6387",
                        "for_Windows_9.5",
                        version_start_including="8.6",
                        version_end_including="9.8",
                    )
                ],
            )
        )
    )
    assert withheld["CVE-2024-6387"].startswith(
        "Ruled out: Microsoft states its OpenSSH for Windows build is not affected"
    )
    assert "msrc.microsoft.com" in withheld["CVE-2024-6387"]


def test_the_vendor_statement_does_not_reach_upstream_openssh():
    kept, _ = _by_id(
        verify_host_findings(
            _host(
                [_ssh_port(version="9.5p1")],
                [
                    _cve(
                        "CVE-2024-6387",
                        "9.5p1",
                        version_start_including="8.6",
                        version_end_including="9.8",
                    )
                ],
            )
        )
    )
    assert kept["CVE-2024-6387"]["confidence"] == Confidence.CONFIRMED.value


# ── A countermeasure seen on the wire ───────────────────────────────────────


def test_an_advertised_strict_kex_rules_terrapin_out():
    _, withheld = _by_id(
        verify_host_findings(
            _host(
                [_ssh_port(version="9.5p1")],
                [_cve("CVE-2023-48795", "9.5p1", version_end_excluding="9.6")],
                kex=STRICT_KEX,
            )
        )
    )
    assert withheld["CVE-2023-48795"] == (
        "Ruled out: the SSH server advertises strict key exchange "
        "(kex-strict-s-v00@openssh.com), the fix for this prefix-truncation "
        "attack, so it implements the countermeasure whatever version its "
        "banner reports."
    )


def test_without_the_countermeasure_terrapin_stands():
    kept, _ = _by_id(
        verify_host_findings(
            _host(
                [_ssh_port(version="9.5p1")],
                [_cve("CVE-2023-48795", "9.5p1", version_end_excluding="9.6")],
                kex=["curve25519-sha256", "diffie-hellman-group14-sha256"],
            )
        )
    )
    assert kept["CVE-2023-48795"]["confidence"] == Confidence.CONFIRMED.value


def test_the_countermeasure_belongs_to_the_port_it_was_seen_on():
    """The probe handshakes 22/tcp; a second sshd on 2222 was never observed."""
    kept, _ = _by_id(
        verify_host_findings(
            _host(
                [_ssh_port(version="9.5p1"), _ssh_port(version="9.5p1", port=2222)],
                [
                    _cve(
                        "CVE-2023-48795",
                        "9.5p1",
                        port=2222,
                        version_end_excluding="9.6",
                    )
                ],
                kex=STRICT_KEX,
            )
        )
    )
    assert "CVE-2023-48795" in kept
