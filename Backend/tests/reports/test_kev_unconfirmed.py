"""
tests/reports/test_kev_unconfirmed.py
─────────────────────────────────────────────────────────────────────────────
A known-exploited CVE the scan could not confirm is shown, and says so.

The report surfaces a CISA KEV entry even below the reporting threshold —
omitting one that is being exploited costs more than one line to verify. On
10.180.6.30 (12 Oct 2026) that was CVE-2023-44487 against an nginx whose
version was never detected, and the executive summary listed it under "Known
exploited vulnerabilities — immediate action" and tagged its plan entry
"[Actively exploited]" exactly like the confirmed Chrome entries beside it.
"""

from testpaths import BACKEND_ROOT

import sys

sys.path.insert(0, str(BACKEND_ROOT))

import reporting.pdf_generator as pdf_generator  # noqa: E402
from reporting.pdf_generator import ScanReportGenerator, _remediation_plan  # noqa: E402
from scans.finding_normalizer import build_scan_report  # noqa: E402

VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"


def _payload():
    return {
        "metadata": {"target": "10.180.6.30", "scan_no": "11"},
        "data": [
            {
                "ip_address": "10.180.6.30",
                "os_guess": "Microsoft Windows 11 Pro",
                "open_ports": [
                    # nginx answered with no version.
                    {
                        "port": 80,
                        "protocol": "tcp",
                        "service": "http",
                        "product": "nginx",
                    },
                    {
                        "port": 22,
                        "protocol": "tcp",
                        "service": "ssh",
                        "product": "OpenSSH",
                        "version": "8.2p1",
                    },
                ],
                "cves": [
                    {
                        "cve_id": "CVE-2023-44487",
                        "description": "HTTP/2 rapid reset.",
                        "cvss_vector": VECTOR,
                        "in_kev": True,
                        "kev_due_date": "2023-10-31",
                        "port": 80,
                        "affected": [
                            {
                                "vendor": "f5",
                                "product": "nginx",
                                "cpe_uri": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
                                "version_start_including": "1.9.5",
                                "version_end_including": "1.25.2",
                            }
                        ],
                    },
                    {
                        "cve_id": "CVE-2021-41617",
                        "description": "sshd privilege escalation.",
                        "cvss_vector": VECTOR,
                        "in_kev": True,
                        "port": 22,
                        "detected_version": "8.2p1",
                        "affected": [
                            {
                                "vendor": "openbsd",
                                "product": "openssh",
                                "cpe_uri": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                                "version_start_including": "6.2",
                                "version_end_including": "8.7",
                            }
                        ],
                    },
                ],
            }
        ],
    }


def test_the_plan_puts_confirmed_exploitation_first_and_marks_the_rest():
    plan = _remediation_plan(build_scan_report(_payload()))
    flags = [(e["kev"], e["kev_confirmed"], e["product"]) for e in plan]
    assert flags[0][:2] == (True, True)  # OpenSSH, version-confirmed
    assert (True, False) in {f[:2] for f in flags}  # nginx, version unknown


def test_the_executive_summary_says_which_exploited_findings_are_unconfirmed(
    tmp_path, monkeypatch
):
    rendered = []
    original = pdf_generator._p

    def capture(text, style, escape=True):
        rendered.append(str(text))
        return original(text, style, escape)

    monkeypatch.setattr(pdf_generator, "_p", capture)
    ScanReportGenerator(output_dir=str(tmp_path)).generate_executive_pdf(
        _payload(), "phase_selective_scan"
    )
    text = "\n".join(rendered)

    # The table row for the unconfirmed finding carries the note.
    assert any("not confirmed on this host" in t and "Potential" in t for t in rendered)
    # The plan's tag tells the two apart.
    assert "[Actively exploited] " in text
    assert "[Exploited elsewhere — unconfirmed here] " in text
    # And so do the narrative and the posture statement.
    assert "Not confirmed on this host: CVE-2023-44487" in text
    assert "1 of them could not be confirmed on this host" in text
