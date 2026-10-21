"""
scripts/verification/verify_report_integrity.py
─────────────────────────────────────────────────────────────────────────────
Audits the report pipeline for fabricated content.

Two independent layers are checked:

  1. Content — the generator's story is built from a scan payload and every
     Paragraph's text is harvested. This is the authoritative check: it sees
     exactly the words that will be drawn, before any font encoding is applied.

  2. Structure — the produced PDF is inspected for outline bookmarks and
     internal links. Rendered text is deliberately not parsed here: reports
     embed a subset TTF for Unicode coverage, so glyph codes in the content
     stream are not ASCII and naive extraction would be meaningless.

Usage
─────
    python scripts/verification/verify_report_integrity.py
    python scripts/verification/verify_report_integrity.py payload.json
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List

sys.path.insert(
    0,
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
)

from reportlab.platypus import Paragraph, Table  # noqa: E402

# ─────────────────────────────────────────────────────────────────────────────
# Assertions
# ─────────────────────────────────────────────────────────────────────────────

#: Strings the previous template-driven generator emitted. Any reappearance
#: means invented content has crept back into the pipeline.
FABRICATED_MARKERS: List[str] = [
    "Vulnerable component matching",
    "Unknown vulnerabil",
    "Vulnerability in Vulnerability",
    "version entering",
    "Upgrade the to version",
    "Upgrade log.c",
    "Linux / Windows",
    "Upgrade MySQL to version 4.0.24",
    "Apply official vendor security patch for CVE-",
    "Stack-based buffer Vulnerability",
]

#: Provenance markers proving the report discloses how it reached its
#: conclusions rather than merely asserting them.
REQUIRED_TECHNICAL_MARKERS: List[str] = [
    "Table of Contents",
    "Host index",
    "How this was detected",
    "Appendix A",
    "Suppressed candidates",
    "recomputed",
    "Limitations",
    "Service inventory",
]

REQUIRED_EXECUTIVE_MARKERS: List[str] = [
    "Security posture",
    "Severity distribution",
    "Prioritised remediation plan",
    "Assessment coverage",
    "remediation policy",
]


SAMPLE_PAYLOAD: Dict[str, Any] = {
    "metadata": {
        "scan_no": "SCAN-VERIFY-001",
        "target": "192.0.2.0/29",
        "scan_method": "TCP SYN + service detection",
        "duration_seconds": 300,
        "cve_feed_updated": "2026-07-28",
    },
    "summary": {},
    "data": [
        {
            "ip_address": "192.0.2.10",
            "hostname": "db-01",
            "os_guess": "Ubuntu 20.04.6 LTS",
            "open_ports": [
                {
                    "port": 5432,
                    "protocol": "tcp",
                    "service": "postgresql",
                    "product": "PostgreSQL DB",
                    "version": "9.6.2",
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
                    "cve_id": "CVE-2017-7546",
                    "title": "PostgreSQL Empty Password Authentication Bypass",
                    "description": "PostgreSQL before 9.6.6 accepts an empty password.",
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "cvss_v3_score": 9.8,
                    "affected_software": [
                        {
                            "vendor": "postgresql",
                            "product": "postgresql",
                            "versionEndExcluding": "9.6.6",
                        }
                    ],
                    "port": 5432,
                    "in_kev": True,
                    "kev_due_date": "2026-08-15",
                    "epss_score": 0.7421,
                    "plugin_output": "  Installed : 9.6.2\n  Fixed in  : 9.6.6",
                },
                {
                    "cve_id": "CVE-2004-1440",
                    "title": "PuTTY modpow Buffer Overflow",
                    "description": "Heap overflow in modpow in PuTTY before 0.55.",
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "affected_software": [
                        {
                            "vendor": "putty",
                            "product": "putty",
                            "versionEndExcluding": "0.55",
                        }
                    ],
                },
            ],
        },
        {
            "ip_address": "192.0.2.11",
            "hostname": "",
            "os_guess": "",
            "open_ports": [{"port": 445, "protocol": "tcp", "service": "microsoft-ds"}],
            "cves": [],
        },
    ],
}


# ─────────────────────────────────────────────────────────────────────────────
# Story harvesting
# ─────────────────────────────────────────────────────────────────────────────


def harvest_text(story: List[Any]) -> str:
    """Recursively collect the plain text of every Paragraph in a story."""
    collected: List[str] = []

    def visit(node: Any, depth: int = 0) -> None:
        if depth > 12 or node is None:
            return
        if isinstance(node, Paragraph):
            try:
                collected.append(node.getPlainText())
            except Exception:
                pass
            return
        if isinstance(node, Table):
            for row in getattr(node, "_cellvalues", []) or []:
                visit(row, depth + 1)
            return
        if isinstance(node, (list, tuple)):
            for item in node:
                visit(item, depth + 1)
            return
        for attribute in ("_content", "_flowables", "flowables"):
            inner = getattr(node, attribute, None)
            if inner:
                visit(inner, depth + 1)
                return

    visit(story)
    return "\n".join(collected)


def build_story_text(payload: Dict[str, Any]) -> Dict[str, str]:
    """
    Build both reports and capture their story text.

    The generator's build call is intercepted so the assembled story can be
    harvested without depending on how ReportLab later encodes it.
    """
    import reporting.pdf_generator as pdf_generator
    from reporting.pdf_generator import ScanReportGenerator
    from scans.report_inputs import with_report_inputs

    captured: Dict[str, str] = {}

    original_doc = ScanReportGenerator._doc

    def make_probe(label: str):
        def probe(self, filename, title, header):
            doc = original_doc(self, filename, title, header)
            real_build = doc.build
            real_multi = doc.multiBuild

            def build(story, *a, **kw):
                captured[label] = harvest_text(story)
                return real_build(story, *a, **kw)

            def multi(story, *a, **kw):
                captured[label] = harvest_text(story)
                return real_multi(story, *a, **kw)

            doc.build = build
            doc.multiBuild = multi
            return doc

        return probe

    generator = ScanReportGenerator(
        output_dir=os.path.join(os.environ.get("TEMP", "/tmp"), "ccure_verify")
    )

    ScanReportGenerator._doc = make_probe("executive")
    executive = generator.generate_executive_pdf(payload, "phase3")

    ScanReportGenerator._doc = make_probe("technical")
    technical = generator.generate_technical_pdf(with_report_inputs(payload), "phase3")

    ScanReportGenerator._doc = original_doc

    captured["_executive_path"] = executive
    captured["_technical_path"] = technical
    return captured


# ─────────────────────────────────────────────────────────────────────────────
# Structural inspection
# ─────────────────────────────────────────────────────────────────────────────


def structure_report(path: str) -> Dict[str, Any]:
    raw = open(path, "rb").read()
    return {
        "size": len(raw),
        "bookmarks": b"/Outlines" in raw,
        "links": raw.count(b"/Link"),
        "embedded_fonts": raw.count(b"/FontFile2") + raw.count(b"/FontFile"),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────


def main() -> int:
    if len(sys.argv) > 1:
        with open(sys.argv[1], "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        print(f"Payload: {sys.argv[1]}")
    else:
        payload = SAMPLE_PAYLOAD
        print("Payload: built-in verification sample")

    captured = build_story_text(payload)
    ok = True

    for label, required in (
        ("executive", REQUIRED_EXECUTIVE_MARKERS),
        ("technical", REQUIRED_TECHNICAL_MARKERS),
    ):
        text = captured.get(label, "")
        path = captured.get(f"_{label}_path", "")
        print(f"\n=== {label} report ===")
        print(f"  file        : {os.path.basename(path)}")
        print(f"  story text  : {len(text):,} chars")

        info = structure_report(path)
        print(f"  size        : {info['size']:,} bytes")
        print(f"  bookmarks   : {info['bookmarks']}")
        print(f"  links       : {info['links']}")
        print(f"  embedded TTF: {info['embedded_fonts']}")

        print("  fabricated strings (must be absent):")
        for marker in FABRICATED_MARKERS:
            if marker in text:
                ok = False
                print(f"    FAIL  found   {marker!r}")
        print(
            "    (none found)" if all(m not in text for m in FABRICATED_MARKERS) else ""
        )

        print("  provenance markers (must be present):")
        for marker in required:
            present = marker in text
            if not present:
                ok = False
            print(f"    {'ok   ' if present else 'FAIL '} {marker!r}")

    print()
    if ok:
        print("PASS - report content is evidence-based; no fabricated strings present.")
        return 0
    print("FAIL - fabricated content or missing provenance markers.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
