"""
A candidate search that stopped at its cap is stated in the scan's reports.

On 10.180.6.45 (13 Oct 2026) the kernel search stopped at 2,000 of ~14,000
CVEs; the only record was one WARNING in the worker log and a per-record flag
nothing read. The host now records it (cve_engine), the phase summary rolls it
up, and the PDF methodology table and the export summary print it. A scan that
predates the record says nothing, rather than claiming every search completed.
"""

from __future__ import annotations

from core.candidate_enumeration import describe, searches_run, truncated_searches
from reporting.exports import scan_context_rows
from reporting.pdf_generator import _truncated_searches_row
from scans.report_inputs import report_inputs


def _row(meta, summary):
    """The PDF's row, with the notes the report inputs carry."""
    notes = report_inputs(meta, summary)["truncated_search_notes"]
    return _truncated_searches_row(meta, summary, notes)


KERNEL = {
    "scope": "host",
    "port": None,
    "protocol": None,
    "search": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
    "source": "cpe_exact",
    "cap": 2000,
}
HOSTS = [
    {
        "ip_address": "10.180.6.45",
        "candidate_enumeration": {"searches": 5, "truncated": [KERNEL]},
    },
    {
        "ip_address": "10.180.6.30",
        "candidate_enumeration": {"searches": 7, "truncated": []},
    },
]


def test_the_summary_rolls_up_every_host():
    assert searches_run(HOSTS) == 12
    (entry,) = truncated_searches(HOSTS)
    assert entry["host"] == "10.180.6.45"


def test_hosts_that_recorded_nothing_give_no_count():
    assert searches_run([{"ip_address": "10.0.0.1"}]) is None


def test_a_truncation_reads_as_what_was_not_evaluated():
    text = describe({**KERNEL, "host": "10.180.6.45"})
    assert text.startswith("10.180.6.45 operating system: 'linux:linux_kernel'")
    assert "stopped at 2,000 candidates" in text
    assert "not evaluated" in text
    port = describe(
        {
            **KERNEL,
            "port": 161,
            "protocol": "udp",
            "search": "snmp",
            "source": "name_match",
        }
    )
    assert port.startswith("port 161/udp: 'snmp' (name match)")


def test_the_pdf_names_each_truncated_search():
    label, value = _row({}, {"candidate_searches_truncated": truncated_searches(HOSTS)})
    assert label == "Candidate searches truncated"
    assert value.startswith("1 — 10.180.6.45 operating system")


def test_the_pdf_says_none_only_when_the_scan_recorded_it():
    assert _row({}, {"candidate_searches_truncated": []})[1].startswith("None")
    assert _row({}, {"candidates_evaluated": 3653}) is None


def test_the_export_summary_has_the_row_only_when_recorded():
    recorded = scan_context_rows(
        {"candidate_searches_truncated": ["x stopped at 2,000"]}
    )
    assert ["Candidate Searches Truncated", "x stopped at 2,000"] in recorded
    none = scan_context_rows({"candidate_searches_truncated": []})
    assert any(
        r[0] == "Candidate Searches Truncated" and r[1].startswith("None") for r in none
    )
    older = scan_context_rows({})
    assert not any(r[0] == "Candidate Searches Truncated" for r in older)


def test_the_record_survives_the_host_model_into_the_stored_payload():
    # HostResult is built from an explicit field list and cleaned through a
    # whitelist; a key missing from either is dropped without a word, which is
    # how verification metadata was once lost on the way to the database.
    from orchestrator.scan_orchestrator import ScanOrchestrator

    orchestrator = ScanOrchestrator.__new__(ScanOrchestrator)
    record = {"searches": 5, "truncated": [KERNEL]}
    host = orchestrator._format_host(
        "10.180.6.45", {"is_active": False, "candidate_enumeration": record}
    )
    assert host.to_phase3_dict()["candidate_enumeration"] == record
