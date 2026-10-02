"""
reporting/audit_export.py
─────────────────────────────────────────────────────────────────────────────
Rendering for the audit-trail export: the CSV that is the machine-verifiable
artefact, and the PDF that is the human-readable one.

Nothing here talks to the database. The router decides *which* rows leave the
platform and *what may be claimed about them*; this module only writes them
down. Keeping the two apart is what lets the integrity vocabulary below be
asserted by a test that never opens a connection.

The integrity vocabulary, and why it has four words rather than two
───────────────────────────────────────────────────────────────────
A row is `verified` **only** when its stored `record_hash` was recomputed
through the database's own canonical function and reproduced exactly. A
non-NULL hash on its own proves nothing — it is the value under suspicion, not
the evidence — so a hash that was never recomputed is `not_verified`, never
`verified`. A row written before the tamper-evidence chain existed has no hash
at all and is `legacy_unverifiable`: honest, and impossible to confuse with a
clean result. A hash that was recomputed and did **not** match is
`INTEGRITY_FAILURE`, spelled in capitals because it is the one value a reader
must not skim past.

The preamble is part of the evidence
────────────────────────────────────
Both formats carry the same header block, and it always states which of the
three verification modes ran. An export produced with `verify=false` says so in
words — "VERIFICATION WAS NOT PERFORMED" — because a file that merely omits the
claim reads, to anyone who did not request it, exactly like one that made it.
"""

from __future__ import annotations

from ccure_platform._legacy import adopt_legacy_name

adopt_legacy_name(__name__, "reporting.audit_export")


import csv
import io
import json
from datetime import datetime, timezone
from typing import Any, Iterable, Iterator, Sequence

# ─── Per-row integrity states ────────────────────────────────────────────────

INTEGRITY_VERIFIED = "verified"
INTEGRITY_LEGACY = "legacy_unverifiable"
INTEGRITY_FAILURE = "INTEGRITY_FAILURE"
INTEGRITY_NOT_VERIFIED = "not_verified"

INTEGRITY_STATES = (
    INTEGRITY_VERIFIED,
    INTEGRITY_LEGACY,
    INTEGRITY_FAILURE,
    INTEGRITY_NOT_VERIFIED,
)

# ─── Whole-export verification modes ─────────────────────────────────────────

VERIFICATION_PERFORMED = "performed"
VERIFICATION_NOT_REQUESTED = "not_requested"
VERIFICATION_UNAVAILABLE = "unavailable"

#: The sentence that goes in the preamble for each mode. Written out rather
#: than assembled from fragments: this is the paragraph an auditor reads to
#: decide what the file is worth, and it must not be able to drift.
VERIFICATION_NOTES = {
    VERIFICATION_PERFORMED: (
        "VERIFICATION PERFORMED. Every exported row carrying a stored "
        "record_hash had that hash recomputed at export time through the "
        "database's own canonical hash function - the same function the insert "
        "trigger uses - and compared against the stored value. Rows marked "
        "'verified' reproduced their stored hash exactly."
    ),
    VERIFICATION_NOT_REQUESTED: (
        "VERIFICATION WAS NOT PERFORMED. This export was requested with "
        "verify=false. No stored hash was recomputed and no row in this file is "
        "cryptographically verified. Rows marked 'not_verified' carry a stored "
        "record_hash that was NOT checked; the hash is reproduced here as "
        "stored, and tampering would not have been detected."
    ),
    VERIFICATION_UNAVAILABLE: (
        "VERIFICATION COULD NOT BE PERFORMED. Verification was requested, but "
        "the tamper-evidence chain functions are not installed in this "
        "database, so no stored hash could be recomputed. No row in this file "
        "is cryptographically verified."
    ),
}

# ─── CSV shape ───────────────────────────────────────────────────────────────
#
# `integrity` comes first deliberately: it is the column that qualifies every
# other one, and a reader who sorts or filters on nothing else will still see
# it. The fields after `user_id` are exactly the canonical payload the chain
# hashes, so a row exported here carries everything needed to reason about its
# own hash, plus the two link columns.

CSV_COLUMNS: tuple[str, ...] = (
    "integrity",
    "id",
    "created_at",
    "org_id",
    "user_id",
    "actor_user_id",
    "actor_username",
    "action",
    "resource_type",
    "resource_id",
    "status",
    "severity",
    "ip_address",
    "user_agent",
    "request_id",
    "changes",
    "prev_hash",
    "record_hash",
)

#: Leading characters a spreadsheet treats as the start of a formula. A
#: User-Agent is attacker-chosen and lands in a cell, so an export opened in
#: Excel is a code-execution path unless these are neutralised.
_FORMULA_LEADERS = ("=", "+", "-", "@", "\t", "\r")

_INJECTION_NOTE = (
    "Cells beginning with = + - @ TAB or CR are prefixed with one apostrophe "
    "(') so a spreadsheet cannot execute them as formulas. Strip a single "
    "leading apostrophe from such a cell to recover the stored value."
)


def _iso(value: Any) -> str:
    """Render a timestamp as unambiguous UTC, or pass a non-timestamp through."""
    if value is None:
        return ""
    if isinstance(value, datetime):
        moment = (
            value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value
        ).astimezone(timezone.utc)
        return moment.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    return str(value)


def _cell(value: Any) -> str:
    """One CSV cell: JSON for structures, neutralised against formula injection."""
    if value is None:
        return ""
    if isinstance(value, datetime):
        text = _iso(value)
    elif isinstance(value, (dict, list, tuple)):
        text = json.dumps(value, separators=(",", ":"), sort_keys=True, default=str)
    else:
        text = str(value)

    if text.startswith(_FORMULA_LEADERS):
        return "'" + text
    return text


def _filters_summary(filters: dict[str, Any] | None) -> str:
    """The active filter set, rendered for a human, or an explicit 'none'."""
    active = {k: v for k, v in (filters or {}).items() if v not in (None, "", [])}
    if not active:
        return "none (whole visible trail)"
    return ", ".join(
        f"{key}={_iso(value) if isinstance(value, datetime) else value}"
        for key, value in sorted(active.items())
    )


def preamble_lines(meta: dict[str, Any]) -> list[str]:
    """
    The header block, shared by both formats.

    Returned as plain sentences with no comment marker; the CSV writer prefixes
    each with `#` and the PDF renders them as paragraphs, so the two formats
    cannot disagree about what the export claims.
    """
    mode = meta.get("verification_mode", VERIFICATION_UNAVAILABLE)
    failures = int(meta.get("integrity_failure_count") or 0)
    legacy = int(meta.get("legacy_unverifiable_count") or 0)

    lines = [
        "CCure Audit PRO - audit trail export",
        f"Generated at        : {_iso(meta.get('generated_at'))}",
        (
            f"Exported by         : {meta.get('exported_by') or 'unknown'}"
            f" ({meta.get('exported_by_user_id') or 'unknown id'})"
        ),
        f"Tenant scope        : {meta.get('organization_scope')}",
        f"Events in this file : {meta.get('row_count')}",
        (
            f"Snapshot up to      : {_iso(meta.get('snapshot_upper_bound'))}"
            "  (no event written after this instant is included)"
        ),
        f"Filters applied     : {_filters_summary(meta.get('filters'))}",
        f"Request id          : {meta.get('request_id') or 'not recorded'}",
        "",
        "INTEGRITY",
        f"Verification mode   : {mode}",
        f"  verified            : {meta.get('verified_count') or 0}",
        f"  not_verified        : {meta.get('not_verified_count') or 0}",
        f"  legacy_unverifiable : {legacy}",
        f"  INTEGRITY_FAILURE   : {failures}",
        "",
        VERIFICATION_NOTES.get(mode, VERIFICATION_NOTES[VERIFICATION_UNAVAILABLE]),
    ]

    if legacy:
        lines.append(
            f"{legacy} event(s) in this file predate the tamper-evidence chain, "
            "carry no hash, and cannot be cryptographically verified by any "
            "means. They are marked 'legacy_unverifiable' and are NOT covered "
            "by any integrity guarantee."
        )
    if failures:
        lines.append(
            f"WARNING: {failures} event(s) carry a stored hash that did NOT "
            "reproduce when recomputed. Those rows are marked "
            "'INTEGRITY_FAILURE'. This trail has been modified outside the "
            "application and must be investigated before it is relied upon."
        )
    if meta.get("chain_schema"):
        lines.append(f"Chain machinery     : {meta['chain_schema']}")
    else:
        lines.append("Chain machinery     : not installed in this database")
    return lines


def iter_csv(meta: dict[str, Any], rows: Iterable[dict[str, Any]]) -> Iterator[str]:
    """
    Yield the export one chunk at a time.

    A generator rather than a string: `rows` is a keyset-paginated cursor over
    up to the row cap, and materialising it to build one payload would make the
    endpoint's memory a function of the export size.
    """
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")

    def drain() -> str:
        text = buffer.getvalue()
        buffer.seek(0)
        buffer.truncate(0)
        return text

    for line in preamble_lines(meta):
        buffer.write(f"# {line}\n" if line else "#\n")
    buffer.write(f"# {_INJECTION_NOTE}\n")
    buffer.write("#\n")
    yield drain()

    writer.writerow(CSV_COLUMNS)
    yield drain()

    for row in rows:
        writer.writerow([_cell(row.get(column)) for column in CSV_COLUMNS])
        yield drain()


# ─── PDF ─────────────────────────────────────────────────────────────────────
#
# Deliberately a *summary* document. A 5,000-row table carrying full hashes is
# not something anybody reads, and printing a truncated hash beside the word
# "verified" would invite exactly the misreading this module exists to prevent
# — so the PDF names the CSV as the artefact that carries the hashes, and its
# own cap is independent and much lower.

PDF_COLUMNS: tuple[tuple[str, str, float], ...] = (
    ("integrity", "Integrity", 78),
    ("created_at", "When (UTC)", 104),
    ("actor", "Actor", 96),
    ("action", "Action", 118),
    ("resource", "Resource", 118),
    ("status", "Status", 50),
    ("severity", "Severity", 50),
    ("ip_address", "Source IP", 76),
    ("id", "Event id", 96),
)


def _pdf_row(row: dict[str, Any]) -> dict[str, str]:
    actor = row.get("actor_username") or row.get("actor_user_id") or ""
    resource = " / ".join(
        part for part in (row.get("resource_type"), row.get("resource_id")) if part
    )
    return {
        "integrity": row.get("integrity") or "",
        "created_at": _iso(row.get("created_at")),
        "actor": str(actor),
        "action": str(row.get("action") or ""),
        "resource": resource,
        "status": str(row.get("status") or ""),
        "severity": str(row.get("severity") or ""),
        "ip_address": str(row.get("ip_address") or ""),
        "id": str(row.get("id") or ""),
    }


def render_pdf(meta: dict[str, Any], rows: Sequence[dict[str, Any]]) -> bytes:
    """Render the summary document. Returns the whole file; the caller caps size."""
    from reporting.report_helpers import (
        clean_control_chars,
        escape_for_reportlab,
        register_report_fonts,
    )
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        LongTable,
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        TableStyle,
    )

    fonts = register_report_fonts()
    base = getSampleStyleSheet()
    body = ParagraphStyle(
        "AuditBody",
        parent=base["Normal"],
        fontName=fonts["regular"],
        fontSize=8.5,
        leading=11.5,
    )
    title = ParagraphStyle(
        "AuditTitle",
        parent=base["Title"],
        fontName=fonts["bold"],
        fontSize=17,
        leading=21,
        alignment=0,
    )
    warn = ParagraphStyle(
        "AuditWarn",
        parent=body,
        fontName=fonts["bold"],
        textColor=colors.HexColor("#B00020"),
    )
    cell = ParagraphStyle(
        "AuditCell",
        parent=base["Normal"],
        fontName=fonts["regular"],
        fontSize=6.6,
        leading=8.2,
    )

    def safe(text: Any) -> str:
        return escape_for_reportlab(clean_control_chars(str(text or "")))

    buffer = io.BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=landscape(A4),
        leftMargin=12 * mm,
        rightMargin=12 * mm,
        topMargin=12 * mm,
        bottomMargin=12 * mm,
        title="CCure Audit PRO - audit trail export",
        author="CCure Audit PRO",
    )

    story: list[Any] = [Paragraph("Audit trail export", title), Spacer(1, 5 * mm)]
    for line in preamble_lines(meta):
        if not line:
            story.append(Spacer(1, 2.5 * mm))
            continue
        loud = line.startswith(
            ("WARNING", "VERIFICATION WAS NOT", "VERIFICATION COULD NOT")
        )
        story.append(Paragraph(safe(line), warn if loud else body))
    story.append(Spacer(1, 4 * mm))
    story.append(
        Paragraph(
            safe(
                "This PDF is a human-readable summary. The CSV export of the "
                "same query carries every hashed field plus prev_hash and "
                "record_hash, and is the artefact to use for independent "
                "verification."
            ),
            body,
        )
    )
    story.append(PageBreak())

    header = [Paragraph(f"<b>{safe(label)}</b>", cell) for _, label, _ in PDF_COLUMNS]
    data = [header]
    for row in rows:
        rendered = _pdf_row(row)
        data.append([Paragraph(safe(rendered[key]), cell) for key, _, _ in PDF_COLUMNS])

    table = LongTable(
        data,
        colWidths=[width for _, _, width in PDF_COLUMNS],
        repeatRows=1,
    )
    style = [
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#C9CED6")),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F2937")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 3),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        (
            "ROWBACKGROUNDS",
            (0, 1),
            (-1, -1),
            [colors.white, colors.HexColor("#F4F6F8")],
        ),
    ]
    # A failed row is tinted as well as labelled: the label is what the file
    # says, the tint is what stops a reader scrolling past it.
    for index, row in enumerate(rows, start=1):
        if row.get("integrity") == INTEGRITY_FAILURE:
            style.append(
                ("BACKGROUND", (0, index), (-1, index), colors.HexColor("#FDE2E4"))
            )
            style.append(
                ("TEXTCOLOR", (0, index), (0, index), colors.HexColor("#B00020"))
            )
    table.setStyle(TableStyle(style))
    story.append(table)

    document.build(story)
    return buffer.getvalue()


def export_filename(
    fmt: str, *, failed: bool, generated_at: datetime | None = None
) -> str:
    """
    Name the file so a failed export cannot be mistaken for a clean one even
    after it has been renamed, mailed on, or filed by name alone.
    """
    moment = generated_at or datetime.now(timezone.utc)
    stamp = moment.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    marker = "INTEGRITY-FAILURE-" if failed else ""
    extension = "pdf" if fmt == "pdf" else "csv"
    return f"ccure-audit-log-{marker}{stamp}.{extension}"
