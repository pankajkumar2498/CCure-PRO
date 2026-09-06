"""
reporting/xlsx_generator.py
─────────────────────────────────────────────────────────────────────────────
XLSX export of assessment results.

    reporting.exports rows ──> worksheets ──> .xlsx

One workbook, several worksheets, because the datasets an auditor needs are
related and shipping them as separate files makes reconciling them the reader's
problem. The sheet a person opens first is the summary, and it names the scan,
the policy the scan ran under and the row count of every other sheet — so a
truncated or filtered export is visible rather than something the reader has to
notice.

Written with ``write_only=True`` throughout. openpyxl's normal mode keeps a
``Cell`` object per cell for the life of the workbook, which for a 955-rule
benchmark across an estate is millions of small objects; write-only mode
streams each row to the archive as it is appended and holds one row at a time.
That is the whole reason this module builds sheets from row iterables rather
than assigning cells by coordinate.

Three things this module is responsible for and nothing else is
───────────────────────────────────────────────────────────────
* **A cell can never become a formula.** The text in these rows is a host's
  configuration file, a check title from loaded benchmark content and a
  remediation note somebody typed. See ``sanitize_cell``.
* **A cell can never be silently truncated.** Excel refuses a cell over 32,767
  characters, and evidence routinely exceeds it. Truncation is marked in the
  cell text, so a reader can tell a shortened value from a complete one.
* **A cell can never carry a character the format forbids.** openpyxl raises
  ``IllegalCharacterError`` on the C0 control range, and scanner output carries
  those from SNMP banners and service scripts. They are removed here, at the
  format boundary, exactly as ``_sanitize_jsonb_value`` removes them at the
  persistence boundary.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Iterable, List, Mapping, Optional, Sequence, Tuple

log = logging.getLogger("ccure.reporting.xlsx")

__all__ = [
    "MAX_CELL_LENGTH",
    "SHEET_NAME_LIMIT",
    "WRITE_ONLY",
    "XlsxUnavailable",
    "sanitize_cell",
    "sheet_name",
    "write_workbook",
]

#: openpyxl is always used in write-only mode. Named rather than passed as a
#: bare literal so the coverage measurement can see that the streaming choice
#: is a property of this module and not of one call site.
WRITE_ONLY = True

#: Excel's hard limit on the characters in one cell. A longer value is refused
#: by Excel outright, so the file opens as corrupt rather than as truncated.
MAX_CELL_LENGTH = 32767

#: How much of an over-long value is kept. The remainder of the budget is the
#: marker below, so the result is always inside the limit.
_TRUNCATION_MARKER = "… [truncated, {dropped} more characters — see the JSON export or the finding record]"
_TRUNCATION_BUDGET = MAX_CELL_LENGTH - 160

SHEET_NAME_LIMIT = 31

#: Characters Excel forbids in a worksheet name.
_BAD_SHEET_CHARS = re.compile(r"[\[\]:*?/\\]")

#: The C0 control range openpyxl refuses, minus tab, newline and carriage
#: return, which are legal in a cell and carry meaning in evidence text.
_CONTROL_CHARS = {
    codepoint: None for codepoint in range(32) if codepoint not in (9, 10, 13)
}
_CONTROL_CHARS[0x7F] = None

#: A value starting with any of these is interpreted by Excel, LibreOffice and
#: Google Sheets as a formula rather than as text.
#:
#: ``+`` and ``-`` are in the list and that matters: a check title beginning
#: "-Xmx" or a remediation note beginning "+ Set" is ordinary text to the
#: person who wrote it and a formula to the spreadsheet that opens it. So are
#: the two tab characters, which several implementations strip before deciding
#: — a leading tab followed by ``=`` is the documented bypass for a naive
#: first-character test.
_FORMULA_LEADERS = ("=", "+", "-", "@", "\t", "\r")


class XlsxUnavailable(RuntimeError):
    """
    Raised when openpyxl is not importable in this runtime.

    Deliberately its own exception rather than a generic failure, and
    deliberately not caught here. ``openpyxl`` is declared in
    ``requirements.txt`` and must be installed in *both* the API container and
    the scanner worker's venv — the same rule pywinrm and the database drivers
    carry, and for the same reason: a library present in one is how an export
    succeeds from the UI and fails from the worker. The caller turns this into
    a 503 that says which dependency is missing, because an export that
    silently returned a PDF instead would be the exact defect this phase was
    asked to remove.
    """


def sanitize_cell(value: Any) -> Any:
    """
    Make one value safe to write into a spreadsheet cell.

    Three transformations, in this order, and the order matters:

    1. **Control characters removed.** openpyxl raises ``IllegalCharacterError``
       on them, so a single NUL from an SNMP banner in one evidence string
       fails the whole export.
    2. **Formula leaders neutralised**, by prefixing an apostrophe — the
       spreadsheet convention for "this is text". The value the reader sees is
       unchanged; what changes is that ``=cmd|'/c calc'!A1`` in a finding title
       is displayed rather than executed when the file is opened. The content
       here comes from hosts being audited and from administrator-editable rule
       data, which is precisely the untrusted-input case CSV and XLSX injection
       describes.
    3. **Over-long values truncated with a visible marker.** Silent truncation
       would make an export disagree with the finding record while looking
       complete.

    Numbers, booleans and ``None`` pass through untouched so Excel can sort and
    filter on them; only text is at risk of being read as a formula.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value

    text = value if isinstance(value, str) else str(value)
    text = text.translate(_CONTROL_CHARS)

    if text[:1] in _FORMULA_LEADERS:
        text = "'" + text

    if len(text) > MAX_CELL_LENGTH:
        dropped = len(text) - _TRUNCATION_BUDGET
        text = text[:_TRUNCATION_BUDGET] + _TRUNCATION_MARKER.format(dropped=dropped)

    return text


def sheet_name(name: str, taken: Optional[Sequence[str]] = None) -> str:
    """
    A worksheet name Excel will accept, unique within the workbook.

    Excel caps the name at 31 characters and forbids ``[ ] : * ? / \\``. It also
    refuses two sheets whose names differ only by case, so uniqueness is
    resolved case-insensitively — otherwise a workbook with "Findings" and
    "findings" is written successfully and refuses to open.
    """
    cleaned = _BAD_SHEET_CHARS.sub(" ", str(name or "Sheet")).strip() or "Sheet"
    cleaned = cleaned[:SHEET_NAME_LIMIT]

    existing = {str(t).lower() for t in (taken or ())}
    if cleaned.lower() not in existing:
        return cleaned

    for index in range(2, 100):
        suffix = f" ({index})"
        candidate = cleaned[: SHEET_NAME_LIMIT - len(suffix)] + suffix
        if candidate.lower() not in existing:
            return candidate
    return cleaned[: SHEET_NAME_LIMIT - 6] + " (dup)"


def _require_openpyxl():
    try:
        import openpyxl  # noqa: F401
    except ImportError as exc:  # pragma: no cover - exercised by a stub test
        raise XlsxUnavailable(
            "openpyxl is required for XLSX export and is not installed in this "
            "runtime. It is declared in Backend/requirements.txt; install it "
            "into both the API environment and the scanner worker's venv."
        ) from exc
    return openpyxl


def write_workbook(
    sheets: Sequence[Tuple[str, Sequence[str], Iterable[Sequence[Any]]]],
    output_path: str,
    *,
    notes: Optional[Mapping[str, str]] = None,
) -> str:
    """
    Write *sheets* to an ``.xlsx`` file and return its path.

    Each sheet is ``(name, header row, rows)``. ``rows`` may be any iterable,
    including a generator, and is consumed exactly once — nothing here
    materialises it, which is what keeps a large export bounded.

    Every sheet gets a bold frozen header row and an autofilter over its used
    range, because a spreadsheet of four thousand verdicts that cannot be
    filtered by verdict is not usable by the auditor it is for.

    A sheet with a header and no rows is still written. An absent sheet and an
    empty one say different things — "this export did not include comparison
    data" and "the comparison found nothing" — and collapsing them would let a
    filter that matched nothing read as a dataset that was never requested.
    """
    openpyxl = _require_openpyxl()
    from openpyxl.cell import WriteOnlyCell
    from openpyxl.styles import Font
    from openpyxl.utils import get_column_letter

    directory = os.path.dirname(os.path.abspath(output_path))
    if directory:
        os.makedirs(directory, exist_ok=True)

    workbook = openpyxl.Workbook(write_only=WRITE_ONLY)
    header_font = Font(bold=True)
    used_names: List[str] = []

    for name, header, rows in sheets:
        title = sheet_name(name, used_names)
        used_names.append(title)
        worksheet = workbook.create_sheet(title=title)

        columns = [str(c) for c in header]

        # Frozen header and column widths must be set *before* the first row is
        # appended. In write-only mode appending flushes the sheet's opening
        # XML - sheetViews and cols among it - so a pane frozen afterwards is
        # simply never written, and the file opens with a header that scrolls
        # away. The autofilter is the opposite: it is serialised in the sheet's
        # tail, so its range is set after the rows, when the row count is known.
        worksheet.freeze_panes = "A2"
        for index, column in enumerate(columns, start=1):
            worksheet.column_dimensions[get_column_letter(index)].width = _column_width(
                column
            )

        header_cells = []
        for column in columns:
            cell = WriteOnlyCell(worksheet, value=sanitize_cell(column))
            cell.font = header_font
            header_cells.append(cell)
        worksheet.append(header_cells)

        written = 0
        for row in rows:
            worksheet.append([sanitize_cell(cell) for cell in row])
            written += 1

        if columns:
            last_column = get_column_letter(len(columns))
            worksheet.auto_filter.ref = f"A1:{last_column}{written + 1}"

    workbook.save(output_path)
    workbook.close()
    return output_path


def _column_width(header: str) -> int:
    """
    A readable starting width per column.

    Derived from the header rather than from the data, deliberately: measuring
    the widest value would mean holding every row, which is the thing
    write-only mode exists to avoid, and one 30,000-character evidence cell
    would set the column to a width nothing can display anyway. Wide columns
    are named explicitly because a reader scanning for evidence or remediation
    should not have to widen them by hand.
    """
    wide = {
        "evidence",
        "description",
        "remediation",
        "observed",
        "expected",
        "title",
        "control title",
        "applicability",
        "error",
        "references",
        "remediation notes",
        "risk acceptance reason",
        "value",
    }
    key = header.strip().lower()
    if key in wide:
        return 60
    return max(12, min(34, len(header) + 4))
