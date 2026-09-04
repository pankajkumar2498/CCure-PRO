"""
tests/reports/test_export_workbook.py
─────────────────────────────────────────────────────────────────────────────
The XLSX writer (GAP-15, exp.fmt.xlsx / exp.xl.formula_injection / exp.xl.large).

Every test here opens the file it wrote and reads the cells back. Asserting
that ``write_workbook`` returned a path proves the function ran; it proves
nothing about whether Excel can open the result, whether a formula survived
into a cell, or whether a 40,000-character evidence string silently corrupted
the archive. Those are the failures this module exists to prevent, and they are
only visible from the other side of the file.
"""

from __future__ import annotations

import os

import pytest

openpyxl = pytest.importorskip(
    "openpyxl",
    reason=(
        "openpyxl is declared in Backend/requirements.txt and must be installed "
        "in both the API environment and the scanner worker's venv"
    ),
)

from reporting.xlsx_generator import (  # noqa: E402
    MAX_CELL_LENGTH,
    WRITE_ONLY,
    XlsxUnavailable,
    sanitize_cell,
    sheet_name,
    write_workbook,
)


def _load(path):
    return openpyxl.load_workbook(path)


# ─────────────────────────────────────────────────────────────────────────────
# exp.xl.formula_injection
# ─────────────────────────────────────────────────────────────────────────────


class TestFormulaInjection:
    """
    A cell must never be executed by the program that opens it.

    The text reaching these cells is a host's own configuration file, a check
    title out of loaded benchmark content and a remediation note somebody
    typed — all of it attacker-influenced in the sense that matters, because
    the scanner reads it off a machine it is auditing.
    """

    @pytest.mark.parametrize(
        "payload",
        [
            "=cmd|'/c calc'!A1",
            "+1+1",
            "-2+3",
            "@SUM(A1:A9)",
            '\t=HYPERLINK("http://evil","click")',
            "\r=1+1",
        ],
    )
    def test_a_formula_leader_is_neutralised(self, tmp_path, payload):
        # exp.xl.formula_injection
        path = str(tmp_path / "inject.xlsx")
        write_workbook([("S", ["Title"], [[payload]])], path)

        value = _load(path)["S"].cell(row=2, column=1).value
        assert value.startswith("'"), (
            "a value beginning with a formula leader must be marked as text; "
            f"got {value!r}"
        )
        assert value[1:] == payload

    def test_ordinary_text_is_not_prefixed(self, tmp_path):
        # exp.xl.formula_injection
        path = str(tmp_path / "plain.xlsx")
        write_workbook([("S", ["Title"], [["SSH root login is permitted"]])], path)
        assert (
            _load(path)["S"].cell(row=2, column=1).value
            == "SSH root login is permitted"
        )

    def test_numbers_and_booleans_stay_typed(self, tmp_path):
        """
        A severity count that arrived as text cannot be sorted or summed, so
        the neutralisation must not reach non-text values.
        """
        # exp.xl.formula_injection
        path = str(tmp_path / "typed.xlsx")
        write_workbook([("S", ["N", "B", "F"], [[7, True, 3.5]])], path)
        sheet = _load(path)["S"]
        assert sheet.cell(row=2, column=1).value == 7
        assert sheet.cell(row=2, column=2).value is True
        assert sheet.cell(row=2, column=3).value == 3.5

    def test_sanitize_cell_is_the_single_decision_point(self):
        # exp.xl.formula_injection
        assert sanitize_cell("=1+1") == "'=1+1"
        assert sanitize_cell(None) is None
        assert sanitize_cell(12) == 12
        assert sanitize_cell(False) is False


# ─────────────────────────────────────────────────────────────────────────────
# Characters and lengths the format itself constrains
# ─────────────────────────────────────────────────────────────────────────────


class TestCellSafety:
    def test_a_control_character_does_not_fail_the_export(self, tmp_path):
        """
        Scanner output carries NUL and other C0 bytes from SNMP banners and
        service scripts — the same class the JSONB persistence boundary strips.
        openpyxl raises IllegalCharacterError on them, so one such byte in one
        evidence string would otherwise lose the entire workbook.
        """
        # exp.fmt.xlsx
        path = str(tmp_path / "control.xlsx")
        write_workbook([("S", ["Evidence"], [["banner\x00\x01text\nline2"]])], path)

        value = _load(path)["S"].cell(row=2, column=1).value
        assert "\x00" not in value and "\x01" not in value
        # Newlines are legal in a cell and carry meaning in evidence.
        assert "\n" in value

    def test_an_over_long_value_is_truncated_visibly(self, tmp_path):
        """
        Excel refuses a cell over 32,767 characters outright, so the file would
        open as corrupt rather than as shortened. Truncation is therefore
        necessary — and it is marked, because a silently shortened evidence
        string makes the export disagree with the finding record while looking
        complete.
        """
        # exp.fmt.xlsx
        path = str(tmp_path / "long.xlsx")
        original = "A" * 90000
        write_workbook([("S", ["Evidence"], [[original]])], path)

        value = _load(path)["S"].cell(row=2, column=1).value
        assert len(value) <= MAX_CELL_LENGTH
        assert "truncated" in value
        assert "90000" not in value or "more characters" in value
        assert value.startswith("A" * 100)

    def test_a_value_at_the_limit_is_untouched(self, tmp_path):
        # exp.fmt.xlsx
        exact = "B" * MAX_CELL_LENGTH
        assert sanitize_cell(exact) == exact


class TestSheetNames:
    @pytest.mark.parametrize("bad", ["A/B", "A:B", "A[B]", "A*B", "A?B", "A\\B"])
    def test_forbidden_characters_are_removed(self, bad):
        # exp.fmt.xlsx
        assert not set(sheet_name(bad)) & set("[]:*?/\\")

    def test_the_name_is_capped_at_the_excel_limit(self):
        # exp.fmt.xlsx
        assert len(sheet_name("x" * 80)) <= 31

    def test_uniqueness_is_case_insensitive(self):
        """
        Excel refuses two sheets whose names differ only by case, so a
        case-sensitive uniqueness check writes a workbook that will not open.
        """
        # exp.fmt.xlsx
        assert sheet_name("Findings", ["findings"]).lower() != "findings"


# ─────────────────────────────────────────────────────────────────────────────
# Usability for the auditor the export is for
# ─────────────────────────────────────────────────────────────────────────────


class TestWorkbookShape:
    def test_header_is_bold_frozen_and_filterable(self, tmp_path):
        # exp.fmt.xlsx
        path = str(tmp_path / "shape.xlsx")
        write_workbook(
            [("Compliance Verdicts", ["Check ID", "Verdict"], [["a", "PASS"]] * 3)],
            path,
        )
        sheet = _load(path)["Compliance Verdicts"]

        assert sheet.cell(row=1, column=1).font.bold is True
        assert sheet.freeze_panes == "A2"
        assert sheet.auto_filter.ref == "A1:B4", (
            "the filter must cover the header and every written row; a range "
            "computed before the rows were appended covers nothing"
        )

    def test_column_order_is_the_header_order(self, tmp_path):
        # exp.fmt.xlsx
        path = str(tmp_path / "order.xlsx")
        header = ["One", "Two", "Three", "Four"]
        write_workbook([("S", header, [["1", "2", "3", "4"]])], path)
        sheet = _load(path)["S"]
        assert [c.value for c in sheet[1]] == header
        assert [c.value for c in sheet[2]] == ["1", "2", "3", "4"]

    def test_an_empty_dataset_still_writes_its_header(self, tmp_path):
        """
        An absent sheet and an empty one say different things — "not requested"
        and "requested, matched nothing". Collapsing them would let a filter
        that matched nothing read as a dataset nobody asked for.
        """
        # exp.fmt.xlsx
        path = str(tmp_path / "empty.xlsx")
        write_workbook([("Scan Comparison", ["Change", "Identifier"], [])], path)
        sheet = _load(path)["Scan Comparison"]
        assert sheet.max_row == 1
        assert sheet.cell(row=1, column=1).value == "Change"

    def test_sheets_keep_the_order_they_were_given(self, tmp_path):
        # exp.fmt.xlsx
        path = str(tmp_path / "sheets.xlsx")
        write_workbook(
            [
                ("Summary", ["Field", "Value"], [["Scan ID", "scn_1"]]),
                ("Compliance Verdicts", ["Verdict"], []),
                ("Findings", ["Identifier"], []),
            ],
            path,
        )
        assert _load(path).sheetnames == [
            "Summary",
            "Compliance Verdicts",
            "Findings",
        ]


# ─────────────────────────────────────────────────────────────────────────────
# exp.xl.large
# ─────────────────────────────────────────────────────────────────────────────


class TestLargeExports:
    def test_rows_are_consumed_from_a_generator_exactly_once(self, tmp_path):
        """
        The streaming guarantee, asserted where it is observable.

        If the writer materialised its rows — sorting them, measuring column
        widths from the data, counting them before writing — a generator would
        be exhausted on the first pass and the sheet would come out empty or
        the second pass would raise. Consuming it once is what keeps a large
        export bounded, so it is pinned rather than assumed.
        """
        # exp.xl.large
        assert WRITE_ONLY is True

        produced = {"n": 0}

        def rows():
            for index in range(5000):
                produced["n"] += 1
                yield [f"ccure.check.{index}", "PASS", "low"]

        path = str(tmp_path / "big.xlsx")
        write_workbook(
            [("Compliance Verdicts", ["Check ID", "Verdict", "Severity"], rows())], path
        )

        assert produced["n"] == 5000, "the row source was iterated more than once"

        sheet = _load(
            path,
        )["Compliance Verdicts"]
        assert sheet.max_row == 5001
        assert sheet.cell(row=5001, column=1).value == "ccure.check.4999"

    def test_a_realistic_benchmark_export_completes(self, tmp_path):
        """
        955 benchmark rules across three hosts, with evidence on every row.
        Not a performance assertion — a correctness one: the last row is
        present, so nothing was dropped on the way through.
        """
        # exp.xl.large
        rows = [
            [
                f"ccure.bench.{host}.{index}",
                "FAIL" if index % 7 else "PASS",
                "x" * 400,
            ]
            for host in range(3)
            for index in range(955)
        ]
        path = str(tmp_path / "bench.xlsx")
        write_workbook(
            [("Compliance Verdicts", ["Check ID", "Verdict", "Evidence"], rows)], path
        )

        sheet = _load(path)["Compliance Verdicts"]
        assert sheet.max_row == len(rows) + 1
        assert sheet.cell(row=sheet.max_row, column=1).value == "ccure.bench.2.954"
        assert os.path.getsize(path) > 0


def test_the_missing_dependency_has_its_own_exception():
    """
    An export must never degrade into some other format. XlsxUnavailable is a
    distinct type so the route can answer 503 naming the dependency, rather
    than a 500 or — the defect this phase was asked to remove — a PDF.
    """
    # exp.fmt.xlsx
    assert issubclass(XlsxUnavailable, RuntimeError)
