"""
Regression tests for the SQLMap wrapper output parser.

The parser previously looked for ``Type:`` and ``Payload:`` on the same line,
but sqlmap prints them on separate lines, so a confirmed injection was recorded
with no evidence of the payload that proved it.
"""

from core.web.sqlmap.wrapper import SqlmapWrapper

_REAL_OUTPUT = """
[INFO] testing if GET parameter 'q' is dynamic
GET parameter 'q' is vulnerable. Do you want to keep testing the others? [y/N] N
sqlmap identified the following injection point(s) with a total of 42 requests:
---
Parameter: q (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: q=test' AND 5858=5858 AND 'abcd'='abcd
---
back-end DBMS: SQLite
"""

_CLEAN_OUTPUT = """
[INFO] testing if GET parameter 'q' is dynamic
[WARNING] GET parameter 'q' does not seem to be injectable
[ERROR] all tested parameters do not appear to be injectable.
"""


def test_confirmed_injection_is_detected():
    vulnerable, points, dbms = SqlmapWrapper._parse_output(_REAL_OUTPUT)
    assert vulnerable is True
    assert dbms == "SQLite"


def test_payload_evidence_is_captured():
    _, points, _ = SqlmapWrapper._parse_output(_REAL_OUTPUT)
    joined = "\n".join(points)
    assert "boolean-based blind" in joined
    assert "Payload: q=test'" in joined
    # Type, Title and Payload each captured.
    assert len(points) == 3


def test_clean_output_is_not_flagged():
    vulnerable, points, dbms = SqlmapWrapper._parse_output(_CLEAN_OUTPUT)
    assert vulnerable is False
    assert points == []
    assert dbms == ""


def test_empty_output_is_safe():
    assert SqlmapWrapper._parse_output("") == (False, [], "")
