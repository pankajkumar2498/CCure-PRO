"""
Phase 23c — schema-based fuzz values + negative testing (Codex item 8).

An OpenAPI schema declares each parameter's type/enum/length/range. These prove
the scanner derives boundary/fuzz values from the schema and a value that
*violates* it for negative testing, and that the negative-test pass flags an
operation that accepts schema-violating input (weak validation).
"""

import pytest

from core.web.api_scan.fuzz import (
    is_required,
    schema_fuzz_values,
    violating_value,
)


# ── schema fuzz values ─────────────────────────────────────────────────────────
def test_enum_fuzz_values_are_the_declared_set():
    assert schema_fuzz_values({"enum": ["a", "b", "c"]}) == ["a", "b", "c"]


def test_integer_fuzz_values_include_boundaries():
    vals = schema_fuzz_values({"type": "integer", "minimum": 5, "maximum": 9})
    assert 5 in vals and 9 in vals and 0 in vals and -1 in vals


def test_string_format_and_length_fuzz():
    email = schema_fuzz_values({"type": "string", "format": "email"})
    assert any("@" in v for v in email)
    bounded = schema_fuzz_values({"type": "string", "maxLength": 3})
    assert any(len(v) > 3 for v in bounded)  # an over-length probe


# ── negative (schema-violating) values ─────────────────────────────────────────
def test_violating_value_for_enum_is_outside_the_enum():
    v = violating_value({"enum": ["x", "y"]})
    assert v not in ("x", "y")


def test_violating_value_for_numeric_is_non_numeric():
    assert violating_value({"type": "integer"}) == "notanumber"


def test_violating_value_none_when_unconstrained():
    assert violating_value({"type": "string"}) is None  # no length bound to violate
    assert violating_value(None) is None


def test_is_required_reads_object_required_list():
    assert is_required({"required": ["a", "b"]}, "a")
    assert not is_required({"required": ["a"]}, "z")
    assert not is_required({}, "a")


# ── negative-testing pass flags weak validation ─────────────────────────────────
@pytest.mark.asyncio
async def test_negative_findings_flags_accepted_violation():
    from core.web.api_scan.engine import ApiScanEngine

    class _Resp:
        def __init__(self, status):
            self.status_code = status

    class _Client:
        def __init__(self):
            self.calls = []

        async def get(self, url, **k):
            self.calls.append(url)
            return _Resp(200)  # the API wrongly accepts everything

    eng = ApiScanEngine()
    endpoints = [
        {
            "url": "http://api.test/items?status=open&page=1",
            "method": "GET",
            "source": "openapi",
            "query_schemas": {"status": {"enum": ["open", "closed"]}},
            "required_query": ["page"],
        }
    ]
    findings = await eng._negative_findings(_Client(), endpoints, {}, {})
    types = {f["finding_type"] for f in findings}
    assert types == {"api_weak_input_validation"}
    # both the enum violation and the required-omission were flagged
    assert len(findings) == 2
    assert all(f["cwe_id"] == "CWE-20" for f in findings)
