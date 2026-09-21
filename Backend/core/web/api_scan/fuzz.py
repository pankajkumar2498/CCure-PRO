"""
core/web/api_scan/fuzz.py
────────────────────────────────────────────────────────────────────────────
Schema-based fuzz values and negative-test inputs (Codex item 8).

An OpenAPI/JSON-schema declares each parameter's type, format, enum and range.
An API scanner that ignores this and sends ``1`` everywhere tests neither the
boundaries a value is validated against nor what the endpoint does with input it
should reject. Two things are derived here, both pure and value-free of any
target data:

  * ``schema_fuzz_values`` — type/format/boundary values worth *sending* as a
    valid-shaped probe (a long string, a boundary integer, a format-specific
    value), which injection and boundary checks consume.
  * ``violating_value`` / ``is_required`` — a single input that *violates* the
    schema (wrong type, out-of-enum, over-length), for negative testing: an
    endpoint that answers 2xx to a schema-violating request is not validating
    its input, which is a real finding.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

_LONG = "A" * 512


def _type_of(schema: Dict[str, Any]) -> str:
    t = schema.get("type")
    if isinstance(t, list):  # JSON-schema union — take the first concrete type
        t = next((x for x in t if x != "null"), None)
    if not t:
        if "enum" in schema:
            return "enum"
        if "properties" in schema:
            return "object"
    return t or "string"


def schema_fuzz_values(schema: Optional[Dict[str, Any]]) -> List[Any]:
    """Valid-shaped boundary/fuzz values to send for a parameter of this schema."""
    if not isinstance(schema, dict):
        return ["1", _LONG]
    if schema.get("enum"):
        # Every declared value is worth exercising.
        return list(schema["enum"])
    t = _type_of(schema)
    if t in ("integer", "number"):
        vals: List[Any] = [0, 1, -1]
        if "minimum" in schema:
            vals.append(schema["minimum"])
        if "maximum" in schema:
            vals.append(schema["maximum"])
        vals += [2**31, -(2**31), 999999999999]
        return vals
    if t == "boolean":
        return [True, False]
    if t == "string":
        fmt = schema.get("f" "ormat")
        specials = {
            "email": "a@b.co",
            "uri": "http://x",
            "url": "http://x",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "date": "2020-01-01",
            "date-time": "2020-01-01T00:00:00Z",
            "ipv4": "127.0.0.1",
        }
        base = [specials.get(fmt, "test")]
        max_len = schema.get("maxLength")
        base.append("A" * (int(max_len) + 1) if max_len else _LONG)
        return base
    if t == "array":
        return [[], [1]]
    return ["1", _LONG]


def is_required(op_schema: Dict[str, Any], name: str) -> bool:
    """Whether ``name`` is a required property of an object schema, or a required
    parameter object."""
    if not isinstance(op_schema, dict):
        return False
    req = op_schema.get("required")
    if isinstance(req, list):
        return name in req
    return bool(req) if isinstance(req, bool) else False


def violating_value(schema: Optional[Dict[str, Any]]) -> Optional[Any]:
    """
    A value that violates the schema, for negative testing — or None when the
    schema imposes no constraint worth violating (so no misleading probe is
    sent). Prefers an out-of-enum value, then a type violation, then an
    over-length / out-of-range value.
    """
    if not isinstance(schema, dict):
        return None
    if schema.get("enum"):
        existing = set(map(str, schema["enum"]))
        cand = "__ccure_not_in_enum__"
        return cand if cand not in existing else "__ccure_x__"
    t = _type_of(schema)
    if t in ("integer", "number"):
        # A non-numeric string violates a numeric type.
        return "notanumber"
    if t == "boolean":
        return "notabool"
    if t == "string":
        max_len = schema.get("maxLength")
        if max_len:
            return "A" * (int(max_len) + 10)
        return None  # a plain string with no length bound has nothing to violate
    if t == "integer":
        return "x"
    return None
