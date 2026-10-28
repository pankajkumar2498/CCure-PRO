"""
reporting/compliance/common.py
─────────────────────────────────────────────────────────────────────────────
What more than one compliance report renders the same way.

Moved unchanged from ``routers/compliance.py`` (G6, C8 of
docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md): a renderer takes the
controls and their rolled-up verdicts the router read, and returns the
document; it reads no table and imports no compliance code.
"""


def _verdict_of(findings_map: dict, control_id: str) -> str:
    """Reads a control's verdict from either a status map or a finding map.

    Twelve report endpoints built `{f.control_id: f for f in findings}` and let
    the last row of an unordered query decide the control. They now pass the
    rolled-up status map from `rolled_up_control_status`, but the accessor
    tolerates the old shape so a caller that has not been converted still
    renders rather than raising.
    """
    value = findings_map.get(control_id)
    if value is None:
        return "PENDING"
    if isinstance(value, str):
        return value.upper()
    return str(getattr(value, "status", "PENDING")).upper()
