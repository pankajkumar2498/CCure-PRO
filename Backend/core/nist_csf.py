"""
Module: core.nist_csf
Purpose: NIST CSF 2.0 structure the *running application* needs — the Function
         and Category order, their display names, and a sort key that puts a
         Subcategory where NIST puts it.

The catalogue itself lives in `scripts/nist_csf_v2_core.py`, which is the seed
generator's input. This module re-exports the two ordering tables so the API,
the report generators and the dashboard share one definition of the order
rather than each restating it — and so nothing under `routers/` has to import
from `scripts/`.

Why an explicit order at all
────────────────────────────
`ORDER BY theme, control_number` sorts CSF alphabetically, and CSF is not
alphabetical. That produced a NIST CSF audit ledger whose first section was
Detect and whose Govern section ran OC, OV, PO, RM, RR, SC — an ordering an
auditor reads as a different framework. The Functions are GV, ID, PR, DE, RS,
RC, and the Categories within each are published in an order that carries
meaning.
"""

from __future__ import annotations

import re

from scripts.nist_csf_v2_core import (
    CATEGORY_ORDER,
    FUNCTION_NAMES,
    FUNCTION_ORDER,
)

FRAMEWORK_ID = "cfw_nist_csf_v2"
FRAMEWORK_CODE = "NIST_CSF_V2"

__all__ = [
    "CATEGORY_ORDER",
    "FRAMEWORK_CODE",
    "FRAMEWORK_ID",
    "FUNCTION_NAMES",
    "FUNCTION_ORDER",
    "category_name_for",
    "function_name_for",
    "is_csf_subcategory",
    "sort_key",
]

_CATEGORY_INDEX = {code: i for i, code in enumerate(CATEGORY_ORDER)}
_FUNCTION_INDEX = {code: i for i, code in enumerate(FUNCTION_ORDER)}

# `GV.OC-01`, and tolerant of a single-digit tail so an externally supplied
# `PR.AA-1` still lands in the right place.
_SUBCATEGORY = re.compile(
    r"^(?P<fn>GV|ID|PR|DE|RS|RC)\.(?P<cat>[A-Z]{2})-(?P<num>\d{1,2})$"
)


def is_csf_subcategory(control_number: str | None) -> bool:
    """True for a CSF 2.0 Subcategory identifier such as `PR.AA-05`."""
    return bool(control_number and _SUBCATEGORY.match(str(control_number).strip()))


def sort_key(control_number: str | None) -> tuple | None:
    """Function, Category, Subcategory number — in NIST's published order.

    Returns None when the argument is not a CSF Subcategory, so callers can
    fall back to the generic control sort without a second pattern match.

    The tuple elements are `(int, int, str)` triples so this composes with
    `routers.compliance.control_sort_key`, which builds keys of that shape for
    every other framework.
    """
    if control_number is None:
        return None
    match = _SUBCATEGORY.match(str(control_number).strip())
    if not match:
        return None

    function = match.group("fn")
    category = f"{function}.{match.group('cat')}"
    return (
        (0, _FUNCTION_INDEX.get(function, len(_FUNCTION_INDEX)), ""),
        (0, _CATEGORY_INDEX.get(category, len(_CATEGORY_INDEX)), ""),
        (0, int(match.group("num")), ""),
    )


def function_name_for(control_number_or_code: str | None) -> str | None:
    """`"PR.AA-05"` or `"PR"` -> `"Protect"`."""
    if not control_number_or_code:
        return None
    code = str(control_number_or_code).strip()[:2].upper()
    return FUNCTION_NAMES.get(code)


def category_name_for(control_number: str | None) -> str | None:
    """`"PR.AA-05"` -> `"Identity Management, Authentication, and Access Control"`."""
    if not is_csf_subcategory(control_number):
        return None
    category = str(control_number).strip().partition("-")[0]
    entry = CATEGORY_ORDER.get(category)
    return entry[1] if entry else None
