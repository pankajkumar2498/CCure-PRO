"""
Field declarations that carry ownership and availability into the schema.

Every field of every contract is declared through :func:`owned`, so the
generated JSON Schema states, per property:

* ``x-ccure-owner`` — the module whose value this is. Only the owner may
  create or change it; every other module treats it as read-only (SRS 7.6.1).
* ``x-ccure-availability`` — for values Audit produces, whether Audit can
  populate the field today. ``not_implemented`` means the contract reserves the
  field and Audit leaves it explicitly unavailable; it never means "zero".
* ``x-ccure-srs`` — the SRS clauses the field exists to satisfy, where one
  applies.

A test walks the generated schemas and fails on any property without an owner,
so a field cannot be added without saying whose it is.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field
from pydantic_core import PydanticUndefined

#: The modules a field can belong to. ``producer`` is used for envelope fields
#: whose owner is whichever module produced the message; ``platform`` for the
#: tenant key, which belongs to the shared platform rather than to any module.
Owner = Literal["policy_pro", "audit", "rank", "ir", "platform", "producer"]

#: ``available`` — Audit populates it today. ``partial`` — populated on some
#: assessment paths and explicitly absent on others. ``not_implemented`` — the
#: contract reserves it; Audit cannot produce it yet and says so.
Availability = Literal["available", "partial", "not_implemented"]

OWNERS: tuple[str, ...] = ("policy_pro", "audit", "rank", "ir", "platform", "producer")
AVAILABILITIES: tuple[str, ...] = ("available", "partial", "not_implemented")


def owned(
    owner: Owner,
    description: str,
    *,
    default: Any = PydanticUndefined,
    availability: Availability = "available",
    srs: tuple[str, ...] = (),
    **kwargs: Any,
) -> Any:
    """A Pydantic ``Field`` annotated with its owner, availability and SRS trace."""
    extra: dict[str, Any] = {
        "x-ccure-owner": owner,
        "x-ccure-availability": availability,
    }
    if srs:
        extra["x-ccure-srs"] = list(srs)
    return Field(default, description=description, json_schema_extra=extra, **kwargs)
