"""
Views — the typed values Audit's application services return.

A view is a frozen, slotted, keyword-only dataclass whose fields hold only
plain values: ``str``, ``int``, ``float``, ``bool``, ``None``, ``Decimal``,
timezone-aware ``datetime``, ``date``, other views, and tuples or frozensets of
those. Declare one with :func:`view`.

Why so strict:

* **No ORM object.** A row carries its session; reading an attribute after the
  session closes raises or silently issues a query, and a row exposes every
  column, including ones no consumer should see.
* **No list or dict.** Both are mutable, so a view could be changed after a
  service returned it — and a consumer could see a different answer from the
  one the service computed. Use a tuple, a frozenset, or a nested view.
* **No naive datetime.** It renders as local time beside UTC siblings.

:func:`impurities` checks a value against these rules. The service tests run
it over everything a service returns, so a leak fails a test rather than
reaching a contract.
"""

from __future__ import annotations

import dataclasses
from datetime import date, datetime
from decimal import Decimal
from typing import Any, List, TypeVar

T = TypeVar("T")

#: Leaf types a view may hold directly.
_PLAIN = (str, int, float, bool, Decimal, date, type(None))


def view(cls: type[T]) -> type[T]:
    """Declare a view: ``@dataclass(frozen=True, slots=True, kw_only=True)``."""
    return dataclasses.dataclass(frozen=True, slots=True, kw_only=True)(cls)


def is_view(value: Any) -> bool:
    """Whether *value* is an instance of a class declared with :func:`view`."""
    if not dataclasses.is_dataclass(value) or isinstance(value, type):
        return False
    params = getattr(type(value), "__dataclass_params__", None)
    return bool(params and params.frozen) and hasattr(type(value), "__slots__")


def impurities(value: Any, path: str = "$") -> List[str]:
    """
    Every place in *value* that breaks the view rules, as ``path: reason``.

    An empty list means the value is safe to hand across the service boundary.
    """
    problems: List[str] = []

    if isinstance(value, datetime):
        if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
            problems.append(f"{path}: naive datetime")
        return problems
    if isinstance(value, _PLAIN):
        return problems
    if isinstance(value, (tuple, frozenset)):
        for index, item in enumerate(value):
            problems.extend(impurities(item, f"{path}[{index}]"))
        return problems
    if is_view(value):
        for f in dataclasses.fields(value):
            problems.extend(impurities(getattr(value, f.name), f"{path}.{f.name}"))
        return problems

    kind = type(value)
    problems.append(
        f"{path}: {kind.__module__}.{kind.__qualname__} is not a view value"
    )
    return problems
