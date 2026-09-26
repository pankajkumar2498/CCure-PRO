"""
CCure Audit boundary layers — Phase 5 step 5.1 (skeleton).

Guards the structure every later Phase 5 step builds on:

* the package layout exists and imports cleanly;
* views are frozen, slotted, keyword-only, and ``impurities`` rejects anything
  that is not a plain value — above all an ORM object;
* the three Phase 5 layer rules are registered;
* nothing in production imports the integration adapter yet.

Design: docs/architecture/PHASE5_AUDIT_INTEGRATION_BOUNDARIES.md.
"""

from __future__ import annotations

import dataclasses
import importlib
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from typing import Optional

import pytest

from ccure_audit.services.views import impurities, is_view, view
from scripts.architecture.import_graph import collect_edges
from scripts.architecture.layer_rules import RULES

# ── Layout ────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "module",
    [
        "ccure_audit",
        "ccure_audit.services",
        "ccure_audit.services.views",
        "ccure_audit.integration",
        "ccure_audit.integration.mappers",
    ],
)
def test_the_boundary_packages_exist(module):
    importlib.import_module(module)


def test_the_phase5_layer_rules_are_registered():
    names = {rule.name for rule in RULES}
    assert {
        "integration-is-an-adapter",
        "services-do-not-speak-contracts",
        "foundations-do-not-import-audit-module",
    } <= names


def test_nothing_in_production_imports_the_integration_adapter_yet():
    """
    The adapter is exercised by tests only until the integration phase (plan
    Phase 7) wires it to routes behind service identity. Delete this test in
    that phase, not before.
    """
    _, edges = collect_edges()
    users = sorted(
        {
            e.src
            for e in edges
            if (
                e.dst == "ccure_audit.integration"
                or e.dst.startswith("ccure_audit.integration.")
            )
            and not e.src.startswith("ccure_audit.integration")
        }
    )
    assert not users, f"production modules importing the adapter: {users}"


# ── Views ─────────────────────────────────────────────────────────────────────


@view
class _Inner:
    name: str
    seen_at: datetime


@view
class _Outer:
    title: str
    count: int
    score: Optional[float]
    ratio: Decimal
    due: date
    tags: frozenset
    inners: tuple


def _outer(**changes):
    base = dict(
        title="t",
        count=1,
        score=None,
        ratio=Decimal("0.5"),
        due=date(2026, 9, 26),
        tags=frozenset({"a"}),
        inners=(_Inner(name="x", seen_at=datetime(2026, 9, 26, tzinfo=timezone.utc)),),
    )
    base.update(changes)
    return _Outer(**base)


def test_a_view_is_frozen_slotted_and_keyword_only():
    value = _outer()
    assert is_view(value)
    with pytest.raises(dataclasses.FrozenInstanceError):
        value.title = "changed"
    assert not hasattr(value, "__dict__"), "slots=True: no per-instance dict"
    with pytest.raises(TypeError):
        _Inner("x", datetime.now(timezone.utc))  # positional arguments refused


def test_a_plain_view_has_no_impurities():
    assert impurities(_outer()) == []


@pytest.mark.parametrize(
    "changes, expected",
    [
        ({"tags": {"a"}}, "$.tags: builtins.set"),
        ({"inners": [1]}, "$.inners: builtins.list"),
        ({"title": {"k": "v"}}, "$.title: builtins.dict"),
        (
            {"inners": (_Inner(name="x", seen_at=datetime(2026, 9, 26)),)},
            "$.inners[0].seen_at: naive datetime",
        ),
        ({"score": object()}, "$.score: builtins.object"),
    ],
)
def test_impurities_names_what_breaks_the_rules(changes, expected):
    found = impurities(_outer(**changes))
    assert any(p.startswith(expected) for p in found), found


def test_an_offset_datetime_is_accepted():
    aware = datetime(
        2026, 9, 26, 10, 0, tzinfo=timezone(timedelta(hours=5, minutes=30))
    )
    assert impurities(_Inner(name="x", seen_at=aware)) == []


def test_an_orm_object_is_never_a_view_value():
    """The whole point of views: a SQLAlchemy row must not cross the boundary."""
    from db.models import Scan

    row = Scan(id="scn_x", org_id="org_x")
    found = impurities(_outer(inners=(row,)))
    assert found and "db.models" in found[0], found


def test_a_mutable_dataclass_is_not_a_view():
    @dataclasses.dataclass
    class Mutable:
        name: str

    assert not is_view(Mutable(name="x"))
    assert impurities(Mutable(name="x"))
