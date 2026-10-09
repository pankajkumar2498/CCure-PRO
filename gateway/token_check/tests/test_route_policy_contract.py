"""
The generated route policy (gateway/policy/route_policy.json, Phase 10.2c)
against this service: every policy it can send must be one the checker knows,
or nginx would forward a policy the checker answers with a fail-closed 500.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from token_check.checker import POLICIES

POLICY = Path(__file__).resolve().parents[2] / "policy" / "route_policy.json"


@pytest.fixture(scope="module")
def policy():
    if not POLICY.is_file():
        pytest.skip(f"{POLICY} is not mounted")
    return json.loads(POLICY.read_text())


def test_every_policy_the_generator_emits_is_one_the_checker_knows(policy):
    emitted = set(policy["class_to_checker_policy"].values())
    emitted |= {e["checker_policy"] for e in policy["routes"]}
    emitted |= {r["checker_policy"] for r in policy["rules"]}
    emitted.add(policy["default"]["checker_policy"])
    assert emitted <= POLICIES, emitted - POLICIES
    assert emitted == POLICIES  # and every checker policy is actually used


def test_route_classes_map_to_the_checker_as_designed(policy):
    assert policy["class_to_checker_policy"] == {
        "public": "none", "bearer": "bearer", "ticket_or_bearer": "ticket_or_bearer",
        "websocket": "ticket", "options": "none", "unrouted": "none",
    }
    for entry in policy["routes"]:
        assert entry["checker_policy"] == policy["class_to_checker_policy"][entry["class"]]
