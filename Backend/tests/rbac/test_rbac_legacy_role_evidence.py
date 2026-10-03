"""
RBAC-3 — what still decides by role *name*: the evidence RBAC-4 migrates from.

RBAC-3 migrates nothing and deletes nothing. It **records**: every remaining legacy
authorization decision made by a role name — ``superadmin``, ``_is_superadmin``,
``require_role``, a direct ``role.name`` comparison — in
``Backend/data/rbac/legacy_role_name_dependencies.json``, with the category it
falls into and what replaces it. The list is measured by the same scanner as the
role-identity ratchet, and this test fails if the list and the code disagree, so the
evidence cannot go stale while RBAC-4 works through it.
"""

from __future__ import annotations

import json
from collections import Counter

import pytest

from ccure_platform.rbac import legacy_map as lm
from scripts.architecture import rbac_guardrails as rg
from testpaths import BACKEND_ROOT, REPO_ROOT

EVIDENCE = BACKEND_ROOT / "data" / "rbac" / "legacy_role_name_dependencies.json"
DOC = REPO_ROOT / "docs" / "architecture" / "RBAC_SHADOW_AUTHORIZATION.md"


@pytest.fixture(scope="module")
def evidence():
    return json.loads(EVIDENCE.read_text(encoding="utf-8"))


def test_the_evidence_lists_every_site_the_ratchet_counts(evidence):
    per_file = {}
    for s in evidence["sites"]:
        per_file.setdefault(s["file"], Counter())[s["kind"]] += 1
    assert {
        f: dict(sorted(c.items())) for f, c in sorted(per_file.items())
    } == rg.KNOWN_LEGACY_ROLE_IDENTITY_SITES
    assert (
        len(evidence["sites"])
        == 27
        == sum(sum(v.values()) for v in rg.measure_legacy().values())
    )


def test_the_evidence_and_the_code_agree_file_by_file(evidence):
    assert {s["file"] for s in evidence["sites"]} == set(rg.measure_legacy())


def test_every_site_has_a_known_category_a_replacement_and_a_phase(evidence):
    for s in evidence["sites"]:
        assert s["category"] in evidence["categories"], s
        assert s["rbac4_replacement"].strip() and s["deferred_to"] in (
            "RBAC-5",
            "RBAC-8",
        ), s
    assert set(evidence["categories"]) >= {s["category"] for s in evidence["sites"]}


def test_a_replacement_that_names_a_permission_names_one_that_exists():
    golden = lm.load_golden()
    keys = {p["key"] for p in golden["permissions"]}
    data = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    named = [
        s
        for s in data["sites"]
        if s["rbac4_replacement"].split(" ")[0].startswith(("platform.", "audit."))
    ]
    assert named
    for s in named:
        assert s["rbac4_replacement"].split(" ")[0] in keys, s


def test_scope_cases_are_deferred_to_rbac_5_and_nothing_else_is(evidence):
    for s in evidence["sites"]:
        if s["category"] == "scope_cross_org":
            assert s["deferred_to"] == "RBAC-5", s
    scope = [s for s in evidence["sites"] if s["category"] == "scope_cross_org"]
    assert len(scope) == 16 and {s["file"] for s in scope} >= {
        "routers/assets.py",
        "routers/dashboard.py",
    }


def test_the_thirteen_migrated_guards_are_gone_from_the_code_and_recorded():
    """RBAC-4 replaced the role-name permission guards and the superadmin shortcuts;
    ``role_name_site_decisions.json`` keeps what each of the 40 sites became."""
    decisions = json.loads(
        (BACKEND_ROOT / "data" / "rbac" / "role_name_site_decisions.json").read_text()
    )["sites"]
    assert len(decisions) == 40
    migrated = [d for d in decisions if d["status"] == "migrated"]
    assert len(migrated) == 13
    assert {d["category"] for d in migrated} == {
        "permission_guard",
        "permission_bypass",
    }
    keys = {p["key"] for p in lm.load_golden()["permissions"]}
    for d in migrated:
        assert d["new_permission"] in keys, d
    deferred = [d for d in decisions if d["status"] == "deferred"]
    assert len(deferred) == 27 and all(d["reason"].strip() for d in deferred)


def test_no_route_is_guarded_by_a_role_name_any_more():
    from main import app

    guarded = [
        r.path
        for r in app.routes
        if any(
            getattr(d.call, "__qualname__", "").startswith("require_role.")
            for d in getattr(getattr(r, "dependant", None), "dependencies", [])
        )
    ]
    assert guarded == []


def test_the_ratchet_baseline_fell_from_forty_to_twenty_seven():
    assert rg.measure_legacy() == rg.KNOWN_LEGACY_ROLE_IDENTITY_SITES
    assert (
        sum(sum(v.values()) for v in rg.KNOWN_LEGACY_ROLE_IDENTITY_SITES.values()) == 27
    )
    assert len(rg.KNOWN_LEGACY_ROLE_IDENTITY_SITES) == 20
    assert rg.measure_new() == []


def test_the_document_lists_the_categories_and_counts(evidence):
    text = DOC.read_text(encoding="utf-8")
    counts = Counter(s["category"] for s in evidence["sites"])
    for category, n in counts.items():
        assert f"`{category}`" in text and str(n) in text, category
    assert (
        "RBAC-3 = SHADOW ONLY" in text
        and "LEGACY AUTHORIZATION = AUTHORITATIVE" in text
    )
