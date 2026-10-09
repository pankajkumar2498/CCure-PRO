"""
Phase 12.1 — the products CCure Home shows, as the module registry declares them.

The registry is the only source of each product's name, description, entry
address and availability (docs/architecture/PHASE12_FRONTEND_SHELL.md §0, §3.1).
Pinned here:

* the four products, in display order, with the owner's URL map;
* CCure IR is a product outside the core — listed, never a module, so nothing is
  mounted, loaded or migrated for it;
* the descriptions are the owner-approved text (D12-9), word for word, so a
  wording change is a reviewed change; each states what the product is
  responsible for;
* every product is listed whatever its state (D12-4);
* the validation that refuses an empty description, a malformed entry address,
  and two products sharing a key, a name or an address.
"""

from __future__ import annotations

import pytest

from ccure_platform.modules import (
    PRODUCT_KINDS,
    TILE_STATES,
    ManifestError,
    ModuleManifest,
    ServiceProduct,
    products,
    registry,
    services,
)

APPROVED = {
    "policy_pro": (
        "CCure Policy Pro",
        "core_module",
        "/policy-dashboard",
        "not_yet_available",
        "Responsible for your organisation's security policies and controls, and for "
        "the baseline — which controls apply, with what parameters — that the other "
        "products assess against.",
    ),
    "audit": (
        "CCure Audit",
        "core_module",
        "/audit-dashboard",
        "available",
        "Responsible for finding and assessing your assets: network and web scanning, "
        "vulnerability and configuration audits, compliance against frameworks, "
        "remediation tracking and reports.",
    ),
    "rank": (
        "CCure Rank",
        "core_module",
        "/rank-dashboard",
        "not_yet_available",
        "Responsible for scoring and ranking your organisation's security posture from "
        "the results the other products produce.",
    ),
    "ir": (
        "CCure IR",
        "service",
        "/ir-dashboard",
        "not_yet_available",
        "Responsible for incident response: recording and managing security incidents, "
        "and feeding what is learned back to the other products.",
    ),
}


def test_the_four_products_in_display_order():
    assert [p.key for p in products()] == ["policy_pro", "audit", "rank", "ir"]


@pytest.mark.parametrize("key", list(APPROVED))
def test_each_product_is_as_approved(key):
    p = next(p for p in products() if p.key == key)
    assert (p.title, p.kind, p.entry_path, p.tile_state, p.description) == APPROVED[key]


def test_the_url_map_is_the_owners():
    assert {p.key: p.entry_path for p in products()} == {
        "policy_pro": "/policy-dashboard",
        "audit": "/audit-dashboard",
        "rank": "/rank-dashboard",
        "ir": "/ir-dashboard",
    }


def test_descriptions_state_responsibility():
    for p in products():
        assert p.description.startswith("Responsible for "), p.key


def test_every_product_is_listed_whatever_its_state():
    listed = {p.key for p in products()}
    assert listed == {m.key for m in registry.modules()} | {s.key for s in services()}
    assert {p.tile_state for p in products()} <= set(TILE_STATES)
    assert {p.kind for p in products()} <= set(PRODUCT_KINDS)
    # the ones not built yet are still there
    assert {p.key for p in products() if p.tile_state == "not_yet_available"} == {
        "policy_pro",
        "rank",
        "ir",
    }


def test_ir_is_a_separate_service_not_a_core_module():
    assert [s.key for s in services()] == ["ir"]
    assert "ir" not in {m.key for m in registry.modules()}
    with pytest.raises(KeyError):
        registry.get("ir")
    assert not any(isinstance(s, ModuleManifest) for s in services())
    # no package, schema, routes, tasks or queues exist for it to contribute
    assert not hasattr(services()[0], "package")


def test_phase_12_1_changes_no_module_contribution_or_state():
    # Adding product metadata turns nothing on: Audit stays the one enabled
    # module, and nothing new is mounted, loaded or queued.
    assert [m.key for m in registry.enabled_modules()] == ["audit"]
    assert registry.task_modules() == [] and registry.queues() == []
    for m in registry.modules():
        assert m.routers == () and m.models == (), m.key


# ── validation ───────────────────────────────────────────────────────────────
def _service(**kw):
    base = dict(
        key="demo",
        title="Demo",
        description="Responsible for nothing; a test-only product.",
        entry_path="/demo-dashboard",
    )
    return ServiceProduct(**{**base, **kw})


@pytest.mark.parametrize(
    "kw,fragment",
    [
        ({"description": ""}, "description is empty"),
        ({"description": "   "}, "description is empty"),
        ({"description": "x" * 301}, "longer than 300"),
        ({"entry_path": "demo-dashboard"}, "entry_path"),
        ({"entry_path": "/demo/dashboard"}, "entry_path"),
        ({"entry_path": "/Demo"}, "entry_path"),
        ({"entry_path": ""}, "entry_path"),
        ({"title": " "}, "title is empty"),
        ({"tile_state": "coming_soon"}, "tile_state"),
        ({"key": "Demo"}, "key"),
    ],
)
def test_a_malformed_product_is_refused(kw, fragment):
    with pytest.raises(ManifestError, match=fragment):
        _service(**kw)


def test_a_module_manifest_is_refused_without_a_description_or_entry_path():
    base = dict(
        key="demo",
        title="Demo",
        package="ccure_demo",
        db_schema="demo",
        route_prefix="/demo",
        task_prefix="ccure.demo",
    )
    with pytest.raises(TypeError):  # both are required fields
        ModuleManifest(**base)
    with pytest.raises(ManifestError, match="description is empty"):
        ModuleManifest(**base, description="", entry_path="/demo-dashboard")


@pytest.mark.parametrize(
    "clash,fragment",
    [
        ({"key": "audit"}, "key 'audit'"),
        ({"title": "CCure Rank"}, "title 'CCure Rank'"),
        ({"entry_path": "/audit-dashboard"}, "entry_path '/audit-dashboard'"),
    ],
)
def test_two_products_cannot_share_a_key_a_name_or_an_address(clash, fragment):
    with pytest.raises(ManifestError, match=fragment):
        registry._check_products(registry.modules(), (_service(**clash),))


def test_the_real_registry_passes_its_own_product_check():
    registry._check_products(registry.modules(), registry.services())
