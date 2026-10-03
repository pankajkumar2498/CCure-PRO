"""
RBAC-8 — the authorization inventory is generated, deterministic, complete and honest:
every live guard is the engine's, nothing legacy is called, and what remains of the old
model is named and classified.
"""

from __future__ import annotations

import json

import pytest

from scripts.rbac import build_migration_inventory as bi
from testpaths import BACKEND_ROOT

STATUSES = {"migrated", "display-only", "compatibility-history", "legacy"}
FIELDS = {
    "site_id",
    "file",
    "line",
    "function",
    "mechanism",
    "permission",
    "status",
    "reason",
}


@pytest.fixture(scope="module")
def inv():
    return json.loads(bi.INVENTORY.read_text(encoding="utf-8"))


def test_the_file_is_exactly_what_the_generator_produces():
    assert bi.INVENTORY.read_text(encoding="utf-8") == bi.render(
        bi.build()
    ), "run: python -m scripts.rbac.build_migration_inventory --write"


def test_the_generator_is_deterministic():
    assert bi.render(bi.build()) == bi.render(bi.build())


def test_every_site_has_every_field_a_known_status_and_a_reason(inv):
    ids = set()
    for s in inv["sites"]:
        assert set(s) == FIELDS, s
        assert s["status"] in STATUSES and s["reason"].strip(), s
        assert s["site_id"] not in ids
        ids.add(s["site_id"])
    assert inv["summary"]["total"] == len(inv["sites"])


def test_no_legacy_call_remains_anywhere(inv):
    assert inv["summary"]["legacy"] == 0
    assert inv["final_state"]["legacy_calls_remaining"] == 0
    assert not [s for s in inv["sites"] if s["status"] == "legacy"]
    assert bi.retired_calls() == []


def test_every_migrated_guard_names_a_declared_permission(inv):
    keys = bi.declared_keys()
    guards = [s for s in inv["sites"] if s["permission"]]
    assert guards
    assert all(s["status"] == "migrated" and s["permission"] in keys for s in guards)


def test_the_records_of_kept_legacy_vocabulary_point_at_code_that_exists(inv):
    for s in inv["sites"]:
        if s["status"] in ("compatibility-history", "display-only"):
            text = (BACKEND_ROOT / s["file"]).read_text(encoding="utf-8")
            assert s["function"] in text, s


def test_the_history_of_the_forty_role_name_sites_is_kept_as_removed(inv):
    removed = inv["removed_role_name_sites"]
    assert len(removed) == 40 == inv["summary"]["removed_role_name_sites"]
    assert all(r["status"] == "removed" for r in removed)
    assert {r["removed_in"] for r in removed} == {
        "RBAC-4",
        "RBAC-5",
        "RBAC-7",
        "RBAC-8",
    }


def test_the_legacy_tables_are_classified_non_authoritative(inv):
    tables = inv["final_state"]["legacy_tables"]
    assert set(tables) == {
        "roles",
        "permissions",
        "role_permissions",
        "rbac_legacy_map",
    }
    assert all(v.startswith("absent from runtime metadata") for v in tables.values())


def test_no_module_code_decides_by_role_name():
    from scripts.architecture import rbac_guardrails as rg

    assert rg.measure_legacy() == {}
