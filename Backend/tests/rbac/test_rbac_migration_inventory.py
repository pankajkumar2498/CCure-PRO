"""
RBAC-4 — the migration inventory is generated, deterministic, complete and honest.
"""

from __future__ import annotations

import json

import pytest

from ccure_platform.rbac import authority as au
from ccure_platform.rbac import legacy_map
from scripts.rbac import build_migration_inventory as bi
from testpaths import BACKEND_ROOT

FIELDS = {
    "site_id",
    "file",
    "line",
    "function",
    "mechanism",
    "legacy_permission",
    "new_permission",
    "path_id",
    "scope",
    "status",
    "migrated",
    "reason",
    "rbac3_evidence",
    "rbac5_dependency",
}


REPLACED_KEYS = frozenset(
    {
        "platform.email_domain.read",
        "platform.email_domain.manage",
        "platform.audit_log.retention",
        "audit.vuln_feed.manage",
        "audit.compliance.manage_shared_rules",
    }
)


@pytest.fixture(scope="module")
def inv():
    return json.loads(bi.INVENTORY.read_text(encoding="utf-8"))


def test_the_file_is_exactly_what_the_generator_produces():
    assert bi.INVENTORY.read_text(encoding="utf-8") == bi.render(
        bi.build()
    ), "run: python -m scripts.rbac.build_migration_inventory --write"


def test_the_generator_is_deterministic():
    assert bi.render(bi.build()) == bi.render(bi.build())


def test_every_site_carries_every_required_field_and_a_reason(inv):
    ids = set()
    for s in inv["sites"]:
        assert FIELDS <= set(s), s
        assert s["status"] in ("migrated", "deferred")
        assert s["migrated"] == (s["status"] == "migrated")
        assert s["reason"].strip(), s
        assert s["site_id"] not in ids
        ids.add(s["site_id"])
        if s["migrated"]:
            assert s["path_id"] and s["rbac3_evidence"], s
        else:
            assert s["path_id"] is None, s


def test_all_forty_rbac3_sites_are_still_tracked(inv):
    sites = inv["rbac3_role_name_sites"]
    assert len(sites) == 40
    assert sum(1 for s in sites if s["status"] == "migrated") == 13
    assert all(s["reason"].strip() for s in sites)
    remaining = [s for s in inv["sites"] if s["mechanism"].startswith("role_name_")]
    # 13 migrated in RBAC-4, 20 in RBAC-5; 9 sites remain in the code (7 original
    # plus the legacy rollback rule's two helpers)
    assert len(remaining) == 6


def test_every_scope_site_has_a_final_rbac5_status(inv):
    scope = [
        s for s in inv["rbac3_role_name_sites"] if s["category"] == "scope_cross_org"
    ]
    assert len(scope) == 16
    for s in inv["rbac3_role_name_sites"]:
        if s["status"] == "migrated":
            continue
        final = s["rbac5"]
        assert final["status"] in ("migrated", "intentionally_deferred"), s
        assert final["reason"].strip(), s
    # nothing is silently dropped: 13 + 20 migrated, 7 deferred
    statuses = [
        "rbac4" if s["status"] == "migrated" else s["rbac5"]["status"]
        for s in inv["rbac3_role_name_sites"]
    ]
    assert (statuses.count("rbac4"), statuses.count("migrated")) == (13, 20)
    # RBAC-7 migrated three of the seven; the other four are RBAC-8
    assert statuses.count("intentionally_deferred") == 7
    assert (
        sum(
            1
            for s in inv["rbac3_role_name_sites"]
            if s.get("rbac7", {}).get("status") == "migrated"
        )
        == 3
    )


def test_only_one_to_one_mapped_atoms_outside_the_deferred_resources_migrate(inv):
    atoms = {a["atom"]: a for a in legacy_map.load_golden()["atoms"]}
    for s in inv["sites"]:
        perm = s["legacy_permission"]
        if not perm:
            continue
        atom = atoms[perm]
        if s["migrated"]:
            assert atom["status"] == "mapped" and len(atom["new_keys"]) == 1, s
            assert perm.split(":")[0] not in bi.DEFERRED_RESOURCES, s
            assert s["path_id"] == perm
        elif perm.split(":")[0] in bi.DEFERRED_RESOURCES:
            assert s["reason"]


def test_read_all_checks_are_now_authoritative_and_organisation_aware(inv):
    reads = [s for s in inv["sites"] if s["legacy_permission"] == "scans:read_all"]
    assert reads and all(s["migrated"] for s in reads)


def test_scope_mechanisms_are_all_migrated_through_scope_paths(inv):
    scope = [
        s
        for s in inv["sites"]
        if s["mechanism"]
        in (
            "resolve_active_organisation",
            "acts_across_organisations",
            "resource_organisation_allowed",
            "check_role_assignment",
        )
    ]
    assert scope and all(
        s["migrated"] and s["path_id"].startswith("scope.") for s in scope
    )


def test_key_paths_name_permissions_the_catalogue_declares(inv):
    keys = {p["key"] for p in legacy_map.load_golden()["permissions"]}
    key_paths = {
        s["path_id"]
        for s in inv["sites"]
        if s["migrated"] and s["mechanism"] in ("require_authorized", "has_permission")
    }
    # the five role-name replacements (RBAC-4) plus the platform-administration keys
    # (RBAC-7); every one is a declared permission
    assert key_paths >= REPLACED_KEYS and key_paths <= keys


def test_the_runtime_switches_only_what_the_inventory_marks_migrated(inv):
    au.set_migrated_paths(None)
    try:
        assert au.migrated_paths() == frozenset(inv["summary"]["migrated_paths"])
    finally:
        au.set_migrated_paths(None)


def test_no_module_code_decides_by_role_name_except_the_recorded_sites():
    from scripts.architecture import rbac_guardrails as rg

    assert sum(sum(v.values()) for v in rg.measure_legacy().values()) == 6
