"""
RBAC-2 — the golden legacy mapping.

``Backend/data/rbac/golden_legacy_mapping.json`` says, for every legacy role and
every legacy ``resource:action`` atom, what it becomes. It exists so RBAC-4's
migration is **mechanically verifiable**: old effective permission set == new
effective permission set, per role, subject to listed differences.

The mapping is checked three ways that do not depend on each other — the file is
internally consistent and accounts for every atom (``validate_golden``); each role's
expected set is *recomputed* from what its legacy role holds (``derive_role_grants``);
and the declarations' own ``default_grants`` must agree with both. A mutation test at
the end shows each check can fail.
"""

from __future__ import annotations

import copy
import json
from collections import Counter

import pytest

from ccure_platform import composition
from ccure_platform.rbac import contract as c
from ccure_platform.rbac import legacy_map as lm
from ccure_platform.rbac.catalogue import sync
from ccure_platform.rbac.model import RbacLegacyMap
from db.migrate_production_schema import PERMISSIONS, ROLE_PERMISSIONS
from rbac_testing import rbac_db_fixture  # noqa: F401
from testpaths import BACKEND_ROOT

LIVE_ONLY = {"audit_logs:read"}
SEEDED = {f"{r}:{a}" for r, a, _ in PERMISSIONS}
LEGACY_ATOMS = SEEDED | LIVE_ONLY


@pytest.fixture(scope="module")
def golden():
    return lm.load_golden()


@pytest.fixture(scope="module")
def decls():
    return [d for s in composition.load_permission_sources() for d in s.permissions]


def legacy_sets():
    """What each legacy role holds. The live database additionally gives the
    org_admin and superadmin roles the live-only ``audit_logs:read``."""
    sets = {r: set(v) for r, v in ROLE_PERMISSIONS.items() if r != "superadmin"}
    sets["org_admin"] |= LIVE_ONLY
    sets["superadmin"] = LEGACY_ATOMS
    return sets


# ── the file ─────────────────────────────────────────────────────────────────


def test_the_golden_mapping_is_valid_against_the_catalogue_and_every_legacy_atom(
    golden, decls
):
    assert (
        lm.validate_golden(golden, declarations=decls, legacy_atoms=LEGACY_ATOMS) == []
    )


def test_there_are_65_seeded_atoms_and_one_live_only_atom():
    assert len(SEEDED) == 65
    golden = lm.load_golden()
    assert golden["legacy_source"]["seeded_atoms"] == 65
    assert golden["legacy_source"]["live_only_atoms"] == ["audit_logs:read"]
    assert {a["atom"] for a in golden["atoms"] if not a["seeded"]} == LIVE_ONLY


def test_every_legacy_atom_ends_in_exactly_one_status_and_none_is_unexplained(golden):
    atoms = golden["atoms"]
    assert len(atoms) == len({a["atom"] for a in atoms}) == 66
    assert {a["atom"] for a in atoms} == LEGACY_ATOMS
    counts = Counter(a["status"] for a in atoms)
    assert counts == {"mapped": 50, "replaced": 6, "retired": 10}
    for a in atoms:
        assert a["status"] in ("mapped", "replaced", "retired")
        assert a["reason"].strip()
        assert bool(a["new_keys"]) == (a["status"] != "retired"), a["atom"]


def test_retired_atoms_are_exactly_those_nothing_enforces(golden):
    retired = {a["atom"] for a in golden["atoms"] if a["status"] == "retired"}
    assert retired == {
        "scans:update",
        "scans:cancel",
        "assets:create",
        "assets:delete",
        "assets:export",
        "findings:export",
        "reports:create",
        "settings:read",
        "compliance:manage_retention",
        "audit_logs:read",
    }
    # and the replaced ones are the atoms whose capability is now expressed differently
    replaced = {a["atom"] for a in golden["atoms"] if a["status"] == "replaced"}
    assert replaced == {
        "settings:update",
        "roles:create",
        "roles:update",
        "roles:delete",
        "organizations:delete",
        "audit:purge",
    }


def test_no_retired_atom_is_actually_required_by_a_route_or_screen(golden):
    """The retirement claim is checkable: no source file spells a retired atom as a
    ``(resource, action)`` pair handed to a guard."""
    import ast

    retired = {
        tuple(a["atom"].split(":")) for a in golden["atoms"] if a["status"] == "retired"
    }
    roots = [
        BACKEND_ROOT / d
        for d in ("routers", "ccure_platform", "scans", "core", "ccure_audit")
    ]
    found = []
    for root in roots:
        for path in root.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    names = getattr(node.func, "id", getattr(node.func, "attr", ""))
                    if names in ("require_permission", "user_has_permission"):
                        strs = [
                            a.value for a in node.args if isinstance(a, ast.Constant)
                        ]
                        for i in range(len(strs) - 1):
                            if (strs[i], strs[i + 1]) in retired:
                                found.append((path.name, strs[i], strs[i + 1]))
    assert not found, found


def test_every_atom_maps_only_to_declared_keys_and_every_key_has_a_source_or_a_reason(
    golden, decls
):
    declared = {d.key for d in decls}
    for a in golden["atoms"]:
        assert set(a["new_keys"]) <= declared
    for p in golden["permissions"]:
        if p["origin"] == "legacy":
            assert p["sources"], p["key"]
        else:
            assert (
                p["origin"] in ("name_check", "new_governance") and p["reason"].strip()
            )


def test_a_merge_only_exists_where_every_legacy_role_holds_all_the_merged_atoms_or_none(
    golden,
):
    """The rule that makes a merge safe: a merged key is held when *all* its atoms
    are, so it is only equivalent where no role holds some but not all."""
    sets = legacy_sets()
    for p in golden["permissions"]:
        sources = p["sources"]
        if len(sources) < 2:
            continue
        for role, held in sets.items():
            if role == "superadmin":
                continue
            mine = [a in held for a in sources]
            assert all(mine) or not any(mine), (
                p["key"],
                role,
                dict(zip(sources, mine)),
            )


def test_a_split_atom_gives_every_part_the_same_holders(golden):
    sets = legacy_sets()
    for a in golden["atoms"]:
        if len(a["new_keys"]) < 2:
            continue
        # each new key's holders (org roles) are a function of its sources; for a
        # split atom they are all derived from that atom, so they cannot differ
        derived = lm.derive_role_grants(golden, sets)
        for role_key, held in derived.items():
            if held == lm.ALL_ACTIVE:
                continue
            in_scope = [k for k in a["new_keys"] if k in held]
            org_keys = [
                k
                for k in a["new_keys"]
                if next(p for p in golden["permissions"] if p["key"] == k)["scope_kind"]
                == "organization"
            ]
            assert len(in_scope) in (0, len(org_keys)), (a["atom"], role_key)


# ── the roles ────────────────────────────────────────────────────────────────


def test_all_five_legacy_roles_are_mapped_to_system_role_keys(golden):
    assert {r["legacy_role"]: r["role_key"] for r in golden["roles"]} == dict(
        c.LEGACY_ROLE_NAMES
    )
    scopes = {r["role_key"]: r["assignable_scope"] for r in golden["roles"]}
    assert scopes["platform.superadmin"] == "platform"
    assert {v for k, v in scopes.items() if k != "platform.superadmin"} == {
        "organization"
    }
    assert {r["default_display_name"] for r in golden["roles"]} == {
        s.display_name for s in c.SYSTEM_ROLE_SEEDS
    }


def test_the_roles_agree_with_the_seeded_system_roles(golden):
    seeds = {s.key: s for s in c.SYSTEM_ROLE_SEEDS}
    for r in golden["roles"]:
        seed = seeds[r["role_key"]]
        assert (seed.assignable_scope, seed.display_name) == (
            r["assignable_scope"],
            r["default_display_name"],
        )


# ── three independent checks that the role sets agree ────────────────────────


def test_each_roles_expected_set_is_recomputed_from_its_legacy_role_and_matches(golden):
    derived = lm.derive_role_grants(golden, legacy_sets())
    for role_key, expected in golden["role_grants"].items():
        if expected == lm.ALL_ACTIVE:
            assert derived[role_key] == lm.ALL_ACTIVE
        else:
            assert derived[role_key] == frozenset(expected), role_key


def test_the_declarations_default_grants_equal_the_golden_sets(golden, decls):
    by_role = {
        r["role_key"]: set()
        for r in golden["roles"]
        if r["assignable_scope"] == "organization"
    }
    for d in decls:
        for role_key in d.default_grants:
            by_role[role_key].add(d.key)
    for role_key, held in by_role.items():
        assert held == set(golden["role_grants"][role_key]), role_key


def test_permission_granted_to_is_the_inverse_of_role_grants(golden):
    for p in golden["permissions"]:
        expected = {
            r
            for r, v in golden["role_grants"].items()
            if v == lm.ALL_ACTIVE or p["key"] in v
        }
        assert set(p["granted_to"]) == expected, p["key"]


def test_the_expected_set_sizes_are_what_the_legacy_roles_translate_to(golden):
    sizes = {r: len(v) for r, v in golden["role_grants"].items() if v != lm.ALL_ACTIVE}
    assert sizes == {
        "platform.org_admin": 47,
        "platform.analyst": 23,
        "platform.viewer": 9,
        "platform.scanner": 4,
    }


def test_no_organisation_role_holds_a_platform_scope_or_non_delegable_key(
    golden, decls
):
    scope = {d.key: d for d in decls}
    for role_key, held in golden["role_grants"].items():
        if held == lm.ALL_ACTIVE:
            continue
        for key in held:
            assert (
                scope[key].scope_kind == "organization"
                and scope[key].delegable_to_org_roles
            )


def test_the_new_capabilities_with_no_legacy_atom_are_held_only_by_superadmin(golden):
    for p in golden["permissions"]:
        if p["origin"] in ("name_check", "new_governance"):
            assert p["granted_to"] == ["platform.superadmin"], p["key"]
            assert p["sources"] == [] or p["origin"] == "legacy"


def test_every_difference_between_old_and_new_is_listed(golden):
    ids = {d["id"] for d in golden["intentional_differences"]}
    assert {"D1", "D2", "D3", "D4", "D5", "D6", "D7"} <= ids
    d1 = next(d for d in golden["intentional_differences"] if d["id"] == "D1")
    assert set(d1["atoms"]) == {
        a["atom"] for a in golden["atoms"] if a["status"] == "retired"
    }


def test_no_role_loses_anything_but_a_retired_atom(golden):
    """The no-loss property: every legacy atom an organisation role holds, other than
    a retired one, is still held by the new role as every key it became. The retired
    atoms are the ONLY legacy permissions a role stops holding (difference D1)."""
    derived = lm.derive_role_grants(golden, legacy_sets())
    for legacy_role, held in legacy_sets().items():
        if legacy_role == "superadmin":
            continue
        new_held = derived[c.LEGACY_ROLE_NAMES[legacy_role]]
        for a in golden["atoms"]:
            if a["atom"] in held and a["status"] != "retired":
                assert set(a["new_keys"]) <= new_held, (legacy_role, a["atom"])


def test_no_role_gains_anything_the_legacy_role_did_not_hold(golden):
    """And the converse: every key a role holds derives only from atoms it held."""
    derived = lm.derive_role_grants(golden, legacy_sets())
    sources = {p["key"]: set(p["sources"]) for p in golden["permissions"]}
    for legacy_role, held in legacy_sets().items():
        if legacy_role == "superadmin":
            continue
        for key in derived[c.LEGACY_ROLE_NAMES[legacy_role]]:
            assert sources[key] and sources[key] <= held, (legacy_role, key)


def test_the_file_is_deterministic_and_stable_under_a_round_trip(golden):
    path = lm.DEFAULT_GOLDEN_PATH
    text = path.read_text(encoding="utf-8")
    assert json.dumps(json.loads(text), indent=2) + "\n" == text
    assert [a["atom"] for a in golden["atoms"]] == [
        f"{r}:{a}" for r, a, _ in PERMISSIONS
    ] + ["audit_logs:read"]


# ── the checks bite ──────────────────────────────────────────────────────────


def mutated(golden, fn):
    g = copy.deepcopy(golden)
    fn(g)
    return g


@pytest.mark.parametrize(
    "name,fn,fragment",
    [
        ("drop an atom", lambda g: g["atoms"].pop(0), "is not accounted for"),
        (
            "invent an atom",
            lambda g: g["atoms"].append(
                dict(atom="x:y", seeded=True, status="retired", new_keys=[], reason="r")
            ),
            "is not a legacy atom",
        ),
        (
            "map to an undeclared key",
            lambda g: g["atoms"][0]["new_keys"].append("audit.nope.read"),
            "not declared",
        ),
        (
            "retire with keys",
            lambda g: g["atoms"][1].update(status="retired"),
            "retired but names new keys",
        ),
        (
            "map to nothing",
            lambda g: g["atoms"][0].update(new_keys=[]),
            "names no new key",
        ),
        ("unknown status", lambda g: g["atoms"][0].update(status="gone"), "has status"),
        ("no reason", lambda g: g["atoms"][0].update(reason=" "), "has no reason"),
        ("drop a permission entry", lambda g: g["permissions"].pop(0), "has no entry"),
        (
            "wrong scope",
            lambda g: g["permissions"][0].update(scope_kind="platform"),
            "scope_kind",
        ),
        (
            "grant an org role a platform key",
            lambda g: g["role_grants"]["platform.viewer"].append(
                "platform.organization.read"
            ),
            "may not hold",
        ),
        (
            "grant an undeclared key",
            lambda g: g["role_grants"]["platform.viewer"].append("audit.nope.read"),
            "undeclared key",
        ),
        (
            "unsorted grants",
            lambda g: g["role_grants"]["platform.viewer"].reverse(),
            "not sorted",
        ),
        (
            "no differences",
            lambda g: g.update(intentional_differences=[]),
            "intentional_differences",
        ),
        ("bad version", lambda g: g.update(schema_version=2), "schema_version"),
    ],
)
def test_the_validator_catches_each_kind_of_gap(golden, decls, name, fn, fragment):
    problems = lm.validate_golden(
        mutated(golden, fn), declarations=decls, legacy_atoms=LEGACY_ATOMS
    )
    assert any(fragment in p for p in problems), (name, problems)


def test_removing_a_legacy_permission_from_a_role_changes_the_derivation(golden):
    sets = legacy_sets()
    sets["analyst"] = sets["analyst"] - {"scans:execute"}
    derived = lm.derive_role_grants(golden, sets)
    assert derived["platform.analyst"] != frozenset(
        golden["role_grants"]["platform.analyst"]
    )
    assert "audit.scan.run" not in derived["platform.analyst"]


def test_a_merged_key_needs_all_its_atoms(golden):
    sets = legacy_sets()
    sets["scanner"] = sets["scanner"] - {"scans:create"}
    assert (
        "audit.scan.run" not in lm.derive_role_grants(golden, sets)["platform.scanner"]
    )


# ── syncing the map into rbac_legacy_map ─────────────────────────────────────


@pytest.fixture
def synced(rbac_db, golden):
    sync(rbac_db, composition.load_permission_sources(), audit=False)
    rbac_db.query(RbacLegacyMap).delete()
    rbac_db.flush()
    report = lm.sync_legacy_map(rbac_db, golden, audit=False)
    return rbac_db, report


def test_the_sync_writes_every_role_and_every_atom_including_retired_ones(
    synced, golden
):
    db, report = synced
    assert len(report.roles_added) == 5
    rows = db.query(RbacLegacyMap).all()
    assert sum(1 for r in rows if r.kind == "role") == 5
    perm_rows = [r for r in rows if r.kind == "permission"]
    atoms = {f"{r.legacy_resource}:{r.legacy_action}" for r in perm_rows}
    assert atoms == LEGACY_ATOMS
    retired = [r for r in perm_rows if r.status == "retired"]
    assert len(retired) == 10 and all(
        r.permission_key is None and r.reason for r in retired
    )
    assert Counter(r.status for r in perm_rows if r.status != "retired") == {
        "mapped": sum(
            len(a["new_keys"]) for a in golden["atoms"] if a["status"] == "mapped"
        ),
        "replaced": sum(
            len(a["new_keys"]) for a in golden["atoms"] if a["status"] == "replaced"
        ),
    }


def test_the_old_atom_is_preserved_unrenamed_in_the_map(synced):
    db, _ = synced
    row = (
        db.query(RbacLegacyMap)
        .filter_by(legacy_resource="scans", legacy_action="execute")
        .one()
    )
    assert (row.legacy_resource, row.legacy_action, row.permission_key) == (
        "scans",
        "execute",
        "audit.scan.run",
    )


def test_the_role_map_is_complete(synced):
    db, _ = synced
    roles = {
        r.legacy_role_name: r.role_key
        for r in db.query(RbacLegacyMap).filter_by(kind="role")
    }
    assert roles == dict(c.LEGACY_ROLE_NAMES)


def test_the_sync_is_idempotent_and_reports_changes_once(synced, golden):
    db, report = synced
    assert report.changed
    again = lm.sync_legacy_map(db, golden, audit=False)
    assert not again.changed and again.stale == ()


def test_a_changed_reason_updates_the_row_and_a_removed_atom_is_reported_stale(
    synced, golden
):
    db, _ = synced
    g = copy.deepcopy(golden)
    g["atoms"][0]["reason"] = "A new reason."
    removed = g["atoms"].pop()  # audit_logs:read
    report = lm.sync_legacy_map(db, g, audit=False)
    assert g["atoms"][0]["atom"] in report.atoms_updated
    assert report.stale == (removed["atom"],)
    # never deleted by the sync
    assert db.query(RbacLegacyMap).filter_by(legacy_resource="audit_logs").count() == 1


def test_the_sync_refuses_to_map_to_a_key_the_catalogue_lacks(rbac_db, golden):
    rbac_db.query(RbacLegacyMap).delete()
    rbac_db.flush()
    with pytest.raises(lm.GoldenError) as err:
        lm.sync_legacy_map(rbac_db, golden, audit=False)
    assert "sync it first" in str(err.value)


def test_a_missing_or_corrupt_golden_file_raises_rather_than_falling_back(tmp_path):
    with pytest.raises(lm.GoldenError):
        lm.load_golden(tmp_path / "missing.json")
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(lm.GoldenError):
        lm.load_golden(bad)


def test_the_sync_writes_one_platform_event_and_never_touches_a_tenants_trail(
    rbac_db, golden
):
    from sqlalchemy import text

    from ccure_platform.models.platform_audit import PlatformAuditEvent

    sync(rbac_db, composition.load_permission_sources(), audit=False)
    rbac_db.query(RbacLegacyMap).delete()
    rbac_db.flush()
    before = rbac_db.execute(text("SELECT count(*) FROM audit_logs")).scalar()
    report = lm.sync_legacy_map(rbac_db, golden)
    assert report.events_written == 1
    event = (
        rbac_db.query(PlatformAuditEvent)
        .filter_by(action="rbac.legacy_map.synced")
        .one()
    )
    assert event.actor_label == lm.SYNC_ACTOR and event.actor_kind == "system"
    assert rbac_db.execute(text("SELECT count(*) FROM audit_logs")).scalar() == before
