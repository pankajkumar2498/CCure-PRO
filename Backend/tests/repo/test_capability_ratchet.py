"""
The capability map and its ratchet (scripts/architecture/capability_map.py).

The module-level ratchets hold no forbidden edge and no module cycle; they
cannot see that on 16 Oct 2026, 22 of Audit's capabilities depended on one
another in a cycle (docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md). This
holds that from growing: new upward or lateral edges, new foreign-table access,
a larger cycle or a heavier load profile fail; coupling that is removed must be
removed from the baseline too, so it cannot quietly return.
"""

import copy

import pytest
import yaml
from scripts.architecture import capability_map as cm
from scripts.architecture.import_graph import discover_modules


@pytest.fixture(scope="module")
def measurement():
    return cm.measure()


# ── The map ───────────────────────────────────────────────────────────────────


def test_every_module_belongs_to_a_capability():
    assert cm.unmapped_modules(discover_modules()) == []


def test_every_mapping_names_a_declared_capability():
    named = set(cm.PREFIXES.values()) | set(cm.PACKAGE_ONLY.values())
    assert named <= set(cm.CAPABILITIES)


def test_a_new_flat_module_in_a_mixed_package_must_be_classified():
    """No default for core/, routers/, scans/ …: a new module there belongs
    nowhere until someone decides, the way a new table needs an owner."""
    for module in ("core.something_new", "routers.something_new", "scans.new_helper"):
        with pytest.raises(cm.UnmappedModule):
            cm.capability_of(module)
    # Inside a classified package the prefix decides.
    assert cm.capability_of("core.web.something_new") == "web_dast"
    assert cm.capability_of("core") == "infra"


def test_ownership_is_read_exactly_as_yaml_reads_it():
    data = yaml.safe_load(cm.OWNERSHIP_FILE.read_text(encoding="utf-8"))
    expected = {
        table: cm.OWNERSHIP_CAPABILITY.get(row["capability"], row["capability"])
        for table, row in data["tables"].items()
    }
    assert cm.table_owners() == expected
    assert set(expected.values()) <= set(cm.CAPABILITIES)


def test_every_model_class_has_an_owned_table():
    owners = cm.table_owners()
    unowned = {c: t for c, t in cm.model_classes().items() if t not in owners}
    assert unowned == {}


def test_a_model_class_belongs_to_the_capability_owning_its_table():
    """Not to the file it is defined in: the credential vault's model sits in
    the compliance model file, and a registry import names neither file."""
    assert (
        cm.capability_of("db.models.compliance:ComplianceCredential")
        == "credential_vault"
    )
    assert cm.capability_of("db.models.compliance:ComplianceRule") == "compliance"
    assert cm.capability_of("db.models.scans:Scan") == "scans"


def test_registry_fan_out_is_nobodys_dependency(measurement):
    """
    ``from db.models import X`` is attributed to X's owner, and the registry's
    own re-exports to nobody. Only ``import db.models`` — which really does load
    every model — still depends on the registry itself.
    """
    import ast

    modules = discover_modules()
    _, edges = cm.capability_edges()
    assert not [e for e in edges if e.src == cm.MODEL_REGISTRY]
    for edge in (e for e in edges if e.dst == cm.MODEL_REGISTRY):
        tree = ast.parse(modules[edge.src].read_text(encoding="utf-8"))
        whole = any(
            isinstance(node, ast.Import)
            and any(alias.name == cm.MODEL_REGISTRY for alias in node.names)
            for node in ast.walk(tree)
        )
        assert whole, f"{edge.src} reaches the registry other than by import db.models"


# ── The ratchet ───────────────────────────────────────────────────────────────


def test_the_ratchet_holds(measurement):
    problems = cm.ratchet_problems(measurement)
    assert problems == [], "\n".join(problems)


def test_the_baseline_is_within_its_ceilings():
    assert cm.ceiling_problems(cm.load_baseline()) == []


def test_the_ceilings_are_never_above_what_they_were_introduced_at():
    """Lowering a ceiling locks progress in; raising one needs a reason in
    review, so the 16 Oct 2026 figures are pinned here as the upper bound."""
    introduced = {
        "largest_cycle": 22,
        "largest_cycle_top_level": 13,
        "upward_edges": 50,
        "lateral_edges": 74,
        "foreign_table_references": 80,
        "foreign_table_writes": 17,
    }
    for name, value in cm.CEILINGS.items():
        assert value <= introduced[name], name


def test_new_coupling_fails(measurement):
    grown = copy.deepcopy(measurement)
    grown["upward_edges"].append(["engines.port.port_engine", "routers.assets"])
    grown["foreign_table_writes"].append(["web_dast", "assets"])
    grown["cycles"][0] = sorted(set(grown["cycles"][0]) | {"dashboard"})
    entry = "core.config_audit.engine"
    grown["load_profiles"][entry]["third_party"].append("sqlalchemy")

    problems = "\n".join(cm.ratchet_problems(grown))
    assert "new upward edge" in problems
    assert "engines.port.port_engine -> routers.assets" in problems
    assert "new write to another capability's table: web_dast -> assets" in problems
    assert "new or enlarged capability cycle" in problems
    assert f"importing {entry} now also loads third_party ['sqlalchemy']" in problems


def test_removed_coupling_must_leave_the_baseline_too(measurement):
    shrunk = copy.deepcopy(measurement)
    gone = shrunk["upward_edges"].pop()
    problems = "\n".join(cm.ratchet_problems(shrunk))
    assert "gone — remove it from the baseline" in problems
    assert f"{gone[0]} -> {gone[1]}" in problems


def test_an_unclassified_module_fails_the_ratchet():
    problems = cm.ratchet_problems({"unmapped": ["core.brand_new"]})
    assert problems and "core.brand_new" in problems[0]
