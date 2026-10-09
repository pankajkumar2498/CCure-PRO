"""
Organisation plan features stay removable (Phase 8.4).

Scan limits (quota), scan scope and the remediation SLA are platform-owned plan
features that CCure Audit consumes. None of them is needed to run an
assessment, and the project owner expects stakeholders may ask for any of them
to be removed. These tests keep that a small, known change:

* **one seam per feature** — exactly one Audit module calls each feature's
  functions in ``ccure_platform.api``. Removing the feature means deleting its
  platform module, its API functions and rewriting that one seam; nothing else
  in Audit knows the feature exists;
* **features are independent** — no feature module imports another, so
  removing one cannot break the rest;
* **no Audit logic in the platform** — the plan package imports no module
  code.

The removal recipe for each feature is in
``docs/architecture/PHASE8_4_ORGANISATION_PLAN.md`` §9.
"""

from __future__ import annotations

import ast

import pytest

from scripts.architecture import identity_boundary as ib
from scripts.architecture.import_graph import collect_edges, discover_modules

#: feature -> (its API functions, the one Audit module allowed to call them)
FEATURES = {
    "scan_limits": (frozenset({"scan_limits"}), "core.quota"),
    "scan_scope": (frozenset({"scan_scope"}), "core.scan_scope"),
    "remediation_sla": (
        frozenset({"remediation_sla_setting", "store_remediation_sla_setting"}),
        "core.remediation.sla",
    ),
}
FEATURE_MODULES = {
    "scan_limits": "ccure_platform.plan.scan_limits",
    "scan_scope": "ccure_platform.plan.scan_scope",
    "remediation_sla": "ccure_platform.plan.remediation_sla",
}


def _api_uses(source: str) -> set[str]:
    """Names of ``ccure_platform.api`` a module uses, however it imported it."""
    tree = ast.parse(source)
    aliases: set[str] = set()
    used: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "ccure_platform":
            aliases |= {a.asname or a.name for a in node.names if a.name == "api"}
        elif isinstance(node, ast.ImportFrom) and node.module == "ccure_platform.api":
            used |= {a.name for a in node.names}
        elif isinstance(node, ast.Import):
            for a in node.names:
                if a.name == "ccure_platform.api":
                    aliases.add(a.asname or a.name)
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            if node.value.id in aliases:
                used.add(node.attr)
    return used


@pytest.fixture(scope="module")
def callers():
    """feature -> modules outside the platform that use its API functions."""
    out: dict[str, set[str]] = {name: set() for name in FEATURES}
    for module, path in sorted(discover_modules().items()):
        if ib.is_platform_side(module):
            continue
        used = _api_uses(path.read_text(encoding="utf-8"))
        for name, (functions, _) in FEATURES.items():
            if used & functions:
                out[name].add(module)
    return out


def test_the_detector_sees_every_import_form():
    assert _api_uses("from ccure_platform import api as p\np.scan_limits(db, o)\n") == {
        "scan_limits"
    }
    assert _api_uses("from ccure_platform.api import scan_scope\n") == {"scan_scope"}
    assert _api_uses("import ccure_platform.api as a\na.remediation_sla_setting\n") == {
        "remediation_sla_setting"
    }


@pytest.mark.parametrize("feature", sorted(FEATURES))
def test_each_plan_feature_has_exactly_one_audit_seam(callers, feature):
    _, seam = FEATURES[feature]
    assert callers[feature] == {seam}, (
        f"the {feature!r} plan feature must be consumed only through {seam} — "
        f"found {sorted(callers[feature])}. A second caller is a second place "
        "to change when stakeholders ask for the feature to be removed; route "
        "it through the seam instead."
    )


@pytest.mark.parametrize("feature", sorted(FEATURE_MODULES))
def test_plan_features_do_not_depend_on_each_other(feature):
    _, edges = collect_edges()
    others = set(FEATURE_MODULES.values()) - {FEATURE_MODULES[feature]}
    bad = sorted(
        e.dst for e in edges if e.src == FEATURE_MODULES[feature] and e.dst in others
    )
    assert not bad, f"{feature} imports another plan feature: {bad}"


def test_the_plan_package_imports_no_module_code():
    """Entitlements are data; counting, admission and due dates are Audit's."""
    _, edges = collect_edges()
    allowed_prefixes = ("ccure_platform", "db", "config")
    bad = sorted(
        (e.src, e.dst)
        for e in edges
        if e.src.startswith("ccure_platform.plan")
        and not e.dst.startswith(allowed_prefixes)
    )
    assert not bad, bad


def test_every_plan_feature_module_is_listed():
    present = {m for m in discover_modules() if m.startswith("ccure_platform.plan.")}
    assert present == set(FEATURE_MODULES.values()) | {"ccure_platform.plan.catalogue"}
