"""
The credential vault as a capability of its own (G2, C5;
docs/architecture/MODULAR_REFACTORING_LOG.md §6).

Its model, ``ComplianceCredential`` and the vocabularies its CHECK constraints
are rendered from, moved out of the compliance model file into
``db/models/credentials.py``. The table, its rows and its constraints are
unchanged; these tests pin that the move left every old import path resolving
to the same objects.
"""

import ast

from testpaths import BACKEND_ROOT

MODEL_FILE = BACKEND_ROOT / "db" / "models" / "credentials.py"


def _moved_names() -> set[str]:
    names = set()
    for node in ast.parse(MODEL_FILE.read_text(encoding="utf-8")).body:
        if isinstance(node, ast.ClassDef):
            names.add(node.name)
        elif isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
            names.add(node.targets[0].id)
    names.discard("_sql_in_list")
    return names


def test_the_old_import_paths_resolve_to_the_same_objects():
    import db.models as registry
    import db.models.compliance as old
    import db.models.credentials as new

    names = _moved_names()
    assert len(names) == 28, sorted(names)
    for name in names:
        assert getattr(old, name) is getattr(new, name), name
    assert registry.ComplianceCredential is new.ComplianceCredential


def test_the_model_still_maps_the_same_table():
    from db.models.credentials import ComplianceCredential

    table = ComplianceCredential.__table__
    assert table.name == "compliance_credentials"
    assert {c.name for c in table.constraints if c.name} >= {
        "ck_compliance_credential_type",
        "ck_compliance_credential_transport",
        "ck_compliance_credential_auth",
    }


# ── Only the vault reads its table ──────────────────────────────────────────

#: The credential vault's own modules, and the two that only re-export its
#: model: the registry and the compliance model file's compatibility alias.
VAULT_MODULES = frozenset(
    {"core.credential_vault", "routers.credentials", "db.models.credentials"}
)
REEXPORTERS = frozenset({"db.models", "db.models.compliance"})
_MODEL_PATHS = frozenset({"db.models", "db.models.compliance", "db.models.credentials"})


def _modules_importing_the_model() -> dict[str, list[int]]:
    from scripts.architecture.import_graph import discover_modules

    found: dict[str, list[int]] = {}
    for module, path in discover_modules().items():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):  # lazy imports count too
            if (
                isinstance(node, ast.ImportFrom)
                and node.module in _MODEL_PATHS
                and any(a.name == "ComplianceCredential" for a in node.names)
            ):
                found.setdefault(module, []).append(node.lineno)
    return found


def test_only_the_vault_imports_the_credential_model():
    """
    Everything else asks ``core.credential_vault``: ``get_for_org`` for a row in
    an organisation, ``resolve`` or ``connection_material`` for what a collector
    connects with, ``stored_secrets`` for what remediation uses. G2 moved the
    last four outside readers onto it: the credentialed route, the compliance
    routes, compliance remediation and the schedule dispatcher.
    """
    outside = {
        module: lines
        for module, lines in _modules_importing_the_model().items()
        if module not in VAULT_MODULES | REEXPORTERS
    }
    assert not outside, (
        "these modules import ComplianceCredential; ask core.credential_vault "
        f"instead: {outside}"
    )


def test_the_vault_depends_only_on_lower_layers():
    """
    A capability is independent when it uses nothing beside or above it: here,
    the platform, infrastructure, the scan kernel's scope admission and the
    credentialed engines it tests a credential with.

    Whether it sits in the capability cycle is decided by edges *into* it, which
    it does not control. After G2 it is in the cycle only because
    ``routers.credentialed``, classified as the credentialed audit's, reaches up
    into it and into the scans capability (refactoring log §7).
    """
    from scripts.architecture import capability_map as cm

    measured = cm.measure()
    outgoing = [
        (src, dst)
        for kind in ("upward_edges", "lateral_edges")
        for src, dst in measured[kind]
        if cm.capability_of(src) == "credential_vault"
    ]
    assert not outgoing, outgoing


# ── Deletion asks who refers to a credential ────────────────────────────────


def test_the_application_registers_schedulings_reference_counter():
    import main  # noqa: F401 — imports every registration, as the API does
    from core import credential_vault

    assert credential_vault.SCAN_SCHEDULE_REFERENCES in (
        credential_vault.registered_reference_counters()
    )


def test_a_counter_cannot_be_replaced_by_another_under_its_name():
    import pytest
    from core import credential_vault

    def first(db, org_id, credential_id):
        return 0

    credential_vault.register_reference_counter("g2-test", first)
    try:
        credential_vault.register_reference_counter("g2-test", first)  # no-op
        with pytest.raises(ValueError, match="already registered"):
            credential_vault.register_reference_counter("g2-test", lambda *a: 1)
    finally:
        credential_vault._reference_counters.pop("g2-test", None)
