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
