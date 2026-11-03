"""
Find attribute assignments on rows a module loaded from another capability's
model: ``x = db.query(Model)….first(); x.attr = …``, or ``for x in
db.query(Model)…: x.attr = …``.

The capability map counts a model construction or a bulk insert, update or
delete as a write, and such an assignment only as a reference. That is how
compliance re-verification's writes to ``services`` and ``assets`` went unseen
until 1 Nov 2026. Used by ``tests/repo/test_findings_writer.py`` and
``tests/repo/test_asset_registry_writes.py``; imported by bare name, as
``testpaths`` is.
"""

import ast


def rows_changed(tree: ast.AST, models: set[str]) -> list[tuple[int, str]]:
    """
    ``(line, "name.attr")`` for each attribute assigned on a name bound to a
    row loaded with ``….query(<one of models>)``, or iterated from one.
    """

    def loads_row(node) -> bool:
        return any(
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Attribute)
            and call.func.attr == "query"
            and call.args
            and isinstance(call.args[0], ast.Name)
            and call.args[0].id in models
            for call in ast.walk(node)
        )

    changed = []
    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
            continue
        rows = set()
        for node in ast.walk(func):
            if isinstance(node, ast.Assign) and loads_row(node.value):
                rows.update(t.id for t in node.targets if isinstance(t, ast.Name))
            elif isinstance(node, ast.For) and loads_row(node.iter):
                if isinstance(node.target, ast.Name):
                    rows.add(node.target.id)
        for node in ast.walk(func):
            targets = (
                node.targets
                if isinstance(node, ast.Assign)
                else [node.target] if isinstance(node, ast.AugAssign) else []
            )
            for target in targets:
                if (
                    isinstance(target, ast.Attribute)
                    and isinstance(target.value, ast.Name)
                    and target.value.id in rows
                ):
                    changed.append((node.lineno, f"{target.value.id}.{target.attr}"))
    return sorted(set(changed))


def models_owned_by(capability: str) -> set:
    """The model classes whose tables *capability* owns."""
    from scripts.architecture import capability_map as cm

    tables = {t for t, cap in cm.table_owners().items() if cap == capability}
    return {name for name, (table, _) in cm._class_tables().items() if table in tables}
