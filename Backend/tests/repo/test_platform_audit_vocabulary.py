"""
Backend alignment, follow-up 3: the Audit vocabulary left in ``ccure_platform``.

``ccure_platform`` imports no Audit code (the layer rules prove that). What is
left is **vocabulary**: words that belong to Audit's domain and still sit in
platform source as strings, field names and column names. Each is classified in
``docs/architecture/PLATFORM_AUDIT_VOCABULARY.md`` — a persisted value, a public
or frontend contract, or an owner decision — and each is left in place on
purpose until the design that owns it (preferences, notifications, the audit
taxonomy, module RBAC) is decided.

This is a ratchet. It counts, per file, the code-level occurrences (string
constants, identifiers, attribute and keyword names — never docstrings or
comments) of Audit's domain words, and fails when the count grows or a new file
starts carrying them. The count may only fall, and when it does the baseline is
lowered here in the same change. Adding a name to the baseline needs a reason in
review: new platform code does not speak Audit's language.

It also pins that platform code names no Audit permission atom: the platform
guards routes by whatever ``(resource, action)`` its callers pass, and owns none.
"""

from __future__ import annotations

import ast
import re

from testpaths import BACKEND_ROOT

PLATFORM = BACKEND_ROOT / "ccure_platform"
PATTERN = re.compile(r"scan|asset|vulnerab|finding|compliance|remediation", re.I)

#: file -> (count, what it is). The classification is in the architecture doc.
BASELINE: dict[str, tuple[int, str]] = {
    "audit_log/taxonomy.py": (
        1,
        "persisted data: the platform's own 'organization.scan_scope_changed' "
        "event (the organisation plan's scan scope); Audit's events moved to "
        "ccure_audit/audit_events.py (follow-up 6)",
    ),
    "notifications/service.py": (
        7,
        "persisted + API + frontend contract: related_scan_id (column, response "
        "field, parameters) — kept for compatibility; Audit's types and the "
        "'scan' category moved to scans/notification_vocabulary.py (follow-up 5)",
    ),
    "notifications/router.py": (
        1,
        "API contract: related_scan_id (notification-ownership follow-up)",
    ),
    "administration/organizations.py": (
        25,
        "owner decision (29 Sep 2026): the organisation plan is platform-owned — "
        "max_assets and the scan-scope endpoints; API contract",
    ),
    "identity/router.py": (
        1,
        "owner decision: the plan default max_assets given to a self-registered org",
    ),
    "models/rbac.py": (
        4,
        "persisted columns: organizations.max_assets / max_scans_per_day / "
        "max_concurrent_scans / scan_scope_cidrs (organisation-plan step 8.4)",
    ),
    "plan/scan_limits.py": (40, "owner decision: organisation plan (scan limits)"),
    "plan/scan_scope.py": (9, "owner decision: organisation plan (scan scope)"),
    "plan/remediation_sla.py": (6, "owner decision: organisation plan (SLA)"),
    "api.py": (
        8,
        "the platform API's plan exports (ScanLimits, scan_scope, …): owner decision",
    ),
    "rbac/contract.py": (
        2,
        "persisted value (RBAC-1): the frozen RBAC-0 key and display name of the "
        "system 'scanner' role (platform.scanner). The word is the role's own "
        "name, not Audit logic; item 5's "
        "module-RBAC decision owns the atoms, this is only the role",
    ),
    "permissions.py": (
        1,
        "persisted value (RBAC-2): the key platform.organization.set_scan_scope — the "
        "organisation plan's scan scope is platform-owned (owner decision, 29 Sep 2026) "
        "and the permission guards that platform feature",
    ),
    "identity/email_security_tasks.py": (
        6,
        "not Audit's: 'retro-scan' of accounts for shared mailboxes (name collision)",
    ),
}

#: Resources of Audit's permission atoms (rows in the platform's ``permissions``).
AUDIT_PERMISSION_RESOURCES = {
    "scans",
    "assets",
    "findings",
    "compliance",
    "credentials",
    "scan_policies",
    "scan_schedules",
    "reports",
    "dashboard",
}


def _docstrings(tree):
    ids = set()
    for n in ast.walk(tree):
        if isinstance(
            n, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            body = n.body
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(getattr(body[0], "value", None), ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                ids.add(id(body[0].value))
    return ids


def _count(path) -> int:
    tree = ast.parse(path.read_text("utf-8"))
    skip = _docstrings(tree)
    n_found = 0
    for n in ast.walk(tree):
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            if id(n) not in skip and len(n.value) <= 120 and PATTERN.search(n.value):
                n_found += 1
        elif isinstance(n, ast.Name) and PATTERN.search(n.id):
            n_found += 1
        elif isinstance(n, ast.Attribute) and PATTERN.search(n.attr):
            n_found += 1
        elif isinstance(
            n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ) and PATTERN.search(n.name):
            n_found += 1
        elif isinstance(n, ast.arg) and PATTERN.search(n.arg):
            n_found += 1
        elif isinstance(n, ast.keyword) and n.arg and PATTERN.search(n.arg):
            n_found += 1
    return n_found


def _current() -> dict[str, int]:
    out = {}
    for path in sorted(PLATFORM.rglob("*.py")):
        count = _count(path)
        if count:
            out[str(path.relative_to(PLATFORM))] = count
    return out


def test_no_new_audit_vocabulary_enters_the_platform():
    current = _current()
    new_files = sorted(set(current) - set(BASELINE))
    grown = sorted(
        f"{f}: {current[f]} > {BASELINE[f][0]}"
        for f in current
        if f in BASELINE and current[f] > BASELINE[f][0]
    )
    assert not new_files and not grown, (
        "Audit vocabulary grew inside ccure_platform.\n"
        f"  new files: {new_files}\n  grown: {grown}\n"
        "Platform code does not name Audit's domain (scan, asset, finding, "
        "compliance, vulnerability …). If this is a deliberate, classified "
        "exception, add it to BASELINE with its reason."
    )


def test_the_baseline_is_lowered_when_vocabulary_is_removed():
    current = _current()
    fallen = sorted(
        f"{f}: {current.get(f, 0)} < {BASELINE[f][0]}"
        for f in BASELINE
        if current.get(f, 0) < BASELINE[f][0]
    )
    assert not fallen, (
        f"Vocabulary was removed; lower BASELINE to match (a ratchet only holds if "
        f"the number follows it down): {fallen}"
    )


def test_platform_code_names_no_audit_permission_atom():
    offenders = []
    for path in PLATFORM.rglob("*.py"):
        tree = ast.parse(path.read_text("utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = getattr(node.func, "id", getattr(node.func, "attr", ""))
            if name not in {"require_permission", "user_has_permission"}:
                continue
            for arg in node.args:
                if (
                    isinstance(arg, ast.Constant)
                    and isinstance(arg.value, str)
                    and arg.value in AUDIT_PERMISSION_RESOURCES
                ):
                    offenders.append(f"{path.relative_to(PLATFORM)}:{node.lineno}")
    assert not offenders, offenders


def test_every_baseline_file_exists():
    for rel in BASELINE:
        assert (PLATFORM / rel).is_file(), rel
