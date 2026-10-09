"""
The legacy HS256 token mechanism is gone, and stays gone (Phase 9.6c).

Source-only: parses and greps files, imports no application state. It fails if a
symmetric secret, a signing-algorithm switch or a legacy verification path returns to
runtime code, so "roll back" is never again a runtime setting but a git revert.
"""

from __future__ import annotations

import ast
import re

from scripts.architecture.import_graph import BACKEND_ROOT

#: Names that existed only for the symmetric mechanism.
FORBIDDEN_NAMES = (
    "JWT_SECRET_KEY",
    "CCURE_ACCEPT_LEGACY_HS256",
    "CCURE_TOKEN_SIGNING_ALG",
    "ACCEPT_LEGACY_HS256",
    "TOKEN_SIGNING_ALG",
    "LegacyHS256",
    "LEGACY_ALGORITHM",
    "legacy_verification_status",
)
#: Not runtime code: tests assert the absence, operator tooling reads old env files
#: to prove key continuity, and migrations are history.
EXEMPT_DIRS = {
    ".venv",
    "tests",
    "alembic",
    "__pycache__",
    "node_modules",
    "logs",
    "reports",
}
EXEMPT_FILES = {"scripts/security/verify_mfa_key_continuity.py"}
#: Runtime code may mention the name only to say it is gone.
PROSE = re.compile(r"(gone|removed|retired|no JWT|no longer|never again)", re.I)


def _runtime_files():
    for path in sorted(BACKEND_ROOT.rglob("*.py")):
        rel = path.relative_to(BACKEND_ROOT)
        if set(rel.parts[:-1]) & EXEMPT_DIRS or rel.as_posix() in EXEMPT_FILES:
            continue
        yield rel.as_posix(), path.read_text(encoding="utf-8")


def _code_hits(source: str):
    """Forbidden names in code (identifiers, attributes, strings), not comments or docstrings."""
    tree = ast.parse(source)
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(
            node, (ast.Module, ast.FunctionDef, ast.ClassDef, ast.AsyncFunctionDef)
        ):
            body = getattr(node, "body", [])
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(getattr(body[0], "value", None), ast.Constant)
            ):
                docstrings.add(id(body[0].value))
    for node in ast.walk(tree):
        text = None
        if isinstance(node, ast.Name):
            text = node.id
        elif isinstance(node, ast.Attribute):
            text = node.attr
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            if id(node) in docstrings:
                continue
            text = node.value
        if text and any(name in text for name in FORBIDDEN_NAMES):
            yield node.lineno, text[:80]


def test_no_runtime_code_names_the_symmetric_mechanism():
    found = []
    for rel, source in _runtime_files():
        for line, text in _code_hits(source):
            if not PROSE.search(text):
                found.append(f"{rel}:{line}: {text}")
    assert not found, "\n".join(found)


def test_no_runtime_code_decodes_or_encodes_with_an_hmac_algorithm():
    found = []
    for rel, source in _runtime_files():
        for match in re.finditer(
            r"algorithm(?:s)?\s*=\s*\[?\s*[\"']HS\d{3}[\"']", source
        ):
            found.append(f"{rel}: {match.group(0)}")
    assert not found, "\n".join(found)


def test_verification_has_no_legacy_parameter_and_refusal_no_legacy_field():
    tree = ast.parse(
        (BACKEND_ROOT / "ccure_platform/identity/verification.py").read_text()
    )
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            assert "legacy" not in [
                a.arg for a in node.args.kwonlyargs + node.args.args
            ], node.name
        if isinstance(node, ast.ClassDef) and node.name == "Refusal":
            fields = [t.target.id for t in node.body if isinstance(t, ast.AnnAssign)]
            assert fields == ["reason", "header"], fields


def test_the_signing_settings_are_gone_from_config():
    source = (BACKEND_ROOT / "config.py").read_text()
    for name in (
        "SECRET_KEY",
        "TOKEN_SIGNING_ALG",
        "ACCEPT_LEGACY_HS256",
        "MFA_KEY_SOURCE",
    ):
        assert f"{name}:" not in source and f"{name} =" not in source, name
