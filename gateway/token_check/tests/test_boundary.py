"""
What gateway-auth may depend on, and what its image may contain.

* It imports the standard library, ``cryptography``, the shared rules
  (``ccure_platform.identity.verification``) and itself — never a JWT library
  directly, never the core's configuration, keys, tokens, database or Redis.
* Its image is built from an allow-list: nothing but its own sources and the
  three ``ccure_platform`` files can reach the build context.
"""

from __future__ import annotations

import ast
import os
import sys
from pathlib import Path

PACKAGE = Path(__file__).resolve().parent.parent
ALLOWED_THIRD_PARTY = {"cryptography"}
ALLOWED_FIRST_PARTY = {"ccure_platform.identity.verification", "ccure_platform.identity",
                       "token_check"}
FORBIDDEN = {"jose", "jwt", "config", "dotenv", "db", "sqlalchemy", "redis", "celery",
             "fastapi", "main", "core", "routers", "auth"}


def _sources():
    return sorted(p for p in PACKAGE.glob("*.py"))


def _imports(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name, None
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                yield node.module, alias.name


def test_imports_are_confined():
    stdlib = set(sys.stdlib_module_names)
    offenders = []
    for path in _sources():
        for module, name in _imports(path):
            root = module.split(".")[0]
            full = f"{module}.{name}" if name else module
            if root in FORBIDDEN:
                offenders.append(f"{path.name}: {full}")
            elif root in stdlib or root in ALLOWED_THIRD_PARTY:
                continue
            elif root == "ccure_platform":
                if full not in ("ccure_platform.identity.verification",) and not (
                    module == "ccure_platform.identity" and name == "verification"
                ):
                    offenders.append(f"{path.name}: {full}")
            elif root != "token_check":
                offenders.append(f"{path.name}: {full}")
    assert not offenders, offenders


def test_the_legacy_secret_is_never_passed():
    """Every verification call in the service passes legacy=None."""
    source = (PACKAGE / "app.py").read_text()
    assert "legacy=None" in source
    assert "LegacyHS256" not in source


def test_the_image_context_is_an_allow_list():
    ignore = (PACKAGE / "Dockerfile.dockerignore").read_text().splitlines()
    rules = [line.strip() for line in ignore if line.strip() and not line.startswith("#")]
    assert rules[0] == "*", "the ignore file must exclude everything first"
    allowed = {r[1:] for r in rules[1:]}
    assert all(r.startswith("!") for r in rules[1:])
    assert allowed == {
        "gateway/token_check/requirements.txt",
        "gateway/token_check/__init__.py",
        "gateway/token_check/config.py",
        "gateway/token_check/jwks.py",
        "gateway/token_check/checker.py",
        "gateway/token_check/app.py",
        "Backend/ccure_platform/__init__.py",
        "Backend/ccure_platform/identity/__init__.py",
        "Backend/ccure_platform/identity/verification.py",
    }
    for entry in allowed:
        assert not any(s in entry for s in (".env", "key", "secret", "pem")), entry


def test_the_image_runs_unprivileged_without_an_access_log():
    dockerfile = (PACKAGE / "Dockerfile").read_text()
    assert "USER 10001:10001" in dockerfile
    assert "--no-access-log" in dockerfile and "--no-server-header" in dockerfile
    assert "@sha256:" in dockerfile.split("FROM", 1)[1].splitlines()[0]
    copied = [line for line in dockerfile.splitlines() if line.startswith("COPY")]
    assert not any(".env" in line or "keys" in line.lower() for line in copied)


def test_the_packaged_rules_are_import_free_packages():
    """The two package __init__ files copied into the image import nothing."""
    backend = Path(os.environ.get("CCURE_BACKEND_ROOT", "/backend"))
    for rel in ("ccure_platform/__init__.py", "ccure_platform/identity/__init__.py"):
        path = backend / rel
        if not path.exists():
            continue
        assert not list(_imports(path)), rel
