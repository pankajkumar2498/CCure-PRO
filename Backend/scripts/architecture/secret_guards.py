"""
Source guards for how a session secret may be handled, measured with ``ast``.

Two rules, each written after the defect it prevents:

* **Nothing interpolates a value into a command that pipes into sudo.**
  ``echo '<password>' | sudo -S`` puts the password in the argv of the shell
  sshd spawns on the target, where ``ps`` shows it to every local user and an
  ``execve`` audit rule records it. The collectors had it (fixed earlier); the
  compliance remediation executor had a second copy that survived because the
  only guard inspected one module. A sudo password travels on the remote
  command's stdin — ``SSHScanner.run_sudo``.
* **Only an executor touches a session's ``_password``.** A collector or
  service that reads the attribute can rebuild the shape above.

Standard library only, so the pre-commit hook (``scripts/architecture/check.py``)
runs it without the backend's dependencies.
``tests/credentialed/test_sudo_password_safety.py`` asserts the same rules.
"""

from __future__ import annotations

import ast
import os
import re
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[2]

#: A single pipe into sudo. ``|| sudo`` is a shell fallback, not a pipe.
PIPED_SUDO = r"(?<!\|)\|(?!\|)\s*sudo\b"

#: Executors hold their own session's secret. Nothing else reads one.
EXECUTORS_HOLDING_A_PASSWORD = frozenset(
    {
        "engines/credentialed/ssh_scanner.py",
        "engines/credentialed/winrm_executor.py",
        "engines/credentialed/smb_executor.py",
        "engines/credentialed/database_executor.py",
    }
)

_THIS = "scripts/architecture/secret_guards.py"

#: Directories under Backend/ that are not application code.
_SKIP = frozenset(
    {"tests", ".venv", "__pycache__", "alembic", "logs", "reports", "data"}
)


def application_sources(root: Path = BACKEND_ROOT):
    """``(path relative to Backend/, source)`` for every application module,
    scripts included — an operator script handles secrets too.

    Walks with pruning rather than ``rglob``: a local ``Backend/.venv`` holds
    thousands of modules, and descending into it only to discard them is most
    of the cost of a check meant to run on every commit."""
    found = []
    for directory, subdirs, files in os.walk(root):
        subdirs[:] = sorted(
            d for d in subdirs if not d.startswith(".") and d not in _SKIP
        )
        for name in files:
            if name.endswith(".py"):
                found.append(Path(directory, name))
    for path in sorted(found):
        yield path.relative_to(root), path.read_text(encoding="utf-8")


def interpolated_piped_sudo(source: str) -> list[int]:
    """
    Lines where code *builds* a string that pipes into sudo out of a variable —
    an f-string, ``%`` formatting, ``+`` concatenation or ``.format``. That is
    the shape that carries a secret into the command line. A fixed literal (a
    redaction placeholder, a remediation catalogue entry) carries none.
    """
    pattern = re.compile(PIPED_SUDO)
    hits: list[int] = []

    def literal(node) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return None

    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.JoinedStr):
            text = "".join(
                v.value if isinstance(v, ast.Constant) else "{}" for v in node.values
            )
            if any(
                isinstance(v, ast.FormattedValue) for v in node.values
            ) and pattern.search(text):
                hits.append(node.lineno)
        elif isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            sides = [literal(node.left), literal(node.right)]
            if any(s and pattern.search(s) for s in sides) and None in sides:
                hits.append(node.lineno)
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "format"
            and literal(node.func.value)
            and pattern.search(literal(node.func.value))
        ):
            hits.append(node.lineno)
    return sorted(set(hits))


def session_password_reads(rel: Path, source: str) -> list[int]:
    """Lines outside an executor that touch a ``_password`` attribute."""
    # This module names the attribute in order to look for it.
    if rel.as_posix() in EXECUTORS_HOLDING_A_PASSWORD or rel.as_posix() == _THIS:
        return []
    lines = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Attribute) and node.attr == "_password":
            lines.append(node.lineno)
        elif isinstance(node, ast.Constant) and node.value == "_password":
            lines.append(node.lineno)
    return sorted(set(lines))


def violations(root: Path = BACKEND_ROOT) -> list[str]:
    """Every breach of either rule, as ``path:line  what``."""
    found = []
    for rel, source in application_sources(root):
        for line in interpolated_piped_sudo(source):
            found.append(f"{rel}:{line}  builds a piped sudo command from a variable")
        for line in session_password_reads(rel, source):
            found.append(
                f"{rel}:{line}  reads a session's _password outside an executor"
            )
    return found
