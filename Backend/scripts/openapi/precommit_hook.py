"""
Pre-commit hook: regenerate ``Backend/openapi.json`` from the code being
committed and stage it if it changed.

Registered in ``.pre-commit-config.yaml`` as ``openapi-contract``. It runs only
when backend Python files (tests excepted), ``requirements.txt`` or the
contract itself are staged, after the formatting, linting and security hooks.

Standard library only: pre-commit runs this file in its own small environment,
and it launches ``scripts.openapi.generate`` with the backend's Python, which
has FastAPI and the application's dependencies. That interpreter is, in order:

1. ``CCURE_BACKEND_PYTHON``, if set;
2. ``Backend/.venv`` in this checkout;
3. ``Backend/.venv`` in the main checkout, when this is a ``git worktree``.

Pre-commit sets unstaged changes aside while hooks run, so the contract is
generated from exactly what is being committed. Any failure blocks the commit
(exit 1). To commit without a backend environment, ``SKIP=openapi-contract git
commit …``; CI's OpenAPI Schema Diff Check still compares the contract.
"""

from __future__ import annotations

import json
import os
import subprocess  # nosec B404 — fixed argv, no shell
import sys
import tempfile
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = BACKEND_ROOT.parent
CONTRACT = BACKEND_ROOT / "openapi.json"
TIMEOUT_SECONDS = 300


def _venv_python(backend: Path) -> Path | None:
    for candidate in (
        backend / ".venv" / "bin" / "python",
        backend / ".venv" / "Scripts" / "python.exe",
    ):
        if candidate.is_file():
            return candidate
    return None


def _main_checkout() -> Path | None:
    """The main worktree's root, when this checkout is a linked worktree."""
    try:
        common = subprocess.run(  # nosec B603 B607 — fixed argv
            ["git", "rev-parse", "--path-format=absolute", "--git-common-dir"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None
    root = Path(common).parent
    return root if root.resolve() != REPO_ROOT.resolve() else None


def backend_python() -> Path | None:
    explicit = os.environ.get("CCURE_BACKEND_PYTHON")
    if explicit:
        return Path(explicit)
    found = _venv_python(BACKEND_ROOT)
    if found:
        return found
    main = _main_checkout()
    return _venv_python(main / "Backend") if main else None


def _operations(text: str) -> set[str]:
    try:
        paths = json.loads(text).get("paths", {})
    except ValueError:
        return set()
    return {f"{method.upper()} {path}" for path, ops in paths.items() for method in ops}


def describe_change(old: str, new: str) -> str:
    """A line saying which API operations the regeneration added or removed."""
    before, after = _operations(old), _operations(new)
    added, removed = sorted(after - before), sorted(before - after)
    parts = []
    if added:
        parts.append("added " + ", ".join(added[:5]) + (" …" if len(added) > 5 else ""))
    if removed:
        parts.append(
            "removed " + ", ".join(removed[:5]) + (" …" if len(removed) > 5 else "")
        )
    return (
        "; ".join(parts)
        or "schemas or descriptions changed; no operation added or removed"
    )


def fail(message: str) -> int:
    print(f"openapi-contract: {message}", file=sys.stderr)
    print(
        "The commit was stopped. To commit without regenerating, run "
        "SKIP=openapi-contract git commit … and regenerate before the PR; "
        "CI compares the contract either way.",
        file=sys.stderr,
    )
    return 1


def main() -> int:
    python = backend_python()
    if python is None or not python.is_file():
        return fail(
            "no backend Python environment found. Create Backend/.venv and "
            "install Backend/requirements.txt, or set CCURE_BACKEND_PYTHON."
        )

    env = dict(os.environ, SKIP_DOTENV_LOAD="1", PYTHONDONTWRITEBYTECODE="1")
    with tempfile.TemporaryDirectory(prefix="ccure-openapi-") as scratch:
        generated = Path(scratch) / "openapi.json"
        try:
            result = subprocess.run(  # nosec B603 — fixed argv, our interpreter
                [
                    str(python),
                    "-m",
                    "scripts.openapi.generate",
                    "--out",
                    str(generated),
                ],
                cwd=BACKEND_ROOT,
                env=env,
                capture_output=True,
                text=True,
                timeout=TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            return fail(f"generation did not finish in {TIMEOUT_SECONDS}s.")
        if result.returncode != 0 or not generated.is_file():
            detail = "\n".join(
                (result.stderr or result.stdout).strip().splitlines()[-15:]
            )
            return fail(f"generating the contract failed:\n{detail}")
        new = generated.read_text(encoding="utf-8")

    old = CONTRACT.read_text(encoding="utf-8") if CONTRACT.exists() else ""
    if new == old:
        return 0

    CONTRACT.write_text(new, encoding="utf-8", newline="\n")
    staged = subprocess.run(  # nosec B603 B607 — fixed argv
        ["git", "add", "--", str(CONTRACT.relative_to(REPO_ROOT))],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    if staged.returncode != 0:
        return fail(
            f"regenerated Backend/openapi.json but could not stage it: {staged.stderr.strip()}"
        )
    print(
        f"openapi-contract: regenerated and staged Backend/openapi.json ({describe_change(old, new)})."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
