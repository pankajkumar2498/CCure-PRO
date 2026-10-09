"""
Generate ``Backend/openapi.json``, the tracked API contract, from the code.

CI's "OpenAPI Schema Diff Check" (``.github/workflows/ci.yml``) regenerates the
contract and fails on any byte of difference from the tracked file. This writes
exactly what that step produces: ``json.dumps(app.openapi(), sort_keys=True,
indent=2, ensure_ascii=False)`` followed by one newline, UTF-8, LF.

    cd Backend
    python -m scripts.openapi.generate            # write openapi.json
    python -m scripts.openapi.generate --check    # exit 1 if it is stale

Three things that made hand-made copies fail CI, each of which this rules out:

- **Different serialisation.** Without ``sort_keys`` and ``indent`` the file is
  one line in insertion order; without ``ensure_ascii=False`` every non-ASCII
  character is escaped. ``DUMPS_KWARGS`` is the one copy, and
  ``tests/repo/test_openapi_contract_hook.py`` pins it to CI's.
- **The console.** Redirecting ``print`` writes the console's encoding and, on
  Windows, CRLF. The file is written directly instead.
- **A different FastAPI or Pydantic.** The schema is rendered by those
  libraries, so another version renders other bytes, which CI rejects. This
  refuses to write unless the installed versions are the ones
  ``requirements.txt`` pins.

The contract does not depend on configuration: it is the same with and without
``Backend/.env`` and needs no database or Redis (measured 8 Oct 2026).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from importlib import metadata
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[2]
CONTRACT = BACKEND_ROOT / "openapi.json"
REQUIREMENTS = BACKEND_ROOT / "requirements.txt"

# Identical to the json.dumps call in ci.yml's OpenAPI Schema Diff Check.
DUMPS_KWARGS = {"sort_keys": True, "indent": 2, "ensure_ascii": False}

# The libraries that render the schema. Starlette follows from FastAPI's pin.
RENDERING_PACKAGES = ("fastapi", "pydantic")


def pinned_versions(requirements: Path = REQUIREMENTS) -> dict[str, str]:
    """``name==version`` pins in requirements.txt for the rendering packages."""
    pins: dict[str, str] = {}
    for line in requirements.read_text(encoding="utf-8").splitlines():
        match = re.match(r"\s*([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?\s*==\s*([^\s;#]+)", line)
        if match and match.group(1).lower() in RENDERING_PACKAGES:
            pins[match.group(1).lower()] = match.group(2)
    return pins


def version_mismatches() -> list[str]:
    """One line per rendering package whose installed version is not pinned."""
    problems = []
    for name, wanted in pinned_versions().items():
        try:
            installed = metadata.version(name)
        except metadata.PackageNotFoundError:
            installed = "not installed"
        if installed != wanted:
            problems.append(
                f"{name} {installed} is installed; requirements.txt pins {wanted}"
            )
    return problems


def render() -> str:
    """The contract exactly as CI generates it, newline included."""
    from main import app  # noqa: PLC0415 — the live application, as in CI

    return json.dumps(app.openapi(), **DUMPS_KWARGS) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--out",
        type=Path,
        default=CONTRACT,
        help="where to write the contract (default: Backend/openapi.json)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="write nothing; exit 1 if the tracked contract is stale",
    )
    args = parser.parse_args(argv)

    problems = version_mismatches()
    if problems:
        print(
            "Refusing to generate the API contract: it would not match what CI "
            "generates.\n  " + "\n  ".join(problems) + "\nInstall the pinned "
            "versions (pip install -r Backend/requirements.txt) and try again.",
            file=sys.stderr,
        )
        return 2

    text = render()
    if args.check:
        current = CONTRACT.read_text(encoding="utf-8") if CONTRACT.exists() else None
        if current != text:
            print(
                "Backend/openapi.json is stale; run: python -m scripts.openapi.generate",
                file=sys.stderr,
            )
            return 1
        return 0

    args.out.write_text(text, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
