"""
Activate the core modules' Alembic branches (Phase 11.3).

Each core module keeps its own migration branch in ``<package>/migrations/``:
``ccure_policy/migrations`` (branch ``policy_pro``) and ``ccure_rank/migrations``
(branch ``rank``). Alembic sees a branch only once ``alembic.ini``'s
``version_locations`` names its folder. That one setting is the activation.

Why it is a separate, deliberate step, and not simply committed with the
branches: ``./Backend`` is bind-mounted into the live API container, and every
API start runs ``db/migrate_production_schema.py`` → ``alembic upgrade heads``.
If ``version_locations`` listed the module folders, the next restart for *any*
reason (a crash, a reboot) would apply the module migrations to the live
database. So the branches, the multi-head handling and the tests are committed
first; activation is its own reviewed change, applied by this script, followed
by one restart.

The rehearsal (``scripts/db/rehearse_module_branches.sh``) uses exactly
``activate()`` on exactly the committed ``alembic.ini``, so what was rehearsed is
what goes live.

    python -m scripts.db.alembic_module_branches --status   # active or not
    python -m scripts.db.alembic_module_branches --print    # the activated file, to stdout
    python -m scripts.db.alembic_module_branches --write    # activate alembic.ini in place
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from ccure_platform.modules import registry

BACKEND_ROOT = Path(__file__).resolve().parents[2]
ALEMBIC_INI = BACKEND_ROOT / "alembic.ini"
MARKER = "# Phase 11.3: each core module's own migration branch (activation)."

_VERSION_LOCATIONS = re.compile(r"^version_locations\s*=.*$", re.MULTILINE)
_PATH_SEPARATOR = re.compile(r"^path_separator\s*=.*$", re.MULTILINE)
_SCRIPT_LOCATION = re.compile(r"^script_location\s*=.*$", re.MULTILINE)


def module_migration_dirs(root: Path = BACKEND_ROOT) -> list[str]:
    """``<package>/migrations`` of every registered module that has one, in
    registry order."""
    return [
        f"{m.package}/migrations"
        for m in registry.modules()
        if (root / m.package / "migrations").is_dir()
    ]


def version_locations_line(root: Path = BACKEND_ROOT) -> str:
    parts = ["%(here)s/alembic/versions"]
    parts += [f"%(here)s/{d}" for d in module_migration_dirs(root)]
    return "version_locations = " + " ".join(parts)


def is_active(text: str, root: Path = BACKEND_ROOT) -> bool:
    match = _VERSION_LOCATIONS.search(text.replace("\r\n", "\n"))
    return bool(match) and match.group(0) == version_locations_line(root)


def activate(text: str, root: Path = BACKEND_ROOT) -> str:
    """The same ini text with the module branches active. Idempotent.

    Two edits: ``version_locations`` lists Audit's history and every module's
    migrations folder (space-separated), and ``path_separator = space`` makes
    Alembic split that list on spaces rather than ``os.pathsep``.
    """
    # The committed alembic.ini uses CRLF line endings; edit on LF and restore
    # them, so the activation changes only the lines it means to.
    newline = "\r\n" if "\r\n" in text else "\n"
    text = text.replace("\r\n", "\n")
    if not _SCRIPT_LOCATION.search(text):
        raise ValueError("alembic.ini has no script_location line")
    line = version_locations_line(root)
    if _VERSION_LOCATIONS.search(text):
        text = _VERSION_LOCATIONS.sub(line, text, count=1)
    else:
        text = _SCRIPT_LOCATION.sub(
            lambda m: f"{m.group(0)}\n\n{MARKER}\n{line}", text, count=1
        )
    if _PATH_SEPARATOR.search(text):
        text = _PATH_SEPARATOR.sub("path_separator = space", text, count=1)
    else:
        text = text.replace(line, f"{line}\npath_separator = space", 1)
    return text.replace("\n", newline)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("--status", action="store_true")
    group.add_argument("--print", action="store_true")
    group.add_argument("--write", action="store_true")
    args = ap.parse_args(argv)
    # Bytes, not read_text(): universal-newline reading would turn the file's
    # CRLF into LF and the activation would rewrite every line.
    text = ALEMBIC_INI.read_bytes().decode("utf-8")
    if args.status:
        print("active" if is_active(text) else "inactive")
        return 0
    activated = activate(text)
    if args.print:
        sys.stdout.buffer.write(activated.encode("utf-8"))
    else:
        ALEMBIC_INI.write_bytes(activated.encode("utf-8"))
        print(f"activated: {version_locations_line()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
