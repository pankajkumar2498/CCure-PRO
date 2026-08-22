"""
Where the compliance catalogue seed files live.

The thirteen ``*_controls_seed.json`` catalogues are data, not code, so they sit
under ``Backend/data/`` beside the other reference data the application ships.
They used to live in ``Backend/scripts/`` alongside the seeders that read them,
which put 1.2 MB of framework definitions in the same directory as the
executable maintenance scripts and made ``scripts/`` look like a data package.

Every consumer resolves the directory through this module rather than spelling
its own ``os.path.join``. That matters more here than it looks: ``main.py``'s
bootstrap condition names all thirteen catalogues, so a seed file it cannot find
makes the condition permanently true and the whole seeder re-runs on every
container start without ever satisfying itself — a failure that shows up as a
slow boot, not an error.
"""

from __future__ import annotations

import glob
import os
from pathlib import Path

#: ``Backend`` — this module lives in ``Backend/core/``.
_BACKEND_ROOT = Path(__file__).resolve().parent.parent

#: The directory holding every ``*_controls_seed.json`` catalogue.
SEEDS_DIR: Path = _BACKEND_ROOT / "data" / "compliance_seeds"

#: The pattern ``seed_compliance`` globs. Catalogues are discovered, never
#: listed by name — two frameworks existed as seed files and were never loaded
#: back when the seeder named its files individually.
SEED_GLOB = "*_controls_seed.json"


def seed_path(filename: str) -> str:
    """Absolute path to one named catalogue, e.g. ``gdpr_controls_seed.json``."""
    return str(SEEDS_DIR / filename)


def all_seed_paths() -> list[str]:
    """Every catalogue on disk, sorted, as absolute paths."""
    return sorted(glob.glob(os.path.join(str(SEEDS_DIR), SEED_GLOB)))


__all__ = ["SEEDS_DIR", "SEED_GLOB", "seed_path", "all_seed_paths"]
