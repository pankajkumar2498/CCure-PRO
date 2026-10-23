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
import json
import logging
import os
from pathlib import Path
from typing import Dict, List, Tuple

#: The logger the NIST seed warning below was written under, in
#: ``core/scap/cci.py`` before G4, kept so the line an operator looks for is
#: unchanged.
log = logging.getLogger("ccure.scap.cci")

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


#: The NIST SP 800-53 Rev. 5 catalogue, which STIG crosswalks name.
NIST_800_53_SEED = "nist_800_53_r5_controls_seed.json"

_KNOWN: Dict[str, Tuple[str, ...]] = {}


def nist_800_53_control_numbers() -> Tuple[str, ...]:
    """
    The control numbers the seeded NIST SP 800-53 Rev. 5 catalogue actually has.

    The SCAP converter checks every NIST crosswalk entry against these, and
    the STIG loader passes them to it (``core.scap.cci.crosswalk_entries``).
    G4 moved this here from ``core/scap/cci.py``: the converter is
    configuration audit's, the catalogue is compliance's.

    Read from the seed rather than from a family list written here, so a
    crosswalk entry cannot name a control this deployment does not hold. The
    alternative — trusting a regular expression over benchmark prose — emitted
    ``DS-1`` and ``DS-6`` from NIST CSF's ``PR.DS-01`` on the first real run.

    An unreadable seed yields an empty tuple, and the caller then emits no
    crosswalk at all rather than an unvalidated one. Losing a crosswalk is
    recoverable; a crosswalk that points nowhere looks like coverage in every
    count that reads the field.
    """
    if "controls" in _KNOWN:
        return _KNOWN["controls"]
    numbers: List[str] = []
    try:
        # ``seed_path`` returns a str. Calling ``.read_text()`` on it raises
        # AttributeError, which the except below swallowed — and the symptom
        # was every crosswalk silently vanishing while the load reported
        # success. Failing open is right here; failing open *quietly* is not,
        # which is why the warning below exists.
        data = json.loads(Path(seed_path(NIST_800_53_SEED)).read_text(encoding="utf-8"))
        for control in data.get("controls") or []:
            number = str(control.get("control_number") or "").strip().upper()
            if number:
                numbers.append(number)
    except Exception as exc:  # a missing seed must not break a benchmark load
        log.warning(
            "The NIST SP 800-53 seed could not be read (%s: %s), so STIG "
            "content will load with no NIST crosswalk. The benchmark is still "
            "usable; its results simply will not roll up to 800-53.",
            type(exc).__name__,
            exc,
        )
        numbers = []
    _KNOWN["controls"] = tuple(sorted(set(numbers)))
    return _KNOWN["controls"]


__all__ = [
    "NIST_800_53_SEED",
    "SEEDS_DIR",
    "SEED_GLOB",
    "all_seed_paths",
    "nist_800_53_control_numbers",
    "seed_path",
]
