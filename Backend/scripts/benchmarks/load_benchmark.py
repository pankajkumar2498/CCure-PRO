"""
scripts/benchmarks/load_benchmark.py
─────────────────────────────────────────────────────────────────────────────
Load a hardening benchmark pack into the compliance catalogue.

    python -m scripts.benchmarks.load_benchmark data/benchmarks/*.benchmark.json
    python -m scripts.benchmarks.load_benchmark --dir data/benchmarks
    python -m scripts.benchmarks.load_benchmark --dry-run <pack>

Dry run is not the default here, unlike the audit-retention scripts: loading a
benchmark writes catalogue rows and deletes nothing, so the risk profile is
"a framework appears" rather than "history is destroyed". It is available
because validating a converted CIS export before committing to it is exactly
what somebody will want to do first.

Loading real CIS Benchmark content
──────────────────────────────────
This repository ships no CIS Benchmark. The recommendation text, rationale and
remediation are the Center for Internet Security's, distributed under licence,
and writing them from memory would put invented control ids and expected values
into a customer's audit report.

A licensed export — CIS-CAT's content, a CIS WorkBench download, or an XCCDF
datastream — converts into this format. ``data/benchmarks/README.md`` documents
the schema field by field. The two packs that ship are CCURE's own baseline and
say so in their ``publisher`` and ``licence``.

Every pack is validated before anything is written, and all packs load in one
transaction. A pack that fails halfway would otherwise leave a framework whose
control count is short — which scores better than the complete one and gives no
sign that it is incomplete.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.benchmarks import (  # noqa: E402
    BenchmarkPack,
    PackError,
    discover_packs,
    load_pack,
)
from core.benchmarks.loader import load_pack_into_db  # noqa: E402
from db.base import SessionLocal  # noqa: E402


def _resolve(args) -> List[Path]:
    paths: List[Path] = [Path(p) for p in args.packs]
    if args.dir:
        paths.extend(discover_packs(args.dir))
    return sorted(set(paths))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packs", nargs="*", help="pack files to load")
    parser.add_argument("--dir", help="load every *.benchmark.json in a directory")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="validate and report, write nothing",
    )
    args = parser.parse_args()

    paths = _resolve(args)
    if not paths:
        parser.error("name at least one pack, or pass --dir")

    # Parse every pack before opening a transaction. A malformed third pack
    # should not leave the first two half-loaded, and parsing is where almost
    # every problem surfaces.
    packs: List[BenchmarkPack] = []
    for path in paths:
        try:
            packs.append(load_pack(path))
        except PackError as exc:
            print(f"REFUSED  {path}: {exc}", file=sys.stderr)
            return 2

    for pack in packs:
        counts = pack.counts()
        print(
            f"{pack.code} v{pack.version} ({pack.platform}) — "
            f"{counts['total']} controls: {counts['automated']} automated, "
            f"{counts['manual']} manual, {counts['unimplemented']} unimplemented "
            f"({pack.automation_pct()}% automated)"
        )
        print(f"    publisher: {pack.publisher}")
        print(f"    licence:   {pack.licence}")
        if pack.profiles:
            print(
                "    profiles:  "
                + ", ".join(
                    f"{p.id} ({len(pack.controls_in_profile(p.id))} controls)"
                    for p in pack.profiles
                )
            )

    if args.dry_run:
        print("\nDry run: nothing written.")
        return 0

    db = SessionLocal()
    try:
        for pack in packs:
            result = load_pack_into_db(db, pack, commit=False)
            print(
                f"\n{pack.code}: {result.controls_created} control(s) created, "
                f"{result.controls_updated} updated; {result.rules_created} rule(s) "
                f"created, {result.rules_updated} updated, "
                f"{result.rules_archived} archived; "
                f"{result.links_created} new rule→control link(s)"
            )
        db.commit()
        print("\nCommitted.")
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        print(f"\nFAILED, rolled back: {exc}", file=sys.stderr)
        return 1
    finally:
        db.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
