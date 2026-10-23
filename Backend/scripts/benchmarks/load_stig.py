"""
scripts/benchmarks/load_stig.py
─────────────────────────────────────────────────────────────────────────────
Convert published SCAP content into a benchmark pack, and optionally load it.

    # inspect what a datastream would produce, writing nothing
    python -m scripts.benchmarks.load_stig ssg-rhel9-ds.xml --profile stig \\
        --publisher "SCAP Security Guide" --licence BSD-3-Clause

    # write a reviewable pack file
    python -m scripts.benchmarks.load_stig ssg-rhel9-ds.xml --profile stig \\
        --publisher "SCAP Security Guide" --licence BSD-3-Clause \\
        --out data/benchmarks/stig_rhel9.benchmark.json

    # load straight into the compliance catalogue
    python -m scripts.benchmarks.load_stig ssg-rhel9-ds.xml --profile stig \\
        --publisher "SCAP Security Guide" --licence BSD-3-Clause --load

Where the content comes from
────────────────────────────
Nothing is bundled and nothing is downloaded by this script. Two sources are
freely available and neither needs a licence negotiation, which is what makes
GAP-05 different from GAP-04:

- **DISA**, ``https://public.cyber.mil/stigs/downloads/`` — the STIG itself,
  and its SCAP benchmark, as a US Government work.
- **SCAP Security Guide**, ``https://github.com/ComplianceAsCode/content`` —
  BSD-3-Clause, publishing an ``xccdf_org.ssgproject.content_profile_stig``
  profile for each supported operating system.

``--publisher`` and ``--licence`` are **required** and have no defaults. They
are a claim about provenance this code cannot verify, and the difference
matters: a result from SSG's STIG profile is SSG's rendering of the STIG's
requirements, not a DISA certification, and a report has to be able to say
which one it ran. Both end up on the framework record.

Why dry run is the default
──────────────────────────
Converting a 28 MB datastream produces several hundred controls, of which some
are automated and some are not. The tally is the interesting output: it says
what this build can and cannot evaluate in *this* content, with a reason for
every gap. Loading before reading that is loading a benchmark whose coverage
nobody has looked at.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.benchmarks import dump_pack  # noqa: E402
from core.compliance_catalogue.benchmark_loader import load_pack_into_db  # noqa: E402
from core.benchmarks.pack import PackError  # noqa: E402
from core.compliance_seeds import nist_800_53_control_numbers  # noqa: E402
from core.scap import load_content, parse_cci_list, to_pack  # noqa: E402
from core.scap.xccdf import XccdfError  # noqa: E402


def _default_code(path: Path, profile: str) -> str:
    """``ssg-rhel9-ds.xml`` + ``stig`` → ``STIG_RHEL9``."""
    stem = path.stem
    for prefix in ("ssg-", "U_", "scap-"):
        if stem.startswith(prefix):
            stem = stem[len(prefix) :]
    for suffix in ("-ds", "-xccdf", "_Manual_STIG", "-oval"):
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
    cleaned = "".join(ch if ch.isalnum() else "_" for ch in stem).strip("_")
    return f"{profile.upper()}_{cleaned.upper()}" if profile else cleaned.upper()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("content", help="SCAP datastream, or an XCCDF benchmark")
    parser.add_argument(
        "--oval",
        action="append",
        default=[],
        help="OVAL document, for a bare XCCDF benchmark. A datastream needs none.",
    )
    parser.add_argument(
        "--profile",
        default="stig",
        help="XCCDF profile to convert; the short label is enough (default: stig)",
    )
    parser.add_argument(
        "--code", help="benchmark code (default: derived from the file)"
    )
    parser.add_argument(
        "--publisher",
        required=True,
        help="who published this content — recorded on the framework",
    )
    parser.add_argument(
        "--licence",
        required=True,
        help="the licence the content is supplied under, e.g. BSD-3-Clause",
    )
    parser.add_argument("--source-url", default="", help="where the content came from")
    parser.add_argument(
        "--expected-digest",
        default="",
        help="SHA-256 the content file must have; a mismatch is refused",
    )
    parser.add_argument(
        "--cci-list",
        help="DISA U_CCI_List.xml, to crosswalk CCIs onto NIST SP 800-53",
    )
    parser.add_argument(
        "--applies-to-name",
        action="append",
        default=[],
        help=(
            "override the OS-name substrings the benchmark targets. Supply this "
            "deliberately to run a vendor's benchmark against a rebuild — "
            "nothing infers that two distributions are interchangeable."
        ),
    )
    parser.add_argument(
        "--applies-to-version",
        action="append",
        default=[],
        help="override the OS version prefixes the benchmark targets",
    )
    parser.add_argument("--out", help="write the converted pack to this file")
    parser.add_argument(
        "--load", action="store_true", help="load the pack into the catalogue"
    )
    parser.add_argument(
        "--show-reasons",
        type=int,
        default=12,
        help="how many unimplemented reasons to list (default 12)",
    )
    args = parser.parse_args()

    path = Path(args.content)
    try:
        content = load_content(
            path,
            oval_paths=[Path(p) for p in args.oval],
            expected_digest=args.expected_digest,
        )
    except (XccdfError, OSError) as exc:
        print(f"could not read {path}: {exc}")
        return 2

    cci_index = None
    if args.cci_list:
        try:
            cci_index = parse_cci_list(Path(args.cci_list).read_bytes())
        except (ValueError, OSError) as exc:
            print(f"could not read the CCI list: {exc}")
            return 2

    applies_to: Optional[Dict[str, Any]] = None
    if args.applies_to_name or args.applies_to_version:
        applies_to = {}
        if args.applies_to_name:
            applies_to["os_name_contains"] = [n.lower() for n in args.applies_to_name]
        if args.applies_to_version:
            applies_to["os_version_prefix"] = list(args.applies_to_version)

    code = args.code or _default_code(path, args.profile)
    try:
        pack, report = to_pack(
            content,
            code=code,
            publisher=args.publisher,
            licence=args.licence,
            profile_id=args.profile,
            applies_to=applies_to,
            source_url=args.source_url,
            cci_index=cci_index,
            nist_controls=nist_800_53_control_numbers(),
        )
    except PackError as exc:
        print(f"could not convert {path}: {exc}")
        return 2

    counts = pack.counts()
    print(f"content   : {path.name}")
    print(f"digest    : sha256:{content.digest}")
    print(f"benchmark : {pack.name}")
    print(f"code      : {pack.code}   version: {pack.version}")
    print(f"publisher : {pack.publisher}   licence: {pack.licence}")
    print(f"profile   : {args.profile}")
    print(f"targeting : {dict(pack.applies_to) or '(none — every Linux host)'}")
    print()
    print(f"controls  : {counts['total']}")
    print(f"  automated     : {counts['automated']}  ({pack.automation_pct()}%)")
    print(f"  manual        : {counts['manual']}")
    print(f"  unimplemented : {counts['unimplemented']}")
    crosswalked = sum(1 for c in pack.controls if c.crosswalk)
    print(f"  with a NIST SP 800-53 crosswalk : {crosswalked}")
    print()

    if report.test_types:
        print("OVAL test types the automated rules use:")
        for name, count in sorted(report.test_types.items()):
            print(f"  {count:5d}  {name}")
        print()

    if report.reasons and args.show_reasons:
        print("why the rest are not automated:")
        ranked = sorted(report.reasons.items(), key=lambda kv: -kv[1])
        for reason, count in ranked[: args.show_reasons]:
            print(f"  {count:5d}  {reason}")
        print()

    if not pack.applies_to:
        print(
            "!! this benchmark declares no operating-system targeting, so every "
            "rule would run against every Linux host in the estate. Supply "
            "--applies-to-name / --applies-to-version before loading it."
        )

    if args.out:
        destination = Path(args.out)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            json.dumps(dump_pack(pack), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        print(f"wrote {destination}")

    if args.load:
        from db.base import SessionLocal

        session = SessionLocal()
        try:
            result = load_pack_into_db(session, pack)
            session.commit()
            print(f"loaded: {result.as_dict()}")
        except Exception as exc:
            session.rollback()
            print(f"load failed, nothing written: {exc}")
            return 1
        finally:
            session.close()
    elif not args.out:
        print("(dry run — nothing written; pass --out or --load)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
