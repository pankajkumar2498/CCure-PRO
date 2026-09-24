#!/usr/bin/env python3
"""Measure how much of a scan's API response the frontend actually renders.

Two steps, because the response and the page do not live in the same place:

    docker cp scripts/audit/api_ui_coverage.py ccure-api:/tmp/c.py
    docker exec -w /app ccure-api python /tmp/c.py <scan_id> --dump-response /tmp/r.json
    docker cp ccure-api:/tmp/r.json /tmp/r.json
    python3 scripts/audit/api_ui_coverage.py <scan_id> --response /tmp/r.json

Three decisions here are the whole point, and each was wrong in an earlier
version of this measurement:

* **Walk a live response, not a model class.** A declared field that is never
  populated and a populated field that is never declared both misreport
  coverage, in opposite directions.

* **Scope the grep to the page that renders the payload.** A whole-frontend
  grep matches `target`, `users`, `coverage` and `packages` in fifty unrelated
  files and reports coverage the operator does not have.

* **"Destructured" is not "rendered".** A field read out of the response and
  never referenced again is bound and thrown away, which looks identical to
  rendering it if you only count occurrences. That is the BOUND-ONLY state.
"""

from __future__ import annotations

import argparse
import io
import json
import re
import sys
from pathlib import Path

#: Where each payload is rendered, and the marker that ends its destructure.
#: A payload whose page is not listed cannot be measured, and the script says
#: so rather than reporting zero coverage for it.
PAGES = {
    "credentialed": (
        "Frontend/src/pages/scan/CredentialedResults.jsx",
        "} = view;",
    ),
}


def repo_root() -> Path:
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "Frontend").is_dir() and (parent / "Backend").is_dir():
            return parent
    # Inside the API container the repo is split; fall back to the mount.
    return Path("/app").parent


def walk(node, path="", depth=0, max_depth=5, out=None):
    """Every dotted path in the response, with `[]` marking a list element."""
    if out is None:
        out = []
    if depth > max_depth:
        return out
    if isinstance(node, dict):
        for key in sorted(node):
            child = f"{path}.{key}" if path else key
            out.append((child, type(node[key]).__name__))
            walk(node[key], child, depth + 1, max_depth, out)
    elif isinstance(node, list) and node:
        if isinstance(node[0], (dict, list)):
            walk(node[0], f"{path}[]", depth + 1, max_depth, out)
    return out


def classify(page_src: str, body: str, field: str) -> str:
    whole = len(re.findall(rf"\b{re.escape(field)}\b", page_src))
    below = len(re.findall(rf"\b{re.escape(field)}\b", body))
    if whole == 0:
        return "MISSING"
    if below == 0:
        return "BOUND-ONLY"
    return "RENDERED"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("scan_id")
    ap.add_argument(
        "--payload",
        default="credentialed",
        choices=sorted(PAGES),
        help="which section of the scan response to measure",
    )
    ap.add_argument(
        "--fail-on-missing",
        action="store_true",
        help="exit non-zero when any field is unrendered — for CI",
    )
    # The two halves of this measurement do not live in the same place. The
    # response comes from the API image, which has no Frontend mount; the page
    # lives in the checkout, which has no database. So the response is dumped
    # in the container and measured on the host, rather than pretending one
    # process can see both.
    ap.add_argument(
        "--dump-response",
        metavar="PATH",
        help="write the live response to PATH and stop (run inside the API container)",
    )
    ap.add_argument(
        "--response",
        metavar="PATH",
        help="measure a previously dumped response instead of querying the database",
    )
    args = ap.parse_args()

    if args.response:
        response = json.loads(io.open(args.response, encoding="utf-8").read())
    else:
        from db.base import SessionLocal
        from scans.legacy_json_builder import build_legacy_scan_results

        db = SessionLocal()
        try:
            response = build_legacy_scan_results(db, args.scan_id) or {}
        finally:
            db.close()

    if args.dump_response:
        io.open(args.dump_response, "w", encoding="utf-8").write(
            json.dumps(response, default=str)
        )
        print(f"wrote {args.dump_response}")
        return 0

    section = response.get(args.payload) or {}
    report = section.get("report") or {}
    if not report:
        print(f"scan {args.scan_id} carries no '{args.payload}' report")
        return 2

    root = repo_root()
    page_rel, destructure_end = PAGES[args.payload]
    page_path = root / page_rel
    if not page_path.is_file():
        print(f"cannot read {page_path} — run this from a checkout, not the API image")
        return 2

    page_src = io.open(page_path, encoding="utf-8").read()
    lines = page_src.splitlines()
    cut = 0
    for i, line in enumerate(lines):
        if line.strip() == destructure_end:
            cut = i
    body = "\n".join(lines[cut:])

    fields = sorted(k for k in report)
    buckets: dict[str, list[str]] = {"RENDERED": [], "BOUND-ONLY": [], "MISSING": []}

    print(f"{'API FIELD':<32} STATUS")
    print("-" * 52)
    for field in fields:
        state = classify(page_src, body, field)
        buckets[state].append(field)
        print(f"{field:<32} {state}")

    total = len(fields)
    print()
    print(f"Top-level fields: {total}")
    for state in ("RENDERED", "BOUND-ONLY", "MISSING"):
        print(f"{state:<12}: {len(buckets[state])}")
    for state in ("BOUND-ONLY", "MISSING"):
        if buckets[state]:
            print(f"{state}: {', '.join(buckets[state])}")

    # Nested counts worth stating, because a rendered top-level key says
    # nothing about whether its contents reached the operator.
    nested = walk(report)
    print(f"\nNested paths below the top level: {len(nested)}")

    unrendered = buckets["MISSING"] + buckets["BOUND-ONLY"]
    if args.fail_on_missing and unrendered:
        print(f"\nFAIL: {len(unrendered)} field(s) not rendered")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
