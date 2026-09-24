#!/usr/bin/env python3
"""Which fields of a live API response the frontend actually references.

The operation-level sweep (`api_ui_matrix.py`) answers "is this endpoint
called". This answers the other half: **of everything the endpoint returned,
how much reaches the operator.** Phase 1 of the coverage programme found six
fields returned by one endpoint and displayed by nothing, so a surface can be
100% reached at the operation level and still be dropping data.

    python3 scripts/audit/api_field_coverage.py --manifest manifest.json \\
        --payloads /tmp/payloads --surface dashboard

The manifest maps each surface to the files that are allowed to render it:

    {"dashboard": {"files": ["Frontend/src/pages/SecurityDashboard.jsx",
                             "Frontend/src/api/dashboard.js"],
                   "payloads": ["summary", "risk-breakdown"]}}

Five decisions, and the first four are what stop this reporting nonsense:

* **Walk a live response, never a model class.** A declared field that is never
  populated and a populated field that is never declared misreport coverage in
  opposite directions.

* **Scope the search to the files that render the payload.** A whole-frontend
  grep matches `status`, `count` and `name` in fifty unrelated modules and
  reports coverage the operator does not have.

* **Leaf keys, not dotted paths.** JavaScript reaches `a.b.c` by destructuring,
  optional chaining, renaming and index access; searching for the dotted path
  finds almost nothing. The leaf key is what survives every one of those.

* **A key that is a common word is reported as LOW-CONFIDENCE, not as covered.**
  `id`, `name`, `status`, `type`, `total`, `count` and their kind match
  something in any file of any size. Counting them as rendered is how a
  measurement flatters itself; they are listed separately for a human to check.

* **`REFERENCED` is not `RENDERED`.** The tool proves a name appears in a file
  that renders this payload. Whether it reaches the screen is a judgement a
  reader makes on the evidence, and the report says so rather than implying a
  certainty it cannot have.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

#: Keys too common to be evidence of anything on their own.
AMBIGUOUS = {
    "id", "name", "type", "status", "value", "label", "count", "total",
    "data", "items", "results", "key", "title", "date", "time", "url",
    "code", "message", "detail", "error", "state", "size", "index", "text",
    "score", "level", "order", "page", "limit", "offset", "skip", "sort",
}

#: Paths whose contents are not audit information in their own right.
NOISE_PREFIXES = ("request_id",)


def leaf_keys(node, path="", depth=0, max_depth=6, out=None):
    """Every (dotted path, leaf key, type) the response carries."""
    if out is None:
        out = []
    if depth > max_depth:
        return out
    if isinstance(node, dict):
        for key in sorted(node):
            child = f"{path}.{key}" if path else key
            out.append((child, key, type(node[key]).__name__))
            leaf_keys(node[key], child, depth + 1, max_depth, out)
    elif isinstance(node, list):
        # Union the first few elements: a list whose first row happens to carry
        # a null column would otherwise hide every key below it.
        for element in node[:5]:
            if isinstance(element, (dict, list)):
                leaf_keys(element, f"{path}[]", depth + 1, max_depth, out)
    return out


def classify(sources: str, key: str) -> str:
    if key in AMBIGUOUS:
        found = re.search(rf"\b{re.escape(key)}\b", sources) is not None
        return "LOW-CONFIDENCE" if found else "MISSING"
    # `foo_bar` may be read as `fooBar` after a camelCase rename, and as
    # `"foo_bar"` when used as a key. Both count as a reference.
    camel = re.sub(r"_(\w)", lambda m: m.group(1).upper(), key)
    for candidate in {key, camel}:
        if re.search(rf"\b{re.escape(candidate)}\b", sources):
            return "REFERENCED"
    return "MISSING"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--payloads", required=True, help="directory of <name>.json")
    ap.add_argument("--surface", action="append", help="limit to these surfaces")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    here = Path(__file__).resolve()
    repo = next(p for p in here.parents if (p / "Frontend").is_dir())
    manifest = json.loads(Path(args.manifest).read_text())
    payload_dir = Path(args.payloads)

    report = {}
    for surface, spec in manifest.items():
        if args.surface and surface not in args.surface:
            continue

        sources = []
        for rel in spec["files"]:
            path = repo / rel
            if not path.is_file():
                print(f"!! {surface}: missing source {rel}", file=sys.stderr)
                continue
            sources.append(path.read_text(encoding="utf-8", errors="replace"))
        blob = "\n".join(sources)

        per_payload = {}
        for name in spec["payloads"]:
            file = payload_dir / f"{name}.json"
            if not file.is_file():
                print(f"!! {surface}: no payload {name}.json", file=sys.stderr)
                continue
            body = json.loads(file.read_text())
            seen, rows = set(), []
            for dotted, key, kind in leaf_keys(body):
                if dotted.startswith(NOISE_PREFIXES) or key in seen:
                    continue
                seen.add(key)
                rows.append(
                    {"path": dotted, "key": key, "type": kind,
                     "state": classify(blob, key)}
                )
            per_payload[name] = rows
        report[surface] = per_payload

    if args.json:
        json.dump(report, sys.stdout, indent=1)
        return 0

    grand = defaultdict(int)
    for surface, payloads in report.items():
        print(f"\n{'=' * 66}\n{surface.upper()}\n{'=' * 66}")
        for name, rows in payloads.items():
            buckets = defaultdict(list)
            for row in rows:
                buckets[row["state"]].append(row)
                grand[row["state"]] += 1
            total = len(rows)
            ref = len(buckets["REFERENCED"])
            print(f"\n  {name}: {ref}/{total} distinct keys referenced")
            for state in ("MISSING", "LOW-CONFIDENCE"):
                if buckets[state]:
                    print(f"    {state} ({len(buckets[state])}):")
                    for row in buckets[state]:
                        print(f"      {row['path']:<52} {row['type']}")

    print(f"\n{'=' * 66}")
    for state in ("REFERENCED", "LOW-CONFIDENCE", "MISSING"):
        print(f"{state:<16} {grand[state]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
