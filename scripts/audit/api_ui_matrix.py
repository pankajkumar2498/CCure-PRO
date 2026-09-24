#!/usr/bin/env python3
"""Which API operations the frontend reaches, and which it does not.

Two steps, because the route table lives inside the container and the frontend
does not:

    docker cp scripts/audit/api_surface_inventory.py ccure-api:/tmp/i.py
    docker exec -w /app ccure-api python /tmp/i.py > /tmp/routes.json
    python3 scripts/audit/api_ui_matrix.py --routes /tmp/routes.json

Four decisions here, each of which a simpler version of this measurement got
wrong:

* **Match paths, not words.** Grepping the frontend for `summary` or `assets`
  matches dozens of unrelated files and reports reach the operator does not
  have. Every candidate is a path literal beginning with `/`, normalised on
  both sides so `` `/scans/${id}/policy` `` and `/scans/{scan_id}/policy`
  compare equal.

* **Resolve the module's own constants.** Nearly every API module is written
  as ``const BASE = "/scan-policies"`` and then `` `${BASE}/settings` ``. A
  matcher that does not substitute those sees `${BASE}/settings`, matches
  nothing, and reports a fully wired module as entirely unreached.

* **Ignore the test tree.** A path that appears only in a test is asserted
  about, not offered to anybody. Counting it is how a measurement reports
  coverage that exists only in CI.

* **Collapse the trailing-slash twins.** FastAPI registers `/x` and `/x/`
  separately where a router declares both; they are one operation to an
  operator and counting them twice inflates both halves of the ratio.

The output is the matrix, grouped by tag, plus the unreached list. Nothing is
inferred about *why* a route is unreached — that is the reviewer's judgement
and belongs in the phase document, not in a script.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

#: A path literal in JS. Three shapes rather than one, because a template
#: literal can hold an arbitrary expression and can begin with one:
#:
#:  * the first version used a single character class with no parentheses, so
#:    `` `${BASE}/findings/${encodeURIComponent(id)}/history` `` never matched
#:    and six fully wired Remediation operations were reported as unreached;
#:  * the second excluded newlines, so
#:    `` `/compliance/frameworks/${fwId}/controls${ ... }` `` — whose
#:    interpolation is wrapped across lines — was dropped;
#:  * and a literal beginning `` `${prefix}/notifications/stream` `` does not
#:    start with `/` at all, which is how the SSE endpoints looked unreached.
#:
#: A measurement's own false negatives are indistinguishable from the gap it
#: is looking for, so all three are handled explicitly.
TEMPLATE = re.compile(r"`([^`]{0,300}?)`", re.DOTALL)
QUOTED = (
    re.compile(r"'(/[^'\n]*)'"),
    re.compile(r'"(/[^"\n]*)"'),
)
#: A template literal opening with an interpolation: take what follows it.
LEADING_HOLE = re.compile(r"^\$\{[^}]*\}(/.*)$", re.DOTALL)


def candidates(text: str):
    """Every path-shaped literal in a source file."""
    for pattern in QUOTED:
        yield from pattern.findall(text)
    for body in TEMPLATE.findall(text):
        if body.startswith("/"):
            yield body
            continue
        hole = LEADING_HOLE.match(body)
        if hole:
            yield hole.group(1)


#: `const NAME = "/literal";` — the module-level bases the API files use.
CONST_PATH = re.compile(
    r"""^\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*["'`](/[^"'`]*)["'`]""",
    re.MULTILINE,
)

SKIP_DIRS = {"__tests__", "node_modules", "dist", "coverage"}


def normalise(path: str) -> str:
    """One spelling for a path, whichever side it came from.

    `${anything}` and `{anything}` both become `{}`, a query string is dropped,
    and a trailing slash is removed — `/x` and `/x/` are one operation.
    """
    path = re.sub(r"\$\{[^{}]*\}", "{}", path, flags=re.DOTALL)
    # A `${` still standing means an interpolation this matcher could not
    # close — in practice a nested template literal, as in
    # `` `/compliance/frameworks/${fwId}/controls${cond ? `?${qs}` : ""}` ``.
    # The path up to that point is still a real path, and what follows is a
    # query string or a suffix, so it is truncated rather than discarded.
    # Resolving it properly would need a JS tokeniser, which is more machinery
    # than a one-off audit earns.
    if "${" in path:
        path = path.split("${", 1)[0]
    path = path.split("?", 1)[0]
    path = re.sub(r"\{[^}]*\}", "{}", path)
    path = re.sub(r"/+", "/", path)
    if len(path) > 1:
        path = path.rstrip("/")
    return path


def frontend_paths(root: Path) -> dict[str, set[str]]:
    """Every API path the frontend names, mapped to the files naming it."""
    found: dict[str, set[str]] = defaultdict(set)
    for file in root.rglob("*"):
        if file.suffix not in (".js", ".jsx", ".ts", ".tsx"):
            continue
        if any(part in SKIP_DIRS for part in file.parts):
            continue
        text = file.read_text(encoding="utf-8", errors="replace")

        # Substitute this file's own path constants before extracting, so
        # `${BASE}/settings` resolves rather than being discarded.
        consts = dict(CONST_PATH.findall(text))
        for name, value in consts.items():
            text = text.replace("${" + name + "}", value)

        rel = str(file.relative_to(root.parent.parent))
        for raw in candidates(text):
            if raw.startswith("//"):  # protocol-relative URL, not a route
                continue
            found[normalise(raw)].add(rel)
    return found


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--routes", required=True, help="routes.json from the API container")
    ap.add_argument("--frontend", default=None)
    ap.add_argument("--json", action="store_true", help="emit the matrix as JSON")
    args = ap.parse_args()

    here = Path(__file__).resolve()
    repo = next(p for p in here.parents if (p / "Frontend").is_dir())
    src = Path(args.frontend) if args.frontend else repo / "Frontend" / "src"

    routes = json.loads(Path(args.routes).read_text())
    seen = frontend_paths(src)

    # One row per (normalised path, method), so the trailing-slash twins and
    # the duplicate registrations collapse into the operation they are.
    ops: dict[tuple[str, str], dict] = {}
    for row in routes:
        key_path = normalise(row["path"])
        for method in row["methods"]:
            key = (key_path, method)
            existing = ops.get(key)
            if existing is None:
                ops[key] = {
                    "path": key_path,
                    "method": method,
                    "tag": (row["tags"] or ["(untagged)"])[0],
                    "name": row["name"],
                    "permissions": row["permissions"],
                    "roles": row["roles"],
                    "authenticated": row["authenticated"],
                }
            else:
                existing["permissions"] = sorted(
                    set(existing["permissions"]) | set(row["permissions"])
                )

    for op in ops.values():
        op["files"] = sorted(seen.get(op["path"], ()))
        op["reached"] = bool(op["files"])

    by_tag: dict[str, list[dict]] = defaultdict(list)
    for op in ops.values():
        by_tag[op["tag"]].append(op)

    if args.json:
        json.dump(
            {
                "total": len(ops),
                "reached": sum(1 for o in ops.values() if o["reached"]),
                "operations": sorted(
                    ops.values(), key=lambda o: (o["tag"], o["path"], o["method"])
                ),
            },
            sys.stdout,
            indent=1,
        )
        return 0

    total = len(ops)
    reached = sum(1 for o in ops.values() if o["reached"])
    print(f"{reached}/{total} operations reached by the frontend\n")

    print(f"{'tag':38} {'reached':>9} {'total':>6}")
    print("-" * 56)
    for tag in sorted(by_tag, key=lambda t: (-len(by_tag[t]), t)):
        rows = by_tag[tag]
        hit = sum(1 for r in rows if r["reached"])
        flag = "" if hit == len(rows) else "   <-"
        print(f"{tag:38} {hit:>9} {len(rows):>6}{flag}")

    print("\nUNREACHED\n" + "-" * 56)
    for tag in sorted(by_tag):
        missing = sorted(
            (r for r in by_tag[tag] if not r["reached"]),
            key=lambda r: (r["path"], r["method"]),
        )
        if not missing:
            continue
        print(f"\n[{tag}]")
        for row in missing:
            perm = ",".join(row["permissions"]) or (
                "role:" + ",".join(row["roles"]) if row["roles"] else "-"
            )
            print(f"  {row['method']:6} {row['path']:52} {perm}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
