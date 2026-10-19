"""
What importing a module really loads, measured by importing it.

    python -m scripts.architecture.import_cost routers.web_scans core.discovery.engine   # from Backend/
    python -m scripts.architecture.import_cost --json MOD... > before.json
    python -m scripts.architecture.import_cost --compare before.json after.json

The capability map (``capability_map.py``) reads load profiles statically, from
import statements. This is the other half: each module is imported in a fresh
interpreter and the modules that appear in ``sys.modules`` are counted. A lazy
import inside a function is invisible here until it runs, and an alias in
``sys.modules`` is counted once; both are why the two measurements are kept
side by side rather than one replacing the other.

For each module it reports:

* ``first_party`` — modules loaded from this ``Backend/`` tree;
* ``all`` — every module loaded, the standard library and dependencies included;
* ``heavy`` — which of a fixed list of large or infrastructure-bound packages
  loaded (``HEAVY``): the network and report toolchains, the database and
  broker clients, the web framework;
* ``watched`` — for each ``--watch MODULE``, whether that module loaded;
* ``first_party_modules`` — the names, with ``--list``.

Reproducibility. Each probe runs ``sys.executable`` with ``Backend/`` as its
working directory and ``SKIP_DOTENV_LOAD=1``, so ``Backend/.env`` is not read,
and nothing is connected to: importing a module opens no database or broker
connection in this codebase. The counts depend on the interpreter and the
installed packages, so a comparison is only meaningful between two runs in the
same environment; ``python`` in the output records which one. The output is
sorted and carries no timestamp.

``--compare`` prints the change for every module in either file and exits 0;
it is a measurement, not a gate.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[2]

#: Packages whose presence is the point of a measurement: what a scan engine,
#: a renderer or a router should not need to load. Top-level names only.
HEAVY = (
    "celery",
    "docx",
    "fastapi",
    "impacket",
    "nmap",
    "openpyxl",
    "paramiko",
    "playwright",
    "psycopg2",
    "redis",
    "reportlab",
    "scapy",
    "sqlalchemy",
    "sslyze",
)

# Runs in the child. Reads the module to import, the heavy list and the watch
# list from argv, and prints one JSON line.
_PROBE = r"""
import json, os, sys
module, heavy, watch, want_list = sys.argv[1], sys.argv[2].split(","), sys.argv[3], sys.argv[4]
watch = [w for w in watch.split(",") if w]
before = set(sys.modules)
import importlib
try:
    importlib.import_module(module)
except BaseException as exc:
    print(json.dumps({"error": f"{type(exc).__name__}: {exc}"}))
    sys.exit(0)
loaded = set(sys.modules) - before
root = os.getcwd() + os.sep
def first_party(name):
    path = getattr(sys.modules.get(name), "__file__", None) or ""
    return path.startswith(root) and (os.sep + ".venv" + os.sep) not in path
names = sorted(n for n in loaded if first_party(n))
result = {
    "first_party": len(names),
    "all": len(loaded),
    "heavy": sorted({n.split(".")[0] for n in loaded} & set(heavy)),
    "watched": {w: w in sys.modules for w in watch},
}
if want_list == "1":
    result["first_party_modules"] = names
print(json.dumps(result, sort_keys=True))
"""


def measure(
    modules: list[str], watch: list[str] | None = None, list_modules: bool = False
) -> dict:
    """Import each module in a fresh interpreter; return the counts per module."""
    env = dict(os.environ)
    env.setdefault("SKIP_DOTENV_LOAD", "1")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    results = {}
    for module in modules:
        done = subprocess.run(
            [
                sys.executable,
                "-c",
                _PROBE,
                module,
                ",".join(HEAVY),
                ",".join(watch or []),
                "1" if list_modules else "0",
            ],
            cwd=BACKEND_ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        lines = [line for line in done.stdout.splitlines() if line.startswith("{")]
        if done.returncode or not lines:
            tail = (done.stderr.strip().splitlines() or ["no output"])[-1]
            results[module] = {"error": tail}
        else:
            results[module] = json.loads(lines[-1])
    return {
        "python": sys.version.split()[0],
        "heavy_list": list(HEAVY),
        "modules": results,
    }


def compare(before: dict, after: dict) -> list[str]:
    """One line per module: first-party and total counts, heavy packages gained or lost."""
    lines = []
    old_mods, new_mods = before.get("modules", {}), after.get("modules", {})
    if before.get("python") != after.get("python"):
        lines.append(
            f"(different interpreters: {before.get('python')} vs {after.get('python')};"
            " counts are not comparable)"
        )
    for module in sorted(set(old_mods) | set(new_mods)):
        old, new = old_mods.get(module), new_mods.get(module)
        if old is None or new is None or "error" in old or "error" in new:
            lines.append(f"{module}: before {old}, after {new}")
            continue
        gone = sorted(set(old["heavy"]) - set(new["heavy"]))
        added = sorted(set(new["heavy"]) - set(old["heavy"]))
        heavy = []
        if gone:
            heavy.append("no longer loads " + ", ".join(gone))
        if added:
            heavy.append("now loads " + ", ".join(added))
        watched = [
            f"{name} {old['watched'].get(name)} -> {new['watched'].get(name)}"
            for name in sorted(
                set(old.get("watched", {})) | set(new.get("watched", {}))
            )
            if old.get("watched", {}).get(name) != new.get("watched", {}).get(name)
        ]
        lines.append(
            f"{module}: first-party {old['first_party']} -> {new['first_party']}, "
            f"all {old['all']} -> {new['all']}"
            + (f"; {'; '.join(heavy)}" if heavy else "")
            + (f"; watched {', '.join(watched)}" if watched else "")
        )
    return lines


def cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    parser.add_argument("modules", nargs="*", help="dotted module names, from Backend/")
    parser.add_argument(
        "--watch",
        action="append",
        default=[],
        metavar="MODULE",
        help="report whether this module loads (repeatable)",
    )
    parser.add_argument(
        "--list", action="store_true", help="name the first-party modules"
    )
    parser.add_argument("--json", action="store_true", help="print the full JSON")
    parser.add_argument("--compare", nargs=2, metavar=("BEFORE", "AFTER"))
    args = parser.parse_args(argv)

    if args.compare:
        before, after = (
            json.loads(Path(path).read_text(encoding="utf-8")) for path in args.compare
        )
        for line in compare(before, after):
            print(line)
        return 0
    if not args.modules:
        parser.error("name at least one module, or --compare two files")

    result = measure(args.modules, watch=args.watch, list_modules=args.list)
    if args.json or args.list:
        print(json.dumps(result, indent=1, sort_keys=True))
        return 0
    for module, row in result["modules"].items():
        if "error" in row:
            print(f"{module}: import failed: {row['error']}")
            continue
        watched = "".join(
            f"  {name}={'loaded' if seen else 'not loaded'}"
            for name, seen in row["watched"].items()
        )
        print(
            f"{module}: {row['first_party']} first-party, {row['all']} in all;"
            f" heavy: {', '.join(row['heavy']) or 'none'}{watched}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(cli())
