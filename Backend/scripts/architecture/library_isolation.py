"""
D1: the engine libraries work with nothing but what they declare
(docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md §10, Phase D).

The import graph says what a module *can* reach; this proves what it does, by
running it. Each library in ``LIBRARIES`` declares the first-party modules and
the third-party packages it may use, and is checked twice, each time in a fresh
interpreter that holds no settings, no database URL and no credentials:

* **import** — its entry points are imported with every first-party import
  checked against the declaration. Afterwards nothing undeclared may be in
  ``sys.modules``, nothing first-party may have come from outside the checkout,
  and none of ``FORBIDDEN`` may have loaded, whoever imported it.
* **exercise** — its own existing tests run under pytest, without
  ``tests/conftest.py``. The tests may import what they like; every import the
  *library's* code makes is checked, including a lazy import of a module the
  tests already loaded. A module already in ``sys.modules`` is never offered
  to an import finder, so the check sits on ``builtins.__import__`` as well as
  ``sys.meta_path``.

A refused import raises ``ImportError`` and is recorded, so a library that
catches the error and carries on still fails the run.

    python -m scripts.architecture.library_isolation                 # every library
    python -m scripts.architecture.library_isolation discovery       # one
    python -m scripts.architecture.library_isolation --import-only

It needs the libraries' third-party packages, so it runs in the backend image:
``scripts/ci/local_guard_tests.sh`` runs it there with no network and the
checkout read-only. This module itself is standard library only, because
``capability_map.py`` reads ``LIBRARIES`` and ``FORBIDDEN`` for E2 in the
stdlib-only pre-commit hook.

Not here: the port and network-check engines, the nmap wrapper, the version
matcher and the topology engine. Since Group 3 the first four load no package
in ``FORBIDDEN`` and ``capability_map.PINNED_ENGINES`` pins that statically;
they are not D1 libraries yet, because each reads the settings module at
import. The topology engine still persists its own links through SQLAlchemy.
Nothing in this module exempts any of them; they are simply not declared.
"""

from __future__ import annotations

import builtins
import importlib
import importlib.abc
import importlib.util
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[2]

#: E2: what no engine library may load, by itself or through anything it
#: imports. ``capability_map.library_problems`` pins it statically.
FORBIDDEN = frozenset({"sqlalchemy", "fastapi", "celery", "redis"})


@dataclass(frozen=True)
class Library:
    #: The modules a caller imports.
    entry_points: tuple[str, ...]
    #: First-party module prefixes it may load: its own code and the kernels
    #: it builds on. The packages above a prefix are admitted for the import
    #: machinery's sake, never their other children.
    first_party: tuple[str, ...]
    #: Third-party distributions it imports, by top-level name. What those
    #: import in turn is theirs, except ``FORBIDDEN``.
    third_party: frozenset[str]
    #: Its existing tests, relative to ``Backend/``.
    tests: tuple[str, ...]


LIBRARIES: dict[str, Library] = {
    "ssh_transport": Library(
        entry_points=("engines.credentialed.ssh_scanner",),
        first_party=("engines.credentialed.ssh_scanner",),
        third_party=frozenset({"paramiko"}),
        tests=("tests/credentialed/test_sudo_password_safety.py",),
    ),
    # The two Windows transports implement ssh_scanner's BaseExecutor protocol
    # and return its CommandResult, so they load it, and paramiko with it.
    "winrm_transport": Library(
        entry_points=("engines.credentialed.winrm_executor",),
        first_party=(
            "engines.credentialed.winrm_executor",
            "engines.credentialed.ssh_scanner",
        ),
        third_party=frozenset({"winrm", "paramiko"}),
        # The file's transport tests by name: the rest exercise the credential
        # model, its API and audit trail (database fixtures from conftest), the
        # coverage table and the Windows collector, none of them this library.
        tests=(
            "tests/credentialed/test_windows_winrm.py::TestWinRMConfiguration",
            "tests/credentialed/test_windows_winrm.py::TestWinRMThreadSafety",
            "tests/credentialed/test_windows_winrm.py"
            "::test_powershell_shell_type_means_commands_are_not_wrapped",
        ),
    ),
    "smb_transport": Library(
        entry_points=("engines.credentialed.smb_executor",),
        first_party=(
            "engines.credentialed.smb_executor",
            "engines.credentialed.ssh_scanner",
        ),
        third_party=frozenset({"impacket", "paramiko"}),
        tests=("tests/credentialed/test_smb_transport.py",),
    ),
    # Configuration audit and the SCAP compiler are one capability (the SCAP
    # collector evaluates compiled definitions; the compiler emits ConfigChecks
    # into benchmark packs), so they declare the same modules. yaml is the
    # structured-configuration reader's, imported when a rule asks for YAML.
    "config_audit": Library(
        entry_points=("core.config_audit.engine",),
        first_party=(
            "core.config_audit",
            "core.scap",
            "core.benchmarks",
            "core.checks",
        ),
        third_party=frozenset({"yaml"}),
        tests=(
            "tests/scans/test_config_audit_engine.py",
            "tests/scans/test_config_audit_collectors.py",
        ),
    ),
    "scap_compiler": Library(
        entry_points=("core.scap.oval",),
        first_party=(
            "core.scap",
            "core.config_audit",
            "core.benchmarks",
            "core.checks",
        ),
        third_party=frozenset({"yaml"}),
        tests=(
            "tests/scans/test_scap_parsers.py",
            "tests/scans/test_scap_evaluation.py",
        ),
    ),
    "check_kernel": Library(
        entry_points=("core.checks.contract", "core.checks.finding_normalizer"),
        first_party=("core.checks",),
        third_party=frozenset(),
        tests=("tests/scans/test_check_framework.py",),
    ),
    # scans.cvss and scans.finding_normalizer are sys.modules aliases of the
    # check kernel's modules (CLAUDE.md, "compatibility import paths"); the PDF
    # renderer still imports the old names.
    "renderers": Library(
        entry_points=("reporting.pdf_generator", "reporting.xlsx_generator"),
        first_party=(
            "reporting.pdf_generator",
            "reporting.xlsx_generator",
            "reporting.report_helpers",
            "reporting.host_assessment",
            "core.checks",
            "scans.cvss",
            "scans.finding_normalizer",
        ),
        third_party=frozenset({"reportlab", "openpyxl"}),
        tests=(
            "tests/reports/test_export_workbook.py",
            "tests/reports/test_report_integrity.py",
        ),
    ),
    # The scan kernel's constants, engine ports and risk helpers, and the pure
    # scoring helpers B3 split out of vulnerability intelligence. Not
    # core.oui_lookup: it reads the MAC-vendor cache through db.models (log §7,
    # from B3), so an ARP path that reaches it fails here.
    "discovery": Library(
        entry_points=("core.discovery.engine",),
        first_party=(
            "core.discovery",
            "engines.discovery",
            "core.constants",
            "core.engine_ports",
            "core.risk",
            "core.vuln_scoring",
            "core.checks",
        ),
        third_party=frozenset({"scapy", "psutil"}),
        tests=(
            "tests/scans/test_host_identity_precedence.py",
            "tests/scans/test_ot_probes.py",
        ),
    ),
}


# ── The child: one library, one phase, one fresh interpreter ─────────────────
_RESULT = "LIBRARY-ISOLATION-RESULT "


class _Guard(importlib.abc.MetaPathFinder):
    """Refuses, and records, every import the governed code may not make."""

    def __init__(self, spec: dict):
        self.root = Path(spec["root"])
        self.tops = frozenset(spec["first_party_tops"])
        self.prefixes = tuple(spec["first_party"])
        self.third_party = frozenset(spec["third_party"])
        # Importing: all first-party code is governed, the library's and the
        # packages above it. Exercising: only the library's, not its tests'.
        self.strict = spec["phase"] == "import"
        self.refusals: list[dict] = []
        self._import = builtins.__import__

    def install(self) -> None:
        sys.meta_path.insert(0, self)
        builtins.__import__ = self._import_hook

    def first_party(self, name: str) -> bool:
        return name.split(".")[0] in self.tops

    def _own(self, name: str) -> bool:
        return any(name == p or name.startswith(p + ".") for p in self.prefixes)

    def permits(self, name: str) -> bool:
        top = name.split(".")[0]
        if top in FORBIDDEN:
            return False
        if top in sys.stdlib_module_names:
            return True
        if top in self.tops:
            return self._own(name) or any(
                p.startswith(name + ".") for p in self.prefixes
            )
        return top in self.third_party

    def governs(self, importer: str | None) -> bool:
        if not importer:
            return False
        if self.strict:
            return importer == "__main__" or self.first_party(importer)
        return self._own(importer)

    def _check(self, importer: str | None, name: str) -> None:
        if not self.governs(importer) or self.permits(name):
            return
        self.refusals.append({"importer": importer, "module": name})
        raise ImportError(
            f"library isolation: {importer} may not import {name}", name=name
        )

    def _is_module(self, name: str) -> bool:
        path = self.root.joinpath(*name.split("."))
        return path.with_suffix(".py").is_file() or (path / "__init__.py").is_file()

    def _import_hook(self, name, globals=None, locals=None, fromlist=(), level=0):
        importer = (globals or {}).get("__name__")
        if self.governs(importer):
            absolute = name
            if level:
                package = globals.get("__package__") or importer.rpartition(".")[0]
                absolute = importlib.util.resolve_name("." * level + name, package)
            self._check(importer, absolute)
            for item in fromlist or ():
                sub = f"{absolute}.{item}"
                if self.first_party(sub) and self._is_module(sub):
                    self._check(importer, sub)
        return self._import(name, globals, locals, fromlist, level)

    def _importer(self) -> str | None:
        """The module whose code asked: the first frame that is neither this
        guard nor the import machinery (``importlib.import_module`` included)."""
        frame = sys._getframe(1)
        while frame is not None:
            name = frame.f_globals.get("__name__", "")
            if frame.f_code not in _GUARD_CODE and not name.startswith(
                ("importlib", "_frozen_importlib")
            ):
                return name
            frame = frame.f_back
        return None

    def find_spec(self, fullname, path=None, target=None):
        self._check(self._importer(), fullname)
        return None


_GUARD_CODE = frozenset(
    f.__code__
    for f in (_Guard._check, _Guard._import_hook, _Guard._importer, _Guard.find_spec)
)


def _child(spec: dict) -> dict:
    root = spec["root"]
    sys.dont_write_bytecode = True
    sys.path[:] = [root] + [
        p for p in sys.path if p and Path(p).resolve() != Path(root)
    ]
    guard = _Guard(spec)
    guard.install()

    if spec["phase"] == "import":
        errors = []
        for entry in spec["entry_points"]:
            try:
                importlib.import_module(entry)
            except Exception as exc:  # noqa: BLE001 — every failure is the result
                errors.append(f"importing {entry}: {type(exc).__name__}: {exc}")
        loaded = sorted(sys.modules)
        first = [m for m in loaded if guard.first_party(m)]
        outside = []
        for m in first:
            origin = getattr(sys.modules[m], "__file__", None)
            if origin and not Path(origin).resolve().is_relative_to(
                Path(root).resolve()
            ):
                outside.append(f"{m} ({origin})")
        return {
            "errors": errors,
            "refusals": guard.refusals,
            "undeclared": [m for m in first if not guard.permits(m)],
            "outside_checkout": outside,
            "forbidden": [m for m in loaded if m.split(".")[0] in FORBIDDEN],
            "first_party_loaded": len(first),
        }

    sys.path.insert(1, os.path.join(root, "tests"))  # testpaths, without conftest
    import pytest

    lines: list[str] = []

    class _Tally:
        def pytest_terminal_summary(self, terminalreporter):
            for key in ("passed", "failed", "error", "skipped", "deselected"):
                count = len(terminalreporter.stats.get(key, ()))
                if count:
                    lines.append(f"{count} {key}")

    code = pytest.main(
        [
            "-q",
            "-p",
            "no:cacheprovider",
            "--noconftest",
            "-c",
            os.path.join(root, "pytest.ini"),
        ]
        + ["--rootdir", root, *spec["tests"]],
        plugins=[_Tally()],
    )
    return {
        "pytest": int(code),
        "summary": ", ".join(lines),
        "refusals": guard.refusals,
    }


# ── The parent: spawn, read, judge ────────────────────────────────────────────
def _first_party_tops(root: Path) -> list[str]:
    return sorted(
        p.stem if p.suffix == ".py" else p.name
        for p in root.iterdir()
        if (p.suffix == ".py" and p.is_file()) or (p / "__init__.py").is_file()
    )


def _environment() -> dict[str, str]:
    """What the child may see: no settings, URLs or credentials; the import
    path keeps only the parent's package directories (the backend image
    installs into a user site named by PYTHONPATH), never the working
    directory an empty entry would add."""
    env = {
        key: os.environ[key]
        for key in ("PATH", "HOME", "LANG", "LC_ALL", "TZ")
        if key in os.environ
    }
    paths = [p for p in os.environ.get("PYTHONPATH", "").split(os.pathsep) if p]
    if paths:
        env["PYTHONPATH"] = os.pathsep.join(paths)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    # A test that reaches config must not read a .env, as in the containers.
    env["SKIP_DOTENV_LOAD"] = "1"
    return env


def _spawn(spec: dict, root: Path, timeout: int) -> tuple[dict | None, str]:
    proc = subprocess.run(
        # -P: the harness's own directory is never on the child's path.
        [
            sys.executable,
            "-P",
            str(Path(__file__).resolve()),
            "--child",
            json.dumps(spec),
        ],
        cwd=root,
        env=_environment(),
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    output = proc.stdout + proc.stderr
    for line in reversed(proc.stdout.splitlines()):
        if line.startswith(_RESULT):
            return json.loads(line[len(_RESULT) :]), output
    return None, output


def _tail(output: str, lines: int = 15) -> str:
    return "\n".join("    " + line for line in output.strip().splitlines()[-lines:])


def check(
    name: str,
    library: Library,
    *,
    root: Path = BACKEND_ROOT,
    import_only: bool = False,
    timeout: int = 900,
) -> tuple[list[str], list[str]]:
    """``(problems, notes)`` for one library: no problems is a pass."""
    root = Path(root).resolve()
    spec = {
        "root": str(root),
        "first_party_tops": _first_party_tops(root),
        "entry_points": list(library.entry_points),
        "first_party": list(library.first_party),
        "third_party": sorted(library.third_party),
        "tests": list(library.tests),
    }
    problems: list[str] = []
    notes: list[str] = []

    result, output = _spawn({**spec, "phase": "import"}, root, timeout)
    if result is None:
        return [f"{name}: the import phase produced no result\n{_tail(output)}"], notes
    problems += [f"{name}: {e}" for e in result["errors"]]
    problems += [
        f"{name}: {r['importer']} may not import {r['module']} (not declared)"
        for r in result["refusals"]
    ]
    problems += [f"{name}: loaded undeclared {m}" for m in result["undeclared"]]
    problems += [
        f"{name}: loaded from outside the checkout: {m}"
        for m in result["outside_checkout"]
    ]
    problems += [f"{name}: loaded {m}, which E2 forbids" for m in result["forbidden"]]
    notes.append(f"import: {result['first_party_loaded']} first-party modules")
    if import_only or problems:
        return problems, notes

    result, output = _spawn({**spec, "phase": "exercise"}, root, timeout)
    if result is None:
        return [
            f"{name}: the exercise phase produced no result\n{_tail(output)}"
        ], notes
    seen = set()
    for r in result["refusals"]:
        key = (r["importer"], r["module"])
        if key not in seen:
            seen.add(key)
            problems.append(
                f"{name}: {r['importer']} may not import {r['module']} (exercise)"
            )
    if result["pytest"] != 0:
        problems.append(
            f"{name}: its tests did not pass in isolation (pytest exit {result['pytest']}: "
            f"{result['summary'] or 'no summary'})\n{_tail(output)}"
        )
    notes.append(f"exercise: {result['summary']}")
    return problems, notes


def run(
    names=None, *, root: Path = BACKEND_ROOT, import_only: bool = False
) -> dict[str, list[str]]:
    return {
        name: check(name, LIBRARIES[name], root=root, import_only=import_only)[0]
        for name in (names or LIBRARIES)
    }


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["--child"]:
        print(_RESULT + json.dumps(_child(json.loads(argv[1]))), flush=True)
        return 0

    import argparse

    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    parser.add_argument(
        "libraries", nargs="*", metavar="LIBRARY", help=", ".join(LIBRARIES)
    )
    parser.add_argument("--import-only", action="store_true", help="skip the tests")
    args = parser.parse_args(argv)
    unknown = sorted(set(args.libraries) - set(LIBRARIES))
    if unknown:
        parser.error(f"unknown library: {', '.join(unknown)}")

    failed = 0
    for name in args.libraries or LIBRARIES:
        problems, notes = check(name, LIBRARIES[name], import_only=args.import_only)
        status = "FAIL" if problems else "ok"
        print(f"{status:4} {name}: " + "; ".join(notes))
        for problem in problems:
            print(f"     {problem}")
        failed += bool(problems)
    print(f"{len(args.libraries or LIBRARIES) - failed} isolated, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
