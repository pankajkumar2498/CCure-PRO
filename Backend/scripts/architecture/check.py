"""
The repository's architecture and secret-handling guards, standard library only.

    python Backend/scripts/architecture/check.py      # from anywhere; exit 1 on a breach

Every rule here is also a test (``tests/repo/test_architecture_guardrails.py``,
``test_identity_boundary.py``,
``tests/credentialed/test_sudo_password_safety.py``). Those need the backend's
dependencies and a disposable PostgreSQL, because ``tests/conftest.py`` builds a
schema before any test runs. This needs neither: it parses source with ``ast``
and imports nothing from the application, so the ``architecture-guards``
pre-commit hook can run it on every backend commit (about five seconds; its
checks run in parallel processes).

It is the local twin of those tests, not a replacement. Remote CI runs the tests
(``.github/workflows/ci.yml``); docs/ci/LOCAL_ENFORCEMENT.md says what runs
where, and what is not running at the moment.

The ratchets fail in both directions, exactly as the tests do: a new breach
fails, and so does a recorded one that no longer exists — delete it from its
list so it cannot come back.
"""

from __future__ import annotations

import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[2]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from scripts.architecture import identity_boundary as ib  # noqa: E402
from scripts.architecture import secret_guards  # noqa: E402
from scripts.architecture.import_graph import collect_edges, module_cycles  # noqa: E402
from scripts.architecture.layer_rules import (  # noqa: E402
    KNOWN_CYCLES,
    KNOWN_VIOLATIONS,
    violations,
)


def check_layering(edges) -> list[str]:
    current = {(rule, e.src, e.dst) for rule, e in violations(edges)}
    problems = [
        f"new layer violation [{rule}] {src} -> {dst}"
        for rule, src, dst in sorted(current - KNOWN_VIOLATIONS)
    ]
    problems += [
        f"fixed layer violation still listed — delete it from KNOWN_VIOLATIONS: "
        f"({rule!r}, {src!r}, {dst!r})"
        for rule, src, dst in sorted(KNOWN_VIOLATIONS - current)
    ]
    return problems


def check_cycles(edges) -> list[str]:
    current = module_cycles(edges)
    problems = [
        "new or enlarged import cycle: " + " <-> ".join(sorted(cycle))
        for cycle in current
        if not any(cycle <= known for known in KNOWN_CYCLES)
    ]
    current_set = set(current)
    problems += [
        "recorded cycle changed or gone — update KNOWN_CYCLES: "
        + " <-> ".join(sorted(known))
        for known in KNOWN_CYCLES
        if known not in current_set
    ]
    return problems


def _count_diff(current: dict, known: dict, label: str, baseline: str) -> list[str]:
    problems = []
    for module in sorted(set(current) | set(known)):
        for what in sorted(set(current.get(module, {})) | set(known.get(module, {}))):
            now = current.get(module, {}).get(what, 0)
            then = known.get(module, {}).get(what, 0)
            if now > then:
                problems.append(f"new {label}: {module} {what} {then} -> {now}")
            elif now < then:
                problems.append(
                    f"fewer {label}s than recorded — lower {baseline}: "
                    f"{module} {what} {then} -> {now}"
                )
    return problems


def check_identity() -> list[str]:
    _, sites = ib.measure()
    imports = ib.imports_by_module(sites)
    problems = [
        f"new identity import outside the platform: {module}: {symbol}"
        for module, symbols in sorted(imports.items())
        for symbol in sorted(
            symbols - ib.KNOWN_IDENTITY_IMPORTS.get(module, frozenset())
        )
    ]
    problems += [
        f"identity import gone — delete it from KNOWN_IDENTITY_IMPORTS: {module}: {symbol}"
        for module, symbols in sorted(ib.KNOWN_IDENTITY_IMPORTS.items())
        for symbol in sorted(symbols - imports.get(module, frozenset()))
    ]
    problems += _count_diff(
        ib.counts_by_module(sites, "query"),
        ib.KNOWN_IDENTITY_QUERIES,
        "identity query",
        "KNOWN_IDENTITY_QUERIES",
    )
    problems += _count_diff(
        ib.counts_by_module(sites, "join"),
        ib.KNOWN_IDENTITY_JOINS,
        "identity join",
        "KNOWN_IDENTITY_JOINS",
    )
    return problems


def check_organisation_settings() -> list[str]:
    return _count_diff(
        ib.counts_by_module(ib.measure_module_organisation_settings(), "setting"),
        ib.KNOWN_MODULE_ORGANISATION_SETTING_REFERENCES,
        "organisation-setting reference",
        "KNOWN_MODULE_ORGANISATION_SETTING_REFERENCES",
    )


def check_secrets() -> list[str]:
    return secret_guards.violations()


def check_import_graph() -> dict[str, list[str]]:
    _, edges = collect_edges()
    return {"layering": check_layering(edges), "import cycles": check_cycles(edges)}


#: Independent checks, each of which parses the source tree itself. They run in
#: parallel processes: one at a time they take ~15 s, together ~5 s.
CHECKS = {
    "import graph": check_import_graph,
    "identity boundary": check_identity,
    "organisation settings": check_organisation_settings,
    "secret handling": check_secrets,
}


def run() -> dict[str, list[str]]:
    from concurrent.futures import ProcessPoolExecutor

    with ProcessPoolExecutor(max_workers=len(CHECKS)) as pool:
        futures = {name: pool.submit(check) for name, check in CHECKS.items()}
        outcomes = {name: future.result() for name, future in futures.items()}
    results: dict[str, list[str]] = {}
    for name, outcome in outcomes.items():
        if isinstance(outcome, dict):
            results.update(outcome)
        else:
            results[name] = outcome
    return results


def main(argv: list[str] | None = None) -> int:
    results = run()
    failed = False
    for name, problems in results.items():
        if problems:
            failed = True
            print(f"FAIL  {name}")
            for problem in problems:
                print(f"      {problem}")
        else:
            print(f"ok    {name}")
    if failed:
        print(
            "\nEach rule says why in its source under Backend/scripts/architecture/. "
            "Adding to a KNOWN_* list needs an explicit reason in review."
        )
    return 1 if failed else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
