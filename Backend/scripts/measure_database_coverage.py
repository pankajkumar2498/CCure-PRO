"""
scripts/measure_database_coverage.py
─────────────────────────────────────────────────────────────────────────────
Measures GAP-10 coverage — authenticated database security assessment.

    python -m scripts.measure_database_coverage

Run before and after a change to get a comparable number.

What this denominator covers, and what it deliberately does not
──────────────────────────────────────────────────────────────
**Authenticated assessment of a database instance.** A credential is presented
to the database engine, its own catalogue and configuration are read, and the
readings are judged against an expected state.

It does **not** cover the unauthenticated network view of a database service —
service and version detection, the CPE→CVE match on a detected banner, the
exposure note on a listening database port, or the no-authentication checks for
Redis, MongoDB and Memcached. All of that already exists and is already counted
in **GAP-06**, whose own frozen denominator names "database service assessment
— GAP-10, not this phase" as the boundary. Counting it a second time here is
double-counting, and double-counting is how a coverage figure stops meaning
anything.

That boundary is why GAP-10 measures **0/31 before this phase** while the gap
matrix carried "5% [measured]". The matrix figure was measuring the
unauthenticated slice. It is not wrong about the code; it is attributing
GAP-06's capability to GAP-10. The correction is recorded in the tracker.

Why the denominator includes things we did not build
────────────────────────────────────────────────────
Eight of the thirty-one areas below are real Nessus database-audit checks this
build does **not** perform, and they are in the denominator on purpose. Some
need filesystem access to the database *host* rather than a session with the
*engine* (a different credential and a different transport); some need an
edition this project cannot obtain to validate against; one needs cipher-suite
enumeration over a database wire protocol, which is not a configuration read.

A coverage figure is only worth reading if it can go down.

Three things are counted separately and must never be conflated
──────────────────────────────────────────────────────────────
``implemented``   a check exists and the engine can execute it
``tested``        an automated test names the area and exercises it
``validated``     it has produced a correct result against a real database

**The headline coverage figure is implemented *and* tested.** Engine breadth —
how many of the supported database platforms answer a given area — is reported
separately and is never folded into the headline: an area answered on one
engine is implemented, and saying so on three engines does not make it three
areas.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

#: The database engines this phase set out to support. Oracle and MongoDB are
#: named in RESERVED_ENGINES below rather than here: a driver exists for both,
#: but neither can be stood up as a disposable target in this environment
#: without a vendor registry account, so neither could be validated — and this
#: programme does not count unvalidated engines.
SUPPORTED_ENGINES: Tuple[str, ...] = ("postgresql", "mysql", "mssql")

RESERVED_ENGINES: Tuple[Tuple[str, str], ...] = (
    ("oracle", "driver available (oracledb thin); no disposable target here"),
    ("mongodb", "document store; check vocabulary differs, deferred"),
)

#: (area id, theme, description). Frozen at the start of Phase 7 and not to be
#: edited to match what was built. Areas the phase does not implement are
#: marked in NOT_PLANNED below with the reason.
SCOPE: Tuple[Tuple[str, str, str], ...] = (
    # ── Authentication & accounts ────────────────────────────────────────────
    ("db.auth.empty_password", "auth", "Accounts with an empty or blank password"),
    ("db.auth.weak_auth_method", "auth", "Weak or legacy authentication method"),
    ("db.auth.default_accounts", "auth", "Well-known default accounts enabled"),
    ("db.auth.password_policy", "auth", "Engine-enforced password policy"),
    ("db.auth.login_auditing", "auth", "Failed / successful login auditing"),
    ("db.auth.superuser_remote", "auth", "Superuser reachable from any host"),
    ("db.auth.lockout", "auth", "Failed-login lockout configured"),
    # ── Privileges, roles & grants ───────────────────────────────────────────
    ("db.priv.superusers", "privilege", "Accounts holding superuser / sysadmin"),
    ("db.priv.public_grants", "privilege", "Excessive privileges granted to PUBLIC"),
    ("db.priv.dangerous_features", "privilege", "Command execution features enabled"),
    ("db.priv.grant_option", "privilege", "GRANT OPTION / WITH ADMIN spread"),
    ("db.priv.schema_create", "privilege", "PUBLIC may create objects in a schema"),
    ("db.priv.filesystem_access", "privilege", "SQL-level filesystem read / write"),
    # ── Encryption & transport ───────────────────────────────────────────────
    ("db.tls.enabled", "encryption", "TLS available for client connections"),
    ("db.tls.enforced", "encryption", "Plaintext client connections refused"),
    ("db.tls.min_version", "encryption", "Minimum TLS protocol version"),
    ("db.tls.cipher_strength", "encryption", "Weak cipher suites accepted"),
    ("db.crypto.at_rest", "encryption", "Data-at-rest encryption / TDE"),
    # ── Audit & logging ──────────────────────────────────────────────────────
    ("db.audit.enabled", "audit", "Statement / audit logging enabled"),
    ("db.audit.connections", "audit", "Connection and disconnection logging"),
    ("db.audit.ddl_privilege", "audit", "DDL and privilege-change logging"),
    ("db.audit.retention", "audit", "Log rotation / retention configured"),
    ("db.audit.log_permissions", "audit", "Log file ownership and permissions"),
    # ── Configuration hardening ──────────────────────────────────────────────
    ("db.conf.listen_exposure", "configuration", "Network binding / listen address"),
    ("db.conf.version_supported", "configuration", "Running a supported release"),
    ("db.conf.dangerous_options", "configuration", "Dangerous server options enabled"),
    ("db.conf.connection_limits", "configuration", "Connection / resource limits set"),
    ("db.conf.sample_databases", "configuration", "Sample or demo databases present"),
    ("db.conf.error_verbosity", "configuration", "Verbose error information leakage"),
    ("db.conf.data_dir_permissions", "configuration", "Data directory permissions"),
    ("db.conf.backup_configured", "configuration", "Backup / point-in-time recovery"),
)

#: Areas inside the denominator that this phase did not set out to implement,
#: each with the reason. Declared so that the gap between "in scope" and "built"
#: is a recorded decision rather than something a reader has to infer from a
#: missing row.
NOT_PLANNED: Dict[str, str] = {
    "db.tls.cipher_strength": (
        "needs cipher-suite enumeration over the database wire protocol, which "
        "is a handshake engine and not a configuration read"
    ),
    "db.crypto.at_rest": (
        "TDE is an enterprise-edition feature on every supported engine; no "
        "disposable target here can exhibit it, so it could not be validated"
    ),
    "db.audit.log_permissions": (
        "the log file lives on the database host's filesystem; reading it needs "
        "a host credential and a shell transport, not a database session"
    ),
    "db.conf.data_dir_permissions": (
        "same as db.audit.log_permissions — a host filesystem read, not a "
        "database read"
    ),
    "db.conf.backup_configured": (
        "backup arrangements are usually external to the engine (pg_basebackup "
        "schedules, Ops Manager, Agent jobs); the engine's own settings do not "
        "establish whether backups happen"
    ),
    "db.auth.lockout": (
        "only MySQL 8 exposes this natively; PostgreSQL has no lockout at all "
        "and SQL Server delegates to Windows policy, so a verdict would be "
        "answerable on one engine of three"
    ),
    "db.priv.grant_option": (
        "requires transitive closure over the grant graph to be meaningful; a "
        "flat listing produces noise rather than a finding"
    ),
    "db.conf.error_verbosity": (
        "the observable behaviour is what an unauthenticated client is told, "
        "which is a network probe rather than an authenticated catalogue read"
    ),
}

#: Named so the exclusion is visible rather than silent. Excluding these is a
#: scoping decision for Phase 7, not a way to raise the percentage.
OUT_OF_SCOPE = (
    "unauthenticated database detection, versioning and CVE matching — GAP-06",
    "no-authentication data-store checks (Redis, MongoDB, Memcached) — GAP-06",
    "default-credential spraying against database accounts",
    "SQL injection and application-layer testing (/web-scans: sqlmap)",
    "database host operating-system hardening — GAP-03 via a host credential",
    "data discovery / classification of database contents",
)


def _implemented() -> Dict[str, object]:
    """Areas with a built-in check the engine can execute."""
    try:
        from core.config_audit.builtin import BUILTIN_CHECKS
    except Exception as exc:  # pragma: no cover - import guard
        print(f"could not import the built-in checks: {exc}")
        return {}
    found: Dict[str, object] = {}
    for check in BUILTIN_CHECKS:
        area = str(check.metadata.get("gap10_area") or "")
        if area:
            found.setdefault(area, check)
    return found


def _engines_per_area() -> Dict[str, Set[str]]:
    """Which supported engines carry a check for each area."""
    try:
        from core.config_audit.builtin import BUILTIN_CHECKS
    except Exception:  # pragma: no cover - import guard
        return {}
    by_area: Dict[str, Set[str]] = {}
    for check in BUILTIN_CHECKS:
        area = str(check.metadata.get("gap10_area") or "")
        if not area:
            continue
        engine = str(check.metadata.get("db_engine") or "")
        if engine:
            by_area.setdefault(area, set()).add(engine)
    return by_area


def _tested() -> Set[str]:
    """
    Areas an automated test names.

    Read from the test sources rather than from a hand-maintained list — a list
    would keep saying "tested" for as long as nobody updated it, which is
    precisely the failure a coverage figure must not have.
    """
    root = Path(__file__).resolve().parents[1] / "tests"
    corpus = ""
    for path in root.rglob("test_database*.py"):
        corpus += path.read_text(encoding="utf-8")
    return {area for area, _t, _d in SCOPE if area in corpus}


def main() -> int:
    implemented = _implemented()
    tested = _tested()
    engines = _engines_per_area()

    print("=" * 78)
    print("GAP-10 — AUTHENTICATED DATABASE ASSESSMENT COVERAGE")
    print("=" * 78)
    print(f"\n{'area':32} {'theme':13} {'impl':5} {'test':5} {'engines':22}")
    print("-" * 78)

    by_theme: Dict[str, List[bool]] = {}
    for area, theme, _description in SCOPE:
        has = area in implemented
        has_test = area in tested
        by_theme.setdefault(theme, []).append(has and has_test)
        covered = sorted(engines.get(area, set()))
        marker = "" if has else ("  (not planned)" if area in NOT_PLANNED else "")
        print(
            f"{area:32} {theme:13} {'yes' if has else 'NO':5} "
            f"{'yes' if has_test else 'NO':5} "
            f"{','.join(covered) if covered else '-':22}{marker}"
        )

    total = len(SCOPE)
    done = sum(1 for area, _t, _d in SCOPE if area in implemented)
    proven = sum(1 for area, _t, _d in SCOPE if area in implemented and area in tested)

    print("-" * 78)
    for theme, flags in by_theme.items():
        print(
            f"  {theme:13} proven: {sum(flags)}/{len(flags)} "
            f"({round(100.0 * sum(flags) / len(flags), 1)}%)"
        )

    print(
        f"\n  implemented          : {done}/{total} = "
        f"{round(100.0 * done / total, 1)}%"
    )
    print(
        f"  implemented + tested : {proven}/{total} = "
        f"**{round(100.0 * proven / total, 1)}%**   <- GAP-10 coverage"
    )
    print("  real-target validated: reported separately, never folded in")

    if done != proven:
        print(
            f"\n  {done - proven} area(s) have a check no automated test names. "
            f"Implemented is not proven, and only proven counts."
        )

    unplanned_but_built = sorted(set(implemented) & set(NOT_PLANNED))
    if unplanned_but_built:
        print(
            f"\n  NOTE: {len(unplanned_but_built)} area(s) marked not-planned "
            f"were built after all: {unplanned_but_built}"
        )
        print("  Update NOT_PLANNED — a stale reason is worse than none.")

    orphans = sorted(set(implemented) - {a for a, _t, _d in SCOPE})
    if orphans:
        print(
            f"\n  WARNING: {len(orphans)} check(s) claim a gap10_area outside "
            f"the scope: {orphans}"
        )
        print("  The denominator is fixed; an area outside it counts for nothing.")

    print("\n  Not implemented, with the reason recorded:")
    for area in sorted(NOT_PLANNED):
        if area not in implemented:
            print(f"    - {area}: {NOT_PLANNED[area]}")

    print("\n  Deliberately out of scope (not in the denominator):")
    for item in OUT_OF_SCOPE:
        print(f"    - {item}")

    print("\n" + "-" * 78)
    print("ENGINE BREADTH — reported separately, never folded into the headline")
    all_engine_checks: Dict[str, int] = {}
    try:
        from core.config_audit.builtin import BUILTIN_CHECKS

        for check in BUILTIN_CHECKS:
            engine = str(check.metadata.get("db_engine") or "")
            if engine:
                all_engine_checks[engine] = all_engine_checks.get(engine, 0) + 1
    except Exception as exc:  # pragma: no cover
        print(f"  (could not measure engine breadth: {exc})")

    for engine in SUPPORTED_ENGINES:
        count = all_engine_checks.get(engine, 0)
        areas_here = sum(1 for a, e in engines.items() if engine in e)
        print(
            f"  {engine:12} checks: {count:3}   areas answered: "
            f"{areas_here}/{len([a for a, _t, _d in SCOPE])}"
        )
    for engine, reason in RESERVED_ENGINES:
        print(f"  {engine:12} reserved — {reason}")

    print("\n" + "-" * 78)
    print("SUPPORTING MEASUREMENTS")
    try:
        from core.config_audit.collectors import (  # noqa: F401
            collector_registry,
        )

        supported = collector_registry.supported_check_types("database")
        print(f"  check types with a collector on 'database' : {supported or '(none)'}")
    except Exception as exc:  # pragma: no cover
        print(f"  (could not read the collector registry: {exc})")

    try:
        from db.models.credentials import USABLE_CREDENTIAL_TYPES

        print(
            f"  credential types the API will create       : {USABLE_CREDENTIAL_TYPES}"
        )
    except Exception as exc:  # pragma: no cover
        print(f"  (could not read the credential vocabulary: {exc})")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
