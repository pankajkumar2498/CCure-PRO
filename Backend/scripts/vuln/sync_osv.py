"""
scripts/vuln/sync_osv.py
─────────────────────────────────────────────────────────────────────────────
Rebuild the OSV advisory tables in `vuln_intel` from osv.dev.

Why this exists
───────────────
OSV is where the credentialed audit gets most of its findings. On a real
Ubuntu host, 2,558 of 2,677 installed packages are assessable *only* through
OSV — they are matched by package name against distribution advisories and
need no CPE identity at all. 759 of 818 findings on that scan came from here.

Until this script, that data had no ingest path. Three million rows sat in the
database with nothing in the repository able to reproduce them: no refresh, no
rebuild after a restore, no way to add an ecosystem. A feed that cannot be
rebuilt is a feed that silently ages, and an aging vulnerability feed reports
"no findings" with exactly the same confidence as an accurate one.

What it fetches
───────────────
osv.dev publishes one zip per ecosystem containing every advisory as a JSON
document. `--list` prints what is offered. The default set covers the
operating systems and language ecosystems this scanner actually meets; `--all`
takes everything.

Two deliberate exclusions
─────────────────────────
*Withdrawn advisories* are skipped. OSV keeps them with a ``withdrawn``
timestamp so consumers can retract them; ingesting them re-asserts findings
their publisher has retracted.

*GIT ranges* are skipped by default (``--include-git-ranges`` restores them).
Their boundaries are 40-character commit hashes, not versions. 175,186 such
rows are in the database today, and no comparison between a commit hash and a
package version like ``5.1.2-4`` can mean anything. They cost storage and can
only ever add noise.

Known limitation, deliberately not addressed here
─────────────────────────────────────────────────
``osv_ranges`` is keyed ``(osv_id, introduced, fixed)`` with no package
column, so an advisory covering several packages stores their version ranges
undifferentiated. The matcher joins on ``osv_id`` alone and therefore compares
every affected package against every fixed version in the advisory. 133,262
advisories — 34% — carry more than one range, so this is not a corner case.

Fixing it means changing that table's uniqueness semantics and the matcher's
query together. That is a correctness change to live findings and deserves its
own migration and its own tests, so this script reproduces the existing shape
faithfully rather than half-changing it underneath the matcher.

Usage
─────
    python Backend/scripts/vuln/sync_osv.py --list
    python Backend/scripts/vuln/sync_osv.py                    # default set
    python Backend/scripts/vuln/sync_osv.py --ecosystems "Red Hat" npm
    python Backend/scripts/vuln/sync_osv.py --all --staging-dir D:\\ccure-feeds\\osv
"""

from __future__ import annotations

import argparse
import io
import json
import logging
import os
import re
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Sequence
from urllib.parse import quote

import requests

# The script runs from the repo root or from Backend/; make `core` importable
# either way so it picks up exactly the same database configuration the API and
# the worker use, rather than a second copy that can drift from it.
_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

import psycopg2  # noqa: E402
from psycopg2.extras import execute_values  # noqa: E402

from config import AppConfig  # noqa: E402

log = logging.getLogger("ccure.vuln.osv")

OSV_BUCKET = "https://osv-vulnerabilities.storage.googleapis.com"
ECOSYSTEMS_URL = f"{OSV_BUCKET}/ecosystems.txt"

#: Downloads land here unless told otherwise. Kept off the system drive by
#: default: the full set is well over a gigabyte of zip archives.
#: Feed downloads are staged here.
#:
#: ``CCURE_FEED_DIR`` sets one root for every feed; ``OSV_STAGING_DIR``
#: overrides it for this one. The default sits beside the repository so a
#: fresh checkout works anywhere — this repository is shared, and an absolute
#: ``D:\`` default is a machine-specific path that fails on every other
#: machine. Point ``CCURE_FEED_DIR`` at a roomy volume in ``Backend/.env``.
_FEED_ROOT = Path(
    os.getenv("CCURE_FEED_DIR") or Path(__file__).resolve().parents[3] / "feeds"
)

DEFAULT_STAGING = Path(os.getenv("OSV_STAGING_DIR") or _FEED_ROOT / "osv")

#: The ecosystems this scanner actually encounters. Operating systems first,
#: since those are what a credentialed audit of a real host matches against.
DEFAULT_ECOSYSTEMS = (
    # Operating systems
    "Ubuntu",
    "Debian",
    "Alpine",
    "Red Hat",
    "Rocky Linux",
    "AlmaLinux",
    "SUSE",
    "openSUSE",
    "Chainguard",
    "Wolfi",
    "Mageia",
    # Language ecosystems — these turn up in application stacks on those hosts
    "PyPI",
    "npm",
    "Maven",
    "Go",
    "NuGet",
    "RubyGems",
    "Packagist",
    "crates.io",
    "Hex",
    "Pub",
    "CRAN",
)

#: A 40-character hex string is a git commit, not a version.
_GIT_HASH = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)

_BATCH = 5000


# ── Schema ───────────────────────────────────────────────────────────────────


def ensure_schema(conn) -> None:
    """
    Create the OSV tables if they are absent.

    The point of this script is that the data can be rebuilt from nothing, and
    "nothing" includes an empty database — after a restore onto a fresh server,
    or when standing up a second environment. `vuln_intel` is not under this
    repository's alembic control (its `alembic_version` names a revision that
    exists nowhere in the tree), so the schema has to be asserted here or it is
    asserted nowhere.

    Written to match the shape already in production exactly, including the
    unique constraints the upserts below depend on.
    """
    with conn.cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS osv (
                id           text PRIMARY KEY,
                ecosystem    text,
                package_name text,
                modified     timestamptz
            );
            CREATE INDEX IF NOT EXISTS idx_osv_ecosystem ON osv (ecosystem);
            CREATE INDEX IF NOT EXISTS idx_osv_package   ON osv (package_name);

            CREATE TABLE IF NOT EXISTS osv_affected (
                id           serial PRIMARY KEY,
                osv_id       text REFERENCES osv (id) ON DELETE CASCADE,
                ecosystem    text,
                package_name text,
                UNIQUE (osv_id, ecosystem, package_name)
            );
            CREATE INDEX IF NOT EXISTS idx_osv_aff ON osv_affected (osv_id);
            CREATE INDEX IF NOT EXISTS idx_osv_affected_package_lower
                ON osv_affected (lower(package_name));

            CREATE TABLE IF NOT EXISTS osv_ranges (
                id         serial PRIMARY KEY,
                osv_id     text REFERENCES osv (id) ON DELETE CASCADE,
                introduced text,
                fixed      text,
                UNIQUE (osv_id, introduced, fixed)
            );
            CREATE INDEX IF NOT EXISTS idx_osv_ranges_osv ON osv_ranges (osv_id);

            -- Which package and release each range actually belongs to.
            --
            -- Without these, an advisory covering several packages or several
            -- distribution releases stores its ranges undifferentiated, and the
            -- matcher — which joins on osv_id alone — compares every installed
            -- package against every fixed version in the advisory. Observed on
            -- an Ubuntu 24.04 target: libtasn1-6 at 4.19.0-3ubuntu0.24.04.2 was
            -- reported as fixed in 4.20.0-2ubuntu0.25.10.1, which is 25.10's
            -- fix and cannot be installed on 24.04. 133,262 advisories (34%)
            -- carry more than one range, so this was not a corner case.
            --
            -- Added nullable so the columns can appear before the data does;
            -- the matcher tolerates NULL and falls back to the old behaviour
            -- for any row a re-sync has not yet rewritten.
            ALTER TABLE osv_ranges ADD COLUMN IF NOT EXISTS ecosystem    text;
            ALTER TABLE osv_ranges ADD COLUMN IF NOT EXISTS package_name text;

            -- The original constraint keyed ranges by (osv_id, introduced,
            -- fixed) alone, which is precisely the shape that loses the
            -- per-package detail: two packages in one advisory sharing an
            -- "introduced 0 / fixed X" pair collapse into a single row, and a
            -- third with a different fix cannot be told apart from them. It
            -- has to go before the scoped rows can be inserted at all.
            ALTER TABLE osv_ranges
                DROP CONSTRAINT IF EXISTS osv_ranges_osv_id_introduced_fixed_key;

            CREATE UNIQUE INDEX IF NOT EXISTS uq_osv_ranges_scoped
                ON osv_ranges (
                    osv_id,
                    coalesce(ecosystem, ''),
                    coalesce(package_name, ''),
                    coalesce(introduced, ''),
                    coalesce(fixed, '')
                );
            CREATE INDEX IF NOT EXISTS idx_osv_ranges_scope
                ON osv_ranges (osv_id, lower(package_name));

            CREATE TABLE IF NOT EXISTS osv_aliases (
                id     serial PRIMARY KEY,
                osv_id text REFERENCES osv (id) ON DELETE CASCADE,
                cve_id text,
                alias  text NOT NULL,
                CONSTRAINT unique_osv_alias UNIQUE (osv_id, alias)
            );
            CREATE INDEX IF NOT EXISTS idx_osv_alias_osv ON osv_aliases (osv_id);
            CREATE INDEX IF NOT EXISTS idx_osv_alias_cve ON osv_aliases (cve_id);
            """
        )
    conn.commit()


# ── Fetching ─────────────────────────────────────────────────────────────────


def list_ecosystems(session: requests.Session) -> list[str]:
    resp = session.get(ECOSYSTEMS_URL, timeout=60)
    resp.raise_for_status()
    return [line.strip() for line in resp.text.splitlines() if line.strip()]


def download_archive(
    session: requests.Session, ecosystem: str, staging: Path, force: bool = False
) -> Path | None:
    """
    Fetch one ecosystem's ``all.zip``, reusing the local copy when unchanged.

    OSV does not version these archives, so the local size is compared against
    the advertised ``Content-Length``. It is a weak check — a same-size change
    slips through — but the cost of being wrong is one stale ecosystem until
    the next ``--force``, while the cost of always downloading is 1.5 GB per
    run. ``--force`` exists for when that trade is not the right one.
    """
    staging.mkdir(parents=True, exist_ok=True)
    # Ecosystem names contain spaces ("Red Hat", "Rocky Linux") and the bucket
    # path must encode them, while the local filename must not.
    url = f"{OSV_BUCKET}/{quote(ecosystem)}/all.zip"
    target = staging / f"{ecosystem.replace('/', '_')}.zip"

    try:
        head = session.head(url, timeout=60)
    except requests.RequestException as exc:
        log.warning("%s: HEAD failed (%s) — skipping", ecosystem, exc)
        return None

    if head.status_code == 404:
        log.warning("%s: no archive published at %s — skipping", ecosystem, url)
        return None
    if head.status_code >= 400:
        log.warning("%s: HTTP %s from bucket — skipping", ecosystem, head.status_code)
        return None

    remote_size = int(head.headers.get("Content-Length") or 0)
    if (
        not force
        and target.exists()
        and remote_size
        and target.stat().st_size == remote_size
    ):
        log.info(
            "%s: local archive matches remote size (%.1f MB) — reusing",
            ecosystem,
            remote_size / 1048576,
        )
        return target

    log.info("%s: downloading %.1f MB", ecosystem, remote_size / 1048576)
    # Download beside the target and rename on success, so an interrupted run
    # cannot leave a truncated archive that the size check would then accept.
    partial = target.with_suffix(".zip.part")
    with session.get(url, stream=True, timeout=(30, 600)) as resp:
        resp.raise_for_status()
        with open(partial, "wb") as handle:
            for chunk in resp.iter_content(chunk_size=1 << 20):
                handle.write(chunk)
    partial.replace(target)
    log.info("%s: downloaded %.1f MB", ecosystem, target.stat().st_size / 1048576)
    return target


# ── Parsing ──────────────────────────────────────────────────────────────────


def iter_records(archive: Path) -> Iterator[dict[str, Any]]:
    """Yield each advisory JSON document in an ecosystem archive."""
    with zipfile.ZipFile(archive) as zf:
        for info in zf.infolist():
            if info.is_dir() or not info.filename.endswith(".json"):
                continue
            try:
                with zf.open(info) as handle:
                    yield json.load(io.TextIOWrapper(handle, encoding="utf-8"))
            except (
                json.JSONDecodeError,
                UnicodeDecodeError,
                zipfile.BadZipFile,
            ) as exc:
                # One malformed advisory must not abandon the other 100,000.
                log.debug(
                    "%s: unreadable entry %s (%s)", archive.name, info.filename, exc
                )


def _parse_modified(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def _range_pairs(
    affected: dict[str, Any], include_git: bool
) -> list[tuple[str | None, str | None]]:
    """
    The ``(introduced, fixed)`` pairs an affected entry declares.

    OSV expresses a range as an ordered event stream — ``introduced`` opens a
    window and ``fixed`` closes it — so events are walked in order and each
    ``introduced`` is paired with the boundary that closes it. A window left
    open (introduced with no fix published) is recorded with ``fixed`` NULL,
    which is the honest representation: affected, no fix available.
    """
    pairs: list[tuple[str | None, str | None]] = []
    for rng in affected.get("ranges") or []:
        if not isinstance(rng, dict):
            continue
        if not include_git and str(rng.get("type") or "").upper() == "GIT":
            continue

        current: str | None = None
        opened = False
        for event in rng.get("events") or []:
            if not isinstance(event, dict):
                continue
            if "introduced" in event:
                if opened:
                    pairs.append((current, None))
                current = str(event["introduced"])
                opened = True
            elif "fixed" in event:
                pairs.append((current, str(event["fixed"])))
                current, opened = None, False
            elif "last_affected" in event:
                # `last_affected` is inclusive where `fixed` is exclusive. The
                # table has only a `fixed` column, and writing an inclusive
                # bound into it would declare the last vulnerable version to be
                # the first safe one — reporting the fixed release as
                # vulnerable, or missing it, depending on the comparison. The
                # window is left open instead: affected, upper bound unstated.
                pairs.append((current, None))
                current, opened = None, False
        if opened:
            pairs.append((current, None))

    if not include_git:
        pairs = [
            (i, f)
            for (i, f) in pairs
            if not (i and _GIT_HASH.match(i)) and not (f and _GIT_HASH.match(f))
        ]
    return pairs


def extract(record: dict[str, Any], include_git: bool) -> tuple[
    tuple[str, str | None, str | None, datetime | None] | None,
    list[tuple[str, str, str]],
    list[tuple[str, str | None, str | None]],
    list[tuple[str, str | None, str]],
]:
    """Flatten one advisory into rows for the four OSV tables."""
    osv_id = str(record.get("id") or "").strip()
    if not osv_id:
        return None, [], [], []
    if record.get("withdrawn"):
        return None, [], [], []

    modified = _parse_modified(record.get("modified"))

    affected_rows: list[tuple[str, str, str]] = []
    range_rows: list[tuple[str, str | None, str | None, str, str]] = []
    seen_affected: set[tuple[str, str]] = set()
    seen_ranges: set[tuple] = set()

    for affected in record.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        package = affected.get("package") or {}
        ecosystem = str(package.get("ecosystem") or "").strip()
        name = str(package.get("name") or "").strip()
        if ecosystem and name and (ecosystem, name) not in seen_affected:
            seen_affected.add((ecosystem, name))
            affected_rows.append((osv_id, ecosystem, name))

        # Ranges are recorded against the package and release that declared
        # them, so a multi-package or multi-release advisory can no longer have
        # one entry's fixed version compared against another's installed one.
        for pair in _range_pairs(affected, include_git):
            key = (pair[0], pair[1], ecosystem, name)
            if key not in seen_ranges:
                seen_ranges.add(key)
                range_rows.append((osv_id, pair[0], pair[1], ecosystem, name))

    if not affected_rows:
        # Nothing names a package, so nothing here can ever match an installed
        # one. Storing it would inflate the row count without adding coverage.
        return None, [], [], []

    # `osv.ecosystem`/`osv.package_name` are the summary columns the existing
    # schema carries; the authoritative per-package list is `osv_affected`.
    head_eco, head_pkg = affected_rows[0][1], affected_rows[0][2]

    alias_rows: list[tuple[str, str | None, str]] = []
    seen_alias: set[str] = set()
    # `aliases` is only where *some* publishers put the CVE. The RHEL family
    # and SUSE use `upstream` (the upstream vulnerability this advisory fixes)
    # and `related`, and never populate `aliases` at all — measured across the
    # published archives, 0 of 3,846 Rocky records and 0 of 4,000 Red Hat
    # records carry one, while every Rocky record carries `upstream`.
    #
    # Reading only `aliases` left every RHEL-family advisory with no alias row,
    # and the matcher reaches findings through an inner join on
    # `osv_aliases.cve_id`. So 67,266 newly ingested RHEL-family advisories
    # matched packages correctly and were then dropped before they could be
    # reported: a Rocky 9.8 host with five genuinely outdated packages audited
    # completely clean.
    for field in ("aliases", "upstream", "related"):
        for alias in record.get(field) or []:
            text = str(alias or "").strip()
            if not text or text in seen_alias:
                continue
            seen_alias.add(text)
            cve = text if text.upper().startswith("CVE-") else None
            alias_rows.append((osv_id, cve, text))

    # An advisory whose own id is a CVE is its own alias. The matcher reaches
    # findings through `osv_aliases.cve_id`, so without this row every
    # DEBIAN-CVE-… and ALPINE-CVE-… style advisory would match a package and
    # then have no CVE to report it under.
    if osv_id.upper().startswith("CVE-") and osv_id not in seen_alias:
        alias_rows.append((osv_id, osv_id, osv_id))
    else:
        embedded = re.search(r"(CVE-\d{4}-\d{4,})", osv_id, re.IGNORECASE)
        if embedded and embedded.group(1) not in seen_alias:
            alias_rows.append(
                (osv_id, embedded.group(1).upper(), embedded.group(1).upper())
            )

    return (osv_id, head_eco, head_pkg, modified), affected_rows, range_rows, alias_rows


# ── Loading ──────────────────────────────────────────────────────────────────


def _flush(conn, osv_rows, affected_rows, range_rows, alias_rows) -> None:
    """
    Write one batch. Order matters: every other table has a foreign key onto
    `osv`, so the parent rows are inserted first.
    """
    with conn.cursor() as cur:
        if osv_rows:
            execute_values(
                cur,
                """
                INSERT INTO osv (id, ecosystem, package_name, modified)
                VALUES %s
                ON CONFLICT (id) DO UPDATE SET
                    ecosystem    = EXCLUDED.ecosystem,
                    package_name = EXCLUDED.package_name,
                    modified     = EXCLUDED.modified
                """,
                osv_rows,
                page_size=1000,
            )
        if affected_rows:
            execute_values(
                cur,
                """
                INSERT INTO osv_affected (osv_id, ecosystem, package_name)
                VALUES %s
                ON CONFLICT (osv_id, ecosystem, package_name) DO NOTHING
                """,
                affected_rows,
                page_size=1000,
            )
        if range_rows:
            # The unique index coalesces NULLs, so ON CONFLICT can carry the
            # de-duplication here rather than needing a NOT EXISTS probe.
            execute_values(
                cur,
                """
                INSERT INTO osv_ranges
                    (osv_id, introduced, fixed, ecosystem, package_name)
                VALUES %s
                ON CONFLICT (
                    osv_id,
                    coalesce(ecosystem, ''),
                    coalesce(package_name, ''),
                    coalesce(introduced, ''),
                    coalesce(fixed, '')
                ) DO NOTHING
                """,
                range_rows,
                page_size=1000,
            )
        if alias_rows:
            # `osv_aliases.cve_id` has a foreign key onto `cve`. An advisory
            # routinely names a CVE that NVD has not published yet, and
            # inserting it raw aborts the whole batch on a FK violation. The
            # lookup resolves to NULL for those, which is what the column
            # means: alias recorded, no CVE row to point at. Re-running after
            # an NVD sync links them.
            execute_values(
                cur,
                """
                INSERT INTO osv_aliases (osv_id, cve_id, alias)
                SELECT v.osv_id,
                       (SELECT c.cve_id FROM cve c WHERE c.cve_id = v.cve_id),
                       v.alias
                FROM (VALUES %s) AS v (osv_id, cve_id, alias)
                ON CONFLICT ON CONSTRAINT unique_osv_alias DO NOTHING
                """,
                alias_rows,
                page_size=1000,
            )
    conn.commit()


def sync_ecosystem(conn, archive: Path, ecosystem: str, include_git: bool) -> dict:
    """Load one ecosystem archive into the database. Returns per-table counts."""
    counts = {"records": 0, "skipped": 0, "affected": 0, "ranges": 0, "aliases": 0}
    osv_rows: list = []
    affected_rows: list = []
    range_rows: list = []
    alias_rows: list = []

    for record in iter_records(archive):
        osv_row, affected, ranges, aliases = extract(record, include_git)
        if osv_row is None:
            counts["skipped"] += 1
            continue

        osv_rows.append(osv_row)
        affected_rows.extend(affected)
        range_rows.extend(ranges)
        alias_rows.extend(aliases)

        counts["records"] += 1
        counts["affected"] += len(affected)
        counts["ranges"] += len(ranges)
        counts["aliases"] += len(aliases)

        if len(osv_rows) >= _BATCH:
            _flush(conn, osv_rows, affected_rows, range_rows, alias_rows)
            osv_rows, affected_rows, range_rows, alias_rows = [], [], [], []
            log.info("%s: %s advisories loaded", ecosystem, f"{counts['records']:,}")

    if osv_rows:
        _flush(conn, osv_rows, affected_rows, range_rows, alias_rows)

    return counts


# ── Entry point ──────────────────────────────────────────────────────────────


def _connect():
    url = AppConfig.VULN_DB_URL
    # AppConfig hands out a SQLAlchemy URL; psycopg2 wants a libpq one.
    return psycopg2.connect(url.replace("postgresql+psycopg2://", "postgresql://"))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Rebuild the OSV advisory tables in vuln_intel from osv.dev."
    )
    parser.add_argument(
        "--list", action="store_true", help="print available ecosystems and exit"
    )
    parser.add_argument(
        "--all", action="store_true", help="sync every published ecosystem"
    )
    parser.add_argument(
        "--ecosystems", nargs="+", metavar="NAME", help="ecosystems to sync"
    )
    parser.add_argument("--staging-dir", type=Path, default=DEFAULT_STAGING)
    parser.add_argument(
        "--force", action="store_true", help="re-download even if size matches"
    )
    parser.add_argument(
        "--include-git-ranges",
        action="store_true",
        help="keep commit-hash ranges (they cannot compare against package versions)",
    )
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
    )

    session = requests.Session()
    session.headers["User-Agent"] = "CCure-Audit-PRO/osv-sync"

    published = list_ecosystems(session)
    if args.list:
        for name in published:
            print(name)
        return 0

    if args.all:
        # The bucket lists versioned children ("Ubuntu:22.04:LTS") alongside
        # their parent. The parent archive already contains every child, so
        # syncing both downloads the same advisories twice.
        wanted = [e for e in published if ":" not in e]
    elif args.ecosystems:
        wanted = list(args.ecosystems)
    else:
        wanted = [e for e in DEFAULT_ECOSYSTEMS if e in published]
        missing = [e for e in DEFAULT_ECOSYSTEMS if e not in published]
        if missing:
            log.info("Not published by OSV, skipping: %s", ", ".join(missing))

    log.info("Syncing %d ecosystem(s) into %s", len(wanted), AppConfig.VULN_DB_NAME)
    log.info("Staging archives in %s", args.staging_dir)

    conn = _connect()
    try:
        ensure_schema(conn)
        totals = {"records": 0, "skipped": 0, "affected": 0, "ranges": 0, "aliases": 0}

        for ecosystem in wanted:
            archive = download_archive(session, ecosystem, args.staging_dir, args.force)
            if archive is None:
                continue
            started = datetime.now(timezone.utc)
            counts = sync_ecosystem(conn, archive, ecosystem, args.include_git_ranges)
            elapsed = (datetime.now(timezone.utc) - started).total_seconds()
            log.info(
                "%s: %s advisories, %s affected, %s ranges, %s aliases "
                "(%s withdrawn/unusable skipped) in %.1fs",
                ecosystem,
                f"{counts['records']:,}",
                f"{counts['affected']:,}",
                f"{counts['ranges']:,}",
                f"{counts['aliases']:,}",
                f"{counts['skipped']:,}",
                elapsed,
            )
            for key in totals:
                totals[key] += counts[key]

        log.info(
            "Done. %s advisories, %s affected rows, %s ranges, %s aliases.",
            f"{totals['records']:,}",
            f"{totals['affected']:,}",
            f"{totals['ranges']:,}",
            f"{totals['aliases']:,}",
        )
    finally:
        conn.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
