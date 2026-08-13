"""
scripts/vuln/sync_msrc.py
─────────────────────────────────────────────────────────────────────────────
Ingest Microsoft's Security Update Guide (CVRF v3.0) into `vuln_intel`.

Why this exists
───────────────
A credentialed audit of a Windows host currently assesses it the same way it
assesses a third-party application: by resolving names in the uninstall
registry to CPE identities. On a real host that reached 13 of 192 installed
applications — 6.8% — and the operating system itself is the largest thing it
misses. Windows does not appear in the uninstall registry, and NVD's CPE entry
for "Windows 11" carries no notion of which cumulative update is installed, so
the OS was effectively unassessed.

Microsoft publishes the missing half. Each monthly Security Update document
lists, per CVE and per product, the update that fixes it and — decisively —
the **build number that update produces**:

    CVE-2026-33834  KB5087539  fixed_build=10.0.26100.32860  Windows Server 2025

A Windows host reports its own build (``10.0.26100.4061``). Comparing the two
answers "is this host patched for this CVE" directly, with no inference from
software names at all.

Why build numbers rather than installed KBs
───────────────────────────────────────────
``Get-HotFix`` lists KB identifiers, and the obvious approach is to check
whether the fixing KB is among them. That approach is wrong in a way that
fails toward false positives: cumulative updates supersede one another, so a
host patched to KB5094127 has never installed KB5087544 and never will, yet is
patched for everything KB5087544 fixed. Chasing ``Supercedence`` chains to
repair this means walking a graph that is incomplete in the feed itself.

The build number sidesteps all of it. Cumulative updates advance the build
monotonically, so ``host_build >= fixed_build`` settles the question in one
comparison, whatever path the host took to get there.

The product mapping is derived, not hardcoded
─────────────────────────────────────────────
Mapping a host to a Microsoft product ("Windows 11 Version 25H2 for x64-based
Systems") is normally a hand-maintained table that rots with every release.
It does not have to be. Every fixed build for that product begins with the
same three components — ``10.0.26200`` — so the feed states the mapping
itself. `msrc_product_build` derives it, and a Windows release published next
year maps itself the first time its first patch ships.

Usage
─────
    python Backend/scripts/vuln/sync_msrc.py                 # 2016 onward
    python Backend/scripts/vuln/sync_msrc.py --since 2024
    python Backend/scripts/vuln/sync_msrc.py --force         # re-fetch all
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

import requests

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

import psycopg2  # noqa: E402
from psycopg2.extras import execute_values  # noqa: E402

from config import AppConfig  # noqa: E402

log = logging.getLogger("ccure.vuln.msrc")

MSRC_BASE = "https://api.msrc.microsoft.com/cvrf/v3.0"
UPDATES_URL = f"{MSRC_BASE}/updates"

#: See sync_osv.py for the rationale: one shared root, overridable per feed,
#: defaulting beside the repository so a checkout needs no D: drive.
_FEED_ROOT = Path(
    os.getenv("CCURE_FEED_DIR") or Path(__file__).resolve().parents[3] / "feeds"
)

DEFAULT_STAGING = Path(os.getenv("MSRC_STAGING_DIR") or _FEED_ROOT / "msrc")

#: CVRF remediation type 2 is "Vendor Fix" — the only kind that names a build
#: a host can be compared against. Types 3 and 6 are workarounds and mitigations,
#: which describe actions an administrator may have taken and which nothing on
#: the host can confirm.
REMEDIATION_VENDOR_FIX = 2

#: Documents before this year use an older product-naming scheme and describe
#: operating systems long out of support; ingesting them adds rows that can
#: never match a live host.
DEFAULT_SINCE_YEAR = 2016

_BUILD = re.compile(r"^\d+\.\d+\.\d+\.\d+$")
_KB = re.compile(r"^\d{6,8}$")


# ── Schema ───────────────────────────────────────────────────────────────────


def ensure_schema(conn) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS msrc_document (
                id                   text PRIMARY KEY,
                title                text,
                current_release_date timestamptz,
                ingested_at          timestamptz DEFAULT now()
            );

            CREATE TABLE IF NOT EXISTS msrc_product (
                product_id text PRIMARY KEY,
                name       text NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_msrc_product_name_lower
                ON msrc_product (lower(name));

            CREATE TABLE IF NOT EXISTS msrc_remediation (
                id          serial PRIMARY KEY,
                cve_id      text NOT NULL,
                product_id  text NOT NULL,
                kb_id       text,
                fixed_build text NOT NULL,
                supersedes  text,
                document_id text,
                release_date timestamptz
            );
            -- kb_id is occasionally absent while fixed_build is not. A plain
            -- UNIQUE would let those rows duplicate on every re-run, because
            -- NULL never equals NULL.
            CREATE UNIQUE INDEX IF NOT EXISTS uq_msrc_remediation
                ON msrc_remediation (cve_id, product_id, coalesce(kb_id, ''), fixed_build);
            CREATE INDEX IF NOT EXISTS idx_msrc_rem_product ON msrc_remediation (product_id);
            CREATE INDEX IF NOT EXISTS idx_msrc_rem_cve     ON msrc_remediation (cve_id);

            -- The host-to-product mapping, read straight out of the fixed
            -- builds rather than maintained by hand. A host reporting
            -- 10.0.26200.1234 matches every product whose builds start
            -- 10.0.26200.
            CREATE OR REPLACE VIEW msrc_product_build AS
            SELECT DISTINCT
                r.product_id,
                p.name AS product_name,
                substring(r.fixed_build from '^[0-9]+\\.[0-9]+\\.[0-9]+') AS build_prefix
            FROM msrc_remediation r
            JOIN msrc_product p ON p.product_id = r.product_id
            WHERE r.fixed_build ~ '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$';
            """
        )
    conn.commit()


# ── Fetching ─────────────────────────────────────────────────────────────────


def fetch_updates(session: requests.Session) -> list[dict[str, Any]]:
    resp = session.get(UPDATES_URL, timeout=120)
    resp.raise_for_status()
    return resp.json().get("value", [])


def fetch_document(
    session: requests.Session, doc_id: str, staging: Path, force: bool
) -> dict[str, Any] | None:
    """
    Fetch one monthly document, caching the raw JSON.

    The cache is what makes re-parsing cheap: the full history is well over a
    gigabyte of JSON, and a parser change should not mean downloading all of it
    from Microsoft again.
    """
    staging.mkdir(parents=True, exist_ok=True)
    cached = staging / f"{doc_id}.json"

    if cached.exists() and not force:
        try:
            return json.loads(cached.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            log.debug("%s: cached copy unreadable, refetching", doc_id)

    try:
        resp = session.get(f"{MSRC_BASE}/cvrf/{doc_id}", timeout=(30, 300))
        resp.raise_for_status()
    except requests.RequestException as exc:
        log.warning("%s: fetch failed (%s) — skipping", doc_id, exc)
        return None

    try:
        payload = resp.json()
    except ValueError:
        log.warning("%s: response was not JSON — skipping", doc_id)
        return None

    cached.write_text(json.dumps(payload), encoding="utf-8")
    return payload


# ── Parsing ──────────────────────────────────────────────────────────────────


def _parse_date(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def extract(doc: dict[str, Any], doc_id: str) -> tuple[list[tuple], list[tuple]]:
    """Return ``(product_rows, remediation_rows)`` for one monthly document."""
    tree = doc.get("ProductTree") or {}
    products: list[tuple[str, str]] = []
    for entry in tree.get("FullProductName") or []:
        pid = str(entry.get("ProductID") or "").strip()
        name = str(entry.get("Value") or "").strip()
        if pid and name:
            products.append((pid, name))

    remediations: list[tuple] = []
    for vuln in doc.get("Vulnerability") or []:
        cve = str(vuln.get("CVE") or "").strip()
        if not cve:
            continue
        released = _parse_date(vuln.get("ReleaseDate"))

        for rem in vuln.get("Remediations") or []:
            if rem.get("Type") != REMEDIATION_VENDOR_FIX:
                continue
            fixed_build = str(rem.get("FixedBuild") or "").strip()
            # Without a build there is nothing to compare a host against, and
            # a remediation row that cannot answer the question is a row that
            # will be joined, filtered and discarded on every scan.
            if not _BUILD.match(fixed_build):
                continue

            description = str((rem.get("Description") or {}).get("Value") or "").strip()
            kb = description if _KB.match(description) else None
            supersedes = str(rem.get("Supercedence") or "").strip() or None

            for pid in rem.get("ProductID") or []:
                pid = str(pid).strip()
                if pid:
                    remediations.append(
                        (cve, pid, kb, fixed_build, supersedes, doc_id, released)
                    )

    return products, remediations


# ── Loading ──────────────────────────────────────────────────────────────────


def load(conn, products: list[tuple], remediations: list[tuple]) -> None:
    with conn.cursor() as cur:
        if products:
            execute_values(
                cur,
                """
                INSERT INTO msrc_product (product_id, name)
                VALUES %s
                ON CONFLICT (product_id) DO UPDATE SET name = EXCLUDED.name
                """,
                products,
                page_size=1000,
            )
        if remediations:
            execute_values(
                cur,
                """
                INSERT INTO msrc_remediation
                    (cve_id, product_id, kb_id, fixed_build, supersedes, document_id, release_date)
                VALUES %s
                ON CONFLICT (cve_id, product_id, coalesce(kb_id, ''), fixed_build)
                DO NOTHING
                """,
                remediations,
                page_size=1000,
            )
    conn.commit()


def mark_document(conn, doc_id: str, title: str, released: datetime | None) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO msrc_document (id, title, current_release_date, ingested_at)
            VALUES (%s, %s, %s, now())
            ON CONFLICT (id) DO UPDATE SET
                title                = EXCLUDED.title,
                current_release_date = EXCLUDED.current_release_date,
                ingested_at          = now()
            """,
            (doc_id, title, released),
        )
    conn.commit()


def already_current(conn, doc_id: str, released: datetime | None) -> bool:
    """
    Whether this document has been ingested at its current revision.

    Microsoft revises past months in place — a CVE gains a product, or a build
    is corrected — and bumps ``CurrentReleaseDate`` when it does. Comparing
    against the stored value re-fetches exactly the months that changed.
    """
    if released is None:
        return False
    with conn.cursor() as cur:
        cur.execute(
            "SELECT current_release_date FROM msrc_document WHERE id = %s", (doc_id,)
        )
        row = cur.fetchone()
    return bool(row and row[0] and row[0] >= released)


# ── Entry point ──────────────────────────────────────────────────────────────


def _connect():
    url = AppConfig.VULN_DB_URL
    return psycopg2.connect(url.replace("postgresql+psycopg2://", "postgresql://"))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Ingest Microsoft Security Update Guide data into vuln_intel."
    )
    parser.add_argument(
        "--since",
        type=int,
        default=DEFAULT_SINCE_YEAR,
        help=f"earliest document year (default {DEFAULT_SINCE_YEAR})",
    )
    parser.add_argument("--staging-dir", type=Path, default=DEFAULT_STAGING)
    parser.add_argument(
        "--force", action="store_true", help="re-fetch and re-parse every document"
    )
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
    )

    session = requests.Session()
    session.headers.update(
        {"Accept": "application/json", "User-Agent": "CCure-Audit-PRO/msrc-sync"}
    )

    updates = fetch_updates(session)
    log.info("MSRC publishes %d update documents", len(updates))

    selected = []
    for upd in updates:
        doc_id = str(upd.get("ID") or "").strip()
        released = _parse_date(upd.get("CurrentReleaseDate"))
        initial = _parse_date(upd.get("InitialReleaseDate"))
        year = (initial or released).year if (initial or released) else 0
        if year < args.since:
            continue
        selected.append((doc_id, str(upd.get("DocumentTitle") or ""), released))

    log.info("Selected %d documents from %s onward", len(selected), args.since)

    conn = _connect()
    try:
        ensure_schema(conn)
        total_products = total_rems = skipped = 0

        for doc_id, title, released in selected:
            if not args.force and already_current(conn, doc_id, released):
                skipped += 1
                continue

            doc = fetch_document(session, doc_id, args.staging_dir, args.force)
            if doc is None:
                continue

            products, remediations = extract(doc, doc_id)
            load(conn, products, remediations)
            mark_document(conn, doc_id, title, released)

            total_products += len(products)
            total_rems += len(remediations)
            log.info(
                "%-10s %-34s %5d products %6d vendor fixes",
                doc_id,
                title[:34],
                len(products),
                len(remediations),
            )

        if skipped:
            log.info("%d documents already current — not re-fetched", skipped)

        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM msrc_product")
            products_total = cur.fetchone()[0]
            cur.execute("SELECT count(*) FROM msrc_remediation")
            rems_total = cur.fetchone()[0]
            cur.execute("SELECT count(DISTINCT cve_id) FROM msrc_remediation")
            cves_total = cur.fetchone()[0]
            cur.execute("SELECT count(DISTINCT build_prefix) FROM msrc_product_build")
            builds_total = cur.fetchone()[0]

        log.info(
            "Done. %s products, %s remediations covering %s CVEs, "
            "%s distinct build lines mapped.",
            f"{products_total:,}",
            f"{rems_total:,}",
            f"{cves_total:,}",
            f"{builds_total:,}",
        )
    finally:
        conn.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
