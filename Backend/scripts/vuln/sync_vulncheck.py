"""
scripts/vuln/sync_vulncheck.py
─────────────────────────────────────────────────────────────────────────────
Ingest VulnCheck KEV — a broader "exploited in the wild" catalogue than CISA's.

Why this is stored separately from `kev`
────────────────────────────────────────
It is tempting to merge this into the existing `kev` table and be done. That
would be wrong, because the two catalogues answer different questions and only
one of them carries a legal obligation.

**CISA KEV** exists to drive US federal remediation deadlines under BOD 22-01.
Each entry has a `due_date`, and a finding marked "in KEV" in a report is read
as "this has a mandated fix-by date". 1,647 entries.

**VulnCheck KEV** is threat intelligence: vulnerabilities observed being
exploited, including ones CISA has not catalogued and may never. 5,117 entries
— roughly three times the coverage. It carries no deadline and implies no
compliance duty.

Folding VulnCheck into `kev` would attach an imaginary federal deadline to
3,470 vulnerabilities that have none, and a compliance report built on that
would be wrong in a way nobody would notice. So `in_kev` keeps meaning exactly
"CISA KEV", and this lands in its own table with its own signal.

What VulnCheck adds beyond a bigger list
────────────────────────────────────────
* ``reported_exploited_by_vulncheck_canaries`` — observed being exploited
  against VulnCheck's own honeypots. That is direct observation rather than a
  report of one, and it is the strongest exploitation evidence in any feed
  here.
* ``knownRansomwareCampaignUse`` — used in ransomware campaigns.
* ``vulncheck_reported_exploitation`` — the sources that reported it, so a
  claim can be followed back rather than taken on trust.

Requires ``VULNCHECK_API_TOKEN`` in the environment (Backend/.env). The token
is never written to the repository.

Usage
─────
    python Backend/scripts/vuln/sync_vulncheck.py
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Sequence

import requests

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

import psycopg2  # noqa: E402
from psycopg2.extras import execute_values  # noqa: E402

from config import AppConfig  # noqa: E402

log = logging.getLogger("ccure.vuln.vulncheck")

API = "https://api.vulncheck.com/v3/index/vulncheck-kev"

#: The API caps pagination at 6 pages regardless of page size, so the page size
#: has to be large enough that 6 pages covers the catalogue. At 1,000 it does,
#: with room to grow; a smaller page size silently truncates the feed.
_PAGE_SIZE = 1000
_MAX_PAGES = 6

_CVE_TOKEN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def ensure_schema(conn) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS vulncheck_kev (
                cve_id            text PRIMARY KEY,
                vendor_project    text,
                product           text,
                vulnerability_name text,
                date_added        timestamptz,
                -- Observed against VulnCheck's honeypots rather than reported
                -- by a third party. Direct observation, and the strongest
                -- exploitation evidence available from any feed here.
                canary_confirmed  boolean NOT NULL DEFAULT false,
                ransomware        text,
                report_count      integer NOT NULL DEFAULT 0,
                required_action   text,
                refreshed_at      timestamptz DEFAULT now()
            );
            CREATE INDEX IF NOT EXISTS idx_vulncheck_canary
                ON vulncheck_kev (canary_confirmed) WHERE canary_confirmed;
            CREATE INDEX IF NOT EXISTS idx_vulncheck_date
                ON vulncheck_kev (date_added);
            """
        )
    conn.commit()


def _parse_date(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def fetch_all(session: requests.Session) -> list[dict]:
    records: list[dict] = []
    for page in range(1, _MAX_PAGES + 1):
        resp = session.get(
            API, params={"limit": _PAGE_SIZE, "page": page}, timeout=(20, 180)
        )
        if resp.status_code == 401:
            raise SystemExit(
                "VulnCheck rejected the token (HTTP 401). Check VULNCHECK_API_TOKEN."
            )
        resp.raise_for_status()
        payload = resp.json()
        data = payload.get("data") or []
        meta = payload.get("_meta") or {}
        records.extend(data)
        total = meta.get("total_documents")
        log.info(
            "page %d/%s: %s records (total catalogue %s)",
            page,
            min(_MAX_PAGES, meta.get("total_pages") or _MAX_PAGES),
            f"{len(data):,}",
            f"{total:,}" if isinstance(total, int) else total,
        )
        if len(data) < _PAGE_SIZE:
            break
        if isinstance(total, int) and len(records) >= total:
            break

    # A silent truncation here would understate exploitation across the whole
    # database, so it is checked rather than assumed.
    if records:
        meta_total = total if isinstance(total, int) else None
        if meta_total and len(records) < meta_total:
            log.warning(
                "Retrieved %s of %s entries — the API's %d-page cap was reached. "
                "Raise _PAGE_SIZE if the catalogue has grown.",
                f"{len(records):,}",
                f"{meta_total:,}",
                _MAX_PAGES,
            )
    return records


def extract(records: Sequence[dict]) -> list[tuple]:
    rows: dict[str, tuple] = {}
    for rec in records:
        # `cve` is an array: one entry can cover several CVEs.
        for raw_cve in rec.get("cve") or []:
            cve = str(raw_cve or "").strip().upper()
            if not _CVE_TOKEN.match(cve):
                continue
            reports = rec.get("vulncheck_reported_exploitation") or []
            ransomware = str(rec.get("knownRansomwareCampaignUse") or "").strip()
            rows[cve] = (
                cve,
                str(rec.get("vendorProject") or "")[:200] or None,
                str(rec.get("product") or "")[:200] or None,
                str(rec.get("vulnerabilityName") or "")[:500] or None,
                _parse_date(rec.get("date_added")),
                bool(rec.get("reported_exploited_by_vulncheck_canaries")),
                ransomware or None,
                len(reports) if isinstance(reports, list) else 0,
                str(rec.get("required_action") or "")[:1000] or None,
            )
    return list(rows.values())


def load(conn, rows: list[tuple]) -> dict:
    with conn.cursor() as cur:
        execute_values(
            cur,
            """
            INSERT INTO vulncheck_kev
                (cve_id, vendor_project, product, vulnerability_name, date_added,
                 canary_confirmed, ransomware, report_count, required_action)
            VALUES %s
            ON CONFLICT (cve_id) DO UPDATE SET
                vendor_project     = EXCLUDED.vendor_project,
                product            = EXCLUDED.product,
                vulnerability_name = EXCLUDED.vulnerability_name,
                date_added         = EXCLUDED.date_added,
                canary_confirmed   = EXCLUDED.canary_confirmed,
                ransomware         = EXCLUDED.ransomware,
                report_count       = EXCLUDED.report_count,
                required_action    = EXCLUDED.required_action,
                refreshed_at       = now()
            """,
            rows,
            page_size=1000,
        )

        # Exploitation evidence also belongs in the exploit-availability signal.
        # Constrained to CVEs the local NVD mirror knows, because
        # `exploits.cve_id` has a foreign key onto `cve` and VulnCheck lists
        # vulnerabilities NVD has not published yet.
        cur.execute(
            """
            INSERT INTO exploits (cve_id, has_exploit, exploit_sources, verified_exploit)
            SELECT v.cve_id, true, ARRAY['VulnCheck KEV'], v.canary_confirmed
            FROM vulncheck_kev v
            JOIN cve c ON c.cve_id = v.cve_id
            ON CONFLICT (cve_id) DO UPDATE SET
                has_exploit = true,
                exploit_sources = (
                    SELECT array_agg(DISTINCT s ORDER BY s)
                    FROM unnest(
                        COALESCE(exploits.exploit_sources, ARRAY[]::text[])
                        || ARRAY['VulnCheck KEV']
                    ) AS s
                ),
                -- Honeypot observation is verification; a third-party report
                -- of exploitation is not, so it must not clear a flag another
                -- source earned.
                verified_exploit = exploits.verified_exploit OR EXCLUDED.verified_exploit,
                refreshed_at = now()
            """
        )
        linked = cur.rowcount

        cur.execute("SELECT count(*) FROM vulncheck_kev")
        stored = cur.fetchone()[0]
        cur.execute("SELECT count(*) FROM vulncheck_kev WHERE canary_confirmed")
        canary = cur.fetchone()[0]
        cur.execute("SELECT count(*) FROM vulncheck_kev WHERE ransomware ILIKE 'known'")
        ransomware = cur.fetchone()[0]
    conn.commit()
    return {
        "stored": stored,
        "canary": canary,
        "ransomware": ransomware,
        "linked": linked,
    }


def _connect():
    url = AppConfig.VULN_DB_URL
    return psycopg2.connect(url.replace("postgresql+psycopg2://", "postgresql://"))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Ingest VulnCheck KEV into vuln_intel."
    )
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
    )

    token = (os.getenv("VULNCHECK_API_TOKEN") or "").strip()
    if not token:
        log.error(
            "VULNCHECK_API_TOKEN is not set. Add it to Backend/.env — the free "
            "tier token is issued at vulncheck.com."
        )
        return 2

    session = requests.Session()
    session.headers.update(
        {
            "Authorization": f"Bearer {token}",
            "User-Agent": "CCure-Audit-PRO/vulncheck-sync",
        }
    )

    records = fetch_all(session)
    rows = extract(records)
    log.info(
        "Parsed %s entries into %s distinct CVEs", f"{len(records):,}", f"{len(rows):,}"
    )

    conn = _connect()
    try:
        ensure_schema(conn)
        result = load(conn, rows)
        log.info(
            "Stored %s CVEs — %s confirmed by honeypot, %s used in ransomware. "
            "%s linked into the exploit signal.",
            f"{result['stored']:,}",
            f"{result['canary']:,}",
            f"{result['ransomware']:,}",
            f"{result['linked']:,}",
        )

        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM kev")
            cisa = cur.fetchone()[0]
            cur.execute(
                "SELECT count(*) FROM vulncheck_kev v "
                "WHERE NOT EXISTS (SELECT 1 FROM kev k WHERE k.cve_id = v.cve_id)"
            )
            beyond = cur.fetchone()[0]
        log.info(
            "CISA KEV holds %s; VulnCheck adds %s exploited CVEs CISA does not list.",
            f"{cisa:,}",
            f"{beyond:,}",
        )
    finally:
        conn.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
