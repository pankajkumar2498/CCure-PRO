"""
scripts/vuln/sync_csaf.py
─────────────────────────────────────────────────────────────────────────────
Ingest vendor and government CSAF 2.0 advisories into `vuln_intel`.

Why CSAF
────────
NVD is a lowest-common-denominator view. The vendor who shipped the software
publishes more, earlier, and with the remediation actually written down —
"Update to V2606 or later" rather than a version boundary inferred from a CPE
range. For OT equipment the difference is starker still: ICS advisories are
frequently the only structured source, because the affected products often have
no CPE at all.

CSAF is the format the industry converged on, which is what makes this worth
building once. Siemens, CISA, Red Hat, Cisco, Oracle, SUSE and most large
vendors publish it, so each additional source is an entry in `PROVIDERS` rather
than a new parser.

Discovery follows the standard: `provider-metadata.json` names ROLIE feeds,
each feed lists advisories, each advisory is a CSAF document. Where a provider
publishes a directory listing instead of ROLIE, it is skipped with a warning
rather than guessed at.

What is stored, and what is deliberately not
────────────────────────────────────────────
Advisories, their CVEs, their affected product names and their remediation
text are stored. That is enough to enrich a finding another engine already
raised: a CVE found on a Siemens host gains the vendor's own advisory and
remediation wording, and the CVE match is exact so the enrichment cannot be
wrong.

Automatic *matching* of installed software against CSAF product trees is not
done here. Those trees are nested branches whose version constraints are
expressed in the `vers:` range syntax ("vers:intdot/<2606"), and turning that
into a verdict about an installed package is precisely the kind of inference
that produces confident false positives. The data is stored faithfully so that
work can be done deliberately, with its own tests.

Usage
─────
    python Backend/scripts/vuln/sync_csaf.py --list
    python Backend/scripts/vuln/sync_csaf.py --providers siemens
    python Backend/scripts/vuln/sync_csaf.py --limit 50      # smoke test
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Sequence

import requests

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

import psycopg2  # noqa: E402
from psycopg2.extras import execute_values  # noqa: E402

from config import AppConfig  # noqa: E402

log = logging.getLogger("ccure.vuln.csaf")

#: Each provider's CSAF entry point, and how hard it may be asked.
#:
#: `metadata` follows the standard: the document names the ROLIE feeds, so
#: nothing below it is hardcoded and a provider reorganising its directories
#: does not break the sync.
#:
#: `workers` and `delay` exist because these are somebody else's
#: infrastructure. Fetched with eight threads and no pause, Siemens' portal
#: started refusing requests — "You made too many requests in a short time for
#: our system... please contact productcert@siemens.com" — and 137 of 831
#: documents were lost to it. A vendor PSIRT portal is not a CDN; the polite
#: rate is the correct rate, and a sync that takes longer but completes beats
#: a fast one that gets the source to block us.
PROVIDERS: dict[str, dict[str, Any]] = {
    # Directly relevant to the OT hosts this scanner is pointed at.
    "siemens": {
        "metadata": "https://cert-portal.siemens.com/productcert/csaf/provider-metadata.json",
        "workers": 1,
        "delay": 0.4,
    },
    # CISA publishes both ICS/OT and IT advisories; the OT feed is the one
    # nothing else covers.
    #
    # Its provider-metadata document sits behind a WAF that returns 403
    # intermittently — it answered a manual request and refused the identical
    # one minutes later. The feeds it names are hosted on raw.githubusercontent
    # and are entirely reliable, so they are declared here as a fallback. The
    # metadata is still tried first, so a change on CISA's side is picked up.
    "cisa": {
        "metadata": "https://www.cisa.gov/sites/default/files/csaf/provider-metadata.json",
        "feeds": [
            "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/"
            "OT/white/cisa-csaf-ot-feed-tlp-white.json",
            "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/"
            "IT/white/cisa-csaf-it-feed-tlp-white.json",
        ],
        "workers": 6,
        "delay": 0.0,
    },
    "redhat": {
        "metadata": "https://security.access.redhat.com/data/csaf/v2/provider-metadata.json",
        "workers": 4,
        "delay": 0.0,
    },
}

#: See sync_osv.py for the rationale: one shared root, overridable per feed,
#: defaulting beside the repository so a checkout needs no D: drive.
_FEED_ROOT = Path(
    os.getenv("CCURE_FEED_DIR") or Path(__file__).resolve().parents[3] / "feeds"
)

DEFAULT_STAGING = Path(os.getenv("CSAF_STAGING_DIR") or _FEED_ROOT / "csaf")

_CVE_TOKEN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

#: Some providers sit behind a CDN that rejects non-browser agents.
_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0"

#: Fallback when a provider names no worker count.
_FETCH_WORKERS = 4


# ── Schema ───────────────────────────────────────────────────────────────────


def ensure_schema(conn) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS csaf_advisory (
                id           text PRIMARY KEY,
                provider     text NOT NULL,
                title        text,
                published    timestamptz,
                updated      timestamptz,
                tlp          text,
                url          text
            );
            CREATE INDEX IF NOT EXISTS idx_csaf_provider ON csaf_advisory (provider);

            CREATE TABLE IF NOT EXISTS csaf_advisory_cve (
                advisory_id text NOT NULL
                    REFERENCES csaf_advisory (id) ON DELETE CASCADE,
                cve_id      text NOT NULL,
                cvss_score  double precision,
                UNIQUE (advisory_id, cve_id)
            );
            CREATE INDEX IF NOT EXISTS idx_csaf_cve ON csaf_advisory_cve (cve_id);

            -- Affected products as the vendor names them, with the vendor's own
            -- remediation wording. No CPE is asserted: most OT products have
            -- none, and inventing one would be a guess the report would then
            -- present as an identity.
            CREATE TABLE IF NOT EXISTS csaf_affected (
                id           serial PRIMARY KEY,
                advisory_id  text NOT NULL
                    REFERENCES csaf_advisory (id) ON DELETE CASCADE,
                cve_id       text,
                product_id   text,
                product_name text,
                category     text,
                status       text,
                remediation  text,
                -- The machine-readable version constraint from the branch
                -- name: the OpenSSF `vers` spec ("vers:all/<V5.6") or a plain
                -- operator and version ("<V2401.0000"). 96.1% of version-range
                -- branches carry one. `product_name` beside it is prose for a
                -- human and yields a parseable constraint only 11.4% of the
                -- time, so matching has to read this column, not that one.
                version_constraint text,
                UNIQUE (advisory_id, cve_id, product_id, status)
            );
            ALTER TABLE csaf_affected
                ADD COLUMN IF NOT EXISTS version_constraint text;
            CREATE INDEX IF NOT EXISTS idx_csaf_affected_advisory
                ON csaf_affected (advisory_id);
            CREATE INDEX IF NOT EXISTS idx_csaf_affected_product_lower
                ON csaf_affected (lower(product_name));
            """
        )
    conn.commit()


# ── Discovery ────────────────────────────────────────────────────────────────


def rolie_feeds(
    session: requests.Session, provider: str, metadata_url: str
) -> list[str]:
    """The ROLIE feed URLs a provider publishes, via its provider-metadata."""
    try:
        resp = session.get(metadata_url, timeout=(20, 90))
        resp.raise_for_status()
        metadata = resp.json()
    except (requests.RequestException, ValueError) as exc:
        log.warning("%s: provider metadata unreadable (%s)", provider, exc)
        return []

    feeds: list[str] = []
    for dist in metadata.get("distributions") or []:
        rolie = dist.get("rolie") or {}
        for feed in rolie.get("feeds") or []:
            url = str(feed.get("url") or "").strip()
            if url:
                feeds.append(url)
        # A directory_url distribution has no machine-readable index; walking
        # it means scraping HTML, which is guesswork. Say so rather than
        # silently covering less than the provider offers.
        if not rolie and dist.get("directory_url"):
            log.warning(
                "%s: publishes a directory listing (%s) rather than a ROLIE "
                "feed — not ingested, as there is no index to follow",
                provider,
                dist["directory_url"],
            )
    return feeds


def advisory_urls(session: requests.Session, feed_url: str) -> list[str]:
    try:
        resp = session.get(feed_url, timeout=(20, 180))
        resp.raise_for_status()
        feed = resp.json().get("feed") or {}
    except (requests.RequestException, ValueError) as exc:
        log.warning("feed unreadable (%s): %s", feed_url, exc)
        return []

    urls: list[str] = []
    for entry in feed.get("entry") or []:
        for link in entry.get("link") or []:
            href = str(link.get("href") or "")
            if href.endswith(".json"):
                urls.append(href)
                break
    return urls


# ── Parsing ──────────────────────────────────────────────────────────────────


def _parse_date(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def _walk_products(
    branches: Iterable[dict], out: dict[str, tuple[str, str, str]]
) -> None:
    """
    Flatten a CSAF product tree to ``product_id -> (name, category, constraint)``.

    The constraint is the *branch* name, and keeping it is the difference
    between data that can be matched and data that can only be read.

    ``product.name`` is prose written for a human — "Simcenter Nastran <
    V2606", "TIA Portal v15: All versions prior to v15.1 Update 7", or two
    products joined by "and". Measured across the corpus, only 11.4% of those
    yield a constraint a parser could act on.

    The branch name beside it carries the machine-readable form: the OpenSSF
    ``vers`` spec (``vers:all/<V5.6``) or a plain operator and version
    (``<V2401.0000``). Measured on the same corpus, **96.1%**. Storing only
    the prose made the whole product tree look unmatchable when the structured
    constraint was one field away.
    """
    for branch in branches or []:
        if not isinstance(branch, dict):
            continue
        product = branch.get("product")
        if isinstance(product, dict):
            pid = str(product.get("product_id") or "").strip()
            if pid:
                branch_name = str(branch.get("name") or "").strip()
                product_name = str(product.get("name") or branch_name).strip()
                category = str(branch.get("category") or "").strip()
                # Only a version-range branch carries a constraint; for any
                # other category the branch name is just the product's own.
                constraint = branch_name if category == "product_version_range" else ""
                out[pid] = (product_name, category, constraint)
        _walk_products(branch.get("branches") or [], out)


def extract(doc: dict, provider: str, url: str) -> tuple[tuple | None, list, list]:
    document = doc.get("document") or {}
    tracking = document.get("tracking") or {}
    advisory_id = str(tracking.get("id") or "").strip()
    if not advisory_id:
        return None, [], []

    tlp = ((document.get("distribution") or {}).get("tlp") or {}).get("label")
    advisory = (
        advisory_id,
        provider,
        str(document.get("title") or "").strip()[:500],
        _parse_date(tracking.get("initial_release_date")),
        _parse_date(tracking.get("current_release_date")),
        str(tlp or "").strip() or None,
        url,
    )

    products: dict[str, tuple[str, str, str]] = {}
    tree = doc.get("product_tree") or {}
    _walk_products(tree.get("branches") or [], products)
    for entry in tree.get("full_product_names") or []:
        pid = str(entry.get("product_id") or "").strip()
        if pid:
            products[pid] = (
                str(entry.get("name") or "").strip(),
                "full_product_name",
                "",
            )

    cve_rows: list[tuple] = []
    affected_rows: list[tuple] = []
    seen_cve: set[str] = set()
    seen_affected: set[tuple] = set()

    for vuln in doc.get("vulnerabilities") or []:
        cve = str(vuln.get("cve") or "").strip().upper()
        if not _CVE_TOKEN.match(cve):
            # An advisory can carry a finding with no CVE assigned yet. It has
            # nothing to join against, so it is not recorded as one.
            cve = ""

        score = None
        for entry in vuln.get("scores") or []:
            for key in ("cvss_v4", "cvss_v3", "cvss_v2"):
                block = entry.get(key) or {}
                if block.get("baseScore") is not None:
                    try:
                        score = float(block["baseScore"])
                    except (TypeError, ValueError):
                        score = None
                    break
            if score is not None:
                break

        if cve and cve not in seen_cve:
            seen_cve.add(cve)
            cve_rows.append((advisory_id, cve, score))

        # The vendor's own remediation wording, kept per product it applies to.
        remediation_by_product: dict[str, str] = {}
        for rem in vuln.get("remediations") or []:
            details = str(rem.get("details") or "").strip()
            if not details:
                continue
            for pid in rem.get("product_ids") or []:
                remediation_by_product.setdefault(str(pid), details)

        for status, product_ids in (vuln.get("product_status") or {}).items():
            for pid in product_ids or []:
                pid = str(pid)
                name, category, constraint = products.get(pid, ("", "", ""))
                key = (advisory_id, cve, pid, status)
                if key in seen_affected:
                    continue
                seen_affected.add(key)
                affected_rows.append(
                    (
                        advisory_id,
                        cve or None,
                        pid,
                        name[:500],
                        category[:100],
                        str(status)[:60],
                        remediation_by_product.get(pid),
                        constraint[:200] or None,
                    )
                )

    return advisory, cve_rows, affected_rows


# ── Loading ──────────────────────────────────────────────────────────────────


def load(conn, advisories, cve_rows, affected_rows) -> None:
    with conn.cursor() as cur:
        if advisories:
            execute_values(
                cur,
                """
                INSERT INTO csaf_advisory
                    (id, provider, title, published, updated, tlp, url)
                VALUES %s
                ON CONFLICT (id) DO UPDATE SET
                    provider = EXCLUDED.provider,
                    title    = EXCLUDED.title,
                    updated  = EXCLUDED.updated,
                    tlp      = EXCLUDED.tlp,
                    url      = EXCLUDED.url
                """,
                advisories,
                page_size=500,
            )
        if cve_rows:
            execute_values(
                cur,
                """
                INSERT INTO csaf_advisory_cve (advisory_id, cve_id, cvss_score)
                VALUES %s
                ON CONFLICT (advisory_id, cve_id) DO UPDATE
                    SET cvss_score = EXCLUDED.cvss_score
                """,
                cve_rows,
                page_size=500,
            )
        if affected_rows:
            # cve_id is nullable, and NULL never equals NULL, so the unique
            # constraint cannot suppress duplicates on rows without a CVE.
            # They are de-duplicated per document during extraction.
            execute_values(
                cur,
                """
                INSERT INTO csaf_affected
                    (advisory_id, cve_id, product_id, product_name,
                     category, status, remediation, version_constraint)
                VALUES %s
                ON CONFLICT (advisory_id, cve_id, product_id, status)
                DO UPDATE SET version_constraint = EXCLUDED.version_constraint
                """,
                affected_rows,
                page_size=500,
            )
    conn.commit()


# ── Entry point ──────────────────────────────────────────────────────────────


def _connect():
    url = AppConfig.VULN_DB_URL
    return psycopg2.connect(url.replace("postgresql+psycopg2://", "postgresql://"))


def _fetch_doc(
    session: requests.Session,
    url: str,
    staging: Path,
    force: bool,
    delay: float = 0.0,
    attempts: int = 4,
) -> tuple[dict | None, str]:
    """
    Fetch one advisory, honouring the provider's pace. Returns ``(doc, reason)``.

    The reason is carried back so a failure can be reported as what it was.
    The first run of this script counted 137 unreadable documents and said
    nothing further, which made a rate limit look like corrupt data.
    """
    cached = staging / (
        re.sub(r"[^A-Za-z0-9._-]", "_", url.rsplit("/", 1)[-1]) or "doc.json"
    )
    if cached.exists() and not force:
        try:
            return json.loads(cached.read_text(encoding="utf-8")), "cached"
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

    backoff = max(delay, 1.0)
    last = "unknown"
    for attempt in range(attempts):
        if delay:
            time.sleep(delay)
        try:
            resp = session.get(url, timeout=(20, 120))
        except requests.RequestException as exc:
            last = f"{type(exc).__name__}"
            time.sleep(backoff)
            backoff *= 2
            continue

        # 403 here is a rate limit rather than a permission problem: the same
        # URL succeeds when asked more slowly. Backing off and retrying is the
        # correct response; retrying immediately is what caused it.
        if resp.status_code in (403, 429, 503):
            last = f"HTTP {resp.status_code} (rate limited)"
            time.sleep(backoff)
            backoff *= 2
            continue
        if resp.status_code != 200:
            return None, f"HTTP {resp.status_code}"

        try:
            payload = resp.json()
        except ValueError:
            last = "not JSON"
            time.sleep(backoff)
            backoff *= 2
            continue

        try:
            cached.write_text(json.dumps(payload), encoding="utf-8")
        except OSError:
            pass
        return payload, "fetched"

    return None, last


def sync_provider(conn, session, provider, config, staging, force, limit) -> dict:
    staging = staging / provider
    staging.mkdir(parents=True, exist_ok=True)

    workers = int(config.get("workers") or 4)
    delay = float(config.get("delay") or 0.0)

    feeds = rolie_feeds(session, provider, config["metadata"])
    if not feeds and config.get("feeds"):
        # The provider's own metadata could not be read, but the feeds it
        # publishes are known. Using them is better than skipping the provider
        # over a document that carries no data itself.
        log.info("%s: falling back to configured feed URLs", provider)
        feeds = list(config["feeds"])
    if not feeds:
        log.warning("%s: no ROLIE feed available — skipped", provider)
        return {"advisories": 0, "cves": 0, "failed": 0}

    urls: list[str] = []
    for feed in feeds:
        found = advisory_urls(session, feed)
        log.info(
            "%s: %s advisories in %s",
            provider,
            f"{len(found):,}",
            feed.rsplit("/", 1)[-1],
        )
        urls.extend(found)
    urls = list(dict.fromkeys(urls))
    if limit:
        urls = urls[:limit]
    log.info(
        "%s: fetching %s documents (%d worker(s), %.2fs delay)",
        provider,
        f"{len(urls):,}",
        workers,
        delay,
    )

    advisories: list = []
    cve_rows: list = []
    affected_rows: list = []
    failed = 0
    reasons: Counter = Counter()

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_fetch_doc, session, url, staging, force, delay): url
            for url in urls
        }
        for done, future in enumerate(as_completed(futures), 1):
            url = futures[future]
            doc, reason = future.result()
            if not doc:
                failed += 1
                reasons[reason] += 1
                continue
            advisory, cves, affected = extract(doc, provider, url)
            if advisory is None:
                failed += 1
                reasons["no tracking id"] += 1
                continue
            advisories.append(advisory)
            cve_rows.extend(cves)
            affected_rows.extend(affected)

            if len(advisories) >= 500:
                load(conn, advisories, cve_rows, affected_rows)
                advisories, cve_rows, affected_rows = [], [], []
            if done % 500 == 0:
                log.info("%s: %s/%s fetched", provider, f"{done:,}", f"{len(urls):,}")

    if advisories:
        load(conn, advisories, cve_rows, affected_rows)

    if failed:
        log.warning(
            "%s: %s document(s) could not be read — %s",
            provider,
            f"{failed:,}",
            ", ".join(f"{reason}: {count}" for reason, count in reasons.most_common()),
        )

    with conn.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM csaf_advisory WHERE provider = %s", (provider,)
        )
        stored = cur.fetchone()[0]
        cur.execute(
            "SELECT count(DISTINCT cve_id) FROM csaf_advisory_cve c "
            "JOIN csaf_advisory a ON a.id = c.advisory_id WHERE a.provider = %s",
            (provider,),
        )
        cves = cur.fetchone()[0]
    return {"advisories": stored, "cves": cves, "failed": failed}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Ingest CSAF advisories into vuln_intel."
    )
    parser.add_argument(
        "--providers", nargs="+", choices=sorted(PROVIDERS), default=sorted(PROVIDERS)
    )
    parser.add_argument("--staging-dir", type=Path, default=DEFAULT_STAGING)
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="advisories per provider (0 = all); for smoke tests",
    )
    parser.add_argument(
        "--force", action="store_true", help="re-download cached documents"
    )
    parser.add_argument("--list", action="store_true", help="print providers and exit")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
    )

    if args.list:
        for name, cfg in sorted(PROVIDERS.items()):
            print(
                f"{name:10} workers={cfg.get('workers', 4)} "
                f"delay={cfg.get('delay', 0.0)}s  {cfg['metadata']}"
            )
        return 0

    session = requests.Session()
    session.headers["User-Agent"] = _UA

    conn = _connect()
    try:
        ensure_schema(conn)
        for provider in args.providers:
            log.info("── %s ──", provider)
            result = sync_provider(
                conn,
                session,
                provider,
                PROVIDERS[provider],
                args.staging_dir,
                args.force,
                args.limit,
            )
            log.info(
                "%s: %s advisories stored, %s distinct CVEs",
                provider,
                f"{result['advisories']:,}",
                f"{result['cves']:,}",
            )

        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM csaf_advisory")
            adv = cur.fetchone()[0]
            cur.execute("SELECT count(DISTINCT cve_id) FROM csaf_advisory_cve")
            cves = cur.fetchone()[0]
            cur.execute("SELECT count(*) FROM csaf_affected")
            aff = cur.fetchone()[0]
        log.info(
            "Done. %s advisories, %s distinct CVEs, %s affected-product rows.",
            f"{adv:,}",
            f"{cves:,}",
            f"{aff:,}",
        )
    finally:
        conn.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
