"""
scripts/security/sync_disposable_domains.py
──────────────────────────────────────────────────────────────────────────────
Refresh the `disposable_domains` corpus from maintained upstream blocklists.

Built in the shape of `scripts/vuln/sync_*.py` — same staging directory, same
`--dry-run`, same "assert what you need and fail loudly" posture — so operations
does not have to learn a second pattern.

Why three sources and not one
─────────────────────────────
Measured on 18 Aug 2026 against the two throwaway domains that actually reached
this deployment's approval queue:

    list                                    size    hutdot.com   radiant-flow.org
    disposable-email-domains (canonical)   8,310       miss           miss
    7c/fakefilter                         10,550       HIT            miss
    disposable/disposable-email-domains   74,753       HIT            miss

The canonical list — the one most implementations use on its own — caught
neither. Merging is not an optimisation here; a single-source build would have
shipped believing it worked.

`radiant-flow.org` is on none of them, and that is not a bug to fix by adding a
fourth list. It has valid MX, Cloudflare nameservers and a 17-month-old
registration; nothing distinguishes it from a small real company except human
judgement. It is what the approval-queue flag exists for.

Merge, never replace
────────────────────
A source that returns an empty body, an error page or a rate-limit notice must
not be able to empty the corpus. That failure is indistinguishable from a clean
run in the logs, and it silently disables the whole feature — the same shape as
the Siemens 403 recorded in CLAUDE.md, where 137 of 831 documents vanished and
looked like corrupt data.

So each source must clear a minimum row count before it is accepted, domains
are merged rather than replaced, and a domain missing from every source is
retired only after `DISPOSABLE_RETIRE_AFTER_MISSES` consecutive successful
syncs.

Usage
─────
    python -m scripts.security.sync_disposable_domains
    python -m scripts.security.sync_disposable_domains --dry-run
    python -m scripts.security.sync_disposable_domains --list-sources
    python -m scripts.security.sync_disposable_domains --write-snapshot
"""

from __future__ import annotations

import argparse
import gzip
import logging
import os
import re
import sys
from datetime import datetime, timezone

# Allow `python scripts/security/sync_disposable_domains.py` as well as -m.
sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

log = logging.getLogger("ccure.disposable_sync")

#: name -> URL. Adding a source is one entry; nothing else changes.
SOURCES: dict[str, str] = {
    "disposable-email-domains": (
        "https://raw.githubusercontent.com/disposable-email-domains/"
        "disposable-email-domains/main/disposable_email_blocklist.conf"
    ),
    "fakefilter": ("https://raw.githubusercontent.com/7c/fakefilter/main/txt/data.txt"),
    "disposable": (
        "https://raw.githubusercontent.com/disposable/"
        "disposable-email-domains/master/domains.txt"
    ),
}

_DOMAIN_RE = re.compile(
    r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$"
)

# Written gzipped. The plain list is 1.1 MB and pre-commit's
# check-added-large-files refuses anything over 500 KB; compressed it is 411 KB.
# Regenerating to the uncompressed name would produce a file that cannot be
# committed, which is a confusing way to find out.
_SNAPSHOT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "data",
    "disposable_domains_snapshot.txt.gz",
)


def _default_feed_dir() -> str:
    return os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "data",
        "feeds",
    )


def _feed_dir() -> str:
    """
    Staging directory, shared with the vulnerability feed syncs.

    `CCURE_FEED_DIR` is `D:/ccure-feeds` on this deployment, which is correct for
    the host worker and meaningless inside a Linux container — where
    `os.makedirs` cheerfully creates a *relative* directory literally named
    `D:` under the working directory. Since /app is the mounted repo, running
    this in the container once left a junk `Backend/D:/` folder in the working
    tree.

    So a configured path is used only if this platform can actually make sense
    of it: absolute here, and not a Windows drive letter when we are not on
    Windows. Anything else silently falls back to the in-repo default rather
    than inventing a directory somebody has to find and delete later.
    """
    configured = (os.getenv("CCURE_FEED_DIR") or "").strip()
    path = configured or _default_feed_dir()

    if configured:
        looks_like_drive_letter = len(configured) > 1 and configured[1] == ":"
        if (os.name != "nt" and looks_like_drive_letter) or not os.path.isabs(
            configured
        ):
            log.warning(
                "CCURE_FEED_DIR=%r is not usable on this platform; staging in %s "
                "instead.",
                configured,
                _default_feed_dir(),
            )
            path = _default_feed_dir()

    try:
        os.makedirs(path, exist_ok=True)
    except OSError as exc:
        log.warning("Could not create feed directory %s (%s); using default", path, exc)
        path = _default_feed_dir()
        os.makedirs(path, exist_ok=True)
    return path


def _parse(text: str) -> set[str]:
    """Extract valid domains, ignoring comments, blanks and anything malformed."""
    found = set()
    for line in text.splitlines():
        domain = line.strip().lower().rstrip(".")
        if not domain or domain.startswith("#") or domain.startswith("//"):
            continue
        # Some lists ship "domain,category" or "domain # note".
        domain = domain.split(",", 1)[0].split()[0].strip()
        if not domain or len(domain) > 253 or not _DOMAIN_RE.match(domain):
            continue
        found.add(domain)
    return found


def fetch_source(name: str, url: str, *, timeout: int = 120) -> set[str]:
    """
    Download and parse one source.

    Returns an empty set on any failure — the caller decides what that means,
    because "this source is down" and "this source is now empty" must not be
    allowed to look the same to the merge step.
    """
    import requests

    try:
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()
    except Exception as exc:
        log.error("Source %s could not be fetched: %s", name, exc)
        return set()

    domains = _parse(response.text)

    # Cache the raw body next to the vulnerability feeds so a failed parse can
    # be diagnosed without re-fetching.
    try:
        with open(
            os.path.join(_feed_dir(), f"disposable_{name}.txt"), "w", encoding="utf-8"
        ) as handle:
            handle.write(response.text)
    except OSError as exc:
        log.warning("Could not cache %s: %s", name, exc)

    log.info("Source %-34s %6d domains", name, len(domains))
    return domains


def run_sync(*, dry_run: bool = False, sources: dict[str, str] | None = None) -> dict:
    """
    Fetch every source, merge into `disposable_domains`, retire stale rows.

    Returns a result dict. `success` is False when *every* source failed — that
    is the case where the corpus must be left exactly as it was.
    """
    from config import AppConfig
    from db.base import SessionLocal
    from db.models.email_security import DisposableDomain

    sources = sources or SOURCES
    min_rows = AppConfig.DISPOSABLE_SYNC_MIN_ROWS_PER_SOURCE
    retire_after = AppConfig.DISPOSABLE_RETIRE_AFTER_MISSES

    merged: dict[str, set[str]] = {}
    accepted: list[str] = []
    rejected: list[str] = []

    for name, url in sources.items():
        domains = fetch_source(name, url)
        if len(domains) < min_rows:
            # The guard that matters. An error page parses to zero domains and
            # a rate-limit notice to a handful; either would silently shrink the
            # corpus if merged. Refusing the source keeps the previous data.
            log.error(
                "Source %s returned %d domains, below the %d minimum — "
                "REJECTED. Previous data for it is retained.",
                name,
                len(domains),
                min_rows,
            )
            rejected.append(name)
            continue
        accepted.append(name)
        for domain in domains:
            merged.setdefault(domain, set()).add(name)

    if not accepted:
        log.error(
            "Every source failed or was rejected. The corpus is unchanged. "
            "This is a sync failure, not an empty blocklist."
        )
        return {
            "success": False,
            "error": "no source passed validation",
            "rejected": rejected,
        }

    if dry_run:
        log.info(
            "[dry-run] %d unique domains from %d source(s); nothing written",
            len(merged),
            len(accepted),
        )
        return {
            "success": True,
            "dry_run": True,
            "unique": len(merged),
            "accepted": accepted,
            "rejected": rejected,
        }

    now = datetime.now(timezone.utc)
    db = SessionLocal()
    try:
        existing = {row.domain: row for row in db.query(DisposableDomain).all()}

        added = 0
        updated = 0
        for domain, names in merged.items():
            row = existing.get(domain)
            if row is None:
                db.add(
                    DisposableDomain(
                        domain=domain,
                        sources=sorted(names),
                        first_seen_at=now,
                        last_seen_at=now,
                        miss_count=0,
                    )
                )
                added += 1
            else:
                row.sources = sorted(names)
                row.last_seen_at = now
                row.miss_count = 0
                updated += 1

        # Retirement. Only domains that every *accepted* source now omits, and
        # only after enough consecutive misses that a single bad fetch cannot
        # drain the corpus.
        retired = 0
        aging = 0
        for domain, row in existing.items():
            if domain in merged:
                continue
            row.miss_count = (row.miss_count or 0) + 1
            if row.miss_count >= retire_after:
                db.delete(row)
                retired += 1
            else:
                aging += 1

        db.commit()

        # The API caches the corpus in-process; without this the new rows are
        # invisible until the TTL lapses.
        try:
            from auth.email_domain_guard import invalidate_cache

            invalidate_cache()
        except Exception:
            pass

        result = {
            "success": True,
            "unique": len(merged),
            "added": added,
            "updated": updated,
            "retired": retired,
            "aging_out": aging,
            "accepted": accepted,
            "rejected": rejected,
        }
        log.info("Sync complete: %s", result)
        return result
    except Exception as exc:
        db.rollback()
        log.error("Sync failed while writing: %s", exc, exc_info=True)
        return {"success": False, "error": str(exc)}
    finally:
        db.close()


def write_snapshot(path: str = _SNAPSHOT_PATH) -> dict:
    """Regenerate the bundled snapshot from the live corpus."""
    from db.base import SessionLocal
    from db.models.email_security import DisposableDomain

    db = SessionLocal()
    try:
        domains = sorted(row[0] for row in db.query(DisposableDomain.domain).all())
    finally:
        db.close()

    if not domains:
        log.error("Corpus is empty; refusing to overwrite the snapshot with nothing.")
        return {"success": False, "error": "empty corpus"}

    os.makedirs(os.path.dirname(path), exist_ok=True)
    if path.endswith(".gz"):
        handle = gzip.open(path, "wt", encoding="utf-8", newline="\n", compresslevel=9)
    else:
        handle = open(path, "w", encoding="utf-8", newline="\n")
    with handle:
        handle.write("# CCure Audit PRO - bundled disposable email domain snapshot\n")
        handle.write(
            "# Merged from disposable-email-domains, 7c/fakefilter and "
            "disposable/disposable-email-domains.\n"
        )
        handle.write(
            "# Seeds `disposable_domains` on first migration so a fresh "
            "deployment is\n# screened before this script has ever run.\n"
        )
        handle.write(
            "# Regenerate with: python -m scripts.security."
            "sync_disposable_domains --write-snapshot\n"
        )
        for domain in domains:
            handle.write(domain + "\n")

    log.info("Wrote %d domains to %s", len(domains), path)
    return {"success": True, "written": len(domains), "path": path}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Refresh the disposable email domain corpus."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Fetch and validate, but write nothing.",
    )
    parser.add_argument(
        "--list-sources",
        action="store_true",
        help="Print the configured sources and exit.",
    )
    parser.add_argument(
        "--write-snapshot",
        action="store_true",
        help="Regenerate the bundled snapshot from the current corpus.",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)-7s %(message)s"
    )

    if args.list_sources:
        for name, url in SOURCES.items():
            print(f"{name:34} {url}")
        return 0

    if args.write_snapshot:
        return 0 if write_snapshot().get("success") else 1

    result = run_sync(dry_run=args.dry_run)
    return 0 if result.get("success") else 1


if __name__ == "__main__":
    raise SystemExit(main())
