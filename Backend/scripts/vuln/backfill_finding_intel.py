"""
scripts/vuln/backfill_finding_intel.py
─────────────────────────────────────────────────────────────────────────────
Apply exploit provenance and vendor advisories to findings already stored.

Why a backfill rather than a re-scan
────────────────────────────────────
The feeds arrived after the findings did. Every row written before them
records the exploit signal as it stood then, which on a real database meant
`has_exploit = 34`, identical to `in_kev = 34` — the exact synonym those feeds
were added to break. Waiting for the next scan of every host to correct it
leaves the intelligence invisible until each one is re-run, and hosts that are
powered off or decommissioned never get corrected at all.

Everything applied here is joined on the CVE. Nothing is raised, retired or
re-scored: a finding's verdict was reached by the engine that produced it, and
this annotates that verdict with what the corpora say about the same CVE. The
join key is exact, so there is no inference and no room for a false positive.

`vuln_intel` and the application database are separate servers, so this cannot
be one SQL statement — the intel is read from one and written to the other.

Usage
─────
    python Backend/scripts/vuln/backfill_finding_intel.py --dry-run
    python Backend/scripts/vuln/backfill_finding_intel.py
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Sequence

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from core.vuln_intel import csaf_advisories_for, exploit_intel_for  # noqa: E402
from db.base import SessionLocal  # noqa: E402
from sqlalchemy import text  # noqa: E402

log = logging.getLogger("ccure.backfill.intel")

_CHUNK = 500


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Backfill exploit provenance and vendor advisories onto findings."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="report what would change without writing",
    )
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
    )

    db = SessionLocal()
    try:
        cve_ids = [
            row[0]
            for row in db.execute(
                text(
                    "SELECT DISTINCT vuln_id FROM asset_vulnerabilities "
                    "WHERE vuln_id IS NOT NULL"
                )
            ).all()
        ]
        log.info("Findings reference %s distinct CVEs", f"{len(cve_ids):,}")

        intel: dict = {}
        advisories: dict = {}
        for start in range(0, len(cve_ids), _CHUNK):
            chunk = cve_ids[start : start + _CHUNK]
            intel.update(exploit_intel_for(chunk))
            advisories.update(csaf_advisories_for(chunk))

        log.info(
            "Matched %s CVEs with exploit evidence, %s with a vendor advisory",
            f"{len(intel):,}",
            f"{len(advisories):,}",
        )

        updates: list[dict] = []
        for cve, entry in intel.items():
            updates.append(
                {
                    "cve": cve,
                    "sources": entry["exploit_sources"] or None,
                    "verified": entry["verified_exploit"],
                    "canary": entry["canary_confirmed"],
                    "ransomware": entry["ransomware_linked"],
                }
            )

        advisory_updates: list[dict] = []
        for cve, entries in advisories.items():
            best = next((e for e in entries if e.get("remediation")), entries[0])
            remediation = best.get("remediation")
            advisory_updates.append(
                {
                    "cve": cve,
                    "advisory_id": best["advisory_id"],
                    "url": best.get("url"),
                    # Attributed for the same reason the live path attributes
                    # it: the advisory covers this CVE but not necessarily this
                    # product, and ICS mitigation must not read as the desktop
                    # vendor's advice.
                    "remediation": (
                        f"{best['provider'].upper()} {best['advisory_id']}: {remediation}"
                        if remediation
                        else None
                    ),
                }
            )

        if args.dry_run:
            affected = db.execute(
                text(
                    "SELECT count(*) FROM asset_vulnerabilities "
                    "WHERE vuln_id = ANY(:cves)"
                ),
                {"cves": list(intel.keys())},
            ).scalar()
            log.info(
                "DRY RUN — %s finding row(s) would gain exploit provenance, "
                "%s CVE(s) would gain a vendor advisory. Nothing written.",
                f"{affected:,}",
                f"{len(advisory_updates):,}",
            )
            return 0

        exploit_rows = 0
        for start in range(0, len(updates), _CHUNK):
            chunk = updates[start : start + _CHUNK]
            result = db.execute(
                text(
                    """
                    UPDATE asset_vulnerabilities AS av SET
                        has_exploit       = true,
                        exploit_sources   = v.sources,
                        verified_exploit  = v.verified,
                        canary_confirmed  = v.canary,
                        ransomware_linked = v.ransomware
                    FROM (VALUES %s) AS v(cve, sources, verified, canary, ransomware)
                    WHERE av.vuln_id = v.cve
                    """.replace(
                        "%s",
                        ", ".join(
                            f"(:cve{i}, CAST(:sources{i} AS text[]), :verified{i}, "
                            f":canary{i}, :ransomware{i})"
                            for i in range(len(chunk))
                        ),
                    )
                ),
                {
                    f"{key}{i}": row[key]
                    for i, row in enumerate(chunk)
                    for key in ("cve", "sources", "verified", "canary", "ransomware")
                },
            )
            exploit_rows += result.rowcount or 0
        db.commit()
        log.info("Exploit provenance written to %s finding row(s)", f"{exploit_rows:,}")

        advisory_rows = 0
        for start in range(0, len(advisory_updates), _CHUNK):
            chunk = advisory_updates[start : start + _CHUNK]
            result = db.execute(
                text(
                    """
                    UPDATE asset_vulnerabilities AS av SET
                        vendor_advisory_id  = v.advisory_id,
                        vendor_advisory_url = v.url,
                        vendor_remediation  = COALESCE(v.remediation, av.vendor_remediation)
                    FROM (VALUES %s) AS v(cve, advisory_id, url, remediation)
                    WHERE av.vuln_id = v.cve
                    """.replace(
                        "%s",
                        ", ".join(
                            f"(:cve{i}, :advisory_id{i}, :url{i}, :remediation{i})"
                            for i in range(len(chunk))
                        ),
                    )
                ),
                {
                    f"{key}{i}": row[key]
                    for i, row in enumerate(chunk)
                    for key in ("cve", "advisory_id", "url", "remediation")
                },
            )
            advisory_rows += result.rowcount or 0
        db.commit()
        log.info("Vendor advisories written to %s finding row(s)", f"{advisory_rows:,}")

        summary = (
            db.execute(
                text(
                    """
                SELECT count(*)                                    AS total,
                       count(*) FILTER (WHERE has_exploit)         AS has_exploit,
                       count(*) FILTER (WHERE verified_exploit)    AS verified,
                       count(*) FILTER (WHERE canary_confirmed)    AS canary,
                       count(*) FILTER (WHERE ransomware_linked)   AS ransomware,
                       count(*) FILTER (WHERE vendor_advisory_id IS NOT NULL) AS advisory,
                       count(*) FILTER (WHERE in_kev)              AS in_kev
                FROM asset_vulnerabilities
                """
                )
            )
            .mappings()
            .first()
        )
        log.info(
            "Findings now: %s total | has_exploit %s | verified %s | honeypot %s | "
            "ransomware %s | vendor advisory %s | CISA KEV %s",
            f"{summary['total']:,}",
            f"{summary['has_exploit']:,}",
            f"{summary['verified']:,}",
            f"{summary['canary']:,}",
            f"{summary['ransomware']:,}",
            f"{summary['advisory']:,}",
            f"{summary['in_kev']:,}",
        )
    finally:
        db.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
