"""
Phase 5.6: map every assessment and finding in the scratch restore through the
integration mappers, and report what the contracts refused.

Run against the scratch database only (see ``capture_exports.py`` for how it
is built), read-only::

    docker exec -i -w /app ccure-api python - < scripts/verification/phase5_golden/verify_mappers.py

Nothing is repaired or skipped silently. A ``MappingError`` is counted and its
first examples printed, because each one is stored data the contract cannot
express honestly — exactly what the mapper exists to surface. The output is a
tally of contract states, so it also shows that the absent cases (not
implemented, not applicable, not collected, NOT_ASSESSED) are real, not zero.
"""

import os
import sys
import uuid
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

SCRATCH = "ccure_phase5_golden"

live = urlsplit(os.environ["DATABASE_URL"])
url = urlunsplit(live._replace(path="/" + SCRATCH))
if urlsplit(url).path.strip("/") != SCRATCH:
    sys.exit("refusing: not the scratch database")
engine = create_engine(
    url, connect_args={"options": "-c default_transaction_read_only=on"}
)
db = sessionmaker(bind=engine)()
assert db.execute(text("select current_database()")).scalar() == SCRATCH

from ccure_audit.integration.envelope import EnvelopeContext  # noqa: E402
from ccure_audit.integration.errors import MappingError  # noqa: E402
from ccure_audit.integration.mappers.control_results import (  # noqa: E402
    control_results,
    controls_page,
)
from ccure_audit.integration.mappers.findings import findings_page  # noqa: E402
from ccure_audit.services.assessment_read import AssessmentReadService  # noqa: E402
from ccure_audit.services.finding_read import FindingReadService  # noqa: E402
from db.models.scans import Scan  # noqa: E402


def ctx(org_id):
    return EnvelopeContext(
        message_id=uuid.uuid4(),
        tenant_id=org_id,
        module_version="phase5.6-verification",
        produced_at=datetime.now(timezone.utc),
        correlation_id="phase5-6-verify",
    )


tally = Counter()
refusals = Counter()
examples = {}


def refuse(kind, exc):
    key = f"{kind}: {str(exc).split(':', 1)[-1].strip()[:90]}"
    refusals[key] += 1
    examples.setdefault(key, str(exc)[:300])


scans = db.query(Scan.id, Scan.org_id).order_by(Scan.id).all()
verdicts_service = AssessmentReadService(db)
findings_service = FindingReadService(db)

for scan_id, org_id in scans:
    tally["scans"] += 1
    try:
        view = verdicts_service.verdicts(org_id=org_id, scan_id=scan_id)
        results = control_results(view)
        controls_page(results, result_id=f"res_{scan_id}", ctx=ctx(org_id))
        tally["control_results"] += len(results)
        for r in results:
            tally[f"control.{r.state.value}"] += 1
            for rule in r.rules:
                tally[f"rule.{rule.state.value}"] += 1
        tally["hosts_unassessed"] += sum(1 for h in view.hosts if not h.assessed)
    except MappingError as exc:
        refuse("controls", exc)

    after = None
    while True:
        page = findings_service.findings(
            org_id=org_id, scan_id=scan_id, after=after, limit=500
        )
        try:
            message = findings_page(page, result_id=f"res_{scan_id}", ctx=ctx(org_id))
            for f in message.items:
                tally["findings"] += 1
                tally[f"finding.exploit.{f.exploit.availability.value}"] += 1
                tally[f"finding.cvss.{f.risk.cvss_component.status.value}"] += 1
                tally[f"finding.detection.{f.detection.method.value}"] += 1
                tally[f"finding.remediation.{f.remediation.state.value}"] += 1
                tally[f"finding.sla.{f.remediation.sla_state.value}"] += 1
        except MappingError:
            # Re-map one by one so a single bad row is named, not the page.
            from ccure_audit.integration.mappers.findings import finding

            for v in page.items:
                try:
                    finding(v)
                    tally["findings"] += 1
                except MappingError as exc:
                    refuse("finding", exc)
        if page.next_after is None:
            break
        after = page.next_after

db.rollback()

for key in sorted(tally):
    print(f"{key:48} {tally[key]}")
print(f"\nrefusals: {sum(refusals.values())}")
for key, n in refusals.most_common():
    print(f"  {n:6}  {key}")
    print(f"          e.g. {examples[key]}")
