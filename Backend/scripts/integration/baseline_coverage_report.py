"""
What Audit can assess of a received ``PolicyBaseline`` — the Contract 1 answer,
computed without storing anything.

    docker exec -i -w /app ccure-api python -m scripts.integration.baseline_coverage_report \\
        < baseline.json                       # summary
    ... baseline_coverage_report --json      # the BaselineCoverage message itself

The baseline goes through the same path the integration phase (plan Phase 14)
will wire to a route: contract → ``baseline_input`` → ``BaselineMappingService``
→ ``baseline_coverage``. Operator tooling: nothing in the application imports
it, and it opens a **read-only** database session, so it can run against the
live catalogue without the possibility of writing.

``activation`` is ``pending_review``: a received baseline governs nothing until
an Audit administrator activates it (Phase 4 review, Q1), and this tool
activates nothing.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Iterable, Optional

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from ccure_audit.integration.envelope import EnvelopeContext
from ccure_audit.integration.mappers.baseline_coverage import baseline_coverage
from ccure_audit.integration.mappers.policy_baseline import baseline_input
from ccure_audit.services.baseline_mapping import BaselineMappingService
from ccure_contracts.policy_baseline.v1.models import (
    CcureBaselineCoverageV1,
    CcurePolicyBaselineV1,
)


def coverage_for(
    db: Session,
    message: CcurePolicyBaselineV1,
    *,
    org_id: Optional[str] = None,
    now: Optional[datetime] = None,
) -> CcureBaselineCoverageV1:
    """The coverage Audit would answer ``message`` with, for ``org_id``."""
    now = now or datetime.now(timezone.utc)
    org = org_id or message.tenant_id
    view = BaselineMappingService(db).map_baseline(
        org_id=org, baseline=baseline_input(message)
    )
    return baseline_coverage(
        view,
        ctx=EnvelopeContext(
            message_id=uuid.uuid4(),
            tenant_id=org,
            module_version="baseline-coverage-report",
            produced_at=now,
            correlation_id=message.correlation_id,
            causation_id=message.message_id,
        ),
        received_at=now,
        mapped_at=now,
        mapping_revision=1,
        activation="pending_review",
    )


def summary(coverage: CcureBaselineCoverageV1, *, limit: int = 12) -> str:
    data = coverage.data
    s = data.summary
    lines = [
        f"baseline {data.baseline.baseline_id} v{data.baseline.baseline_version} — "
        f"{s.controls_total} controls, activation {data.activation}",
        f"  AUTOMATED            {s.automated}",
        f"  PARTIALLY_AUTOMATED  {s.partially_automated}",
        f"  ATTESTATION_REQUIRED {s.attestation_required}",
        f"  UNKNOWN_CONTROL      {s.unknown_control}",
        f"  UNSUPPORTED          {s.unsupported}",
    ]
    by_state = defaultdict(list)
    for c in data.controls:
        by_state[c.mapping_state.value].append(c)
    for state, items in by_state.items():
        lines.append(f"\n{state} ({len(items)})")
        for c in items[:limit]:
            rules = f" rules={len(c.audit_rules)}" if c.audit_rules else ""
            note = f" — {c.reason}" if c.reason else ""
            lines.append(
                f"  {c.control.control_id:8} {c.applicability.value:15}{rules}{note[:120]}"
            )
        if len(items) > limit:
            lines.append(f"  … {len(items) - limit} more")
    notes = Counter(n for c in data.controls for n in c.notes)
    if notes:
        lines.append("\nnotes")
        lines.extend(f"  {n:4} × {text_}" for text_, n in notes.most_common())
    handling = Counter(p.handling.value for p in data.parameters)
    lines.append(f"\nparameters: {dict(handling) or 'none received'}")
    lines.append(
        f"scope: applied={data.scope.applied} "
        f"rejected={[r.entry for r in data.scope.rejected_entries]}"
    )
    return "\n".join(lines)


def _read_only_session() -> Session:
    engine = create_engine(
        os.environ["DATABASE_URL"],
        connect_args={"options": "-c default_transaction_read_only=on"},
    )
    db = sessionmaker(bind=engine)()
    if db.execute(text("show default_transaction_read_only")).scalar() != "on":
        raise SystemExit("refusing: the session is not read-only")
    return db


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument(
        "--baseline", default="-", help="PolicyBaseline JSON, or - for stdin"
    )
    parser.add_argument(
        "--org", help="organisation to map for (default: the message's tenant)"
    )
    parser.add_argument(
        "--json", action="store_true", help="print the BaselineCoverage message"
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    raw = (
        sys.stdin.read()
        if args.baseline == "-"
        else open(args.baseline, encoding="utf-8").read()
    )
    message = CcurePolicyBaselineV1.model_validate(json.loads(raw))
    db = _read_only_session()
    try:
        coverage = coverage_for(db, message, org_id=args.org)
    finally:
        db.rollback()
        db.close()
    if args.json:
        print(coverage.model_dump_json(by_alias=True, indent=2))
    else:
        print(summary(coverage))
    return 0


if __name__ == "__main__":
    sys.exit(main())
