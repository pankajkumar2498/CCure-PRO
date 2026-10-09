"""
Reference converter: a PolicyPro policy library + an organisation's SoA answers
→ a Contract 1 ``PolicyBaseline`` message (JSON).

Producing a baseline is Policy Pro's job; this is the translation written down
and proven against Audit's contract, for the PolicyPro team to adopt. It is
operator tooling under ``scripts/`` — nothing in the application imports it.

    # The organisation's decisions, in PolicyPro's own SoA column names
    python -m scripts.integration.policypro_library_to_baseline \\
        --library 09A_ISO27001_Full_Policy_Library_for_PolicyPro.csv \\
        --soa soa_answers.csv --tenant org_default \\
        --baseline-id acme-isms --baseline-version 3 \\
        --policy-id pp-isms-policy --policy-version 2.1 --policy-title "ACME ISMS Policy" \\
        --approved-at 2026-09-01T00:00:00Z > baseline.json

    # A demonstration with no organisation behind it: every Annex A control
    # declared applicable, and the output labelled as a demonstration.
    python -m scripts.integration.policypro_library_to_baseline \\
        --library - --demo-all-applicable --tenant org_default < library.csv

On this VM the library lives outside the API container's bind mount, so pass
``--library -`` and feed the file on stdin through ``docker exec -i``.

**What is carried.** One requirement per ISO reference, from its "Policy
Clause" row: the requirement id is PolicyPro's ``clause_id``, the control is
``ISO27001_2022`` / ``2022`` / ``iso_reference`` (the spelling Audit's
catalogue stores), and ``requirement_text`` is the clause's requirement. The
other twelve row types per reference (SOP, questionnaire, test case, …) are
PolicyPro's own content and do not belong in a baseline.

**What is never invented.**

* Applicability is an organisation decision. Annex A controls take it from the
  SoA file (``annex_control_id``, ``applicable_yes_no``,
  ``justification_for_exclusion``, as the library names those fields); a
  control the SoA does not decide is refused, not assumed. Management-system
  clauses 4–10 are mandatory for ISO 27001 conformity, so they are always
  applicable, and an SoA excluding one is refused.
* Parameters are empty. The library names template fields (``timeout_value``,
  ``freshness_days``, …) but carries no values, and Audit's parameter
  vocabulary is empty until rule parameterisation (plan Phase 17). ``--report``
  lists the candidate names for that conversation.
* No executable check is ever emitted; the contract refuses one anyway.
"""

from __future__ import annotations

import argparse
import csv
import io
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, TextIO, Tuple

from ccure_contracts.policy_baseline.v1.models import (
    POLICY_BASELINE_CONTRACT,
    CcurePolicyBaselineV1,
)
from ccure_contracts.registry import SCHEMA_VERSION

ISO_CODE = "ISO27001_2022"
ISO_VERSION = "2022"
POLICY_CLAUSE = "Policy Clause"
ISMS_AREA = "ISMS Management Clause"
ANNEX_AREA = "Annex A Control"

#: Columns that identify a PolicyPro ISO library. A file without them is not
#: one, and guessing at another layout is how a wrong control id is emitted.
ISO_COLUMNS = (
    "iso_area",
    "iso_reference",
    "clause_id",
    "clause_type",
    "control_title",
    "detailed_policy_requirement",
    "policypro_template_fields",
)

#: Template-field names that are organisational bookkeeping rather than a
#: measurable setting, left out of the candidate-parameter report.
_BOOKKEEPING = {
    "owner",
    "evidence",
    "applicability",
    "implementation_status",
    "system",
    "scope",
    "policy_owner",
    "exception",
    "remediation",
    "baseline",
    "drift",
}

_NS = uuid.UUID("6f2b8c1e-5d3a-4e7b-9c41-2a8d0e6f1b35")


class ConversionError(ValueError):
    """The input cannot become an honest baseline; the message says why."""


@dataclass(frozen=True)
class SoaDecision:
    applicable: bool
    justification: Optional[str]


@dataclass
class Report:
    references: int = 0
    isms_clauses: int = 0
    annex_controls: int = 0
    not_applicable: int = 0
    candidate_parameters: Dict[str, List[str]] = field(default_factory=dict)


def _read_rows(stream: TextIO) -> List[Dict[str, str]]:
    return list(csv.DictReader(stream))


def _library_kind(rows: Sequence[Mapping[str, str]]) -> str:
    if not rows:
        raise ConversionError("the library is empty")
    columns = set(rows[0].keys())
    if all(c in columns for c in ISO_COLUMNS):
        return "iso27001"
    if "hipaa_reference" in columns:
        raise ConversionError(
            "HIPAA library: its identifiers are PolicyPro's own (HIPAA-POL-…) "
            "and its CFR references are section-level, while Audit's HIPAA "
            "Security Rule catalogue names each requirement by CFR paragraph "
            "(e.g. 164.312(a)(2)(iii)). Guessing a paragraph from a name would "
            "put a requirement on the wrong control. See ask 4 in "
            "docs/architecture/policypro/POLICYPRO_BASELINE_EXPORT_REQUIREMENTS.md."
        )
    raise ConversionError(
        f"not a PolicyPro ISO 27001 library: expected columns {ISO_COLUMNS}"
    )


def read_soa(stream: TextIO) -> Dict[str, SoaDecision]:
    """
    An organisation's SoA answers, keyed by ``annex_control_id``. Accepts the
    library's own SoA field names; ``applicable_yes_no`` must say yes or no.
    """
    decisions: Dict[str, SoaDecision] = {}
    for n, row in enumerate(csv.DictReader(stream), start=2):
        control = (row.get("annex_control_id") or "").strip()
        answer = (row.get("applicable_yes_no") or "").strip().lower()
        if not control:
            raise ConversionError(f"SoA line {n}: annex_control_id is empty")
        if answer not in ("yes", "no"):
            raise ConversionError(
                f"SoA line {n} ({control}): applicable_yes_no must be yes or "
                f"no, not {answer!r} — an unanswered control is not decided"
            )
        if control in decisions:
            raise ConversionError(f"SoA line {n}: {control} is answered twice")
        why = (
            row.get("justification_for_exclusion")
            if answer == "no"
            else row.get("justification_for_inclusion")
        )
        why = (why or "").strip() or None
        if answer == "no" and not why:
            raise ConversionError(
                f"SoA line {n} ({control}): an excluded control must carry "
                "justification_for_exclusion (ISO/IEC 27001 6.1.3(d))"
            )
        decisions[control] = SoaDecision(applicable=answer == "yes", justification=why)
    return decisions


def _candidates(fields: str) -> List[str]:
    names = [f.strip() for f in fields.split("|")]
    return [n for n in names if n and n.lower() not in _BOOKKEEPING]


def build_baseline(
    rows: Sequence[Mapping[str, str]],
    *,
    soa: Optional[Mapping[str, SoaDecision]],
    demo_all_applicable: bool,
    tenant: str,
    baseline_id: str,
    baseline_version: int,
    policy_id: str,
    policy_version: str,
    policy_title: str,
    approved_at: datetime,
    effective_from: datetime,
    produced_at: datetime,
) -> Tuple[CcurePolicyBaselineV1, Report]:
    if (soa is None) == (not demo_all_applicable):
        raise ConversionError(
            "give the organisation's SoA answers (--soa) or ask for a "
            "demonstration explicitly (--demo-all-applicable), never both and "
            "never neither: applicability is a decision, not a default"
        )
    _library_kind(rows)

    clauses = [r for r in rows if r["clause_type"] == POLICY_CLAUSE]
    report = Report(references=len(clauses))
    seen: Dict[str, str] = {}
    controls: List[dict] = []
    for row in clauses:
        ref = row["iso_reference"].strip()
        if ref in seen:
            raise ConversionError(
                f"{ref} has two Policy Clause rows ({seen[ref]}, {row['clause_id']})"
            )
        seen[ref] = row["clause_id"]

        isms = row["iso_area"] == ISMS_AREA
        if isms:
            report.isms_clauses += 1
            decision = SoaDecision(applicable=True, justification=None)
            if soa is not None and ref in soa and not soa[ref].applicable:
                raise ConversionError(
                    f"{ref} is a management-system clause, mandatory for ISO "
                    "27001 conformity; the SoA cannot exclude it"
                )
        elif row["iso_area"] == ANNEX_AREA:
            report.annex_controls += 1
            if soa is None:
                decision = SoaDecision(applicable=True, justification=None)
            elif ref not in soa:
                raise ConversionError(
                    f"{ref} ({row['control_title']}) has no SoA decision; an "
                    "undecided control is not applicable by default"
                )
            else:
                decision = soa[ref]
        else:
            raise ConversionError(f"{ref}: unknown iso_area {row['iso_area']!r}")

        if not decision.applicable:
            report.not_applicable += 1
        found = _candidates(row.get("policypro_template_fields", ""))
        if found:
            report.candidate_parameters[ref] = found

        controls.append(
            {
                "requirement_id": row["clause_id"],
                "control": {
                    "framework": {"code": ISO_CODE, "version": ISO_VERSION},
                    "control_id": ref,
                },
                "applicability": (
                    "applicable" if decision.applicable else "not_applicable"
                ),
                "applicability_justification": decision.justification,
                "requirement_text": (
                    row.get("detailed_policy_requirement") or ""
                ).strip()
                or None,
                "parameters": [],
            }
        )

    if soa is not None:
        unknown = sorted(set(soa) - set(seen))
        if unknown:
            raise ConversionError(
                f"SoA answers controls the library does not have: {unknown}"
            )

    title = policy_title
    if demo_all_applicable:
        title = f"DEMONSTRATION ONLY — not an approved policy: {policy_title}"

    content = {
        "baseline_id": baseline_id,
        "baseline_version": baseline_version,
        "policy": {
            "policy_id": policy_id,
            "policy_version": policy_version,
            "title": title[:500],
        },
        "status": "approved",
        "approved_at": approved_at,
        "effective_from": effective_from,
        "frameworks": [{"code": ISO_CODE, "version": ISO_VERSION}],
        "controls": controls,
    }
    message = CcurePolicyBaselineV1.model_validate(
        {
            "contract": POLICY_BASELINE_CONTRACT,
            "schema_version": SCHEMA_VERSION,
            # Stable across retries of the same baseline version — the contract's
            # idempotency key.
            "message_id": uuid.uuid5(_NS, f"{tenant}|{baseline_id}|{baseline_version}"),
            "tenant_id": tenant,
            "source": {
                "module": "policy_pro",
                "module_version": "library-converter-reference",
            },
            "produced_at": produced_at,
            "correlation_id": f"policypro-import-{baseline_id}-{baseline_version}",
            "data": content,
        }
    )
    return message, report


def _open(path: str) -> TextIO:
    if path == "-":
        return io.TextIOWrapper(sys.stdin.buffer, encoding="utf-8", newline="")
    return open(path, encoding="utf-8", newline="")


def _when(text: Optional[str], default: datetime) -> datetime:
    if not text:
        return default
    value = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if value.tzinfo is None:
        raise ConversionError(f"{text!r} carries no timezone")
    return value


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--library", required=True, help="library CSV, or - for stdin")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--soa", help="the organisation's SoA answers CSV")
    group.add_argument("--demo-all-applicable", action="store_true")
    parser.add_argument("--tenant", required=True)
    parser.add_argument("--baseline-id", default="policypro-iso27001-demo")
    parser.add_argument("--baseline-version", type=int, default=1)
    parser.add_argument("--policy-id", default="policypro-iso27001-library")
    parser.add_argument("--policy-version", default="1")
    parser.add_argument("--policy-title", default="ISO/IEC 27001:2022 policy library")
    parser.add_argument("--approved-at")
    parser.add_argument("--effective-from")
    parser.add_argument(
        "--report", action="store_true", help="print the conversion report to stderr"
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    now = datetime.now(timezone.utc)
    try:
        if args.soa and not args.approved_at:
            raise ConversionError(
                "--approved-at is required with --soa: an approved policy has an approval date"
            )
        with _open(args.library) as fh:
            rows = _read_rows(fh)
        soa = None
        if args.soa:
            with _open(args.soa) as fh:
                soa = read_soa(fh)
        approved = _when(args.approved_at, now)
        message, report = build_baseline(
            rows,
            soa=soa,
            demo_all_applicable=args.demo_all_applicable,
            tenant=args.tenant,
            baseline_id=args.baseline_id,
            baseline_version=args.baseline_version,
            policy_id=args.policy_id,
            policy_version=args.policy_version,
            policy_title=args.policy_title,
            approved_at=approved,
            effective_from=_when(args.effective_from, approved),
            produced_at=now,
        )
    except ConversionError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2

    print(message.model_dump_json(by_alias=True, indent=2))
    if args.report:
        print(
            f"references {report.references} (ISMS clauses {report.isms_clauses}, "
            f"Annex A {report.annex_controls}); not applicable {report.not_applicable}; "
            f"references with candidate parameter names {len(report.candidate_parameters)}",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
