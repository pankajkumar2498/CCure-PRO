"""
core/findings/comparison.py
─────────────────────────────────────────────────────────────────────────────
What changed between two scans.

At the scale this product now reaches — 955 benchmark rules on top of the
built-ins, and 4,633 findings measured on a single Linux host — the full
finding list stopped being a thing a person can read. The delta is the workable
unit: twelve new, eight fixed, two back again.

No new finding model and no second store. ``asset_vulnerabilities`` already
carries everything this needs and has since before Phase 0:

* ``id``              — deterministic from (asset, vuln_id, source_family), so
                        the *same logical finding* keeps one row across scans
                        and re-detections. This is the identity used here; row
                        ids are not re-minted per scan.
* ``first_found_at``  — when it was first seen
* ``last_found_at``   — when it was last seen
* ``fixed_at``        — when it was last observed to have gone
* ``status``          — ``open`` / ``fixed``

Reconstructing a baseline without a per-scan occurrence table
─────────────────────────────────────────────────────────────
The obvious way to ask "was this finding present in scan X" is a row per
finding per scan. That table would carry thousands of rows per host per scan
and it is not necessary, because the lifecycle timestamps already answer the
question for **any** point in time:

    a finding was open at time T
      iff  first_found_at <= T  and  (fixed_at is null or fixed_at > T)

A baseline scan is just a T. That is the whole trick, and it is why this ships
as a query rather than a schema change.

Its one limitation is stated rather than hidden: only the *most recent*
``fixed_at`` survives, so a finding that has been fixed and has come back more
than once reconstructs correctly for the latest cycle and approximately for
earlier ones. Findings that flap are exactly the ones an operator most wants to
see, which is why ``REAPPEARED`` is a class of its own rather than folded into
``NEW``.

**The rule this module exists to enforce**
──────────────────────────────────────────
A finding is **never** reported fixed because it was absent from a scan. It is
reported fixed only when the scan that could have found it actually looked and
did not. "Nobody looked" and "it is gone" are different facts, and a scanner
that confuses them tells an operator a vulnerability was remediated when the
credential simply expired. Absence with no assessment is ``NOT_ASSESSED`` — a
class of its own, visible in the counts and in the report.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from sqlalchemy.orm import Session

from db.models.findings import AssetVulnerability
from db.models.scans import Scan

log = logging.getLogger("ccure.findings.comparison")

__all__ = [
    "CLASS_NEW",
    "CLASS_STILL_OPEN",
    "CLASS_FIXED",
    "CLASS_REAPPEARED",
    "CLASS_NOT_ASSESSED",
    "CLASSIFICATIONS",
    "AssessmentScope",
    "FindingDelta",
    "ScanComparison",
    "compare_scans",
    "record_assessment_scope",
    "read_assessment_scope",
]

#: Open now, and not open at the baseline.
CLASS_NEW = "new"
#: Open at the baseline and open now. The bulk of any estate.
CLASS_STILL_OPEN = "still_open"
#: Open at the baseline, looked for by this scan, and gone.
CLASS_FIXED = "fixed"
#: Fixed at or before the baseline and open again now.
CLASS_REAPPEARED = "reappeared"
#: Open at the baseline, absent now, and **this scan did not look**. Never
#: folded into ``fixed`` — see the module docstring.
CLASS_NOT_ASSESSED = "not_assessed"

CLASSIFICATIONS: Tuple[str, ...] = (
    CLASS_NEW,
    CLASS_STILL_OPEN,
    CLASS_FIXED,
    CLASS_REAPPEARED,
    CLASS_NOT_ASSESSED,
)

#: Where the per-scan assessment scope lives. ``scans.options`` is JSONB, is
#: already used for ``options.origin``, and is returned to clients — which is
#: fine for scope and is why no secret may go near it.
#:
#: A dedicated column was considered and rejected: it would be a migration on a
#: live table for something with no query predicate of its own, and GAP-12 will
#: introduce a real scan-policy record that this should fold into rather than
#: compete with. This is the smallest thing that makes a comparison honest.
SCOPE_KEY = "assessment_scope"


@dataclass(frozen=True)
class AssessmentScope:
    """
    What a scan actually assessed.

    ``families`` are ``source_family`` values — the same vocabulary
    ``asset_syncer`` and ``core.tasks`` already classify findings by, so no new
    taxonomy is introduced. ``assets`` are the asset ids the scan reached.

    ``recorded`` is False for any scan that predates this phase or that failed
    before it could record anything. That is not a defect and must not be
    treated as "assessed nothing recently" — it is "we do not know", and the
    comparison degrades to never reporting a fix rather than guessing.
    """

    recorded: bool = False
    families: Tuple[str, ...] = ()
    assets: Tuple[str, ...] = ()
    detail: Mapping[str, Any] = field(default_factory=dict)

    def covers(self, asset_id: str, family: str) -> bool:
        """Whether this scan looked at *family* on *asset_id*."""
        if not self.recorded:
            return False
        if self.assets and asset_id not in self.assets:
            return False
        return family in self.families

    @property
    def assessed_checks(self) -> frozenset:
        """
        The configuration checks this scan reached a PASS or FAIL on.

        Written by ``core.tasks`` from the same set its own fixed-sweep uses,
        so the sweep and the comparison cannot disagree about what was
        assessed. Empty when the scan predates the record — which is "we do not
        know", handled by ``covers_check`` below and never as "nothing".
        """
        raw = (self.detail or {}).get("assessed_checks")
        if not isinstance(raw, (list, tuple, set, frozenset)):
            return frozenset()
        return frozenset(str(item) for item in raw if item)

    def covers_check(self, vuln_id: str) -> bool:
        """
        Whether this scan actually evaluated the check behind *vuln_id*.

        ``covers`` answers a question about *families*, and every credentialed
        finding — CVE and configuration alike — carries the family
        ``credentialed_package``. That is coarse enough to be wrong in a way
        real targets showed: a scan narrowed by a GAP-12 policy still covers
        the family, so a configuration finding whose check the policy stopped
        selecting looked, to the comparison, like a finding the scan had
        searched for and not found — a **fix**, reported for five controls on
        a host where nothing had changed and where the scan's own sweep had
        correctly left them open.

        A CVE is unaffected: the package matcher runs over the whole installed
        inventory, so a CVE it does not report on a host it inventoried really
        is gone. Only a check has to have been individually selected.

        A scan that recorded no check set at all returns True — the
        pre-GAP-15 behaviour — because "we do not know which checks ran" must
        not silently reclassify every historical comparison.
        """
        assessed = self.assessed_checks
        if not assessed:
            return True

        from core.checks.definitions import (
            DEFINITION_TYPE_CVE,
            definition_type_for_id,
        )

        identifier = str(vuln_id or "")
        if not identifier:
            return True
        if definition_type_for_id(identifier) == DEFINITION_TYPE_CVE:
            return True
        return identifier in assessed

    def as_dict(self) -> Dict[str, Any]:
        return {
            "recorded": self.recorded,
            "families": list(self.families),
            "assets": list(self.assets),
            "detail": dict(self.detail),
        }


@dataclass
class FindingDelta:
    """One finding, and what happened to it between the two scans."""

    finding_id: str
    vuln_id: str
    asset_id: str
    classification: str
    severity: str = ""
    title: str = ""
    source_family: str = ""
    first_found_at: Optional[datetime] = None
    last_found_at: Optional[datetime] = None
    fixed_at: Optional[datetime] = None
    evidence: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "vuln_id": self.vuln_id,
            "asset_id": self.asset_id,
            "classification": self.classification,
            "severity": self.severity,
            "title": self.title,
            "source_family": self.source_family,
            "first_found_at": (
                self.first_found_at.isoformat() if self.first_found_at else None
            ),
            "last_found_at": (
                self.last_found_at.isoformat() if self.last_found_at else None
            ),
            "fixed_at": self.fixed_at.isoformat() if self.fixed_at else None,
            "evidence": self.evidence,
        }


@dataclass
class ScanComparison:
    """The whole answer: whether it is meaningful, the counts, and the rows."""

    current_scan_id: str
    baseline_scan_id: str
    comparable: bool
    reason: str = ""
    counts: Dict[str, int] = field(default_factory=dict)
    severity_counts: Dict[str, Dict[str, int]] = field(default_factory=dict)
    findings: List[FindingDelta] = field(default_factory=list)
    current_scope: AssessmentScope = field(default_factory=AssessmentScope)
    baseline_scope: AssessmentScope = field(default_factory=AssessmentScope)
    assets: Tuple[str, ...] = ()
    #: GAP-12. What configuration each scan ran under, and whether they agree.
    #: ``policies_match`` False does not make the comparison invalid -- the
    #: counts are still correct for the findings that exist -- but it means the
    #: delta partly reflects a change in what was assessed, and the report says
    #: so rather than implying the estate changed.
    current_policy: Dict[str, Any] = field(default_factory=dict)
    baseline_policy: Dict[str, Any] = field(default_factory=dict)
    policies_match: bool = False

    def summary_line(self) -> str:
        """``12 new, 340 unchanged, 8 fixed, 2 reappeared`` — the report's line."""
        parts = [
            f"{self.counts.get(CLASS_NEW, 0)} new",
            f"{self.counts.get(CLASS_STILL_OPEN, 0)} unchanged",
            f"{self.counts.get(CLASS_FIXED, 0)} fixed",
            f"{self.counts.get(CLASS_REAPPEARED, 0)} reappeared",
        ]
        not_assessed = self.counts.get(CLASS_NOT_ASSESSED, 0)
        if not_assessed:
            # Said out loud rather than omitted. A reader who is told "8 fixed"
            # and not told "40 not assessed" has been given a number that
            # implies progress the scan did not establish.
            parts.append(f"{not_assessed} not assessed")
        return ", ".join(parts)

    def as_dict(self, *, include_findings: bool = True) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "current_scan_id": self.current_scan_id,
            "baseline_scan_id": self.baseline_scan_id,
            "comparable": self.comparable,
            "reason": self.reason,
            "summary": self.summary_line(),
            "counts": dict(self.counts),
            "severity_counts": {k: dict(v) for k, v in self.severity_counts.items()},
            "assets": list(self.assets),
            "current_scope": self.current_scope.as_dict(),
            "baseline_scope": self.baseline_scope.as_dict(),
            "current_policy": dict(self.current_policy),
            "baseline_policy": dict(self.baseline_policy),
            "policies_match": self.policies_match,
        }
        if include_findings:
            payload["findings"] = [f.as_dict() for f in self.findings]
        return payload


# ─────────────────────────────────────────────────────────────────────────────
# Assessment scope
# ─────────────────────────────────────────────────────────────────────────────


def record_assessment_scope(
    scan: Scan,
    *,
    assets: Iterable[str],
    families: Iterable[str],
    detail: Optional[Mapping[str, Any]] = None,
) -> None:
    """
    Record what *scan* assessed, merging with anything already recorded.

    Merged rather than replaced because one scan writes findings from several
    paths — the package matcher and the configuration audit are separate calls
    over the same session — and the second must not erase the first's account
    of what it looked at.

    Mutates ``scan.options`` in place; the caller commits. Never called with a
    secret: ``options`` is returned to clients.
    """
    options = dict(scan.options or {})
    existing = options.get(SCOPE_KEY) or {}

    merged_assets = sorted(
        {str(a) for a in (existing.get("assets") or []) if a}
        | {str(a) for a in assets if a}
    )
    merged_families = sorted(
        {str(f) for f in (existing.get("families") or []) if f}
        | {str(f) for f in families if f}
    )
    merged_detail = dict(existing.get("detail") or {})
    merged_detail.update(dict(detail or {}))

    options[SCOPE_KEY] = {
        "recorded": True,
        "assets": merged_assets,
        "families": merged_families,
        "detail": merged_detail,
    }
    # Reassigned rather than mutated: SQLAlchemy does not see an in-place edit
    # of a JSON column, so the write would be silently dropped.
    scan.options = options


def policy_context(scan: Optional[Scan]) -> Dict[str, Any]:
    """
    The assessment configuration a scan ran under, for the comparison payload.

    GAP-12 supplies this; GAP-13 only reports it. Two scans are not equivalent
    assessments merely because they ran against the same host — if one assessed
    the Ubuntu 24.04 STIG at severity high and the other assessed everything
    installed, the difference between their findings is a difference in *scope*
    and reporting it as a change in the estate would be wrong.

    A scan with no snapshot returns ``recorded: False``. That is "we do not
    know how this was configured", which is deliberately **not** treated as
    agreement — see ``policies_comparable`` below.
    """
    from core.scan_policy import read_policy_snapshot

    policy = read_policy_snapshot(scan)
    if policy is None:
        return {"recorded": False}
    return {
        "recorded": True,
        "policy_id": policy.policy_id,
        "policy_name": policy.policy_name or None,
        "policy_family_code": policy.policy_family_code or None,
        "version_number": policy.version_number or None,
        "fingerprint": policy.fingerprint(),
        "source": policy.source,
        "summary": policy.describe(),
    }


def policies_comparable(
    current: Mapping[str, Any], baseline: Mapping[str, Any]
) -> bool:
    """
    Whether the two scans were assessed the same way.

    Compared on the fingerprint, which excludes the policy's name and version
    by construction: renaming a policy, or bumping a version that changed only
    a description, must not make a scan incomparable with the one before it.
    Editing what it assesses must.

    An unrecorded snapshot on either side is **not** agreement. Both scans
    predating GAP-12 is the common case and is reported as unknown rather than
    as equivalent — a comparison that quietly assumed two unknown
    configurations matched would be making the claim this function exists to
    stop.
    """
    if not current.get("recorded") or not baseline.get("recorded"):
        return False
    left = str(current.get("fingerprint") or "")
    right = str(baseline.get("fingerprint") or "")
    return bool(left) and left == right


def read_assessment_scope(scan: Optional[Scan]) -> AssessmentScope:
    if scan is None:
        return AssessmentScope()
    raw = (scan.options or {}).get(SCOPE_KEY) or {}
    if not raw.get("recorded"):
        return AssessmentScope()
    return AssessmentScope(
        recorded=True,
        families=tuple(raw.get("families") or ()),
        assets=tuple(raw.get("assets") or ()),
        detail=dict(raw.get("detail") or {}),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Comparison
# ─────────────────────────────────────────────────────────────────────────────


def _scan_window(scan: Scan) -> Tuple[Optional[datetime], Optional[datetime]]:
    """
    When the scan ran.

    ``started_at`` and ``completed_at`` are written once and never rewritten.
    ``updated_at`` carries ``onupdate=utcnow``, so it moves every time the row
    is touched for any reason — CLAUDE.md records a case where regenerating a
    report bumped it and corrupted the Scan History date. Using it as the end
    of the observation window would mean a scan's boundary silently travelling
    forward whenever anything edited the row, which for this comparison would
    reclassify findings on a scan nobody re-ran. It is a last-resort fallback
    for rows that predate those columns, nothing more.
    """
    start = (
        getattr(scan, "started_at", None)
        or getattr(scan, "queued_at", None)
        or getattr(scan, "created_at", None)
    )
    end = getattr(scan, "completed_at", None) or getattr(scan, "updated_at", None)
    return start, end


def _classify(
    row: AssetVulnerability,
    *,
    baseline_start: Optional[datetime],
    baseline_end: datetime,
    current_start: datetime,
    current_scope: AssessmentScope,
) -> Optional[str]:
    """
    Which bucket one finding belongs in, or None if it is not part of the delta.

    Every branch here is a statement about *evidence*, not about convenience.
    """
    first_found = row.first_found_at
    fixed_at = row.fixed_at
    last_found = row.last_found_at
    is_open = (row.status or "").lower() == "open"

    # Was it open at the moment the baseline finished?
    #
    # The third clause is what stops a finding being reported as a regression
    # for the rest of its life. `fixed_at` holds only the *most recent* fix, and
    # it is not cleared when a finding comes back — so a CVE fixed in scan B and
    # back in scan C still carries B's timestamp when D is compared against C.
    # Measured on the disposable target: four curl CVEs correctly reported
    # reappeared for C-against-B, then wrongly reported reappeared again for
    # D-against-C, when by then they had simply been open the whole time.
    #
    # If the fix predates the baseline's own start and the finding is open now,
    # it must have returned at or before the baseline — so the baseline saw it
    # open, and it is unchanged rather than a regression.
    open_at_baseline = bool(
        first_found
        and first_found <= baseline_end
        and (
            fixed_at is None
            or fixed_at > baseline_end
            or (baseline_start is not None and fixed_at < baseline_start and is_open)
        )
    )

    # Did the current scan actually touch it? `last_found_at` is stamped by the
    # sync on every re-detection, so a finding this scan saw carries a
    # timestamp inside the scan's own window.
    seen_by_current = bool(last_found and current_start and last_found >= current_start)

    if is_open and seen_by_current:
        if open_at_baseline:
            return CLASS_STILL_OPEN
        # Open now, not open at the baseline. Two ways that happens, and they
        # are worth telling apart: it is genuinely new, or it had been fixed
        # and is back.
        if fixed_at is not None and fixed_at <= baseline_end:
            return CLASS_REAPPEARED
        return CLASS_NEW

    if open_at_baseline and not seen_by_current:
        # The finding was open and this scan did not report it. Whether that is
        # a fix depends entirely on whether the scan looked.
        if current_scope.covers(
            row.asset_id or "", row.source_family or ""
        ) and current_scope.covers_check(row.vuln_id or ""):
            # It looked, and did not find it. That is a fix — and note the row
            # itself need not say "fixed": the sweep in the sync marks it, but
            # this classification does not depend on that having run.
            return CLASS_FIXED
        return CLASS_NOT_ASSESSED

    return None


def compare_scans(
    db: Session,
    *,
    current: Scan,
    baseline: Scan,
    asset_ids: Optional[Sequence[str]] = None,
    severities: Optional[Sequence[str]] = None,
    limit_findings: Optional[int] = None,
) -> ScanComparison:
    """
    Compare *current* against *baseline* for the assets they share.

    Both scans must already have been fetched through the caller's own
    tenant-scoped lookup; this function trusts that and filters findings by
    ``org_id`` again anyway, because a comparison that leaked one tenant's
    findings into another's report would be the worst defect available here.
    """
    org_id = current.org_id
    current_scope = read_assessment_scope(current)
    baseline_scope = read_assessment_scope(baseline)
    current_policy = policy_context(current)
    baseline_policy = policy_context(baseline)

    comparison = ScanComparison(
        current_scan_id=str(current.id),
        baseline_scan_id=str(baseline.id),
        comparable=True,
        current_policy=current_policy,
        baseline_policy=baseline_policy,
        policies_match=policies_comparable(current_policy, baseline_policy),
        current_scope=current_scope,
        baseline_scope=baseline_scope,
        counts={c: 0 for c in CLASSIFICATIONS},
    )

    if baseline.org_id != org_id:
        comparison.comparable = False
        comparison.reason = "the two scans belong to different organisations"
        return comparison

    baseline_start, baseline_end = _scan_window(baseline)
    current_start, _current_end = _scan_window(current)
    if baseline_end is None or current_start is None:
        comparison.comparable = False
        comparison.reason = "one of the scans has no recorded time window"
        return comparison
    if current_start < baseline_end:
        comparison.comparable = False
        comparison.reason = (
            "the baseline scan finished after the current scan started; pass "
            "the older scan as the baseline"
        )
        return comparison

    # Which assets both scans cover. Falls back to the current scan's own scope
    # when the baseline predates scope recording, because comparing against a
    # scan whose reach is unknown is still useful — it just cannot produce a
    # FIXED, which `_classify` enforces through `current_scope`.
    shared = set(current_scope.assets) if current_scope.recorded else set()
    if baseline_scope.recorded and baseline_scope.assets:
        shared = (
            shared & set(baseline_scope.assets)
            if shared
            else set(baseline_scope.assets)
        )
    if asset_ids:
        wanted = {str(a) for a in asset_ids}
        shared = (shared & wanted) if shared else wanted
    comparison.assets = tuple(sorted(shared))

    if not current_scope.recorded:
        # Everything still classifies; nothing can be called fixed. Said in the
        # response so a reader knows why the fixed count is zero.
        comparison.reason = (
            "the current scan recorded no assessment scope, so a finding that "
            "is absent cannot be distinguished from one that was never looked "
            "for; nothing is reported as fixed"
        )

    query = db.query(AssetVulnerability).filter(AssetVulnerability.org_id == org_id)
    if comparison.assets:
        query = query.filter(AssetVulnerability.asset_id.in_(list(comparison.assets)))
    if severities:
        wanted_sev = {str(s).strip().lower() for s in severities if s}
        if wanted_sev:
            query = query.filter(AssetVulnerability.severity.in_(list(wanted_sev)))

    deltas: List[FindingDelta] = []
    severity_counts: Dict[str, Dict[str, int]] = {c: {} for c in CLASSIFICATIONS}

    # `yield_per` keeps this bounded on an estate with thousands of findings per
    # host: the rows stream rather than materialising the whole result set.
    for row in query.yield_per(1000):
        classification = _classify(
            row,
            baseline_start=baseline_start,
            baseline_end=baseline_end,
            current_start=current_start,
            current_scope=current_scope,
        )
        if classification is None:
            continue
        comparison.counts[classification] = comparison.counts.get(classification, 0) + 1
        sev = (row.severity or "unknown").strip().lower()
        bucket = severity_counts.setdefault(classification, {})
        bucket[sev] = bucket.get(sev, 0) + 1
        if limit_findings is not None and len(deltas) >= limit_findings:
            continue
        deltas.append(
            FindingDelta(
                finding_id=str(row.id),
                vuln_id=str(row.vuln_id or ""),
                asset_id=str(row.asset_id or ""),
                classification=classification,
                severity=sev,
                source_family=str(row.source_family or ""),
                first_found_at=row.first_found_at,
                last_found_at=row.last_found_at,
                fixed_at=row.fixed_at,
                evidence=str(row.evidence or "")[:2000],
            )
        )

    comparison.findings = deltas
    comparison.severity_counts = severity_counts
    return comparison


def _scan_targets(scan: Scan) -> list[str]:
    raw = getattr(scan, "target_hosts", None) or []
    if isinstance(raw, str):
        raw = [raw]
    targets = [str(t).strip() for t in raw if str(t).strip()]
    if not targets:
        targets = [
            t.strip() for t in str(getattr(scan, "target_str", "") or "").split(",")
        ]
    return [t for t in targets if t]


def _target_network(target: str):
    import ipaddress

    try:
        return ipaddress.ip_network(target, strict=False)
    except ValueError:
        return None


def targets_overlap(a: Scan, b: Scan) -> bool:
    """
    Whether two scans examined at least one address in common.

    Addresses and CIDR ranges are compared as networks, so a /24 sweep can be
    the baseline for a scan of one host inside it. Any other target (a
    hostname, a range string) has to match exactly.
    """
    a_targets, b_targets = _scan_targets(a), _scan_targets(b)
    b_networks = [n for n in (_target_network(t) for t in b_targets) if n]
    b_names = {t.lower() for t in b_targets if _target_network(t) is None}
    for target in a_targets:
        network = _target_network(target)
        if network is None:
            if target.lower() in b_names:
                return True
            continue
        if any(
            network.version == other.version and network.overlaps(other)
            for other in b_networks
        ):
            return True
    return False


#: How many earlier scans of the same shape are examined for an overlapping
#: one before giving up. Bounds the walk on a busy organisation.
_BASELINE_LOOKBACK = 200


def previous_scan_for(db: Session, scan: Scan) -> Optional[Scan]:
    """
    The most recent completed scan of the same shape, over the same hosts.

    Same organisation and same ``pipeline_mode``, because a credentialed audit
    and a discovery sweep look for different things and neither one's absence
    says anything about the other's findings.

    And at least one target in common. Without that, in any organisation that
    scans more than one host, the "previous scan" was simply the last one run:
    a Windows audit was compared with a Linux audit of another machine and
    reported every finding as new — and remediation verification, which reads
    this baseline, judged fixes against a scan that never looked at the host.
    """
    candidates = (
        db.query(Scan)
        .filter(
            Scan.org_id == scan.org_id,
            Scan.id != scan.id,
            Scan.pipeline_mode == scan.pipeline_mode,
            Scan.created_at < scan.created_at,
            Scan.status.in_(("complete", "completed")),
        )
        .order_by(Scan.created_at.desc())
        .limit(_BASELINE_LOOKBACK)
    )
    for candidate in candidates:
        if targets_overlap(scan, candidate):
            return candidate
    return None
