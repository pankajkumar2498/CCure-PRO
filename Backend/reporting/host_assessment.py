"""
host_assessment.py
─────────────────────────────────────────────────────────────────────────────
What an authenticated pass examined on each host, pulled out of a stored scan
payload.

Three readings the credentialed pipeline has recorded for a long time and no
report has ever printed:

  * ``hardening_audits`` — the host's configuration posture, PASS / FAIL /
    WARN / NOT_ASSESSED per control.
  * ``collection_errors`` — the sections the authenticated session could not
    read, and why.
  * ``listeners_undetermined`` — listening services whose reachability was
    never established.

They are host-level, not per-finding, so none of them can be a column on the
findings sheet. They belong in sections of their own, and they matter for the
same reason: **a report must never make an assessment look more complete than
it was.** A host whose package collection failed produces no package findings,
which on the page is byte-identical to a host with nothing wrong with it.

Extraction lives here, apart from ``pdf_generator``, because it is pure
dictionary work with no ReportLab in it — which is what makes it testable
without building a document, and reviewable without reading a 130 KB module.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

#: The verdict vocabulary ``core.tasks._hardening_row`` writes, and what each
#: word is allowed to mean in a report.
#:
#: ``NOT_ASSESSED`` is the load-bearing one. The SMB transport serves a subset
#: of the Windows inventory, so a control nobody read is a normal outcome
#: rather than a fault — and rendering it as PASS claims a control was
#: satisfied on evidence that was never gathered, which is the single defect
#: this whole distinction exists to prevent.
HARDENING_STATUS_MEANING: Dict[str, str] = {
    "PASS": "The setting was read and is in the hardened state.",
    "FAIL": "The setting was read and is not in the hardened state.",
    "WARN": "The setting was read and needs review in context.",
    "NOT_ASSESSED": "This scan did not read the setting. No verdict is claimed.",
}

#: Order for the posture table: what needs action first, then what passed, then
#: what nobody looked at. Deliberately not alphabetical — a reader scanning the
#: section is looking for the failures.
_STATUS_ORDER = {"FAIL": 0, "WARN": 1, "PASS": 2, "NOT_ASSESSED": 3}

#: Keys a stored credentialed report carries. A mapping holding any of them is
#: one of these records; a mapping holding none of them is some other part of
#: the payload we are walking past.
_REPORT_MARKERS = (
    "hardening_audits",
    "collection_errors",
    "exposure_summary",
    "inventory_complete",
)


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


@dataclass
class HardeningControl:
    """One hardening control's verdict, as the scan recorded it."""

    key: str
    label: str
    status: str
    detail: str

    @property
    def assessed(self) -> bool:
        return self.status != "NOT_ASSESSED"

    @property
    def meaning(self) -> str:
        return HARDENING_STATUS_MEANING.get(
            self.status,
            # A status this build does not know is reported as itself rather
            # than folded into one it does. Mapping an unrecognised verdict
            # onto PASS or FAIL would be inventing the answer; saying it is
            # unrecognised sends the reader to the scan that wrote it.
            "Recorded by the scan; this report has no description for it.",
        )

    def sort_key(self) -> Tuple[int, str]:
        return (_STATUS_ORDER.get(self.status, 4), self.label.lower())


@dataclass
class CollectionFailure:
    """One section an authenticated session could not read, and the reason."""

    section: str
    reason: str

    #: The SMB transport records the items it structurally does not serve under
    #: an ``item:`` prefix, which is a different statement from a section that
    #: was attempted and failed. Keeping them apart stops a transport's known
    #: limits reading as a broken scan.
    @property
    def is_unserved_item(self) -> bool:
        return self.section.startswith("item:")

    @property
    def display_section(self) -> str:
        return self.section[5:] if self.is_unserved_item else self.section


@dataclass
class ListenerExposure:
    """How many listening services were placed, and how many were not."""

    total: Optional[int] = None
    exposed: Optional[int] = None
    host_only: Optional[int] = None
    filtered: Optional[int] = None
    undetermined: Optional[int] = None
    correlated: Optional[bool] = None

    @property
    def recorded(self) -> bool:
        return any(
            value is not None
            for value in (
                self.total,
                self.exposed,
                self.host_only,
                self.filtered,
                self.undetermined,
            )
        )

    @property
    def has_undetermined(self) -> bool:
        return bool(self.undetermined)


@dataclass
class HostAssessment:
    """One host's credentialed assessment record."""

    host: str = ""
    hardening: List[HardeningControl] = field(default_factory=list)
    collection_failures: List[CollectionFailure] = field(default_factory=list)
    exposure: ListenerExposure = field(default_factory=ListenerExposure)
    #: ``None`` when the scan did not record the flag at all, which is not the
    #: same as recording that the inventory was incomplete.
    inventory_complete: Optional[bool] = None

    @property
    def has_content(self) -> bool:
        return bool(
            self.hardening or self.collection_failures or self.exposure.recorded
        )

    def hardening_sorted(self) -> List[HardeningControl]:
        return sorted(self.hardening, key=lambda c: c.sort_key())

    def hardening_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for control in self.hardening:
            counts[control.status] = counts.get(control.status, 0) + 1
        return counts


def _as_int(value: Any) -> Optional[int]:
    """An integer, or ``None`` — never a zero standing in for an absent count."""
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _as_bool_or_none(value: Any) -> Optional[bool]:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in ("true", "yes", "1"):
        return True
    if text in ("false", "no", "0"):
        return False
    return None


def _parse_hardening(raw: Any) -> List[HardeningControl]:
    if not isinstance(raw, Mapping):
        return []
    out: List[HardeningControl] = []
    for key, row in raw.items():
        if not isinstance(row, Mapping):
            continue
        status = _text(row.get("status")).upper() or "NOT_ASSESSED"
        out.append(
            HardeningControl(
                key=str(key),
                label=_text(row.get("label")) or str(key).replace("_", " ").title(),
                status=status,
                detail=_text(row.get("detail")),
            )
        )
    return out


def _parse_collection_errors(raw: Any) -> List[CollectionFailure]:
    if not isinstance(raw, Mapping):
        return []
    return [
        CollectionFailure(section=str(section), reason=_text(reason))
        for section, reason in raw.items()
    ]


def _parse_exposure(raw: Any) -> ListenerExposure:
    if not isinstance(raw, Mapping):
        return ListenerExposure()
    return ListenerExposure(
        total=_as_int(raw.get("listeners_total")),
        exposed=_as_int(raw.get("listeners_exposed")),
        host_only=_as_int(raw.get("listeners_host_only")),
        filtered=_as_int(raw.get("listeners_filtered")),
        undetermined=_as_int(raw.get("listeners_undetermined")),
        correlated=_as_bool_or_none(raw.get("correlated_with_port_scan")),
    )


def collect_host_assessments(
    payload: Any, depth: int = 0, host_hint: str = ""
) -> List[HostAssessment]:
    """
    Every credentialed assessment record in a stored scan payload.

    **Walked rather than read from a fixed path**, for exactly the reason
    ``reporting.exports._collect_host_audits`` is: the same record reaches at
    least three shapes. The vulnerability-audit pipeline nests it under
    ``_phase_data[i].credentialed_report``, the standalone credentialed scan
    puts the whole report in ``options["credentialed_report"]``, and a
    multi-host run carries a list of reports beside a single ``report``. A
    fixed path finds one of those and returns nothing for the other two — and
    "nothing" here renders as a host with no collection failures, which is the
    reassuring reading.

    The host is taken from the record's own container, so a walk can never
    attribute one machine's collection failures to another.
    """
    found: List[HostAssessment] = []
    if depth > 8:
        return found

    if isinstance(payload, Mapping):
        host = (
            _text(payload.get("target"))
            or _text(payload.get("ip_address"))
            or _text(payload.get("ip"))
            or host_hint
        )
        if any(marker in payload for marker in _REPORT_MARKERS):
            record = HostAssessment(
                host=host,
                hardening=_parse_hardening(payload.get("hardening_audits")),
                collection_failures=_parse_collection_errors(
                    payload.get("collection_errors")
                ),
                exposure=_parse_exposure(payload.get("exposure_summary")),
                inventory_complete=_as_bool_or_none(payload.get("inventory_complete")),
            )
            if record.has_content:
                found.append(record)
        for key, value in payload.items():
            if key in _REPORT_MARKERS:
                continue
            found.extend(collect_host_assessments(value, depth + 1, host))
    elif isinstance(payload, list):
        for item in payload:
            found.extend(collect_host_assessments(item, depth + 1, host_hint))

    return found


def dedupe_host_assessments(records: List[HostAssessment]) -> List[HostAssessment]:
    """
    One record per host per distinct reading.

    A multi-host credentialed scan stores the first host's report twice — once
    as ``report`` for the consumers that predate multi-host support and once
    inside ``reports`` — so a plain walk returns it twice and the posture table
    would list that host's controls twice over.
    """
    seen: set = set()
    out: List[HostAssessment] = []
    for record in records:
        key = (
            record.host,
            tuple(sorted((c.key, c.status) for c in record.hardening)),
            tuple(sorted((f.section, f.reason) for f in record.collection_failures)),
            (
                record.exposure.total,
                record.exposure.exposed,
                record.exposure.host_only,
                record.exposure.filtered,
                record.exposure.undetermined,
            ),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(record)
    return out


def host_assessments(payload: Any) -> List[HostAssessment]:
    """Every credentialed assessment record in a payload, deduplicated."""
    return dedupe_host_assessments(collect_host_assessments(payload))


def exposure_sentence(exposure: ListenerExposure) -> str:
    """
    The listener-exposure line, stating only what was placed.

    Every clause is omitted when its count was not recorded. The previous
    wording in the methodology appendix read

        "{exposed or 0} listening service(s) confirmed reachable,
         {host_only or 0} bound to loopback"

    which does two things this must not. It turns an unrecorded count into a
    zero — an assertion that nothing was found where the truth is that nobody
    counted — and it accounts for two categories out of four, so the listeners
    whose reachability was never established simply vanish from a sentence
    whose whole job is to add up.
    """
    if not exposure.recorded:
        return ""

    parts: List[str] = []
    if exposure.exposed is not None:
        parts.append(f"{exposure.exposed} confirmed reachable from the scanner")
    if exposure.host_only is not None:
        parts.append(f"{exposure.host_only} bound to loopback and not reachable")
    if exposure.filtered is not None:
        parts.append(f"{exposure.filtered} listening but filtered")
    if exposure.undetermined is not None:
        # Named explicitly, and never folded into "filtered" or "exposed".
        # A listener outside the scanned port range had nothing established
        # about it in either direction.
        parts.append(f"{exposure.undetermined} whose reachability was not established")

    if not parts:
        return ""

    total = (
        f"{exposure.total} listening service(s): "
        if exposure.total is not None
        else "Listening services: "
    )
    return total + ", ".join(parts) + "."
