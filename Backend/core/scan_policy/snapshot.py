"""
core/scan_policy/snapshot.py
─────────────────────────────────────────────────────────────────────────────
The immutable record of what configuration produced a scan.

    route / dispatcher  ──resolve──>  EffectivePolicy
                        ──record───>  scans.options["scan_policy"]
    worker              ──read─────>  EffectivePolicy      (the same one)
    API / report        ──read─────>  EffectivePolicy      (still the same one)

The design decision the phase turns on
──────────────────────────────────────
**The snapshot is not a copy of what ran. It is what runs.** The dispatching
side resolves the policy once, writes it into the scan's own row, and the
worker reads it back from there rather than being handed it separately in the
task arguments. So the historical record and the execution cannot disagree,
because there is only one of them.

The alternative — pass the settings to the task *and* store a copy for the
report — is two sources that agree until the day they do not, and the day they
do not is the day an auditor is reading the report.

Why ``scans.options`` and not a new column
──────────────────────────────────────────
``options`` is JSONB, GIN-indexed, already carries ``origin``, ``schedule_id``
and GAP-13's ``assessment_scope``, and is already the client-visible record of
how a scan was configured. GAP-13 recorded in the tracker that "GAP-12's policy
record is where this should eventually fold in"; this is that fold. A column
on a live ``scans`` table for a value with no query predicate of its own buys
a migration and nothing else.

**Nothing secret may go in here.** The column is returned by the scan API,
rendered into the report and copied into comparison payloads.

Immutability
────────────
:func:`record_policy_snapshot` refuses to overwrite an existing snapshot. A
scan's configuration is settled once, at dispatch; a second write with a
different fingerprint means something has tried to rewrite history and is
logged as such. That is what makes "changing a policy does not alter Scan A's
recorded configuration" a property of the code rather than of everybody
remembering.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Mapping, Optional

from core.scan_policy.spec import EffectivePolicy, effective_from_config

log = logging.getLogger("ccure.scan_policy.snapshot")

__all__ = [
    "SNAPSHOT_KEY",
    "policy_summary_rows",
    "read_policy_snapshot",
    "record_policy_snapshot",
    "snapshot_payload",
]

#: The key inside ``scans.options``. Sibling of GAP-13's ``assessment_scope``
#: and of ``origin``.
SNAPSHOT_KEY = "scan_policy"


def snapshot_payload(policy: EffectivePolicy) -> Dict[str, Any]:
    """The stored form: identity, fingerprint and the full effective config."""
    return {
        "recorded": True,
        "policy_id": policy.policy_id,
        "policy_name": policy.policy_name,
        "policy_family_code": policy.policy_family_code,
        "version_number": policy.version_number,
        "scan_kind": policy.scan_kind,
        "source": policy.source,
        "fingerprint": policy.fingerprint(),
        "effective": policy.as_dict(),
    }


def record_policy_snapshot(
    scan: Any,
    policy: EffectivePolicy,
    *,
    overwrite: bool = False,
) -> bool:
    """
    Write *policy* into *scan*'s options. Returns True if it was written.

    Refuses to replace an existing snapshot unless *overwrite* is explicitly
    passed, which nothing in the product does — the parameter exists so a
    future repair path has a supported way in rather than editing the column by
    hand. A refused overwrite whose fingerprint differs from the stored one is
    logged at WARNING: it means something tried to change the recorded
    configuration of a scan that had already been configured, and that is worth
    seeing.

    Mutates ``scan.options`` in place and does **not** commit; the caller owns
    the transaction, so the snapshot lands in the same commit as the scan row
    it describes.
    """
    options = dict(getattr(scan, "options", None) or {})
    existing = options.get(SNAPSHOT_KEY)

    if existing and not overwrite:
        stored = str(existing.get("fingerprint") or "")
        incoming = policy.fingerprint()
        if stored and stored != incoming:
            log.warning(
                "Scan %s already carries policy snapshot %s; refusing to "
                "replace it with %s. A completed scan's configuration is the "
                "record of what produced it and is not rewritten.",
                getattr(scan, "id", "?"),
                stored[:16],
                incoming[:16],
            )
        return False

    options[SNAPSHOT_KEY] = snapshot_payload(policy)
    # Reassigned rather than mutated: SQLAlchemy does not see an in-place edit
    # of a JSON column, so the write would be silently dropped — the same trap
    # ``record_assessment_scope`` documents.
    scan.options = options
    return True


def read_policy_snapshot(scan: Any) -> Optional[EffectivePolicy]:
    """
    The configuration a scan was run under, or None if it predates this phase.

    None is a real answer and must not be turned into a default policy. A scan
    from before GAP-12 was assessed by whatever the request said, and inventing
    a policy record for it would put a claim in a report that nothing supports.
    """
    if scan is None:
        return None
    raw = (getattr(scan, "options", None) or {}).get(SNAPSHOT_KEY) or {}
    if not raw.get("recorded"):
        return None
    effective = raw.get("effective") or {}
    return effective_from_config(
        effective,
        policy_id=raw.get("policy_id"),
        policy_name=str(raw.get("policy_name") or ""),
        policy_family_code=str(raw.get("policy_family_code") or ""),
        version_number=int(raw.get("version_number") or 0),
        scan_kind=str(raw.get("scan_kind") or "any"),
        source=str(raw.get("source") or "request"),
    )


def policy_summary_rows(scan: Any) -> Dict[str, str]:
    """
    Report-ready rows for a scan's policy, or an honest absence.

    A scan with no snapshot says so in words. The alternative — omitting the
    section — leaves a reader unable to tell "no policy was used" from "this
    report does not show policies", and only the first is a fact about the
    scan.
    """
    policy = read_policy_snapshot(scan)
    if policy is None:
        return {
            "Policy": "None recorded (scan predates policy recording)",
        }
    return policy.describe()


def snapshots_agree(
    left: Optional[Mapping[str, Any]], right: Optional[Mapping[str, Any]]
) -> bool:
    """
    Whether two stored snapshots describe the same assessment configuration.

    Compared on the fingerprint alone, which excludes name and version by
    construction. Two scans run under v3 and v4 of a family that changed only
    its description are the same assessment and compare cleanly; two run under
    the same version number in different installations with different settings
    do not.

    An absent snapshot on either side is **not** agreement. "We do not know how
    that scan was configured" and "it was configured identically" are different
    facts, and only the second licenses a direct comparison.
    """
    if not left or not right:
        return False
    left_fp = str(left.get("fingerprint") or "")
    right_fp = str(right.get("fingerprint") or "")
    return bool(left_fp) and left_fp == right_fp
