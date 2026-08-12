"""
scans/cvss.py
─────────────────────────────────────────────────────────────────────────────
CVSS v2 / v3.0 / v3.1 / v4.0 vector parsing, base-score computation, and
integrity validation.

Why this module exists
──────────────────────
A vulnerability report is only defensible if every number in it can be
re-derived from published data. This module never invents a score. It only:

  1. Parses a vector string that came from NVD (or a vendor feed).
  2. Recomputes the base score from that vector using the official FIRST
     specification arithmetic.
  3. Compares the recomputed value against the score the feed supplied and
     reports a discrepancy when they disagree.

If a CVE has no published vector, this module returns ``None``. Callers are
expected to render "Not scored by NVD" rather than substitute a guess.

References
──────────
  CVSS v3.1 specification, FIRST.org  §7.1 (Base score equations)
  CVSS v2  specification, FIRST.org  §3.2.1
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

__all__ = [
    "SEVERITY_ORDER",
    "SEVERITY_RANK",
    "CvssData",
    "parse_cvss_vector",
    "severity_from_score",
    "canonical_severity",
    "display_severity",
    "cvss_version_of_vector",
    "CANONICAL_SEVERITIES",
]


# ─────────────────────────────────────────────────────────────────────────────
# Severity tiers (FIRST qualitative severity rating scale, CVSS v3.1 §5)
# ─────────────────────────────────────────────────────────────────────────────

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "None", "Unscored"]

SEVERITY_RANK: Dict[str, int] = {
    "Critical": 5,
    "High": 4,
    "Medium": 3,
    "Low": 2,
    "None": 1,
    "Unscored": 0,
}


#: The only severity spellings that may be written to the database.
#: Storage is lower-case; presentation is Title case via ``display_severity``.
#: Two spellings of one severity is not a cosmetic problem: ``GROUP BY severity``
#: returns "critical" and "Critical" as separate rows, and any dict keyed on the
#: result silently loses one of them. That defect hid 100 of 146 findings from
#: the security dashboard, so the convention is enforced by a CHECK constraint.
CANONICAL_SEVERITIES = ("critical", "high", "medium", "low", "none", "unscored")

_SEVERITY_ALIASES: Dict[str, str] = {
    "critical": "critical",
    "crit": "critical",
    "4": "critical",
    "high": "high",
    "3": "high",
    "medium": "medium",
    "med": "medium",
    "moderate": "medium",
    "2": "medium",
    "low": "low",
    "1": "low",
    "none": "none",
    "info": "none",
    "informational": "none",
    "0": "none",
    "unscored": "unscored",
    "": "unscored",
}


def canonical_severity(value) -> str:
    """
    Reduce any severity spelling to the one form that may be stored.

    Unrecognised input becomes "unscored" rather than a guess — the same rule
    ``normalize_severity`` applies, kept identical so a value cannot mean one
    thing on the way in and another on the way out.
    """
    return _SEVERITY_ALIASES.get(str(value or "").strip().lower(), "unscored")


def display_severity(value) -> str:
    """
    Title-case a stored severity for display.

    The frontend keys its badge classes on "Critical"/"High"/... , so a raw
    lower-case value from the catalogue renders as unstyled text. Every API
    response therefore passes severities through here rather than emitting the
    stored form.
    """
    canon = canonical_severity(value)
    return "Info" if canon == "none" else canon.title()


def cvss_version_of_vector(vector: Optional[str]) -> Optional[str]:
    """
    Recover the CVSS version a vector string was written in.

    v3 and v4 vectors are self-identifying ("CVSS:3.1/...", "CVSS:4.0/...").
    A v2 vector carries no prefix and is recognised by ``Au:``, a metric that
    exists only in v2. Getting this wrong is how 751 v2 scores came to sit in
    ``cvss_v3_score`` and be reported as v3 figures.
    """
    text = str(vector or "").strip()
    if not text:
        return None
    if text.upper().startswith("CVSS:4"):
        return "4.0"
    if text.upper().startswith("CVSS:3.1"):
        return "3.1"
    if text.upper().startswith("CVSS:3.0"):
        return "3.0"
    if text.upper().startswith("CVSS:2"):
        return "2.0"
    if "Au:" in text or "AU:" in text.upper():
        return "2.0"
    return None


def severity_from_score(score: Optional[float]) -> str:
    """
    Map a CVSS base score to its qualitative rating.

    Returns "Unscored" for ``None`` — deliberately distinct from "None"
    (which means a real published score of 0.0).
    """
    if score is None:
        return "Unscored"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return "None"


# ─────────────────────────────────────────────────────────────────────────────
# Metric weight tables
# ─────────────────────────────────────────────────────────────────────────────

_V3_WEIGHTS: Dict[str, Dict[str, float]] = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    # Privileges Required is scope-dependent; the Changed-scope values are
    # applied in _v3_base_score().
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
    "PR_CHANGED": {"N": 0.85, "L": 0.68, "H": 0.5},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}

_V2_WEIGHTS: Dict[str, Dict[str, float]] = {
    "AV": {"L": 0.395, "A": 0.646, "N": 1.0},
    "AC": {"H": 0.35, "M": 0.61, "L": 0.71},
    "Au": {"M": 0.45, "S": 0.56, "N": 0.704},
    "C": {"N": 0.0, "P": 0.275, "C": 0.660},
    "I": {"N": 0.0, "P": 0.275, "C": 0.660},
    "A": {"N": 0.0, "P": 0.275, "C": 0.660},
}

# Human-readable expansions used in the report so a reader does not need to
# memorise the abbreviations.
_V3_LABELS: Dict[str, Dict[str, str]] = {
    "AV": {"N": "Network", "A": "Adjacent Network", "L": "Local", "P": "Physical"},
    "AC": {"L": "Low", "H": "High"},
    "PR": {"N": "None", "L": "Low", "H": "High"},
    "UI": {"N": "None", "R": "Required"},
    "S": {"U": "Unchanged", "C": "Changed"},
    "C": {"H": "High", "L": "Low", "N": "None"},
    "I": {"H": "High", "L": "Low", "N": "None"},
    "A": {"H": "High", "L": "Low", "N": "None"},
}

_V2_LABELS: Dict[str, Dict[str, str]] = {
    "AV": {"L": "Local", "A": "Adjacent Network", "N": "Network"},
    "AC": {"H": "High", "M": "Medium", "L": "Low"},
    "Au": {"M": "Multiple", "S": "Single", "N": "None"},
    "C": {"N": "None", "P": "Partial", "C": "Complete"},
    "I": {"N": "None", "P": "Partial", "C": "Complete"},
    "A": {"N": "None", "P": "Partial", "C": "Complete"},
}

# CVSS v4.0 replaces the single C/I/A triad with separate Vulnerable-system and
# Subsequent-system triads, drops Scope entirely, and adds Attack Requirements.
# Only base metrics are listed here; threat (E), environmental (CR/IR/AR/M*)
# and supplemental (S/AU/R/V/RE/U) metrics are intentionally absent so they are
# skipped during rendering rather than mislabelled against v3 names.
_V4_LABELS: Dict[str, Dict[str, str]] = {
    "AV": {"N": "Network", "A": "Adjacent Network", "L": "Local", "P": "Physical"},
    "AC": {"L": "Low", "H": "High"},
    "AT": {"N": "None", "P": "Present"},
    "PR": {"N": "None", "L": "Low", "H": "High"},
    "UI": {"N": "None", "P": "Passive", "A": "Active"},
    "VC": {"H": "High", "L": "Low", "N": "None"},
    "VI": {"H": "High", "L": "Low", "N": "None"},
    "VA": {"H": "High", "L": "Low", "N": "None"},
    "SC": {"H": "High", "L": "Low", "N": "None"},
    "SI": {"H": "High", "L": "Low", "N": "None"},
    "SA": {"H": "High", "L": "Low", "N": "None"},
}

# Display names per metric key. v4.0 reuses AV/AC/PR/UI but adds its own keys;
# the two maps are kept separate because "S" means Scope in v3 and Safety in
# v4, and conflating them produced mislabelled output.
_V3_METRIC_NAMES: Dict[str, str] = {
    "AV": "Attack Vector",
    "AC": "Attack Complexity",
    "PR": "Privileges Required",
    "Au": "Authentication",
    "UI": "User Interaction",
    "S": "Scope",
    "C": "Confidentiality",
    "I": "Integrity",
    "A": "Availability",
}

_V4_METRIC_NAMES: Dict[str, str] = {
    "AV": "Attack Vector",
    "AC": "Attack Complexity",
    "AT": "Attack Requirements",
    "PR": "Privileges Required",
    "UI": "User Interaction",
    "VC": "Confidentiality (vulnerable system)",
    "VI": "Integrity (vulnerable system)",
    "VA": "Availability (vulnerable system)",
    "SC": "Confidentiality (subsequent system)",
    "SI": "Integrity (subsequent system)",
    "SA": "Availability (subsequent system)",
}


# ─────────────────────────────────────────────────────────────────────────────
# Parsed representation
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class CvssData:
    """
    A parsed CVSS vector plus the score recomputed from it.

    ``feed_score`` is whatever the upstream data source claimed. ``computed_score``
    is what the vector actually evaluates to. When these disagree by more than
    0.1 the discrepancy is recorded in ``integrity_warnings`` and the report
    renders the computed value, because the vector is the primary artefact.
    """

    version: str  # "2.0" | "3.0" | "3.1" | "4.0"
    vector_string: str
    metrics: Dict[str, str] = field(default_factory=dict)
    computed_score: Optional[float] = None
    feed_score: Optional[float] = None
    integrity_warnings: List[str] = field(default_factory=list)

    @property
    def score(self) -> Optional[float]:
        """The score the report should display."""
        if self.computed_score is not None:
            return self.computed_score
        return self.feed_score

    @property
    def severity(self) -> str:
        return severity_from_score(self.score)

    @property
    def attack_vector(self) -> Optional[str]:
        return self.metrics.get("AV")

    @property
    def is_remotely_exploitable(self) -> bool:
        return self.metrics.get("AV") == "N"

    @property
    def is_local_only(self) -> bool:
        """True when exploitation requires local or physical access."""
        return self.metrics.get("AV") in ("L", "P")

    @property
    def is_v4(self) -> bool:
        return self.version.startswith("4")

    @property
    def requires_user_interaction(self) -> bool:
        # v3 encodes this as UI:R; v4 splits it into Passive and Active.
        if self.is_v4:
            return self.metrics.get("UI") in ("P", "A")
        return self.metrics.get("UI") == "R"

    @property
    def requires_privileges(self) -> bool:
        return self.metrics.get("PR") in ("L", "H")

    @property
    def display_vector(self) -> str:
        """
        The vector with undefined (":X") metrics removed.

        A published v4.0 vector carries every threat, environmental and
        supplemental metric set to X. Printing them adds ~30 characters of
        noise that says nothing, so they are dropped for display while
        ``vector_string`` keeps the verbatim published value.
        """
        raw = self.vector_string
        if ":X" not in raw:
            return raw
        head, _, body = (
            raw.partition("/") if raw.upper().startswith("CVSS:") else ("", "", raw)
        )
        kept = [tok for tok in body.split("/") if not tok.upper().endswith(":X")]
        if not kept:
            return raw
        return f"{head}/{'/'.join(kept)}" if head else "/".join(kept)

    def humanised(self) -> List[tuple]:
        """
        Return [(metric label, value label), ...] for display.

        Renders the vector in words so the reader can sanity-check the score
        without consulting the specification. Only base metrics are returned;
        undefined (X) metrics are omitted rather than printed as "X".
        """
        if self.version == "2.0":
            labels, names = _V2_LABELS, _V3_METRIC_NAMES
        elif self.is_v4:
            labels, names = _V4_LABELS, _V4_METRIC_NAMES
        else:
            labels, names = _V3_LABELS, _V3_METRIC_NAMES

        out = []
        for key, value in self.metrics.items():
            label_map = labels.get(key)
            if not label_map or value == "X":
                continue
            out.append((names.get(key, key), label_map.get(value, value)))
        return out


# ─────────────────────────────────────────────────────────────────────────────
# Score computation
# ─────────────────────────────────────────────────────────────────────────────


def _round_up_1(value: float) -> float:
    """
    CVSS v3.1 Appendix A "Roundup": smallest 1-decimal number >= value.

    Implemented on scaled integers to avoid the floating-point edge cases the
    specification explicitly calls out (e.g. 0.1 + 0.2 style drift).
    """
    integer_input = round(value * 100000)
    if integer_input % 10000 == 0:
        return integer_input / 100000.0
    return (math.floor(integer_input / 10000) + 1) / 10.0


def _v3_base_score(m: Dict[str, str]) -> Optional[float]:
    """Compute a CVSS v3.x base score per FIRST specification §7.1."""
    required = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
    if not all(k in m for k in required):
        return None

    try:
        scope_changed = m["S"] == "C"

        iss = (
            (1 - _V3_WEIGHTS["C"][m["C"]])
            * (1 - _V3_WEIGHTS["I"][m["I"]])
            * (1 - _V3_WEIGHTS["A"][m["A"]])
        )
        impact_sub = 1 - iss

        if scope_changed:
            impact = 7.52 * (impact_sub - 0.029) - 3.25 * (impact_sub - 0.02) ** 15
        else:
            impact = 6.42 * impact_sub

        if impact <= 0:
            return 0.0

        pr_table = _V3_WEIGHTS["PR_CHANGED"] if scope_changed else _V3_WEIGHTS["PR"]
        exploitability = (
            8.22
            * _V3_WEIGHTS["AV"][m["AV"]]
            * _V3_WEIGHTS["AC"][m["AC"]]
            * pr_table[m["PR"]]
            * _V3_WEIGHTS["UI"][m["UI"]]
        )

        if scope_changed:
            return _round_up_1(min(1.08 * (impact + exploitability), 10.0))
        return _round_up_1(min(impact + exploitability, 10.0))

    except (KeyError, ValueError, OverflowError):
        return None


def _v2_base_score(m: Dict[str, str]) -> Optional[float]:
    """Compute a CVSS v2 base score per FIRST specification §3.2.1."""
    required = ("AV", "AC", "Au", "C", "I", "A")
    if not all(k in m for k in required):
        return None

    try:
        impact = 10.41 * (
            1
            - (1 - _V2_WEIGHTS["C"][m["C"]])
            * (1 - _V2_WEIGHTS["I"][m["I"]])
            * (1 - _V2_WEIGHTS["A"][m["A"]])
        )
        exploitability = (
            20.0
            * _V2_WEIGHTS["AV"][m["AV"]]
            * _V2_WEIGHTS["AC"][m["AC"]]
            * _V2_WEIGHTS["Au"][m["Au"]]
        )
        f_impact = 0.0 if impact == 0 else 1.176
        score = ((0.6 * impact) + (0.4 * exploitability) - 1.5) * f_impact
        return round(score, 1)
    except (KeyError, ValueError, OverflowError):
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Public parser
# ─────────────────────────────────────────────────────────────────────────────

# Metric keys are 1-3 characters. The upper bound matters: CVSS v4.0 defines
# three-letter modified-environmental keys (MAV, MAC, MPR, MUI, MVC, ...). With
# a two-character bound the regex cannot match "MAV" at the M, so it re-anchors
# one character later and reads "MAV:X" as "AV:X" — silently overwriting the
# real base metric with the undefined placeholder. Anchoring each token to a
# "/" or string start prevents that class of mis-parse regardless of key length.
_VECTOR_TOKEN = re.compile(r"(?:^|/)([A-Za-z]{1,3}):([A-Za-z])(?=/|$)")


def parse_cvss_vector(
    vector_string: Optional[str],
    feed_score: Optional[float] = None,
    declared_version: Optional[str] = None,
) -> Optional[CvssData]:
    """
    Parse a CVSS vector string and recompute its base score.

    Returns ``None`` when there is no usable vector — callers must then render
    the finding as unscored rather than fabricate a value.

    Parameters
    ----------
    vector_string
        e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" or a bare v2
        vector "AV:N/AC:L/Au:N/C:P/I:P/A:P".
    feed_score
        The base score the upstream feed reported, used only for cross-checking.
    declared_version
        Optional override when the version is known but absent from the string.
    """
    if not vector_string or not str(vector_string).strip():
        return None

    raw = str(vector_string).strip()

    # Determine the version. v3.x and v4.0 vectors carry an explicit prefix;
    # a bare vector containing the "Au" metric is v2.
    version = declared_version
    prefix = re.match(r"^CVSS:(\d\.\d)/", raw, re.IGNORECASE)
    if prefix:
        version = prefix.group(1)
    elif version is None:
        version = "2.0" if "Au:" in raw else "3.1"

    # Some feeds wrap bare v2 vectors in parentheses. The token regex anchors on
    # "/" or string start, so those wrappers have to come off first.
    body = raw[prefix.end() :] if prefix else raw
    body = body.strip().strip("()").strip()
    metrics = {key: value.upper() for key, value in _VECTOR_TOKEN.findall(body)}

    # Normalise the v2 authentication key, whose canonical spelling is mixed
    # case and therefore survives the regex as "AU". Gated to v2: CVSS v4.0
    # defines its own "AU" metric (Automatable), which must not be rewritten
    # into the v2 Authentication key.
    if version.startswith("2") and "AU" in metrics:
        metrics["Au"] = metrics.pop("AU")

    if not metrics:
        return None

    warnings: List[str] = []

    if version.startswith("2"):
        computed = _v2_base_score(metrics)
    elif version.startswith("4"):
        # CVSS v4.0 uses a lookup-table scoring model rather than a closed-form
        # equation. Recomputation is not attempted; the feed score is used and
        # labelled as unverified so the report never implies it was checked.
        computed = None
        if feed_score is not None:
            warnings.append(
                "CVSS v4.0 base score is reported as published by the feed; "
                "this tool does not independently recompute v4.0 scores."
            )
    else:
        computed = _v3_base_score(metrics)

    data = CvssData(
        version=version,
        vector_string=raw,
        metrics=metrics,
        computed_score=computed,
        feed_score=round(float(feed_score), 1) if feed_score is not None else None,
    )

    # ── Integrity checks ─────────────────────────────────────────────────────

    if computed is None and not version.startswith("4"):
        warnings.append(
            f"CVSS vector is incomplete or malformed and could not be "
            f"recomputed: '{raw}'."
        )

    if computed is not None and data.feed_score is not None:
        # Both values are rounded to one decimal, so any genuine disagreement is
        # at least 0.1. The 0.05 threshold catches that while tolerating binary
        # floating-point representation error (10.0 - 9.9 == 0.0999...).
        if abs(computed - data.feed_score) >= 0.05:
            warnings.append(
                f"Score mismatch: the published vector evaluates to {computed}, "
                f"but the source feed reported {data.feed_score}. The computed "
                f"value is shown."
            )

    # The plausibility checks below run against the score the report will
    # actually display, so v4.0 findings (whose score comes from the feed) are
    # sanity-checked too rather than silently skipped.
    shown = data.score

    if shown is not None and shown >= 9.0 and data.is_local_only:
        warnings.append(
            f"Scored Critical ({shown}) but the attack vector is "
            f"{_V3_LABELS['AV'].get(metrics.get('AV', ''), metrics.get('AV', '?'))}, "
            f"so exploitation requires local or physical access."
        )

    if shown is not None and shown >= 9.0 and metrics.get("PR") == "H":
        warnings.append(
            f"Scored Critical ({shown}) but exploitation requires high "
            f"privileges on the target beforehand."
        )

    data.integrity_warnings = warnings
    return data
