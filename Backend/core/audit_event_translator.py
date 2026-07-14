"""
core/audit_event_translator.py
─────────────────────────────────────────────────────────────────────────────
Translates raw AssetChangeLog records into enriched, human-readable
business events for the SaaS-grade Asset Activity Timeline.

Design:
  - Pure functions: no database access, operates on dicts.
  - Called at the API response layer (routers/assets.py).
  - Preserves all raw data — translation is additive, never destructive.
  - Scan-based grouping collapses 10-20 per-field events into summary cards.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Optional


# ─────────────────────────────────────────────────────────────────────────────
# Field → Event Mapping
# ─────────────────────────────────────────────────────────────────────────────
# Each entry: field_name → (event_title, category, icon, base_severity)

FIELD_EVENT_MAP: dict[str, tuple[str, str, str, str]] = {
    # ── Asset Identification ──────────────────────────────────────────────────
    "hostname": ("Hostname Updated", "asset_identification", "🖥️", "LOW"),
    "fqdn": ("FQDN Resolved", "asset_identification", "🌐", "LOW"),
    "dns_name": ("DNS Name Resolved", "asset_identification", "🔗", "LOW"),
    "netbios_name": ("NetBIOS Name Discovered", "asset_identification", "📛", "LOW"),
    "mac_address": (
        "Network Interface Identified",
        "asset_identification",
        "📡",
        "LOW",
    ),
    "vendor": ("Vendor Identified", "asset_identification", "🏷️", "LOW"),
    "manufacturer": ("Manufacturer Identified", "asset_identification", "🏭", "MEDIUM"),
    "device_category": (
        "Device Classification Updated",
        "asset_identification",
        "📂",
        "HIGH",
    ),
    "ip_address": ("IP Address Changed", "network", "🔀", "MEDIUM"),
    # ── Operating System ──────────────────────────────────────────────────────
    "os_name": ("Operating System Identified", "operating_system", "💻", "MEDIUM"),
    "os_version": ("OS Version Updated", "operating_system", "🔄", "MEDIUM"),
    "os_family": ("OS Family Classified", "operating_system", "🗂️", "MEDIUM"),
    "os_confidence": (
        "OS Detection Confidence Updated",
        "operating_system",
        "📊",
        "INFO",
    ),
    # ── Network ───────────────────────────────────────────────────────────────
    "subnet": ("Network Classification Updated", "network", "🌍", "LOW"),
    "response_time_ms": ("Response Time Updated", "network", "⏱️", "INFO"),
    "vlan_id": ("VLAN Assignment Updated", "network", "🔌", "LOW"),
    # ── Lifecycle ─────────────────────────────────────────────────────────────
    "discovery_method": ("Discovery Method Updated", "lifecycle", "🔍", "INFO"),
}

# Special change_type events (not field_update)
CHANGE_TYPE_EVENT_MAP: dict[str, tuple[str, str, str, str]] = {
    "lifecycle": ("Asset Lifecycle Event", "lifecycle", "♻️", "LOW"),
    "vulnerability_fixed": ("Vulnerability Remediated", "security", "✅", "MEDIUM"),
    "vulnerability_reopened": ("Vulnerability Reopened", "security", "🔓", "CRITICAL"),
    "port_opened": ("Open Port Detected", "security", "🚪", "MEDIUM"),
    "port_closed": ("Port Closed", "security", "🔒", "LOW"),
}


# ─────────────────────────────────────────────────────────────────────────────
# Category Metadata
# ─────────────────────────────────────────────────────────────────────────────

CATEGORY_META: dict[str, dict[str, str]] = {
    "asset_identification": {
        "label": "Asset Identification",
        "icon": "🖥️",
        "color": "#3b82f6",
    },
    "operating_system": {"label": "Operating System", "icon": "💻", "color": "#8b5cf6"},
    "network": {"label": "Network", "icon": "🌐", "color": "#06b6d4"},
    "security": {"label": "Security", "icon": "🛡️", "color": "#ef4444"},
    "lifecycle": {"label": "Lifecycle", "icon": "♻️", "color": "#22c55e"},
}


# ─────────────────────────────────────────────────────────────────────────────
# Severity Ordering (for comparison and dynamic escalation)
# ─────────────────────────────────────────────────────────────────────────────

SEVERITY_RANK: dict[str, int] = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

SEVERITY_COLORS: dict[str, str] = {
    "INFO": "#6366f1",
    "LOW": "#22c55e",
    "MEDIUM": "#eab308",
    "HIGH": "#f97316",
    "CRITICAL": "#ef4444",
}


# ─────────────────────────────────────────────────────────────────────────────
# Source Classification
# ─────────────────────────────────────────────────────────────────────────────


def _classify_event_source(change_type: str) -> str:
    """Determine the event source from the change type."""
    if change_type in ("vulnerability_fixed", "vulnerability_reopened"):
        return "VULNERABILITY_ENGINE"
    return "SCAN_ENGINE"


# ─────────────────────────────────────────────────────────────────────────────
# Scan Type Labels
# ─────────────────────────────────────────────────────────────────────────────

SCAN_TYPE_LABELS: dict[str, tuple[str, str]] = {
    "credentialed": ("Credentialed Scan Completed", "🔑"),
    "discovery": ("Host Discovery Completed", "📡"),
    "host_discovery": ("Host Discovery Completed", "📡"),
    "asset_discovery": ("Asset Discovery Completed", "🔎"),
    "fingerprinting": ("Service Fingerprinting Completed", "🔬"),
    "vulnerability_audit": ("Vulnerability Audit Completed", "🛡️"),
    "scanner": ("Network Scan Completed", "📡"),
}


def _scan_type_from_id(scan_id: Optional[str]) -> str:
    """Infer scan type from scan_id prefix convention."""
    if not scan_id:
        return "unknown"
    sid = scan_id.lower()
    if "cdac" in sid or "cred" in sid:
        return "credentialed"
    # Fallback — the API can override with actual scan_type from DB
    return "scan"


# ─────────────────────────────────────────────────────────────────────────────
# Value Formatting
# ─────────────────────────────────────────────────────────────────────────────


def _extract_display_value(raw_value: Any) -> Optional[str]:
    """
    Extract a clean display string from the JSONB value.

    The asset_syncer stores values as {"val": <actual_value>}.
    The router's _display_json_value may have already unwrapped simple types
    or serialized them to JSON strings. Handle both cases.
    """
    if raw_value is None:
        return None

    # If it's already a simple scalar from _display_json_value
    if isinstance(raw_value, (int, float, bool)):
        return str(raw_value)
    if isinstance(raw_value, str):
        # Check if it's a JSON string like '{"val": "HP"}'
        if raw_value.startswith("{"):
            try:
                parsed = json.loads(raw_value)
                if isinstance(parsed, dict) and "val" in parsed:
                    inner = parsed["val"]
                    return str(inner) if inner is not None else None
                return json.dumps(parsed)
            except (json.JSONDecodeError, TypeError):
                pass
        return raw_value if raw_value not in ("null", "None", "") else None

    # Dict case: {"val": X}
    if isinstance(raw_value, dict):
        if "val" in raw_value:
            inner = raw_value["val"]
            return str(inner) if inner is not None else None
        return json.dumps(raw_value, ensure_ascii=False)

    return str(raw_value)


def _format_field_value(field_name: str, display_value: Optional[str]) -> str:
    """Apply field-specific formatting to display values."""
    if display_value is None:
        return "Unknown"

    if field_name == "mac_address":
        return display_value.upper()

    if field_name == "response_time_ms":
        try:
            ms = int(float(display_value))
            return f"{ms} ms"
        except (ValueError, TypeError):
            return display_value

    if field_name == "os_confidence":
        try:
            pct = int(float(display_value))
            return f"{pct}%"
        except (ValueError, TypeError):
            return display_value

    if field_name == "risk_score":
        try:
            score = int(float(display_value))
            return str(score)
        except (ValueError, TypeError):
            return display_value

    return display_value


# ─────────────────────────────────────────────────────────────────────────────
# Dynamic Severity Escalation
# ─────────────────────────────────────────────────────────────────────────────


def _compute_dynamic_severity(
    field_name: str,
    base_severity: str,
    old_display: Optional[str],
    new_display: Optional[str],
) -> str:
    """
    Escalate severity based on the nature of the change.

    Examples:
      - risk_score increase from 10 to 90 → CRITICAL
      - device_category change (e.g., Endpoint → Server) → HIGH
      - First discovery (null → value) stays at base severity
    """
    if field_name == "risk_score" and old_display and new_display:
        try:
            old_score = int(float(old_display))
            new_score = int(float(new_display))
            delta = new_score - old_score
            if delta >= 40:
                return "CRITICAL"
            if delta >= 20:
                return "HIGH"
            if delta < 0:
                return "INFO"  # Improvement
        except (ValueError, TypeError):
            pass

    if field_name == "device_category" and old_display and old_display != "Unknown":
        return "HIGH"

    return base_severity


# ─────────────────────────────────────────────────────────────────────────────
# Lifecycle Event Descriptions
# ─────────────────────────────────────────────────────────────────────────────

LIFECYCLE_LABELS: dict[str, str] = {
    "discovered": "Asset first discovered on the network",
    "bootstrapped_via_credentialed": "Asset record created via credentialed scan",
}


# ─────────────────────────────────────────────────────────────────────────────
# Core Translation
# ─────────────────────────────────────────────────────────────────────────────


def translate_changelog_entry(entry: dict) -> dict:
    """
    Translate a single raw changelog entry into an enriched event.

    Input: dict from the existing API response (id, change_type, field_name,
           old_value, new_value, scan_id, detected_at)

    Output: enriched dict with event_title, category, severity, formatted
            values, etc.
    """
    change_type = entry.get("change_type", "field_update")
    field_name = entry.get("field_name")

    # 1. Resolve event metadata
    if change_type == "field_update" and field_name in FIELD_EVENT_MAP:
        event_title, category, icon, base_severity = FIELD_EVENT_MAP[field_name]
    elif change_type in CHANGE_TYPE_EVENT_MAP:
        event_title, category, icon, base_severity = CHANGE_TYPE_EVENT_MAP[change_type]
    else:
        # Fallback for unknown fields
        clean_field = (field_name or change_type or "unknown").replace("_", " ").title()
        event_title = f"{clean_field} Updated"
        category = "lifecycle"
        icon = "📌"
        base_severity = "INFO"

    # 2. Extract and format display values
    old_raw = entry.get("old_value")
    new_raw = entry.get("new_value")
    old_display = _extract_display_value(old_raw)
    new_display = _extract_display_value(new_raw)

    old_formatted = _format_field_value(field_name or "", old_display)
    new_formatted = _format_field_value(field_name or "", new_display)

    # 3. Determine if this is a new discovery
    is_new_discovery = old_display is None and new_display is not None

    # 4. Compute dynamic severity
    severity = _compute_dynamic_severity(
        field_name or "", base_severity, old_display, new_display
    )

    # 5. Build event description
    if change_type == "lifecycle":
        lifecycle_val = new_display or old_display or "unknown"
        event_description = LIFECYCLE_LABELS.get(
            lifecycle_val, f"Asset lifecycle event: {lifecycle_val}"
        )
    elif change_type in ("vulnerability_fixed", "vulnerability_reopened"):
        cve_id = new_display or old_display or "Unknown CVE"
        if change_type == "vulnerability_fixed":
            event_description = (
                f"{cve_id} has been remediated and is no longer detected"
            )
        else:
            event_description = (
                f"{cve_id} has been re-detected after previous remediation"
            )
    elif is_new_discovery:
        event_description = f"{(field_name or '').replace('_', ' ').title()} detected as {new_formatted}"
    else:
        event_description = f"Changed from {old_formatted} to {new_formatted}"

    # 6. Classify event source
    event_source = _classify_event_source(change_type)

    return {
        # Original fields preserved
        "id": entry.get("id"),
        "change_type": change_type,
        "field_name": field_name,
        "scan_id": entry.get("scan_id"),
        "detected_at": entry.get("detected_at"),
        # Enriched fields
        "event_title": event_title,
        "event_description": event_description,
        "category": category,
        "severity": severity,
        "severity_color": SEVERITY_COLORS.get(severity, "#64748b"),
        "icon": icon,
        # Formatted values
        "old_value": old_raw,
        "new_value": new_raw,
        "old_value_display": old_formatted,
        "new_value_display": new_formatted,
        "is_new_discovery": is_new_discovery,
        "event_source": event_source,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Scan-Based Grouping
# ─────────────────────────────────────────────────────────────────────────────

# Maximum time window (seconds) for events to be grouped under the same scan
GROUP_WINDOW_SECONDS = 60


def _group_key(entry: dict) -> str:
    """Generate a grouping key from scan_id + timestamp window."""
    scan_id = entry.get("scan_id") or "no_scan"
    detected_at = entry.get("detected_at")

    if detected_at:
        # Parse ISO timestamp and round to GROUP_WINDOW_SECONDS
        try:
            if isinstance(detected_at, str):
                # Handle timezone-aware ISO strings
                dt = datetime.fromisoformat(detected_at.replace("Z", "+00:00"))
            elif isinstance(detected_at, datetime):
                dt = detected_at
            else:
                dt = datetime.now(timezone.utc)
            epoch = int(dt.timestamp())
            window = epoch - (epoch % GROUP_WINDOW_SECONDS)
        except (ValueError, TypeError):
            window = 0
    else:
        window = 0

    return f"{scan_id}_{window}"


def group_changelog_by_scan(
    translated_entries: list[dict],
    scan_type_map: Optional[dict[str, str]] = None,
) -> list[dict]:
    """
    Group translated changelog entries by scan_id + timestamp window.

    Returns a list of group objects, each containing:
      - group_id, scan_id, scan_type, detected_at, event_count
      - summary_title, summary_subtitle
      - events: list of individual translated events
      - highest_severity: the max severity in the group

    scan_type_map: optional {scan_id: scan_type} from DB for accurate labels.
    """
    if not translated_entries:
        return []

    scan_type_map = scan_type_map or {}

    # 1. Bucket entries by group key
    buckets: dict[str, list[dict]] = {}
    for entry in translated_entries:
        key = _group_key(entry)
        buckets.setdefault(key, []).append(entry)

    # 2. Build group objects
    groups = []
    for key, events in buckets.items():
        scan_id = events[0].get("scan_id")
        detected_at = events[0].get("detected_at")

        # Resolve scan type
        scan_type = scan_type_map.get(scan_id, _scan_type_from_id(scan_id))

        # Summary title from scan type
        label_info = SCAN_TYPE_LABELS.get(scan_type)
        if label_info:
            summary_title, group_icon = label_info
        else:
            summary_title = "Scan Completed"
            group_icon = "📡"

        # Count discoveries vs changes
        discoveries = sum(1 for e in events if e.get("is_new_discovery"))
        changes = len(events) - discoveries

        # Build subtitle
        parts = []
        if discoveries:
            parts.append(
                f"{discoveries} new attribute{'s' if discoveries != 1 else ''} discovered"
            )
        if changes:
            parts.append(f"{changes} attribute{'s' if changes != 1 else ''} updated")
        summary_subtitle = (
            " · ".join(parts)
            if parts
            else f"{len(events)} event{'s' if len(events) != 1 else ''}"
        )

        # Highest severity in group
        max_sev = max(
            (SEVERITY_RANK.get(e.get("severity", "INFO"), 0) for e in events),
            default=0,
        )
        highest_severity = next(
            (s for s, r in SEVERITY_RANK.items() if r == max_sev), "INFO"
        )

        # Category breakdown
        categories_in_group = list(
            {e.get("category") for e in events if e.get("category")}
        )

        # Stable group ID
        group_id = hashlib.md5(key.encode()).hexdigest()[:12]

        groups.append(
            {
                "group_id": f"grp_{group_id}",
                "scan_id": scan_id,
                "scan_type": scan_type,
                "group_icon": group_icon,
                "detected_at": detected_at,
                "event_count": len(events),
                "discovery_count": discoveries,
                "change_count": changes,
                "summary_title": summary_title,
                "summary_subtitle": summary_subtitle,
                "highest_severity": highest_severity,
                "highest_severity_color": SEVERITY_COLORS.get(
                    highest_severity, "#64748b"
                ),
                "categories": categories_in_group,
                "events": events,
            }
        )

    # 3. Sort groups by detected_at descending (newest first)
    groups.sort(key=lambda g: g.get("detected_at") or "", reverse=True)

    return groups


# ─────────────────────────────────────────────────────────────────────────────
# Main Orchestrator
# ─────────────────────────────────────────────────────────────────────────────


def translate_and_group_changelog(
    raw_entries: list[dict],
    scan_type_map: Optional[dict[str, str]] = None,
) -> dict:
    """
    Full pipeline: translate raw changelog entries → group by scan → compute stats.

    Returns:
        {
            "timeline":       [grouped event objects],
            "raw_changelog":  [original raw entries],
            "categories":     [unique categories present],
            "stats": {
                "total_events": int,
                "total_groups": int,
                "by_category": {category: count},
                "by_severity": {severity: count},
            },
        }
    """
    # 1. Translate each entry
    translated = [translate_changelog_entry(e) for e in raw_entries]

    # 2. Group by scan
    timeline = group_changelog_by_scan(translated, scan_type_map)

    # 3. Compute stats
    categories_set: set[str] = set()
    by_category: dict[str, int] = {}
    by_severity: dict[str, int] = {
        "INFO": 0,
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0,
    }

    for event in translated:
        cat = event.get("category", "lifecycle")
        sev = event.get("severity", "INFO")
        categories_set.add(cat)
        by_category[cat] = by_category.get(cat, 0) + 1
        by_severity[sev] = by_severity.get(sev, 0) + 1

    # Sort categories by the order defined in CATEGORY_META
    category_order = list(CATEGORY_META.keys())
    sorted_categories = sorted(
        categories_set,
        key=lambda c: category_order.index(c) if c in category_order else 99,
    )

    return {
        "timeline": timeline,
        "raw_changelog": raw_entries,
        "categories": sorted_categories,
        "category_meta": CATEGORY_META,
        "stats": {
            "total_events": len(translated),
            "total_groups": len(timeline),
            "by_category": by_category,
            "by_severity": by_severity,
        },
    }
