"""Additive execution evidence for legacy network probes, without changing findings."""

STATUSES = frozenset(
    {
        "completed_with_findings",
        "completed_with_no_findings",
        "skipped",
        "unsupported",
        "failed",
        "timed_out",
    }
)
COMPLETE = frozenset({"completed_with_findings", "completed_with_no_findings"})


def result_with_outcome(
    result=None, *, status=None, detail="", complete=True, endpoints=None
):
    result = dict(result or {})
    status = status or (
        "completed_with_findings"
        if result.get("cves")
        else "completed_with_no_findings"
    )
    if status not in STATUSES:
        raise ValueError("invalid network plugin outcome")
    result["_plugin_outcome"] = {
        "status": status,
        "detail": detail,
        "coverage_complete": bool(complete and status in COMPLETE),
        "endpoints": list(endpoints or []),
    }
    return result


def outcome_for_result(plugin, result):
    supplied = result.get("_plugin_outcome")
    if not isinstance(supplied, dict) or supplied.get("status") not in STATUSES:
        # Legacy absence/metadata cannot prove every internal check completed.
        supplied = {
            "status": (
                "completed_with_findings" if result.get("cves") else "unsupported"
            ),
            "coverage_complete": False,
            "detail": "Probe did not provide complete execution evidence; no clean assessment is asserted.",
        }
    return {
        **supplied,
        "plugin": plugin,
        "findings_count": len(result.get("cves") or []),
    }


def coverage_summary(hosts):
    outcomes = [o for h in hosts for o in h.get("plugin_outcomes", [])]
    return {
        "recorded": bool(outcomes),
        "complete": bool(outcomes)
        and all(o.get("coverage_complete") for o in outcomes),
        "counts": {
            s: sum(o.get("status") == s for o in outcomes) for s in sorted(STATUSES)
        },
        "incomplete": [
            {"host": h.get("ip_address") or h.get("ip"), **o}
            for h in hosts
            for o in h.get("plugin_outcomes", [])
            if not o.get("coverage_complete")
        ],
    }
