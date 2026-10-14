"""Endpoint observations inside existing JSON/text evidence contracts."""

FIELDS = (
    "port",
    "protocol",
    "target",
    "matched_at",
    "service_id",
    "service_name",
    "detected_version",
    "detection_method",
    "execution_plugin",
    "evidence_captured",
    "template_id",
    "corroborating_templates",
    "evidence",
    "proof",
    "plugin_output",
)


def observations_for(finding):
    if (
        finding.get("detection_method") == "os_reported"
        or finding.get("finding_origin") == "credentialed"
    ):
        return []
    existing = finding.get("endpoint_observations")
    if isinstance(existing, list) and existing:
        return [dict(o) for o in existing if isinstance(o, dict)]
    if (
        finding.get("port") is None
        and not finding.get("matched_at")
        and not finding.get("target")
    ):
        return []
    return [{key: finding[key] for key in FIELDS if finding.get(key) is not None}]


def merge_observations(*groups):
    out = []
    for group in groups:
        for observation in group:
            if observation not in out:
                out.append(dict(observation))
    return out


def render_observations(observations):
    blocks = []
    for observation in observations:
        endpoint = observation.get("matched_at") or observation.get("target") or ""
        lines = [
            f"Endpoint: {endpoint} · {observation.get('port', 'host')}/{observation.get('protocol', 'tcp')}"
        ]
        for key, label in (
            ("service_name", "Service"),
            ("service_id", "Service ID"),
            ("detected_version", "Detected version"),
            ("detection_method", "Detection method"),
            ("template_id", "Template"),
            ("corroborating_templates", "Corroborating templates"),
        ):
            if observation.get(key):
                lines.append(f"{label}: {observation[key]}")
        for key in ("evidence", "proof", "plugin_output"):
            value = str(observation.get(key) or "").strip()
            if value and value not in lines:
                lines.append(value)
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks)
