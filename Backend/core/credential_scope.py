"""Validate credential references/scopes before any secret is resolved or offered."""

import ipaddress


def credential_plan_entries(raw):
    if raw is None:
        return []
    if isinstance(raw, dict):
        raw = [raw]
    if not isinstance(raw, list):
        raise ValueError("credentials must be a list of credential references")
    entries = []
    for entry in raw:
        if isinstance(entry, str):
            entry = {"credential_id": entry}
        if not isinstance(entry, dict):
            raise ValueError("each credential must name a credential_id")
        if set(entry) - {"credential_id", "targets"}:
            raise ValueError(
                "credential references contain unsupported or ambiguous scope fields"
            )
        credential_id = entry.get("credential_id")
        if not isinstance(credential_id, str) or not credential_id.strip():
            raise ValueError("each credential must name a nonempty credential_id")
        networks = None
        if "targets" in entry:
            targets = entry["targets"]
            if not isinstance(targets, list) or not targets:
                raise ValueError(
                    "credential targets must be a nonempty list of IPs or networks; omit targets for the whole scan"
                )
            networks = []
            for target in targets:
                if not isinstance(target, str) or not target.strip():
                    raise ValueError(
                        "credential targets must contain IP addresses or canonical networks"
                    )
                try:
                    networks.append(ipaddress.ip_network(target.strip(), strict=True))
                except ValueError as exc:
                    raise ValueError(
                        "credential target is invalid or has ambiguous network host bits"
                    ) from exc
        entries.append((credential_id.strip(), networks))
    return entries


def validate_credential_options(options):
    if options is not None and "credentials" in options:
        # Explicit null is ambiguous; omission alone means no credential plan.
        if options["credentials"] is None:
            raise ValueError("credentials must be a list, not null")
        credential_plan_entries(options["credentials"])
    return options
