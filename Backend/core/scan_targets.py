"""
core/scan_targets.py
─────────────────────────────────────────────────────────────────────────────
Whether a scan's targets can be scanned, and may be: the usability checks and
the organisation's scan-scope check every scan-creating path runs before it
dispatches anything.

Part of the scan kernel (G3, docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md):
the scan routes and the schedules — the dispatcher and the schedule API — ask
it, so scheduling no longer imports ``scan_helpers``. Moved unchanged out of
``scan_helpers``, which re-exports every name.
"""


def _is_scannable_address(value: str) -> bool:
    """A real network destination, as opposed to the scanner's own vantage point."""
    import ipaddress

    try:
        addr = ipaddress.ip_address(str(value).strip())
    except ValueError:
        # Hostnames are resolved upstream by expand_target; anything still
        # unparseable here is not this function's to reject.
        return True
    return not (
        addr.is_loopback
        or addr.is_link_local
        or addr.is_unspecified
        or addr.is_multicast
    )


# Distinguishes "this caller does not do scope enforcement" from "this caller
# enforces scope and the organisation does not exist" (scope=None). The second
# must still be denied under REQUIRE_SCAN_SCOPE, so it cannot share a default
# with the first.
_SCOPE_NOT_CHECKED = object()


def validate_custom_ports(custom_ports: str | None) -> None:
    """Reject malformed custom ports before a scan is dispatched."""
    if custom_ports:
        from core.utils import InputValidator
        from fastapi import HTTPException

        try:
            InputValidator.parse_custom_ports(custom_ports)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc


def validate_scan_targets(
    targets: list[str] | None, scope=_SCOPE_NOT_CHECKED
) -> list[str]:
    """
    Reject a scan request that can never produce results, before it costs anything.

    An unparseable target used to be accepted with HTTP 200: the API created a
    scan row and only failed asynchronously
    seconds later with a reason the API never returned. A typo should come back
    as an error the operator can fix, not as a scan that quietly dies.

    When `scope` is supplied — the organisation's ``ScanScopeView`` from
    ``core.scan_scope.org_scan_scope`` — the targets are additionally checked
    against it. The two checks are distinct and both belong here: everything
    above `scope` is a usability filter answering "can this scan work?", the
    scope check is an authorisation boundary answering "is this scan
    permitted?". Callers that omit `scope` get validation only — which is why
    every scan-creating route passes it.

    Returns the cleaned target list.
    """
    from core.utils import InputValidator
    from fastapi import HTTPException

    cleaned = [str(t).strip() for t in (targets or []) if str(t).strip()]
    if not cleaned:
        raise HTTPException(
            status_code=422,
            detail="At least one scan target is required.",
        )

    invalid: list[str] = []
    unscannable: list[str] = []
    total = 0
    for target in cleaned:
        expanded = InputValidator.expand_target(target)
        if not expanded:
            invalid.append(target)
            continue
        # A loopback or link-local target describes the scanner's own vantage
        # point, not a host on the network. Scanning one produced an
        # "unreachable" scan at best; at worst it resolved to the same MAC as a
        # real asset and rewrote that asset's address to 127.0.0.1, detaching
        # its findings from the address they belong to.
        if all(not _is_scannable_address(ip) for ip in expanded):
            unscannable.append(target)
            continue
        total += len(expanded)

    if invalid:
        raise HTTPException(
            status_code=422,
            detail=(
                "Not a valid IP address, range, CIDR block or resolvable hostname: "
                + ", ".join(invalid)
            ),
        )

    if unscannable:
        raise HTTPException(
            status_code=422,
            detail=(
                "Loopback and link-local addresses are not scannable targets: "
                + ", ".join(unscannable)
                + ". Use the address the host is reachable on from this network."
            ),
        )

    if total > InputValidator.MAX_HOSTS:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Total requested hosts ({total}) exceeds the global limit of "
                f"{InputValidator.MAX_HOSTS}."
            ),
        )

    if scope is not _SCOPE_NOT_CHECKED:
        from core.scan_scope import ScanScopeError, enforce_org_scan_scope

        try:
            enforce_org_scan_scope(cleaned, scope)
        except ScanScopeError as exc:
            # 403, not 422: the request is well-formed and the operator is
            # authenticated. What is missing is authorisation for this target.
            raise HTTPException(status_code=403, detail=exc.message) from exc

    return cleaned
