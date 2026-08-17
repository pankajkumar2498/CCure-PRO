"""
core/scan_scope.py
──────────────────────────────────────────────────────────────────────────────
Per-organisation authorisation for scan targets.

Why this exists
───────────────
Every other control in this product answers "who is this user?". None of them
answered "is this user allowed to point a scanner at *that address*?".

`scan_helpers.validate_scan_targets` looked like it did, but it is a usability
check: it rejects targets that are unparseable, loopback, or over the global
host cap — a typo filter, not an authorisation boundary. `SCAN_IP_BLACKLIST` is
a single global deny-list read from the environment, applied in the worker
after the API has already accepted the job.

The net effect was that any authenticated account could aim Nmap, Scapy and
Nuclei at any routable address on the internet, from a worker running on the
host with raw-socket privileges. Unauthorised scanning is a legal exposure as
much as a technical one, and a deny-list cannot cover the address space.

So: an allow-list, per organisation, enforced at the API boundary before a scan
row is created, and again in the worker after DNS resolution.

Semantics of `Organization.scan_scope_cidrs`
────────────────────────────────────────────
    NULL   → no scope configured.
             REQUIRE_SCAN_SCOPE=False (default) → unrestricted, warned in logs
             REQUIRE_SCAN_SCOPE=True            → denied
    []     → explicitly deny all scanning for this org
    [...]  → scanning permitted only inside these blocks

NULL is not the same as `[]`. NULL means "nobody has decided yet" and exists
only so this ships without instantly breaking every existing organisation;
`[]` means "somebody decided: none". Once every org has a scope, set
REQUIRE_SCAN_SCOPE=True and the ambiguity is gone.

Hostname targets and TOCTOU
───────────────────────────
A hostname is checked against the scope by resolving it. Resolution at
admission time is not binding on what the scanner later connects to — DNS can
change between the two, deliberately (rebinding) or not. That is why
`filter_to_scope` is also applied in the orchestrator's expansion path, on the
addresses actually about to be scanned. The API check gives the operator a
fast, readable error; the worker check is the one that is authoritative.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Iterable, Sequence

log = logging.getLogger("ccure.scan_scope")

# Reused for both IPv4 and IPv6 networks.
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


class ScanScopeError(Exception):
    """Raised when a target falls outside the organisation's authorised scope."""

    def __init__(self, message: str, out_of_scope: Sequence[str] = ()):
        super().__init__(message)
        self.message = message
        self.out_of_scope = list(out_of_scope)


def parse_scope(raw: object) -> list[IPNetwork] | None:
    """
    Turn a stored `scan_scope_cidrs` value into networks.

    Returns None for "no scope configured". An entry that does not parse is
    dropped with a warning rather than failing the scan: a malformed row must
    not be able to widen the scope, and dropping narrows it.
    """
    if raw is None:
        return None
    if not isinstance(raw, (list, tuple)):
        log.warning(
            "scan_scope_cidrs is %s, expected a list; treating as deny-all",
            type(raw).__name__,
        )
        return []

    networks: list[IPNetwork] = []
    for entry in raw:
        try:
            networks.append(ipaddress.ip_network(str(entry).strip(), strict=False))
        except ValueError:
            log.warning("Ignoring unparseable scan scope entry %r", entry)
    return networks


def normalise_scope(entries: Iterable[str]) -> list[str]:
    """
    Validate and canonicalise operator-supplied CIDRs before storing them.

    Raises ValueError on the first bad entry — unlike parse_scope, which reads
    already-stored data, this is the write path and a typo should be rejected
    loudly rather than silently narrowing what an admin thought they granted.
    """
    out: list[str] = []
    for entry in entries:
        text = str(entry).strip()
        if not text:
            continue
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError as exc:
            raise ValueError(f"Not a valid CIDR block: {text!r} ({exc})") from exc
        out.append(str(network))
    # Preserve order, drop duplicates.
    return list(dict.fromkeys(out))


def _addresses_for(target: str) -> list[str]:
    """Expand a target to concrete addresses, resolving hostnames."""
    from core.utils import InputValidator

    expanded = InputValidator.expand_target(target)
    if expanded:
        return expanded
    # expand_target returns [] for an unresolvable or unsafe target.
    # validate_scan_targets has already rejected those by the time we run, but
    # the worker path can reach us directly.
    return []


def is_in_scope(address: str, scope: list[IPNetwork] | None) -> bool:
    """True if `address` is inside the scope. None scope means unrestricted."""
    if scope is None:
        return True
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(ip in network for network in scope)


def filter_to_scope(
    addresses: Iterable[str], scope: list[IPNetwork] | None
) -> tuple[list[str], list[str]]:
    """Split addresses into (allowed, denied) against a parsed scope."""
    if scope is None:
        return list(addresses), []
    allowed: list[str] = []
    denied: list[str] = []
    for address in addresses:
        (allowed if is_in_scope(address, scope) else denied).append(address)
    return allowed, denied


def scope_for_org(org) -> list[IPNetwork] | None:
    """Parsed scope for an Organization row, honouring REQUIRE_SCAN_SCOPE."""
    from config import AppConfig

    raw = getattr(org, "scan_scope_cidrs", None) if org is not None else None
    scope = parse_scope(raw)

    if scope is None:
        if AppConfig.REQUIRE_SCAN_SCOPE:
            # Fail closed: an unconfigured org scans nothing.
            return []
        log.warning(
            "Organisation %s has no scan scope configured; scanning is "
            "unrestricted. Set scan_scope_cidrs, then REQUIRE_SCAN_SCOPE=True.",
            getattr(org, "id", "<unknown>"),
        )
    return scope


def enforce_org_scan_scope(targets: Sequence[str], org) -> None:
    """
    Admission check. Raises ScanScopeError if any target leaves the scope.

    A target is rejected if *any* address it expands to is out of scope, not
    only if all of them are. A /24 that straddles the boundary is a request to
    scan addresses the org is not authorised for, and silently trimming it
    would run a different scan than the one the operator asked for and read as
    success.
    """
    scope = scope_for_org(org)
    if scope is None:
        return

    org_id = getattr(org, "id", "<unknown>")

    if not scope:
        raise ScanScopeError(
            "This organisation has no authorised scan ranges. Ask a "
            "superadmin to configure its scan scope before running a scan.",
            list(targets),
        )

    offending: list[str] = []
    for target in targets:
        addresses = _addresses_for(target)
        if not addresses:
            # Unresolvable here means we cannot prove it is in scope.
            offending.append(target)
            continue
        _, denied = filter_to_scope(addresses, scope)
        if denied:
            offending.append(target)

    if offending:
        log.warning(
            "Scan denied for org %s: targets outside authorised scope: %s",
            org_id,
            ", ".join(offending),
        )
        raise ScanScopeError(
            "Target(s) outside this organisation's authorised scan scope: "
            + ", ".join(offending)
            + ". Scanning an address you are not authorised for may be "
            "unlawful; ask a superadmin to extend the scope if this is "
            "expected.",
            offending,
        )
