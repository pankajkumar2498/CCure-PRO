"""
engines/credentialed/coverage.py
────────────────────────────────────────────────────────────────────────────
What a credentialed audit examined, and how its host-side view of listening
sockets relates to what the network can actually reach.

Two concerns live together here because they answer the same question from
opposite ends.

``credentialed_coverage`` states the audit's own limits. A credentialed audit
reads the operating system from the inside: it can enumerate installed
packages exactly, and it cannot see a filtered port, a weak cipher suite or a
default credential on a service it never connected to. Recording that on the
report is the difference between "no network findings" and "no network
exposure", which are not the same claim — and an empty findings list reads as
the second unless the report says otherwise.

``correlate_listeners`` joins the host's own socket table to a port scan's
results. Neither view establishes exposure on its own: the socket table lists
what the host is running, including services bound to loopback that nothing
off-box can reach; a port scan lists what answered, without knowing what is
behind it. Together they separate a service that is genuinely exposed from one
that is merely running — which is the single most useful thing an authenticated
scan adds to an unauthenticated one.
"""

from __future__ import annotations

from typing import Any, Iterable

# ── Bind-scope vocabulary ────────────────────────────────────────────────────

#: A socket bound here answers on every interface the host has.
BIND_ALL = "all_interfaces"
#: A socket bound here is reachable only from the host itself.
BIND_LOOPBACK = "loopback"
#: Bound to one named address — reachable only via that interface.
BIND_SPECIFIC = "specific_interface"
#: The collector did not record an address we can interpret.
BIND_UNKNOWN = "unknown"

_WILDCARD_BINDS = {"0.0.0.0", "::", "*", "0"}
_LOOPBACK_EXACT = {"::1", "localhost"}


# ── Exposure vocabulary ──────────────────────────────────────────────────────

EXPOSURE_EXPOSED = "exposed"
EXPOSURE_HOST_ONLY = "host_only"
EXPOSURE_FILTERED = "filtered"
EXPOSURE_UNDETERMINED = "undetermined"

EXPOSURE_LABELS = {
    EXPOSURE_EXPOSED: "Exposed — listening and reachable from the scanner",
    EXPOSURE_HOST_ONLY: "Host-only — bound to loopback, not reachable off-box",
    EXPOSURE_FILTERED: "Filtered — listening on the host but not reachable from the scanner",
    EXPOSURE_UNDETERMINED: "Not determined — no network port scan was performed against this host",
}


def _address_part(local_addr: Any) -> str:
    """
    The address half of a ``host:port`` socket string.

    Handles every shape the collectors emit: ``0.0.0.0:22``, ``*:22``,
    ``:::22``, ``[::]:22``, ``127.0.0.1:631``, ``[::1]:631``.
    """
    text = str(local_addr or "").strip()
    if ":" not in text:
        return ""
    return text.rsplit(":", 1)[0].strip("[]").strip()


def bind_scope(local_addr: Any) -> str:
    """Classify what a listening socket's bind address makes reachable."""
    addr = _address_part(local_addr)
    if not addr:
        return BIND_UNKNOWN
    if addr in _WILDCARD_BINDS:
        return BIND_ALL
    lowered = addr.lower()
    if lowered in _LOOPBACK_EXACT or lowered.startswith("127."):
        return BIND_LOOPBACK
    return BIND_SPECIFIC


def _port_number(record: Any) -> int | None:
    """Read a port number out of either collector's or the port engine's shape."""
    if isinstance(record, dict):
        raw = record.get("port")
    else:
        raw = record
    try:
        port = int(str(raw).strip())
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def _protocol(record: Any, default: str = "tcp") -> str:
    if isinstance(record, dict):
        proto = str(record.get("protocol") or "").strip().lower()
        if proto:
            return proto
    return default


def network_port_keys(network_ports: Iterable[Any]) -> set[tuple[int, str]]:
    """
    The ``(port, protocol)`` pairs a network scan actually found open.

    Only ports in an open state count. A port the scan recorded as filtered or
    closed is evidence *against* reachability, so folding it in here would
    invert the very distinction this module exists to draw.
    """
    keys: set[tuple[int, str]] = set()
    for record in network_ports or []:
        port = _port_number(record)
        if port is None:
            continue
        state = ""
        if isinstance(record, dict):
            state = str(record.get("state") or "open").strip().lower()
        if state and state not in ("open", "open|filtered", "listen", "listening"):
            continue
        keys.add((port, _protocol(record)))
    return keys


def correlate_listeners(
    listeners: Iterable[dict],
    network_ports: Iterable[Any] | None = None,
    network_scanned: bool = False,
    scanned_ports: Iterable[int] | None = None,
) -> tuple[list[dict], dict]:
    """
    Annotate each host-side listener with whether the network can reach it.

    Returns ``(annotated_listeners, summary)``. The input records are copied
    rather than mutated, so a caller can correlate without disturbing the raw
    collector output it may still need to store verbatim.

    A loopback bind is decided from the socket table alone — that conclusion
    needs no port scan and is therefore available even in the host-only audit.
    Everything else is left explicitly undetermined until a scan of the network
    has something to say, because "we did not look" must not render as "not
    reachable".

    ``scanned_ports`` is what separates the two negative verdicts. A port scan
    reports the ports it found open, not the ports it tried, so the open set
    alone cannot distinguish a service the scanner probed and could not reach
    (**filtered** — a real finding, usually a firewall doing its job) from one
    on a port the scan never covered (**undetermined** — nothing was learned).
    Without this argument the second is never claimed as the first: on a real
    host, a scan of eight ports against a machine with a hundred listeners
    would otherwise have declared ninety-two services "not reachable from the
    scanner" on the strength of never having looked at them.
    """
    open_keys = network_port_keys(network_ports or []) if network_scanned else set()
    probed: set[int] = set()
    if network_scanned and scanned_ports:
        probed = {p for p in (_port_number(x) for x in scanned_ports) if p is not None}

    annotated: list[dict] = []
    counts = {
        EXPOSURE_EXPOSED: 0,
        EXPOSURE_HOST_ONLY: 0,
        EXPOSURE_FILTERED: 0,
        EXPOSURE_UNDETERMINED: 0,
    }

    for raw in listeners or []:
        if not isinstance(raw, dict):
            continue
        record = dict(raw)
        scope = bind_scope(record.get("local_addr"))
        port = _port_number(record)
        proto = _protocol(record)

        record["bind_scope"] = scope

        if scope == BIND_LOOPBACK:
            reachable: bool | None = False
            exposure = EXPOSURE_HOST_ONLY
        elif not network_scanned or port is None:
            reachable = None
            exposure = EXPOSURE_UNDETERMINED
        elif (port, proto) in open_keys:
            reachable = True
            exposure = EXPOSURE_EXPOSED
        elif port in probed:
            # Probed and stayed silent — something between the scanner and the
            # host is dropping it.
            reachable = False
            exposure = EXPOSURE_FILTERED
        else:
            # Outside the scanned range. Nothing was learned about this one.
            reachable = None
            exposure = EXPOSURE_UNDETERMINED

        record["network_reachable"] = reachable
        record["exposure"] = exposure
        record["exposure_label"] = EXPOSURE_LABELS[exposure]
        counts[exposure] += 1
        annotated.append(record)

    summary = {
        "listeners_total": len(annotated),
        "listeners_exposed": counts[EXPOSURE_EXPOSED],
        "listeners_host_only": counts[EXPOSURE_HOST_ONLY],
        "listeners_filtered": counts[EXPOSURE_FILTERED],
        "listeners_undetermined": counts[EXPOSURE_UNDETERMINED],
        "correlated_with_port_scan": bool(network_scanned),
    }
    return annotated, summary


def mark_credentialed_confirmed(
    network_ports: Iterable[dict],
    listeners: Iterable[dict],
) -> list[dict]:
    """
    Flag network-discovered ports that the host itself confirms it is serving.

    The reverse direction of :func:`correlate_listeners`. A port that answered a
    probe *and* appears in the host's socket table is confirmed from both sides;
    one that answered but has no matching listener is worth knowing about too —
    it usually means a middlebox, a forwarded port, or a container namespace the
    collector could not see.
    """
    listener_keys: set[tuple[int, str]] = set()
    for record in listeners or []:
        port = _port_number(record)
        if port is not None:
            listener_keys.add((port, _protocol(record)))

    annotated: list[dict] = []
    for raw in network_ports or []:
        if not isinstance(raw, dict):
            continue
        record = dict(raw)
        port = _port_number(record)
        if port is not None:
            record["credentialed_confirmed"] = (
                port,
                _protocol(record),
            ) in listener_keys
        annotated.append(record)
    return annotated


# ── Coverage statements ──────────────────────────────────────────────────────

#: Extra methodology rows the report prints for scans that authenticated.
#: Ordered ``(metadata key, printed label)`` — the renderer stays free of the
#: wording so this file remains the single place the claims are written.
COVERAGE_ROWS = (
    ("authenticated_checks", "Authenticated checks"),
    ("unauthenticated_checks", "Unauthenticated checks"),
    ("network_reachability", "Network reachability"),
)


def credentialed_coverage(network_scanned: bool = False) -> dict:
    """
    What a credentialed audit did and did not examine.

    ``network_scanned`` distinguishes the two ways credentials are used here:
    the standalone host-only audit, and the Vulnerability Audit pipeline where
    discovery, port scanning and unauthenticated checks ran first and the
    credentialed pass enriches them. The claims differ substantially between the
    two, and the report has to make the correct one.
    """
    if network_scanned:
        return {
            "authenticated_checks": (
                "Installed package inventory matched against the vulnerability "
                "feed; host hardening policy audited"
            ),
            "unauthenticated_checks": (
                "Performed — network-facing service checks ran against the "
                "ports found by the asset discovery phase"
            ),
            "network_reachability": (
                "Determined — host-side listening sockets were correlated with "
                "the network port scan to separate exposed services from those "
                "listening but unreachable"
            ),
        }

    return {
        # Keys the methodology appendix already renders. Stating these
        # explicitly is the whole point: left unset they print as "Not
        # recorded", which invites the reader to assume the checks ran and
        # found nothing.
        "port_range": (
            "Not scanned — this audit reads the host's own listening socket "
            "table and performs no network port scan"
        ),
        "service_detection": (
            "Host-side process and socket inspection only — no network service "
            "fingerprinting"
        ),
        "os_detection": "Authenticated — read from the operating system",
        "timing_template": "Not applicable — no network probing performed",
        "scanner": "Built-in credentialed collector over SSH",
        "discovery_scan_method": (
            "None — the target was supplied directly and no host discovery ran"
        ),
        # Credentialed-specific claims.
        "authenticated_checks": (
            "Installed package inventory matched against the vulnerability "
            "feed; host hardening policy audited"
        ),
        "unauthenticated_checks": (
            "Not performed — TLS, SSH algorithm, HTTP header, default-credential "
            "and other network-facing checks require the Vulnerability Audit "
            "pipeline"
        ),
        "network_reachability": (
            "Not determined for non-loopback services — listening sockets were "
            "read from the host and not confirmed reachable from the network. "
            "Loopback-bound services are identified from their bind address"
        ),
    }
