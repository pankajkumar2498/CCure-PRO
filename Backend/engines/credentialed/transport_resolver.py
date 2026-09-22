"""
Where to open the authenticated session — resolved, not assumed.

An authenticated scan has to reach a listener before it can collect anything,
and until this module existed the only thing that decided *where* was
``compliance_credentials.port``. That column is ``NOT NULL`` with a model-level
default of ``22``, so "the operator chose 22" and "nobody said anything" are the
same row. A host running SSH on 2222 was therefore skipped with "port 22/tcp not
open" on a scan that had *already discovered and identified* sshd on 2222 two
phases earlier, and a Windows credential whose listener sits on 5986 rather than
5985 failed in the same way.

The fix is not a longer list of default ports. It is to treat the port scan's
service identification as what it is — evidence — and to resolve the endpoint
from it when the stated one does not answer.

Three properties this module exists to hold:

* **A credential is only ever presented to a port that is either stated on the
  credential or positively identified as that transport's service.** Walking
  every open port until something authenticates is credential spraying against
  the customer's own estate, and it is what a "try harder" resolver becomes the
  moment the identification step is dropped.

* **Selection is by TCP reachability, never by attempting authentication.**
  Both executors expose a ``test_connectivity`` probe that opens a socket and
  closes it. Choosing between candidates by trying the credential on each would
  turn one failed logon into three and walk into the account lockout this
  product documents elsewhere as a control it must not trip. Exactly one
  authentication attempt is made, against the endpoint chosen here.

* **``use_tls`` is carried, not re-derived.** ``WinRMExecutor`` infers TLS from
  ``port == 5986`` when it is not told, which is right for the conventional
  layout and wrong for every other one — an HTTPS listener on 6986 would be
  addressed as ``http://`` and fail with a handshake error that reads as a
  broken host. A discovered endpoint carries whatever the identification
  established and ``None`` when it established nothing, so the executor's own
  inference applies only where there is genuinely nothing better.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Callable, Iterable, List, Optional, Sequence, Set

log = logging.getLogger(__name__)

TRANSPORT_SSH = "ssh"
TRANSPORT_WINRM = "winrm"
TRANSPORT_SMB = "smb"

#: Conventional port per transport, used only when a credential names none.
#: A starting point for resolution, never the answer on its own.
DEFAULT_PORT = {TRANSPORT_SSH: 22, TRANSPORT_WINRM: 5985, TRANSPORT_SMB: 445}

#: Additional well-known ports probed when the stated port does not answer and
#: there is no port-scan evidence to resolve from — the standalone credentialed
#: scan runs no discovery of its own.
#:
#: Deliberately short. This is a courtesy for the conventional alternates, not a
#: port scan: a long list turns every unreachable host into a minute of connect
#: timeouts, and the honest answer beyond these is that the operator states the
#: port or runs a discovery scan first.
FALLBACK_PORTS = {
    TRANSPORT_SSH: (22, 2222),
    TRANSPORT_WINRM: (5985, 5986),
    # 139 is the NetBIOS session service, still found on old estates and still
    # spoken by the SMB client. Direct-hosted SMB on 445 leads because that is
    # what every supported Windows prefers.
    TRANSPORT_SMB: (445, 139),
}

#: Ports whose TLS posture is settled by convention. Anything else discovered as
#: WinRM carries ``None`` — unknown — rather than a guess.
_WINRM_TLS_BY_PORT = {5985: False, 5986: True}

#: RFC 4253 section 4.2 identification string. A listener that opens with this
#: *is* SSH, whatever the port scan named the service.
_SSH_BANNER = re.compile(r"^SSH-\d", re.IGNORECASE)

_SSH_PRODUCT_HINTS = ("openssh", "dropbear", "libssh", "tectia", "cisco ssh")
_WINRM_PRODUCT_HINTS = ("microsoft httpapi", "winrm", "wsman")
#: nmap names 445 ``microsoft-ds`` and 139 ``netbios-ssn``; a Samba server is
#: identified by product rather than by service name.
_SMB_PRODUCT_HINTS = ("samba", "windows smb", "microsoft-ds", "smbd")

_TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")


@dataclass(frozen=True)
class TransportEndpoint:
    """One place worth attempting the authenticated session."""

    port: int
    #: True/False when established, ``None`` when nothing established it — in
    #: which case the executor's own convention applies. Only meaningful for
    #: WinRM; always ``None`` for SSH.
    use_tls: Optional[bool] = None
    #: ``credential`` (stated on the stored credential), ``discovered`` (the
    #: port scan identified this transport's service here), or ``fallback`` (a
    #: conventional alternate probed because nothing else answered).
    source: str = "credential"
    #: Why this endpoint is in the list, in words, for the scan record.
    evidence: str = ""

    def describe(self) -> str:
        scheme = ""
        if self.use_tls is True:
            scheme = " TLS"
        elif self.use_tls is False:
            scheme = " plaintext"
        return f"{self.port}/tcp{scheme} [{self.source}]"


@dataclass
class EndpointResolution:
    """The outcome of resolution, including what was rejected and why."""

    endpoint: Optional[TransportEndpoint] = None
    considered: List[TransportEndpoint] = field(default_factory=list)
    reason: str = ""

    @property
    def resolved(self) -> bool:
        return self.endpoint is not None


def _tokens(*values: object) -> Set[str]:
    out: Set[str] = set()
    for value in values:
        if not value:
            continue
        for token in _TOKEN_SPLIT.split(str(value).strip().lower()):
            if token:
                out.add(token)
    return out


def _is_ssh_service(record: dict) -> bool:
    """Does the port scan's identification of this port say 'SSH'?"""
    banner = str(record.get("banner") or "").strip()
    if _SSH_BANNER.match(banner):
        return True
    product = str(record.get("product") or "").lower()
    if any(hint in product for hint in _SSH_PRODUCT_HINTS):
        return True
    # ``ssh``, ``SSH`` and ``SSH-Alt`` (this product's own PORT_DB label for
    # 2222) all tokenise to a bare ``ssh``. Matching the token rather than a
    # substring keeps ``ssl`` and any future ``*ssh*`` service name out.
    return "ssh" in _tokens(record.get("service"), record.get("extra"))


def _is_winrm_service(record: dict) -> bool:
    """Does the port scan's identification of this port say 'WinRM'?"""
    product = str(record.get("product") or "").lower()
    if any(hint in product for hint in _WINRM_PRODUCT_HINTS):
        return True
    tokens = _tokens(record.get("service"), record.get("extra"))
    # nmap names 5985 ``wsman``; this product's PORT_DB names it ``WinRM-HTTP``.
    return bool(tokens & {"wsman", "winrm"})


def _is_smb_service(record: dict) -> bool:
    """Does the port scan's identification of this port say 'SMB'?"""
    product = str(record.get("product") or "").lower()
    if any(hint in product for hint in _SMB_PRODUCT_HINTS):
        return True
    tokens = _tokens(record.get("service"), record.get("extra"))
    # ``microsoft-ds`` tokenises to {microsoft, ds}; ``netbios-ssn`` to
    # {netbios, ssn}. Both are matched as pairs rather than on the generic
    # halves, so a service merely called ``microsoft`` does not qualify.
    if "smb" in tokens or "smbd" in tokens:
        return True
    if {"microsoft", "ds"} <= tokens:
        return True
    return {"netbios", "ssn"} <= tokens


def _winrm_tls_hint(record: dict) -> Optional[bool]:
    """
    What the identification says about TLS on this port, or ``None``.

    ``None`` is a real answer and the common one off the conventional ports:
    nmap reports a TLS-wrapped listener as service ``http`` with the TLS fact in
    a ``tunnel`` attribute this product does not currently parse. Returning a
    guess here would address an HTTPS listener as ``http://``.
    """
    try:
        known = _WINRM_TLS_BY_PORT.get(int(record.get("port")))
    except (TypeError, ValueError):
        known = None
    if known is not None:
        return known
    if _tokens(record.get("service"), record.get("extra")) & {"https", "ssl", "tls"}:
        return True
    return None


def _identifier(transport: str) -> Optional[Callable[[dict], bool]]:
    return {
        TRANSPORT_SSH: _is_ssh_service,
        TRANSPORT_WINRM: _is_winrm_service,
        TRANSPORT_SMB: _is_smb_service,
    }.get(transport)


def _open_tcp_records(open_ports: Optional[Iterable]) -> List[dict]:
    records: List[dict] = []
    for record in open_ports or []:
        if not isinstance(record, dict):
            continue
        if str(record.get("protocol") or "tcp").lower() != "tcp":
            continue
        state = str(record.get("state") or "open").lower()
        # ``filtered`` and ``closed`` are not places to send a credential. An
        # entry with no state comes from the paths that record only open ports,
        # so it is treated as open — which is what it means there.
        if state != "open":
            continue
        try:
            port = int(record.get("port"))
        except (TypeError, ValueError):
            continue
        if 1 <= port <= 65535:
            records.append(dict(record, port=port))
    return records


def candidate_endpoints(
    *,
    transport: str,
    stated_port: Optional[int] = None,
    use_tls: Optional[bool] = None,
    open_ports: Optional[Sequence] = None,
    include_fallbacks: bool = False,
    exclude_ports: Optional[Iterable] = None,
) -> List[TransportEndpoint]:
    """
    Every endpoint worth attempting for this credential, best first.

    The stated port leads, because an operator who wrote one meant it. Ports the
    scan *identified* as this transport's service follow, which is what makes a
    non-standard listener reachable without anybody reconfiguring the
    credential. ``include_fallbacks`` adds the conventional alternates and is
    for the standalone credentialed scan, which runs no discovery and so has no
    identification to resolve from.
    """
    resolved_transport = (transport or TRANSPORT_SSH).strip().lower()
    endpoints: List[TransportEndpoint] = []
    seen: Set[int] = set()
    # Ports the caller has already attempted. The standalone scan attempts the
    # stated port directly and only resolves after a *transport* failure, so
    # re-probing what just refused a connection buys a second timeout and no
    # information.
    for port in exclude_ports or ():
        try:
            seen.add(int(port))
        except (TypeError, ValueError):
            continue

    def add(endpoint: TransportEndpoint) -> None:
        if endpoint.port in seen:
            return
        seen.add(endpoint.port)
        endpoints.append(endpoint)

    try:
        stated = int(stated_port) if stated_port else 0
    except (TypeError, ValueError):
        stated = 0
    if not 1 <= stated <= 65535:
        stated = 0

    stated_endpoint = (
        TransportEndpoint(
            port=stated,
            use_tls=use_tls,
            source="credential",
            evidence="port stated on the stored credential",
        )
        if stated
        else None
    )

    records = _open_tcp_records(open_ports)
    identifies = _identifier(resolved_transport)
    discovered: List[TransportEndpoint] = []
    if identifies is not None:
        for record in records:
            if not identifies(record):
                continue
            hint = use_tls
            if resolved_transport == TRANSPORT_WINRM and hint is None:
                hint = _winrm_tls_hint(record)
            service = str(record.get("service") or "").strip() or "unknown"
            discovered.append(
                TransportEndpoint(
                    port=record["port"],
                    use_tls=hint,
                    source="discovered",
                    evidence=f"port scan identified '{service}' on this port",
                )
            )

    # The stated port normally leads, because an operator who wrote one meant
    # it. The exception is when discovery has *positively identified* that port
    # as some other service: ``compliance_credentials.port`` is NOT NULL with a
    # model default of 22, so a Windows credential can carry an SSH port without
    # anyone having chosen it, and on a host running both sshd and WinRM that
    # would send a WS-Management request to sshd while the real listener sat
    # identified two entries away. Contradicted by evidence, the stated port
    # goes second — it is never dropped, because service detection can be wrong.
    stated_contradicted = False
    if stated_endpoint is not None and discovered:
        for record in records:
            if record["port"] != stated:
                continue
            named = str(record.get("service") or "").strip().lower()
            if named and named != "unknown" and not identifies(record):
                stated_contradicted = True
            break

    if stated_endpoint is not None and not stated_contradicted:
        add(stated_endpoint)
    for endpoint in discovered:
        add(endpoint)
    if stated_endpoint is not None and stated_contradicted:
        add(stated_endpoint)

    if not stated and not endpoints:
        default = DEFAULT_PORT.get(resolved_transport)
        if default:
            add(
                TransportEndpoint(
                    port=default,
                    use_tls=use_tls,
                    source="credential",
                    evidence="no port stated; conventional port for this transport",
                )
            )

    if include_fallbacks:
        for port in FALLBACK_PORTS.get(resolved_transport, ()):
            hint = use_tls
            if resolved_transport == TRANSPORT_WINRM and hint is None:
                hint = _WINRM_TLS_BY_PORT.get(port)
            add(
                TransportEndpoint(
                    port=port,
                    use_tls=hint,
                    source="fallback",
                    evidence="conventional alternate port for this transport",
                )
            )

    return endpoints


def _default_probe(transport: str) -> Callable[..., bool]:
    resolved = (transport or TRANSPORT_SSH).strip().lower()
    if resolved == TRANSPORT_WINRM:
        from engines.credentialed.winrm_executor import WinRMExecutor

        return WinRMExecutor.test_connectivity
    if resolved == TRANSPORT_SMB:
        from engines.credentialed.smb_executor import SMBExecutor

        return SMBExecutor.test_connectivity
    from engines.credentialed.ssh_scanner import SSHScanner

    return SSHScanner.test_connectivity


def resolve_endpoint(
    *,
    ip: str,
    transport: str,
    stated_port: Optional[int] = None,
    use_tls: Optional[bool] = None,
    open_ports: Optional[Sequence] = None,
    include_fallbacks: bool = False,
    exclude_ports: Optional[Iterable] = None,
    probe: Optional[Callable[..., bool]] = None,
    timeout: int = 5,
) -> EndpointResolution:
    """
    Choose the one endpoint to authenticate against, or explain why none.

    **Discovery is authoritative where it exists.** When the caller supplies the
    port scan's view of this host, a candidate is accepted if that view says the
    port is open and rejected if it does not — no socket is opened, because the
    answer is already known and a 5-second connect per host is minutes across a
    large scan. That is the rule this function inherited from the enrichment
    path and it is kept deliberately.

    **A TCP probe is the fallback where discovery does not exist.** The
    standalone credentialed scan runs no discovery, so there is nothing to
    consult and the probe is the only evidence available. It opens a socket and
    closes it; it never presents the credential.
    """
    endpoints = candidate_endpoints(
        transport=transport,
        stated_port=stated_port,
        use_tls=use_tls,
        open_ports=open_ports,
        include_fallbacks=include_fallbacks,
        exclude_ports=exclude_ports,
    )
    result = EndpointResolution(considered=list(endpoints))
    label = (transport or TRANSPORT_SSH).strip().upper()

    if not endpoints:
        result.reason = "no candidate port could be resolved for this credential"
        return result

    known_open = {record["port"] for record in _open_tcp_records(open_ports)}

    if known_open:
        for endpoint in endpoints:
            if endpoint.port in known_open:
                result.endpoint = endpoint
                return result
        tried = ", ".join(e.describe() for e in endpoints)
        result.reason = (
            f"{label} is not open on any resolved port ({tried}) — "
            f"no authenticated session attempted"
        )
        return result

    try:
        probe_fn = probe or _default_probe(transport)
    except Exception as exc:  # noqa: BLE001 — an absent transport is not a crash
        log.warning("No reachability probe available for %s: %s", transport, exc)
        result.reason = f"no reachability probe is available for {label}"
        return result

    for endpoint in endpoints:
        try:
            reachable = bool(probe_fn(ip, endpoint.port, timeout))
        except Exception as exc:  # noqa: BLE001 — a failed probe means "closed"
            log.debug(
                "Reachability probe failed for %s:%s — %s", ip, endpoint.port, exc
            )
            reachable = False
        if reachable:
            result.endpoint = endpoint
            return result

    tried = ", ".join(e.describe() for e in endpoints)
    result.reason = (
        f"nothing accepted a TCP connection for {label} — considered {tried}"
    )
    return result


# ── Transport discovery ──────────────────────────────────────────────────────
#
# Everything above answers "which *port* for this transport". This answers the
# question in front of it: "which transport at all".
#
# Until this existed the transport was whatever the credential row said, and a
# Windows credential therefore had to be created twice — once for WinRM and
# once for SMB — by an operator who had to know in advance which one the target
# would accept. WinRM is off by default on Windows *client* editions and on by
# default on Server; SMB is on almost everywhere. So the operator was being
# asked for the one fact the scanner is better placed to establish than they
# are, and getting it wrong reads as "the credential was refused".
#
# The order is preference, not fallback-only: each is *probed*, and the first
# that answers is used.

#: Transports to try for a credential type that does not name one, in the order
#: they are preferred.
#:
#: WinRM leads for Windows because it is the deeper transport — it runs
#: arbitrary PowerShell, so every collector item is served, where SMB serves 18
#: of 31 natively and records the rest in ``collection_errors``. SMB follows
#: because it reaches the hosts WinRM does not.
DISCOVERY_ORDER = {
    "windows": (TRANSPORT_WINRM, TRANSPORT_SMB),
    "ssh": (TRANSPORT_SSH,),
    # A credential whose type says nothing: try everything, Windows first only
    # because its two transports are cheap TCP probes on distinctive ports.
    "auto": (TRANSPORT_WINRM, TRANSPORT_SMB, TRANSPORT_SSH),
}


@dataclass
class AccessResolution:
    """Which transport and port an authenticated session should use.

    ``attempted`` records every transport considered and why it was or was not
    chosen, because "the credential was refused" and "nothing was listening for
    any transport we support" send the operator to completely different places.
    """

    transport: Optional[str] = None
    endpoint: Optional[TransportEndpoint] = None
    attempted: List[tuple] = field(default_factory=list)
    reason: str = ""

    @property
    def resolved(self) -> bool:
        return self.transport is not None and self.endpoint is not None

    def describe(self) -> str:
        """One line naming the mechanism, for the scan record and the UI."""
        if not self.resolved:
            return self.reason or "no supported authentication service was reachable"
        return f"{self.transport.upper()} on {self.endpoint.describe()}"

    def as_dict(self) -> dict:
        return {
            "transport": self.transport,
            "port": self.endpoint.port if self.endpoint else None,
            "use_tls": self.endpoint.use_tls if self.endpoint else None,
            "source": self.endpoint.source if self.endpoint else None,
            "summary": self.describe(),
            "considered": [
                {"transport": t, "resolved": ok, "reason": why}
                for t, ok, why in self.attempted
            ],
        }


def resolve_access(
    *,
    ip: str,
    credential_type: str = "auto",
    stated_transport: Optional[str] = None,
    prefer: Optional[str] = None,
    stated_port: Optional[int] = None,
    use_tls: Optional[bool] = None,
    open_ports: Optional[Sequence] = None,
    include_fallbacks: bool = True,
    probe: Optional[Callable[..., bool]] = None,
    timeout: int = 5,
) -> AccessResolution:
    """
    Decide *how* to reach this host, not merely where.

    **A stated transport is honoured and is not second-guessed.** An operator
    who chose WinRM gets WinRM; discovery exists for the operator who chose
    nothing, which after this change is the normal case. ``prefer`` is the
    middle ground a stored credential needs -- see the note on ordering below. What discovery must
    never become is "try each transport with the credential until one accepts
    it" — that is credential spraying with an account the lockout policy is
    watching. Selection here is by **TCP reachability only**; exactly one
    authentication attempt is made afterwards, against the winner.

    **A stated port does not pin the transport.** 5985 states WinRM as clearly
    as it states a port, but 22 on a Windows credential is the model default
    (``compliance_credentials.port`` is NOT NULL default 22) and means nothing
    at all — which is the whole reason this module exists. So a stated port is
    offered to each transport in turn and simply fails to resolve for the ones
    it does not belong to.
    """
    result = AccessResolution()

    if stated_transport:
        order = (stated_transport.strip().lower(),)
    else:
        key = (credential_type or "auto").strip().lower()
        order = DISCOVERY_ORDER.get(key) or DISCOVERY_ORDER["auto"]
        # A stored credential always carries a transport -- the column is NOT
        # NULL -- so it cannot say "I do not mind". Treating it as a *pin*
        # would silently override an operator who chose SMB because WinRM is
        # listening here but misconfigured; ignoring it would throw away a
        # deliberate choice. It is therefore a preference: tried first, with
        # the others still available behind it.
        chosen = (prefer or "").strip().lower()
        if chosen and chosen in order:
            order = (chosen,) + tuple(t for t in order if t != chosen)

    for transport in order:
        # The stated port is only meaningful to the transport it belongs to.
        # Offering 5985 to SSH would have SSH resolve a WinRM port and open an
        # SSH handshake against a WinRM listener -- the exact defect the
        # module docstring above describes, reached from a new direction.
        port_for_this = stated_port
        if stated_port is not None and len(order) > 1:
            conventional = FALLBACK_PORTS.get(transport, ())
            if stated_port not in conventional:
                port_for_this = None

        resolution = resolve_endpoint(
            ip=ip,
            transport=transport,
            stated_port=port_for_this,
            use_tls=use_tls,
            open_ports=open_ports,
            include_fallbacks=include_fallbacks,
            probe=probe,
            timeout=timeout,
        )
        if resolution.resolved:
            result.transport = transport
            result.endpoint = resolution.endpoint
            result.attempted.append((transport, True, resolution.endpoint.describe()))
            log.info("Credentialed access to %s resolved to %s", ip, result.describe())
            return result
        result.attempted.append((transport, False, resolution.reason))

    tried = "; ".join(f"{t}: {why}" for t, _, why in result.attempted)
    result.reason = f"no supported authentication service answered on {ip} — {tried}"
    log.info("Credentialed access to %s unresolved: %s", ip, result.reason)
    return result
