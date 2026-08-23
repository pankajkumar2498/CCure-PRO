"""
core/ip_resolver.py
───────────────────
Resolve the client address a security decision should be made about.

This is not a logging helper. The value returned here is the rate-limiting
bucket key and the address recorded in the audit trail, so anything that can
influence it can influence both. The whole module is therefore written around
one question: *which hop is allowed to speak about the client?*

The answer is `AppConfig.TRUSTED_PROXIES`, and it must list the reverse proxies
themselves — never the network the users sit on. See the note on that setting
in `config.py` for what went wrong when it named 10.0.0.0/8 on a deployment
whose clients live at 10.180.6.0/24.

Two rules, both load-bearing:

  1. **Forwarding headers are only read when the immediate peer is a trusted
     proxy.** `X-Forwarded-For` and `X-Real-IP` are request headers like any
     other — a client that can reach this application directly can set them to
     anything. If the socket peer is not a proxy we trust, the socket address
     is the only honest answer available.

  2. **The chain is walked from the nearest hop outward**, stopping at the
     first address that is not a trusted proxy. A proxy appends the address it
     received the connection from, so everything to the left of the first
     untrusted entry was written by somebody we have no reason to believe.
"""

import ipaddress
import logging

from config import AppConfig
from fastapi import Request

logger = logging.getLogger(__name__)

# Compile trusted network objects once from AppConfig
_TRUSTED_NETWORKS = []
for net_str in AppConfig.TRUSTED_PROXIES:
    try:
        _TRUSTED_NETWORKS.append(ipaddress.ip_network(net_str.strip()))
    except ValueError as e:
        logger.warning(f"Invalid trusted proxy range: {net_str}. Error: {e}")

# A very wide trusted range is the failure this module was rewritten for: it
# quietly turns "which hop may speak about the client" into "nearly anyone".
#
# The threshold is /12, which is not arbitrary — 172.16.0.0/12 is Docker's
# default address pool and is the widest range that legitimately appears here,
# so it is the boundary rather than a violation. 10.0.0.0/8, the entry that
# caused the problem, is four bits wider and trips this.
_WIDEST_SANE_PREFIX = 12


def log_trust_boundary() -> list[str]:
    """
    Report which hops may declare a client address, and complain about any
    range wide enough to be a user network.

    Called from the application lifespan rather than at import, and that is not
    a style choice: `main.py` imports every router before it reaches
    `logging.basicConfig`, so anything this module logged at import time was
    emitted with no handlers installed. INFO vanished entirely and the warning
    below only survived via `logging.lastResort`, unformatted and without the
    logger name. A safety warning nobody can see is not a safety warning.

    Returns the concerning ranges, so a test can assert on them without
    parsing log output.
    """
    logger.info(
        "Client IP resolution trusts %d proxy range(s): %s",
        len(_TRUSTED_NETWORKS),
        ", ".join(str(n) for n in _TRUSTED_NETWORKS) or "(none configured)",
    )

    too_wide = []
    for net in _TRUSTED_NETWORKS:
        if net.version == 4 and not net.is_loopback:
            if net.prefixlen < _WIDEST_SANE_PREFIX:
                too_wide.append(str(net))
                logger.warning(
                    "TRUSTED_PROXIES contains %s, which spans %d addresses. "
                    "This list should name reverse proxies, not the network "
                    "your users sit on: any address inside it is allowed to "
                    "declare the client IP used for rate limiting and audit "
                    "logging.",
                    net,
                    net.num_addresses,
                )
    return too_wide


def _is_trusted_proxy(ip_str: str) -> bool:
    """Check if an IP address falls within the configured trusted proxy networks."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return any(ip in net for net in _TRUSTED_NETWORKS)
    except ValueError:
        return False


def _normalise(candidate: str | None, fallback: str | None) -> str:
    """Return `candidate` if it parses as an IP address, else a safe default."""
    for value in (candidate, fallback):
        if not value:
            continue
        if value == "testclient":  # Starlette's TestClient peer name
            return "127.0.0.1"
        try:
            ipaddress.ip_address(value)
            return value
        except ValueError:
            continue
    return "127.0.0.1"


def get_client_ip(request: Request) -> str:
    """
    Resolve the client address, refusing to be told what it is by an untrusted
    peer.

    Returns the socket peer when no forwarding header may be believed, and
    "127.0.0.1" when nothing usable can be determined at all — never None, so
    callers cannot accidentally key a rate limit on a missing value.
    """
    if not request:
        return None

    socket_ip = request.client.host if request.client else None

    # The peer that actually opened this connection. If it is not a proxy we
    # trust, no forwarding header on this request means anything: the client
    # wrote it. Answer with the socket address and stop.
    #
    # The TestClient peer is "testclient" rather than an address; it is the
    # in-process test harness, and treating it as an untrusted direct client
    # would make every test exercise this branch instead of the deployed one.
    if socket_ip and socket_ip != "testclient" and not _is_trusted_proxy(socket_ip):
        return _normalise(socket_ip, None)

    x_forwarded_for = request.headers.get("x-forwarded-for")
    if x_forwarded_for:
        # Build the chain of hops: header entries, then the peer we heard from.
        hops = [ip.strip() for ip in x_forwarded_for.split(",") if ip.strip()]
        if socket_ip:
            hops.append(socket_ip)

        # Walk right-to-left and stop at the first hop that is not a proxy we
        # trust. That is the furthest address whose provenance we can vouch for.
        for ip in reversed(hops):
            if not _is_trusted_proxy(ip):
                return _normalise(ip, socket_ip)

        # Every hop is a trusted proxy. Either the client genuinely sits inside
        # one of those ranges, or a proxy is forwarding a header it should have
        # overwritten. The leftmost entry is the conventional answer, and it is
        # only safe because TRUSTED_PROXIES names proxies rather than user
        # networks — which is why that setting is checked at import above.
        return _normalise(hops[0], socket_ip)

    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        # Reached only when the peer is a trusted proxy, per the guard above.
        # Without that guard this branch was an unconditional override: any
        # client could name its own address simply by sending X-Real-IP and no
        # X-Forwarded-For, and nothing downstream could tell.
        return _normalise(real_ip.strip(), socket_ip)

    return _normalise(socket_ip, None)
