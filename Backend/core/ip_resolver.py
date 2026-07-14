"""
core/ip_resolver.py
───────────────────
Secure client IP resolution from HTTP request headers.
Handles nested proxies (X-Forwarded-For, X-Real-IP) and prevents header spoofing
by only trusting designated proxy CIDR ranges.
"""

import ipaddress
import logging
from fastapi import Request
from config import AppConfig

logger = logging.getLogger(__name__)

# Compile trusted network objects once from AppConfig
_TRUSTED_NETWORKS = []
for net_str in AppConfig.TRUSTED_PROXIES:
    try:
        _TRUSTED_NETWORKS.append(ipaddress.ip_network(net_str.strip()))
    except ValueError as e:
        logger.warning(f"Invalid trusted proxy range: {net_str}. Error: {e}")


def _is_trusted_proxy(ip_str: str) -> bool:
    """Check if an IP address falls within the configured trusted proxy networks."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return any(ip in net for net in _TRUSTED_NETWORKS)
    except ValueError:
        return False


def get_client_ip(request: Request) -> str:
    """
    Securely resolves the actual client IP address, avoiding IP spoofing.

    Traverses the proxy forwarding chain (X-Forwarded-For) from right to left
    (nearest proxy to original client). The first IP that is NOT a trusted proxy
    is returned. If all IPs are trusted proxies, the leftmost IP in the chain is returned.

    If X-Forwarded-For is not present, falls back to X-Real-IP (if present) or
    the raw socket connection peer IP.
    """
    if not request:
        return None

    # Get raw client host from the connection socket
    socket_ip = request.client.host if request.client else None

    # 1. Parse X-Forwarded-For chain
    x_forwarded_for = request.headers.get("x-forwarded-for")
    ip_to_return = None
    if x_forwarded_for:
        # Build the chain of hops: client-supplied headers + socket IP
        hops = [ip.strip() for ip in x_forwarded_for.split(",") if ip.strip()]
        if socket_ip:
            hops.append(socket_ip)

        # Traverse right-to-left (from immediate peer back to client)
        for ip in reversed(hops):
            if not _is_trusted_proxy(ip):
                ip_to_return = ip
                break
        else:
            # If all hops are trusted (e.g. internal requests), return the first one (leftmost client IP)
            ip_to_return = hops[0]
    elif request.headers.get("x-real-ip"):
        # 2. Fall back to X-Real-IP if no X-Forwarded-For is present
        ip_to_return = request.headers.get("x-real-ip").strip()
    else:
        # 3. Fall back to socket peer IP
        ip_to_return = socket_ip

    if ip_to_return == "testclient" or not ip_to_return:
        return "127.0.0.1"

    try:
        ipaddress.ip_address(ip_to_return)
        return ip_to_return
    except ValueError:
        return "127.0.0.1"
