"""
core/discovery/techniques/tcp_conn.py — Async TCP Connect (no root required)
"""
import asyncio
import logging
import ssl
import time
from typing import Dict, List

log = logging.getLogger("ccure.discovery.tcp_conn")

_TLS_PORTS = {443, 8443, 465, 993, 995}


async def probe(
    ips: List[str],
    ports: List[int],
    results: Dict[str, Dict],
    timeout: float = 0.8,
    concurrency: int = 256,
    retries: int = 0,
) -> None:
    """
    Async TCP connect probe — works without root or Scapy.

    The universal fallback technique: runs after all Scapy probes
    to catch hosts that block ICMP/ARP but accept TCP connections.

    Args:
        ips:         IPs to probe (typically the still-inactive subset).
        ports:       Ports to try per IP (tries all; stops at first success).
        results:     Shared results dict, mutated in place.
        timeout:     Per-connection timeout in seconds.
        concurrency: Max simultaneous connections (semaphore).
        retries:     Number of retry attempts on timeout.
    """
    sem = asyncio.Semaphore(concurrency)

    async def _one(ip: str, port: int) -> None:
        async with sem:
            use_tls = port in _TLS_PORTS
            for attempt in range(max(retries + 1, 1)):
                try:
                    t0 = time.time()
                    if use_tls:
                        ctx = ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                        conn = asyncio.open_connection(ip, port, ssl=ctx)
                    else:
                        conn = asyncio.open_connection(ip, port)
                    _, writer = await asyncio.wait_for(conn, timeout=timeout)
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
                    elapsed = (time.time() - t0) * 1000
                    if not results[ip]["is_active"]:
                        results[ip].update(
                            is_active=True,
                            method=f"TCP:{port}",
                            elapsed_ms=elapsed,
                        )
                        results[ip]["confirmations"].append(f"TCP:{port}")
                    return   # success — don't retry
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    pass
                except Exception:
                    return

    tasks = [
        _one(ip, port)
        for ip in ips
        for port in ports
    ]
    await asyncio.gather(*tasks)
