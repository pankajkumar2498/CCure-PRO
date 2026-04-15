"""
engines/discovery/service_probe_engine.py
------------------------------------------
Priority 3-I: JSON-driven service probe engine.

Replaces hard-coded banner matching with a data-driven probe/match system
modelled after nmap-service-probes format but expressed as JSON for easy
extension without touching Python code.

Probe execution flow
--------------------
1. Load ``service_probes.json`` once (lazy, cached).
2. For each probe whose protocol matches the target:
   a. Connect / send payload.
   b. Read response (up to ``_MAX_RESPONSE_BYTES``).
   c. Try every regex in the probe's ``matches`` list.
   d. If a match fires → return {service, version, banner}.
3. Return ``{"service": "unknown", "version": "", "banner": raw_banner}``
   if no probe matched.

Callers can restrict which probes run with the *probe_names* parameter,
e.g. only run the NULL probe for quick scans.
"""

import asyncio
import binascii
import json
import logging
import os
import re
import socket
import ssl
from typing import Dict, List, Optional

log = logging.getLogger("ccure.service_probe")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_PROBE_DB_PATH      = os.path.join(os.path.dirname(__file__), "service_probes.json")
_MAX_RESPONSE_BYTES = 4096
_DEFAULT_CONNECT_TO = 3.0   # seconds
_DEFAULT_READ_TO    = 2.0   # seconds

# ---------------------------------------------------------------------------
# Probe database (lazy-loaded)
# ---------------------------------------------------------------------------

_PROBE_DB: List[Dict] = []


def _load_probes() -> List[Dict]:
    global _PROBE_DB
    if _PROBE_DB:
        return _PROBE_DB
    try:
        with open(_PROBE_DB_PATH, "r", encoding="utf-8") as fh:
            _PROBE_DB = json.load(fh)
        log.info("Service probe DB loaded: %d probes", len(_PROBE_DB))
    except FileNotFoundError:
        log.warning("Service probe DB not found at %s", _PROBE_DB_PATH)
        _PROBE_DB = []
    except Exception as exc:
        log.warning("Service probe DB load error: %s", exc)
        _PROBE_DB = []
    return _PROBE_DB


# ---------------------------------------------------------------------------
# Match helpers
# ---------------------------------------------------------------------------

def _build_payload(probe: Dict, target_ip: str) -> bytes:
    """
    Build the raw bytes to send for a probe.

    Priority:
      1. ``payload_ascii`` (template-expanded, then encoded)
      2. ``payload_hex``   (hex-decoded; empty string → empty bytes)
    """
    ascii_tmpl = probe.get("payload_ascii", "")
    if ascii_tmpl:
        text = ascii_tmpl.replace("{target}", target_ip)
        return text.encode("latin-1", errors="replace")

    hex_str = probe.get("payload_hex", "")
    if hex_str:
        try:
            return binascii.unhexlify(hex_str)
        except Exception:
            return b""
    return b""


def _try_match(response: bytes, probe: Dict) -> Optional[Dict]:
    """
    Attempt each match rule in *probe* against *response*.

    Returns a result dict on the first match, or None if nothing matched.
    """
    try:
        text = response.decode("utf-8", errors="replace")
    except Exception:
        text = ""

    for rule in probe.get("matches", []):
        pattern      = rule.get("pattern", "")
        service      = rule.get("service", "unknown")
        ver_group    = rule.get("version_group")
        info_tmpl    = rule.get("info_template", "")

        try:
            m = re.search(pattern, text, re.MULTILINE | re.DOTALL)
        except re.error:
            continue

        if not m:
            continue

        version = ""
        if ver_group is not None:
            try:
                version = m.group(ver_group).strip()
            except IndexError:
                pass

        # Fill info_template placeholders: {1} → group(1), {2} → group(2), …
        info = info_tmpl
        for idx in range(1, 6):
            placeholder = "{" + str(idx) + "}"
            if placeholder in info:
                try:
                    info = info.replace(placeholder, m.group(idx))
                except (IndexError, AttributeError):
                    info = info.replace(placeholder, "")

        return {
            "service": service,
            "version": version,
            "info":    info,
            "probe":   probe["name"],
            "banner":  text[:256],
        }

    return None


# ---------------------------------------------------------------------------
# Synchronous probe runner (used from executor)
# ---------------------------------------------------------------------------

def _run_tcp_probe(ip: str, port: int, probe: Dict, tls: bool = False) -> Optional[bytes]:
    """
    Send a single TCP probe and return raw response bytes, or None on error.
    """
    payload = _build_payload(probe, ip)
    wait_ms = probe.get("wait_ms", 500)

    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(_DEFAULT_CONNECT_TO)
        raw_sock.connect((ip, port))

        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw_sock, server_hostname=ip)
        else:
            sock = raw_sock

        sock.settimeout(_DEFAULT_READ_TO)

        if payload:
            sock.sendall(payload)

        data = b""
        deadline = wait_ms / 1000.0
        sock.settimeout(deadline)
        try:
            while len(data) < _MAX_RESPONSE_BYTES:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                data += chunk
        except (socket.timeout, OSError):
            pass

        sock.close()
        return data if data else None

    except Exception as exc:
        log.debug("TCP probe %s → %s:%d error: %s", probe["name"], ip, port, exc)
        return None


def _run_udp_probe(ip: str, port: int, probe: Dict) -> Optional[bytes]:
    """
    Send a single UDP probe and return raw response bytes, or None on error.
    """
    payload = _build_payload(probe, ip)
    wait_ms = probe.get("wait_ms", 500)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(wait_ms / 1000.0)
        if payload:
            sock.sendto(payload, (ip, port))
        else:
            sock.sendto(b"\x00", (ip, port))   # trigger a response

        data, _ = sock.recvfrom(_MAX_RESPONSE_BYTES)
        sock.close()
        return data if data else None

    except Exception as exc:
        log.debug("UDP probe %s → %s:%d error: %s", probe["name"], ip, port, exc)
        return None


# ---------------------------------------------------------------------------
# Main engine
# ---------------------------------------------------------------------------

class ServiceProbeEngine:
    """
    JSON-driven service identification engine (Priority 3-I).

    Usage (synchronous — call from thread-pool)::

        engine = ServiceProbeEngine()

        # Quick identification (NULL probe only):
        result = engine.identify(ip="192.168.1.1", port=22, protocol="tcp")

        # Deep identification (all TCP probes):
        result = engine.identify(ip="192.168.1.1", port=80, protocol="tcp",
                                  probe_names=["NULL", "GetRequest", "HTTPOptions"])

        # result -> {
        #   "service": "ssh",
        #   "version": "OpenSSH_8.9p1",
        #   "info":    "SSH 2.0",
        #   "probe":   "NULL",
        #   "banner":  "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
        # }

    Async usage (preferred in async contexts)::

        result = await engine.identify_async(ip, port, protocol)
    """

    def identify(
        self,
        ip:           str,
        port:         int,
        protocol:     str            = "tcp",
        probe_names:  Optional[List[str]] = None,
        tls:          bool           = False,
    ) -> Dict:
        """
        Run probes synchronously.  Safe to call from ``run_in_executor``.

        *probe_names* — if supplied, only probes whose ``name`` is in the list
        are tried (in that order).  Pass ``None`` to run all probes that match
        the *protocol*.
        """
        probes = _load_probes()
        candidates = [
            p for p in probes
            if p.get("protocol", "tcp").lower() == protocol.lower()
            and (probe_names is None or p["name"] in probe_names)
        ]
        if probe_names:
            # Preserve caller-requested ordering
            order = {name: i for i, name in enumerate(probe_names)}
            candidates.sort(key=lambda p: order.get(p["name"], 999))

        for probe in candidates:
            response = (
                _run_tcp_probe(ip, port, probe, tls=tls)
                if protocol.lower() == "tcp"
                else _run_udp_probe(ip, port, probe)
            )
            if response is None:
                continue

            result = _try_match(response, probe)
            if result:
                log.debug(
                    "Service match: %s:%d → %s (%s) via probe '%s'",
                    ip, port, result["service"], result["version"], probe["name"],
                )
                return result

        # Nothing matched — return raw banner from NULL probe if we got one
        banner = ""
        if candidates:
            raw = (
                _run_tcp_probe(ip, port, candidates[0], tls=tls)
                if protocol.lower() == "tcp"
                else _run_udp_probe(ip, port, candidates[0])
            )
            if raw:
                try:
                    banner = raw[:256].decode("utf-8", errors="replace")
                except Exception:
                    pass

        return {"service": "unknown", "version": "", "info": "", "probe": "", "banner": banner}

    async def identify_async(
        self,
        ip:          str,
        port:        int,
        protocol:    str            = "tcp",
        probe_names: Optional[List[str]] = None,
        tls:         bool           = False,
    ) -> Dict:
        """
        Async wrapper — runs synchronous probe code in the default executor
        so blocking socket I/O does not stall the event loop.
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            lambda: self.identify(ip, port, protocol, probe_names, tls),
        )


# ---------------------------------------------------------------------------
# Module-level convenience singleton
# ---------------------------------------------------------------------------

_engine: Optional[ServiceProbeEngine] = None


def get_service_probe_engine() -> ServiceProbeEngine:
    """Return the module-level singleton ``ServiceProbeEngine``."""
    global _engine
    if _engine is None:
        _engine = ServiceProbeEngine()
    return _engine


def identify_service(
    ip:          str,
    port:        int,
    protocol:    str = "tcp",
    tls:         bool = False,
) -> Dict:
    """
    Convenience function: quick NULL-probe service identification.

    Returns the same dict as ``ServiceProbeEngine.identify()``.
    """
    return get_service_probe_engine().identify(
        ip, port, protocol,
        probe_names=["NULL"],
        tls=tls,
    )
