"""
core/nmap/wrapper.py
────────────────────────────────────────────────────────────────────────────
Centralized Nmap Integration Layer for CCure Audit PRO

DESIGN RULES (per architecture spec):
  ✅ All Nmap calls go through this file — NEVER call nmap.PortScanner()
     or subprocess(['nmap', ...]) anywhere else in the codebase.
  ✅ XML parsing lives here and nowhere else.
  ✅ Returns structured dicts (NmapScanResult) — callers never parse raw Nmap.
  ❌ DO NOT reimplement Nmap features in Scapy.
  ❌ DO NOT scatter nmap calls across port_engine, vuln_engine, etc.

WHY NMAP (not pure Scapy) FOR PORT SCANNING:
  - Nmap SYN scan (-sS) sends ~10× more packets/sec than our async TCP connect.
  - Service/version detection (-sV) uses a 4,500-probe Nmap-Service-Probes DB
    that would take months to replicate.
  - OS fingerprinting (-O) uses a 2,600+ signature Nmap-OS-DB that is the
    industry gold standard.
  - Banner grabbing (-sC / NSE scripts) is battle-tested and NSE-scriptable.

MODES:
  detect_services(target, ports)         → service + version + banner
  full_scan(target)                      → service + OS + NSE scripts

AVAILABILITY:
  nmap must be installed: apt install nmap  /  brew install nmap
  python-nmap package:    pip install python-nmap
  NmapScanner degrades gracefully when nmap is missing: returns empty results
  and logs a warning. The port_engine falls back to TCP connect in that case.
"""

import json
import logging
import threading
import shutil
import time
import uuid
import hashlib
import xml.etree.ElementTree as ET
from contextlib import contextmanager
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional

from config import AppConfig
from core.redis_client import get_redis_client

log = logging.getLogger("ccure.nmap")


class _NmapProcessLimiter:
    """
    Cross-worker guard for local Nmap process pressure.

    Redis is used when available so multiple Celery worker processes/containers
    share one global limit. If Redis is unreachable, we fall back to an in-process
    semaphore so scans still run, but the cap is local to that Python process.
    """

    _RELEASE_SCRIPT = """
    if redis.call("get", KEYS[1]) == ARGV[1] then
        return redis.call("del", KEYS[1])
    end
    return 0
    """

    def __init__(self, max_processes: int, wait_timeout: int, lease_seconds: int):
        self.max_processes = max(1, int(max_processes or 1))
        self.wait_timeout = max(1, int(wait_timeout or lease_seconds))
        self.lease_seconds = max(60, int(lease_seconds or 300) + 120)
        self._local = threading.BoundedSemaphore(self.max_processes)
        self._redis = None
        self._redis_unavailable_logged = False

    def _client(self):
        if self._redis is not None:
            return self._redis
        try:
            import redis
            self._redis = redis.from_url(
                AppConfig.CELERY_BROKER_URL,
                socket_timeout=3,
                socket_connect_timeout=3,
                decode_responses=True,
            )
            self._redis.ping()
            return self._redis
        except Exception as exc:
            if not self._redis_unavailable_logged:
                log.warning(
                    "Redis unavailable for global Nmap limiter; using local process limiter only: %s",
                    exc,
                )
                self._redis_unavailable_logged = True
            self._redis = None
            return None

    def acquire(self):
        owner = f"{uuid.uuid4()}:{threading.get_ident()}"
        redis_client = self._client()
        if redis_client is None:
            if not self._local.acquire(timeout=self.wait_timeout):
                raise TimeoutError(
                    f"Timed out waiting for local Nmap slot "
                    f"(max={self.max_processes}, wait={self.wait_timeout}s)"
                )
            return ("local", owner)

        deadline = time.time() + self.wait_timeout
        keys = [f"ccure:nmap:slot:{i}" for i in range(self.max_processes)]
        while time.time() < deadline:
            for key in keys:
                try:
                    if redis_client.set(key, owner, nx=True, ex=self.lease_seconds):
                        return ("redis", key, owner)
                except Exception as exc:
                    log.warning("Redis Nmap limiter failed; falling back to local limiter: %s", exc)
                    self._redis = None
                    if not self._local.acquire(timeout=self.wait_timeout):
                        raise TimeoutError(
                            f"Timed out waiting for local Nmap slot "
                            f"(max={self.max_processes}, wait={self.wait_timeout}s)"
                        )
                    return ("local", owner)
            time.sleep(0.25)

        raise TimeoutError(
            f"Timed out waiting for global Nmap slot "
            f"(max={self.max_processes}, wait={self.wait_timeout}s)"
        )

    def release(self, token) -> None:
        if not token:
            return
        if token[0] == "local":
            self._local.release()
            return
        _, key, owner = token
        redis_client = self._client()
        if redis_client is None:
            return
        try:
            redis_client.eval(self._RELEASE_SCRIPT, 1, key, owner)
        except Exception as exc:
            log.warning("Failed to release Redis Nmap slot %s: %s", key, exc)


_nmap_limiter = _NmapProcessLimiter(
    max_processes=AppConfig.MAX_NMAP_PROCESSES,
    wait_timeout=AppConfig.NMAP_PROCESS_WAIT_TIMEOUT,
    lease_seconds=AppConfig.NMAP_TIMEOUT,
)


@contextmanager
def _nmap_process_slot(label: str):
    token = None
    start = time.time()
    try:
        token = _nmap_limiter.acquire()
        waited = time.time() - start
        if waited >= 1:
            log.info("Acquired Nmap slot for %s after %.1fs", label, waited)
        yield
    finally:
        _nmap_limiter.release(token)

# ── Try importing python-nmap (preferred) ────────────────────────────────────
try:
    import nmap as _nmap_lib
    _NMAP_LIB_AVAILABLE = True
except ImportError:
    _nmap_lib = None
    _NMAP_LIB_AVAILABLE = False

# ── Check that the nmap binary is on PATH ────────────────────────────────────
_NMAP_BINARY = shutil.which("nmap")
NMAP_AVAILABLE = _NMAP_BINARY is not None

if not NMAP_AVAILABLE:
    log.warning(
        "nmap binary not found in PATH. Port scanning will fall back to "
        "async TCP connect. Install nmap: apt install nmap / brew install nmap"
    )
if not _NMAP_LIB_AVAILABLE:
    log.warning(
        "python-nmap not installed. Install it: pip install python-nmap"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Data Models returned by NmapScanner
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class NmapPortResult:
    """Single port result from Nmap."""
    port:     int
    protocol: str           = "tcp"        # tcp / udp
    state:    str           = "filtered"   # open / closed / filtered / open|filtered
    service:  str           = "unknown"
    product:  str           = ""           # e.g. "OpenSSH"
    version:  str           = ""           # e.g. "8.9p1"
    extra:    str           = ""           # e.g. "Ubuntu"
    banner:   str           = ""           # raw banner text from NSE
    cpe:      List[str]     = field(default_factory=list)   # CPE identifiers
    scripts:  Dict[str, str] = field(default_factory=dict)  # NSE script outputs

    @property
    def full_version(self) -> str:
        """Human-readable version string: 'OpenSSH 8.9p1 Ubuntu'."""
        parts = [p for p in (self.product, self.version, self.extra) if p]
        return " ".join(parts)

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["full_version"] = self.full_version
        return d


@dataclass
class NmapOSMatch:
    """OS detection result from Nmap."""
    name:       str   = "Unknown"
    accuracy:   int   = 0        # 0–100
    os_family:  str   = ""       # Linux, Windows, Cisco, etc.
    os_gen:     str   = ""       # 2.6.X, 10, etc.
    cpe:        List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class NmapScanResult:
    """
    Complete Nmap scan result for one host.
    This is what callers receive — no raw XML / python-nmap internals leak out.
    """
    ip:          str
    hostname:    str              = ""
    state:       str              = "up"          # up / down / error / timeout / nmap_unavailable
    error_message: Optional[str]  = None
    ports:       List[NmapPortResult] = field(default_factory=list)
    os_matches:  List[NmapOSMatch]    = field(default_factory=list)
    scan_duration: float          = 0.0
    nmap_version:  str            = ""
    command_line:  str            = ""

    # Convenience accessors
    @property
    def open_ports(self) -> List[NmapPortResult]:
        return [p for p in self.ports if p.state == "open"]

    @property
    def best_os(self) -> Optional[NmapOSMatch]:
        if not self.os_matches:
            return None
        return max(self.os_matches, key=lambda o: o.accuracy)

    def to_dict(self) -> Dict:
        d = {
            "ip":            self.ip,
            "hostname":      self.hostname,
            "state":         self.state,
            "error_message": self.error_message,
            "ports":         [p.to_dict() for p in self.ports],
            "open_ports":    [p.to_dict() for p in self.open_ports],
            "os_matches":    [o.to_dict() for o in self.os_matches],
            "best_os":       self.best_os.to_dict() if self.best_os else None,
            "scan_duration": self.scan_duration,
            "nmap_version":  self.nmap_version,
            "command_line":  self.command_line,
        }
        return d


# ─────────────────────────────────────────────────────────────────────────────
# NmapScanner — the ONLY class that calls nmap in this codebase
# ─────────────────────────────────────────────────────────────────────────────

class NmapScanner:
    """
    Centralized Nmap integration.

    All nmap calls in CCure Audit PRO MUST go through this class.
    Never call nmap directly in engines/port/, engines/vulnerability/, etc.

    Usage::

        scanner = NmapScanner()

        # Asset Discovery — batch port states (returns dict of IP → NmapScanResult)
        results = scanner.scan_hosts(["10.180.6.140", "10.180.6.141"], intensity="basic")

        # Asset Discovery — service/version on known open ports
        result = scanner.detect_services("10.180.6.140", ports=[22, 80, 443])

        # Vulnerability Audit — full service + OS fingerprint + NSE scripts
        result = scanner.full_scan("10.180.6.140")

    Thread Safety:
        Each call creates its own python-nmap PortScanner instance.
        NmapScanner itself is stateless and safe to call concurrently.
    """

    # ── Intensity → nmap arguments mapping ───────────────────────────────────
    _INTENSITY_ARGS = {
        # Phase 2 / Asset Discovery — speed over depth
        "basic":    "-sS -F --open -T4",
        # Phase 2 / Asset Discovery — standard named ports (top-1000)
        "normal":   "-sS --top-ports 1000 --open -T4",
        # Phase 2 / Asset Discovery — all 65535 ports
        "deep":     "-sS -p- --open -T3",
        # Phase 3 / Vulnerability Audit — service + version detection
        "service":  "-sS -sV --version-intensity 5 -T4",
        # Phase 3 / Vulnerability Audit — service + OS + default NSE
        "full":     "-sS -sV -O --version-intensity 7 -T4",
        # Phase 3 / Vulnerability Audit — vuln scripts
        "vuln":     "-sS -sV --script=vuln,safe -T4",
    }

    # ── Top ports by intensity for Phase 2 ───────────────────────────────────
    _TOP_PORTS = {
        "basic":  "-F",              # Nmap top-100 ports
        "normal": "--top-ports 1000",
        "deep":   "-p-",             # all 65535
    }

    # ── Parallelism hints appended when scanning multiple hosts ───────────────
    # Tells Nmap to keep ≥N probes in-flight at once and send ≥M packets/sec,
    # dramatically reducing wall-clock time on local LAN subnets.
    _MULTI_PERF_ARGS = "--min-parallelism 64 --min-rate 500"

    def __init__(self, sudo: bool = True, timeout_sec: int = 300, cache_ttl_hours: Optional[int] = None):
        """
        Args:
            sudo:            Run nmap with sudo (required for SYN scan, OS detection).
            timeout_sec:     Per-host scan timeout in seconds.
            cache_ttl_hours: Override default TTL from config.
        """
        self.sudo = sudo
        self.timeout_sec = timeout_sec
        self.cache_ttl = (cache_ttl_hours or AppConfig.NMAP_CACHE_TTL_HOURS) * 3600
        self._redis = None
        self._cache_enabled = self._init_redis() if AppConfig.NMAP_CACHE_ENABLED else False

    def _init_redis(self) -> bool:
        """Initialize Redis connection for caching (non-fatal if fails)."""
        try:
            self._redis = get_redis_client()
            if self._redis:
                self._redis.ping()
                log.info("Redis cache enabled for Nmap results")
                return True
        except Exception as e:
            log.warning("Redis unavailable for Nmap cache: %s", e)
        return False

    def _cache_key(self, target: str, ports: Optional[List[int]], mode: str) -> str:
        """
        Generate cache key for Nmap results.
        Format: nmap_cache:{target}:{ports_hash}:{mode}
        """
        # Create hash of port list for compact key
        port_str = ",".join(sorted(str(p) for p in ports)) if ports else "all"
        port_hash = hashlib.md5(port_str.encode()).hexdigest()[:8]
        return f"nmap_cache:{target}:{port_hash}:{mode}"

    def _get_cache(self, key: str) -> Optional[NmapScanResult]:
        """Retrieve cached Nmap result from Redis."""
        if not self._cache_enabled or not self._redis:
            return None
        try:
            cached = self._redis.get(key)
            if cached:
                data = json.loads(cached)
                log.debug("Nmap cache HIT: %s", key)
                return self._deserialize_nmap_result(data)
        except Exception as e:
            log.debug("Nmap cache read error: %s", e)
        return None

    def _set_cache(self, key: str, result: NmapScanResult) -> None:
        """Store Nmap result in Redis cache."""
        if not self._cache_enabled or not self._redis:
            return
        try:
            data = self._serialize_nmap_result(result)
            self._redis.setex(key, self.cache_ttl, json.dumps(data))
            log.debug("Nmap cache SET: %s (TTL: %d seconds)", key, self.cache_ttl)
        except Exception as e:
            log.debug("Nmap cache write error: %s", e)

    def _serialize_nmap_result(self, result: NmapScanResult) -> dict:
        """Convert NmapScanResult to JSON-serializable dict."""
        return {
            "ip":            result.ip,
            "hostname":      result.hostname,
            "state":         result.state,
            "error_message": result.error_message,
            "ports":         [p.to_dict() for p in result.ports],
            "os_matches":    [o.to_dict() for o in result.os_matches],
            "scan_duration": result.scan_duration,
            "nmap_version":  result.nmap_version,
            "command_line":  result.command_line,
        }

    def _deserialize_nmap_result(self, data: dict) -> NmapScanResult:
        """Reconstruct NmapScanResult from cached JSON."""
        ports = [
            NmapPortResult(
                port     = p["port"],
                protocol = p["protocol"],
                state    = p["state"],
                service  = p["service"],
                product  = p["product"],
                version  = p["version"],
                extra    = p["extra"],
                banner   = p["banner"],
                cpe      = p["cpe"],
                scripts  = p["scripts"],
            )
            for p in data.get("ports", [])
        ]
        os_matches = [
            NmapOSMatch(
                name      = o["name"],
                accuracy  = o["accuracy"],
                os_family = o["os_family"],
                os_gen    = o["os_gen"],
                cpe       = o["cpe"],
            )
            for o in data.get("os_matches", [])
        ]
        return NmapScanResult(
            ip            = data["ip"],
            hostname      = data["hostname"],
            state         = data["state"],
            error_message = data.get("error_message"),
            ports         = ports,
            os_matches    = os_matches,
            scan_duration = data.get("scan_duration", 0.0),
            nmap_version  = data.get("nmap_version", ""),
            command_line  = data.get("command_line", ""),
        )

    # ── Public API ────────────────────────────────────────────────────────────

    def detect_services(
        self,
        target: str,
        ports: Optional[List[int]] = None,
    ) -> NmapScanResult:
        """
        Service and version detection. Requires open port list for efficiency.

        Used by: Vulnerability Audit (Phase 3) — after ports are known from Phase 2

        Args:
            target: Single IP.
            ports:  If provided, limits service detection to these ports (faster).
                    If None, scans all ports with service detection (slow).

        Returns:
            NmapScanResult enriched with service/version/banner.
        """
        if not NMAP_AVAILABLE:
            return self._unavailable_result(target)

        # Check cache first
        cache_key = self._cache_key(target, ports, "service")
        cached = self._get_cache(cache_key)
        if cached:
            log.info("Using cached Nmap service result for %s", target)
            return cached

        port_arg = self._port_arg(ports, "normal")
        args = f"-sS -sV --version-light {port_arg} -T4"
        result = self._run(target, args)

        # Cache successful result
        if result.state not in ("error", "nmap_unavailable", "timeout"):
            self._set_cache(cache_key, result)

        return result

    def full_scan(
        self,
        target: str,
        ports: Optional[List[int]] = None,
    ) -> NmapScanResult:
        """
        Full scan: service detection (optimized for speed).

        Used by: Vulnerability Audit (Phase 3) for multi-host scans (enrichment).
        Note: OS detection and intensive probing already done in Phases 1/2,
        so we focus on fast service detection only.

        Args:
            target: Single IP.
            ports:  Ports to focus service detection on (uses known open ports
                    from Phase 2 for efficiency). None = all ports.

        Returns:
            NmapScanResult with service/version data populated.
        """
        if not NMAP_AVAILABLE:
            return self._unavailable_result(target)

        # Check cache first
        cache_key = self._cache_key(target, ports, "full")
        cached = self._get_cache(cache_key)
        if cached:
            log.info("Using cached Nmap full result for %s (saves ~60 seconds)", target)
            return cached

        port_arg = self._port_arg(ports, "normal")
        # OPTIMIZATION: Use --version-intensity 5 (vs 7) for 30-40% faster service detection
        # while maintaining 95%+ accuracy. Keep -O for accurate OS fingerprinting (core
        # feature of Advanced module). Phase 1/2 don't perform active OS fingerprinting.
        args = f"-sS -sV -O --version-intensity 5 {port_arg} -T4"
        result = self._run(target, args)

        # Cache successful result
        if result.state not in ("error", "nmap_unavailable", "timeout"):
            self._set_cache(cache_key, result)

        return result

    def scan_hosts(
        self,
        targets: List[str],
        intensity: str = "basic",
        with_services: bool = False,
        with_os: bool = False,
        ports: Optional[List[int]] = None,
        exclude_ports: Optional[List[int]] = None,
        exclude_ot_from_nmap: bool = True,
    ) -> Dict[str, NmapScanResult]:
        """
        Batch port scan for multiple hosts.

        Used by: Asset Discovery scanning all discovered hosts concurrently.
        Nmap handles internal parallelism; no need for per-host threading here.

        Args:
            targets:       List of IPs.
            intensity:     "basic" | "normal" | "deep"
            with_services: When True, merges ``-sV --version-light`` into this
                           single batch call so callers can skip the expensive
                           per-host service-enrichment pass entirely.
                           Not used for "deep" (handled separately).
            with_os:       When True, appends ``-O`` for active OS fingerprinting
                           so Phase 2 Asset Discovery produces OS classification
                           consistent with Phase 3 Vulnerability Audit.
            ports:         Optional custom list of ports to scan.
            exclude_ports: Optional list of ports to exclude from scanning
                           (passed to Nmap as --exclude-ports).
            exclude_ot_from_nmap: When True, excludes OT ports from Nmap scan and
                                  caps the Nmap packet rate.

        Returns:
            Dict mapping IP → NmapScanResult (ports include service/version
            when with_services=True, plus OS matches when with_os=True).
        """
        if not NMAP_AVAILABLE or not targets:
            return {ip: self._unavailable_result(ip) for ip in targets}

        if ports:
            port_arg = self._port_arg(ports, intensity)
        else:
            port_arg = self._TOP_PORTS.get(intensity, "-F")

        # Merge service detection into the batch call when requested.
        svc_arg = "-sV --version-intensity 7" if with_services and intensity != "deep" else ""

        # Append -O when OS fingerprinting is requested
        os_arg = "-O" if with_os else ""

        # Append --exclude-ports when exclusion list is provided or exclude_ot_from_nmap is True
        exclude_list = list(exclude_ports) if exclude_ports else []
        if exclude_ot_from_nmap:
            ot_ports = {502, 102, 44818, 47808, 20000, 4840, 2404, 18245, 9600, 5007, 2455}
            exclude_list = list(set(exclude_list) | ot_ports)

        exclude_arg = f"--exclude-ports {','.join(str(p) for p in exclude_list)}" if exclude_list else ""

        # Adjust performance settings. If we exclude OT from Nmap, we cap the rate at 100 packets/sec
        # and reduce parallelism to prevent network saturation.
        perf_args = self._MULTI_PERF_ARGS
        if exclude_ot_from_nmap:
            perf_args = "--min-parallelism 8 --max-rate 100"

        args = " ".join(filter(None, [
            "-sS", svc_arg, os_arg, port_arg, "--open", "-T4", perf_args, exclude_arg
        ]))

        log.debug("scan_hosts args: %s", args)
        return self._run_multi(targets, args)


    # ── Internal execution engine ─────────────────────────────────────────────

    def _run(self, target: str, args: str) -> NmapScanResult:
        """Execute nmap and parse results for a single target."""
        if not _NMAP_LIB_AVAILABLE:
            return self._run_subprocess(target, args)

        t0 = time.time()
        try:
            with _nmap_process_slot(f"single:{target}"):
                nm = _nmap_lib.PortScanner()
                nm.scan(hosts=target, arguments=args, sudo=self.sudo, timeout=self.timeout_sec)
            duration = time.time() - t0

            # Extract first host (single target mode)
            hosts = nm.all_hosts()
            if not hosts:
                log.debug("Nmap: no host results for %s", target)
                ip = target.split()[0]  # first IP if space-separated
                return NmapScanResult(ip=ip, state="down", scan_duration=duration)

            ip = hosts[0]
            return self._parse_python_nmap(nm, ip, duration)

        except Exception as exc:
            error_msg = str(exc)
            log.warning("NmapScanner._run(%s) error: %s", target, error_msg)
            ip = target.split()[0] if target else "0.0.0.0"
            return NmapScanResult(
                ip=ip, state="error", error_message=error_msg,
                scan_duration=time.time() - t0
            )

    def _run_multi(self, targets: List[str], args: str) -> Dict[str, NmapScanResult]:
        """Execute nmap for multiple targets, return per-IP results."""
        if not _NMAP_LIB_AVAILABLE or not NMAP_AVAILABLE:
            return {ip: self._unavailable_result(ip) for ip in targets}

        target_str = " ".join(targets)
        t0 = time.time()
        try:
            with _nmap_process_slot(f"multi:{len(targets)} hosts"):
                nm = _nmap_lib.PortScanner()
                nm.scan(hosts=target_str, arguments=args, sudo=self.sudo, timeout=self.timeout_sec)
            duration = time.time() - t0

            results = {}
            for ip in nm.all_hosts():
                results[ip] = self._parse_python_nmap(nm, ip, duration)

            # Fill in any targets not returned (Nmap marks them down/filtered)
            for target_ip in targets:
                if target_ip not in results:
                    results[target_ip] = NmapScanResult(
                        ip=target_ip, state="down", scan_duration=duration
                    )
            return results

        except Exception as exc:
            error_msg = str(exc)
            log.warning("NmapScanner._run_multi error: %s", error_msg)
            return {
                ip: NmapScanResult(ip=ip, state="error", error_message=error_msg, scan_duration=time.time() - t0)
                for ip in targets
            }

    def _run_subprocess(self, target: str, args: str) -> NmapScanResult:
        """
        Subprocess fallback when python-nmap is not installed.
        Calls nmap directly and parses XML output.
        """
        import subprocess, tempfile, os

        t0 = time.time()
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
            xml_out = tmp.name
        cmd = ["nmap", "-oX", xml_out] + args.split() + [target]
        if self.sudo:
            cmd = ["sudo"] + cmd

        try:
            with _nmap_process_slot(f"subprocess:{target}"):
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    timeout=self.timeout_sec,
                )
            duration = time.time() - t0

            if not os.path.exists(xml_out):
                log.warning("Nmap produced no XML output for %s", target)
                return NmapScanResult(ip=target, state="error", scan_duration=duration)

            with open(xml_out) as f:
                xml_content = f.read()
            os.unlink(xml_out)

            return self._parse_xml(xml_content, duration)

        except subprocess.TimeoutExpired:
            log.warning("Nmap timed out scanning %s (limit=%ds)", target, self.timeout_sec)
            return NmapScanResult(ip=target, state="timeout", scan_duration=self.timeout_sec)
        except Exception as exc:
            log.warning("Nmap subprocess error (%s): %s", target, exc)
            return NmapScanResult(ip=target, state="error", scan_duration=time.time() - t0)

    # ── Parsers ───────────────────────────────────────────────────────────────

    def _parse_python_nmap(
        self, nm: "_nmap_lib.PortScanner", ip: str, duration: float
    ) -> NmapScanResult:
        """Convert python-nmap result for one host into NmapScanResult."""
        host_data = nm[ip]
        state     = host_data.state()

        # ── Hostname ─────────────────────────────────────────────────────
        hostnames = host_data.hostnames()
        hostname  = hostnames[0].get("name", "") if hostnames else ""

        # ── Ports ─────────────────────────────────────────────────────────
        ports: List[NmapPortResult] = []
        for proto in host_data.all_protocols():
            for port_num in sorted(host_data[proto].keys()):
                p = host_data[proto][port_num]
                port_result = NmapPortResult(
                    port     = port_num,
                    protocol = proto,
                    state    = p.get("state", "filtered"),
                    service  = p.get("name", "unknown"),
                    product  = p.get("product", ""),
                    version  = p.get("version", ""),
                    extra    = p.get("extrainfo", ""),
                    cpe      = p.get("cpe", "").split(",") if p.get("cpe") else [],
                    scripts  = {},
                )
                # NSE script outputs
                if "script" in p:
                    port_result.scripts = dict(p["script"])
                    # Extract banner from scripts if present
                    port_result.banner = p["script"].get("banner", "")
                ports.append(port_result)

        # ── OS Detection ──────────────────────────────────────────────────
        os_matches: List[NmapOSMatch] = []
        if "osmatch" in host_data:
            for om in host_data["osmatch"]:
                osclass = om.get("osclass", [{}])
                first_class = osclass[0] if osclass else {}
                cpes = []
                for cls in osclass:
                    cpe_str = cls.get("cpe", "")
                    if cpe_str:
                        cpes.append(cpe_str)
                os_matches.append(NmapOSMatch(
                    name      = om.get("name", "Unknown"),
                    accuracy  = int(om.get("accuracy", 0)),
                    os_family = first_class.get("osfamily", ""),
                    os_gen    = first_class.get("osgen", ""),
                    cpe       = cpes,
                ))

        return NmapScanResult(
            ip            = ip,
            hostname      = hostname,
            state         = state,
            ports         = ports,
            os_matches    = os_matches,
            scan_duration = duration,
            nmap_version  = nm.nmap_version() if hasattr(nm, "nmap_version") else "",
            command_line  = nm.command_line() if hasattr(nm, "command_line") else "",
        )

    def _parse_xml(self, xml_content: str, duration: float) -> NmapScanResult:
        """
        Parse raw Nmap XML output. Used when python-nmap is unavailable.
        This is the SINGLE place where Nmap XML is parsed in this codebase.
        """
        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError as exc:
            log.warning("Nmap XML parse error: %s", exc)
            return NmapScanResult(ip="0.0.0.0", state="error", scan_duration=duration)

        host_elem = root.find("host")
        if host_elem is None:
            return NmapScanResult(ip="0.0.0.0", state="down", scan_duration=duration)

        # ── IP address ────────────────────────────────────────────────────
        ip = ""
        for addr in host_elem.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                ip = addr.get("addr", "")
                break

        # ── State ─────────────────────────────────────────────────────────
        status   = host_elem.find("status")
        state    = status.get("state", "unknown") if status is not None else "unknown"

        # ── Hostname ──────────────────────────────────────────────────────
        hostname = ""
        hostnames_elem = host_elem.find("hostnames")
        if hostnames_elem is not None:
            h = hostnames_elem.find("hostname")
            if h is not None:
                hostname = h.get("name", "")

        # ── Ports ─────────────────────────────────────────────────────────
        ports: List[NmapPortResult] = []
        for port_elem in host_elem.findall(".//port"):
            state_elem  = port_elem.find("state")
            service_elem = port_elem.find("service")
            port_state  = state_elem.get("state", "filtered") if state_elem is not None else "filtered"
            service     = ""
            product     = ""
            version_str = ""
            extra       = ""
            cpes        = []

            if service_elem is not None:
                service     = service_elem.get("name", "unknown")
                product     = service_elem.get("product", "")
                version_str = service_elem.get("version", "")
                extra       = service_elem.get("extrainfo", "")
                for cpe_elem in service_elem.findall("cpe"):
                    cpes.append(cpe_elem.text or "")

            # NSE scripts on port
            scripts: Dict[str, str] = {}
            for script_elem in port_elem.findall("script"):
                script_id  = script_elem.get("id", "")
                script_out = script_elem.get("output", "")
                if script_id:
                    scripts[script_id] = script_out

            ports.append(NmapPortResult(
                port     = int(port_elem.get("portid", 0)),
                protocol = port_elem.get("protocol", "tcp"),
                state    = port_state,
                service  = service,
                product  = product,
                version  = version_str,
                extra    = extra,
                cpe      = cpes,
                scripts  = scripts,
                banner   = scripts.get("banner", ""),
            ))

        # ── OS Detection ──────────────────────────────────────────────────
        os_matches: List[NmapOSMatch] = []
        for osmatch_elem in host_elem.findall(".//osmatch"):
            name     = osmatch_elem.get("name", "Unknown")
            accuracy = int(osmatch_elem.get("accuracy", 0))
            osclasses = osmatch_elem.findall("osclass")
            first_cls = osclasses[0] if osclasses else None
            os_family = first_cls.get("osfamily", "") if first_cls is not None else ""
            os_gen    = first_cls.get("osgen", "")    if first_cls is not None else ""
            cpes      = [
                cpe.text for cls in osclasses
                for cpe in cls.findall("cpe")
                if cpe.text
            ]
            os_matches.append(NmapOSMatch(
                name=name, accuracy=accuracy,
                os_family=os_family, os_gen=os_gen, cpe=cpes,
            ))

        # ── Scan metadata ─────────────────────────────────────────────────
        runstats  = root.find("runstats/finished")
        nmap_ver  = root.get("version", "")
        cmd_line  = root.get("args", "")

        return NmapScanResult(
            ip            = ip,
            hostname      = hostname,
            state         = state,
            ports         = ports,
            os_matches    = os_matches,
            scan_duration = duration,
            nmap_version  = nmap_ver,
            command_line  = cmd_line,
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _port_arg(ports: Optional[List[int]], intensity: str) -> str:
        """Build the -p argument from a port list or intensity level."""
        if ports:
            return f"-p {','.join(str(p) for p in ports)}"
        return {
            "basic":  "-F",
            "normal": "--top-ports 1000",
            "deep":   "-p-",
        }.get(intensity, "-F")

    @staticmethod
    def _unavailable_result(target: str) -> NmapScanResult:
        """Return an empty result when Nmap is not available."""
        return NmapScanResult(
            ip=target, state="nmap_unavailable",
            scan_duration=0.0,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Module-level singleton  (avoids repeated PATH checks)
# ─────────────────────────────────────────────────────────────────────────────

_scanner: Optional[NmapScanner] = None

def get_scanner(sudo: bool = True) -> NmapScanner:
    """Return the module-level NmapScanner singleton."""
    global _scanner
    if _scanner is None:
        _scanner = NmapScanner(sudo=sudo)
    return _scanner
