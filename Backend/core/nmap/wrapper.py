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
  scan_ports(target, ports, intensity)   → port states only (fast)
  detect_services(target, ports)         → service + version + banner
  full_scan(target)                      → service + OS + NSE scripts
  os_fingerprint(target)                 → OS only (needs root)
  vuln_scan(target, ports)               → NSE vuln scripts

AVAILABILITY:
  nmap must be installed: apt install nmap  /  brew install nmap
  python-nmap package:    pip install python-nmap
  NmapScanner degrades gracefully when nmap is missing: returns empty results
  and logs a warning. The port_engine falls back to TCP connect in that case.
"""

import logging
import shutil
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional

log = logging.getLogger("ccure.nmap")

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
    state:       str              = "up"          # up / down
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

        # Asset Discovery — fast port states only
        result = scanner.scan_ports("192.168.1.10", intensity="basic")

        # Advanced Scan — full service + version + OS
        result = scanner.full_scan("192.168.1.10")

        # Vulnerability scan — NSE vuln scripts
        result = scanner.vuln_scan("192.168.1.10", ports=[80, 443, 22])

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
        # Phase 3 / Advanced Scan — service + version detection
        "service":  "-sS -sV --version-intensity 5 -T4",
        # Phase 3 / Advanced Scan — service + OS + default NSE
        "full":     "-sS -sV -O --version-intensity 7 -T4",
        # Phase 3 / Advanced Scan — vuln scripts
        "vuln":     "-sS -sV --script=vuln,safe -T4",
    }

    # ── Top ports by intensity for Phase 2 ───────────────────────────────────
    _TOP_PORTS = {
        "basic":  "-F",              # Nmap top-100 ports
        "normal": "--top-ports 1000",
        "deep":   "-p-",             # all 65535
    }

    def __init__(self, sudo: bool = True, timeout_sec: int = 300):
        """
        Args:
            sudo:        Run nmap with sudo (required for SYN scan, OS detection).
            timeout_sec: Per-host scan timeout in seconds.
        """
        self.sudo = sudo
        self.timeout_sec = timeout_sec

    # ── Public API ────────────────────────────────────────────────────────────

    def scan_ports(
        self,
        target: str,
        ports: Optional[List[int]] = None,
        intensity: str = "basic",
    ) -> NmapScanResult:
        """
        Port scanning only — fast, no service/version detection.

        Used by: Asset Discovery (Phase 2)

        Args:
            target:    Single IP or CIDR (e.g. "192.168.1.10" or "192.168.1.0/24").
                       For multiple hosts, call scan_hosts() instead.
            ports:     Explicit port list. If None, uses intensity-based top-ports.
            intensity: "basic" (top-100) | "normal" (top-1000) | "deep" (all 65535)

        Returns:
            NmapScanResult for the target host.
        """
        if not NMAP_AVAILABLE:
            return self._unavailable_result(target)

        port_arg = self._port_arg(ports, intensity)
        args = f"-sS {port_arg} --open -T4"
        return self._run(target, args)

    def detect_services(
        self,
        target: str,
        ports: Optional[List[int]] = None,
    ) -> NmapScanResult:
        """
        Service and version detection. Requires open port list for efficiency.

        Used by: Advanced Scan (Phase 3) — after ports are known from Phase 2

        Args:
            target: Single IP.
            ports:  If provided, limits service detection to these ports (faster).
                    If None, scans all ports with service detection (slow).

        Returns:
            NmapScanResult enriched with service/version/banner.
        """
        if not NMAP_AVAILABLE:
            return self._unavailable_result(target)

        port_arg = self._port_arg(ports, "normal")
        args = f"-sS -sV --version-intensity 7 {port_arg} -T4"
        return self._run(target, args)

    def full_scan(
        self,
        target: str,
        ports: Optional[List[int]] = None,
    ) -> NmapScanResult:
        """
        Full scan: service detection + OS fingerprinting + default NSE scripts.

        Used by: Advanced Scan (Phase 3) when running in "advanced" pipeline mode.

        ⚠️  Requires root/Administrator for OS detection (-O).
            Run the backend process with sudo or as Administrator.

        Args:
            target: Single IP.
            ports:  Ports to focus service detection on (uses known open ports
                    from Phase 2 for efficiency). None = all ports.

        Returns:
            NmapScanResult with OS matches populated.
        """
        if not NMAP_AVAILABLE:
            return self._unavailable_result(target)

        port_arg = self._port_arg(ports, "normal")
        args = f"-sS -sV -O --version-intensity 7 {port_arg} -T4"
        return self._run(target, args)

    def os_fingerprint(self, target: str) -> NmapScanResult:
        """
        OS fingerprinting only. Requires root + at least one open and one
        closed/filtered port.

        Args:
            target: Single IP.

        Returns:
            NmapScanResult with os_matches populated.
        """
        if not NMAP_AVAILABLE:
            return self._unavailable_result(target)

        args = "-O -p 80,443,22,445,3389 -T4"
        return self._run(target, args)

    def vuln_scan(
        self,
        target: str,
        ports: Optional[List[int]] = None,
    ) -> NmapScanResult:
        """
        NSE vulnerability script scan. Runs scripts from the 'vuln' and 'safe'
        categories which detect common CVEs without exploiting them.

        Used by: Advanced Scan (Phase 3) for authenticated vulnerability checks.

        Args:
            target: Single IP.
            ports:  Limit NSE scripts to these ports.

        Returns:
            NmapScanResult with script outputs in NmapPortResult.scripts.
        """
        if not NMAP_AVAILABLE:
            return self._unavailable_result(target)

        port_arg = self._port_arg(ports, "normal")
        args = f"-sS -sV --script=vuln,safe {port_arg} -T4"
        return self._run(target, args)

    def scan_hosts(
        self,
        targets: List[str],
        intensity: str = "basic",
    ) -> Dict[str, NmapScanResult]:
        """
        Batch port scan for multiple hosts.

        Used by: Asset Discovery scanning all discovered hosts concurrently.
        Nmap handles internal parallelism; no need for per-host threading here.

        Args:
            targets:   List of IPs.
            intensity: "basic" | "normal" | "deep"

        Returns:
            Dict mapping IP → NmapScanResult.
        """
        if not NMAP_AVAILABLE or not targets:
            return {ip: self._unavailable_result(ip) for ip in targets}

        target_str = " ".join(targets)
        port_arg = self._TOP_PORTS.get(intensity, "-F")
        args = f"-sS {port_arg} --open -T4"

        multi = self._run(target_str, args)
        # python-nmap returns one result per host — we need to demux
        # by running individual scans here
        # (python-nmap's all_hosts() handles multi-host correctly)
        return self._run_multi(targets, args)

    # ── Internal execution engine ─────────────────────────────────────────────

    def _run(self, target: str, args: str) -> NmapScanResult:
        """Execute nmap and parse results for a single target."""
        if not _NMAP_LIB_AVAILABLE:
            return self._run_subprocess(target, args)

        t0 = time.time()
        try:
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
            log.warning("NmapScanner._run(%s) error: %s", target, exc)
            ip = target.split()[0] if target else "0.0.0.0"
            return NmapScanResult(ip=ip, state="error", scan_duration=time.time() - t0)

    def _run_multi(self, targets: List[str], args: str) -> Dict[str, NmapScanResult]:
        """Execute nmap for multiple targets, return per-IP results."""
        if not _NMAP_LIB_AVAILABLE or not NMAP_AVAILABLE:
            return {ip: self._unavailable_result(ip) for ip in targets}

        target_str = " ".join(targets)
        t0 = time.time()
        try:
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
            log.warning("NmapScanner._run_multi error: %s", exc)
            return {ip: self._unavailable_result(ip) for ip in targets}

    def _run_subprocess(self, target: str, args: str) -> NmapScanResult:
        """
        Subprocess fallback when python-nmap is not installed.
        Calls nmap directly and parses XML output.
        """
        import subprocess, tempfile, os

        t0 = time.time()
        xml_out = tempfile.mktemp(suffix=".xml")
        cmd = ["nmap", "-oX", xml_out] + args.split() + [target]
        if self.sudo:
            cmd = ["sudo"] + cmd

        try:
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
