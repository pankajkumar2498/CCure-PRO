# CCure Audit PRO — Scan Engine Design

**Version:** 1.0.0

---

## Overview

CCure's scan pipeline is composed of four distinct engines, each responsible for one phase of analysis. Engines are stateless — they accept a list of host dicts, mutate them in-place or return new enriched dicts, and pass the output to the next engine. No engine has knowledge of the HTTP layer or the database.

```
                Phase 1              Phase 2              Phase 3 + 4
Targets ──► DiscoveryEngine ──► PortEngine ──────► VulnerabilityEngine
                                                          │
                                                   Plugin Registry:
                                                   ├── tls_scanner
                                                   ├── http_analyzer
                                                   ├── ssh_probe
                                                   ├── smb_probe
                                                   ├── snmp_probe
                                                   ├── udp_scanner
                                                   ├── icmp_probe
                                                   ├── ftp_checker
                                                   └── cve_engine (last)
```

Independently, for credentialed scanning:

```
SSH Target ──► SSHScanner ──► LinuxCollector / WindowsCollector ──► VulnMatcher
```

---

## Phase 1 — Host Discovery Engine

**Module:** `engines/discovery/discovery_engine.py`  
**Class:** `DiscoveryEngine`

### Purpose
Determine which IP addresses in the target range are live (reachable). Produces a host dict for every IP — both active and inactive.

### Scan Modes

| Mode       | Mechanism                                                     | Privilege Required |
|------------|---------------------------------------------------------------|--------------------|
| `arp`      | Layer-2 ARP broadcast via Scapy `srp(Ether/ARP)`             | Root               |
| `ping`     | ICMP Echo Request via Scapy `sr(IP/ICMP)`                    | Root               |
| `tcp`      | Async TCP `connect()` to ports 80, 443, 22, 445, 3389        | No                 |
| `full`     | ARP + ICMP + TCP SYN + UDP in sequence                        | Root               |
| `adaptive` | LAN subnet → ARP; WAN → TCP SYN; fallback → TCP connect       | Root (preferred)   |
| `stealth`  | Fragmented packets with low TTL to evade stateful inspection   | Root               |

### Privilege Downgrade
If the scanner runs without root/administrator privileges and an elevated mode is requested, it automatically switches to TCP connect and logs a warning in `metadata.privilege_warning`.

### OS Fingerprinting (Phase 1)
Where possible (ARP/ICMP responses), TTL and TCP window size are extracted from Scapy response packets and passed to `core.risk.fingerprint_os()`:
- TTL ≤ 64 → Linux/Unix
- TTL ≤ 128 → Windows
- TCP window 65535 → Windows 7/2008
- TCP window 8192 → Windows XP/2003

### Output Schema (per host)

```python
{
    "ip":            "192.168.1.10",
    "is_active":     True,
    "mac":           "aa:bb:cc:dd:ee:ff",
    "method":        "ARP",            # or ICMP, TCP, ADAPTIVE, etc.
    "elapsed_ms":    1.3,
    "os_guess":      "Linux",
    "os_confidence": "Medium",
    "confirmations": ["ARP", "ICMP"]   # list of probes that confirmed activity
}
```

`confirmations` length determines detection confidence: ≥2 probes or ARP confirmation → `"High"`.

---

## Phase 2 — Port Engine

**Module:** `engines/port/port_engine.py`  
**Class:** `PortEngine`

### Purpose
For each active host, determine which TCP/UDP ports are open and grab service banners. Mutates host dicts in-place by adding `open_ports` and `udp_services`.

### Port Lists by Intensity

| Intensity | Port List        | Count          | Use Case                                  |
|-----------|------------------|----------------|-------------------------------------------|
| `light`   | `SCAN_PORTS_QUICK` | 68 ports     | Quick scan — top critical ports only      |
| `normal`  | `SCAN_PORTS_FULL`  | All in PORT_DB | Standard audit                           |
| `deep`    | `SCAN_PORTS_FULL`  | All in PORT_DB | Extended timeout + deeper banner grab    |

### TCP Scanning
Uses Python `asyncio` for concurrent non-blocking TCP connect attempts. For each open port:
1. Generic banner read (first 1024 bytes after connect)
2. Protocol-specific probe (if port is in `_PROTOCOL_PROBES`):
   - Databases: MySQL, PostgreSQL, MSSQL, MongoDB, Redis
   - Remote Access: RDP, VNC
   - Mail: SMTP, POP3, IMAP
   - File Transfer: FTP
3. TLS upgrade attempt (ports 443, 8443, 465, 993, 995)
4. Version extraction via regex on banner string
5. CVE pre-screening via `core.utils.lookup_cve()` (hint-based, before full CVE engine)

### UDP Scanning
Six UDP services are probed on every scan regardless of intensity:

| Port | Service  | Risk Rating | Notes                                    |
|------|----------|-------------|------------------------------------------|
| 53   | DNS      | High        | Zone transfer exposure                   |
| 67   | DHCP     | High        | Rogue DHCP risk                          |
| 123  | NTP      | Medium      | Amplification attack surface             |
| 161  | SNMP     | High        | Community string leakage                 |
| 162  | SNMP-trap| Medium      | Trap receiver                            |
| 514  | Syslog   | Medium      | Plaintext log transmission               |
| 1900 | UPnP     | Medium      | Universal Plug and Play exposure         |

### Output Schema (additions to host dict)

```python
{
    "open_ports": [
        {
            "port":    22,
            "service": "ssh",
            "state":   "open",
            "banner":  "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
            "version": "8.2p1",
            "risk":    "Medium",
            "cves":    []
        },
        ...
    ],
    "udp_services": [
        {"port": 161, "service": "snmp", "risk": "High", "state": "open"}
    ]
}
```

---

## Phase 3 + 4 — Vulnerability Engine

**Module:** `engines/vulnerability/vulnerability_engine.py`  
**Class:** `VulnerabilityEngine`

### Purpose
Deep protocol-level analysis and vulnerability detection for each active host with known open ports. Phase 3 runs all registered plugins; Phase 4 (risk scoring) runs immediately after as part of the same engine.

### Plugin Architecture
The engine maintains an ordered `PLUGINS` list. Each plugin is a Python module exposing a single function:

```python
def run(ip: str, open_ports: List[int], **kwargs) -> Dict:
    ...
```

The returned dict is merged into the host record. List fields (`cves`, `udp_services`) are extended rather than replaced.

**Plugin execution:** All plugins run concurrently via `ThreadPoolExecutor(max_workers=len(PLUGINS))`. The CVE engine runs serially after all other plugins complete — it needs full banner data from other plugins to perform accurate matching.

A single plugin failure never aborts the host scan. Exceptions are caught per-plugin and logged.

### Rate Limiting
A `TokenBucket` (from `core.utils`) limits total scan throughput. Default rate: 200 tokens/second. One token is consumed per host before plugins execute. This prevents network flooding in large subnets.

---

## Vulnerability Plugins

### `tls_scanner.py`
Probes HTTPS/TLS on standard ports (443, 8443, 465, 993, 995).

Checks:
- Protocol version (TLS 1.0/1.1 → flagged as weak)
- Cipher suite weakness
- Certificate expiry
- Self-signed certificate detection
- Subject Alternative Names (SANs)
- TLS grade assignment (A/B/C/F)

Output key: `tls_info` (TLSInfo dataclass serialized to dict)

---

### `http_analyzer.py`
Sends HTTP GET to detected web servers. Checks response headers for security posture.

Checks:
- `Strict-Transport-Security` (HSTS)
- `X-Frame-Options`
- `Content-Security-Policy`
- `X-Content-Type-Options`
- `X-XSS-Protection`
- HTTP → HTTPS redirect enforcement
- Server header exposure (version disclosure risk)

Output key: `http_audit` (HTTPAudit dataclass serialized to dict)

---

### `ssh_probe.py`
Connects to SSH port (22, or any port with `ssh` service) and reads the SSH version banner.

Collects:
- SSH protocol version
- Software version string
- Key exchange algorithm list (KEX)
- Supported host key types

Flags:
- SSH-1.x as critical (deprecated, known-vulnerable protocol)
- Weak KEX algorithms

Output key: `ssh_info`

---

### `smb_probe.py`
Probes port 445 to determine SMB protocol version.

Detection:
- SMBv1 detection via SMB negotiate packet (Scapy if available; socket fallback)
- SMBv2/v3 detection
- SMBv1 flagged as **Critical** — known EternalBlue (MS17-010) exposure surface

Output key: `smb_info`

---

### `snmp_probe.py`
Sends SNMP GET request with community string `public` to port 161.

Collects:
- `sysDescr` — OS/device description
- `sysName` — device hostname
- Response status (confirms community string is accepted)

Flags default community string acceptance as a **High** severity finding.

Output key: `snmp_info`

---

### `udp_scanner.py`
Probes common UDP services not covered by the port engine's initial UDP pass.

Output key: `udp_services` (extended, not replaced)

---

### `icmp_probe.py`
Sends ICMP echo requests via Scapy (if available).

Collects:
- Round-trip time
- TTL from response (used for OS fingerprinting refinement)

Output key: `icmp_info`

---

### `ftp_checker.py`
Connects to FTP port (21) and attempts anonymous authentication.

Result:
- `anonymous_allowed: True/False`
- Anonymous FTP flagged as **High** severity

Output key: `ftp_info` (merged into host dict)

---

### `cve_engine.py`
Runs last — after all other plugins have populated their data. Correlates open port service banners against the NVD CVE database (`cves.db`).

Matching logic:
1. Extract service name and version from each `open_port` dict
2. Query `cves.db` with `LIKE %service_name%` against `affected_software` and `description` columns
3. Return up to 20 CVEs per service, sorted by CVSS score descending
4. Falls back to `CVE_HINTS` in `core.constants` if `cves.db` is unavailable

Output key: `cves` (extended, not replaced; deduplication happens in risk scorer)

---

## Phase 4 — Risk Scoring (within VulnerabilityEngine)

After all plugins complete, `_score_host()` is called per host:

1. **CVE deduplication** — `core.risk.deduplicate_cves()` removes duplicate CVE IDs (plugins may produce overlapping matches)
2. **Score calculation** via `core.risk.calculate_risk()`:

| Input                      | Score Contribution                        |
|----------------------------|-------------------------------------------|
| Each open port `risk` field | Critical=25, High=15, Medium=8, Low=3, Info=0 |
| CVSS ≥ 9.0 (Critical)      | +20 per CVE                               |
| CVSS 7.0–8.9 (High)        | +10 per CVE                               |
| CVSS 4.0–6.9 (Medium)      | +5 per CVE                                |
| CVSS < 4.0 (Low)           | +2 per CVE                                |
| HTTP header issue           | +2 per missing/misconfigured header       |
| TLS cert expired            | +15                                       |
| TLS self-signed             | +10                                       |
| TLS weak cipher             | +10                                       |
| TLS grade F                 | +20                                       |
| Maximum cap                 | 100                                       |

3. **Risk level assignment:**

| Score Range | Level    |
|-------------|----------|
| 75–100      | Critical |
| 50–74       | High     |
| 25–49       | Medium   |
| 10–24       | Low      |
| 0–9         | Info     |

Output fields added to host: `host_risk_score` (int, 0–100), `host_risk_level` (string)

---

## Credentialed Scanning Engine

### `ssh_scanner.py` — SSHScanner
A context-managed Paramiko SSH session wrapper. Provides:
- `test_connectivity(ip, port, timeout)` — static pre-check via TCP connect before attempting SSH
- `run(command, timeout)` — execute a remote command and return `CommandResult(stdout, stderr, exit_code, success)`
- Auto-detection of OS type via `uname -s` (Linux) vs `cmd /c ver` (Windows)

Credentials are passed only to the constructor and used only for the session lifetime. They are **never written to disk or stored in any database**.

---

### `linux_collector.py` — LinuxCollector
Executes a defined set of SSH commands on a Linux target and parses output into structured dicts.

**Command set (COMMANDS dict):**

| Key              | Command                                                       |
|------------------|---------------------------------------------------------------|
| `os_release`     | `cat /etc/os-release`                                        |
| `kernel`         | `uname -r`                                                    |
| `hostname`       | `hostname -f`                                                 |
| `uptime`         | `uptime -p`                                                   |
| `packages_deb`   | `dpkg -l` (Debian/Ubuntu)                                     |
| `packages_rpm`   | `rpm -qa --queryformat ...` (RHEL/CentOS)                    |
| `running_svcs`   | `systemctl list-units --type=service --state=running`         |
| `open_ports`     | `ss -tlnp` (fallback: `netstat -tlnp`)                       |
| `users`          | `cat /etc/passwd`                                             |
| `sudo_rules`     | `sudo -ln`                                                    |
| `suid_files`     | `find / -perm -4000 -type f` (25s timeout, max 100 results)  |
| `world_writable` | `find / -perm -0002 -type d` (25s timeout, max 50 results)   |
| `cpu`            | `lscpu`                                                       |
| `memory`         | `free -h`                                                     |
| `disk`           | `df -h`                                                       |
| `failed_logins`  | `lastb -n 20` or journalctl SSHD entries                      |
| `env_vars`       | `env`                                                         |

**Selectable sections:** `system_info`, `packages`, `services`, `ports`, `users`, `security`, `network`, `history`

---

### `windows_collector.py` — WindowsCollector
Equivalent collector for Windows targets accessed over SSH (e.g., OpenSSH on Windows Server). Uses PowerShell and cmd commands.

---

### `vuln_matcher.py` — VulnMatcher
Matches installed packages against the CVE database using NVD-sourced version constraint data.

**Matching algorithm:**
1. For each installed package (name + version from package manager)
2. Query `cves.db` for rows where `affected_software LIKE %name%`
3. For each candidate CVE, extract `cpeMatch` constraints from the `affected_software` JSON blob
4. Apply version range check: `min_ver ≤ installed_ver < max_ver`
5. If within range → emit `CredentialedCVE` finding

**Version parsing** handles Debian epoch prefixes (`1:7.6p1`), distribution suffixes (`ubuntu`, `el9`), and letter suffixes (`1.1.1f` → numeric offset).

This is significantly more accurate than banner-based matching because the exact package version is known from the package manager rather than inferred from a service banner.
