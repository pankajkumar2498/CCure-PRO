# CCure Audit PRO — Data Flow and Processing

**Version:** 1.0.0

---

## Overview

This document traces data from user input through every transformation step to its final resting place in the database and PDF report. Understanding this flow is essential for debugging scan result anomalies or extending the processing pipeline.

---

## 1. Input → Target Expansion

**Entry point:** `POST /scan/host-discovery` body → `ScanOrchestrator.run_host_discovery_only()`

```
User Input: targets = ["192.168.1.0/24", "10.0.0.5"]
                │
                ▼
InputValidator.resolve_target(target)  [for each target]
    ├── type = "cidr"  → ipaddress.ip_network(target).hosts()
    │                   → ["192.168.1.1", "192.168.1.2", ... "192.168.1.254"]
    ├── type = "range" → InputValidator.expand_ip_range(target)
    │                   → ["10.0.0.1", ..., "10.0.0.50"]
    └── type = "ip"    → [resolved_ip]
                │
                ▼
    Deduplicate (dict.fromkeys preserves order)
    all_ips = ["192.168.1.1", ..., "192.168.1.254", "10.0.0.5"]
```

---

## 2. Host Discovery → Raw Host Dicts

**Entry point:** `DiscoveryEngine.run(all_ips, scan_type)`

```
all_ips (flat list)  +  DiscoveryScanType.ADAPTIVE
            │
            ▼
For each IP concurrently:
    ├── ARP probe (if LAN + root)  →  {mac, elapsed_ms, ttl}
    ├── ICMP probe (if root)       →  {elapsed_ms, ttl, window_size}
    └── TCP probe (always fallback)→  {elapsed_ms}
            │
            ▼
Raw host dict (one per IP):
{
    "ip":             "192.168.1.10",
    "is_active":      True,
    "mac":            "aa:bb:cc:dd:ee:ff",
    "method":         "ARP",
    "elapsed_ms":     1.3,
    "os_guess":       "Linux",
    "os_confidence":  "Medium",
    "confirmations":  ["ARP", "ICMP"]
}
```

---

## 3. Raw Dict → HostResult → Phase 1 Dict

**In:** `ScanOrchestrator._format_host(ip, data)` followed by `.to_phase1_dict()`

```
Raw host dict
    │
    ├── Reverse DNS lookup (active hosts only)   → hostname
    ├── Local IP check → enrich with local hostname/MAC if applicable
    ├── ARP cache lookup (fallback for MAC)       → mac
    ├── OUI vendor lookup (manuf.txt)             → vendor
    ├── Confidence calculation:
    │       confirmations ≥ 2 or "ARP" in confs  → "High"
    │       confirmations == 1                    → "Medium"
    │       else                                  → "Low"
    └── Assembles HostResult dataclass
            │
            ▼
    HostResult.to_phase1_dict()
    {
        "ip_address":      "192.168.1.10",
        "is_active":       True,
        "status":          "Active",
        "scan_method":     "ARP",
        "discovery_method": "ARP",   ← frontend alias
        "hostname":        "server01.local",
        "mac_address":     "aa:bb:cc:dd:ee:ff",
        "vendor":          "Dell Inc.",
        "response_time_ms": 1.3,
        "os_guess":        "Linux",
        "os_confidence":   "Medium",
        "confidence":      "High",
        "scan_timestamp":  "2024-01-15T10:05:00"
    }
```

---

## 4. Phase 1 → Database

**In:** `scans.db_helpers.create_scan()`

```
Phase 1 result  +  user_id  +  pipeline_mode
        │
        ▼
Scan row created:
    scans.id            = auto-increment
    scans.user_id       = user.id
    scans.target        = "192.168.1.0/24"
    scans.targets_json  = '["192.168.1.0/24"]'
    scans.scan_type     = "adaptive"
    scans.pipeline_mode = "advanced"
    scans.phase         = 1
    scans.status        = "running"  ← (or "complete" if basic mode)
    scans.summary       = JSON of summary dict
        │
ScanPhaseResult row created:
    scan_id     = scans.id
    phase_key   = "phase1"
    phase_order = 1
    payload     = JSON of {data, summary, metadata}
```

---

## 5. Phase 1 Hosts → Port Engine → Enriched Hosts

**In:** `PortEngine.run(active_hosts)`

```
Active host dicts (is_active=True only)
    │
    ▼
For each host, async TCP connect to each port in port list:
    ├── Port closed  →  skip
    └── Port open    →
            ├── Banner read (recv 1024 bytes)
            ├── Protocol-specific probe (if configured)
            ├── Version extraction from banner (regex)
            ├── TLS upgrade attempt (ports 443/8443/etc.)
            ├── CVE pre-screen via core.utils.lookup_cve()
            └── Append PortResult to host["open_ports"]

UDP probes (6 services, all hosts):
    ├── DNS (53), DHCP (67), NTP (123)
    ├── SNMP (161/162), Syslog (514), UPnP (1900)
    └── Detected → append to host["udp_services"]

OS inference applied (infer_os_from_host):
    - Open ports + banner text + service names
    - Scoring model → assigns os_guess / os_confidence

Mutation: active_hosts list modified in-place
```

---

## 6. Enriched Hosts → Vulnerability Engine → Final Host Record

**In:** `VulnerabilityEngine.run(active_hosts)`

```
Host with open_ports
    │
    ▼
TokenBucket.consume()  [rate limiting]
    │
    ▼
ThreadPoolExecutor — all plugins run concurrently:

    tls_scanner.run()     → {"tls_info": {...}}
    http_analyzer.run()   → {"http_audit": {...}}
    ssh_probe.run()       → {"ssh_info": {...}}
    smb_probe.run()       → {"smb_info": {...}}
    snmp_probe.run()      → {"snmp_info": {...}}
    udp_scanner.run()     → {"udp_services": [...]}
    icmp_probe.run()      → {"icmp_info": {...}}
    ftp_checker.run()     → {"ftp_info": {...}}
        │
        ▼ (all merged into host dict)

cve_engine.run()  [serial, last — needs all banner data]
    → {"cves": [...]}
        │
        ▼ (extended into host["cves"])

_score_host(host):
    deduplicate_cves(host["cves"])
    calculate_risk(open_ports, cves, http_audit, tls_info)
    → host["host_risk_score"] = 72
    → host["host_risk_level"] = "High"

Final host dict → HostResult.to_clean_dict()
    (drops empty/N/A/falsy optional fields for clean JSON output)
```

---

## 7. Phase Results → PDF Report

**In:** `ScanOrchestrator.generate_phase_report()` → `ScanReportGenerator.generate()`

```
Result dict (success, data, summary, metadata)
    │
    ├── scan_type determines report template
    │   ("host_discovery" | "asset_discovery" | "phase_selective_scan" | "credentialed_scan")
    │
    ├── JSON-format PDF:
    │   - reportlab Table with scan results
    │   - Filename: reports/{timestamp}_{scan_type}_json.pdf
    │
    └── XML-format PDF:
        - reportlab Table with hierarchical structure
        - Filename: reports/{timestamp}_{scan_type}_xml.pdf

Returns: {"json_pdf": "/path/to/file.pdf", "xml_pdf": "/path/to/file.pdf"}
Paths stored in scans.report_json_path and scans.report_xml_path
```

---

## 8. Inter-Phase Data Contract

Each phase passes its `data` array directly to the next phase. The receiving engine normalizes keys via `_normalize_host_record()` to handle aliasing between `ip_address` / `ip`, `scan_method` / `discovery_method`, etc.

**Key aliases maintained throughout:**

| Canonical Key     | Aliases Accepted                                 |
|-------------------|--------------------------------------------------|
| `ip`              | `ip_address`                                     |
| `method`          | `scan_method`, `discovery_method`                |
| `elapsed_ms`      | `response_time_ms`                               |

Both canonical and alias forms appear in output for frontend compatibility.

---

## 9. Metadata Propagation

Scan metadata (target string, scan method) is resolved and attached to each phase result via `_resolve_report_context()`. Priority order:

```
1. request.targets (explicit user input)          → highest priority
2. scans.target / scans.targets_json (DB row)     → middle priority
3. host["ip_address"] list from data              → fallback

scan_method:
1. request.scan_type (explicit)
2. scans.scan_type in DB
3. summary.discovery_scan_method in DB blob
4. host["method"] field from data array
```

Phase 2 and Phase 3 also backfill Phase 1 summary counts (total_hosts, active_hosts, inactive_hosts) via `_apply_phase1_summary_hints()` so the final report has complete context even though it only received the enriched active hosts.

---

## 10. Credentialed Scan Data Flow

```
POST /scan/credentialed
    │
    ├── SSHScanner.test_connectivity(ip, port)    [pre-flight TCP check]
    ├── SSHScanner.__enter__()                    [Paramiko connect + auth]
    │       │
    │       ├── os_type="auto" → uname -s → detect Linux/Windows
    │       ├── LinuxCollector(ssh).collect_all() OR WindowsCollector(ssh).collect_all()
    │       │       │
    │       │       ├── Run each COMMAND via ssh.run(cmd, timeout)
    │       │       ├── Parse stdout into structured dicts
    │       │       └── Return merged system_data dict
    │       │
    │       └── SSHScanner.__exit__()             [Paramiko disconnect]
    │
    ├── VulnMatcher().match_packages(system_data["packages"])
    │       │
    │       ├── For each package: SQL query on cves.db
    │       ├── Extract NVD CPE constraints from affected_software JSON
    │       ├── Version range comparison (_version_gte, _version_lt)
    │       └── Return List[CredentialedCVE] sorted by CVSS desc
    │
    ├── Build stored_report dict (system_info, packages, CVEs, security audit)
    ├── create_completed_scan() → DB write (status="complete")
    ├── generate_phase_report() → PDF
    └── Return response with scan_id
```
