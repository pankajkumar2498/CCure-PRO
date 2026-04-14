# CCure Audit PRO — Credentialed Scanning

**Version:** 1.0.0

---

## Overview

Credentialed scanning provides a significantly deeper view of a target than network-based scanning alone. By authenticating to a host via SSH, the scanner can:

- Enumerate all installed packages with exact version numbers
- Match installed packages against NVD CVE constraints (far more accurate than banner-based matching)
- Detect misconfigurations: SUID binaries, world-writable directories, sudo rules, cron jobs
- Identify security events: failed login counts, brute-force patterns
- Collect hardware and system inventory: CPU, memory, disk usage, network interfaces
- List running services and open ports as seen from inside the host (bypasses host-based firewall rules)

This maps directly to the "credentialed scan" concept in commercial scanners like Nessus, which uses authenticated access to avoid false negatives caused by firewall filtering.

---

## Supported Protocols and Targets

| Protocol | Supported | Notes                                         |
|----------|-----------|-----------------------------------------------|
| SSH v2   | Yes       | Linux and Windows targets (via Paramiko 3.4)  |
| SSH v1   | No        | Deprecated and insecure — not supported       |
| WinRM    | Planned   | WindowsCollector exists; WinRM endpoint not yet exposed |
| RDP      | No        | Not in scope                                  |
| SNMP v3  | No        | Read-only community discovery via unauthenticated probe only |

---

## Authentication Methods

### Password Authentication
```json
{
  "auth_method": "password",
  "username": "admin",
  "password": "secret"
}
```

### SSH Key Authentication
```json
{
  "auth_method": "key",
  "username": "admin",
  "key_path": "/path/to/private_key"
}
```

The `key_path` must be accessible to the backend process. It is used directly by Paramiko's `RSAKey.from_private_key_file()`.

---

## Credential Security Policy

> **Credentials are never persisted.**

This is a hard architectural guarantee:

1. Credentials (password or key path) are received in the POST body of `/scan/credentialed`
2. They are passed only to the `SSHScanner` constructor
3. `SSHScanner` opens a Paramiko transport, authenticates, and holds the session for the duration of collection
4. When the `with SSHScanner(...) as ssh:` block exits, the Paramiko connection is closed
5. No credential field is written to the `Scan` or `ScanPhaseResult` database tables
6. No credential field appears in any log output
7. The stored report includes only `username` (for audit attribution) — never the password or key material

This design is intentional. If credential storage is required for scheduled or recurring scans, it must be implemented as an external secrets management integration (e.g., HashiCorp Vault, AWS Secrets Manager).

---

## Pre-Flight Checks

Before opening an SSH connection, the backend performs a TCP connectivity check:

```python
SSHScanner.test_connectivity(req.ip, req.port, timeout=5)
```

This attempts a raw TCP connect to `ip:port`. If it fails, the endpoint returns `400` immediately without attempting SSH authentication. This prevents long timeout hangs and provides a clear diagnostic message to the caller.

---

## OS Auto-Detection

When `os_type="auto"` (default), the backend probes the target to determine the operating system:

```
1. SSH connect
2. Run: uname -s
   - If succeeds and stdout is non-empty → os_type = "linux"
3. Else run: cmd /c ver
   - If succeeds → os_type = "windows"
4. Else default → os_type = "linux"
```

Explicit override with `os_type="linux"` or `os_type="windows"` skips the probe.

---

## Linux Collection Details (`LinuxCollector`)

### Package Enumeration
The collector attempts both Debian and RPM package manager commands:

- `dpkg -l` → Debian/Ubuntu systems
- `rpm -qa --queryformat '%{NAME} %{VERSION}-%{RELEASE}\n'` → RHEL/CentOS/Fedora systems

The first command that returns results determines the package list. Output is parsed into `{"name": str, "version": str}` dicts.

### Security Audit Checks

| Check                  | Method                                                       | Risk                    |
|------------------------|--------------------------------------------------------------|-------------------------|
| SUID binaries          | `find / -perm -4000 -type f` (25s timeout, max 100 results) | Privilege escalation    |
| World-writable dirs    | `find / -perm -0002 -type d` (25s timeout, max 50 results)  | Unauthorized write      |
| Passwordless sudo      | `sudo -ln` → check for NOPASSWD rules                        | Privilege escalation    |
| Failed login count     | `lastb -n 20` or journalctl SSHD                             | Brute force detection   |
| Environment variables  | `env` → flag secrets in var names (KEY, SECRET, TOKEN, PASS) | Credential leakage      |
| Cron jobs              | `crontab -l` + `ls /etc/cron*`                               | Persistence mechanism   |

### Brute Force Warning
`brute_force_warning: true` is set if `failed_login_count ≥ 10` within the last 20 entries from `lastb`.

---

## Windows Collection Details (`WindowsCollector`)

Windows targets must have OpenSSH Server installed and running. The collector uses PowerShell and cmd commands over the SSH channel.

Collected data mirrors the Linux collector's sections: system info, installed software (from registry/WMI), running services, open ports, users, and security configuration.

---

## Selectable Collection Sections

The `sections` field allows partial collection to reduce scan time when only specific data is needed:

| Section       | Data Collected                                        |
|---------------|-------------------------------------------------------|
| `system_info` | OS, kernel, hostname, uptime, CPU, memory, disk       |
| `packages`    | Installed package list with versions                  |
| `services`    | Running systemd/service units                         |
| `ports`       | Open ports (via ss/netstat from inside the host)      |
| `users`       | Local user accounts (/etc/passwd)                     |
| `security`    | SUID binaries, world-writable dirs, sudo rules, cron  |
| `network`     | Network interfaces, ARP table                         |
| `history`     | Login history, failed logins, recent events           |

Pass `"sections": null` (or omit the field) to collect all sections.

---

## CVE Matching (Package-Version)

After collection, the installed package list is passed to `VulnMatcher.match_packages()`. See `CVE_INTEGRATION.md` for the full matching algorithm.

The key advantage over network scanning is precision:
- Network scanning sees: `banner = "SSH-2.0-OpenSSH_8.2p1"` → fuzzy match
- Credentialed scanning sees: `dpkg -l | grep openssh → openssh-server 1:8.2p1-4ubuntu0.5` → exact version with constraint check

---

## Report Structure

The credentialed scan report is stored in the database as a single `phase3` (`credentialed`) payload and the scan is immediately marked `status="complete"`. No phase 1 or phase 2 steps precede a credentialed scan — it is an independent scan type.

Report PDF is generated and stored at completion. The `scan_id` returned in the response can be used with `GET /reports/download/{scan_id}` to retrieve the PDF.

---

## Setting Up Windows Targets

For Windows targets to accept SSH-based credentialed scans, the `scripts/` directory contains a PowerShell preparation suite:

| Script                              | Purpose                                           |
|-------------------------------------|---------------------------------------------------|
| `Prepare-WindowsForVulnScan.ps1`    | Installs OpenSSH, configures firewall, sets up WMI |
| `Verify-WindowsScanReadiness.ps1`   | Pre-scan checklist for Windows targets             |
| `Diagnose-WindowsScanIssues.ps1`    | Troubleshoot connectivity and permission issues    |
| `Deploy-ScanPrepToMultiple.ps1`     | Bulk deployment to multiple Windows hosts          |

Refer to `scripts/WINDOWS_SCAN_SETUP_GUIDE.md` for the complete Windows setup procedure.

---

## Security Considerations

1. **Network exposure:** SSH must be accessible from the scanner host. Restrict SSH access to scanner IP only where possible.
2. **Least privilege:** The SSH user should be a dedicated scan account with sudo read-only access (for `sudo -ln`) rather than the root account.
3. **Key management:** If using key-based auth, the private key should be owned and readable only by the process user running the backend.
4. **Timeout controls:** The SUID and world-writable directory searches have explicit 25-second timeouts to prevent indefinite hangs on large filesystems.
5. **No stored credentials:** Verify this guarantee is maintained if extending the credentialed engine with any new persistence logic.
