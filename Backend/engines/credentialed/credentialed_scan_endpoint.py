"""
credentialed_scan_endpoint.py
-------------------------------
Drop-in addition to Backend/main.py.

HOW TO INTEGRATE:
-----------------
1. Copy the imports block below and add them to the top of main.py
   (after the existing imports).

2. Copy the Pydantic model CredentialedScanRequest below main.py's
   existing request models section.

3. Copy the @app.post("/scan/credentialed") route into main.py
   (after the existing /scan/advanced-scan route is a good spot).

4. Add `paramiko==3.4.0` to requirements.txt.

This file exists as documentation / reference. All actual code blocks
are clearly delimited so you can paste them individually.
"""

# ============================================================
# BLOCK 1 — Add these imports to the top of main.py
# (after: from scans.db_helpers import create_scan, update_scan_phase)
# ============================================================

IMPORTS_TO_ADD = """
from engines.credentialed.ssh_scanner   import SSHScanner, PARAMIKO_AVAILABLE
from engines.credentialed.linux_collector import LinuxCollector
from engines.credentialed.vuln_matcher  import VulnMatcher
"""

# ============================================================
# BLOCK 2 — Add this Pydantic model to main.py
# (after the existing AdvancedScanRequest model)
# ============================================================

MODEL_TO_ADD = '''
class CredentialedScanRequest(BaseModel):
    """
    Request model for credentialed (SSH) scanning.

    Credentials are NEVER stored — they are used for the duration of the
    SSH session and then immediately discarded (Option A).

    Example::

        {
            "ip":       "192.168.1.10",
            "username": "root",
            "password": "mysecretpass",
            "port":     22,
            "auth_method": "password",
            "sections": ["system_info", "packages", "services",
                         "ports", "users", "security", "network", "history"]
        }
    """
    ip:          str            = Field(...,  example="192.168.1.10",  description="Target IP or hostname")
    username:    str            = Field(...,  example="root",           description="SSH username")
    password:    Optional[str]  = Field(None, example="mysecretpass",  description="SSH password (discarded after use)")
    key_path:    Optional[str]  = Field(None, description="Path to SSH private key on the server (alternative to password)")
    port:        int            = Field(22,   ge=1, le=65535,          description="SSH port")
    auth_method: str            = Field("password", description="'password' or 'key'")
    sections:    Optional[List[str]] = Field(
        None,
        description=(
            "Which data categories to collect. "
            "None = all. "
            "Options: system_info | packages | services | ports | users | security | network | history"
        ),
    )
'''

# ============================================================
# BLOCK 3 — Add this route to main.py
# (after the existing /scan/advanced-scan route)
# ============================================================

ROUTE_TO_ADD = '''
@app.post("/scan/credentialed", tags=["Credentialed Scans"])
async def scan_credentialed(
    req:  CredentialedScanRequest,
    db:   Session = Depends(get_db),
    user: User    = Depends(get_current_user),
):
    """
    🔐 Credentialed SSH Scan (Linux targets).

    Logs into the target via SSH, collects full system information, and
    matches installed package versions against a CVE database.

    **Key differences from unauthenticated scans:**
    - Exact OS version (not guessed from TTL)
    - Exact kernel version
    - Full installed package list with versions
    - Running services list
    - Open socket table (not just TCP connect)
    - Users, sudo rules, SUID binaries, cron jobs
    - Login history and failed login count
    - CVE accuracy ~90% vs ~30% for banner-based matching

    **Security:** Credentials are NEVER stored. They are used for the
    SSH connection duration and immediately discarded (Option A).

    Example request::

        POST /scan/credentialed
        {
            "ip":       "192.168.1.10",
            "username": "root",
            "password": "mysecretpass",
            "port":     22
        }
    """
    import time

    if not PARAMIKO_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="Credentialed scanning requires paramiko. Run: pip install paramiko==3.4.0",
        )

    start_time = time.time()

    # ── Quick TCP check before attempting SSH ──────────────────────────────
    if not SSHScanner.test_connectivity(req.ip, req.port, timeout=5):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot reach {req.ip}:{req.port} — host is down or port is closed.",
        )

    # ── Connect and collect ────────────────────────────────────────────────
    try:
        with SSHScanner(
            ip        = req.ip,
            username  = req.username,
            password  = req.password if req.auth_method == "password" else None,
            key_path  = req.key_path  if req.auth_method == "key"      else None,
            port      = req.port,
            timeout   = 15,
        ) as ssh:
            collector = LinuxCollector(ssh)
            system_data = collector.collect_all(sections=req.sections)

    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        log.exception("Unexpected error during credentialed scan of %s", req.ip)
        raise HTTPException(status_code=500, detail=f"Scan error: {exc}")

    # ── CVE matching on installed packages ────────────────────────────────
    packages = system_data.get("packages", [])
    matcher  = VulnMatcher()
    raw_findings = matcher.match_packages(packages)
    cve_list     = matcher.to_report_format(raw_findings)

    # ── Build severity summary ────────────────────────────────────────────
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for cve in cve_list:
        sev = cve.get("severity", "Info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    scan_duration = round(time.time() - start_time, 2)

    # ── Persist to DB (no credentials stored) ────────────────────────────
    scan = create_scan(
        db           = db,
        user_id      = user.id,
        target       = req.ip,
        scan_type    = "credentialed",
        phase1_data  = {
            "data":    [{"ip_address": req.ip, "is_active": True}],
            "summary": {
                "total_hosts": 1,
                "active_hosts": 1,
                "scan_type":   "credentialed",
                "scan_duration": scan_duration,
            },
        },
    )

    # ── Response ───────────────────────────────────────────────────────────
    return {
        "success":      True,
        "scan_id":      scan.id,
        "scan_type":    "credentialed",
        "target":       req.ip,
        "username":     req.username,
        # credentials NOT echoed back
        "system_info":  {
            "os_name":         system_data.get("os_name", ""),
            "os_version_id":   system_data.get("os_version_id", ""),
            "kernel_version":  system_data.get("kernel_version", ""),
            "hostname":        system_data.get("hostname_fqdn", ""),
            "uptime":          system_data.get("uptime", ""),
            "cpu_model":       system_data.get("cpu_model", ""),
            "cpu_count":       system_data.get("cpu_count", ""),
            "cpu_arch":        system_data.get("cpu_arch", ""),
            "memory_summary":  system_data.get("memory_summary", {}),
            "disk_usage":      system_data.get("disk_usage", []),
        },
        "packages":             packages,
        "package_count":        len(packages),
        "running_services":     system_data.get("running_services", []),
        "open_ports_credentialed": system_data.get("open_ports_credentialed", []),
        "users":                system_data.get("users", []),
        # Security audit
        "suid_binaries":        system_data.get("suid_binaries", []),
        "world_writable_dirs":  system_data.get("world_writable_dirs", []),
        "sudo_nopasswd":        system_data.get("sudo_nopasswd", False),
        "sudo_rules_raw":       system_data.get("sudo_rules_raw", ""),
        "cron_info_raw":        system_data.get("cron_info_raw", ""),
        "security_issues":      system_data.get("security_issues", []),
        # Login history
        "failed_login_count":   system_data.get("failed_login_count", 0),
        "brute_force_warning":  system_data.get("brute_force_warning", False),
        "failed_logins_recent": system_data.get("failed_logins_recent", []),
        # Network
        "network_interfaces_raw": system_data.get("network_interfaces_raw", ""),
        "env_vars_flagged":       system_data.get("env_vars_summary", []),
        # CVEs
        "cves":                   cve_list,
        "cve_count":              len(cve_list),
        "severity_summary":       severity_counts,
        # Scan metadata
        "scan_duration":          scan_duration,
    }
'''
