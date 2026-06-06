"""
scans/legacy_json_builder.py
───────────────────────────────────────────────────────────────────────────────
Dynamically reconstructs the legacy JSON payload from the normalized 
relational database tables (Assets, Services, Vulnerabilities).
Ensures the frontend UI requires no changes to display newly stored scans.
"""

import base64
import re
import zlib
from pathlib import Path

from sqlalchemy.orm import Session
from sqlalchemy import or_

from db.models.assets import Asset
from db.models.findings import Service, AssetVulnerability, VulnerabilityDefinition
from db.models.scans import Scan, ScanPhase


BACKEND_DIR = Path(__file__).absolute().parents[1]

from typing import Optional, List, Tuple, Dict

def _resolve_backend_path(path_value: Optional[str]) -> Optional[Path]:
    if not path_value:
        return None
    path = Path(str(path_value))
    if not path.is_absolute():
        path = BACKEND_DIR / path
    try:
        resolved = path.resolve()
        resolved.relative_to(BACKEND_DIR)
        return resolved
    except Exception:
        return None


def _decode_pdf_string(value: str) -> str:
    def repl(match):
        token = match.group(1)
        if token.isdigit():
            return chr(int(token, 8))
        return {
            "n": "\n",
            "r": "\r",
            "t": "\t",
            "b": "\b",
            "f": "\f",
            "(": "(",
            ")": ")",
            "\\": "\\",
        }.get(token, token)

    return re.sub(r"\\([0-7]{1,3}|.)", repl, value)


def _extract_reportlab_pdf_strings(path_value: Optional[str]) -> List[str]:
    path = _resolve_backend_path(path_value)
    if not path or not path.is_file() or path.suffix.lower() != ".pdf":
        return []

    data = path.read_bytes()
    chunks: List[str] = []
    pos = 0
    while True:
        start = data.find(b"stream", pos)
        if start < 0:
            break
        stream_start = start + len(b"stream")
        while data[stream_start:stream_start + 1] in (b"\r", b"\n"):
            stream_start += 1
        stream_end = data.find(b"endstream", stream_start)
        if stream_end < 0:
            break

        raw = data[stream_start:stream_end].strip()
        pos = stream_end + len(b"endstream")
        try:
            decoded = base64.a85decode(raw, adobe=True)
        except Exception:
            decoded = raw
        try:
            chunks.append(zlib.decompress(decoded).decode("latin1", "ignore"))
        except Exception:
            continue

    content = "\n".join(chunks)
    return [
        _decode_pdf_string(match.group(1)).strip()
        for match in re.finditer(r"\(((?:\\.|[^\\)])*)\)\s*Tj", content)
        if match.group(1).strip()
    ]


def _is_pdf_header_token(token: str) -> bool:
    return (
        token in {
            "CDAC Automation Tool",
            "Host Discovery Report",
            "Copyright@CDAC Bangalore RTSG",
            "Host IP",
            "CVE ID",
            "Severity",
            "Package",
            "Description",
            "Service",
            "Status",
            "Value",
            "Property",
            "Version",
            "Has CVE",
        }
        or token.startswith("Generated:")
        or token.startswith("Page ")
    )


def _first_after(strings: List[str], label: str, default: str = "") -> str:
    try:
        idx = strings.index(label)
        return strings[idx + 1] if idx + 1 < len(strings) else default
    except ValueError:
        return default


def _clean_pdf_text(value: str) -> str:
    return value.replace("\x97", "-").strip()


def _count_from_title(strings: List[str], prefix: str) -> int:
    for token in strings:
        if token.startswith(prefix):
            match = re.search(r"\((\d+)", token)
            if match:
                return int(match.group(1))
    return 0


def _section(strings: List[str], start_prefix: str, end_prefixes: Tuple[str, ...]) -> List[str]:
    start = next((i for i, token in enumerate(strings) if token.startswith(start_prefix)), -1)
    if start < 0:
        return []
    end = len(strings)
    for i in range(start + 1, len(strings)):
        if any(strings[i].startswith(prefix) for prefix in end_prefixes):
            end = i
            break
    return [token for token in strings[start + 1:end] if token and not _is_pdf_header_token(token)]


def _raw_section(strings: List[str], start_prefix: str, end_prefixes: Tuple[str, ...]) -> List[str]:
    start = next((i for i, token in enumerate(strings) if token.startswith(start_prefix)), -1)
    if start < 0:
        return []
    end = len(strings)
    for i in range(start + 1, len(strings)):
        if any(strings[i].startswith(prefix) for prefix in end_prefixes):
            end = i
            break
    return [token for token in strings[start + 1:end] if token]


def _recover_credentialed_report_from_pdf(scan: Scan) -> Optional[Dict]:
    strings = _extract_reportlab_pdf_strings(getattr(scan, "report_json_path", None))
    if not strings:
        return None

    target = getattr(scan, "target_str", None) or _first_after(strings, "Target")
    system_tokens = _raw_section(strings, "System Information (Credentialed)", ("System Users", "Running Services"))
    system_info = {
        "os_name": _first_after(system_tokens, "OS"),
        "os_version_id": _first_after(system_tokens, "Version"),
        "kernel_version": _first_after(system_tokens, "Kernel / Build"),
        "hostname": _first_after(system_tokens, "Hostname"),
        "cpu_model": _first_after(system_tokens, "CPU"),
        "cpu_arch": _first_after(system_tokens, "Arch"),
    }

    users = []
    user_tokens = _section(strings, "System Users", ("Running Services",))
    user_tokens = [t for t in user_tokens if t not in {"Username", "UID", "Shell", "Type"}]
    for i in range(0, len(user_tokens) - 3, 4):
        users.append({
            "username": user_tokens[i],
            "uid": user_tokens[i + 1],
            "shell": user_tokens[i + 2],
            "type": user_tokens[i + 3],
        })

    running_services = []
    service_tokens = _section(strings, "Running Services", ("Installed Packages",))
    i = 0
    while i + 2 < len(service_tokens):
        if service_tokens[i].startswith("... and"):
            i += 1
            continue
        running_services.append({
            "name": service_tokens[i],
            "sub_state": service_tokens[i + 1],
            "description": service_tokens[i + 2],
        })
        i += 3

    packages = []
    package_tokens = _section(strings, "Installed Packages", ("Security Audit Findings", "Vulnerabilities / CVEs"))
    i = 0
    while i + 2 < len(package_tokens):
        if package_tokens[i].startswith("... and"):
            i += 1
            continue
        packages.append({
            "name": package_tokens[i],
            "version": package_tokens[i + 1],
            "has_cve": package_tokens[i + 2].upper() == "YES",
        })
        i += 3

    security_issues = []
    security_tokens = _section(strings, "Security Audit Findings", ("Vulnerabilities / CVEs",))
    for i, token in enumerate(security_tokens):
        if token == "Misconfiguration" and i + 1 < len(security_tokens):
            security_issues.append(_clean_pdf_text(security_tokens[i + 1]))

    cves = []
    cve_count = _count_from_title(strings, "  Vulnerabilities / CVEs") or _count_from_title(strings, "Vulnerabilities / CVEs")
    severity_summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    severities = set(severity_summary)
    i = 0
    while i < len(strings):
        if strings[i] != target or i + 3 >= len(strings) or not strings[i + 1].startswith("CVE-"):
            i += 1
            continue
        cve_id = strings[i + 1]
        severity = strings[i + 2] if strings[i + 2] in severities else "Info"
        package = strings[i + 3]
        desc_parts = []
        i += 4
        while i < len(strings):
            token = strings[i]
            if token == target and i + 1 < len(strings) and strings[i + 1].startswith("CVE-"):
                break
            if not _is_pdf_header_token(token):
                desc_parts.append(token)
            i += 1
        severity_summary[severity] = severity_summary.get(severity, 0) + 1
        cves.append({
            "cve_id": cve_id,
            "severity": severity,
            "package": package,
            "description": " ".join(desc_parts).strip(),
        })

    scan_duration = getattr(scan, "duration_seconds", None)
    if scan_duration is None:
        duration_text = _first_after(strings, "Scan Duration")
        match = re.search(r"([\d.]+)", duration_text)
        scan_duration = float(match.group(1)) if match else None

    return {
        "scan_type": "credentialed",
        "target": target,
        "detected_os": "windows" if "windows" in (system_info.get("os_name") or "").lower() else "linux",
        "system_info": system_info,
        "packages": packages,
        "package_count": _count_from_title(strings, "Installed Packages") or len(packages),
        "running_services": running_services,
        "open_ports_credentialed": [],
        "users": users,
        "suid_binaries": [],
        "world_writable_dirs": [],
        "sudo_nopasswd": False,
        "sudo_rules_raw": "",
        "cron_info_raw": "",
        "security_issues": security_issues,
        "failed_login_count": int(_first_after(strings, "Failed Logins", "0").split(" ", 1)[0] or 0),
        "brute_force_warning": False,
        "failed_logins_recent": [],
        "network_interfaces_raw": "",
        "env_vars_flagged": [],
        "cves": cves,
        "cve_count": cve_count or len(cves),
        "severity_summary": severity_summary,
        "scan_duration": scan_duration,
        "recovered_from_report_pdf": True,
    }

def build_legacy_scan_results(db: Session, scan_id: str) -> dict:
    """
    Reconstructs the multi-phase JSON blob shape expected by the React frontend:
    {
      "phase1": { "data": [...], "summary": {...} },
      "phase2": { "data": [...], "summary": {...} },
      ...
    }
    """
    results_out = {}
    
    # 1. Fetch all phases for this scan
    phases = db.query(ScanPhase).filter(ScanPhase.scan_id == scan_id).order_by(ScanPhase.phase_order.asc()).all()
    
    if not phases:
        return results_out

    scan = db.query(Scan).filter(Scan.id == scan_id).first()

    assets = None
    services_by_asset = None
    vulns_by_asset = None

    def _lazy_load_db_relations():
        nonlocal assets, services_by_asset, vulns_by_asset
        if assets is not None: return
        assets = db.query(Asset).outerjoin(Service, Service.asset_id == Asset.id).outerjoin(
            AssetVulnerability, AssetVulnerability.asset_id == Asset.id
        ).filter(
            or_(
                Asset.last_scan_id == scan_id,
                Service.scan_id == scan_id,
                AssetVulnerability.scan_id == scan_id
            )
        ).all()

        services_by_asset = {}
        db_services = db.query(Service).filter(Service.scan_id == scan_id).all()
        for db_svc in db_services:
            services_by_asset.setdefault(db_svc.asset_id, []).append(db_svc)

        vulns_by_asset = {}
        db_vulns = db.query(
            AssetVulnerability, VulnerabilityDefinition
        ).join(
            VulnerabilityDefinition, AssetVulnerability.vuln_id == VulnerabilityDefinition.id
        ).filter(AssetVulnerability.scan_id == scan_id).all()
        
        for av, vdef in db_vulns:
            vulns_by_asset.setdefault(av.asset_id, []).append({
                "cve_id": vdef.cve_id,
                "title": vdef.title,
                "description": vdef.description,
                "severity": vdef.severity,
                "cvss": float(vdef.cvss_v3_score or 0.0),
                "status": av.status
            })

    # 3. Reconstruct Phase payloads based on the actual DB records
    for p in phases:
        phase_key = p.phase_key
        # Convert modern names back to frontend expected legacy names
        legacy_key_map = {
            "host_discovery": "phase1",
            "asset_discovery": "phase2",
            "vulnerability_assessment": "phase3",
            "credentialed": "credentialed"
        }
        out_key = legacy_key_map.get(phase_key, phase_key)
        
        # Extract raw data if it was embedded in the summary (ensures deep probe fidelity)
        raw_data = []
        clean_summary = p.summary or {}
        if isinstance(clean_summary, dict) and "_phase_data" in clean_summary:
            raw_data = clean_summary["_phase_data"]
            # Remove internal key so it doesn't leak to frontend as summary data
            clean_summary = {k: v for k, v in clean_summary.items() if k != "_phase_data"}

        phase_dict = {
            "summary": clean_summary,
            "data": raw_data
        }

        if out_key == "credentialed":
            report = None
            options = getattr(scan, "options", None) or {}
            if isinstance(options, dict):
                report = options.get("credentialed_report")
            if not report and isinstance(p.summary, dict):
                report = p.summary.get("report")
            if not report and scan:
                report = _recover_credentialed_report_from_pdf(scan)
            if not report and scan:
                report = {
                    "scan_type": "credentialed",
                    "target": scan.target_str,
                    "detected_os": (p.summary or {}).get("detected_os", "linux"),
                    "system_info": {},
                    "packages": [],
                    "package_count": (p.summary or {}).get("package_count", 0),
                    "running_services": [],
                    "open_ports_credentialed": [],
                    "users": [],
                    "suid_binaries": [],
                    "world_writable_dirs": [],
                    "sudo_nopasswd": False,
                    "sudo_rules_raw": "",
                    "cron_info_raw": "",
                    "security_issues": [],
                    "failed_login_count": 0,
                    "brute_force_warning": False,
                    "failed_logins_recent": [],
                    "network_interfaces_raw": "",
                    "env_vars_flagged": [],
                    "cves": [],
                    "cve_count": (p.summary or {}).get("cve_count", getattr(scan, "total_vulns", 0) or 0),
                    "severity_summary": {
                        "Critical": getattr(scan, "critical_count", 0) or 0,
                        "High": getattr(scan, "high_count", 0) or 0,
                        "Medium": getattr(scan, "medium_count", 0) or 0,
                        "Low": getattr(scan, "low_count", 0) or 0,
                        "Info": getattr(scan, "info_count", 0) or 0,
                    },
                    "scan_duration": getattr(scan, "duration_seconds", None),
                }
            if report:
                phase_dict["report"] = report
            results_out[out_key] = phase_dict
            continue

        if raw_data:
            # If we have the raw data blob, use it as the source of truth.
            results_out[out_key] = phase_dict
            continue

        _lazy_load_db_relations()
        for asset in assets:
            if out_key == "phase1":
                phase_dict["data"].append({
                    "ip": asset.ip_address,
                    "mac": asset.mac_address,
                    "hostname": asset.hostname,
                    "vendor": asset.vendor or "Unknown",
                    "state": "up" if asset.is_active else "down",
                    # Modern keys used by Phase1Results.jsx and Phase2Results.jsx:
                    "ip_address": asset.ip_address,
                    "mac_address": asset.mac_address,
                    "is_active": asset.is_active,
                    "discovery_method": asset.discovery_method,
                    "response_time_ms": asset.response_time_ms,
                })
            
            elif out_key == "phase2":
                asset_services = services_by_asset.get(asset.id, [])
                if asset_services or asset.last_scan_id == scan_id: 
                    # Include if it had services or was active in this scan
                    ports_list = []
                    for svc in asset_services:
                        ports_list.append({
                            "port": svc.port,
                            "protocol": svc.protocol,
                            "service": svc.service_name,
                            "product": svc.service_product,
                            "version": svc.service_version,
                            "extra": svc.service_extra,
                            "banner": svc.banner,
                            "state": svc.state or "open",
                        })
                    
                    if ports_list:
                        phase_dict["data"].append({
                            "ip": asset.ip_address,
                            "mac": asset.mac_address,
                            "hostname": asset.hostname,
                            "vendor": asset.vendor,
                            "os_guess": asset.os_name,
                            "open_ports": ports_list,
                            # Modern keys:
                            "ip_address": asset.ip_address,
                            "mac_address": asset.mac_address,
                            "is_active": asset.is_active,
                        })

            elif out_key == "phase3":
                asset_vulns = vulns_by_asset.get(asset.id, [])
                if asset_vulns:
                    asset_services = services_by_asset.get(asset.id, [])
                    ports_list = []
                    for svc in asset_services:
                        ports_list.append({
                            "port": svc.port,
                            "protocol": svc.protocol,
                            "service": svc.service_name,
                            "product": svc.service_product,
                            "version": svc.service_version,
                            "extra": svc.service_extra,
                            "banner": svc.banner,
                            "state": svc.state or "open",
                        })
                    phase_dict["data"].append({
                        "ip": asset.ip_address,
                        "ip_address": asset.ip_address,
                        "hostname": asset.hostname,
                        "mac": asset.mac_address,
                        "mac_address": asset.mac_address,
                        "vendor": asset.vendor,
                        "is_active": asset.is_active,
                        "open_ports": ports_list,
                        "os_guess": asset.os_name,
                        "device_category": asset.device_category,
                        "cves": asset_vulns,
                        "vulnerabilities": asset_vulns,
                        "host_risk_score": asset.risk_score or 0,
                        "host_risk_level": (asset.risk_level or "info").title(),
                    })

        results_out[out_key] = phase_dict

    return results_out
