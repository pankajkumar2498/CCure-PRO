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

from db.models.assets import Asset
from db.models.findings import AssetVulnerability, Service, VulnerabilityDefinition
from db.models.scans import Scan, ScanPhase
from sqlalchemy import or_
from sqlalchemy.orm import Session

BACKEND_DIR = Path(__file__).absolute().parents[1]

from typing import Dict, List, Optional, Tuple


def _resolve_backend_path(path_value: str | None) -> Path | None:
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


def _extract_reportlab_pdf_strings(path_value: str | None) -> list[str]:
    path = _resolve_backend_path(path_value)
    if not path or not path.is_file() or path.suffix.lower() != ".pdf":
        return []

    data = path.read_bytes()
    chunks: list[str] = []
    pos = 0
    while True:
        start = data.find(b"stream", pos)
        if start < 0:
            break
        stream_start = start + len(b"stream")
        while data[stream_start : stream_start + 1] in (b"\r", b"\n"):
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
        token
        in {
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


def _first_after(strings: list[str], label: str, default: str = "") -> str:
    try:
        idx = strings.index(label)
        return strings[idx + 1] if idx + 1 < len(strings) else default
    except ValueError:
        return default


def _clean_pdf_text(value: str) -> str:
    return value.replace("\x97", "-").strip()


def _count_from_title(strings: list[str], prefix: str) -> int:
    for token in strings:
        if token.startswith(prefix):
            match = re.search(r"\((\d+)", token)
            if match:
                return int(match.group(1))
    return 0


def _section(
    strings: list[str], start_prefix: str, end_prefixes: tuple[str, ...]
) -> list[str]:
    start = next(
        (i for i, token in enumerate(strings) if token.startswith(start_prefix)), -1
    )
    if start < 0:
        return []
    end = len(strings)
    for i in range(start + 1, len(strings)):
        if any(strings[i].startswith(prefix) for prefix in end_prefixes):
            end = i
            break
    return [
        token
        for token in strings[start + 1 : end]
        if token and not _is_pdf_header_token(token)
    ]


def _raw_section(
    strings: list[str], start_prefix: str, end_prefixes: tuple[str, ...]
) -> list[str]:
    start = next(
        (i for i, token in enumerate(strings) if token.startswith(start_prefix)), -1
    )
    if start < 0:
        return []
    end = len(strings)
    for i in range(start + 1, len(strings)):
        if any(strings[i].startswith(prefix) for prefix in end_prefixes):
            end = i
            break
    return [token for token in strings[start + 1 : end] if token]


def _recover_credentialed_report_from_pdf(scan: Scan) -> dict | None:
    strings = _extract_reportlab_pdf_strings(
        getattr(scan, "report_executive_path", None)
    )
    if not strings:
        return None

    # This recovery path only works on PDFs drawn with the base-14 Type1 fonts,
    # whose text is stored as readable ASCII. Reports rendered with an embedded
    # TTF store subset glyph indices instead, so naive extraction yields noise.
    # Without this guard that noise would be assembled into a hollow report and
    # returned as if it were real recovered data.
    if not any(
        marker in strings
        for marker in (
            "System Information (Credentialed)",
            "Installed Packages",
            "Running Services",
            "System Users",
        )
    ):
        return None

    target = getattr(scan, "target_str", None) or _first_after(strings, "Target")
    system_tokens = _raw_section(
        strings,
        "System Information (Credentialed)",
        ("System Users", "Running Services"),
    )
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
    user_tokens = [
        t for t in user_tokens if t not in {"Username", "UID", "Shell", "Type"}
    ]
    for i in range(0, len(user_tokens) - 3, 4):
        users.append(
            {
                "username": user_tokens[i],
                "uid": user_tokens[i + 1],
                "shell": user_tokens[i + 2],
                "type": user_tokens[i + 3],
            }
        )

    running_services = []
    service_tokens = _section(strings, "Running Services", ("Installed Packages",))
    i = 0
    while i + 2 < len(service_tokens):
        if service_tokens[i].startswith("... and"):
            i += 1
            continue
        running_services.append(
            {
                "name": service_tokens[i],
                "sub_state": service_tokens[i + 1],
                "description": service_tokens[i + 2],
            }
        )
        i += 3

    packages = []
    package_tokens = _section(
        strings,
        "Installed Packages",
        ("Security Audit Findings", "Vulnerabilities / CVEs"),
    )
    i = 0
    while i + 2 < len(package_tokens):
        if package_tokens[i].startswith("... and"):
            i += 1
            continue
        packages.append(
            {
                "name": package_tokens[i],
                "version": package_tokens[i + 1],
                "has_cve": package_tokens[i + 2].upper() == "YES",
            }
        )
        i += 3

    security_issues = []
    security_tokens = _section(
        strings, "Security Audit Findings", ("Vulnerabilities / CVEs",)
    )
    for i, token in enumerate(security_tokens):
        if token == "Misconfiguration" and i + 1 < len(security_tokens):
            security_issues.append(_clean_pdf_text(security_tokens[i + 1]))

    cves = []
    cve_count = _count_from_title(
        strings, "  Vulnerabilities / CVEs"
    ) or _count_from_title(strings, "Vulnerabilities / CVEs")
    severity_summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    severities = set(severity_summary)
    i = 0
    while i < len(strings):
        if (
            strings[i] != target
            or i + 3 >= len(strings)
            or not strings[i + 1].startswith("CVE-")
        ):
            i += 1
            continue
        cve_id = strings[i + 1]
        severity = strings[i + 2] if strings[i + 2] in severities else "Info"
        package = strings[i + 3]
        desc_parts = []
        i += 4
        while i < len(strings):
            token = strings[i]
            if (
                token == target
                and i + 1 < len(strings)
                and strings[i + 1].startswith("CVE-")
            ):
                break
            if not _is_pdf_header_token(token):
                desc_parts.append(token)
            i += 1
        severity_summary[severity] = severity_summary.get(severity, 0) + 1
        cves.append(
            {
                "cve_id": cve_id,
                "severity": severity,
                "package": package,
                "description": " ".join(desc_parts).strip(),
                # Reconstructed from a credentialed audit, and tagged as such.
                # Verification asserts credentialed origin from the record
                # rather than inferring it, so a rebuilt record that does not
                # say where it came from is treated as an unverifiable network
                # claim and withheld.
                "detection_method": "credentialed",
            }
        )

    scan_duration = getattr(scan, "duration_seconds", None)
    if scan_duration is None:
        duration_text = _first_after(strings, "Scan Duration")
        match = re.search(r"([\d.]+)", duration_text)
        scan_duration = float(match.group(1)) if match else None

    return {
        "scan_type": "credentialed",
        "target": target,
        "detected_os": (
            "windows"
            if "windows" in (system_info.get("os_name") or "").lower()
            else "linux"
        ),
        "system_info": system_info,
        "packages": packages,
        "package_count": _count_from_title(strings, "Installed Packages")
        or len(packages),
        "running_services": running_services,
        "open_ports_credentialed": [],
        "users": users,
        "suid_binaries": [],
        "world_writable_dirs": [],
        "sudo_nopasswd": False,
        "sudo_rules_raw": "",
        "cron_info_raw": "",
        "security_issues": security_issues,
        "failed_login_count": int(
            _first_after(strings, "Failed Logins", "0").split(" ", 1)[0] or 0
        ),
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


def _load_threat_intel(db: Session, cve_ids: set[str]) -> dict[str, dict]:
    """
    Look up EPSS exploitation probability and CISA KEV membership for a set of CVEs.

    Both datasets are optional. When the tables do not exist (or are empty) this
    returns an empty mapping and the report omits those columns entirely rather
    than displaying a default value that could be mistaken for real data.
    """
    if not cve_ids:
        return {}

    from sqlalchemy import text

    out: dict[str, dict] = {}
    ids = [c for c in cve_ids if c]

    # The epss and kev tables live in the dedicated vulnerability-intelligence
    # database, not the application database, so the lookup runs against that
    # engine. If it is not configured the report simply omits these columns
    # rather than showing a default that could be mistaken for real data.
    from core.vuln_intel import get_vuln_engine

    engine = get_vuln_engine()
    if engine is None:
        return {}

    try:
        with engine.connect() as conn:
            try:
                rows = conn.execute(
                    text(
                        "SELECT cve_id, epss_score, percentile FROM epss "
                        "WHERE cve_id = ANY(:ids)"
                    ),
                    {"ids": ids},
                ).fetchall()
                for row in rows:
                    entry = out.setdefault(row[0], {})
                    entry["epss_score"] = float(row[1]) if row[1] is not None else None
                    entry["epss_percentile"] = (
                        float(row[2]) if row[2] is not None else None
                    )
            except Exception:
                pass

            try:
                rows = conn.execute(
                    text("SELECT cve_id, due_date FROM kev WHERE cve_id = ANY(:ids)"),
                    {"ids": ids},
                ).fetchall()
                for row in rows:
                    entry = out.setdefault(row[0], {})
                    entry["in_kev"] = True
                    entry["kev_due_date"] = str(row[1]) if row[1] else ""
            except Exception:
                pass
    except Exception:
        return out

    return out


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
    phases = (
        db.query(ScanPhase)
        .filter(ScanPhase.scan_id == scan_id)
        .order_by(ScanPhase.phase_order.asc())
        .all()
    )

    if not phases:
        return results_out

    scan = db.query(Scan).filter(Scan.id == scan_id).first()

    assets = None
    services_by_asset = None
    vulns_by_asset = None

    def _lazy_load_db_relations():
        nonlocal assets, services_by_asset, vulns_by_asset
        if assets is not None:
            return
        assets = (
            db.query(Asset)
            .outerjoin(Service, Service.asset_id == Asset.id)
            .outerjoin(AssetVulnerability, AssetVulnerability.asset_id == Asset.id)
            .filter(
                or_(
                    Asset.last_scan_id == scan_id,
                    Service.scan_id == scan_id,
                    AssetVulnerability.scan_id == scan_id,
                )
            )
            .all()
        )

        services_by_asset = {}
        db_services = db.query(Service).filter(Service.scan_id == scan_id).all()
        for db_svc in db_services:
            services_by_asset.setdefault(db_svc.asset_id, []).append(db_svc)

        vulns_by_asset = {}
        db_vulns = (
            db.query(AssetVulnerability, VulnerabilityDefinition)
            .join(
                VulnerabilityDefinition,
                AssetVulnerability.vuln_id == VulnerabilityDefinition.id,
            )
            .filter(AssetVulnerability.scan_id == scan_id)
            .all()
        )

        # Resolve the observed port/service for every finding that carries a
        # service_id. This is what lets the report bind a CVE to a port because
        # the scan actually saw it there, rather than inferring the port from
        # product names appearing in CVE prose.
        service_by_id = {svc.id: svc for svc in db_services}

        # Threat-intel enrichment (EPSS probability + CISA KEV). Both are
        # optional: if the tables are absent the report simply omits the
        # columns rather than substituting placeholder values.
        cve_ids = {(vdef.cve_id or vdef.id) for _, vdef in db_vulns}
        intel = _load_threat_intel(db, cve_ids)

        for av, vdef in db_vulns:
            cve_key = vdef.cve_id or vdef.id

            def _score(value):
                if value is None:
                    return None
                try:
                    return float(value)
                except (ValueError, TypeError):
                    return None

            v3 = _score(vdef.cvss_v3_score)
            v2 = _score(vdef.cvss_v2_score)
            v4 = _score(vdef.cvss_v4_score)
            finding_score = _score(av.cvss_score)

            svc = service_by_id.get(av.service_id) if av.service_id else None
            tintel = intel.get(cve_key, {})

            vulns_by_asset.setdefault(av.asset_id, []).append(
                {
                    "cve_id": cve_key,
                    "cve": cve_key,
                    "title": vdef.title,
                    "description": vdef.description,
                    "severity": av.severity or vdef.severity,
                    # Scores are passed through as-is. None means "not published"
                    # and the report renders it as unscored.
                    "cvss_score": (
                        v3
                        if v3 is not None
                        else (finding_score if finding_score is not None else v4)
                    ),
                    "cvss_v2_score": v2,
                    "cvss_v3_score": v3,
                    "cvss_vector": vdef.cvss_vector,
                    "cwe_ids": vdef.cwe_ids or [],
                    "references": vdef.references or [],
                    "affected_software": vdef.affected_software or [],
                    "plugin_output": av.plugin_output or av.proof or "",
                    "proof": av.proof or av.plugin_output or "",
                    "plugin_family": vdef.source or "General",
                    "source": vdef.source or "General",
                    "published_at": str(vdef.published_at) if vdef.published_at else "",
                    "last_modified_at": (
                        str(vdef.last_modified_at) if vdef.last_modified_at else ""
                    ),
                    "status": av.status,
                    "service_id": av.service_id,
                    "evidence_source": av.evidence_source,
                    "remediation_notes": av.remediation_notes or "",
                    "first_found_at": (
                        str(av.first_found_at) if av.first_found_at else ""
                    ),
                    "last_found_at": str(av.last_found_at) if av.last_found_at else "",
                    # Observed service context, resolved from the service_id FK
                    "port": svc.port if svc else None,
                    "protocol": svc.protocol if svc else None,
                    "service_name": svc.service_name if svc else None,
                    "service_product": svc.service_product if svc else None,
                    "detected_version": svc.service_version if svc else None,
                    # Threat intelligence
                    "epss_score": tintel.get("epss_score"),
                    "epss_percentile": tintel.get("epss_percentile"),
                    "in_kev": tintel.get("in_kev", False),
                    "kev_due_date": tintel.get("kev_due_date", ""),
                }
            )

    # 3. Reconstruct Phase payloads based on the actual DB records
    for p in phases:
        phase_key = p.phase_key
        # Convert modern names back to frontend expected legacy names
        legacy_key_map = {
            "host_discovery": "phase1",
            "asset_discovery": "phase2",
            "vulnerability_assessment": "phase3",
            "credentialed": "credentialed",
        }
        out_key = legacy_key_map.get(phase_key, phase_key)

        # Extract raw data if it was embedded in the summary (ensures deep probe fidelity)
        raw_data = []
        clean_summary = p.summary or {}
        if isinstance(clean_summary, dict) and "_phase_data" in clean_summary:
            raw_data = clean_summary["_phase_data"]
            # Remove internal key so it doesn't leak to frontend as summary data
            clean_summary = {
                k: v for k, v in clean_summary.items() if k != "_phase_data"
            }

        phase_dict = {"summary": clean_summary, "data": raw_data}

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
                    "cve_count": (p.summary or {}).get(
                        "cve_count", getattr(scan, "total_vulns", 0) or 0
                    ),
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
                phase_dict["data"].append(
                    {
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
                    }
                )

            elif out_key == "phase2":
                asset_services = services_by_asset.get(asset.id, [])
                if asset_services or asset.last_scan_id == scan_id:
                    # Include if it had services or was active in this scan
                    ports_list = []
                    for svc in asset_services:
                        ports_list.append(
                            {
                                "port": svc.port,
                                "protocol": svc.protocol,
                                "service": svc.service_name,
                                "product": svc.service_product,
                                "version": svc.service_version,
                                "extra": svc.service_extra,
                                "banner": svc.banner,
                                "state": svc.state or "open",
                            }
                        )

                    if ports_list:
                        phase_dict["data"].append(
                            {
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
                            }
                        )

            elif out_key == "phase3":
                asset_vulns = vulns_by_asset.get(asset.id, [])
                if asset_vulns:
                    asset_services = services_by_asset.get(asset.id, [])
                    ports_list = []
                    for svc in asset_services:
                        ports_list.append(
                            {
                                "port": svc.port,
                                "protocol": svc.protocol,
                                "service": svc.service_name,
                                "product": svc.service_product,
                                "version": svc.service_version,
                                "extra": svc.service_extra,
                                "banner": svc.banner,
                                "state": svc.state or "open",
                            }
                        )
                    phase_dict["data"].append(
                        {
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
                        }
                    )

        results_out[out_key] = phase_dict

    return results_out
