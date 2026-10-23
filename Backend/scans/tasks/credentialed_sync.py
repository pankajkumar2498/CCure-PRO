"""
Writing a credentialed audit's results: the asset's identity, the services
the host reported listening, and the findings, package and configuration
alike.

Split from core/tasks.py in G1 (C2, docs/architecture/MODULAR_REFACTORING_LOG.md
§6), unchanged. Since G3 (C3) the findings writer, ``core.findings.writer``,
writes the services, catalogue rows and findings and sweeps the findings the
audit retired; this module writes the asset and its change log, records what
the scan assessed, and calls the writer. Logs under ``ccure.tasks``, as the
hub did.
"""

import logging
from core.mac import mac_identity
from db.base import gen_asset_id, utcnow
from db.models import Asset, Scan
from ccure_platform import api as platform_api
from core.findings.writer import (
    _sync_credentialed_vulnerabilities,
    risk_from_open_findings,
    sweep_credentialed_findings,
    upsert_credentialed_services,
)

log = logging.getLogger("ccure.tasks")


def _sync_credentialed_asset_identity(
    db,
    *,
    user_id: str,
    ip: str,
    scan_id: str,
    os_type: str,
    system_data: dict,
    stored_report: dict,
    cve_list: list[dict],
    severity_counts: dict[str, int],
) -> None:
    """
    Promote trusted credentialed scan identity into the Asset Registry.
    Phase 4: Adds forensic logging and provenance.
    """
    from core.oui_lookup import lookup_vendor
    from scans.asset_syncer import (
        CREDENTIALED_STATUS_SUCCESS,
        _confidence_to_percent,
        _has_value,
        _record_asset_change,
        _set_asset_field,
        _to_int,
    )

    user = platform_api.user(db, user_id)
    if not user:
        log.warning("Credentialed asset sync skipped: user %s not found", user_id)
        return

    # Resolve scan's target org_id
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    org_id = str(scan.org_id) if scan else str(user.org_id)

    mac_address = _normalize_mac(system_data.get("mac_address"))
    asset = None
    if mac_address:
        asset = (
            db.query(Asset)
            .filter(Asset.org_id == org_id, Asset.mac_address == mac_address)
            .first()
        )
    if not asset:
        asset = (
            db.query(Asset)
            .filter(Asset.org_id == org_id, Asset.ip_address == ip)
            .first()
        )

    if asset:
        if asset.ip_address != ip and ip != "0.0.0.0":
            # Release IP from any other asset currently claiming it (IP Hijacking protection)
            other_asset = (
                db.query(Asset)
                .filter(Asset.org_id == org_id, Asset.ip_address == ip)
                .first()
            )
            if other_asset and other_asset.id != asset.id:
                other_asset.ip_address = None
                other_asset.is_active = False
                _record_asset_change(
                    db, other_asset.id, scan_id, "ip_address", ip, None
                )
                db.flush()

            _record_asset_change(
                db, asset.id, scan_id, "ip_address", str(asset.ip_address), ip
            )
            asset.ip_address = ip
    else:
        log.info("Asset not found for ip=%s. Bootstrapping new asset record.", ip)
        org = platform_api.organisation(db, org_id)
        org_slug = org.slug if org else org_id

        asset = Asset(
            id=gen_asset_id(org_slug, ip),
            org_id=org_id,
            ip_address=ip,
            is_active=True,
            discovery_method="credentialed",
            first_seen_at=utcnow(),
            last_seen_at=utcnow(),
            created_at=utcnow(),
            updated_at=utcnow(),
        )
        db.add(asset)
        db.flush()
        _record_asset_change(
            db, asset.id, scan_id, "lifecycle", None, "bootstrapped_via_credentialed"
        )

    os_name = _clean_text(system_data.get("os_name"))
    os_version = _clean_text(system_data.get("os_version_id"))
    hostname, fqdn, raw_hostname_fqdn = _extract_credentialed_identity_names(
        system_data
    )
    os_build = _clean_text(system_data.get("os_build"))
    kernel_version = _clean_text(system_data.get("kernel_version"))
    netbios_name = _clean_text(
        system_data.get("netbios_name") or system_data.get("netbios_computer")
    )
    normalized_os_type = _clean_text(system_data.get("detected_os") or os_type).lower()
    manufacturer = _clean_text(system_data.get("manufacturer"))
    # mac_address resolved above
    mac_vendor = _clean_text(
        system_data.get("mac_vendor")
        or (lookup_vendor(mac_address) if mac_address else "")
    )
    vendor = mac_vendor or (manufacturer if not _has_value(asset.vendor) else "")
    os_family = _clean_text(
        system_data.get("os_family")
        or (
            "Windows"
            if normalized_os_type == "windows"
            else "Linux" if normalized_os_type == "linux" else ""
        )
    )
    os_confidence = _confidence_to_percent(system_data.get("os_confidence") or 100)
    subnet = _clean_text(system_data.get("subnet"))
    credentialed_response_time = _to_int(
        system_data.get("credentialed_response_time_ms")
    )

    # PHASE 4: FORENSIC CHANGE LOGGING
    _set_asset_field(
        db, asset, scan_id, "os_name", os_name, "credentialed", max_len=255
    )
    _set_asset_field(
        db, asset, scan_id, "os_family", os_family, "credentialed", max_len=100
    )
    _set_asset_field(
        db, asset, scan_id, "os_version", os_version, "credentialed", max_len=100
    )
    _set_asset_field(db, asset, scan_id, "os_confidence", os_confidence, "credentialed")
    _set_asset_field(
        db, asset, scan_id, "hostname", hostname, "credentialed", max_len=255
    )
    _set_asset_field(db, asset, scan_id, "fqdn", fqdn, "credentialed", max_len=512)
    _set_asset_field(
        db, asset, scan_id, "netbios_name", netbios_name, "credentialed", max_len=255
    )
    _set_asset_field(db, asset, scan_id, "mac_address", mac_address, "credentialed")
    _set_asset_field(db, asset, scan_id, "vendor", vendor, "credentialed", max_len=255)
    _set_asset_field(db, asset, scan_id, "subnet", subnet, "credentialed", max_len=50)
    _set_asset_field(
        db, asset, scan_id, "manufacturer", manufacturer, "credentialed", max_len=255
    )
    _set_asset_field(
        db,
        asset,
        scan_id,
        "discovery_method",
        "credentialed",
        "credentialed",
        max_len=50,
    )
    if credentialed_response_time and not _has_value(asset.response_time_ms):
        _set_asset_field(
            db,
            asset,
            scan_id,
            "response_time_ms",
            credentialed_response_time,
            "credentialed",
        )

    # Classify device category using the credentialed OS/identity details
    from core.device_classifier import classify_device

    c_host = {
        "discovery_method": "credentialed",
        "os_name": os_name,
        "os_family": os_family,
        "hostname": hostname,
        "vendor": vendor,
        "custom_attributes": asset.custom_attributes or {},
    }
    category = classify_device(c_host)
    _set_asset_field(
        db, asset, scan_id, "device_category", category, "credentialed", max_len=100
    )

    # Store the signal name ("credentialed") in provenance for future priority comparisons
    attrs = dict(asset.custom_attributes or {})
    prov = dict(attrs.get("provenance") or {})
    dev_prov = dict(prov.get("device_category") or {})
    dev_prov["signal"] = "credentialed"
    prov["device_category"] = dev_prov
    attrs["provenance"] = prov
    asset.custom_attributes = attrs

    _sync_credentialed_services(
        db,
        asset,
        scan_id,
        stored_report.get("open_ports_credentialed", []),
        stored_report.get("packages", []),
    )

    # 1. Sync Vulnerabilities (Marks as open/reopened)
    _sync_credentialed_vulnerabilities(db, asset, org_id, scan_id, cve_list)

    # 2. PHASE 4: VULNERABILITY STATUS HISTORY
    _config_summary, _assessed_checks, _packages_assessed = sweep_credentialed_findings(
        db,
        asset_id=asset.id,
        scan_id=scan_id,
        cve_list=cve_list,
        stored_report=stored_report,
        record_change=_record_asset_change,
    )

    # What this scan looked at, so a later comparison can tell "gone" from
    # "nobody looked". Smallest clean record: merged into `scans.options`,
    # which is JSONB and already carries `options.origin`. GAP-12's policy
    # engine is where this eventually belongs; it is deliberately not built here.
    try:
        from core.findings import record_assessment_scope
        from db.models.scans import Scan as _Scan

        _scan_row = db.query(_Scan).filter(_Scan.id == scan_id).first()
        if _scan_row is not None:
            record_assessment_scope(
                _scan_row,
                assets=[asset.id],
                families=["credentialed_package"],
                detail={
                    "config_audit_assessed": bool(_config_summary.get("assessed")),
                    "packages_assessed": _packages_assessed,
                    "checks_assessed": len(_assessed_checks),
                    # The set itself, not only its size. The sweep above uses
                    # it to decide which absent configuration findings are
                    # genuinely gone; without it recorded, a later comparison
                    # has only the *family* to go on — and every credentialed
                    # finding shares one family, so a scan narrowed by a GAP-12
                    # policy reported the checks it stopped selecting as fixed.
                    # Measured on a real target: five controls reported
                    # remediated on a host where nothing had changed, while
                    # this same sweep had correctly left them open.
                    #
                    # Only checks that reached a verdict are in it, so it is
                    # tens of ids rather than the whole selected set.
                    "assessed_checks": sorted(_assessed_checks),
                },
            )
    except Exception as exc:  # never fail a scan over its own bookkeeping
        log.warning("Could not record assessment scope for scan %s: %s", scan_id, exc)

    db.flush()

    # Recalculate aggregate vuln_counts
    counts, agg_score, agg_level = risk_from_open_findings(db, asset.id)
    asset.vuln_counts = counts
    asset.risk_score = agg_score
    asset.risk_level = agg_level

    # Custom attributes merge
    attrs = dict(asset.custom_attributes or {})
    credentialed_attrs = dict(attrs.get("credentialed_system_info") or {})
    credentialed_attrs.update(
        {
            "os_name": os_name,
            "os_version_id": os_version,
            "os_family": os_family,
            "os_build": os_build,
            "kernel_version": kernel_version,
            "hardware_model": _clean_text(system_data.get("hardware_model")),
            "cpu_model": _clean_text(system_data.get("cpu_model")),
            "cpu_count": _clean_text(system_data.get("cpu_count")),
            "uptime": _clean_text(system_data.get("uptime")),
            "hostname": hostname,
            "hostname_short": _clean_text(system_data.get("hostname_short")),
            "hostname_fqdn_raw": raw_hostname_fqdn,
            "netbios_name": netbios_name,
            "fqdn": fqdn,
            "serial_number": _clean_text(system_data.get("serial_number")),
            "bios_version": _clean_text(system_data.get("bios_version")),
            "local_groups": system_data.get("local_groups", []),
            "mac_address": mac_address,
            "mac_vendor": mac_vendor,
            "vendor": vendor,
            "domain": _clean_text(system_data.get("domain")),
            "subnet": subnet,
            "manufacturer": manufacturer,
            "credentialed_response_time_ms": credentialed_response_time,
            "detected_os": normalized_os_type or os_type,
            "source_scan_id": scan_id,
            "synced_at": utcnow().isoformat(),
            "running_services": system_data.get("running_services", []),
            "suspicious_scheduled_tasks": system_data.get(
                "suspicious_scheduled_tasks", []
            ),
            "cron_info_raw": system_data.get("cron_info_raw", ""),
        }
    )
    attrs["credentialed_system_info"] = {
        key: value
        for key, value in credentialed_attrs.items()
        if value is not None and value != ""
    }

    # Compliance Engine Evidence Mappings. The literal used to live here and
    # only here, which is why the Vulnerability Audit's credentialed pass never
    # set it — there was nothing to call.
    attrs["credentialed_status"] = CREDENTIALED_STATUS_SUCCESS

    # Password policy is *collected*, never assumed. This used to be a
    # hard-coded {complexity: True, history_length: 24, min_length: 14}
    # regardless of the host, so every rule reading it passed unconditionally
    # on every machine — a fabricated value presented to an auditor as
    # evidence. Keys the collector could not determine are omitted entirely,
    # which the compliance engine renders as "not assessed" rather than as a
    # pass or a fail.
    collected_pwd = system_data.get("password_policy") or {}
    password_policy = {
        k: v
        for k, v in {
            "complexity": collected_pwd.get("complexity"),
            "history_length": collected_pwd.get("history_length"),
            "min_length": collected_pwd.get("min_length"),
            "max_age_days": collected_pwd.get("max_age_days"),
            "lockout_threshold": collected_pwd.get("lockout_threshold"),
        }.items()
        if v is not None
    }
    if password_policy:
        attrs["password_policy"] = password_policy
    else:
        attrs.pop("password_policy", None)
        log.info(
            "No password policy collected for asset=%s; compliance controls "
            "depending on it will report as not assessed.",
            asset.id,
        )

    # Registry Hardening / Firewall / RDP status
    issues = system_data.get("security_issues") or []
    fw_disabled = any(
        "Firewall profile" in issue and "is DISABLED" in issue for issue in issues
    )

    rdp_enabled = system_data.get("rdp_enabled")
    if rdp_enabled is None:
        rdp_enabled = any("RDP is enabled" in issue for issue in issues)

    uac_disabled = any(
        "UAC" in issue and "disabled" in issue.lower() for issue in issues
    )

    audit_configured = True
    if normalized_os_type == "windows" and not system_data.get("audit_policy"):
        audit_configured = False
    elif normalized_os_type == "linux":
        running_svcs = system_data.get("running_services") or []
        audit_configured = any(svc.get("name") == "auditd" for svc in running_svcs)

    if normalized_os_type == "linux":
        running_svcs = system_data.get("running_services") or []
        fw_active = any(
            svc.get("name") in ("ufw", "firewalld", "iptables") for svc in running_svcs
        )
    else:
        fw_active = not fw_disabled

    attrs["registry_hardening"] = {
        "firewall_active": fw_active,
        "rdp_disabled": not rdp_enabled,
        "uac_enabled": not uac_disabled,
        "audit_configured": audit_configured,
        # No ``False`` default: an absent key means the collector did not read
        # the setting, and defaulting it asserts the insecure state as fact —
        # a FAIL nothing established, which is the same defect as the PASS the
        # collector used to synthesise, pointing the other way. ``None`` travels
        # to the evidence adapter, which drops it, and a dropped key routes the
        # rule to manual review.
        "smbv1_disabled": system_data.get("smbv1_disabled"),
        "netbios_disabled": system_data.get("netbios_disabled"),
        "legacy_tls_disabled": system_data.get("legacy_tls_disabled"),
        "telnet_disabled": system_data.get("telnet_disabled"),
        "rdp_nla_enforced": system_data.get("rdp_nla_enforced"),
    }

    asset.custom_attributes = attrs
    asset.last_scan_id = scan_id
    asset.last_seen_at = utcnow()
    asset.updated_at = utcnow()
    log.info(
        "Credentialed asset sync updated asset=%s ip=%s os=%s",
        asset.id,
        ip,
        asset.os_name,
    )


def _extract_credentialed_identity_names(system_data: dict) -> tuple[str, str, str]:
    raw_hostname_fqdn = _clean_text(system_data.get("hostname_fqdn"))
    explicit_fqdn = _clean_text(system_data.get("fqdn"))
    hostname_short = _clean_text(system_data.get("hostname_short"))
    hostname = _clean_text(
        system_data.get("hostname")
        or hostname_short
        or (raw_hostname_fqdn.split(".")[0] if raw_hostname_fqdn else "")
    )
    fqdn = (
        explicit_fqdn
        if "." in explicit_fqdn
        else (raw_hostname_fqdn if "." in raw_hostname_fqdn else "")
    )
    return hostname, fqdn, raw_hostname_fqdn


def _clean_text(value) -> str:
    return str(value or "").strip()


def _normalize_mac(value) -> str:
    """
    Canonical ``aa:bb:cc:dd:ee:ff`` for asset identity, or ``""``.

    The parsing is ``core.mac.mac_colon``; the policy — that a reserved address
    is not an identity — is applied here, because it is this caller's. It is
    applied to the *normalized* value, and the order is the whole point.

    The reserved check used to run against the raw text, so it only recognised
    the two addresses spelled exactly as they appear in ``RESERVED_MACS``.
    ``000000000000``, ``0:0:0:0:0:0`` and ``0000.0000.0000`` are the same
    all-zero address written differently; every one of them slipped past and
    was returned as ``00:00:00:00:00:00``. ``ffffffffffff`` did the same for
    broadcast.

    That matters because ``assets`` is keyed on ``(org_id, mac_address)``. Any
    number of hosts can report an all-zero MAC — it is what a NIC with no
    hardware address, some hypervisor interfaces and a failed read all produce —
    and each one that got through claimed the same asset row, so they collapsed
    into a single host that appeared to change identity on every scan. Returning
    ``""`` instead sends the caller down the IP-based identity path, which is
    what it already does for a host whose MAC could not be read at all.

    Reserved addresses are compared after normalization for the same reason the
    hex check happens after it: a value is only comparable once it is in one
    form.
    """
    return mac_identity(value) or ""


def _credentialed_sections_with_identity(
    sections: list[str] | None,
) -> list[str] | None:
    if sections is None:
        return None
    required = ["system_info", "network"]
    merged = list(sections)
    for section in required:
        if section not in merged:
            merged.append(section)
    return merged


def _port_int(value) -> int | None:
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    if 1 <= port <= 65535:
        return port
    return None


def _sync_credentialed_services(
    db, asset: Asset, scan_id: str, ports: list[dict], packages: list[dict] = None
) -> None:
    """Persist the host's listening sockets. See core.findings.writer for the semantics."""
    upsert_credentialed_services(db, asset.id, scan_id, ports or [], packages)
