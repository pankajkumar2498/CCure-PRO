"""
Writing a credentialed audit's results: the asset's identity, the services
the host reported listening, and the findings, package and configuration
alike.

Split from core/tasks.py in G1 (C2, docs/architecture/MODULAR_REFACTORING_LOG.md
§6), unchanged. The findings writes are what C3 moves into one findings
writer; keeping them in a module of their own is what makes that move one
module's worth. Logs under ``ccure.tasks``, as the hub did.
"""

import logging
from core.findings.credentialed_scope import assessed_check_ids, packages_assessed
from core.findings.fix_state import fix_state_for
from core.mac import mac_identity
from db.base import gen_asset_id, utcnow
from db.models import Asset, AssetVulnerability, Scan, VulnerabilityDefinition
from ccure_platform import api as platform_api
from sqlalchemy import func
from sqlalchemy.dialects.postgresql import insert

log = logging.getLogger("ccure.tasks")


# Shared with the pipeline's sweep in scans.asset_syncer, so the two cannot
# disagree about which absent findings a credentialed audit really retired.
_assessed_config_definition_ids = assessed_check_ids


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
    from core.findings.writer import (
        _finding_family,
        _finding_source_from_record,
        risk_from_open_findings,
    )
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
    found_cve_ids = {
        _clean_text(v.get("cve_id") or v.get("cve") or v.get("id"))
        for v in (cve_list or [])
    }
    found_cve_ids = {cid for cid in found_cve_ids if cid}

    current_open = (
        db.query(AssetVulnerability)
        .filter(
            AssetVulnerability.asset_id == asset.id, AssetVulnerability.status == "open"
        )
        .all()
    )

    # Which configuration checks actually produced a verdict this run, and
    # therefore which absent configuration findings are genuinely gone.
    _config_summary = (stored_report or {}).get("config_audit") or {}
    _assessed_checks = _assessed_config_definition_ids(_config_summary)
    # And whether the package inventory was assessed at all. With no inventory,
    # or a feed lookup that failed, cve_list carries no package CVEs, and the
    # sweep below used to read that as every package finding remediated.
    _packages_assessed = packages_assessed(stored_report)

    from core.checks.definitions import DEFINITION_TYPE_CVE, definition_type_for_id

    for f in current_open:
        if _finding_family(_finding_source_from_record(f)) != "credentialed_package":
            continue
        if f.vuln_id in found_cve_ids:
            continue
        # A configuration or privilege finding is only fixed if its check ran
        # and answered. Package findings keep the previous behaviour: the
        # matcher runs over the whole installed inventory, so a CVE it does not
        # report on a host it inventoried really is gone.
        if definition_type_for_id(f.vuln_id) != DEFINITION_TYPE_CVE:
            if f.vuln_id not in _assessed_checks:
                # Not assessed is not fixed. Left open, and the scan's recorded
                # assessment scope is what lets a comparison say so out loud
                # rather than silently carrying it forward.
                continue
        elif not _packages_assessed:
            continue
        f.status = "fixed"
        f.fixed_at = utcnow()
        _record_asset_change(
            db, asset.id, scan_id, "vulnerability_fixed", f.vuln_id, "fixed"
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
    from core.findings.writer import upsert_credentialed_services

    upsert_credentialed_services(db, asset.id, scan_id, ports or [], packages)


def _first_advisory(vuln: dict, key: str) -> str | None:
    """The first vendor advisory's field, when the finding carries any."""
    advisories = vuln.get("vendor_advisories") or []
    if not isinstance(advisories, list):
        return None
    for entry in advisories:
        if isinstance(entry, dict) and entry.get(key):
            return str(entry[key])[:2000]
    return None


def _sync_credentialed_vulnerabilities(
    db,
    asset: Asset,
    org_id: str,
    scan_id: str,
    cve_list: list[dict],
) -> None:
    from core.checks.definitions import (
        DEFINITION_TYPE_CVE,
        definition_type_for_id,
    )
    from core.findings.writer import _catalog_title, _resolve_finding_id

    source_family = "credentialed_package"
    for vuln in cve_list or []:
        cve_id = _clean_text(vuln.get("cve_id") or vuln.get("cve") or vuln.get("id"))
        if not cve_id:
            continue

        # What kind of catalogue row this identifier names. `cve_list` carries
        # configuration and privilege findings alongside package CVEs — that is
        # deliberate, and `_run_configuration_audit` documents it — so not every
        # entry here is a CVE. This function assumed they all were: it wrote the
        # identifier into `cve_id` and let `definition_type` take its 'cve'
        # default.
        #
        # Two consequences, one loud and one silent. `cve_id` is varchar(30) and
        # a minted id is longer — CCURE-CFG-CCURE-LINUX-AUDITD-RUNNING is 37 —
        # so the INSERT raised StringDataRightTruncation and **aborted the
        # finding sync for the entire scan**, losing the package findings with
        # it. Where the id did fit, the row inherited everything a CVE row
        # means: KEV lookups, EPSS scores, CVSS bands, and an NVD link that
        # resolves to nothing.
        #
        # Recovered from the identifier rather than trusted from the finding,
        # exactly as `asset_syncer` does on the network path, because the
        # finding is built by a plugin and the catalogue's CHECK constraint
        # `ck_vuln_def_cve_id_matches_type` is what has to hold.
        definition_type = definition_type_for_id(cve_id)
        is_real_cve = definition_type == DEFINITION_TYPE_CVE

        cvss = float(vuln.get("cvss_score", vuln.get("cvss", 0.0)) or 0.0)
        # Derived from the score and stored in the one canonical (lower) case.
        #
        # This wrote `.title()` of whatever the matcher supplied, which is how
        # "High" and "high" came to coexist in the same column — the split that
        # made GROUP BY return two rows for one severity and cost the dashboard
        # 100 of 146 findings. Deriving from the score also stops a feed's
        # textual rating disagreeing with the vector it published.
        from scans.cvss import canonical_severity, severity_from_score

        severity = (
            severity_from_score(cvss).lower()
            if cvss
            else canonical_severity(vuln.get("severity"))
        )
        description = _clean_text(vuln.get("description") or vuln.get("desc"))
        package_name = _clean_text(vuln.get("package"))
        installed_ver = _clean_text(vuln.get("installed_ver"))
        fixed_ver = _clean_text(vuln.get("fixed_ver"))

        proof = _clean_text(
            f"Source_Family:credentialed_package\nPackage: {package_name} {installed_ver}".strip()
        )
        plugin_output = _clean_text(
            f"{description}\nFixed version: {fixed_ver or 'N/A'}\nPriority: {vuln.get('priority_level') or 'N/A'} ({vuln.get('priority_score') or 0})"
        )

        # Get enriched details from local CVE database if available
        cvss_vector = vuln.get("cvss_vector")
        cwe_ids = []
        references = []

        try:
            from core.cve_database import get_cve_database

            cve_db = get_cve_database() if is_real_cve else None
            if cve_db is not None and cve_db.db_available:
                details = cve_db.get_cve_details(cve_id)
                if details:
                    description = details.get("description") or description
                    cvss_vector = (
                        details.get("cvss_vector")
                        or details.get("cvss_v3_vector")
                        or cvss_vector
                    )
                    cwe_ids = details.get("cwe_ids") or []

                    raw_refs = details.get("references") or []
                    clean_refs = []
                    for ref in raw_refs:
                        if isinstance(ref, str):
                            clean_refs.append(ref)
                        elif isinstance(ref, dict) and ref.get("url"):
                            clean_refs.append(ref["url"])
                    references = clean_refs
        except Exception as e:
            log.warning(
                "Failed to lookup CVE details for %s during credentialed sync: %s",
                cve_id,
                e,
            )

        # 1. UPSERT CVE Definition
        cve_insert = insert(VulnerabilityDefinition).values(
            id=cve_id,
            # NULL for anything that is not a published CVE. This is the column
            # every join to the vulnerability feeds runs through, so a check row
            # carrying a CVE-shaped string here is how a configuration weakness
            # acquires an exploit record, a KEV due date and a CVSS band that
            # belong to nothing.
            cve_id=cve_id if is_real_cve else None,
            definition_type=definition_type,
            title=(
                f"{cve_id} in {package_name}"
                if (is_real_cve and package_name)
                else _catalog_title(vuln, cve_id, description)
            ),
            description=description,
            cvss_vector=cvss_vector,
            cwe_ids=cwe_ids,
            references=references,
            severity=severity,
            cvss_v3_score=cvss,
            source="credentialed",
            created_at=utcnow(),
            updated_at=utcnow(),
        )
        db.execute(cve_insert.on_conflict_do_nothing(index_elements=["id"]))

        # 2. UPSERT Finding
        finding_id = _resolve_finding_id(db, org_id, asset.id, cve_id, source_family)
        evidence_text = (
            (
                f"Source           : authenticated package query\n"
                f"Package          : {package_name or 'unknown'}\n"
                f"Installed version: {installed_ver or 'not reported'}\n"
                f"Fixed in         : {fixed_ver or 'no fixed version published'}\n"
                f"Reference        : https://nvd.nist.gov/vuln/detail/{cve_id}"
            )
            if is_real_cve
            # A configuration or privilege check has no package and no fixed
            # version, so three of those lines would read 'unknown' or 'not
            # reported', and it has no NVD record, so the reference would be
            # a link to a page that does not exist. The check's own
            # expected-versus-observed reading is the evidence here.
            else (
                "Source           : authenticated configuration check\n"
                + (
                    _clean_text(vuln.get("evidence"))
                    or (
                        f"Expected: {vuln.get('expected_state') or 'not stated'}\n"
                        f"Observed: {vuln.get('observed_state') or 'not stated'}"
                    )
                )
            )
        )

        fnd_insert = insert(AssetVulnerability).values(
            id=finding_id,
            org_id=org_id,
            scan_id=scan_id,
            asset_id=asset.id,
            vuln_id=cve_id,
            severity=severity,
            cvss_score=cvss,
            status="open",
            source_family=source_family,
            evidence_source="credentialed",
            proof=proof,
            plugin_output=plugin_output,
            # An authenticated package match is the strongest evidence this
            # product produces: the version came from the host's own package
            # manager, not from a banner.
            evidence=evidence_text,
            confidence="Confirmed",
            qod=97,
            detection_method="credentialed_package",
            detected_version=installed_ver or None,
            cvss_vector=_clean_text(cvss_vector) or None,
            component=(package_name or None),
            component_version=(installed_ver or None),
            component_fixed_version=(fixed_ver or None),
            fix_state=fix_state_for(vuln),
            in_kev=bool(vuln.get("in_kev")),
            has_exploit=bool(vuln.get("has_exploit")),
            # Exploitation provenance and the vendor's advisory, both joined on
            # the CVE upstream. Stored so triage can separate a weaponised
            # exploit from a proof of concept without re-querying the feeds.
            exploit_sources=(list(vuln.get("exploit_sources") or []) or None),
            verified_exploit=bool(vuln.get("verified_exploit")),
            canary_confirmed=bool(vuln.get("canary_confirmed")),
            ransomware_linked=bool(vuln.get("ransomware_linked")),
            vendor_advisory_id=_first_advisory(vuln, "advisory_id"),
            vendor_advisory_url=_first_advisory(vuln, "url"),
            vendor_remediation=_clean_text(vuln.get("vendor_remediation")) or None,
            first_scan_id=scan_id,
            first_found_at=utcnow(),
            last_found_at=utcnow(),
        )

        fnd_upsert = fnd_insert.on_conflict_do_update(
            index_elements=["id", "org_id"],
            set_={
                "last_found_at": utcnow(),
                "scan_id": scan_id,
                "status": "open",
                "severity": severity,
                "cvss_score": cvss,
                "source_family": source_family,
                "evidence_source": "credentialed",
                # Refreshed for the same reason the version fields below are.
                # Evidence describes what *this* scan observed; a finding that
                # stays open otherwise reports the reading from the day it was
                # first seen. On a configuration check that is the whole
                # content of the finding — "Observed: 0" survives a partial
                # remediation to 8 — and the report then argues from a
                # measurement the host has already moved past.
                "evidence": func.coalesce(
                    func.nullif(evidence_text, ""), AssetVulnerability.evidence
                ),
                "proof": func.coalesce(
                    func.nullif(proof, ""), AssetVulnerability.proof
                ),
                "plugin_output": func.coalesce(
                    func.nullif(plugin_output, ""), AssetVulnerability.plugin_output
                ),
                # What this scan observed, refreshed on every re-scan.
                #
                # These were previously written only on first insert, so a
                # finding that stayed open kept the version from the day it was
                # first seen: a host upgraded from Chrome 138 to 139 with the
                # CVE still unfixed went on reporting 138 indefinitely, and the
                # grouped row would have advised an upgrade already performed.
                "component": (package_name or None),
                "component_version": (installed_ver or None),
                "component_fixed_version": (fixed_ver or None),
                "fix_state": fix_state_for(vuln),
                "detected_version": (installed_ver or None),
                # Exploit corpora and vendor advisories change between scans:
                # an exploit gets published, a vendor issues an advisory. A
                # finding that keeps its first-seen provenance forever would
                # under-report both.
                "exploit_sources": (list(vuln.get("exploit_sources") or []) or None),
                "verified_exploit": bool(vuln.get("verified_exploit")),
                "canary_confirmed": bool(vuln.get("canary_confirmed")),
                "ransomware_linked": bool(vuln.get("ransomware_linked")),
                "vendor_advisory_id": _first_advisory(vuln, "advisory_id"),
                "vendor_advisory_url": _first_advisory(vuln, "url"),
                "vendor_remediation": _clean_text(vuln.get("vendor_remediation"))
                or None,
            },
        )
        db.execute(fnd_upsert)
