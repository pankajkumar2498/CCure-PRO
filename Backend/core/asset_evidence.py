"""
core/asset_evidence.py
─────────────────────────────────────────────────────────────────────────────
The asset registry's compliance evidence: what compliance's evidence sources
read from the asset record — the attributes a credentialed scan collected onto
it.

``credential_validation``  whether the scanner authenticated, and the host's
                           password policy
``offline_configuration``  the host's hardening, logging and governance
                           attributes
``malware_scan``           anti-malware agents among its services and its
                           collected processes; the service names come from
                           the findings store and are passed in

and :func:`asset_identity`, what the web-application evidence matches a web
scan's target against.

G4 (C4 of docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md) moved these,
unchanged, out of ``core/compliance_evidence.py``, which queried the asset table
itself. Audit's composition root, ``ccure_audit/evidence_providers.py``,
registers them with compliance's registry; nothing here imports compliance.

A rule reads its key from the dict literal a provider returns, and
``tests/compliance/test_compliance_rule_wiring.py`` reads those literals
statically, so every key a provider can serve is named in one. A value nobody
collected is dropped, never defaulted: the engine reads a missing key as not
assessed.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional, Sequence

from db.models.assets import Asset
from sqlalchemy.orm import Session

__all__ = [
    "AssetIdentity",
    "asset_identity",
    "credential_validation",
    "malware_scan",
    "offline_configuration",
]


def _days_since(value) -> Optional[int]:
    """Whole days between an ISO-8601 timestamp and now, or None."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - parsed).days


def malware_scan(
    db: Session, asset_id: str, network_service_names: Sequence[Optional[str]]
) -> dict[str, Any]:
    """
    Whether an anti-malware agent runs on the asset, from the names of its
    network services (*network_service_names*, the findings store's
    ``service_names``, in its order) and then the processes a credentialed
    scan collected onto the asset record.
    """
    # Checks if anti-malware services are present and active
    malware_processes = [
        "defender",
        "clamav",
        "sentinel",
        "mcafee",
        "symantec",
        "crowdstrike",
    ]

    active_av_agents = []
    for service_name in network_service_names:
        svc_name = (service_name or "").lower()
        if any(av in svc_name for av in malware_processes):
            active_av_agents.append(service_name)

    # Query custom_attributes from the Asset directly
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if asset and asset.custom_attributes:
        sys_info = asset.custom_attributes.get("credentialed_system_info", {})
        running_svcs = sys_info.get("running_services", [])
        for svc in running_svcs:
            svc_name = (svc.get("name") or svc.get("description") or "").lower()
            if any(av in svc_name for av in malware_processes):
                active_av_agents.append(svc.get("name") or svc.get("description"))

    # Deduplicate
    active_av_agents = list(set(active_av_agents))

    return {
        "malware_detected": False,  # Managed by agent alerts
        "anti_malware_agents_active": len(active_av_agents) > 0,
        "agents_list": active_av_agents,
    }


def credential_validation(db: Session, asset_id: str) -> dict[str, Any]:
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    creds_status = (
        (asset.custom_attributes or {}).get("credentialed_status", "unknown")
        if asset
        else "unknown"
    )

    pwd_attrs = (
        (asset.custom_attributes or {}).get("password_policy") or {} if asset else {}
    )

    # Only `credentialed_scan_successful` is always known — it is a fact
    # about this scanner, not about the host. The password-policy keys used
    # to carry defaults (`False`, `0`, `8`) that were indistinguishable
    # from a collected value, so an uncollected policy was reported as a
    # measured failure.
    payload: dict[str, Any] = {
        "credentialed_scan_successful": creds_status == "success",
        "password_complexity_configured": pwd_attrs.get("complexity"),
        "password_history_length": pwd_attrs.get("history_length"),
        "minimum_password_length": pwd_attrs.get("min_length"),
        "password_max_age_days": pwd_attrs.get("max_age_days"),
        "account_lockout_threshold": pwd_attrs.get("lockout_threshold"),
    }

    # Every key this adapter can serve is named in the literal above so the
    # catalogue guard in tests/test_compliance_rule_wiring.py can read the
    # adapter's key surface statically. Uncollected keys are then dropped,
    # which routes the rule to `manual_review` rather than to a `fail`
    # computed from a value nobody measured.
    return {k: v for k, v in payload.items() if v is not None}


def offline_configuration(db: Session, asset_id: str) -> dict[str, Any]:
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    registry_attrs = (
        (asset.custom_attributes or {}).get("registry_hardening", {}) if asset else {}
    )
    custom_attrs = (asset.custom_attributes or {}) if asset else {}

    rdp_disabled = registry_attrs.get("rdp_disabled", False)
    # A host with RDP switched off satisfies "NLA is enforced" whatever the
    # NLA setting says, so that stays a real answer. Otherwise an unread NLA
    # setting is unknown rather than unenforced.
    _nla_raw = registry_attrs.get("rdp_nla_enforced")
    if rdp_disabled:
        rdp_nla_enforced = True
    elif _nla_raw is None:
        rdp_nla_enforced = None
    else:
        rdp_nla_enforced = bool(_nla_raw)

    # --- PCI-DSS v4.0 FIM (File Integrity Monitoring) Detection ---
    # None when neither source recorded it: read only by a PCI rule, where a
    # False default failed requirement 11.5.2 on every host nobody had
    # checked (see the note on the PCI keys below).
    _fim_values = [
        v
        for v in (registry_attrs.get("fim_active"), custom_attrs.get("fim_active"))
        if v is not None
    ]
    fim_active = any(bool(v) for v in _fim_values) if _fim_values else None
    fim_monitored_dirs = registry_attrs.get(
        "fim_monitored_dirs", []
    ) or custom_attrs.get("fim_monitored_dirs", [])

    # The four PCI keys below are None when nothing was recorded, never
    # False. Each is read by an active PCI rule (crl_pci_auth_mfa,
    # crl_pci_asv_fresh, crl_pci_log_daily, crl_pci_ir_test_365d), and a
    # False default made every host that had never recorded the fact FAIL
    # the requirement — an unknown reported as a known failure. None is
    # dropped from the payload below, so the rule reads the key as missing
    # and renders manual_review. The same applies to a stored date that
    # does not parse: nothing was established.

    # --- PCI-DSS v4.0 PAM MFA Module Detection (Linux pam_duo.so, pam_google_authenticator.so) ---
    pam_mfa_modules = custom_attrs.get("pam_mfa_modules")
    pam_mfa_enforced = (
        len(pam_mfa_modules) > 0 if isinstance(pam_mfa_modules, list) else None
    )

    # --- PCI-DSS v4.0 ASV Scan Freshness Tracking ---
    # Track last PASSING ASV scan date, not just any scan execution
    asv_last_passing_scan_date = custom_attrs.get("asv_last_passing_scan_date")
    asv_scan_fresh = None
    if asv_last_passing_scan_date:
        try:
            last_scan = datetime.fromisoformat(
                asv_last_passing_scan_date.replace("Z", "+00:00")
            )
            days_since = (datetime.now(timezone.utc) - last_scan).days
            asv_scan_fresh = days_since <= 90  # Quarterly cadence
        except (ValueError, TypeError):
            asv_scan_fresh = None

    # --- PCI-DSS v4.0 Daily Log Review (Req 10.4.1) ---
    pci_log_daily_reviewed = custom_attrs.get("pci_log_daily_reviewed")

    # --- PCI-DSS v4.0 IR Tabletop Exercise Freshness (Req 12.10.2) ---
    ir_last_test_date = custom_attrs.get("ir_last_test_date")
    ir_test_fresh_365d = None
    if ir_last_test_date:
        try:
            last_test = datetime.fromisoformat(ir_last_test_date.replace("Z", "+00:00"))
            days_since_test = (datetime.now(timezone.utc) - last_test).days
            ir_test_fresh_365d = days_since_test <= 365
        except (ValueError, TypeError):
            ir_test_fresh_365d = None

    # --- PCI-DSS v4.0 Session Timeout Configuration (Req 8.2.8) ---
    session_timeout_minutes = registry_attrs.get(
        "session_timeout_minutes"
    ) or custom_attrs.get("session_timeout_minutes")

    # --- PCI-DSS v4.0 Account Lockout Policy (Req 8.3.4) ---
    account_lockout_threshold = registry_attrs.get(
        "account_lockout_threshold"
    ) or custom_attrs.get("account_lockout_threshold")

    # --- PCI-DSS v4.0 WAF Active (Req 6.4.1) ---
    waf_active = custom_attrs.get("waf_active")

    # --- PCI-DSS v4.0 IDS/IPS Active (Req 11.5.1) ---
    ids_ips_active = custom_attrs.get("ids_ips_active")

    # --- PCI-DSS v4.0 Log Retention (Req 10.5.1: >= 365 days) ---
    log_retention_days = registry_attrs.get("retention_days") or custom_attrs.get(
        "log_retention_days"
    )

    # --- NIST 800-53 / CERT-In operational hygiene ---
    # These were referenced by seeded rules and emitted by nothing, so the
    # rules could only ever report "not assessed".
    last_scan_days_ago = _days_since(custom_attrs.get("last_vuln_scan_at"))
    disk_encryption_enabled = registry_attrs.get(
        "disk_encryption_enabled"
    ) or custom_attrs.get("disk_encryption_enabled")
    password_complexity_enforced = (
        (custom_attrs.get("password_policy") or {}).get("complexity")
        if isinstance(custom_attrs.get("password_policy"), dict)
        else None
    )

    # No ``False`` default on these four or on ``ids_ips_active`` /
    # ``waf_active`` above: a value that was never collected is absent, and
    # the engine renders an absent key as not assessed. They defaulted to
    # False until 28 Sep 2026 — the pattern CLAUDE.md forbids on this path —
    # so a host whose registry hardening was never read FAILED the ISO,
    # NIST CSF, CIS and PCI rules that read them (3 of this installation's 4
    # assets on that date). ``rdp_disabled`` stays a boolean for the NLA
    # derivation above; only what is published changes.
    payload = {
        "uac_enabled": registry_attrs.get("uac_enabled"),
        "firewall_profile_active": registry_attrs.get("firewall_active"),
        "remote_desktop_disabled": registry_attrs.get("rdp_disabled"),
        "audit_policy_configured": registry_attrs.get("audit_configured"),
        # New normalized protocol hardening attributes
        # No ``False`` default on these four: the key is absent when the
        # transport did not collect the setting, and a default turns "not
        # assessed" into a verdict. ``None`` is dropped by the comprehension
        # at the end of this function, and a dropped key is what the engine
        # reads as unassessed rather than breached.
        "smbv1_disabled": registry_attrs.get("smbv1_disabled"),
        "netbios_disabled": registry_attrs.get("netbios_disabled"),
        "legacy_tls_disabled": registry_attrs.get("legacy_tls_disabled"),
        "telnet_disabled": registry_attrs.get("telnet_disabled"),
        "rdp_nla_enforced": rdp_nla_enforced,
        # --- CERT-In Technical Checks ---
        "retention_days": registry_attrs.get("retention_days")
        or custom_attrs.get("log_retention_days"),
        "ntp_servers": registry_attrs.get("ntp_servers")
        or custom_attrs.get("ntp_servers")
        or [],
        "incident_reporting_sla_hours": registry_attrs.get(
            "incident_reporting_sla_hours"
        )
        or custom_attrs.get("incident_reporting_sla_hours"),
        "vpn_log_retention_years": registry_attrs.get("vpn_log_retention_years")
        or custom_attrs.get("vpn_log_retention_years"),
        # --- PCI-DSS v4.0 ---
        # Every one of these was computed above and then dropped on the
        # floor: the return statement simply did not include them, so the
        # five PCI rules that read them reported "not assessed" forever
        # while the adapter did the work each time.
        "fim_active": fim_active,
        "fim_monitored_dirs": fim_monitored_dirs,
        "pam_mfa_enforced": pam_mfa_enforced,
        "pam_mfa_modules": pam_mfa_modules,
        "asv_scan_fresh": asv_scan_fresh,
        "pci_log_daily_reviewed": pci_log_daily_reviewed,
        "ir_test_fresh_365d": ir_test_fresh_365d,
        "session_timeout_minutes": session_timeout_minutes,
        "account_lockout_threshold": account_lockout_threshold,
        "waf_active": waf_active,
        "ids_ips_active": ids_ips_active,
        "log_retention_days": log_retention_days,
        # --- NIST SP 800-53 Rev. 5 ---
        "last_scan_days_ago": last_scan_days_ago,
        "disk_encryption_enabled": disk_encryption_enabled,
        "password_complexity_enforced": password_complexity_enforced,
        "mfa_enforced_admin": custom_attrs.get("mfa_enforced_admin"),
        "account_review_completed": custom_attrs.get("account_review_completed"),
        "log_review_frequency_days": custom_attrs.get("log_review_frequency_days"),
        "backup_frequency_days": custom_attrs.get("backup_frequency_days"),
        "scrm_plan_documented": custom_attrs.get("scrm_plan_documented"),
        # --- DPDP Act 2023 & GDPR Technical Checks ---
        # These used to default to True — an organisation that had never
        # recorded whether it encrypts personal data, appointed a DPO or
        # ran a DPIA was reported as compliant with all three. A privacy
        # control nobody has answered is unassessed, not satisfied, and the
        # engine already renders a missing key as `manual_review`. Absent
        # keys are therefore stripped below rather than invented here.
        "pii_encryption_enabled": custom_attrs.get("pii_encryption_enabled"),
        "dpo_designated": custom_attrs.get("dpo_designated"),
        "dpia_conducted": custom_attrs.get("dpia_conducted"),
        "breach_notification_sla_hours": custom_attrs.get(
            "breach_notification_sla_hours"
        ),
        "consent_management_active": custom_attrs.get("consent_management_active"),
        "pii_retention_days": custom_attrs.get("pii_retention_days"),
    }

    # A key whose value is None was not collected. Leaving it present makes
    # the engine evaluate it — and `_evaluate_operator` returns False for a
    # None actual, which records a *failure* against a control nobody
    # measured. Dropping the key routes it to `manual_review` instead,
    # which is the distinction the whole engine is built around.
    return {k: v for k, v in payload.items() if v is not None}


@dataclass(frozen=True)
class AssetIdentity:
    """What another capability matches against an asset: its organisation,
    its address and its host name, as the asset record holds them."""

    org_id: str
    ip_address: Any
    hostname: Optional[str]


def asset_identity(db: Session, asset_id: str) -> Optional[AssetIdentity]:
    """The asset's identity, or None when there is no such asset."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if asset is None:
        return None
    return AssetIdentity(
        org_id=asset.org_id, ip_address=asset.ip_address, hostname=asset.hostname
    )
