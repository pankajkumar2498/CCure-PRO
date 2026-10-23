"""
core/findings/writer.py — the one writer of the findings tables.

G3 (C3, docs/architecture/MODULAR_REFACTORING_LOG.md §6) moves every write to
``services``, ``tls_details``, ``vulnerability_definitions`` and
``asset_vulnerabilities`` into this module, from the modules outside the
findings capability that made them. The code moved unchanged. Its callers keep
what is theirs:

* **The asset.** Its identity, change log, risk columns and last-seen record
  stay with the caller. A finding that reopens, is retired or is ruled out is
  recorded in the asset's change log through the ``record_change`` callback
  the caller passes, so this module writes no asset table and imports no asset
  model.
* **The scan.** What a scan assessed is recorded on the scan row
  (``core.findings.record_assessment_scope``, into ``scans.options``) by the
  caller, with what the functions here return.

``http_security_details`` is a findings table no code writes.

From the vulnerability-audit pipeline (``scans.asset_syncer``): the services a
port scan or a credentialed pass observed, each host's catalogue rows and
findings and the sweep of those the scan retired, the TLS reading, and the
asset risk computed from open findings.

From the standalone credentialed audit (``scans.tasks.credentialed_sync``):
its catalogue rows and findings, and the sweep of those it retired.

Moved code logs under the name it always had, so its log lines read as they
did: ``scans.asset_syncer`` for the pipeline's, ``ccure.tasks`` for the
standalone audit's.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any, Callable, Dict, List, NamedTuple, Optional

from core.checks.contract import normalize_severity
from core.checks.definitions import DEFINITION_TYPE_CVE, definition_type_for_id
from core.findings.comparison import STATUS_RULED_OUT
from core.findings.credentialed_scope import (
    CREDENTIALED_DETECTIONS,
    CREDENTIALED_ID_PREFIXES,
    assessed_check_ids,
    is_credentialed_finding,
    packages_assessed,
)
from core.findings.fix_state import fix_state_for
from db.base import gen_service_id, utcnow
from db.models.findings import (
    SOURCE_CREDENTIALED,
    SOURCE_NETWORK_SCAN,
    STATE_HOST_ONLY,
    STATE_LISTENING,
    STATE_OPEN,
    AssetVulnerability,
    Service,
    TLSDetail,
    VulnerabilityDefinition,
)
from engines.credentialed.coverage import BIND_LOOPBACK, bind_scope
from scans.cvss import (
    canonical_severity,
    cvss_version_of_vector,
    severity_from_score,
)
from sqlalchemy import case, func
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

logger = logging.getLogger("scans.asset_syncer")

#: ``record_change(db, asset_id, scan_id, field, old_value, new_value)``: the
#: caller's entry in the asset's change log.
RecordChange = Callable[[Session, str, str, str, Any, Any], None]


# ── Value helpers ────────────────────────────────────────────────────────────
#
# The same definitions as scans.asset_syncer's, which its identity code keeps
# using; tests/repo/test_findings_writer.py holds them equal. ``_clean`` is the
# definition asset_syncer's code actually calls: a second ``_clean`` there
# replaces the first at import.

EMPTY_VALUES = {
    None,
    "",
    "Unknown",
    "unknown",
    "UNKNOWN",
    "N/A",
    "n/a",
    "None",
    "00:00:00:00:00:00",
}


def _has_value(value) -> bool:
    if value in EMPTY_VALUES:
        return False
    if isinstance(value, str) and value.strip() in EMPTY_VALUES:
        return False
    if value in ([], {}):
        return False
    return True


def _clean(value, max_len: int | None = None):
    """
    Return the value, or None when it is a scanner placeholder.

    "Unknown", "unknown", "N/A" and friends mean the scan found nothing. Stored
    verbatim they read as real observations in the registry and in reports, and
    they defeat hostname search. NULL is the honest representation of absence.
    """
    if not _has_value(value):
        return None
    if isinstance(value, str):
        text = value.strip()
        return text[:max_len] if max_len else text
    return value


def _port_int(value) -> int | None:
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def _normalize_source(source: str | None) -> str:
    source = str(source or "legacy").strip().lower()
    return {
        "phase1": "discovery",
        "phase2": "asset_discovery",
        "phase3": "vulnerability_audit",
        "vulnerability_assessment": "vulnerability_audit",
        "advanced": "vulnerability_audit",
        "port_scan": "asset_discovery",
    }.get(source, source)


# ── Services ────────────────────────────────────────────────────────────────

#: Process names that identify the operating system itself rather than any
#: installed product. They are common English words, so substring matching
#: attaches them to whatever package happens to contain the word — on a real
#: host "System" (PID 4, the kernel) resolved to "HP System Default Settings
#: 1.5.20.1", putting a false product *and version* on SMB and WinRM. A wrong
#: version is worse than none: it feeds the CVE range check.
_GENERIC_PROCESS_NAMES = {
    "system",
    "idle",
    "svchost",
    "services",
    "lsass",
    "wininit",
    "winlogon",
    "csrss",
    "smss",
    "spoolsv",
    "dllhost",
    "conhost",
    "taskhostw",
    "rundll32",
    "dwm",
    "explorer",
    "systemd",
    "init",
    "kthreadd",
}


def service_identity_from_process(
    raw_process: str, packages: list[dict] | None
) -> tuple[str | None, str | None]:
    """
    Resolve the process holding a socket to an installed package and version.

    The socket table names the binary; the package inventory knows its version.
    Joining them is what turns "sshd is listening" into "OpenSSH 8.9p1 is
    listening", which is the difference between a service row that can be
    version-matched and one that cannot.

    This is inference, not observation, so it is deliberately conservative: a
    match must be the package's exact name or its opening words. Substring
    matching anywhere in the name is not evidence — it is how a kernel process
    acquired a laptop vendor's utility as its "product". Where a caller already
    has the binary's own version resource it should use that instead and never
    call this.
    """
    import re

    process_name = ""
    text = (raw_process or "").strip()
    if text:
        # Linux ss -tlnp: users:(("sshd",pid=1142,fd=3))
        match = re.search(r'"([^"]+)"', text)
        if match:
            process_name = match.group(1).split("/")[-1].split("\\")[-1]
        elif not text.upper().startswith("PID "):
            process_name = (
                text.split("/")[-1].split("\\")[-1].split()[0].strip("(),;\"'")
            )

    if not process_name:
        return None, None

    service_product: str | None = process_name
    service_version: str | None = None
    proc_lower = process_name.lower()

    # An OS process is named, never attributed to a package.
    bare_name = proc_lower[:-4] if proc_lower.endswith(".exe") else proc_lower
    if bare_name in _GENERIC_PROCESS_NAMES:
        return service_product, None

    if packages:
        for pkg in packages:
            if pkg.get("name", "").lower() == proc_lower:
                return pkg.get("name"), pkg.get("version")
        # Anchored at the start only. "postgres" may claim "PostgreSQL 18";
        # "system" may not claim "HP System Default Settings".
        best_match = None
        for pkg in packages:
            pkg_name = pkg.get("name", "").lower()
            if pkg_name.startswith(proc_lower):
                if not best_match or len(pkg_name) < len(best_match.get("name", "")):
                    best_match = pkg
        if best_match:
            return best_match.get("name"), best_match.get("version")
    return service_product, service_version


def upsert_credentialed_services(
    db: Session,
    asset_id: str,
    scan_id: str,
    ports: list[dict],
    packages: list[dict] | None = None,
) -> None:
    """
    Record what the host itself reports it is listening on.

    Shared by the standalone credentialed audit and the credentialed pass of
    the Vulnerability Audit pipeline, so both produce identical rows.

    A listening socket is not the same observation as an open port. Whether the
    network can reach it is a question the socket table cannot answer — except
    for a loopback bind, which settles it. Recording every listener as "open"
    made a service on 127.0.0.1 indistinguishable from one a scan confirmed.
    """
    unique_ports: dict[str, tuple[int, str, dict]] = {}
    for port_data in ports or []:
        if not isinstance(port_data, dict):
            continue
        port_num = _port_int(port_data.get("port"))
        if not port_num:
            continue
        protocol = (_clean(port_data.get("protocol")) or "tcp").lower()[:10]
        service_id = gen_service_id(asset_id, port_num, protocol)
        if service_id not in unique_ports:
            unique_ports[service_id] = (port_num, protocol, port_data)

    for service_id, (port, protocol, port_data) in unique_ports.items():
        scope = _clean(port_data.get("bind_scope")) or bind_scope(
            port_data.get("local_addr")
        )
        reachable = port_data.get("network_reachable")
        if reachable not in (True, False):
            reachable = None

        if scope == BIND_LOOPBACK:
            state = STATE_HOST_ONLY
        elif reachable is True:
            state = STATE_OPEN
        else:
            state = STATE_LISTENING

        raw_process = port_data.get("process") or ""
        service_name = (
            _clean(
                port_data.get("service")
                or port_data.get("name")
                or raw_process
                or "unknown"
            )
        )[:100]
        banner = _clean(port_data.get("banner")) or None
        # A caller that already resolved the process to a package passes the
        # result through rather than shipping the whole inventory here just so
        # this can redo the lookup.
        service_product = _clean(port_data.get("product")) or None
        service_version = _clean(port_data.get("version")) or None
        if not service_product:
            service_product, service_version = service_identity_from_process(
                raw_process, packages
            )

        svc_insert = insert(Service).values(
            id=service_id,
            asset_id=asset_id,
            scan_id=scan_id,
            port=port,
            protocol=protocol,
            state=state,
            discovery_source=SOURCE_CREDENTIALED,
            network_reachable=reachable,
            bind_scope=scope or None,
            credentialed_confirmed=True,
            service_name=service_name,
            service_product=service_product,
            service_version=service_version,
            banner=banner,
            created_at=utcnow(),
            updated_at=utcnow(),
        )

        # A port scan observes reachability directly; the host cannot see the
        # firewall in front of it. So where a network observation already
        # exists, this pass adds what the host knows (the process behind the
        # socket, its bind scope, the confirmation) without overwriting what
        # only the network could establish.
        keep_network_verdict = Service.network_reachable.is_(True)
        db.execute(
            svc_insert.on_conflict_do_update(
                index_elements=["id"],
                set_={
                    "state": case((keep_network_verdict, Service.state), else_=state),
                    "network_reachable": (
                        Service.network_reachable
                        if reachable is None
                        else func.coalesce(Service.network_reachable, reachable)
                    ),
                    "bind_scope": scope or Service.bind_scope,
                    "discovery_source": case(
                        (
                            Service.discovery_source == SOURCE_NETWORK_SCAN,
                            SOURCE_NETWORK_SCAN,
                        ),
                        else_=SOURCE_CREDENTIALED,
                    ),
                    "credentialed_confirmed": True,
                    "scan_id": scan_id,
                    "updated_at": utcnow(),
                    "service_name": func.coalesce(
                        func.nullif(Service.service_name, "unknown"),
                        func.nullif(service_name, ""),
                        Service.service_name,
                    ),
                    "service_product": func.coalesce(
                        Service.service_product,
                        func.nullif(service_product or "", ""),
                    ),
                    "service_version": func.coalesce(
                        Service.service_version,
                        func.nullif(service_version or "", ""),
                    ),
                    "banner": func.coalesce(Service.banner, func.nullif(banner, "")),
                },
            )
        )


def upsert_network_service(db: Session, asset_id: str, scan_id: str, p: dict) -> None:
    """
    Record a port the scanner reached across the network.

    The port-scan path only records a port once something answered on it, so
    every row it writes is a network-confirmed observation and says so. A
    credentialed audit may have written the same row first from the host's own
    socket table; the flags it set there (``credentialed_confirmed``,
    ``bind_scope``) describe the host and are preserved — this observation adds
    reachability, it does not replace what the host reported about itself.

    Note on retention: the row id is ``gen_service_id(asset, port, protocol)``,
    so ``services`` holds the *current* state of each asset's ports — one row
    per (asset, port, protocol) — and ``scan_id`` names the scan that last
    observed it. Re-scanning an asset re-points those rows rather than adding a
    second generation, so this table cannot be queried as per-scan history.
    Point-in-time results live in ``scan_phases.summary``, which is what the
    scan-detail API and the reports read back.
    """
    port_num = p.get("port")
    if not port_num:
        return
    proto = p.get("protocol", "tcp").lower()
    service_id = gen_service_id(asset_id, int(port_num), proto)

    # A version read from inside the host supersedes the remote guess this
    # table already holds. The usual coalesce preserves whatever was written
    # first, which would keep nmap's "9.6.0 or later" over the authenticated
    # 18.3 and leave the asset disagreeing with the report about the same
    # service.
    authenticated = p.get("fingerprint_source") == "credentialed"
    incoming_version = func.nullif(p.get("version") or "", "")
    version_update = (
        func.coalesce(incoming_version, Service.service_version)
        if authenticated
        else func.coalesce(Service.service_version, incoming_version)
    )

    db.execute(
        insert(Service)
        .values(
            id=service_id,
            asset_id=asset_id,
            scan_id=scan_id,
            port=int(port_num),
            protocol=proto,
            state=STATE_OPEN,
            discovery_source=SOURCE_NETWORK_SCAN,
            network_reachable=True,
            credentialed_confirmed=bool(p.get("credentialed_confirmed", False)),
            service_name=p.get("service") or "unknown",
            service_product=p.get("product") or None,
            service_version=p.get("version") or None,
            banner=p.get("banner"),
            created_at=utcnow(),
            updated_at=utcnow(),
        )
        .on_conflict_do_update(
            index_elements=["id"],
            set_={
                "state": STATE_OPEN,
                "discovery_source": SOURCE_NETWORK_SCAN,
                "network_reachable": True,
                # Never clear a confirmation the credentialed pass established.
                "credentialed_confirmed": func.coalesce(
                    Service.credentialed_confirmed, False
                )
                | bool(p.get("credentialed_confirmed", False)),
                "scan_id": scan_id,
                "updated_at": utcnow(),
                "service_name": func.coalesce(
                    func.nullif(Service.service_name, "unknown"),
                    func.nullif(p.get("service") or "", ""),
                    Service.service_name,
                ),
                # Preserve richer data on conflict — never overwrite a non-null
                # value with null.
                "service_product": func.coalesce(
                    Service.service_product,
                    func.nullif(p.get("product") or "", ""),
                ),
                "service_version": version_update,
                "banner": func.coalesce(
                    Service.banner, func.nullif(p.get("banner") or "", "")
                ),
            },
        )
    )


# ── Catalogue rows and findings ──────────────────────────────────────────────

FINDING_SOURCE_FAMILY = {
    "advanced": "network_service",
    "vulnerability_audit": "network_service",
    "scanner": "network_service",
    "scanner_network": "network_service",
    "credentialed": "credentialed_package",
    "credentialed_package": "credentialed_package",
}


def _catalog_title(v: dict, cve_id: str, description: str) -> str:
    """
    A readable title for a CVE.

    The scanner's own title is used when it carries information. Two kinds did
    not: a synthesised ``"Vuln CVE-2026-6475"``, and a vendor/product string
    taken from the first CPE in the affected list — which is how CVE-2024-6387,
    the OpenSSH regreSSHion flaw, came to be titled "Sonicwall Sma 6200
    Firmware Vulnerability", and how PostgreSQL CVEs became "Postgresql
    Postgresql Vulnerability". Falling back to the opening clause of the
    published description names the actual flaw.
    """
    title = str(v.get("title") or "").strip()
    placeholder = (
        not title
        or title.lower().startswith("vuln cve-")
        or title.lower().endswith(" vulnerability")
    )
    if not placeholder:
        return title[:500]

    summary = str(description or "").strip()
    if summary:
        sentence = summary.split(". ")[0].strip().rstrip(".")
        if 12 <= len(sentence) <= 180:
            return sentence
        if summary:
            return summary[:180].rstrip() + ("…" if len(summary) > 180 else "")
    return title or f"Vuln {cve_id}"


def _detection_fields(v: dict) -> Dict[str, Any]:
    """
    The detection and exploit-intelligence columns for one finding.

    Every value here is computed during the scan and printed in the exported
    reports. None of it used to be stored, so the API answered with hardcoded
    zeros: the UI could not tell a version-confirmed finding from an unverified
    guess, and the dashboard showed no known-exploited vulnerabilities while the
    executive PDF named three from the same scan.
    """

    def _num(value):
        try:
            return float(value) if value is not None else None
        except (TypeError, ValueError):
            return None

    kev_due = v.get("kev_due_date")
    if isinstance(kev_due, str):
        from datetime import datetime as _dt

        try:
            kev_due = _dt.fromisoformat(kev_due).date()
        except ValueError:
            kev_due = None

    confidence = str(v.get("confidence") or "").strip().lower() or None
    qod = v.get("qod")
    try:
        qod = int(qod) if qod is not None else None
    except (TypeError, ValueError):
        qod = None

    return {
        "confidence": confidence,
        "qod": qod,
        "detection_method": str(v.get("detection_method") or "").strip() or None,
        "detected_version": str(v.get("detected_version") or "").strip()[:160] or None,
        "cvss_vector": str(v.get("cvss_vector") or "").strip()[:200] or None,
        "cvss_version": str(v.get("cvss_version") or "").strip()[:8] or None,
        "attack_surface": str(v.get("attack_surface") or "").strip()[:16] or None,
        "in_kev": bool(v.get("in_kev")),
        "kev_due_date": kev_due,
        "epss_score": _num(v.get("epss_score")),
        "epss_percentile": _num(v.get("epss_percentile")),
        "has_exploit": bool(v.get("has_exploit")),
        # Exploitation provenance and the vendor's advisory.
        #
        # This is the syncer the vulnerability_audit pipeline uses — the one
        # that actually runs — so omitting these here would have left the whole
        # feed programme invisible on every pipeline scan while appearing to
        # work on the standalone credentialed path. `has_exploit` alone cannot
        # separate a weaponised Metasploit module from an unreproduced proof of
        # concept, which is the distinction triage turns on.
        "exploit_sources": (list(v.get("exploit_sources") or []) or None),
        "verified_exploit": bool(v.get("verified_exploit")),
        "canary_confirmed": bool(v.get("canary_confirmed")),
        "ransomware_linked": bool(v.get("ransomware_linked")),
        "vendor_advisory_id": _vendor_advisory_field(v, "advisory_id"),
        "vendor_advisory_url": _vendor_advisory_field(v, "url"),
        "vendor_remediation": (str(v.get("vendor_remediation") or "").strip() or None),
    }


def _vendor_advisory_field(v: dict, key: str) -> Optional[str]:
    """The first vendor advisory's field, when the finding carries any."""
    advisories = v.get("vendor_advisories") or []
    if not isinstance(advisories, list):
        return None
    for entry in advisories:
        if isinstance(entry, dict) and entry.get(key):
            return str(entry[key])[:2000]
    return None


def _finding_component(
    v: dict, service: Optional[Service]
) -> tuple[Optional[str], Optional[str]]:
    """
    The component a finding is about, and the version observed for it.

    A credentialed finding names its package directly. A network finding names
    the product fingerprinted on the port. Either way this is what an operator
    would actually remediate — you upgrade Chrome, not CVE-2026-13782 — so it is
    the key the UI and the executive report group on.
    """
    package = str(v.get("package") or v.get("package_name") or "").strip()
    if package:
        version = str(
            v.get("installed_version") or v.get("detected_version") or ""
        ).strip()
        return package[:200], (version[:160] or None)

    if service is not None:
        name = str(service.service_product or service.service_name or "").strip()
        if name:
            version = str(service.service_version or "").strip()
            return name[:200], (version[:160] or None)

    # A host-level finding (an OS or kernel CVE) is about the platform itself.
    detected = str(v.get("detected_version") or "").strip()
    if str(v.get("detection_method") or "") == "os_reported":
        return "Operating system", (detected[:160] or None)

    return None, (detected[:160] or None)


def _finding_fixed_version(v: dict) -> Optional[str]:
    """
    The version that resolves this finding, when the source published one.

    Stored beside the component so the grouped view can state the action rather
    than only the problem. Without it a rolled-up row reads "Google Chrome
    138.0.7204.184, 1,736 findings" and leaves "upgrade to what?" unanswered —
    the answer was known at detection time but only ever written into prose.

    Returning None is meaningful: a vulnerability with no published fix is a
    real state, and it must stay distinguishable from one whose fix simply was
    not recorded.
    """
    for key in ("fixed_ver", "fixed_version", "fixed_in"):
        value = str(v.get(key) or "").strip()
        if value and value.lower() not in {"none", "n/a", "unknown", "-"}:
            return value[:160]
    return None


def _stored_severity(finding: dict, cvss_score: Optional[float]) -> str:
    """
    The severity written for a finding: from its CVSS score, else as declared.

    A network or configuration check — TLS hostname mismatch, missing security
    headers — carries a severity its check definition states and no CVSS score.
    Deriving severity from the score alone stored those as "unscored" while the
    report, the CSV and the scan's own severity counts said Medium and Low, so
    the findings page disagreed with every report of the same scan.
    """
    if cvss_score is not None:
        return severity_from_score(cvss_score).lower()
    return normalize_severity(finding.get("severity"))


def _build_finding_evidence(
    v: dict, service: Optional[Service], host_data: dict, cve_id: str = ""
) -> str:
    """
    Record what the scan observed that caused this finding to be raised.

    An operator reading a finding has to be able to answer "why does the tool
    think this is here?" without re-running the scan. That means the service
    that was probed, the version fingerprinted on it, the banner the host
    returned, and the published range the version was tested against — not the
    CVE's catalogue description, which says nothing about this host.
    """
    lines: List[str] = []

    if service is not None and service.port is not None:
        lines.append(f"Port/Protocol    : {service.port}/{service.protocol or 'tcp'}")
        if service.service_name:
            lines.append(f"Service          : {service.service_name}")
        product = service.service_product or ""
        if product:
            lines.append(f"Product          : {product}")
        observed = service.service_version or ""
        lines.append(f"Detected version : {observed or 'not determined by this scan'}")
        if service.banner:
            lines.append(f"Service banner   : {str(service.banner)[:400]}")
    else:
        # A host-level finding (an OS or kernel CVE) has no listening service
        # behind it. Saying so is more honest than binding it to a port.
        lines.append("Scope            : host-level (no listening service implicated)")
        os_name = host_data.get("os_guess") or host_data.get("os_name") or ""
        if os_name:
            lines.append(f"Operating system : {os_name}")
        detected = str(v.get("detected_version") or "").strip()
        if detected:
            lines.append(f"Detected version : {detected}")

    method = str(v.get("detection_method") or "").strip()
    confidence = str(v.get("confidence") or "").strip()
    qod = v.get("qod")
    if method or confidence:
        detail = " · ".join(
            part
            for part in (
                f"confidence {confidence}" if confidence else "",
                f"method {method}" if method else "",
                f"QoD {qod}%" if qod is not None else "",
            )
            if part
        )
        lines.append(f"Determination    : {detail}")

    fixed = str(v.get("fixed_version") or v.get("fixed_in") or "").strip()
    if fixed:
        lines.append(f"Fixed in         : {fixed}")

    matched = v.get("matched_range") or v.get("vulnerable_range")
    if matched:
        lines.append(f"Vulnerable range : {str(matched)[:200]}")

    if cve_id:
        lines.append(f"Reference        : https://nvd.nist.gov/vuln/detail/{cve_id}")

    # A plugin that captured real probe output (a TLS handshake, an HTTP
    # response, an SNMP sysDescr) contributes it verbatim underneath.
    #
    # Skipped for host-level findings: the upstream block is rendered from the
    # service the candidate was originally generated against, and appending it
    # to a finding that has just declared "no listening service implicated"
    # contradicts the line above it.
    captured = str(v.get("evidence") or v.get("proof") or "").strip()
    if (
        (service is not None or v.get("endpoint_observations"))
        and captured
        and captured != "Source_Family:network_service"
    ):
        lines.append("")
        lines.append("Probe output:")
        lines.append(captured if v.get("endpoint_observations") else captured[:2000])

    return "\n".join(lines)


def _finding_family(source: str) -> str:
    return FINDING_SOURCE_FAMILY.get(_normalize_source(source), "unknown")


def _finding_source_from_record(finding: AssetVulnerability) -> str:
    source_family = getattr(finding, "source_family", None)
    if _has_value(source_family) and source_family != "unknown":
        return (
            "credentialed_package"
            if source_family == "credentialed_package"
            else "vulnerability_audit"
        )
    text = " ".join(
        str(v or "") for v in (finding.proof, finding.plugin_output)
    ).lower()
    if "source_family:credentialed_package" in text or "package:" in text:
        return "credentialed_package"
    if "source_family:network_service" in text:
        return "vulnerability_audit"
    return "vulnerability_audit"


CREDENTIALED_FAMILY = "credentialed_package"


def _row_family(finding: AssetVulnerability) -> str:
    """
    The family a stored finding belongs to, for deciding which scan may retire it.

    The vulnerability-audit pipeline filed every finding under network_service,
    including the package, configuration and privilege findings its credentialed
    enrichment adds, so an unauthenticated rescan of the host "covered" them and
    swept them as fixed: on 13 Oct 2026 scan #19 retired all 2,281 of #17's
    credentialed findings, a remediation nobody made. Rows written that way
    before the fix still say network_service; their detection method or
    identifier says where they came from.
    """
    family = _finding_family(_finding_source_from_record(finding))
    if family == CREDENTIALED_FAMILY:
        return family
    detection = str(getattr(finding, "detection_method", "") or "").lower()
    identifier = str(getattr(finding, "vuln_id", "") or "").upper()
    if detection in CREDENTIALED_DETECTIONS or identifier.startswith(
        CREDENTIALED_ID_PREFIXES
    ):
        return CREDENTIALED_FAMILY
    return family


def _credentialed_assessment(host: dict) -> Optional[dict]:
    """
    What this scan's credentialed audit of ``host`` assessed, or None if none ran.

    ``packages`` says whether absent package CVEs are gone; ``checks`` is the
    set of configuration checks that reached a verdict. See
    core.findings.credentialed_scope.
    """
    report = host.get("credentialed_report")
    if not host.get("credentialed") or not isinstance(report, dict) or not report:
        return None
    config_summary = report.get("config_audit") or {}
    checks = assessed_check_ids(config_summary)
    return {
        "packages": packages_assessed(report),
        "checks": checks,
        "config_audit_assessed": bool(
            isinstance(config_summary, dict) and config_summary.get("assessed")
        ),
    }


def _source_specific_finding_id(asset_id: str, cve_id: str, source_family: str) -> str:
    return f"fnd_{asset_id}_{source_family}_{cve_id}"


#: Separates a product qualifier from the finding id it qualifies (the
#: downgrade of migration a7c9e1b3d5f8 relies on it).
_COMPONENT_ID_MARK = "__"


def _explicit_package(v: dict) -> str:
    return str(v.get("package") or v.get("package_name") or "").strip()


def _component_finding_id(base_id: str, package: str) -> str:
    digest = hashlib.sha1(package.lower().encode(), usedforsecurity=False).hexdigest()
    return f"{base_id}{_COMPONENT_ID_MARK}{digest[:10]}"


def _base_id_owners(
    db: Session,
    org_id: str,
    asset_id: str,
    source_family: str,
    vulns: list,
) -> Dict[str, str]:
    """
    For each CVE this host reports against a named product, the product that
    owns the CVE's base finding id.

    A finding was keyed by (asset, CVE, family), so one CVE affecting six
    installed Siemens products — reported as six findings — was stored as one
    row naming whichever product was written last. Each product now has its
    own row: the base id stays with the product already stored under it, for
    good, and every other product takes an id qualified by its name. Only a
    CVE with no stored row yet gives the base id to the first product by
    name, so the choice never depends on the order a scan lists them in, and
    the common one-product case keeps exactly the id it always had.
    """
    present: Dict[str, set] = {}
    for v in vulns:
        cve_id = v.get("cve_id") or v.get("cve") or v.get("id")
        package = _explicit_package(v)
        if cve_id and package:
            present.setdefault(cve_id, set()).add(package)
    if not present:
        return {}

    legacy_ids = {f"fnd_{asset_id}_{cve}": cve for cve in present}
    specific_ids = {
        _source_specific_finding_id(asset_id, cve, source_family): cve
        for cve in present
    }
    stored: Dict[str, Optional[str]] = {}
    rows = (
        db.query(AssetVulnerability)
        .filter(
            AssetVulnerability.org_id == org_id,
            AssetVulnerability.id.in_(list(legacy_ids) + list(specific_ids)),
        )
        .all()
    )
    for row in rows:
        if row.id in legacy_ids:
            # The legacy id is the base id only while its family matches,
            # exactly as _resolve_finding_id decides.
            if _finding_family(_finding_source_from_record(row)) == source_family:
                stored[legacy_ids[row.id]] = row.component
        else:
            stored.setdefault(specific_ids[row.id], row.component)

    return {
        cve: (stored.get(cve) or sorted(names)[0]) for cve, names in present.items()
    }


def _resolve_finding_id(
    db: Session, org_id: str, asset_id: str, cve_id: str, source_family: str
) -> str:
    legacy_id = f"fnd_{asset_id}_{cve_id}"
    existing = (
        db.query(AssetVulnerability)
        .filter(
            AssetVulnerability.id == legacy_id,
            AssetVulnerability.org_id == org_id,
        )
        .first()
    )
    if (
        existing
        and _finding_family(_finding_source_from_record(existing)) == source_family
    ):
        return legacy_id
    return _source_specific_finding_id(asset_id, cve_id, source_family)


def risk_from_open_findings(db: Session, asset_id: str):
    sev_rows = (
        db.query(
            AssetVulnerability.severity, func.count(AssetVulnerability.id).label("cnt")
        )
        .filter(
            AssetVulnerability.asset_id == asset_id, AssetVulnerability.status == "open"
        )
        .group_by(AssetVulnerability.severity)
        .all()
    )
    # Folded, and accumulated rather than assigned: GROUP BY yields one row per
    # stored spelling, so keying a dict on the normalised form silently drops a
    # count whenever two spellings coexist.
    sev_map: Dict[str, int] = {}
    for r in sev_rows or []:
        key = canonical_severity(r.severity)
        sev_map[key] = sev_map.get(key, 0) + r.cnt
    counts = {
        "critical": sev_map.get("critical", 0),
        "high": sev_map.get("high", 0),
        "medium": sev_map.get("medium", 0),
        "low": sev_map.get("low", 0),
    }
    computed = min(
        100,
        counts["critical"] * 25
        + counts["high"] * 15
        + counts["medium"] * 8
        + counts["low"] * 3,
    )
    return (
        counts,
        computed,
        (
            "Critical"
            if computed >= 90
            else (
                "High"
                if computed >= 70
                else "Medium" if computed >= 40 else "Low" if computed > 0 else "Info"
            )
        ),
    )


class HostFindings(NamedTuple):
    """What ``write_host_findings`` decided, for its caller's record of the scan."""

    #: The family this pass files its network findings under.
    source_family: str
    #: What the host's credentialed audit assessed, or None if none ran.
    credentialed: Optional[dict]


def write_host_findings(
    db: Session,
    *,
    org_id: str,
    scan_id: str,
    asset_id: str,
    host: dict,
    catalogue_cache: Dict[str, Optional[dict]],
    record_change: RecordChange,
) -> HostFindings:
    """
    One host's vulnerability-audit findings: the catalogue rows they name, the
    findings, and the sweep of the findings this scan retired.

    Moved unchanged from ``scans.asset_syncer.sync_vulnerability_audit``'s host
    loop (G3). ``catalogue_cache`` is that sync's memo of CVE details, shared
    by its hosts.
    """
    source_family = _finding_family("vulnerability_audit")
    found_in_this_scan = set()
    vulns = host.get("vulnerabilities") or host.get("cves") or []

    # Service rows are written by the asset-discovery phase, not here, so
    # the set of valid FK targets is read back rather than assumed. A
    # finding referencing a service row that was never recorded would fail
    # the foreign key and abort the whole insert.
    # Keyed by id rather than collected as a bare set: the evidence written
    # with each finding names the service it was observed on, so the row
    # itself is needed, not just proof that the FK target exists.
    service_by_id: Dict[str, Service] = {}
    if vulns:
        service_by_id = {
            row.id: row
            for row in db.query(Service).filter(Service.asset_id == asset_id).all()
        }
    synced_service_ids = set(service_by_id)
    base_id_owners = _base_id_owners(db, org_id, asset_id, source_family, vulns)
    written_finding_ids: set = set()
    written_components: Dict[str, set] = {}
    for v in vulns:
        cve_id = v.get("cve_id") or v.get("cve") or v.get("id")
        if not cve_id:
            continue
        found_in_this_scan.add(cve_id)

        # What kind of catalogue row this identifier names. Recovered from
        # the identifier rather than trusted from the finding, because the
        # finding is built by a plugin and the catalogue's CHECK constraint
        # is what has to hold.
        #
        # Before this, the insert below set neither `definition_type` nor a
        # NULL `cve_id`, so every non-CVE network finding — MISC-FTP-ANON,
        # MISC-REDIS-NOAUTH, every MISC-NUCLEI-<template> — took the column
        # default 'cve' and stored its own fabricated string in `cve_id`.
        # It then inherited everything a CVE row means: KEV membership
        # lookups, EPSS scoring, CVSS band tables, and an NVD link that
        # resolves to nothing. ck_vuln_def_cve_id_matches_type could not
        # catch it, because the row did carry a cve_id — just not a real one.
        definition_type = definition_type_for_id(cve_id)
        is_real_cve = definition_type == DEFINITION_TYPE_CVE

        # Get enriched details from local CVE database if available
        description = None
        cvss_vector = None
        cwe_ids = []
        references = []
        published_at = None
        affected_software = []

        try:
            from core.cve_database import get_cve_database

            # Only a real CVE is looked up in the CVE feed. A check
            # identifier has no NVD record by definition, so the query
            # could only ever return nothing — one wasted round trip per
            # check finding per host, and a lookup whose *intent* is wrong
            # even where its result is harmless.
            cve_db = get_cve_database() if is_real_cve else None
            if cve_db is not None and cve_db.db_available:
                # One round trip per CVE, memoised for this sync. The same
                # CVE is routinely present on several hosts in a scan, and
                # the record is immutable for the duration of the run.
                if cve_id in catalogue_cache:
                    details = catalogue_cache[cve_id]
                else:
                    details = cve_db.get_cve_details(cve_id)
                    catalogue_cache[cve_id] = details
                if details:
                    description = details.get("description")
                    cvss_vector = details.get("cvss_vector") or details.get(
                        "cvss_v3_vector"
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

                    # CPE version ranges. The report compares the detected
                    # service version against these boundaries to confirm a
                    # finding or rule it out; without them every finding can
                    # only ever be reported as unverified.
                    affected_software = [
                        cpe
                        for cpe in (details.get("affected") or [])
                        if isinstance(cpe, dict)
                    ]

                    from datetime import date, datetime

                    pub = details.get("published")
                    if isinstance(pub, str):
                        try:
                            published_at = datetime.fromisoformat(pub).date()
                        except ValueError:
                            pass
                    elif isinstance(pub, (datetime, date)):
                        published_at = pub
        except Exception as e:
            logger.warning(
                "Failed to lookup CVE details for %s during sync: %s", cve_id, e
            )

        # UPSERT Catalog
        #
        # This backfills enrichment onto CVE rows that already exist. The
        # previous do-nothing behaviour meant a CVE first seen before the
        # feed carried CPE ranges could never acquire them, so its findings
        # would stay permanently unverifiable. Each field falls back to the
        # stored value, so a lookup that returns nothing never erases data.
        # The score has to be filed under the CVSS revision it was actually
        # published in. Writing every score to cvss_v3_score put 751 v2
        # scores in the v3 column, and because v2 has no Critical tier the
        # two revisions' band tables then disagreed above 9.0 — the same CVE
        # came out "High" in one code path and "critical" in another.
        cvss_score_val = float(v.get("cvss") or v.get("cvss_score") or 0.0) or None
        cvss_ver = str(
            v.get("cvss_version") or cvss_version_of_vector(cvss_vector) or ""
        ).strip()
        score_columns = {
            "cvss_v2_score": cvss_score_val if cvss_ver.startswith("2") else None,
            "cvss_v3_score": (
                cvss_score_val if cvss_ver.startswith("3") or not cvss_ver else None
            ),
            "cvss_v4_score": cvss_score_val if cvss_ver.startswith("4") else None,
        }

        catalog_stmt = insert(VulnerabilityDefinition).values(
            id=cve_id,
            # NULL for anything that is not a published CVE. This is the
            # column every join to the vulnerability feeds runs through, so
            # a check row carrying a CVE-shaped string here is how a
            # configuration weakness acquires an exploit record, a KEV due
            # date and a CVSS band that belong to nothing.
            cve_id=cve_id if is_real_cve else None,
            definition_type=definition_type,
            title=_catalog_title(v, cve_id, description),
            description=description,
            cvss_vector=cvss_vector,
            cvss_version=cvss_ver or None,
            cwe_ids=cwe_ids,
            references=references,
            affected_software=affected_software,
            published_at=published_at,
            severity=_stored_severity(v, cvss_score_val),
            source="scanner",
            created_at=utcnow(),
            updated_at=utcnow(),
            **score_columns,
        )
        db.execute(
            catalog_stmt.on_conflict_do_update(
                index_elements=["id"],
                set_={
                    "description": func.coalesce(
                        func.nullif(catalog_stmt.excluded.description, ""),
                        VulnerabilityDefinition.description,
                    ),
                    "cvss_vector": func.coalesce(
                        func.nullif(catalog_stmt.excluded.cvss_vector, ""),
                        VulnerabilityDefinition.cvss_vector,
                    ),
                    "cvss_v2_score": func.coalesce(
                        catalog_stmt.excluded.cvss_v2_score,
                        VulnerabilityDefinition.cvss_v2_score,
                    ),
                    "cvss_v3_score": func.coalesce(
                        catalog_stmt.excluded.cvss_v3_score,
                        VulnerabilityDefinition.cvss_v3_score,
                    ),
                    "cvss_v4_score": func.coalesce(
                        catalog_stmt.excluded.cvss_v4_score,
                        VulnerabilityDefinition.cvss_v4_score,
                    ),
                    "cvss_version": func.coalesce(
                        func.nullif(catalog_stmt.excluded.cvss_version, ""),
                        VulnerabilityDefinition.cvss_version,
                    ),
                    # Severity was previously omitted here, so a row created
                    # by an earlier import kept whatever spelling and scale
                    # that import used no matter how often it was re-seen.
                    "severity": catalog_stmt.excluded.severity,
                    "published_at": func.coalesce(
                        catalog_stmt.excluded.published_at,
                        VulnerabilityDefinition.published_at,
                    ),
                    # A real CVE title should replace a synthesised
                    # placeholder ("Vuln CVE-2026-6475"), but never the
                    # other way round.
                    "title": case(
                        (
                            catalog_stmt.excluded.title.like("Vuln CVE-%"),
                            VulnerabilityDefinition.title,
                        ),
                        else_=func.coalesce(
                            func.nullif(catalog_stmt.excluded.title, ""),
                            VulnerabilityDefinition.title,
                        ),
                    ),
                    "cwe_ids": func.coalesce(
                        func.nullif(catalog_stmt.excluded.cwe_ids, "[]"),
                        VulnerabilityDefinition.cwe_ids,
                    ),
                    "references": func.coalesce(
                        func.nullif(catalog_stmt.excluded.references, "[]"),
                        VulnerabilityDefinition.references,
                    ),
                    "affected_software": func.coalesce(
                        func.nullif(catalog_stmt.excluded.affected_software, "[]"),
                        VulnerabilityDefinition.affected_software,
                    ),
                    # Converge the typing on every re-scan rather than only
                    # on first insert. A row written before this phase is a
                    # check filed as a `cve` carrying a fabricated cve_id;
                    # without these two the migration would be the only
                    # thing that could ever repair it, and a database
                    # restored from an older dump would silently go back to
                    # producing fabricated CVEs. Both are computed from the
                    # identifier, so this can only ever move a row towards
                    # the constraint, never away from it.
                    "definition_type": catalog_stmt.excluded.definition_type,
                    "cve_id": catalog_stmt.excluded.cve_id,
                    "updated_at": utcnow(),
                },
            )
        )

        # PHASE 4: Detect Reopened Vulnerabilities
        finding_id = _resolve_finding_id(db, org_id, asset_id, cve_id, source_family)
        package = _explicit_package(v)
        if package and base_id_owners.get(cve_id, package) != package:
            finding_id = _component_finding_id(finding_id, package)
        written_finding_ids.add(finding_id)
        existing_fnd = (
            db.query(AssetVulnerability)
            .filter(AssetVulnerability.id == finding_id)
            .first()
        )

        if existing_fnd and existing_fnd.status in ("fixed", STATUS_RULED_OUT):
            record_change(
                db, asset_id, scan_id, "vulnerability_reopened", cve_id, "open"
            )

        # Bind the finding to the service it was observed on. The report
        # resolves the port, product, and detected version through this FK,
        # which is what lets it compare the running version against the
        # CVE's vulnerable range instead of reporting it unverified.
        finding_service_id = None
        vuln_port = v.get("port")
        if vuln_port is not None:
            try:
                finding_service_id = gen_service_id(
                    asset_id, int(vuln_port), str(v.get("protocol") or "tcp")
                )
            except (TypeError, ValueError):
                finding_service_id = None

        # Only reference a service row that this scan actually recorded,
        # otherwise the FK insert fails and takes the whole finding with it.
        if finding_service_id and finding_service_id not in synced_service_ids:
            finding_service_id = None

        # An OS-level finding is about the host. The verifier already strips
        # the port from these, but the upsert below deliberately preserves a
        # previous binding when the current pass resolves none — which meant
        # a kernel CVE first recorded against 161/udp kept that port for
        # ever. Host-level findings clear it instead.
        is_host_level = str(v.get("detection_method") or "") == "os_reported"

        # ── Evidence ─────────────────────────────────────────────────────
        # Every finding used to store the identical literal
        # "Source_Family:network_service" in `proof`, and the CVE's
        # catalogue description in `plugin_output`. Neither is evidence:
        # one is a constant, the other is text the scan did not produce, so
        # nothing recorded why the finding was raised against this host.
        #
        # What is recorded now is the observation the match was made on —
        # the service, the version fingerprinted on it, the banner returned,
        # and the published range that version was tested against.
        finding_service = service_by_id.get(finding_service_id)
        from core.checks.endpoint_evidence import render_observations

        for observation in v.get("endpoint_observations") or []:
            try:
                endpoint_id = gen_service_id(
                    asset_id,
                    int(observation["port"]),
                    str(observation.get("protocol") or "tcp"),
                )
            except (KeyError, TypeError, ValueError):
                continue
            observed_service = service_by_id.get(endpoint_id)
            if observed_service is not None:
                observation["service_id"] = endpoint_id
                observation["service_name"] = observed_service.service_name
        if v.get("endpoint_observations"):
            v["evidence"] = render_observations(v["endpoint_observations"])
        evidence = _build_finding_evidence(v, finding_service, host, cve_id=cve_id)
        # The family a later scan must cover before it can retire this
        # finding; the id above keeps the pipeline's, unchanged.
        row_family = (
            CREDENTIALED_FAMILY if is_credentialed_finding(v) else source_family
        )
        proof = f"Source_Family:{row_family}"
        plugin_output = (
            v.get("plugin_output") or v.get("description") or v.get("desc") or ""
        )

        detection = _detection_fields(v)
        finding_cvss = float(v.get("cvss") or v.get("cvss_score") or 0.0) or None
        finding_severity = _stored_severity(v, finding_cvss)
        component, component_version = _finding_component(v, finding_service)
        detection["component"] = component
        detection["component_version"] = component_version
        if component:
            written_components.setdefault(cve_id, set()).add(component)
        detection["component_fixed_version"] = _finding_fixed_version(v)
        # Refreshed with the version on every re-detection: the day the
        # distribution releases a fix, the finding stops reading as one
        # nobody can patch.
        detection["fix_state"] = fix_state_for(v)
        db.execute(
            insert(AssetVulnerability)
            .values(
                id=finding_id,
                org_id=org_id,
                scan_id=scan_id,
                asset_id=asset_id,
                vuln_id=cve_id,
                service_id=finding_service_id,
                severity=finding_severity,
                cvss_score=finding_cvss,
                status="open",
                proof=proof,
                plugin_output=plugin_output,
                evidence=evidence,
                source_family=row_family,
                evidence_source=str(v.get("evidence_source") or "vulnerability_audit"),
                first_scan_id=scan_id,
                first_found_at=utcnow(),
                last_found_at=utcnow(),
                **detection,
            )
            .on_conflict_do_update(
                index_elements=["id", "org_id"],
                set_={
                    "last_found_at": utcnow(),
                    "scan_id": scan_id,
                    "status": "open",
                    "severity": finding_severity,
                    "cvss_score": finding_cvss,
                    "source_family": row_family,
                    "evidence_source": str(
                        v.get("evidence_source") or "vulnerability_audit"
                    ),
                    # Keep an existing binding when this pass could not
                    # resolve one, so a re-scan never loses port context —
                    # except for host-level findings, which must not carry
                    # a port at all.
                    "service_id": (
                        None
                        if is_host_level
                        else func.coalesce(
                            finding_service_id, AssetVulnerability.service_id
                        )
                    ),
                    "proof": func.coalesce(
                        func.nullif(proof, ""), AssetVulnerability.proof
                    ),
                    "plugin_output": func.coalesce(
                        func.nullif(plugin_output or "", ""),
                        AssetVulnerability.plugin_output,
                    ),
                    # Re-observed: this scan's evidence is the current one.
                    "evidence": func.coalesce(
                        func.nullif(evidence or "", ""),
                        AssetVulnerability.evidence,
                    ),
                    # Written once, so "which findings did scan N report?"
                    # survives the re-scan that moves scan_id forward.
                    "first_scan_id": func.coalesce(
                        AssetVulnerability.first_scan_id, scan_id
                    ),
                    **detection,
                },
            )
        )

    # PHASE 4: Targeted Remediation with History
    open_findings = (
        db.query(AssetVulnerability)
        .filter(
            AssetVulnerability.asset_id == asset_id,
            AssetVulnerability.status == "open",
        )
        .all()
    )

    # What this scan positively ruled out on this host — "Ruled out: the
    # version detected … falls outside the vulnerable range" and the like.
    # A finding that disappears for that reason was never there, and
    # recording it as "fixed" claimed a remediation nobody made: 41
    # PostgreSQL findings raised against nmap's "9.6.0 or later" were
    # marked fixed once an authenticated scan read the real 18.3.
    ruled_out_here = {
        str(entry.get("identifier") or "").strip().upper()
        for entry in host.get("suppressed_cves") or []
        if isinstance(entry, dict)
        and str(entry.get("reason") or "").startswith("Ruled out")
    }
    # Credentialed findings are retired only by a scan whose credentialed
    # audit of this host assessed them: package CVEs when the inventory was
    # collected and matched, configuration findings when their check
    # reached a verdict. An unauthenticated rescan assesses neither.
    credentialed = _credentialed_assessment(host)
    for f in open_findings:
        family = _row_family(f)
        if family == CREDENTIALED_FAMILY:
            if credentialed is None:
                continue
            if definition_type_for_id(f.vuln_id) == DEFINITION_TYPE_CVE:
                if not credentialed["packages"]:
                    continue
            elif f.vuln_id not in credentialed["checks"]:
                continue
        elif family != source_family:
            continue
        elif "plugin_outcomes" in host:
            # Absence after an incomplete network assessment is not remediation.
            from core.checks.plugin_outcomes import coverage_summary

            if not coverage_summary([host])["complete"]:
                continue
        if f.id in written_finding_ids:
            continue
        # A product's row is gone when *its* product no longer reports the
        # CVE, even if another product on the host still does.
        gone_product = bool(f.component) and f.component not in (
            written_components.get(f.vuln_id) or set()
        )
        if f.vuln_id not in found_in_this_scan or gone_product:
            ruled_out = (
                not gone_product and str(f.vuln_id or "").upper() in ruled_out_here
            )
            f.status = STATUS_RULED_OUT if ruled_out else "fixed"
            f.fixed_at = utcnow()
            record_change(
                db,
                asset_id,
                scan_id,
                "vulnerability_ruled_out" if ruled_out else "vulnerability_fixed",
                f.vuln_id,
                f.status,
            )
    return HostFindings(source_family, credentialed)


def upsert_tls_details(db: Session, asset_id: str, host: dict) -> None:
    """
    The TLS reading of the host's first TLS port, when the scan made one.

    Moved unchanged from ``scans.asset_syncer.sync_vulnerability_audit`` (G3).
    """
    # Upsert TLS Details if present
    tls_info = host.get("tls_info")
    if tls_info and tls_info.get("enabled"):
        open_ports = [
            p.get("port") for p in host.get("open_ports", []) if p.get("port")
        ]
        tls_port = None
        for p in [443, 8443, 465, 993, 995]:
            if p in open_ports:
                tls_port = p
                break

        if tls_port:
            service_id = gen_service_id(asset_id, tls_port, "tcp")

            # Parse expiration datetime
            cert_expiry_raw = tls_info.get("cert_expiry")
            cert_not_after = None
            if cert_expiry_raw:
                try:
                    from datetime import datetime, timezone

                    clean_expiry = " ".join(cert_expiry_raw.split())
                    cert_not_after = datetime.strptime(
                        clean_expiry, "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=timezone.utc)
                except Exception:
                    try:
                        # Fallback if cert_expiry is written in ISO format or another standard format
                        cert_not_after = datetime.fromisoformat(
                            cert_expiry_raw.replace("Z", "+00:00")
                        )
                    except Exception:
                        pass

            cert_subject = {"common_name": tls_info.get("cert_subject") or ""}
            cert_issuer = {"common_name": tls_info.get("cert_issuer") or ""}

            tls_insert = insert(TLSDetail).values(
                service_id=service_id,
                is_enabled=True,
                protocol_version=tls_info.get("version"),
                cipher_suite=tls_info.get("cipher"),
                grade=tls_info.get("score") or "N/A",
                is_weak_cipher=tls_info.get("weak_cipher") or False,
                cert_is_expired=tls_info.get("cert_expired") or False,
                cert_is_self_signed=tls_info.get("cert_self_signed") or False,
                cert_not_after=cert_not_after,
                cert_subject=cert_subject,
                cert_issuer=cert_issuer,
                issues=tls_info.get("issues") or [],
                created_at=utcnow(),
            )

            tls_upsert = tls_insert.on_conflict_do_update(
                index_elements=["service_id"],
                set_={
                    "protocol_version": tls_info.get("version"),
                    "cipher_suite": tls_info.get("cipher"),
                    "grade": tls_info.get("score") or "N/A",
                    "is_weak_cipher": tls_info.get("weak_cipher") or False,
                    "cert_is_expired": tls_info.get("cert_expired") or False,
                    "cert_is_self_signed": tls_info.get("cert_self_signed") or False,
                    "cert_not_after": cert_not_after,
                    "cert_subject": cert_subject,
                    "cert_issuer": cert_issuer,
                    "issues": tls_info.get("issues") or [],
                },
            )
            db.execute(tls_upsert)


# ── The standalone credentialed audit ───────────────────────────────────────
#
# From ``scans.tasks.credentialed_sync`` (G3): the catalogue rows and findings a
# credentialed audit reported, and the sweep of those it retired. Its code logs
# under ``ccure.tasks``, the name the task hub's always had.

log = logging.getLogger("ccure.tasks")


# Shared with the pipeline's sweep (``_credentialed_assessment``), so the two
# cannot disagree about which absent findings a credentialed audit really
# retired.
_assessed_config_definition_ids = assessed_check_ids


def _clean_text(value) -> str:
    return str(value or "").strip()


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
    asset,
    org_id: str,
    scan_id: str,
    cve_list: list[dict],
) -> None:
    from core.checks.definitions import (
        DEFINITION_TYPE_CVE,
        definition_type_for_id,
    )

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


class CredentialedSweep(NamedTuple):
    """What ``sweep_credentialed_findings`` found the audit assessed."""

    #: The audit's configuration summary (``config_audit``).
    config_summary: dict
    #: The configuration checks that reached a verdict.
    assessed_checks: set
    #: Whether the package inventory was collected and matched.
    packages_assessed: bool


def sweep_credentialed_findings(
    db: Session,
    *,
    asset_id: str,
    scan_id: str,
    cve_list: list[dict],
    stored_report: dict,
    record_change: RecordChange,
) -> CredentialedSweep:
    """
    Mark fixed the open credentialed findings this audit no longer reports,
    when it assessed them.

    Moved unchanged from
    ``scans.tasks.credentialed_sync._sync_credentialed_asset_identity`` (G3).
    """
    found_cve_ids = {
        _clean_text(v.get("cve_id") or v.get("cve") or v.get("id"))
        for v in (cve_list or [])
    }
    found_cve_ids = {cid for cid in found_cve_ids if cid}

    current_open = (
        db.query(AssetVulnerability)
        .filter(
            AssetVulnerability.asset_id == asset_id, AssetVulnerability.status == "open"
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
        record_change(db, asset_id, scan_id, "vulnerability_fixed", f.vuln_id, "fixed")
    return CredentialedSweep(_config_summary, _assessed_checks, _packages_assessed)
