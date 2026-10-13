"""
scans/asset_syncer.py
───────────────────────────────────────────────────────────────────────────────
Performs "Identity Resolution" and synchronizes scanner payload blobs
into their respective normalized PostgreSQL rows (assets, services, findings).
"""

import hashlib
import logging
from typing import Any, Dict, List, Optional

from core.checks.definitions import (
    DEFINITION_TYPE_CVE,
    definition_type_for_id,
    is_cve_id,
)
from core.mac import mac_identity
from db.base import gen_asset_id, gen_service_id, utcnow
from db.models import (
    Asset,
    AssetChangeLog,
    AssetVulnerability,
    Service,
    VulnerabilityDefinition,
)
from db.models.findings import (
    SOURCE_CREDENTIALED,
    SOURCE_NETWORK_SCAN,
    STATE_HOST_ONLY,
    STATE_LISTENING,
    STATE_OPEN,
)
from engines.credentialed.coverage import BIND_LOOPBACK, bind_scope
from core.checks.contract import normalize_severity
from core.findings.comparison import STATUS_RULED_OUT
from scans.db_text import sanitize_for_db_in_place
from scans.cvss import (
    canonical_severity,
    cvss_version_of_vector,
    severity_from_score,
)
from sqlalchemy import case, func, or_
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

# Signal priority for device_classifier — used to prevent low-confidence
# classifications from overwriting high-confidence ones.
# Matches the priority chain in core/device_classifier.py classify_device():
#   1. snmp       (highest — active OID interrogation)
#   2. l2_sniffer (high — passive CDP/LLDP/STP multicast)
#   3. mdns       (high — mDNS service records)
#   4. netbios    (high — NetBIOS suffix roles)
#   5. nmap_cpe   (medium-high — active OS stack detection)
#   6. port_profile (medium-high — port set hints)
#   7. banner     (medium — service banner keywords)
#   8. oui        (medium — vendor substring match)
#   9. ttl        (low — OS family heuristic)
#   10. none      (fallback — unknown)
_DEVICE_SIGNAL_PRIORITY = {
    "credentialed": 110,
    "snmp": 100,
    "l2_sniffer": 95,
    "mdns": 90,
    "netbios": 85,
    "nmap_cpe": 80,
    "port_profile": 70,
    "banner": 50,
    "oui": 40,
    "ttl": 20,
    "none": 0,
}


def _clean(value) -> str:
    return str(value or "").strip()


def _port_int(value) -> int | None:
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


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


def _service_identity_from_process(
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


#: What an authenticated pass concluded about a host, recorded on the asset.
#:
#: ``success`` is the only value the compliance engine treats as "this host was
#: authenticated to"; everything else routes a credentialed rule to
#: ``manual_review`` rather than to a verdict, which is the safe direction.
CREDENTIALED_STATUS_SUCCESS = "success"
CREDENTIALED_STATUS_FAILED = "failed"


def set_credentialed_status(asset, status: str) -> None:
    """
    Record whether this scan authenticated to *asset*.

    One definition, called from both authenticated paths. The standalone audit
    set this inline while the Vulnerability Audit's credentialed pass did not,
    so a host that was authenticated to, collected from and audited for
    configuration still read as ``unknown`` — and
    ``core.compliance_tasks`` routes every rule in
    ``CREDENTIALED_EVIDENCE_SOURCES`` to ``manual_review`` unless this says
    ``success``. The scan had the evidence; the compliance register reported it
    as unassessed.

    ``custom_attributes`` is reassigned rather than mutated in place: it is a
    JSONB column and SQLAlchemy does not track mutation of a plain dict, so an
    in-place write is silently dropped at flush.
    """
    attrs = dict(asset.custom_attributes or {})
    attrs["credentialed_status"] = status
    asset.custom_attributes = attrs


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
            service_product, service_version = _service_identity_from_process(
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


def _upsert_network_service(db: Session, asset_id: str, scan_id: str, p: dict) -> None:
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


def _get_stored_device_signal(asset: Asset) -> str | None:
    """
    Read the stored device classification signal from the asset's custom_attributes.
    Returns None if no previous classification exists.
    """
    attrs = dict(asset.custom_attributes or {})
    provenance = dict(attrs.get("provenance") or {})
    dev_prov = provenance.get("device_category") or {}
    return dev_prov.get("signal")


SOURCE_PRIORITY = {
    "legacy": 5,
    "discovery": 10,
    "basic": 10,
    "host_discovery": 10,
    "asset_discovery": 20,
    "fingerprinting": 20,
    "advanced": 30,
    "vulnerability_audit": 30,
    "scanner": 30,
    "scanner_network": 30,
    "credentialed": 40,
    "credentialed_package": 40,
}

FINDING_SOURCE_FAMILY = {
    "advanced": "network_service",
    "vulnerability_audit": "network_service",
    "scanner": "network_service",
    "scanner_network": "network_service",
    "credentialed": "credentialed_package",
    "credentialed_package": "credentialed_package",
}

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


def _resolve_ip(host_data: dict) -> str:
    return str(host_data.get("ip_address") or host_data.get("ip") or "0.0.0.0").strip()


def _resolve_mac(host_data: dict) -> str | None:
    """
    Return a canonical lowercase colon-separated MAC, or None.

    Case matters here. PostgreSQL's ``macaddr`` type stores addresses
    lowercase, so writing them uppercase made every scan see the stored
    lowercase value differ from the incoming uppercase one and log a MAC
    "change" that never happened — on every host, on every scan.

    *Spacing* matters for the same reason, and used not to be handled. This
    lowercased and swapped hyphens for colons but did not otherwise normalize,
    so a scanner emitting ``001a2b3c4d5e`` or ``001a.2b3c.4d5e`` got that
    string back unchanged. The database tolerates both — ``macaddr`` parses
    every dialect and stores one canonical value — but ``_existing_assets_for_hosts``
    keys ``existing_by_mac`` off the *stored* form, so the reconciliation
    lookups at the three call sites missed on any host whose scanner did not
    happen to emit colons, and the host was re-identified by IP or created
    again. Returning the canonical form is what makes those lookups hit.

    Three further things it did not do, all of which end at a PostgreSQL
    ``MACADDR`` column:

    * **No hex check at all.** ``"zz:zz:zz:zz:zz:zz"`` was returned verbatim and
      raised ``DataError`` on write, failing the whole sync.
    * **No broadcast filter.** ``ff:ff:ff:ff:ff:ff`` was accepted as an identity.
    * **All-zero filtered by spelling only.** ``000000000000`` and
      ``0:0:0:0:0:0`` are the same address as ``00:00:00:00:00:00`` and slipped
      past the literal comparison.

    ``"n/a"`` and ``"unknown"`` no longer need naming: they are not addresses,
    so ``mac_identity`` refuses them along with every other placeholder a
    scanner might invent.

    Returns None — not ``""`` — because callers branch on it, and one of them
    substitutes the string ``"unknown"`` into an asset id when there is no MAC.
    """
    return mac_identity(host_data.get("mac_address") or host_data.get("mac"))


def _existing_assets_for_hosts(db: Session, org_id: str, hosts: list[dict]):
    batch_ids = [
        gen_asset_id(
            org_id,
            (
                _resolve_ip(h)
                if _resolve_ip(h) != "0.0.0.0"
                else (_resolve_mac(h) or "unknown")
            ),
        )
        for h in hosts
    ]
    batch_ips = [_resolve_ip(h) for h in hosts if _resolve_ip(h) != "0.0.0.0"]
    batch_macs = [_resolve_mac(h) for h in hosts if _resolve_mac(h)]

    query = db.query(Asset).filter(Asset.org_id == org_id)

    filters = [Asset.id.in_(batch_ids)]
    if batch_ips:
        filters.append(Asset.ip_address.in_(batch_ips))
    if batch_macs:
        normalized_macs = [m.lower().replace("-", ":") for m in batch_macs]
        filters.append(Asset.mac_address.in_(normalized_macs))

    assets = query.filter(or_(*filters)).all()
    return (
        {a.id: a for a in assets},
        {str(a.ip_address): a for a in assets if a.ip_address},
        {
            str(a.mac_address).lower().replace("-", ":"): a
            for a in assets
            if a.mac_address
        },
    )


def _is_routable_ip(value) -> bool:
    """
    Whether an address identifies a host to anyone but itself.

    Loopback, link-local and the unspecified address describe a vantage point,
    not a machine: 127.0.0.1 means "wherever this scan ran from". They are
    therefore never allowed to become an asset's identity.
    """
    import ipaddress

    text = str(value or "").strip()
    if not text:
        return False
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return False
    return not (
        addr.is_loopback
        or addr.is_link_local
        or addr.is_unspecified
        or addr.is_multicast
    )


def _may_rebind_ip(current, incoming) -> bool:
    """
    Whether an asset's address may be replaced by one just observed.

    An asset is resolved by MAC as well as by address, so a scan of a *second*
    address belonging to the same physical machine finds the existing record and
    offers its own address as the new identity. That is correct for DHCP churn
    (one routable address replacing another) and wrong for anything that is not
    a routable address.

    Scanning 127.0.0.1 rewrote the identity of a real host from 10.180.6.14 to
    127.0.0.1: the record was flagged inactive, its 142 findings were detached
    from the address they belong to, it dropped out of the "top vulnerable
    assets" ranking, and the dashboard began reporting 127.0.0.0/24 as the
    highest-risk subnet. Nothing in the product could tell that the asset it was
    describing had moved.
    """
    if not _is_routable_ip(incoming):
        # Never demote a real address to a vantage-point address.
        return False
    if not _is_routable_ip(current):
        # Anything routable is an improvement on a placeholder.
        return True
    # Both routable: a genuine address change (DHCP lease, re-addressing).
    return True


def _has_value(value) -> bool:
    if value in EMPTY_VALUES:
        return False
    if isinstance(value, str) and value.strip() in EMPTY_VALUES:
        return False
    if value in ([], {}):
        return False
    return True


def _subnet_of(ip: str | None) -> str | None:
    """
    Derive the containing /24 (or /64 for IPv6) for an address.

    The column existed but nothing ever wrote it, so the registry's subnet
    filter had nothing to filter on.
    """
    if not ip or ip == "0.0.0.0":
        return None
    try:
        import ipaddress

        addr = ipaddress.ip_address(str(ip))
        prefix = 24 if addr.version == 4 else 64
        return str(ipaddress.ip_network(f"{addr}/{prefix}", strict=False))
    except ValueError:
        return None


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


# Zones that are never a host's DNS name, however well-formed they look.
# A reverse-lookup string is the *question* asked about an address, and one
# reached this predicate — "14.6.180.10.in-addr.arpa" satisfied every test
# below and, at six labels, then beat every real name in the length tiebreak
# in _can_update_field, so nothing could ever correct it.
_NON_DNS_ZONE_SUFFIXES = (".in-addr.arpa", ".ip6.arpa")


def _looks_like_fqdn(value) -> bool:
    if not _has_value(value) or not isinstance(value, str):
        return False
    text_value = value.strip().rstrip(".")
    if "." not in text_value:
        return False
    lowered = text_value.lower()
    if lowered.endswith(_NON_DNS_ZONE_SUFFIXES):
        return False
    labels = [label for label in text_value.split(".") if label]
    if len(labels) < 2:
        return False
    # "<name>.local" is the mDNS shape and is link-local: it resolves on the
    # segment that answered and nowhere else, so it is not a DNS name. Note
    # the label count is what distinguishes it — plenty of Active Directory
    # estates use .local as a real internal domain, and "pc1.corp.local" is a
    # legitimate FQDN. Rejecting the suffix outright would break those.
    if len(labels) == 2 and lowered.endswith(".local"):
        return False
    return not all(label.isdigit() for label in labels)


def _fqdn_label_count(value) -> int:
    if not _looks_like_fqdn(value):
        return 0
    return len([label for label in str(value).strip().rstrip(".").split(".") if label])


def _first_text(*values) -> str | None:
    for value in values:
        if isinstance(value, list):
            for item in value:
                text = _first_text(item)
                if text:
                    return text
            continue
        if isinstance(value, dict):
            text = _first_text(value.get("name"), value.get("hostname"))
            if text:
                return text
            continue
        if _has_value(value):
            return str(value).strip()
    return None


def _first_fqdn(*values) -> str | None:
    for value in values:
        if isinstance(value, list):
            nested = _first_fqdn(*value)
            if nested:
                return nested
            continue
        if isinstance(value, dict):
            nested = _first_fqdn(value.get("name"), value.get("hostname"))
            if nested:
                return nested
            continue
        text_value = str(value).strip().rstrip(".") if _has_value(value) else ""
        if _looks_like_fqdn(text_value):
            return text_value
    return None


def _extract_netbios_name(host_data: dict) -> str | None:
    netbios_name = _first_text(
        host_data.get("netbios_computer"), host_data.get("netbios_name")
    )
    if netbios_name:
        return netbios_name
    for entry in host_data.get("netbios_names") or []:
        if isinstance(entry, dict) and entry.get("name"):
            t = entry.get("type")
            s = entry.get("suffix")
            if t is not None:
                if t in (0, 32):  # 0x00 / 0x20
                    return str(entry.get("name")).strip()
            elif s is not None:
                if s in ("00", "20"):
                    return str(entry.get("name")).strip()
            else:
                flags = entry.get("flags")
                if flags is not None:
                    if not (flags & 0x8000):
                        return str(entry.get("name")).strip()
                else:
                    return str(entry.get("name")).strip()
    return None


def _extract_dns_identity(host_data: dict) -> tuple[str | None, str | None]:
    dns_name = _first_fqdn(
        host_data.get("dns_name"),
        host_data.get("ptr_hostname"),
        host_data.get("fqdn"),
        host_data.get("hostname"),
        host_data.get("hostnames"),
    )
    # ``mdns_name`` is deliberately not consulted here. An mDNS name is
    # link-local ("host.local") and is scoped to the segment that answered;
    # it is not a DNS name and does not resolve anywhere else, so writing it
    # into fqdn/dns_name asserts a DNS identity the host does not have.
    # It stays available on the host result for display and is the machine's
    # own statement of its name, which is a different question from this one.
    fqdn = _first_fqdn(
        dns_name,
        host_data.get("fqdn"),
        host_data.get("ptr_hostname"),
        host_data.get("dns_name"),
        host_data.get("hostname"),
        host_data.get("hostnames"),
    )
    return dns_name, fqdn


def _confidence_to_percent(value) -> int | None:
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        return max(0, min(100, int(value)))
    label = str(value).strip().lower()
    label = label.removesuffix("%")
    try:
        return max(0, min(100, int(float(label))))
    except ValueError:
        return {"high": 90, "medium": 60, "low": 30, "n/a": None}.get(label)


# OS guess → (os_family, manufacturer) lookup table.
# Keys are lowercase substrings; evaluated in order, first match wins.
_OS_GUESS_META: list = [
    # (substring_match,       os_family,       manufacturer)
    ("windows server 2022", "Windows Server", "Microsoft Corporation"),
    ("windows server 2019", "Windows Server", "Microsoft Corporation"),
    ("windows server 2016", "Windows Server", "Microsoft Corporation"),
    ("windows server 2012", "Windows Server", "Microsoft Corporation"),
    ("windows server 2008", "Windows Server", "Microsoft Corporation"),
    ("windows server", "Windows Server", "Microsoft Corporation"),
    ("windows 11", "Windows", "Microsoft Corporation"),
    ("windows 10", "Windows", "Microsoft Corporation"),
    ("windows 8", "Windows", "Microsoft Corporation"),
    ("windows 7", "Windows", "Microsoft Corporation"),
    ("windows xp", "Windows", "Microsoft Corporation"),
    ("windows vista", "Windows", "Microsoft Corporation"),
    ("windows (winrm)", "Windows", "Microsoft Corporation"),
    ("windows (iis)", "Windows", "Microsoft Corporation"),
    ("windows (service fingerprint)", "Windows", "Microsoft Corporation"),
    ("windows", "Windows", "Microsoft Corporation"),
    ("ubuntu", "Linux", "Canonical"),
    ("debian", "Linux", "Debian Project"),
    ("centos", "Linux", "Red Hat / CentOS"),
    ("red hat", "Linux", "Red Hat"),
    ("rhel", "Linux", "Red Hat"),
    ("rocky linux", "Linux", "Rocky Enterprise Software Foundation"),
    ("alma linux", "Linux", "AlmaLinux OS Foundation"),
    ("alpine", "Linux", "Alpine Linux"),
    ("arch linux", "Linux", "Arch Linux"),
    ("fedora", "Linux", "Red Hat"),
    ("suse", "Linux", "SUSE"),
    ("opensuse", "Linux", "SUSE"),
    ("linux/unix (service fingerprint)", "Linux", None),
    ("linux", "Linux", None),
    ("freebsd", "BSD", "FreeBSD Project"),
    ("openbsd", "BSD", "OpenBSD Project"),
    ("netbsd", "BSD", "NetBSD Foundation"),
    ("bsd/macos (service fingerprint)", "macOS / BSD", None),
    ("macos", "macOS", "Apple"),
    ("mac os x", "macOS", "Apple"),
    ("darwin", "macOS", "Apple"),
    ("cisco ios", "Cisco IOS", "Cisco"),
    ("cisco", "Cisco IOS", "Cisco"),
    ("junos", "Junos OS", "Juniper Networks"),
    ("fortios", "FortiOS", "Fortinet"),
    ("routeros", "RouterOS", "MikroTik"),
    ("network appliance (service fingerprint)", "Network OS", None),
]


def _derive_os_meta(os_guess: str | None) -> tuple[str | None, str | None]:
    """
    Derive (os_family, manufacturer) from a raw os_guess string.

    Returns (None, None) if os_guess is empty or "Unknown".
    This is intentionally conservative — only returns values when confidence
    is high enough to avoid misleading the analyst.
    """
    if not os_guess or str(os_guess).strip().lower() in ("unknown", "n/a", ""):
        return None, None
    needle = os_guess.lower()
    for substr, family, manufacturer in _OS_GUESS_META:
        if substr in needle:
            return family, manufacturer
    # Generic fallback: if the guess text is non-trivial but unrecognized,
    # still don't make up a manufacturer — just skip both.
    return None, None


def _to_int(value) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(round(float(value)))
    except (TypeError, ValueError):
        return None


def _to_float(value, ndigits: int = 3) -> float | None:
    """Parse a latency value while keeping sub-millisecond resolution."""
    if value in (None, ""):
        return None
    try:
        return round(float(value), ndigits)
    except (TypeError, ValueError):
        return None


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


def _source_rank(source: str | None) -> int:
    return SOURCE_PRIORITY.get(_normalize_source(source), SOURCE_PRIORITY["legacy"])


def _current_source(asset: Asset, field: str) -> str:
    attrs = dict(asset.custom_attributes or {})
    provenance = dict(attrs.get("provenance") or {})
    source = (provenance.get(field) or {}).get("source")
    if source:
        return _normalize_source(source)
    return _normalize_source(asset.discovery_method or "legacy")


def _can_update_field(asset: Asset, field: str, incoming, incoming_source: str) -> bool:
    if not _has_value(incoming):
        return False
    if field in ("fqdn", "dns_name") and not _looks_like_fqdn(str(incoming)):
        return False
    incoming_source = _normalize_source(incoming_source)
    if field in ("fqdn", "dns_name") and incoming_source == "credentialed":
        return False
    current = getattr(asset, field, None)
    if not _has_value(current):
        return True
    if field in ("fqdn", "dns_name"):
        current_source = _current_source(asset, field)
        current_is_fqdn = _looks_like_fqdn(str(current))
        if not current_is_fqdn:
            return True

        incoming_rank = _source_rank(incoming_source)
        current_rank = _source_rank(current_source)
        if incoming_rank < current_rank:
            return False
        if incoming_rank > current_rank:
            # A better source wins outright. The length tiebreak below used to
            # apply here too, so a deeper name from a weaker scan could hold
            # off a better-sourced one indefinitely — authority is the stronger
            # signal and must not be overridden by a count of dots.
            return True

        # Same authority: prefer the more qualified name, since "host.corp
        # .example.com" says strictly more than "host.example.com". This is a
        # tiebreak between two names already established as real DNS names,
        # never a test of whether a value is one — that is _looks_like_fqdn's
        # job, and the reverse-lookup strings that made this rule notorious
        # are refused there now.
        return _fqdn_label_count(str(incoming)) >= _fqdn_label_count(str(current))
    return _source_rank(incoming_source) >= _source_rank(_current_source(asset, field))


def _set_asset_field(
    db: Session,
    asset: Asset,
    scan_id: str,
    field: str,
    incoming,
    source: str,
    max_len: int | None = None,
) -> bool:
    if not _can_update_field(asset, field, incoming, source):
        return False
    value = str(incoming).strip() if isinstance(incoming, str) else incoming
    if isinstance(value, str) and max_len:
        value = value[:max_len]
    old_value = getattr(asset, field, None)
    if old_value != value:
        _record_asset_change(db, asset.id, scan_id, field, old_value, value)
        setattr(asset, field, value)
    _update_provenance(asset, field, source, scan_id)
    return True


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


def _enrich_findings_with_intel(hosts: List[dict]) -> None:
    """
    Attach exploit provenance and vendor advisories to every finding in place.

    One batched lookup for the whole sync. Failure is tolerated and logged:
    a report without exploit provenance is still a correct report, so a feed
    being unreachable must not fail the scan that found the vulnerabilities.
    """

    def _pick(mapping: dict, *keys: str) -> Any:
        for key in keys:
            value = mapping.get(key)
            if value:
                return value
        return None

    findings: List[dict] = []
    for host in hosts or []:
        if not isinstance(host, dict):
            continue
        raw = _pick(host, "cves", "vulnerabilities", "findings") or []
        if isinstance(raw, list):
            findings.extend(f for f in raw if isinstance(f, dict))

    # Only real CVEs are looked up. The feeds this reaches — exploit
    # provenance, CISA KEV, VulnCheck KEV, CSAF vendor advisories — are all
    # keyed on published CVE identifiers, so passing a check identifier can
    # only return nothing. Filtering here is not an optimisation: it keeps a
    # configuration weakness out of the code path whose entire output is
    # CVE-specific threat intelligence, so it cannot acquire an exploit
    # record or a KEV due date by a future change to how these tables are
    # keyed.
    cve_ids = [
        str(_pick(f, "cve_id", "cve", "id") or "").strip().upper() for f in findings
    ]
    cve_ids = [c for c in cve_ids if c and is_cve_id(c)]
    if not cve_ids:
        return

    try:
        from core.vuln_intel import csaf_advisories_for, exploit_intel_for

        intel = exploit_intel_for(cve_ids)
        advisories = csaf_advisories_for(cve_ids)
    except Exception as exc:  # noqa: BLE001 - enrichment must never fail a scan
        logger.warning("Finding enrichment skipped: %s", exc)
        return

    exploit_hits = advisory_hits = 0
    for finding in findings:
        cve = str(_pick(finding, "cve_id", "cve", "id") or "").strip().upper()
        # Restated rather than relying on `intel` simply not containing the
        # key. The lookup dictionaries are built from a filtered list above, so
        # a check identifier misses today by construction; this makes it miss
        # by intent, so widening what those feeds are keyed on cannot silently
        # attach an exploit record to a configuration finding.
        if not cve or not is_cve_id(cve):
            continue

        entry = intel.get(cve)
        if entry:
            finding.update(entry)
            finding["has_exploit"] = True
            exploit_hits += 1

        matches = advisories.get(cve)
        if matches:
            finding["vendor_advisories"] = matches
            source = next((m for m in matches if m.get("remediation")), None)
            if source:
                # Attributed: the advisory covers this CVE but not necessarily
                # this product — a Chrome CVE appears in an ICS advisory whose
                # mitigation is written for the ICS context. Naming the source
                # keeps that judgement with the reader.
                finding["vendor_remediation"] = (
                    f"{source['provider'].upper()} {source['advisory_id']}: "
                    f"{source['remediation']}"
                )
            advisory_hits += 1

    if exploit_hits or advisory_hits:
        logger.info(
            "Enriched %d finding(s) with exploit provenance and %d with a "
            "vendor advisory",
            exploit_hits,
            advisory_hits,
        )


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
    if service is not None and captured and captured != "Source_Family:network_service":
        lines.append("")
        lines.append("Probe output:")
        lines.append(captured[:2000])

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


def _recalculate_asset_risk(db: Session, asset_id: str):
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


# Measured values that drift a little on every scan. Logging them as asset
# "changes" buried the entries that matter — a new OS, a changed MAC — under a
# steady stream of network jitter. They are still stored on the asset; they just
# no longer count as a change worth recording.
_VOLATILE_FIELDS = {"response_time_ms"}


def _record_asset_change(
    db: Session, asset_id: str, scan_id: str, field: str, old_val: Any, new_val: Any
):
    """Logs a specific field change to the AssetChangeLog."""
    if old_val == new_val or (not old_val and not new_val):
        return
    if field in _VOLATILE_FIELDS:
        return
    db.add(
        AssetChangeLog(
            asset_id=asset_id,
            scan_id=scan_id,
            change_type="field_update",
            field_name=field,
            old_value={"val": old_val},
            new_value={"val": new_val},
            detected_at=utcnow(),
        )
    )


def _update_provenance(asset: Asset, field: str, source: str, scan_id: str):
    """Tracks which scan type provided which piece of data."""
    attrs = dict(asset.custom_attributes or {})
    prov = dict(attrs.get("provenance") or {})
    prov[field] = {"source": source, "scan_id": scan_id, "at": utcnow().isoformat()}
    attrs["provenance"] = prov
    asset.custom_attributes = attrs


def sync_host_discovery(
    db: Session, scan_id: str, org_id: str, user_id: str | None, hosts: list[dict]
):
    """
    Called after Phase 1 (Host Discovery).
    Phase 4: Adds Change Auditing and Provenance.
    """
    if not hosts:
        return

    # Probe output reaches every text column below. One NUL from an SNMP
    # agent or a banner made psycopg2 refuse the statement and lost the whole
    # sync, so the records are cleaned here, where every path converges.
    sanitize_for_db_in_place(hosts)

    logger.info(f"Syncing {len(hosts)} hosts with Phase 4 Change Auditing")

    # Pre-fetch existing assets for comparison (Selective Select-then-Update for Change Log accuracy)
    existing, existing_by_ip, existing_by_mac = _existing_assets_for_hosts(
        db, org_id, hosts
    )

    def _register_asset_in_memory(asset: Asset):
        if not asset:
            return
        existing[asset.id] = asset
        if asset.ip_address:
            existing_by_ip[str(asset.ip_address)] = asset
        if asset.mac_address:
            existing_by_mac[str(asset.mac_address).lower().replace("-", ":")] = asset

    for host in hosts:
        ip = _resolve_ip(host)
        mac = _resolve_mac(host)
        hostname = (
            (host.get("hostname") or host.get("hostnames", [None])[0])
            if isinstance(host.get("hostnames"), list)
            else host.get("hostname")
        )
        netbios_name = _extract_netbios_name(host)
        dns_name, fqdn = _extract_dns_identity(host)
        vendor = host.get("vendor", "Unknown")
        is_active = host.get("is_active") or host.get("state") == "up"
        response_time = _to_float(
            host.get("response_time_ms") or host.get("response_time")
        )
        os_confidence = _confidence_to_percent(
            host.get("os_confidence") or host.get("confidence")
        )

        os_match = host.get("os_match") or host.get("os_guess")
        derived_os_family, derived_manufacturer = _derive_os_meta(os_match)
        os_family_val = host.get("os_family") or derived_os_family
        device_category = host.get("device_category")

        # The probe that actually found this host (ARP, ICMP, TCP_CONN, NBNS…).
        # Storing the literal "discovery" — or worse, the pipeline name — threw
        # away the one piece of provenance that explains how the host was seen.
        discovery_technique = _first_text(
            host.get("discovery_method"),
            host.get("scan_method"),
        )

        # 3-Tiered Reconciliation
        asset = None
        if mac:
            asset = existing_by_mac.get(mac.lower().replace("-", ":"))
        if not asset and ip != "0.0.0.0" and hostname:
            potential_asset = existing_by_ip.get(ip)
            if (
                potential_asset
                and potential_asset.hostname
                and potential_asset.hostname.lower() == hostname.lower()
            ):
                asset = potential_asset
        if not asset and ip != "0.0.0.0":
            asset = existing_by_ip.get(ip)

        asset_id = (
            asset.id
            if asset
            else gen_asset_id(org_id, ip if ip != "0.0.0.0" else (mac or "unknown"))
        )
        if not asset:
            asset = existing.get(asset_id)
        if not asset:
            asset = db.get(Asset, asset_id)
            if asset:
                _register_asset_in_memory(asset)

        if asset:
            # PHASE 4: CHANGE AUDITING
            _set_asset_field(
                db, asset, scan_id, "hostname", hostname, "discovery", max_len=255
            )
            _set_asset_field(db, asset, scan_id, "fqdn", fqdn, "discovery", max_len=512)
            _set_asset_field(
                db, asset, scan_id, "dns_name", dns_name, "discovery", max_len=512
            )
            _set_asset_field(
                db,
                asset,
                scan_id,
                "netbios_name",
                netbios_name,
                "discovery",
                max_len=255,
            )
            _set_asset_field(
                db, asset, scan_id, "vendor", vendor, "discovery", max_len=255
            )
            _set_asset_field(db, asset, scan_id, "mac_address", mac, "discovery")
            _set_asset_field(
                db, asset, scan_id, "subnet", _subnet_of(ip), "discovery", max_len=50
            )
            _set_asset_field(
                db, asset, scan_id, "response_time_ms", response_time, "discovery"
            )
            _set_asset_field(
                db, asset, scan_id, "os_confidence", os_confidence, "discovery"
            )
            _set_asset_field(
                db, asset, scan_id, "os_name", os_match, "discovery", max_len=255
            )
            _set_asset_field(
                db, asset, scan_id, "os_family", os_family_val, "discovery", max_len=100
            )
            # The column existed but nothing ever wrote it, so the exact build a
            # probe established (an SNMP sysDescr names the running kernel) was
            # thrown away and the registry showed only the coarse os_name.
            _set_asset_field(
                db,
                asset,
                scan_id,
                "os_version",
                host.get("os_version"),
                "discovery",
                max_len=100,
            )
            _set_asset_field(
                db,
                asset,
                scan_id,
                "device_category",
                device_category,
                "discovery",
                max_len=100,
            )
            _set_asset_field(
                db,
                asset,
                scan_id,
                "discovery_method",
                discovery_technique,
                "discovery",
                max_len=50,
            )

            if (
                asset.ip_address != ip
                and ip != "0.0.0.0"
                and _may_rebind_ip(asset.ip_address, ip)
            ):
                # Release IP from any other asset currently claiming it (IP Hijacking protection)
                other_asset = existing_by_ip.get(ip)
                if other_asset and other_asset.id != asset.id:
                    other_asset.ip_address = None
                    other_asset.is_active = False
                    _record_asset_change(
                        db, other_asset.id, scan_id, "ip_address", ip, None
                    )
                    db.flush()
                    existing_by_ip.pop(str(ip), None)
                _record_asset_change(
                    db, asset_id, scan_id, "ip_address", str(asset.ip_address), ip
                )
                asset.ip_address = ip
                existing_by_ip[str(ip)] = asset

            asset.last_seen_at = utcnow()
            asset.last_scan_id = scan_id
            asset.is_active = is_active
            asset.updated_at = utcnow()
            if asset.mac_address:
                existing_by_mac[str(asset.mac_address).lower().replace("-", ":")] = (
                    asset
                )
            if asset.ip_address:
                existing_by_ip[str(asset.ip_address)] = asset
            existing[asset.id] = asset
        elif is_active:
            # New Asset.
            #
            # Every free-text field goes through _clean(): the scanners emit
            # "Unknown" / "unknown" / "N/A" to mean "nothing was found", and
            # storing those as if they were observations put the word "Unknown"
            # in the asset registry, the technical PDF and the CSV export. Worse,
            # _set_asset_field skips empty incoming values, so a placeholder
            # written here could never be corrected by a later, better scan.
            created_at = utcnow()
            new_asset = Asset(
                id=asset_id,
                org_id=org_id,
                ip_address=ip if ip != "0.0.0.0" else None,
                mac_address=mac,
                subnet=_subnet_of(ip),
                hostname=_clean(hostname, 255),
                vendor=_clean(vendor, 255),
                response_time_ms=response_time,
                os_confidence=os_confidence,
                is_active=True,
                discovery_method=_clean(discovery_technique, 50) or "discovery",
                last_scan_id=scan_id,
                first_seen_at=created_at,
                last_seen_at=created_at,
                created_at=created_at,
                updated_at=created_at,
                os_name=_clean(os_match, 255),
                os_family=_clean(os_family_val, 100),
                os_version=_clean(host.get("os_version"), 100),
                device_category=_clean(device_category, 100),
            )
            db.add(new_asset)
            if _has_value(hostname):
                _update_provenance(new_asset, "hostname", "discovery", scan_id)
            if _has_value(vendor):
                _update_provenance(new_asset, "vendor", "discovery", scan_id)
            if _has_value(mac):
                _update_provenance(new_asset, "mac_address", "discovery", scan_id)
            if _has_value(response_time):
                _update_provenance(new_asset, "response_time_ms", "discovery", scan_id)
            if _has_value(os_confidence):
                _update_provenance(new_asset, "os_confidence", "discovery", scan_id)
            if _has_value(os_match):
                _update_provenance(new_asset, "os_name", "discovery", scan_id)
            if _has_value(os_family_val):
                _update_provenance(new_asset, "os_family", "discovery", scan_id)
            if _has_value(device_category):
                _update_provenance(new_asset, "device_category", "discovery", scan_id)
            if _looks_like_fqdn(str(fqdn)):
                new_asset.fqdn = str(fqdn)[:512]
                _update_provenance(new_asset, "fqdn", "discovery", scan_id)
            if _looks_like_fqdn(str(dns_name)):
                new_asset.dns_name = str(dns_name)[:512]
                _update_provenance(new_asset, "dns_name", "discovery", scan_id)
            if _has_value(netbios_name):
                new_asset.netbios_name = str(netbios_name)[:255]
                _update_provenance(new_asset, "netbios_name", "discovery", scan_id)
            _record_asset_change(db, asset_id, scan_id, "lifecycle", None, "discovered")
            _register_asset_in_memory(new_asset)

        # Sync open ports/services discovered during Phase 1 enrichment
        ports = host.get("open_ports") or host.get("ports") or []
        for p in ports:
            _upsert_network_service(db, asset_id, scan_id, p)

    db.commit()


def sync_asset_discovery(
    db: Session, scan_id: str, org_id: str, user_id: str | None, hosts: list[dict]
):
    """
    Called after Phase 2 (Asset Discovery / Port Scan).
    Phase 4: Provenance tracking for fingerprinting.
    """
    if not hosts:
        return

    # Probe output reaches every text column below. One NUL from an SNMP
    # agent or a banner made psycopg2 refuse the statement and lost the whole
    # sync, so the records are cleaned here, where every path converges.
    sanitize_for_db_in_place(hosts)

    existing, existing_by_ip, existing_by_mac = _existing_assets_for_hosts(
        db, org_id, hosts
    )

    for host in hosts:
        ip = _resolve_ip(host)
        mac = _resolve_mac(host)
        hostname = (
            (host.get("hostname") or host.get("hostnames", [None])[0])
            if isinstance(host.get("hostnames"), list)
            else host.get("hostname")
        )

        # 3-Tiered Reconciliation
        asset = None
        if mac:
            asset = existing_by_mac.get(mac.lower().replace("-", ":"))
        if not asset and ip != "0.0.0.0" and hostname:
            potential_asset = existing_by_ip.get(ip)
            if (
                potential_asset
                and potential_asset.hostname
                and potential_asset.hostname.lower() == hostname.lower()
            ):
                asset = potential_asset
        if not asset and ip != "0.0.0.0":
            asset = existing_by_ip.get(ip)

        if not asset:
            continue
        asset_id = asset.id
        dns_name, fqdn = _extract_dns_identity(host)
        netbios_name = _extract_netbios_name(host)

        ports = host.get("open_ports") or host.get("ports") or []
        for p in ports:
            # UPSERT for services (high volume); asset enrichment below is a
            # selective update.
            _upsert_network_service(db, asset_id, scan_id, p)

        os_match = host.get("os_match") or host.get("os_guess")
        incoming_os_confidence = _confidence_to_percent(host.get("os_confidence"))

        # Derive os_family and manufacturer from the os_guess string so that the
        # Asset Registry can display these fields after an Asset Discovery scan,
        # without waiting for a full Vulnerability Audit or Credentialed scan.
        derived_os_family, derived_manufacturer = _derive_os_meta(os_match)

        # Prefer explicitly provided values (e.g. from Nmap -O) over derived ones.
        os_family_val = host.get("os_family") or derived_os_family
        # `manufacturer` is who made the hardware. The OS lookup only knows who
        # publishes the operating system, so using it directly labelled an HP
        # workstation as manufactured by "Microsoft Corporation". The MAC OUI
        # vendor is the real answer whenever we have it; the OS publisher is a
        # last resort for hosts with no OUI match (a VM, a spoofed MAC).
        manufacturer_val = _first_text(
            host.get("manufacturer"),
            host.get("vendor"),
            derived_manufacturer,
        )
        device_category = host.get("device_category")

        # ── Confidence-aware OS field merge ─────────────────────────────────
        # AssetCorrelationEngine cross-phase principle: if Phase 2 produced a
        # high-confidence OS detection (e.g. from Nmap -O at ≥90% accuracy), but
        # Phase 3 later provides a lower-confidence guess (e.g. from banner/TTL
        # heuristics at ≤30%), we should keep the Phase 2 value.
        #
        # The _can_update_field() check already handles source priority (asset_discovery
        # priority=20, vulnerability_audit=30). However when both come from the same
        # phase, we use the OS confidence score as a tiebreaker so that a well-detected
        # Nmap fingerprint is not overwritten by a poorer detection later.
        current_os_confidence = _confidence_to_percent(asset.os_confidence)
        if incoming_os_confidence is not None and current_os_confidence is not None:
            # Read the current os_name to decide whether to keep or replace
            current_os_name = getattr(asset, "os_name", None)
            if (
                _has_value(current_os_name)
                and incoming_os_confidence < current_os_confidence
            ):
                # Incoming OS data is lower confidence — skip os_name and os_family
                # but still write manufacturer and device_category.
                _set_asset_field(
                    db,
                    asset,
                    scan_id,
                    "hostname",
                    host.get("hostname"),
                    "asset_discovery",
                    max_len=255,
                )
                _set_asset_field(
                    db, asset, scan_id, "fqdn", fqdn, "asset_discovery", max_len=512
                )
                _set_asset_field(
                    db,
                    asset,
                    scan_id,
                    "dns_name",
                    dns_name,
                    "asset_discovery",
                    max_len=512,
                )
                _set_asset_field(
                    db,
                    asset,
                    scan_id,
                    "netbios_name",
                    netbios_name,
                    "asset_discovery",
                    max_len=255,
                )
                _set_asset_field(
                    db,
                    asset,
                    scan_id,
                    "manufacturer",
                    manufacturer_val,
                    "asset_discovery",
                    max_len=255,
                )
                _set_asset_field(
                    db,
                    asset,
                    scan_id,
                    "device_category",
                    device_category,
                    "asset_discovery",
                    max_len=100,
                )
                _set_asset_field(
                    db,
                    asset,
                    scan_id,
                    "os_confidence",
                    incoming_os_confidence,
                    "asset_discovery",
                )
                _set_asset_field(
                    db,
                    asset,
                    scan_id,
                    "discovery_method",
                    "asset_discovery",
                    "asset_discovery",
                    max_len=50,
                )
                # Skip os_name and os_family — preserve the higher-confidence value
                db.commit()
                continue

        _set_asset_field(
            db,
            asset,
            scan_id,
            "hostname",
            host.get("hostname"),
            "asset_discovery",
            max_len=255,
        )
        _set_asset_field(
            db, asset, scan_id, "fqdn", fqdn, "asset_discovery", max_len=512
        )
        _set_asset_field(
            db, asset, scan_id, "dns_name", dns_name, "asset_discovery", max_len=512
        )
        _set_asset_field(
            db,
            asset,
            scan_id,
            "netbios_name",
            netbios_name,
            "asset_discovery",
            max_len=255,
        )
        _set_asset_field(
            db, asset, scan_id, "os_name", os_match, "asset_discovery", max_len=255
        )
        _set_asset_field(
            db,
            asset,
            scan_id,
            "os_family",
            os_family_val,
            "asset_discovery",
            max_len=100,
        )
        # Phase 2 is where the SNMP probe runs, so this is the pass that knows
        # the exact build. Writing it only in the Phase 1 syncer left the column
        # empty for every asset whose kernel was established here.
        _set_asset_field(
            db,
            asset,
            scan_id,
            "os_version",
            host.get("os_version"),
            "asset_discovery",
            max_len=100,
        )
        _set_asset_field(
            db,
            asset,
            scan_id,
            "manufacturer",
            manufacturer_val,
            "asset_discovery",
            max_len=255,
        )
        _set_asset_field(
            db,
            asset,
            scan_id,
            "device_category",
            device_category,
            "asset_discovery",
            max_len=100,
        )
        _set_asset_field(
            db,
            asset,
            scan_id,
            "os_confidence",
            incoming_os_confidence,
            "asset_discovery",
        )
        _set_asset_field(
            db,
            asset,
            scan_id,
            "discovery_method",
            "asset_discovery",
            "asset_discovery",
            max_len=50,
        )

    db.commit()


def sync_vulnerability_audit(
    db: Session, scan_id: str, org_id: str, user_id: str | None, hosts: list[dict]
):
    """
    Called after Phase 3 (Vulnerability Audit).
    Phase 4: Vulnerability Status Auditing (History).
    """
    if not hosts:
        return

    # Probe output reaches every text column below. One NUL from an SNMP
    # agent or a banner made psycopg2 refuse the statement and lost the whole
    # sync, so the records are cleaned here, where every path converges.
    sanitize_for_db_in_place(hosts)

    # Annotate every finding with exploitation provenance and the vendor's own
    # advisory before any of it is written.
    #
    # Done here, once, across all hosts: the alternative is a lookup per host
    # or per finding, and this is the point where every path in the pipeline
    # converges on the database. Both lookups join on the CVE, so neither can
    # raise a finding or alter a verdict — they annotate what the engines
    # already established.
    _enrich_findings_with_intel(hosts)

    existing_assets, existing_by_ip, existing_by_mac = _existing_assets_for_hosts(
        db, org_id, hosts
    )

    # Catalogue details for one CVE are identical wherever that CVE appears, so
    # they are fetched once per sync rather than once per (host, finding).
    _catalogue_cache: dict[str, dict | None] = {}

    touched_asset_ids = set()
    for host in hosts:
        ip = _resolve_ip(host)
        mac = _resolve_mac(host)
        hostname = host.get("hostname")

        # 3-Tiered Reconciliation
        asset = None
        if mac:
            asset = existing_by_mac.get(mac.lower().replace("-", ":"))
        if not asset and ip != "0.0.0.0" and hostname:
            potential_asset = existing_by_ip.get(ip)
            if (
                potential_asset
                and potential_asset.hostname
                and potential_asset.hostname.lower() == hostname.lower()
            ):
                asset = potential_asset
        if not asset and ip != "0.0.0.0":
            asset = existing_by_ip.get(ip)

        if not asset:
            continue
        asset_id = asset.id
        touched_asset_ids.add(asset_id)
        dns_name, fqdn = _extract_dns_identity(host)
        netbios_name = _extract_netbios_name(host)

        # Phase 3 normally carries no ports — phase 2 already recorded them.
        # A host the credentialed pass authenticated to is the exception: its
        # ports now carry the correlation between what answered on the network
        # and what the host says it is running, and its socket table adds
        # services no port scan could see. Both are written here, or the
        # correlation would exist only in the report and never in the asset.
        if host.get("credentialed"):
            for p in host.get("open_ports") or []:
                _upsert_network_service(db, asset_id, scan_id, p)
            # The listener records already carry the package each process
            # resolved to — the enrichment did that while the inventory was
            # loaded, so no package list needs to travel this far.
            upsert_credentialed_services(
                db, asset_id, scan_id, host.get("open_ports_credentialed") or []
            )

        # Whether this pass authenticated. Absent means nothing was attempted —
        # no credential was in scope, or no endpoint was open — and that must
        # stay distinct from an attempt that was refused, so it is left unset
        # rather than written as a failure.
        credentialed_status = host.get("credentialed_status")
        if credentialed_status is None and host.get("credentialed"):
            credentialed_status = CREDENTIALED_STATUS_SUCCESS
        if credentialed_status:
            set_credentialed_status(asset, credentialed_status)

        _set_asset_field(
            db,
            asset,
            scan_id,
            "hostname",
            host.get("hostname"),
            "vulnerability_audit",
            max_len=255,
        )
        _set_asset_field(
            db, asset, scan_id, "fqdn", fqdn, "vulnerability_audit", max_len=512
        )
        _set_asset_field(
            db, asset, scan_id, "dns_name", dns_name, "vulnerability_audit", max_len=512
        )
        _set_asset_field(
            db,
            asset,
            scan_id,
            "netbios_name",
            netbios_name,
            "vulnerability_audit",
            max_len=255,
        )
        _set_asset_field(
            db,
            asset,
            scan_id,
            "os_name",
            host.get("os_match") or host.get("os_guess"),
            "vulnerability_audit",
            max_len=255,
        )
        _set_asset_field(
            db,
            asset,
            scan_id,
            "os_family",
            host.get("os_family"),
            "vulnerability_audit",
            max_len=100,
        )
        _set_asset_field(
            db,
            asset,
            scan_id,
            "os_confidence",
            _confidence_to_percent(host.get("os_confidence")),
            "vulnerability_audit",
        )

        # ── Device classification signal priority check ────────────────────
        # Prevents a low-confidence classification (e.g. TTL heuristic at
        # priority=20) from overwriting a high-confidence one (e.g. SNMP OID
        # at priority=100) across scan phases.
        incoming_device_cat = host.get("device_category")
        if _has_value(incoming_device_cat):
            incoming_signal = host.get("device_category_signal") or "none"
            incoming_priority = _DEVICE_SIGNAL_PRIORITY.get(incoming_signal, 0)
            stored_signal = _get_stored_device_signal(asset)
            stored_priority = _DEVICE_SIGNAL_PRIORITY.get(stored_signal or "none", 0)
            if stored_signal is not None and incoming_priority < stored_priority:
                # Incoming signal is weaker — preserve the stored classification
                logger.debug(
                    "Skipping device_category update for %s: stored signal '%s' (pri=%d) "
                    "> incoming '%s' (pri=%d)",
                    _resolve_ip(host),
                    stored_signal,
                    stored_priority,
                    incoming_signal,
                    incoming_priority,
                )
            else:
                _set_asset_field(
                    db,
                    asset,
                    scan_id,
                    "device_category",
                    incoming_device_cat,
                    "vulnerability_audit",
                    max_len=100,
                )
                # Also store the signal name in provenance for future comparisons
                attrs = dict(asset.custom_attributes or {})
                prov = dict(attrs.get("provenance") or {})
                dev_prov = dict(prov.get("device_category") or {})
                dev_prov["signal"] = incoming_signal
                prov["device_category"] = dev_prov
                attrs["provenance"] = prov
                asset.custom_attributes = attrs
        # If no incoming device_category, don't overwrite anything

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
                    if cve_id in _catalogue_cache:
                        details = _catalogue_cache[cve_id]
                    else:
                        details = cve_db.get_cve_details(cve_id)
                        _catalogue_cache[cve_id] = details
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
            finding_id = _resolve_finding_id(
                db, org_id, asset_id, cve_id, source_family
            )
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
                _record_asset_change(
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
            evidence = _build_finding_evidence(v, finding_service, host, cve_id=cve_id)
            proof = f"Source_Family:{source_family}"
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
                    source_family=source_family,
                    evidence_source=str(
                        v.get("evidence_source") or "vulnerability_audit"
                    ),
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
                        "source_family": source_family,
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
        for f in open_findings:
            if _finding_family(_finding_source_from_record(f)) != source_family:
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
                _record_asset_change(
                    db,
                    asset_id,
                    scan_id,
                    "vulnerability_ruled_out" if ruled_out else "vulnerability_fixed",
                    f.vuln_id,
                    f.status,
                )

        # What this scan looked at on this asset, so a later comparison can
        # tell a finding that went away from one nobody looked for. The network
        # sweep above is already family-scoped, so this is bookkeeping for the
        # comparison rather than a guard on the sweep.
        try:
            from core.findings import record_assessment_scope
            from db.models.scans import Scan as _Scan

            _scan_row = db.query(_Scan).filter(_Scan.id == scan_id).first()
            if _scan_row is not None:
                record_assessment_scope(
                    _scan_row, assets=[asset_id], families=[source_family]
                )
        except Exception as exc:  # bookkeeping must never fail a scan
            logger.warning(
                "Could not record assessment scope for scan %s: %s", scan_id, exc
            )

        asset.last_scan_id = scan_id
        asset.last_seen_at = utcnow()
        asset.updated_at = utcnow()
        _set_asset_field(
            db,
            asset,
            scan_id,
            "discovery_method",
            "vulnerability_audit",
            "vulnerability_audit",
            max_len=50,
        )

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
                service_id = gen_service_id(asset.id, tls_port, "tcp")

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

                from db.models.findings import TLSDetail

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
                        "cert_is_self_signed": tls_info.get("cert_self_signed")
                        or False,
                        "cert_not_after": cert_not_after,
                        "cert_subject": cert_subject,
                        "cert_issuer": cert_issuer,
                        "issues": tls_info.get("issues") or [],
                    },
                )
                db.execute(tls_upsert)

    db.commit()

    # 4. Final aggregation (This could also be moved to a background trigger later)
    # Keeping the existing recalculation logic but using more efficient queries if possible
    # (Leaving it as is for Step 3 to ensure stability)
    try:
        # Simplified batch recalculation for assets in this scan
        for a_id in touched_asset_ids:
            counts, computed, level = _recalculate_asset_risk(db, a_id)
            db.query(Asset).filter(Asset.id == a_id).update(
                {
                    "vuln_counts": counts,
                    "risk_score": computed,
                    "risk_level": level,
                    "updated_at": utcnow(),
                }
            )
        db.commit()
    except Exception:
        db.rollback()


# Backward compatibility alias for legacy callers.
sync_advanced_scan = sync_vulnerability_audit
