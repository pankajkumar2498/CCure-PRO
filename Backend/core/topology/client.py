"""
core/topology/client.py
───────────────────────
Pluggable SNMP client for topology discovery.

Supports SNMPv1, v2c, and v3 with optional context names.
Fetches ARP tables, LLDP/CDP neighbor tables, and FDB (MAC address) tables
from managed switches and routers.

Design decisions:
  - Uses pysnmp-lextudio==6.1.2 (the stable version containing the synchronous hlapi).
  - Lazy-loaded: import cost is paid only when topology mapping is requested.
  - FDB walk is capped at MAX_FDB_ENTRIES (2000) to prevent memory exhaustion
    on large enterprise switches with 50k+ MAC entries.
  - All walks are synchronous (run inside Celery worker thread).
  - Errors are caught per-walk and logged — a failing LLDP walk does not
    prevent ARP results from being returned.
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

log = logging.getLogger("ccure.topology.client")

# ─── Safety Caps ─────────────────────────────────────────────────────────────
MAX_FDB_ENTRIES = 2000


# ─── Well-known OIDs ─────────────────────────────────────────────────────────

# ARP Table (ipNetToMediaTable) — RFC 2011
OID_ARP_TABLE = "1.3.6.1.2.1.4.22.1"
OID_ARP_PHYS_ADDRESS = "1.3.6.1.2.1.4.22.1.2"  # MAC address
OID_ARP_NET_ADDRESS = "1.3.6.1.2.1.4.22.1.3"  # IP address

# LLDP Remote Systems (lldpRemTable) — IEEE 802.1AB
OID_LLDP_REM_CHASSIS_ID = "1.0.8802.1.1.2.1.4.1.1.5"
OID_LLDP_REM_PORT_ID = "1.0.8802.1.1.2.1.4.1.1.7"
OID_LLDP_REM_SYS_NAME = "1.0.8802.1.1.2.1.4.1.1.9"
OID_LLDP_REM_PORT_DESC = "1.0.8802.1.1.2.1.4.1.1.8"

# CDP Cache (cdpCacheEntry) — Cisco proprietary
OID_CDP_CACHE_ADDRESS = "1.3.6.1.4.1.9.9.23.1.2.1.1.4"
OID_CDP_CACHE_DEVICE_ID = "1.3.6.1.4.1.9.9.23.1.2.1.1.6"
OID_CDP_CACHE_DEVICE_PORT = "1.3.6.1.4.1.9.9.23.1.2.1.1.7"
OID_CDP_CACHE_PLATFORM = "1.3.6.1.4.1.9.9.23.1.2.1.1.8"

# FDB / Forwarding Database (dot1dTpFdbTable) — RFC 1493
OID_FDB_ADDRESS = "1.3.6.1.2.1.17.4.3.1.1"
OID_FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"

# System description (sysDescr / sysName / sysServices)
OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"
OID_SYS_SERVICES = "1.3.6.1.2.1.1.7.0"  # Layer bitmask (L2=2, L3=4, L7=64)

# Interface Table (ifTable / ifXTable) — RFC 2863
OID_IF_DESCR = "1.3.6.1.2.1.2.2.1.2"  # e.g., "GigabitEthernet1/0/5"
OID_IF_SPEED = "1.3.6.1.2.1.2.2.1.5"  # 32-bit speed (bps), caps at ~4.29 Gbps
OID_IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"  # Short name (ifXTable)
OID_IF_HIGH_SPEED = "1.3.6.1.2.1.31.1.1.1.15"  # Speed in Mbps (for >4 Gbps links)
OID_IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"  # Operator-configured description

# Bridge Port to ifIndex mapping — RFC 1493
OID_BRIDGE_PORT_IF_INDEX = "1.3.6.1.2.1.17.1.4.1.2"  # dot1dBasePortIfIndex

# VLAN tables
OID_DOT1Q_PVID = "1.3.6.1.2.1.17.7.1.4.5.1.1"  # 802.1Q port native VLAN
OID_CISCO_VM_VLAN = "1.3.6.1.4.1.9.9.68.1.2.2.1.2"  # Cisco vmVlan (access VLAN)


@dataclass
class SNMPCredentials:
    """
    SNMP credential configuration.

    For v1/v2c: community is required.
    For v3: username + auth_protocol + auth_passphrase are required.
             priv_protocol + priv_passphrase are optional (for authPriv).
    """

    version: str = "v2c"  # "v1", "v2c", "v3"
    community: str = "public"  # v1/v2c community string
    username: str = ""  # v3 USM username
    auth_protocol: str = ""  # v3: "MD5", "SHA", "SHA256", "SHA512"
    auth_passphrase: str = ""  # v3 auth passphrase
    priv_protocol: str = ""  # v3: "DES", "AES128", "AES256"
    priv_passphrase: str = ""  # v3 priv passphrase
    context_name: str = ""  # v3 context name (e.g., VLAN-aware switches)
    port: int = 161  # SNMP agent port
    timeout: float = 1.5  # seconds per request
    retries: int = 1  # retry count

    @classmethod
    def from_dict(cls, data: dict) -> "SNMPCredentials":
        """Build from a frontend-submitted dict. Unknown keys are ignored."""
        if not data:
            return cls()
        return cls(
            version=str(data.get("version") or "v2c").lower(),
            community=str(data.get("community") or "public"),
            username=str(data.get("username") or ""),
            auth_protocol=str(data.get("auth_protocol") or ""),
            auth_passphrase=str(data.get("auth_passphrase") or ""),
            priv_protocol=str(data.get("priv_protocol") or ""),
            priv_passphrase=str(data.get("priv_passphrase") or ""),
            context_name=str(data.get("context_name") or ""),
            port=int(data.get("port") or 161),
            timeout=float(data.get("timeout") or 1.5),
            retries=int(data.get("retries") or 1),
        )


@dataclass
class ARPEntry:
    """One row from ipNetToMediaTable."""

    ip_address: str
    mac_address: str
    interface_index: str = ""


@dataclass
class LLDPNeighbor:
    """One LLDP neighbor discovered on a local port."""

    chassis_id: str  # Usually a MAC address
    port_id: str  # Remote port
    system_name: str = ""  # Remote hostname
    port_desc: str = ""  # Remote port description
    local_port_index: str = ""


@dataclass
class CDPNeighbor:
    """One CDP neighbor (Cisco-specific)."""

    device_id: str  # Remote device hostname
    ip_address: str = ""  # Remote management IP
    device_port: str = ""  # Remote port
    platform: str = ""  # Remote platform string
    local_port_index: str = ""


@dataclass
class FDBEntry:
    """One MAC forwarding table entry."""

    mac_address: str
    port_index: str
    vlan_id: int = 0  # Populated during VLAN-indexed walks


@dataclass
class InterfaceInfo:
    """Cached metadata for a single interface, keyed by ifIndex."""

    if_index: str
    descr: str = ""  # ifDescr (e.g., "GigabitEthernet1/0/5")
    name: str = ""  # ifName  (e.g., "Gi1/0/5")
    alias: str = ""  # ifAlias (operator label, e.g., "Uplink to Core")
    speed_bps: int = 0  # Normalized speed in bps
    vlan_id: int = 0  # Access VLAN for this port

    @property
    def display_name(self) -> str:
        """Best human-readable label for this interface."""
        base = self.descr or self.name or f"if{self.if_index}"
        if self.alias:
            return f"{self.alias} ({base})"
        return base


@dataclass
class SNMPWalkResult:
    """Aggregated results from all SNMP walks against a single target."""

    target_ip: str
    sys_name: str = ""
    sys_descr: str = ""
    sys_services: int = 0  # Layer bitmask
    arp_table: List[ARPEntry] = field(default_factory=list)
    lldp_neighbors: List[LLDPNeighbor] = field(default_factory=list)
    cdp_neighbors: List[CDPNeighbor] = field(default_factory=list)
    fdb_table: List[FDBEntry] = field(default_factory=list)
    interface_table: Dict[str, InterfaceInfo] = field(
        default_factory=dict
    )  # ifIndex -> InterfaceInfo
    bridge_port_map: Dict[str, str] = field(
        default_factory=dict
    )  # bridge_port -> ifIndex
    errors: List[str] = field(default_factory=list)

    @property
    def has_data(self) -> bool:
        return bool(
            self.arp_table
            or self.lldp_neighbors
            or self.cdp_neighbors
            or self.fdb_table
        )

    def resolve_interface(self, port_index: str) -> Optional[InterfaceInfo]:
        """Resolve a bridge/FDB port index to its InterfaceInfo via bridge_port_map."""
        if_index = self.bridge_port_map.get(str(port_index), str(port_index))
        return self.interface_table.get(if_index)


# ─── Helpers ─────────────────────────────────────────────────────────────────


def _get_oid_suffix(oid_str: str, base_oid: str) -> str:
    """
    Extract the suffix of a walked OID relative to a base OID.
    Normalizes both OIDs, verifies the walked OID is strictly equal to
    or a sub-OID under the base OID, and returns the suffix without leading/trailing dots.
    """
    clean_oid = oid_str.strip(".")
    clean_base = base_oid.strip(".")
    if clean_oid == clean_base:
        return ""
    prefix_dot = clean_base + "."
    if clean_oid.startswith(prefix_dot):
        return clean_oid[len(prefix_dot) :]
    return ""


def _format_mac(raw_bytes) -> str:
    """Convert raw SNMP OctetString bytes to colon-delimited MAC address."""
    if hasattr(raw_bytes, "asOctets"):
        raw_bytes = raw_bytes.asOctets()
    if isinstance(raw_bytes, (bytes, bytearray)):
        if len(raw_bytes) == 6:
            return ":".join(f"{b:02x}" for b in raw_bytes)
        try:
            return raw_bytes.decode("utf-8", errors="ignore").strip()
        except Exception:
            pass
    text = str(raw_bytes).strip()
    # Already formatted (e.g., "aa:bb:cc:dd:ee:ff")
    compact = text.lower().replace(":", "").replace("-", "").replace(".", "")
    if len(compact) == 12 and all(c in "0123456789abcdef" for c in compact):
        return ":".join(compact[i : i + 2] for i in range(0, 12, 2))
    return text


def _format_ip_from_oid(oid_suffix: str) -> str:
    """Extract IP from the trailing OID index (e.g., '.1.10.180.6.14' → '10.180.6.14')."""
    parts = oid_suffix.strip(".").split(".")
    if len(parts) >= 4:
        return ".".join(parts[-4:])
    return oid_suffix


def _format_ip_from_bytes(raw_bytes) -> str:
    """Convert raw 4-byte IP address to dotted notation."""
    if hasattr(raw_bytes, "asOctets"):
        raw_bytes = raw_bytes.asOctets()
    if isinstance(raw_bytes, (bytes, bytearray)) and len(raw_bytes) == 4:
        return ".".join(str(b) for b in raw_bytes)
    return str(raw_bytes)


def _oid_to_tuple(oid_str: str) -> tuple:
    """Convert dotted OID string to integer tuple for correct numeric comparison."""
    try:
        return tuple(int(x) for x in oid_str.strip(".").split(".") if x.isdigit())
    except Exception:
        return ()


# ─── SNMP Engine Builder ─────────────────────────────────────────────────────


def _build_snmp_engine(creds: SNMPCredentials, target_ip: str):
    """
    Build pysnmp transport target + auth data objects.
    Returns (snmp_engine, auth_data, transport_target, context_data).

    Lazy-imports pysnmp so the module doesn't fail on import
    if pysnmp is not installed (e.g., during unit tests).
    """
    from pysnmp.hlapi.asyncio import (
        SnmpEngine,
        CommunityData,
        UsmUserData,
        UdpTransportTarget,
        ContextData,
    )

    engine = SnmpEngine()
    transport = UdpTransportTarget(
        (target_ip, creds.port),
        timeout=creds.timeout,
        retries=creds.retries,
    )

    context = ContextData()
    if creds.context_name:
        context = ContextData(contextName=creds.context_name)

    if creds.version in ("v1", "v2c"):
        mpmodel = 0 if creds.version == "v1" else 1
        auth = CommunityData(creds.community, mpModel=mpmodel)
    else:
        # SNMPv3
        auth_proto = None
        priv_proto = None

        if creds.auth_protocol:
            from pysnmp.hlapi.asyncio import (
                usmHMACMD5AuthProtocol,
                usmHMACSHAAuthProtocol,
                usmHMAC128SHA224AuthProtocol,
                usmHMAC192SHA256AuthProtocol,
            )

            AUTH_MAP = {
                "md5": usmHMACMD5AuthProtocol,
                "sha": usmHMACSHAAuthProtocol,
                "sha224": usmHMAC128SHA224AuthProtocol,
                "sha256": usmHMAC192SHA256AuthProtocol,
            }
            auth_proto = AUTH_MAP.get(
                creds.auth_protocol.lower(), usmHMACSHAAuthProtocol
            )

        if creds.priv_protocol:
            from pysnmp.hlapi.asyncio import (
                usmDESPrivProtocol,
                usmAesCfb128Protocol,
                usmAesCfb256Protocol,
            )

            PRIV_MAP = {
                "des": usmDESPrivProtocol,
                "aes": usmAesCfb128Protocol,
                "aes128": usmAesCfb128Protocol,
                "aes256": usmAesCfb256Protocol,
            }
            priv_proto = PRIV_MAP.get(creds.priv_protocol.lower(), usmAesCfb128Protocol)

        kwargs = {"userName": creds.username}
        if auth_proto:
            kwargs["authProtocol"] = auth_proto
            kwargs["authKey"] = creds.auth_passphrase
        if priv_proto:
            kwargs["privProtocol"] = priv_proto
            kwargs["privKey"] = creds.priv_passphrase

        auth = UsmUserData(**kwargs)

    return engine, auth, transport, context


async def _snmp_walk_async(
    engine, auth, transport, context, oid: str, max_rows: int = 0
) -> List[tuple]:
    """
    Perform an asynchronous SNMP walk starting from `oid`.
    Returns list of (oid_str, value) tuples.

    If max_rows > 0, stops after max_rows results (safety cap).
    """
    from pysnmp.hlapi.asyncio import walkCmd, ObjectType, ObjectIdentity

    results = []
    count = 0
    previous_oid = None

    try:
        async for errorIndication, errorStatus, errorIndex, varBinds in walkCmd(
            engine,
            auth,
            transport,
            context,
            ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False,
        ):
            if errorIndication:
                log.warning("SNMP walk [%s] warning: %s", oid, errorIndication)
                break
            if errorStatus:
                log.warning("SNMP walk [%s] PDU error: %s", oid, errorStatus)
                break

            stop_walk = False
            for varBind in varBinds:
                oid_str = str(varBind[0])
                value = varBind[1]

                oid_tuple = _oid_to_tuple(oid_str)
                # Infinite loop prevention: check if OID is not strictly increasing numerically
                if previous_oid is not None and oid_tuple <= previous_oid:
                    log.warning(
                        "SNMP walk: detected non-increasing OID (%s -> %s). Terminating walk to prevent infinite loop.",
                        previous_oid,
                        oid_tuple,
                    )
                    stop_walk = True
                    break

                previous_oid = oid_tuple
                results.append((oid_str, value))
                count += 1

                if 0 < max_rows <= count:
                    log.info("FDB walk safety cap reached: %d entries", max_rows)
                    stop_walk = True
                    break

            if stop_walk:
                break
    except Exception as exc:
        log.warning("Exception during SNMP walk for %s: %s", oid, exc)

    return results


async def _snmp_get_async(engine, auth, transport, context, oid: str):
    """Perform a single SNMP GET request asynchronously."""
    from pysnmp.hlapi.asyncio import getCmd, ObjectType, ObjectIdentity

    try:
        errorIndication, errorStatus, errorIndex, varBinds = await getCmd(
            engine,
            auth,
            transport,
            context,
            ObjectType(ObjectIdentity(oid)),
        )

        if errorIndication or errorStatus:
            return None

        if varBinds:
            return varBinds[0][1]
    except Exception as exc:
        log.warning("Exception during SNMP get for %s: %s", oid, exc)
    return None


# ─── Public API ──────────────────────────────────────────────────────────────


def walk_target(target_ip: str, creds: SNMPCredentials) -> SNMPWalkResult:
    """
    Run the full SNMP discovery against a single target IP.

    Walks:
      1. System identity (sysName, sysDescr)
      2. ARP table (ipNetToMediaTable)
      3. LLDP neighbors (lldpRemTable)
      4. CDP neighbors (cdpCacheEntry)
      5. FDB table (dot1dTpFdbTable) — capped at MAX_FDB_ENTRIES

    Each walk is independent; a failure in one does not affect the others.
    """
    import asyncio

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    log.info("SNMP walk [%s]: starting SNMP discovery...", target_ip)
    result = SNMPWalkResult(target_ip=target_ip)

    try:
        try:
            engine, auth, transport, context = _build_snmp_engine(creds, target_ip)
        except Exception as exc:
            result.errors.append(f"SNMP engine build failed: {exc}")
            log.error("SNMP walk [%s]: engine build failed: %s", target_ip, exc)
            return result

        async def run_walks_async():
            # 1. System identity + sysServices
            log.info("SNMP walk [%s]: querying system identity...", target_ip)
            try:
                val = await _snmp_get_async(
                    engine, auth, transport, context, OID_SYS_NAME
                )
                if val:
                    result.sys_name = (
                        val.asOctets().decode("utf-8", errors="ignore").strip()
                        if hasattr(val, "asOctets")
                        else str(val).strip()
                    )
                val = await _snmp_get_async(
                    engine, auth, transport, context, OID_SYS_DESCR
                )
                if val:
                    result.sys_descr = (
                        val.asOctets().decode("utf-8", errors="ignore").strip()
                        if hasattr(val, "asOctets")
                        else str(val).strip()
                    )
                val = await _snmp_get_async(
                    engine, auth, transport, context, OID_SYS_SERVICES
                )
                if val:
                    try:
                        result.sys_services = int(val)
                    except (ValueError, TypeError):
                        pass
                log.info(
                    "SNMP walk [%s]: system identity retrieved (name='%s', services=%d)",
                    target_ip,
                    result.sys_name,
                    result.sys_services,
                )
            except Exception as exc:
                result.errors.append(f"System identity walk failed: {exc}")
                log.warning(
                    "SNMP walk [%s]: system identity walk failed: %s", target_ip, exc
                )

            # 1b. Interface table (ifDescr, ifName, ifAlias, ifSpeed, ifHighSpeed)
            log.info("SNMP walk [%s]: walking interface table...", target_ip)
            try:
                descr_rows = await _snmp_walk_async(
                    engine, auth, transport, context, OID_IF_DESCR
                )
                name_rows = await _snmp_walk_async(
                    engine, auth, transport, context, OID_IF_NAME
                )
                alias_rows = await _snmp_walk_async(
                    engine, auth, transport, context, OID_IF_ALIAS
                )
                speed_rows = await _snmp_walk_async(
                    engine, auth, transport, context, OID_IF_SPEED
                )
                high_speed_rows = await _snmp_walk_async(
                    engine, auth, transport, context, OID_IF_HIGH_SPEED
                )

                # Build lookup maps keyed by ifIndex suffix
                name_map = {}
                for oid_str, val in name_rows:
                    sfx = _get_oid_suffix(oid_str, OID_IF_NAME)
                    name_map[sfx] = (
                        val.asOctets().decode("utf-8", errors="ignore").strip()
                        if hasattr(val, "asOctets")
                        else str(val).strip()
                    )

                alias_map = {}
                for oid_str, val in alias_rows:
                    sfx = _get_oid_suffix(oid_str, OID_IF_ALIAS)
                    alias_map[sfx] = (
                        val.asOctets().decode("utf-8", errors="ignore").strip()
                        if hasattr(val, "asOctets")
                        else str(val).strip()
                    )

                speed_map = {}
                for oid_str, val in speed_rows:
                    sfx = _get_oid_suffix(oid_str, OID_IF_SPEED)
                    try:
                        speed_map[sfx] = int(val)
                    except (ValueError, TypeError):
                        pass

                high_speed_map = {}
                for oid_str, val in high_speed_rows:
                    sfx = _get_oid_suffix(oid_str, OID_IF_HIGH_SPEED)
                    try:
                        high_speed_map[sfx] = int(val)
                    except (ValueError, TypeError):
                        pass

                for oid_str, val in descr_rows:
                    if_index = _get_oid_suffix(oid_str, OID_IF_DESCR)
                    if not if_index:
                        continue
                    descr = (
                        val.asOctets().decode("utf-8", errors="ignore").strip()
                        if hasattr(val, "asOctets")
                        else str(val).strip()
                    )

                    # Normalize speed: prefer ifHighSpeed when ifSpeed is 0, missing, or sentinel 4294967295
                    raw_speed = speed_map.get(if_index, 0)
                    high_speed = high_speed_map.get(if_index, 0)
                    if (
                        raw_speed == 0
                        or raw_speed == 4294967295
                        or (high_speed and high_speed > 0)
                    ):
                        speed_bps = high_speed * 1_000_000 if high_speed else raw_speed
                    else:
                        speed_bps = raw_speed

                    result.interface_table[if_index] = InterfaceInfo(
                        if_index=if_index,
                        descr=descr,
                        name=name_map.get(if_index, ""),
                        alias=alias_map.get(if_index, ""),
                        speed_bps=speed_bps,
                    )

                log.info(
                    "SNMP walk [%s]: interface table built (%d interfaces)",
                    target_ip,
                    len(result.interface_table),
                )
            except Exception as exc:
                result.errors.append(f"Interface table walk failed: {exc}")
                log.warning(
                    "SNMP walk [%s]: interface table walk failed: %s", target_ip, exc
                )

            # 1c. Bridge port to ifIndex mapping (dot1dBasePortIfIndex)
            log.info("SNMP walk [%s]: walking bridge port mapping...", target_ip)
            try:
                bridge_rows = await _snmp_walk_async(
                    engine, auth, transport, context, OID_BRIDGE_PORT_IF_INDEX
                )
                for oid_str, val in bridge_rows:
                    bridge_port = _get_oid_suffix(oid_str, OID_BRIDGE_PORT_IF_INDEX)
                    if bridge_port:
                        result.bridge_port_map[bridge_port] = str(val).strip()
                log.info(
                    "SNMP walk [%s]: bridge port mapping built (%d ports)",
                    target_ip,
                    len(result.bridge_port_map),
                )
            except Exception as exc:
                result.errors.append(f"Bridge port mapping walk failed: {exc}")
                log.warning(
                    "SNMP walk [%s]: bridge port mapping walk failed: %s",
                    target_ip,
                    exc,
                )

            # 1d. VLAN tables (dot1qPvid + Cisco vmVlan)
            log.info("SNMP walk [%s]: walking VLAN tables...", target_ip)
            vlan_port_map: Dict[str, int] = {}  # ifIndex/bridge_port -> vlan_id
            try:
                pvid_rows = await _snmp_walk_async(
                    engine, auth, transport, context, OID_DOT1Q_PVID
                )
                for oid_str, val in pvid_rows:
                    port_idx = _get_oid_suffix(oid_str, OID_DOT1Q_PVID)
                    if port_idx:
                        try:
                            vlan_port_map[port_idx] = int(val)
                        except (ValueError, TypeError):
                            pass
            except Exception as exc:
                log.debug(
                    "SNMP walk [%s]: dot1qPvid walk failed (may not be supported): %s",
                    target_ip,
                    exc,
                )

            if not vlan_port_map:
                # Fallback to Cisco vmVlan
                try:
                    vm_rows = await _snmp_walk_async(
                        engine, auth, transport, context, OID_CISCO_VM_VLAN
                    )
                    for oid_str, val in vm_rows:
                        if_index = _get_oid_suffix(oid_str, OID_CISCO_VM_VLAN)
                        if if_index:
                            try:
                                vlan_port_map[if_index] = int(val)
                            except (ValueError, TypeError):
                                pass
                except Exception as exc:
                    log.debug(
                        "SNMP walk [%s]: vmVlan walk failed (may not be supported): %s",
                        target_ip,
                        exc,
                    )

            # Merge VLAN IDs into interface_table entries
            for port_or_idx, vlan_id in vlan_port_map.items():
                # Try direct ifIndex match first
                if port_or_idx in result.interface_table:
                    result.interface_table[port_or_idx].vlan_id = vlan_id
                else:
                    # Try bridge port translation
                    mapped_idx = result.bridge_port_map.get(port_or_idx)
                    if mapped_idx and mapped_idx in result.interface_table:
                        result.interface_table[mapped_idx].vlan_id = vlan_id
            log.info(
                "SNMP walk [%s]: VLAN mapping completed (%d entries)",
                target_ip,
                len(vlan_port_map),
            )

            # 2. ARP Table
            log.info("SNMP walk [%s]: walking ARP table...", target_ip)
            try:
                rows = await _snmp_walk_async(
                    engine, auth, transport, context, OID_ARP_PHYS_ADDRESS
                )
                for oid_str, value in rows:
                    mac = _format_mac(value)
                    # Extract IP from OID suffix
                    suffix = _get_oid_suffix(oid_str, OID_ARP_PHYS_ADDRESS)
                    ip = _format_ip_from_oid(suffix)
                    if mac and ip:
                        # Extract interface index from OID
                        parts = suffix.strip(".").split(".")
                        iface_idx = parts[0] if parts else ""
                        result.arp_table.append(
                            ARPEntry(
                                ip_address=ip,
                                mac_address=mac,
                                interface_index=iface_idx,
                            )
                        )
                log.info(
                    "SNMP walk [%s]: ARP walk completed (%d entries)",
                    target_ip,
                    len(result.arp_table),
                )
            except Exception as exc:
                result.errors.append(f"ARP walk failed: {exc}")
                log.warning("SNMP walk [%s]: ARP walk failed: %s", target_ip, exc)

            # 3. LLDP Neighbors
            log.info("SNMP walk [%s]: walking LLDP neighbors...", target_ip)
            try:
                chassis_rows = await _snmp_walk_async(
                    engine, auth, transport, context, OID_LLDP_REM_CHASSIS_ID
                )
                port_rows = await _snmp_walk_async(
                    engine, auth, transport, context, OID_LLDP_REM_PORT_ID
                )
                name_rows = await _snmp_walk_async(
                    engine, auth, transport, context, OID_LLDP_REM_SYS_NAME
                )

                # Build index maps keyed by OID suffix
                port_map = {}
                for oid, val in port_rows:
                    sfx = _get_oid_suffix(str(oid), OID_LLDP_REM_PORT_ID)
                    port_map[sfx] = (
                        val.asOctets().decode("utf-8", errors="ignore").strip()
                        if hasattr(val, "asOctets")
                        else str(val).strip()
                    )

                name_map = {}
                for oid, val in name_rows:
                    sfx = _get_oid_suffix(str(oid), OID_LLDP_REM_SYS_NAME)
                    name_map[sfx] = (
                        val.asOctets().decode("utf-8", errors="ignore").strip()
                        if hasattr(val, "asOctets")
                        else str(val).strip()
                    )

                for oid_str, value in chassis_rows:
                    suffix = _get_oid_suffix(oid_str, OID_LLDP_REM_CHASSIS_ID)
                    chassis_id = _format_mac(value)

                    parts = suffix.strip(".").split(".")
                    # Index is [TimeFilter].[LocalPortNum].[RemIndex]
                    local_port = parts[1] if len(parts) >= 2 else ""

                    result.lldp_neighbors.append(
                        LLDPNeighbor(
                            chassis_id=chassis_id,
                            port_id=port_map.get(suffix, ""),
                            system_name=name_map.get(suffix, ""),
                            local_port_index=local_port,
                        )
                    )
                log.info(
                    "SNMP walk [%s]: LLDP walk completed (%d neighbors)",
                    target_ip,
                    len(result.lldp_neighbors),
                )
            except Exception as exc:
                result.errors.append(f"LLDP walk failed: {exc}")
                log.warning("SNMP walk [%s]: LLDP walk failed: %s", target_ip, exc)

            # 4. CDP Neighbors
            log.info("SNMP walk [%s]: walking CDP neighbors...", target_ip)
            try:
                addr_rows = await _snmp_walk_async(
                    engine, auth, transport, context, OID_CDP_CACHE_ADDRESS
                )
                dev_rows = await _snmp_walk_async(
                    engine, auth, transport, context, OID_CDP_CACHE_DEVICE_ID
                )
                port_rows = await _snmp_walk_async(
                    engine, auth, transport, context, OID_CDP_CACHE_DEVICE_PORT
                )
                plat_rows = await _snmp_walk_async(
                    engine, auth, transport, context, OID_CDP_CACHE_PLATFORM
                )

                dev_map = {}
                for oid, val in dev_rows:
                    sfx = _get_oid_suffix(str(oid), OID_CDP_CACHE_DEVICE_ID)
                    dev_map[sfx] = (
                        val.asOctets().decode("utf-8", errors="ignore").strip()
                        if hasattr(val, "asOctets")
                        else str(val).strip()
                    )

                port_map = {}
                for oid, val in port_rows:
                    sfx = _get_oid_suffix(str(oid), OID_CDP_CACHE_DEVICE_PORT)
                    port_map[sfx] = (
                        val.asOctets().decode("utf-8", errors="ignore").strip()
                        if hasattr(val, "asOctets")
                        else str(val).strip()
                    )

                plat_map = {}
                for oid, val in plat_rows:
                    sfx = _get_oid_suffix(str(oid), OID_CDP_CACHE_PLATFORM)
                    plat_map[sfx] = (
                        val.asOctets().decode("utf-8", errors="ignore").strip()
                        if hasattr(val, "asOctets")
                        else str(val).strip()
                    )

                for oid_str, value in addr_rows:
                    suffix = _get_oid_suffix(oid_str, OID_CDP_CACHE_ADDRESS)
                    ip = _format_ip_from_bytes(value)

                    parts = suffix.strip(".").split(".")
                    # Index is [cdpCacheIfIndex].[cdpCacheDeviceIndex]
                    local_port = parts[0] if parts else ""

                    result.cdp_neighbors.append(
                        CDPNeighbor(
                            device_id=dev_map.get(suffix, ""),
                            ip_address=ip,
                            device_port=port_map.get(suffix, ""),
                            platform=plat_map.get(suffix, ""),
                            local_port_index=local_port,
                        )
                    )
                log.info(
                    "SNMP walk [%s]: CDP walk completed (%d neighbors)",
                    target_ip,
                    len(result.cdp_neighbors),
                )
            except Exception as exc:
                result.errors.append(f"CDP walk failed: {exc}")
                log.warning("SNMP walk [%s]: CDP walk failed: %s", target_ip, exc)

            # 5. FDB Table (capped at MAX_FDB_ENTRIES)
            log.info("SNMP walk [%s]: walking FDB forwarding table...", target_ip)
            try:
                # Default/VLAN 1 walk
                mac_rows = await _snmp_walk_async(
                    engine,
                    auth,
                    transport,
                    context,
                    OID_FDB_ADDRESS,
                    max_rows=MAX_FDB_ENTRIES,
                )
                port_rows = await _snmp_walk_async(
                    engine,
                    auth,
                    transport,
                    context,
                    OID_FDB_PORT,
                    max_rows=MAX_FDB_ENTRIES,
                )

                port_map = {}
                for oid_str, val in port_rows:
                    suffix = _get_oid_suffix(oid_str, OID_FDB_PORT)
                    port_map[suffix] = str(val).strip()

                for oid_str, value in mac_rows:
                    mac = _format_mac(value)
                    suffix = _get_oid_suffix(oid_str, OID_FDB_ADDRESS)
                    port_idx = port_map.get(suffix, "")
                    if mac:
                        result.fdb_table.append(
                            FDBEntry(mac_address=mac, port_index=port_idx, vlan_id=1)
                        )

                # Multi-VLAN / Context-based walking for other active non-default VLANs
                active_vlans = sorted(
                    list(
                        {
                            v
                            for v in vlan_port_map.values()
                            if v and v not in (0, 1, 4095)
                        }
                    )
                )
                for vlan_id in active_vlans:
                    log.info(
                        "SNMP walk [%s]: walking FDB for VLAN %d...", target_ip, vlan_id
                    )
                    if creds.version in ("v1", "v2c"):
                        from pysnmp.hlapi.asyncio import CommunityData

                        mpmodel = 0 if creds.version == "v1" else 1
                        vlan_auth = CommunityData(
                            f"{creds.community}@{vlan_id}", mpModel=mpmodel
                        )
                        vlan_context = context
                    else:
                        from pysnmp.hlapi.asyncio import ContextData

                        vlan_auth = auth
                        vlan_context = ContextData(contextName=str(vlan_id))

                    try:
                        vlan_mac_rows = await _snmp_walk_async(
                            engine,
                            vlan_auth,
                            transport,
                            vlan_context,
                            OID_FDB_ADDRESS,
                            max_rows=MAX_FDB_ENTRIES,
                        )
                        vlan_port_rows = await _snmp_walk_async(
                            engine,
                            vlan_auth,
                            transport,
                            vlan_context,
                            OID_FDB_PORT,
                            max_rows=MAX_FDB_ENTRIES,
                        )

                        vlan_port_map_local = {}
                        for oid_str, val in vlan_port_rows:
                            suffix = _get_oid_suffix(oid_str, OID_FDB_PORT)
                            vlan_port_map_local[suffix] = str(val).strip()

                        for oid_str, value in vlan_mac_rows:
                            mac = _format_mac(value)
                            suffix = _get_oid_suffix(oid_str, OID_FDB_ADDRESS)
                            port_idx = vlan_port_map_local.get(suffix, "")
                            if mac:
                                result.fdb_table.append(
                                    FDBEntry(
                                        mac_address=mac,
                                        port_index=port_idx,
                                        vlan_id=vlan_id,
                                    )
                                )
                    except Exception as exc:
                        log.debug(
                            "SNMP walk [%s]: FDB walk for VLAN %d failed or not supported: %s",
                            target_ip,
                            vlan_id,
                            exc,
                        )

                log.info(
                    "SNMP walk [%s]: FDB walk completed (%d total entries)",
                    target_ip,
                    len(result.fdb_table),
                )
            except Exception as exc:
                result.errors.append(f"FDB walk failed: {exc}")
                log.warning("SNMP walk [%s]: FDB walk failed: %s", target_ip, exc)

        # Enforce a global hard timeout of 90 seconds for the entire SNMP walk series
        # (increased from 40s to accommodate interface/VLAN enrichment walks)
        try:
            loop.run_until_complete(asyncio.wait_for(run_walks_async(), timeout=90.0))
        except asyncio.TimeoutError:
            err_msg = "SNMP walk timed out after 90 seconds (forced cancellation)"
            result.errors.append(err_msg)
            log.error("SNMP walk [%s]: %s", target_ip, err_msg)
        except Exception as exc:
            result.errors.append(f"SNMP walk execution failed: {exc}")
            log.error("SNMP walk [%s]: walk execution failed: %s", target_ip, exc)

        log.info("SNMP walk [%s]: SNMP discovery complete", target_ip)
        return result
    finally:
        if "engine" in locals():
            try:
                engine.transportDispatcher.closeDispatcher()
            except Exception as exc:
                log.warning("Failed to close SNMP transport dispatcher: %s", exc)
        try:
            # Let loop run one tick to cleanly collect/close pending generators/tasks
            if not loop.is_closed() and not loop.is_running():
                loop.run_until_complete(asyncio.sleep(0.01))
            loop.close()
        except Exception:
            pass
