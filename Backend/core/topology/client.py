"""
core/topology/client.py
───────────────────────
Pluggable SNMP client for topology discovery.

Supports SNMPv1, v2c, and v3 with optional context names.
Fetches ARP tables, neighbour tables (LLDP, CDP and Extreme's EDP), FDB (MAC
address) tables, and the interface/bridge-port/VLAN metadata needed to say which
physical port a link is in.

Design decisions:
  - Uses pysnmp-lextudio==6.1.2 (the stable version containing the synchronous hlapi).
  - Lazy-loaded: import cost is paid only when topology mapping is requested.
  - GETBULK is used wherever the protocol allows (everything but SNMPv1).
    GETNEXT costs a round trip per row and measured ~2-3.4x slower per table
    against a real core switch holding ~900 ARP and ~1000 FDB entries.
  - FDB walk is capped at MAX_FDB_ENTRIES (2000) to prevent memory exhaustion
    on large enterprise switches with 50k+ MAC entries.
  - All walks are synchronous (run inside Celery worker thread).
  - Errors are caught per-walk and logged — a failing LLDP walk does not
    prevent ARP results from being returned.
  - Three neighbour protocols are read, not two. LLDP is the standard, CDP is
    Cisco's and EDP is Extreme's; an all-Extreme estate commonly runs only EDP,
    and reading just LLDP/CDP there returns an empty backbone while reporting
    success.
  - `SNMPWalkResult.capabilities` records the row count each MIB returned.
    An agent answering ARP and FDB happily while returning nothing for LLDP and
    all of Q-BRIDGE is normal, and the caller has to be able to tell that apart
    from a network that genuinely has no neighbours.
"""

import logging
import os
from dataclasses import dataclass, field

log = logging.getLogger("ccure.topology.client")

# ─── Safety Caps ─────────────────────────────────────────────────────────────
MAX_FDB_ENTRIES = 2000

#: Hard ceiling for one target's full walk series. Enrichment (interfaces,
#: bridge ports, VLANs) runs before the topology walks, so this has to cover
#: all of them, not just ARP/LLDP/CDP/EDP/FDB.
#:
#: A core switch legitimately holds thousands of rows; at 90s this deadline was
#: cutting real walks off mid-table and silently returning partial ARP and FDB
#: data. Overridable for very large chassis.
WALK_TIMEOUT_SECONDS = float(os.getenv("CCURE_SNMP_WALK_TIMEOUT", "240"))

#: Rows requested per GETBULK round trip. 25 is the conventional default: large
#: enough to collapse thousands of round trips into dozens, small enough that a
#: response still fits comfortably inside a normal MTU.
MAX_BULK_REPETITIONS = 25

#: Per-VLAN FDB walks are the most expensive part of a walk on a switch with
#: many VLANs — each one is a full pair of table walks. Cap the fan-out.
MAX_VLAN_FDB_WALKS = 32

#: Consecutive empty per-VLAN FDB walks before concluding the agent does not
#: support community indexing at all.
VLAN_FDB_GIVE_UP_AFTER = 3


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

# EDP neighbours (extremeEdpTable) — Extreme Networks proprietary.
#
# EXOS runs EDP by default and many Extreme estates never enable LLDP, so on an
# all-Extreme network this is the *only* source of switch-to-switch adjacency.
# Verified against an X670V-48x on EXOS 15.3.1.4: the row index is
#   <local ifIndex>.<2 reserved octets>.<6-octet neighbour MAC>
# e.g. ...1.3.1034.0.0.0.4.150.131.100.172 → ifIndex 1034, MAC 00:04:96:83:64:ac,
# which matches that MAC's bridge-port entry in the FDB on the same port.
# Column 7 looks like a port number but is the neighbour's hold timer: sampled
# 20s apart it changed on 6 of 6 neighbours while the cabling did not. It is
# deliberately not read — labelling a link with it would put a plausible but
# wrong remote port on every EDP adjacency. This EXOS build exposes no remote
# port column (cols 1, 2 and 8-11 return no rows; col 5 and 6 are constants),
# so EDP links carry a verified local port and no remote port at all.
OID_EDP_NEIGHBOR_NAME = "1.3.6.1.4.1.1916.1.13.2.1.3"
OID_EDP_NEIGHBOR_VERSION = "1.3.6.1.4.1.1916.1.13.2.1.4"

# FDB / Forwarding Database (dot1dTpFdbTable) — RFC 1493
OID_FDB_ADDRESS = "1.3.6.1.2.1.17.4.3.1.1"
OID_FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"

# System description (sysDescr / sysName / sysServices)
OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"  # Cheapest scalar for a liveness probe
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"
OID_SYS_SERVICES = "1.3.6.1.2.1.1.7.0"  # Layer bitmask (L2=2, L3=4, L7=64)

# ipForwarding — RFC 4293. 1 = forwarding (router), 2 = not-forwarding (host).
# Authoritative where sysServices is only advisory: Windows' agent sets the
# internet bit in sysServices on every workstation.
OID_IP_FORWARDING = "1.3.6.1.2.1.4.1.0"

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

# EXTREME-VLAN-MIB. EXOS 15.3 implements none of Q-BRIDGE — dot1qPvid,
# dot1qVlanStaticName, dot1qVlanCurrentEgressPorts and dot1qTpFdbPort all return
# zero rows — so without these every Extreme link would carry a NULL VLAN.
# Indexed by the VLAN's own router-interface ifIndex, which is also the ifIndex
# ARP entries are learned on (ifDescr 1000033 = "rtif(10.180.8.1/24)").
OID_EXTREME_VLAN_NAME = "1.3.6.1.4.1.1916.1.2.1.2.1.2"
OID_EXTREME_VLAN_TAG = "1.3.6.1.4.1.1916.1.2.1.2.1.10"

# Per-VLAN port membership, as an 802.1Q-style PortList bitmap.
# Row OID is <col>.<prefix>.<vlanIfIndex>.<slot>, so the VLAN's interface index
# is the second-to-last sub-identifier. Decoding verified on the live device:
# all six EDP uplink ports came out as multi-VLAN trunks while access ports
# resolved to single, correctly named VLANs (port 2 -> VLAN 30 "cmvt").
OID_EXTREME_VLAN_PORTS = "1.3.6.1.4.1.1916.1.2.6.1.1"


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
class EDPNeighbor:
    """
    One EDP neighbour (Extreme Networks proprietary discovery).

    Serves the same role as LLDP/CDP: it names the device on the other end of a
    physical link. `mac_address` comes from the row index and is the neighbour's
    chassis MAC, so it correlates directly with FDB and ARP observations of the
    same device.
    """

    device_name: str
    mac_address: str = ""
    local_port_index: str = ""
    software_version: str = ""


@dataclass
class FDBEntry:
    """
    One MAC forwarding table entry.

    ``port_index`` is a dot1dBasePort (bridge port), *not* an ifIndex — the two
    numbering spaces overlap, so it must be translated through
    dot1dBasePortIfIndex before it means anything.

    ``vlan_id`` is 0 when the VLAN is genuinely unknown. The default (unscoped)
    dot1dTpFdbTable walk returns whichever VLAN the agent's default context
    exposes; assuming that is VLAN 1 would stamp a wrong VLAN onto every
    endpoint learned from a switch whose default context is anything else.
    """

    mac_address: str
    port_index: str
    vlan_id: int = 0  # 0 = unknown; only set for VLAN-scoped walks


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
    ip_forwarding: int = 0  # 0 = unknown, 1 = forwarding, 2 = not forwarding
    arp_table: list[ARPEntry] = field(default_factory=list)
    lldp_neighbors: list[LLDPNeighbor] = field(default_factory=list)
    cdp_neighbors: list[CDPNeighbor] = field(default_factory=list)
    edp_neighbors: list[EDPNeighbor] = field(default_factory=list)
    fdb_table: list[FDBEntry] = field(default_factory=list)
    interface_table: dict[str, InterfaceInfo] = field(
        default_factory=dict
    )  # ifIndex -> InterfaceInfo
    bridge_port_map: dict[str, str] = field(
        default_factory=dict
    )  # bridge_port -> ifIndex
    errors: list[str] = field(default_factory=list)

    #: Which MIBs the agent actually served, as table name -> row count.
    #: A walk that returns nothing is not the same as a network with nothing to
    #: report: an Extreme switch answers every ARP and FDB query while returning
    #: zero rows for LLDP and all of Q-BRIDGE. Without this the run reports
    #: success with no errors and an operator cannot tell "no neighbours" from
    #: "cannot read neighbours".
    capabilities: dict[str, int] = field(default_factory=dict)

    @property
    def has_data(self) -> bool:
        return bool(
            self.arp_table
            or self.lldp_neighbors
            or self.cdp_neighbors
            or self.edp_neighbors
            or self.fdb_table
        )

    @property
    def neighbor_protocols(self) -> list[str]:
        """Neighbour-discovery protocols that actually returned adjacency."""
        found = []
        if self.lldp_neighbors:
            found.append("lldp")
        if self.cdp_neighbors:
            found.append("cdp")
        if self.edp_neighbors:
            found.append("edp")
        return found

    def resolve_by_if_index(self, if_index: str) -> InterfaceInfo | None:
        """
        Resolve an ifIndex to its InterfaceInfo.

        ARP (ipNetToMediaIfIndex), LLDP (lldpRemLocalPortNum on agents that key
        it by ifIndex) and CDP (cdpCacheIfIndex) all index the ifTable directly.
        They must NOT be passed through bridge_port_map: bridge port 1 commonly
        maps to ifIndex 10101, so translating an ifIndex of 1 would attach a
        completely unrelated port's description, VLAN and speed to the link.
        """
        if not if_index:
            return None
        return self.interface_table.get(str(if_index))

    def resolve_by_bridge_port(self, bridge_port: str) -> InterfaceInfo | None:
        """
        Resolve a dot1dBasePort (FDB port index) to its InterfaceInfo.

        Falls back to treating the value as an ifIndex only when the bridge port
        map is empty, which is what agents that do not implement
        dot1dBasePortIfIndex effectively mean.
        """
        if not bridge_port:
            return None
        key = str(bridge_port)
        mapped = self.bridge_port_map.get(key)
        if mapped is not None:
            return self.interface_table.get(mapped)
        if self.bridge_port_map:
            # The map exists but has no entry for this port — the port is not a
            # bridge port we know about; guessing an ifIndex here would invent
            # a wrong association.
            return None
        return self.interface_table.get(key)


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


def _decode_text(value) -> str:
    """Decode an SNMP OctetString (or any value) to a stripped string."""
    if value is None:
        return ""
    if hasattr(value, "asOctets"):
        return value.asOctets().decode("utf-8", errors="ignore").strip()
    return str(value).strip()


def _parse_edp_index(suffix: str) -> tuple[str, str]:
    """
    Split an extremeEdpTable row index into (local ifIndex, neighbour MAC).

    The index is ``<ifIndex>.<reserved>.<6-octet MAC>``. Taking the MAC as the
    final six sub-identifiers and the ifIndex as the first is stable across the
    reserved fields in between, whose width is not worth depending on.

    Verified on EXOS 15.3: ``1034.0.0.0.4.150.131.100.172`` → ifIndex 1034 and
    00:04:96:83:64:ac, a MAC that also appears in that switch's FDB on bridge
    port 34, which maps to ifIndex 1034.
    """
    parts = [p for p in suffix.strip(".").split(".") if p != ""]
    if len(parts) < 7:
        return (parts[0] if parts else ""), ""
    local_port = parts[0]
    mac_octets = parts[-6:]
    try:
        mac = ":".join(f"{int(o):02x}" for o in mac_octets)
    except ValueError:
        return local_port, ""
    return local_port, mac


def _decode_port_list(raw) -> list[int]:
    """
    Decode an 802.1Q PortList bitmap into 1-based port numbers.

    The first octet covers ports 1-8 with the most significant bit as port 1,
    which is the convention Q-BRIDGE defines and Extreme's VLAN tables reuse.
    Positions are dot1dBasePort numbers, so callers must translate through
    dot1dBasePortIfIndex before treating them as ifIndexes.
    """
    if hasattr(raw, "asOctets"):
        raw = raw.asOctets()
    if not isinstance(raw, (bytes, bytearray)):
        return []
    return [
        octet_index * 8 + bit + 1
        for octet_index, octet in enumerate(raw)
        for bit in range(8)
        if octet & (0x80 >> bit)
    ]


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
        CommunityData,
        ContextData,
        SnmpEngine,
        UdpTransportTarget,
        UsmUserData,
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
                usmHMAC128SHA224AuthProtocol,
                usmHMAC192SHA256AuthProtocol,
                usmHMACMD5AuthProtocol,
                usmHMACSHAAuthProtocol,
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
                usmAesCfb128Protocol,
                usmAesCfb256Protocol,
                usmDESPrivProtocol,
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
    engine,
    auth,
    transport,
    context,
    oid: str,
    max_rows: int = 0,
    use_bulk: bool = True,
) -> list[tuple]:
    """
    Perform an asynchronous SNMP walk starting from `oid`.
    Returns list of (oid_str, value) tuples.

    If max_rows > 0, stops after max_rows results (safety cap).

    Uses GETBULK where the protocol allows it. GETNEXT costs one request/response
    round trip per row; against a core switch with ~900 ARP entries, ~1000 FDB
    entries and 162 interfaces that is several thousand sequential round trips,
    which measured at ~90s per device and overran the walk deadline mid-table.
    GETBULK returns MAX_BULK_REPETITIONS rows per round trip. SNMPv1 has no
    GETBULK, so it keeps the GETNEXT path.
    """
    from pysnmp.hlapi.asyncio import (
        ObjectIdentity,
        ObjectType,
        bulkWalkCmd,
        walkCmd,
    )

    results = []
    count = 0
    previous_oid = None

    common = dict(
        lexicographicMode=False,
        # Every OID here is walked and parsed numerically, so MIB resolution
        # buys nothing and costs a MIB compile on first use — which also
        # fails noisily for enterprise trees such as CDP.
        lookupMib=False,
    )

    if use_bulk:
        cmd = bulkWalkCmd(
            engine,
            auth,
            transport,
            context,
            0,  # nonRepeaters
            MAX_BULK_REPETITIONS,
            ObjectType(ObjectIdentity(oid)),
            **common,
        )
    else:
        cmd = walkCmd(
            engine,
            auth,
            transport,
            context,
            ObjectType(ObjectIdentity(oid)),
            **common,
        )

    try:
        async for errorIndication, errorStatus, errorIndex, varBinds in cmd:
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
    from pysnmp.hlapi.asyncio import ObjectIdentity, ObjectType, getCmd

    try:
        errorIndication, errorStatus, errorIndex, varBinds = await getCmd(
            engine,
            auth,
            transport,
            context,
            ObjectType(ObjectIdentity(oid)),
            lookupMib=False,
        )

        if errorIndication or errorStatus:
            return None

        if varBinds:
            return varBinds[0][1]
    except Exception as exc:
        log.warning("Exception during SNMP get for %s: %s", oid, exc)
    return None


# ─── Public API ──────────────────────────────────────────────────────────────


def _run_isolated(coro_factory, timeout: float):
    """
    Run one coroutine on a private event loop, then put the thread's loop policy
    back the way it was found.

    Celery workers reuse threads. Installing a fresh loop and closing it without
    restoring the previous one leaves a *closed* loop registered for the thread,
    so the next library that calls ``asyncio.get_event_loop()`` on that worker
    fails with "Event loop is closed" — a failure that surfaces far from here.
    """
    import asyncio

    try:
        previous_loop = asyncio.get_event_loop_policy().get_event_loop()
    except Exception:
        previous_loop = None

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(
            asyncio.wait_for(coro_factory(), timeout=timeout)
        )
    finally:
        try:
            # pysnmp's dispatcher leaves timeout tasks parked on the loop.
            # Closing without cancelling them logs "Task was destroyed but it
            # is pending!" for every walk, which buries real errors.
            pending = [t for t in asyncio.all_tasks(loop) if not t.done()]
            for task in pending:
                task.cancel()
            if pending:
                loop.run_until_complete(
                    asyncio.gather(*pending, return_exceptions=True)
                )
        except Exception:
            pass
        try:
            loop.run_until_complete(loop.shutdown_asyncgens())
        except Exception:
            pass
        try:
            loop.close()
        except Exception:
            pass
        try:
            asyncio.set_event_loop(
                previous_loop
                if previous_loop and not previous_loop.is_closed()
                else None
            )
        except Exception:
            pass


def probe_snmp(target_ip: str, creds: SNMPCredentials) -> bool:
    """
    Cheap reachability test: one GET of sysObjectID.

    `walk_target` issues roughly a dozen walks. Against a host with no SNMP
    agent every one of them burns ``timeout × (retries + 1)`` before giving up,
    so walking a /24 of ordinary workstations costs hours of wall clock for
    zero rows. Probing first turns each non-agent host into a single timeout.
    """
    engine = None
    try:
        engine, auth, transport, context = _build_snmp_engine(creds, target_ip)
    except Exception as exc:
        log.debug("SNMP probe [%s]: engine build failed: %s", target_ip, exc)
        return False

    async def _probe():
        return await _snmp_get_async(
            engine, auth, transport, context, OID_SYS_OBJECT_ID
        )

    # One request plus its retries, with a little headroom for scheduling.
    budget = max(2.0, creds.timeout * (creds.retries + 1) + 1.0)
    try:
        value = _run_isolated(_probe, timeout=budget)
        return value is not None
    except Exception as exc:
        log.debug("SNMP probe [%s]: no response (%s)", target_ip, exc)
        return False
    finally:
        _close_engine(engine, target_ip)


def _close_engine(engine, target_ip: str) -> None:
    """Release the transport dispatcher owned by an SNMP engine."""
    if engine is None:
        return
    try:
        engine.transportDispatcher.closeDispatcher()
    except Exception as exc:
        log.debug("SNMP [%s]: dispatcher close failed: %s", target_ip, exc)


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
    log.info("SNMP walk [%s]: starting SNMP discovery...", target_ip)
    result = SNMPWalkResult(target_ip=target_ip)
    engine = None

    try:
        try:
            engine, auth, transport, context = _build_snmp_engine(creds, target_ip)
        except Exception as exc:
            result.errors.append(f"SNMP engine build failed: {exc}")
            log.error("SNMP walk [%s]: engine build failed: %s", target_ip, exc)
            return result

        # SNMPv1 predates GETBULK; everything newer gets the bulk path.
        use_bulk = creds.version != "v1"

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
                val = await _snmp_get_async(
                    engine, auth, transport, context, OID_IP_FORWARDING
                )
                if val is not None:
                    try:
                        result.ip_forwarding = int(val)
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
                    engine, auth, transport, context, OID_IF_DESCR, use_bulk=use_bulk
                )
                name_rows = await _snmp_walk_async(
                    engine, auth, transport, context, OID_IF_NAME, use_bulk=use_bulk
                )
                alias_rows = await _snmp_walk_async(
                    engine, auth, transport, context, OID_IF_ALIAS, use_bulk=use_bulk
                )
                speed_rows = await _snmp_walk_async(
                    engine, auth, transport, context, OID_IF_SPEED, use_bulk=use_bulk
                )
                high_speed_rows = await _snmp_walk_async(
                    engine,
                    auth,
                    transport,
                    context,
                    OID_IF_HIGH_SPEED,
                    use_bulk=use_bulk,
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
                    engine,
                    auth,
                    transport,
                    context,
                    OID_BRIDGE_PORT_IF_INDEX,
                    use_bulk=use_bulk,
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
            vlan_port_map: dict[str, int] = {}  # ifIndex/bridge_port -> vlan_id
            #: VLANs eligible for a community-indexed per-VLAN FDB walk. Only
            #: the standard/Cisco port-VLAN tables feed this. Vendor VLAN
            #: inventories (e.g. EXTREME-VLAN-MIB) describe VLAN *interfaces*,
            #: not access ports, and community indexing is a Cisco convention —
            #: driving the walk from them fires dozens of queries at communities
            #: the agent will never answer, each costing a full timeout.
            fdb_vlan_candidates: set[int] = set()
            try:
                pvid_rows = await _snmp_walk_async(
                    engine, auth, transport, context, OID_DOT1Q_PVID, use_bulk=use_bulk
                )
                for oid_str, val in pvid_rows:
                    port_idx = _get_oid_suffix(oid_str, OID_DOT1Q_PVID)
                    if port_idx:
                        try:
                            vlan_port_map[port_idx] = int(val)
                            fdb_vlan_candidates.add(int(val))
                        except (ValueError, TypeError):
                            pass
            except Exception as exc:
                log.debug(
                    "SNMP walk [%s]: dot1qPvid walk failed (may not be supported): %s",
                    target_ip,
                    exc,
                )

            # Cisco vmVlan query (merge results with dot1qPvid)
            try:
                vm_rows = await _snmp_walk_async(
                    engine,
                    auth,
                    transport,
                    context,
                    OID_CISCO_VM_VLAN,
                    use_bulk=use_bulk,
                )
                for oid_str, val in vm_rows:
                    if_index = _get_oid_suffix(oid_str, OID_CISCO_VM_VLAN)
                    if if_index and if_index not in vlan_port_map:
                        try:
                            vlan_port_map[if_index] = int(val)
                            fdb_vlan_candidates.add(int(val))
                        except (ValueError, TypeError):
                            pass
            except Exception as exc:
                log.debug(
                    "SNMP walk [%s]: vmVlan walk failed (may not be supported): %s",
                    target_ip,
                    exc,
                )

            # EXTREME-VLAN-MIB fallback. EXOS implements none of Q-BRIDGE, so
            # without this every link discovered from an Extreme switch carries
            # a NULL VLAN. Keyed by the VLAN's router-interface ifIndex, which
            # is the ifIndex ARP entries are learned on.
            try:
                tag_rows = await _snmp_walk_async(
                    engine,
                    auth,
                    transport,
                    context,
                    OID_EXTREME_VLAN_TAG,
                    use_bulk=use_bulk,
                )
                name_rows = await _snmp_walk_async(
                    engine,
                    auth,
                    transport,
                    context,
                    OID_EXTREME_VLAN_NAME,
                    use_bulk=use_bulk,
                )
                vlan_names = {
                    _get_oid_suffix(oid, OID_EXTREME_VLAN_NAME): _decode_text(val)
                    for oid, val in name_rows
                }
                for oid_str, val in tag_rows:
                    vlan_if_index = _get_oid_suffix(oid_str, OID_EXTREME_VLAN_TAG)
                    if not vlan_if_index:
                        continue
                    try:
                        tag = int(val)
                    except (ValueError, TypeError):
                        continue
                    vlan_port_map.setdefault(vlan_if_index, tag)
                    iface = result.interface_table.get(vlan_if_index)
                    if iface is not None and not iface.alias:
                        # Surface the operator's VLAN name ("un-lan", "sci-cloud")
                        # rather than only the generated rtif(...) description.
                        iface.alias = vlan_names.get(vlan_if_index, "")
                result.capabilities["extreme_vlan"] = len(tag_rows)

                # Per-port VLAN membership. The tag table above describes VLAN
                # *interfaces*; this maps VLANs to the physical ports that carry
                # them, which is what an endpoint's VLAN actually depends on.
                vlan_tags = {
                    _get_oid_suffix(oid, OID_EXTREME_VLAN_TAG): int(val)
                    for oid, val in tag_rows
                    if str(val).lstrip("-").isdigit()
                }
                membership: dict[int, set[int]] = {}
                port_rows = await _snmp_walk_async(
                    engine,
                    auth,
                    transport,
                    context,
                    OID_EXTREME_VLAN_PORTS,
                    use_bulk=use_bulk,
                )
                for oid_str, val in port_rows:
                    suffix = _get_oid_suffix(oid_str, OID_EXTREME_VLAN_PORTS)
                    parts = suffix.split(".")
                    if len(parts) < 2:
                        continue
                    tag = vlan_tags.get(parts[-2])  # <prefix>.<vlanIfIndex>.<slot>
                    if tag is None:
                        continue
                    for bridge_port in _decode_port_list(val):
                        membership.setdefault(bridge_port, set()).add(tag)

                # Only a port belonging to exactly one VLAN has an unambiguous
                # VLAN. A trunk carrying nine VLANs has no single answer, and
                # picking one would put a wrong VLAN on every endpoint behind
                # it — on this device all six inter-switch uplinks are trunks.
                access_ports = 0
                for bridge_port, tag_set in membership.items():
                    if len(tag_set) != 1:
                        continue
                    if_index = result.bridge_port_map.get(str(bridge_port))
                    iface = result.interface_table.get(if_index or "")
                    if iface is not None and not iface.vlan_id:
                        iface.vlan_id = next(iter(tag_set))
                        access_ports += 1
                result.capabilities["extreme_vlan_ports"] = len(membership)
                log.info(
                    "SNMP walk [%s]: VLAN port membership resolved "
                    "(%d ports, %d unambiguous access ports)",
                    target_ip,
                    len(membership),
                    access_ports,
                )
            except Exception as exc:
                log.debug(
                    "SNMP walk [%s]: EXTREME-VLAN walk failed (not an Extreme "
                    "device?): %s",
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
                    engine,
                    auth,
                    transport,
                    context,
                    OID_ARP_PHYS_ADDRESS,
                    use_bulk=use_bulk,
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
                    engine,
                    auth,
                    transport,
                    context,
                    OID_LLDP_REM_CHASSIS_ID,
                    use_bulk=use_bulk,
                )
                port_rows = await _snmp_walk_async(
                    engine,
                    auth,
                    transport,
                    context,
                    OID_LLDP_REM_PORT_ID,
                    use_bulk=use_bulk,
                )
                name_rows = await _snmp_walk_async(
                    engine,
                    auth,
                    transport,
                    context,
                    OID_LLDP_REM_SYS_NAME,
                    use_bulk=use_bulk,
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
                    engine,
                    auth,
                    transport,
                    context,
                    OID_CDP_CACHE_ADDRESS,
                    use_bulk=use_bulk,
                )
                dev_rows = await _snmp_walk_async(
                    engine,
                    auth,
                    transport,
                    context,
                    OID_CDP_CACHE_DEVICE_ID,
                    use_bulk=use_bulk,
                )
                port_rows = await _snmp_walk_async(
                    engine,
                    auth,
                    transport,
                    context,
                    OID_CDP_CACHE_DEVICE_PORT,
                    use_bulk=use_bulk,
                )
                plat_rows = await _snmp_walk_async(
                    engine,
                    auth,
                    transport,
                    context,
                    OID_CDP_CACHE_PLATFORM,
                    use_bulk=use_bulk,
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

            # 4b. EDP Neighbors (Extreme Networks)
            log.info("SNMP walk [%s]: walking EDP neighbors...", target_ip)
            try:
                name_rows = await _snmp_walk_async(
                    engine,
                    auth,
                    transport,
                    context,
                    OID_EDP_NEIGHBOR_NAME,
                    use_bulk=use_bulk,
                )
                version_rows = await _snmp_walk_async(
                    engine,
                    auth,
                    transport,
                    context,
                    OID_EDP_NEIGHBOR_VERSION,
                    use_bulk=use_bulk,
                )
                version_map = {
                    _get_oid_suffix(oid, OID_EDP_NEIGHBOR_VERSION): _decode_text(val)
                    for oid, val in version_rows
                }

                for oid_str, value in name_rows:
                    suffix = _get_oid_suffix(oid_str, OID_EDP_NEIGHBOR_NAME)
                    local_port, mac = _parse_edp_index(suffix)
                    device_name = _decode_text(value)
                    if not device_name and not mac:
                        continue
                    result.edp_neighbors.append(
                        EDPNeighbor(
                            device_name=device_name,
                            mac_address=mac,
                            local_port_index=local_port,
                            software_version=version_map.get(suffix, ""),
                        )
                    )
                log.info(
                    "SNMP walk [%s]: EDP walk completed (%d neighbors)",
                    target_ip,
                    len(result.edp_neighbors),
                )
            except Exception as exc:
                result.errors.append(f"EDP walk failed: {exc}")
                log.warning("SNMP walk [%s]: EDP walk failed: %s", target_ip, exc)

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
                    use_bulk=use_bulk,
                )
                port_rows = await _snmp_walk_async(
                    engine,
                    auth,
                    transport,
                    context,
                    OID_FDB_PORT,
                    max_rows=MAX_FDB_ENTRIES,
                    use_bulk=use_bulk,
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
                        # vlan_id stays 0: the default context's FDB is not
                        # guaranteed to be VLAN 1, and a guessed VLAN would be
                        # written straight onto the endpoint's asset record.
                        result.fdb_table.append(
                            FDBEntry(mac_address=mac, port_index=port_idx, vlan_id=0)
                        )

                # Multi-VLAN / Context-based walking for other active non-default VLANs
                active_vlans = sorted(
                    {v for v in fdb_vlan_candidates if v and v not in (0, 1, 4095)}
                )
                if len(active_vlans) > MAX_VLAN_FDB_WALKS:
                    log.warning(
                        "SNMP walk [%s]: %d active VLANs, walking the first %d",
                        target_ip,
                        len(active_vlans),
                        MAX_VLAN_FDB_WALKS,
                    )
                    active_vlans = active_vlans[:MAX_VLAN_FDB_WALKS]

                # Community indexing is a Cisco convention. On an agent that
                # does not implement it every VLAN query goes unanswered and
                # costs timeout x (retries + 1); across dozens of VLANs that
                # alone can exceed the whole walk deadline. Give up after a few
                # consecutive empty VLANs rather than paying for all of them.
                empty_vlan_walks = 0
                for vlan_id in active_vlans:
                    if empty_vlan_walks >= VLAN_FDB_GIVE_UP_AFTER:
                        log.info(
                            "SNMP walk [%s]: per-VLAN FDB unsupported (%d empty "
                            "VLAN walks) — skipping remaining %d VLANs",
                            target_ip,
                            empty_vlan_walks,
                            len(active_vlans) - active_vlans.index(vlan_id),
                        )
                        break
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

                        # SNMPv3 has no community indexing. The equivalent on
                        # Cisco IOS is a context named "vlan-<id>" — a bare
                        # numeric context name matches nothing and the per-VLAN
                        # walk silently returns zero rows.
                        vlan_auth = auth
                        vlan_context = ContextData(contextName=f"vlan-{vlan_id}")

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

                        if not vlan_mac_rows:
                            empty_vlan_walks += 1
                        else:
                            empty_vlan_walks = 0

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

        # Hard ceiling for the whole walk series, so one unresponsive agent
        # cannot stall the scan. Partial results collected before the deadline
        # are kept — `result` is mutated in place by run_walks_async.
        import asyncio

        try:
            _run_isolated(run_walks_async, timeout=WALK_TIMEOUT_SECONDS)
        except asyncio.TimeoutError:
            err_msg = (
                f"SNMP walk timed out after {WALK_TIMEOUT_SECONDS:.0f}s "
                "(partial results retained)"
            )
            result.errors.append(err_msg)
            log.error("SNMP walk [%s]: %s", target_ip, err_msg)
        except Exception as exc:
            result.errors.append(f"SNMP walk execution failed: {exc}")
            log.error("SNMP walk [%s]: walk execution failed: %s", target_ip, exc)

        result.capabilities.update(
            {
                "interfaces": len(result.interface_table),
                "bridge_ports": len(result.bridge_port_map),
                "arp": len(result.arp_table),
                "lldp": len(result.lldp_neighbors),
                "cdp": len(result.cdp_neighbors),
                "edp": len(result.edp_neighbors),
                "fdb": len(result.fdb_table),
            }
        )
        if not result.neighbor_protocols:
            # Not an error — but the map will have no switch-to-switch links,
            # and the operator needs to know that came from the device rather
            # than from the network genuinely being flat.
            log.warning(
                "SNMP walk [%s]: no neighbour-discovery data (LLDP/CDP/EDP all "
                "empty) — inter-device links cannot be derived for this target",
                target_ip,
            )
        log.info(
            "SNMP walk [%s]: SNMP discovery complete (%s)",
            target_ip,
            ", ".join(f"{k}={v}" for k, v in sorted(result.capabilities.items())),
        )
        return result
    finally:
        _close_engine(engine, target_ip)
