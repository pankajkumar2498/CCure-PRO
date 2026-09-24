"""
core/topology/engine.py
───────────────────────
Topology Correlation Engine.

Converts raw SNMP walk results (ARP, LLDP, CDP, FDB) from one or more
switch/router targets into a deduplicated set of NetworkLink records, and
renders those records as a graph for the UI.

Pipeline:
  1. Probe every candidate target for an SNMP agent (cheap, concurrent).
  2. Walk the responders concurrently, bounded by SNMP_WALK_CONCURRENCY.
  3. Convert each walk into `LinkObservation`s, giving both ends an identity
     (see core.topology.identity).
  4. Anchor those identities on inventory, so one device observed under two
     identifiers becomes one node.
  5. Merge observations of the same adjacency, keeping the strongest evidence.
  6. Upsert links in canonical orientation, in one transaction, enrolling
     assets for LLDP/CDP neighbours inventory has not seen.

Design decisions:
  - Endpoint identity is computed once, at the walk boundary. An LLDP chassis
    ID or CDP device ID is frequently a hostname rather than a MAC, and
    `Asset.mac_address` is a PostgreSQL MACADDR column: querying it with a
    non-MAC raises and poisons the transaction rather than returning no rows.
  - Identity is then anchored on the asset an endpoint resolves to. A switch
    is reported by management IP when it is walked and by chassis MAC when a
    neighbour names it; without anchoring those are two nodes, and worse, the
    identity shifts between runs as inventory fills in — writing a second set
    of link rows instead of updating the first.
  - Evidence is ranked. LLDP and CDP describe the physical wire; ARP proves
    L3 reachability through a device; an FDB entry only proves a frame was
    seen. A neighbour discovered by LLDP that also appears in the FDB is still
    an LLDP neighbour.
  - Links are stored with their endpoints in sorted-key order, so the two
    reciprocal reports of one wire converge on one row instead of overwriting
    each other's port assignments. The reporting device is written to the
    source side, so "source observed target" holds for ARP and FDB links.
  - Assets are loaded once per run into an in-memory index. The previous
    per-link lookups were 3–5 round trips each, on up to MAX_FDB_ENTRIES
    entries per switch.
"""

import logging
import os
from collections import defaultdict
from dataclasses import dataclass, field

from core.topology.identity import (
    Endpoint,
    canonical_pair,
    is_valid_ip,
    make_endpoint,
    normalize_mac,
)
from db.base import gen_asset_id, gen_network_link_id, utcnow
from db.models import Asset, Organization, Scan
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

log = logging.getLogger("ccure.topology.engine")

#: How many targets to probe/walk at once. SNMP agents are slow and mostly
#: idle-waiting, so this is I/O bound; the ceiling exists to avoid flooding
#: small network gear with simultaneous sessions.
SNMP_WALK_CONCURRENCY = int(os.getenv("CCURE_SNMP_WALK_CONCURRENCY", "8"))

#: Postgres caps bind parameters per statement; IN-lists are chunked to fit.
_ID_CHUNK = 500

#: Relative strength of each discovery protocol as evidence of adjacency.
#: LLDP, CDP and EDP all describe a physical wire and rank together; ARP proves
#: only L3 reachability, and an FDB entry only that a frame was seen.
EVIDENCE_PRIORITY = {"lldp": 40, "cdp": 30, "edp": 30, "arp": 20, "fdb": 10}

#: Protocols whose presence means the two endpoints are directly cabled, and
#: whose remote end is therefore network infrastructure worth enrolling.
NEIGHBOR_PROTOCOLS = frozenset({"lldp", "cdp", "edp"})

#: Categories that render on the infrastructure tier of the map.
INFRA_CATEGORIES = frozenset(
    {
        "switch",
        "router",
        "gateway",
        "firewall",
        "wireless_ap",
        "load_balancer",
        "modem",
    }
)

#: Categories generic enough that topology evidence may overwrite them.
_GENERIC_CATEGORIES = frozenset(
    {"", "host", "generic", "unknown", "endpoint", "device"}
)

#: VLAN IDs that mean "no VLAN": 0 is the untagged/priority-tagged sentinel and
#: 4095 is reserved by 802.1Q.
_SENTINEL_VLANS = frozenset({0, 4095})


def _valid_vlan(vlan_id) -> int | None:
    """Return a usable 802.1Q VLAN ID, or None."""
    try:
        vid = int(vlan_id)
    except (TypeError, ValueError):
        return None
    if vid in _SENTINEL_VLANS or not (1 <= vid <= 4094):
        return None
    return vid


# ─── Device classification ───────────────────────────────────────────────────

#: Hostname tokens that identify infrastructure. Matched against tokens split on
#: non-alphanumerics, never as substrings: "rt" as a substring matches "port",
#: "smart" and "north", which is how ordinary switches ended up labelled routers.
_ROUTER_TOKENS = frozenset({"router", "rtr", "rt", "gw", "gateway", "edge", "core-rtr"})
_FIREWALL_TOKENS = frozenset({"firewall", "fw", "asa", "palo", "fortigate"})
_SWITCH_TOKENS = frozenset({"switch", "sw", "swt", "access", "dist"})


def _tokens(*values: str | None) -> set[str]:
    """Split labels into comparable lowercase tokens."""
    import re

    out: set[str] = set()
    for value in values:
        if not value:
            continue
        out.update(t for t in re.split(r"[^a-z0-9]+", str(value).lower()) if t)
    return out


def classify_neighbor_category(
    hostname: str | None, platform: str | None = None
) -> str:
    """
    Best-effort category for an LLDP/CDP neighbour known only by name.

    Neighbours reached over LLDP/CDP are network infrastructure by definition —
    those protocols run between network devices — so the question is only which
    kind. Defaults to "switch", the overwhelmingly common case.
    """
    tokens = _tokens(hostname, platform)
    if tokens & _FIREWALL_TOKENS:
        return "firewall"
    if tokens & _ROUTER_TOKENS:
        return "router"
    return "switch"


def classify_snmp_device(walk) -> str | None:
    """
    Classify a walked device from what it reports about itself.

    Returns "switch", "router", or None when the evidence does not support a
    confident answer — in which case the existing inventory category is left
    alone rather than being overwritten with a guess.

    sysServices alone is not sufficient: Windows' SNMP agent sets the internet
    (L3) bit on ordinary workstations and servers, so testing `sysServices & 4`
    labels every Windows host a router. ipForwarding (RFC 4293) states the
    device's actual role and takes precedence; a populated bridge/forwarding
    table is direct evidence of switching.
    """
    if walk is None:
        return None

    services = int(getattr(walk, "sys_services", 0) or 0)
    forwarding = int(getattr(walk, "ip_forwarding", 0) or 0)

    bridging = bool(getattr(walk, "fdb_table", None)) or bool(
        getattr(walk, "bridge_port_map", None)
    )

    if forwarding == 1:
        routing = True
    elif forwarding == 2:
        routing = False  # The device says it does not forward. Believe it.
    else:
        # ipForwarding unavailable. Fall back to sysServices, but only trust it
        # when the device is not also advertising the application layer, which
        # general-purpose operating systems do and dedicated L3 gear does not.
        routing = bool(services & 4) and not bool(services & 64)

    if bridging:
        return "switch"
    if routing:
        return "router"
    if services & 2 and not services & 64:
        return "switch"
    return None


# ─── Observations ────────────────────────────────────────────────────────────


@dataclass
class LinkObservation:
    """
    One adjacency as reported by one device, before merging.

    `local` is the walked device; `remote` is what it reported. Ports are held
    per side so that canonical reordering can swap them together with their
    endpoints.
    """

    local: Endpoint
    remote: Endpoint
    link_type: str
    local_port: str | None = None
    local_port_desc: str | None = None
    remote_port: str | None = None
    remote_port_desc: str | None = None
    vlan_id: int | None = None
    speed_bps: int | None = None


@dataclass
class MergedLink:
    """
    An adjacency after canonical ordering and evidence merging.

    Endpoints are held in canonical (sorted-key) order — that is what makes the
    two reciprocal reports of one wire converge on a single record. `local_keys`
    remembers which endpoints actually reported the adjacency, so the row can be
    written out with the reporting device on the source side; downstream, "the
    source observed the target" is what tells an ARP entry's switch apart from
    the endpoint it saw.
    """

    link_id: str
    first: Endpoint
    second: Endpoint
    link_type: str
    observed_types: set[str] = field(default_factory=set)
    first_port: str | None = None
    first_port_desc: str | None = None
    second_port: str | None = None
    second_port_desc: str | None = None
    vlan_id: int | None = None
    speed_bps: int | None = None
    local_keys: set[str] = field(default_factory=set)
    #: Whether each side's port came from that device's own walk rather than
    #: from its neighbour's view of it.
    first_port_from_self: bool = False
    second_port_from_self: bool = False
    #: Evidence rank of the observation each side's port came from.
    first_port_rank: int = 0
    second_port_rank: int = 0

    @property
    def is_infrastructure_link(self) -> bool:
        """True when a neighbour-discovery protocol backs this adjacency."""
        return bool(self.observed_types & NEIGHBOR_PROTOCOLS)

    def oriented(self) -> tuple[Endpoint, Endpoint, tuple, tuple]:
        """
        Return (source, target, source_ports, target_ports) with the reporting
        device as the source.

        When both ends reported each other — reciprocal LLDP between two
        switches — either orientation is equally true, so canonical order breaks
        the tie and keeps the stored row stable across runs.
        """
        first_side = (self.first_port, self.first_port_desc)
        second_side = (self.second_port, self.second_port_desc)

        second_is_reporter = (
            self.second.key in self.local_keys and self.first.key not in self.local_keys
        )
        if second_is_reporter:
            return self.second, self.first, second_side, first_side
        return self.first, self.second, first_side, second_side


def _merge_endpoint(existing: Endpoint, incoming: Endpoint) -> Endpoint:
    """
    Combine two views of the same endpoint, keeping every attribute learned.

    Two reporters routinely know different things about the same device: an
    ARP entry supplies an IP, LLDP supplies a system name, the FDB supplies
    only a MAC.
    """
    return Endpoint(
        kind=existing.kind,
        key=existing.key,
        mac=existing.mac or incoming.mac,
        ip=existing.ip or incoming.ip,
        name=existing.name or incoming.name,
    )


def merge_observations(
    observations: list[LinkObservation], org_slug: str
) -> dict[str, MergedLink]:
    """
    Collapse observations into one MergedLink per adjacency.

    Endpoints are placed in canonical order so that A→B and B→A converge, and
    the strongest evidence wins the `link_type` while every protocol that saw
    the adjacency is recorded in `observed_types`. Enrichment fields are filled
    from whichever observation supplied them.
    """
    merged: dict[str, MergedLink] = {}

    for obs in observations:
        first, second, swapped = canonical_pair(obs.local, obs.remote)
        link_id = gen_network_link_id(org_slug, first.key, second.key)

        # `swapped` says whether canonical ordering flipped local/remote, which
        # is also what decides whose port description each side carries.
        if swapped:
            first_side = (obs.remote_port, obs.remote_port_desc, False)
            second_side = (obs.local_port, obs.local_port_desc, True)
        else:
            first_side = (obs.local_port, obs.local_port_desc, True)
            second_side = (obs.remote_port, obs.remote_port_desc, False)

        current = merged.get(link_id)
        if current is None:
            merged[link_id] = MergedLink(
                link_id=link_id,
                first=first,
                second=second,
                link_type=obs.link_type,
                observed_types={obs.link_type},
                first_port=first_side[0],
                first_port_desc=first_side[1],
                first_port_from_self=first_side[2] and bool(first_side[0]),
                first_port_rank=EVIDENCE_PRIORITY.get(obs.link_type, 0),
                second_port=second_side[0],
                second_port_desc=second_side[1],
                second_port_from_self=second_side[2] and bool(second_side[0]),
                second_port_rank=EVIDENCE_PRIORITY.get(obs.link_type, 0),
                vlan_id=obs.vlan_id,
                speed_bps=obs.speed_bps,
                local_keys={obs.local.key},
            )
            continue

        current.observed_types.add(obs.link_type)
        current.local_keys.add(obs.local.key)
        current.first = _merge_endpoint(current.first, first)
        current.second = _merge_endpoint(current.second, second)

        if EVIDENCE_PRIORITY.get(obs.link_type, 0) > EVIDENCE_PRIORITY.get(
            current.link_type, 0
        ):
            current.link_type = obs.link_type

        rank = EVIDENCE_PRIORITY.get(obs.link_type, 0)
        _apply_side(current, "first", first_side, rank)
        _apply_side(current, "second", second_side, rank)

        current.vlan_id = current.vlan_id or obs.vlan_id
        current.speed_bps = current.speed_bps or obs.speed_bps

    return merged


def _apply_side(link: MergedLink, side: str, value: tuple, rank: int = 0) -> None:
    """
    Fold one observation's view of a link side into the merged record.

    Ports are ranked by (self-reported, evidence strength):

      * A device's own walk beats a neighbour's recollection of it — when both
        describe the same end of the wire, the local ifIndex is authoritative.
      * Among a device's own observations, stronger evidence wins. This matters
        on real hardware: an ARP entry for a neighbouring switch is learned on
        the *routed VLAN interface* it replied through — "rtif(10.180.4.1/22)" —
        while the EDP/LLDP entry for that same neighbour names the physical port
        the cable is in, "Port 34". Both are self-reported and ARP is walked
        first, so without ranking the topology link would be labelled with a
        VLAN interface instead of a port.
    """
    port, desc, from_self = value
    if not port and not desc:
        return

    incoming = (bool(from_self and port), rank)
    current = (
        bool(getattr(link, f"{side}_port_from_self") and getattr(link, f"{side}_port")),
        getattr(link, f"{side}_port_rank"),
    )

    if getattr(link, f"{side}_port") and incoming <= current:
        # Keep what we have, but fill in a description if it was missing.
        if desc and not getattr(link, f"{side}_port_desc"):
            setattr(link, f"{side}_port_desc", desc)
        return

    if port:
        setattr(link, f"{side}_port", port)
        setattr(link, f"{side}_port_from_self", from_self)
        setattr(link, f"{side}_port_rank", rank)
    if desc:
        setattr(link, f"{side}_port_desc", desc)


def observations_from_walk(walk, local: Endpoint) -> list[LinkObservation]:
    """
    Convert one SNMPWalkResult into adjacency observations.

    Port indices are resolved through the correct namespace for each protocol:
    ARP, LLDP and CDP index the ifTable directly, while FDB entries are
    dot1dBasePort values that must go through dot1dBasePortIfIndex first.
    """
    observations: list[LinkObservation] = []

    def _iface_fields(iface):
        if iface is None:
            return None, None, None
        return (
            iface.display_name,
            (iface.speed_bps or None),
            _valid_vlan(iface.vlan_id),
        )

    # ARP — proves the reporting device can reach the endpoint at L3.
    for arp in walk.arp_table:
        remote = make_endpoint(raw_id=arp.mac_address, ip=arp.ip_address)
        if remote is None or remote.key == local.key:
            continue
        desc, speed, vlan = _iface_fields(walk.resolve_by_if_index(arp.interface_index))
        observations.append(
            LinkObservation(
                local=local,
                remote=remote,
                link_type="arp",
                local_port=f"if{arp.interface_index}" if arp.interface_index else None,
                local_port_desc=desc,
                vlan_id=vlan,
                speed_bps=speed,
            )
        )

    # LLDP — the authoritative view of the physical wire.
    for neighbor in walk.lldp_neighbors:
        remote = make_endpoint(raw_id=neighbor.chassis_id, name=neighbor.system_name)
        if remote is None or remote.key == local.key:
            continue
        desc, speed, vlan = _iface_fields(
            walk.resolve_by_if_index(neighbor.local_port_index)
        )
        observations.append(
            LinkObservation(
                local=local,
                remote=remote,
                link_type="lldp",
                local_port=(
                    f"if{neighbor.local_port_index}"
                    if neighbor.local_port_index
                    else None
                ),
                local_port_desc=desc,
                remote_port=neighbor.port_id or neighbor.port_desc or None,
                remote_port_desc=neighbor.port_desc or neighbor.port_id or None,
                vlan_id=vlan,
                speed_bps=speed,
            )
        )

    # CDP — same role as LLDP on Cisco gear.
    for neighbor in walk.cdp_neighbors:
        remote = make_endpoint(
            raw_id=neighbor.device_id,
            ip=neighbor.ip_address,
            name=neighbor.device_id,
        )
        if remote is None or remote.key == local.key:
            continue
        desc, speed, vlan = _iface_fields(
            walk.resolve_by_if_index(neighbor.local_port_index)
        )
        observations.append(
            LinkObservation(
                local=local,
                remote=remote,
                link_type="cdp",
                local_port=(
                    f"if{neighbor.local_port_index}"
                    if neighbor.local_port_index
                    else None
                ),
                local_port_desc=desc,
                remote_port=neighbor.device_port or None,
                remote_port_desc=neighbor.device_port or None,
                vlan_id=vlan,
                speed_bps=speed,
            )
        )

    # EDP — Extreme's equivalent. On an all-Extreme estate this is typically the
    # only neighbour protocol running, so without it the entire switch-to-switch
    # backbone is invisible and every peer switch collapses into the MAC-only
    # cluster as an anonymous forwarding-table entry.
    for neighbor in getattr(walk, "edp_neighbors", ()):
        remote = make_endpoint(
            raw_id=neighbor.mac_address or neighbor.device_name,
            name=neighbor.device_name,
        )
        if remote is None or remote.key == local.key:
            continue
        desc, speed, vlan = _iface_fields(
            walk.resolve_by_if_index(neighbor.local_port_index)
        )
        observations.append(
            LinkObservation(
                local=local,
                remote=remote,
                link_type="edp",
                local_port=(
                    f"if{neighbor.local_port_index}"
                    if neighbor.local_port_index
                    else None
                ),
                local_port_desc=desc,
                # No remote port: this EXOS build's EDP table exposes none, and
                # the column that resembles one is a hold timer.
                vlan_id=vlan,
                speed_bps=speed,
            )
        )

    # FDB — weakest evidence: a frame from this MAC was seen on this port.
    for fdb in walk.fdb_table:
        remote = make_endpoint(raw_id=fdb.mac_address)
        if remote is None or remote.key == local.key:
            continue
        desc, speed, iface_vlan = _iface_fields(
            walk.resolve_by_bridge_port(fdb.port_index)
        )
        observations.append(
            LinkObservation(
                local=local,
                remote=remote,
                link_type="fdb",
                local_port=f"port:{fdb.port_index}" if fdb.port_index else None,
                local_port_desc=desc,
                vlan_id=iface_vlan or _valid_vlan(fdb.vlan_id),
                speed_bps=speed,
            )
        )

    return observations


# ─── Asset resolution ────────────────────────────────────────────────────────


class AssetIndex:
    """
    In-memory view of an organisation's assets for the duration of one run.

    Loading once and resolving in memory replaces several thousand per-link
    queries on a large switch, and keeps every non-MAC identifier away from the
    MACADDR column.
    """

    def __init__(self, db: Session, org_id: str):
        self.db = db
        self.org_id = org_id
        self.by_mac: dict[str, Asset] = {}
        self.by_ip: dict[str, Asset] = {}
        self.by_hostname: dict[str, Asset] = {}
        #: Hostnames held by more than one asset. A default model name shared
        #: across an estate identifies nothing, so it must never resolve.
        self._ambiguous_hostnames: set[str] = set()
        self.created: list[Asset] = []
        #: endpoint key → asset-anchored identity, memoised because an FDB walk
        #: can present the same endpoint thousands of times.
        self._canonical_cache: dict[str, Endpoint] = {}

        for asset in db.query(Asset).filter(Asset.org_id == org_id).all():
            self.register(asset)

    def register(self, asset: Asset) -> None:
        """Index an asset under every identifier it carries."""
        mac = normalize_mac(asset.mac_address)
        if mac:
            self.by_mac.setdefault(mac, asset)
        if asset.ip_address:
            self.by_ip.setdefault(str(asset.ip_address), asset)
        if asset.hostname:
            hostname = str(asset.hostname).lower()
            claimed = self.by_hostname.setdefault(hostname, asset)
            if claimed is not asset:
                # A second device answering to the same name makes the name
                # useless as an identifier; retract it rather than letting it
                # match one of them arbitrarily.
                self._ambiguous_hostnames.add(hostname)

    def resolve(self, endpoint: Endpoint) -> Asset | None:
        """
        Find the asset an endpoint refers to.

        Tiered by how strongly each identifier binds to one device:
          1. MAC — an L2 identity, stable across DHCP leases.
          2. IP + hostname — corroborated, so a recycled lease cannot alias.
          3. IP alone.
          4. Hostname alone, and only when nothing stronger is available.

        Tier 4 is deliberately the narrowest. Network gear ships with a model
        name as its default hostname, so an estate can hold several devices all
        calling themselves "X460-48t" — observed on this network, where two
        physically distinct switches on ports 41 and 43 share that name. Merging
        on hostname would fuse them into one node and invent a link between
        their neighbours. So it is skipped whenever the endpoint carries a MAC
        or IP of its own (a strong identifier that failed to match means a
        *different* device, not a reason to fall back), and ambiguous hostnames
        are excluded from the index entirely.
        """
        if endpoint.mac:
            asset = self.by_mac.get(endpoint.mac)
            if asset:
                return asset

        hostname = (endpoint.name or "").lower()
        if endpoint.ip and hostname:
            asset = self.by_ip.get(endpoint.ip)
            if asset and (asset.hostname or "").lower() == hostname:
                return asset

        if endpoint.ip:
            asset = self.by_ip.get(endpoint.ip)
            if asset:
                return asset

        if hostname and not endpoint.mac and not endpoint.ip:
            if hostname in self._ambiguous_hostnames:
                return None
            return self.by_hostname.get(hostname)

        return None

    def get_or_create(
        self, endpoint: Endpoint, device_category: str | None
    ) -> Asset | None:
        """
        Resolve an endpoint, enrolling a placeholder asset when it is unknown.

        Used only for LLDP/CDP neighbours: those are real infrastructure devices
        the scan proved exist, and leaving them out leaves holes in the map.
        Endpoints known only by MAC from an FDB entry are deliberately not
        enrolled — a forwarding-table entry is not evidence of a manageable
        asset, and enrolling them would flood inventory.
        """
        asset = self.resolve(endpoint)
        if asset is not None:
            self._enrich(asset, endpoint, device_category)
            return asset

        seed = endpoint.ip or endpoint.mac or endpoint.name
        if not seed:
            return None

        asset_id = gen_asset_id(self.org_id, seed)
        existing = self.db.get(Asset, asset_id)
        if existing is not None:
            self.register(existing)
            self._enrich(existing, endpoint, device_category)
            return existing

        now = utcnow()
        asset = Asset(
            id=asset_id,
            org_id=self.org_id,
            ip_address=endpoint.ip,
            mac_address=endpoint.mac,
            hostname=endpoint.name or None,
            device_category=device_category,
            discovery_method="topology",
            last_seen_at=now,
            created_at=now,
            updated_at=now,
        )
        self.db.add(asset)
        self.db.flush()  # Make the PK available for the link's FK.
        self.register(asset)
        self.created.append(asset)
        return asset

    def canonical(self, endpoint: Endpoint) -> Endpoint:
        """
        Re-key an endpoint onto the asset it resolves to.

        One device is routinely observed under two identities: by management IP
        when it is the walk target (inventory may not know its MAC yet) and by
        chassis MAC when a neighbour reports it. Left alone, those produce two
        node identities — and worse, the identity *changes between runs* as
        inventory fills in, so the next scan writes a second set of link rows
        instead of updating the first. Anchoring on the asset makes identity
        stable no matter which attribute was learned first.

        Endpoints that resolve to nothing keep their own key; inventing an
        identity for them would be a guess.
        """
        cached = self._canonical_cache.get(endpoint.key)
        if cached is not None:
            return _merge_endpoint(cached, endpoint)

        asset = self.resolve(endpoint)
        if asset is None or not asset.id:
            return endpoint

        canonical = Endpoint(
            kind="asset",
            key=f"asset:{asset.id}",
            mac=endpoint.mac or normalize_mac(asset.mac_address),
            ip=endpoint.ip or (str(asset.ip_address) if asset.ip_address else None),
            name=endpoint.name or (str(asset.hostname) if asset.hostname else None),
        )
        self._canonical_cache[endpoint.key] = canonical
        return canonical

    def _enrich(
        self, asset: Asset, endpoint: Endpoint, device_category: str | None
    ) -> None:
        """Fill gaps on an existing asset without overwriting better data."""
        if not asset.mac_address and endpoint.mac:
            asset.mac_address = endpoint.mac
            self.by_mac.setdefault(endpoint.mac, asset)
        if not asset.hostname and endpoint.name:
            asset.hostname = endpoint.name
            self.by_hostname.setdefault(endpoint.name.lower(), asset)
        current = (asset.device_category or "").lower()
        # An inventory category that says something specific — "printer",
        # "server" — outranks anything topology can infer.
        if device_category and current in _GENERIC_CATEGORIES:
            asset.device_category = device_category


# ─── Mapping run ─────────────────────────────────────────────────────────────


def _register_walked_target(index: AssetIndex, ip: str, walk) -> Endpoint:
    """
    Establish the identity of a walked device, enrolling it if inventory has
    somehow not seen it.

    A device that answered SNMP demonstrably exists, so giving it an asset up
    front costs nothing and buys a stable identity: without one, the first run
    keys its links by management IP and the second — after enrolment filled in
    its MAC — keys them differently, writing a duplicate set of rows instead of
    updating the originals.
    """
    sys_name = (getattr(walk, "sys_name", "") or "").strip() or None
    seed = make_endpoint(raw_id=None, ip=ip, name=sys_name) or Endpoint(
        "ip", f"ip:{ip}", ip=ip
    )

    asset = index.get_or_create(seed, classify_snmp_device(walk))
    if asset is None:
        return seed

    if sys_name and not asset.hostname:
        asset.hostname = sys_name

    return index.canonical(seed)


def _canonicalize_observations(
    observations: list[LinkObservation], index: AssetIndex
) -> list[LinkObservation]:
    """
    Anchor both ends of every observation on inventory identity.

    Runs before merging, because merging is keyed on endpoint identity: two
    observations of the same device under different identifiers have to agree on
    a key before they can collapse into one link. Observations whose ends turn
    out to be the same asset are dropped — a device is not adjacent to itself.
    """
    resolved: list[LinkObservation] = []
    for obs in observations:
        obs.local = index.canonical(obs.local)
        obs.remote = index.canonical(obs.remote)
        if obs.local.key == obs.remote.key:
            continue
        resolved.append(obs)
    return resolved


def _walk_targets(target_ips: list[str], creds) -> tuple[dict, list[str]]:
    """
    Probe and walk targets concurrently.

    Returns (walks_by_ip, errors). Probing first means a host with no SNMP
    agent costs one timeout instead of one per table walk.
    """
    from concurrent.futures import ThreadPoolExecutor

    from core.topology.client import probe_snmp, walk_target

    errors: list[str] = []
    walks: dict = {}

    workers = max(1, min(SNMP_WALK_CONCURRENCY, len(target_ips)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        responsive = [
            ip
            for ip, alive in zip(
                target_ips, pool.map(lambda t: probe_snmp(t, creds), target_ips)
            )
            if alive
        ]
        log.info(
            "SNMP probe: %d of %d targets responded", len(responsive), len(target_ips)
        )
        if not responsive:
            return walks, errors

        def _walk(ip: str):
            try:
                return ip, walk_target(ip, creds), None
            except Exception as exc:  # one bad agent must not stop the run
                log.exception("Topology walk failed for %s", ip)
                return ip, None, f"Walk failed for {ip}: {exc}"

        # Iterate in target order so the merge is deterministic across runs.
        for ip, walk, error in pool.map(_walk, responsive):
            if error:
                errors.append(error)
                continue
            if walk is None:
                continue
            errors.extend(walk.errors)
            if walk.has_data:
                walks[ip] = walk
            else:
                log.info("No topology data from %s (agent returned empty tables)", ip)

    return walks, errors


def run_topology_mapping(
    db: Session,
    scan_id: str,
    org_id: str,
    snmp_config: dict,
    target_ips: list[str] | None = None,
) -> dict:
    """
    Execute the full topology mapping pipeline.

    Args:
        db: SQLAlchemy session.
        scan_id: The scan that triggered this mapping.
        org_id: Organization ID (for scoping and link IDs).
        snmp_config: SNMP credentials dict from scan.options["snmp"].
        target_ips: Optional list of IPs to walk. If None, walks all
                    active hosts discovered in the scan.

    Returns:
        dict with keys: success, links_created, links_updated, total_links,
        targets_walked, assets_enrolled, errors.
    """
    from core.topology.client import SNMPCredentials

    creds = SNMPCredentials.from_dict(snmp_config)

    org = db.query(Organization).filter(Organization.id == org_id).first()
    org_slug = org.slug if org else org_id

    if not target_ips:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        target_ips = list(scan.target_hosts) if scan and scan.target_hosts else []

    # De-duplicate while preserving order — the same host can appear in several
    # phase summaries.
    target_ips = list(dict.fromkeys(ip for ip in target_ips if is_valid_ip(ip)))

    if not target_ips:
        log.warning("No target IPs for topology mapping on scan %s", scan_id)
        return {
            "success": True,
            "links_created": 0,
            "links_updated": 0,
            "total_links": 0,
            "targets_walked": 0,
            "assets_enrolled": 0,
            "errors": ["No targets"],
        }

    log.info(
        "Starting topology mapping for scan=%s, org=%s, targets=%d, snmp_version=%s",
        scan_id,
        org_id,
        len(target_ips),
        creds.version,
    )

    walks, all_errors = _walk_targets(target_ips, creds)

    index = AssetIndex(db, org_id)

    # Identify and classify each walked device from what it reports about
    # itself, before any link identity is derived from it.
    observations: list[LinkObservation] = []
    for ip in target_ips:
        walk = walks.get(ip)
        if walk is None:
            continue
        local = _register_walked_target(index, ip, walk)
        observations.extend(observations_from_walk(walk, local))

    observations = _canonicalize_observations(observations, index)
    merged = merge_observations(observations, org_slug)
    log.info(
        "Topology mapping produced %d unique links from %d observations",
        len(merged),
        len(observations),
    )

    created, updated = _persist_links(db, org_id, scan_id, merged, index)

    log.info(
        "Topology mapping complete for scan=%s: %d created, %d updated, "
        "%d assets enrolled, %d errors",
        scan_id,
        created,
        updated,
        len(index.created),
        len(all_errors),
    )

    return {
        "success": True,
        "links_created": created,
        "links_updated": updated,
        "total_links": len(merged),
        "targets_walked": len(walks),
        "assets_enrolled": len(index.created),
        "errors": all_errors,
    }


def _persist_links(
    db: Session,
    org_id: str,
    scan_id: str,
    merged: dict[str, MergedLink],
    index: AssetIndex,
) -> tuple[int, int]:
    """
    Upsert merged links, resolving both endpoints to assets.

    Runs as one transaction: a partially written topology is worse than none,
    because the map cannot tell the difference between "not adjacent" and
    "not written yet".
    """
    from db.models import NetworkLink

    if not merged:
        db.commit()
        return 0, 0

    link_ids = list(merged.keys())
    existing_ids: set[str] = set()
    for start in range(0, len(link_ids), _ID_CHUNK):
        chunk = link_ids[start : start + _ID_CHUNK]
        existing_ids.update(
            row[0]
            for row in db.query(NetworkLink.id)
            .filter(NetworkLink.org_id == org_id, NetworkLink.id.in_(chunk))
            .all()
        )

    created = 0
    updated = 0
    now = utcnow()

    try:
        for link in merged.values():
            source, target, source_side, target_side = link.oriented()

            if link.is_infrastructure_link:
                # LLDP/CDP neighbours are network devices the scan proved exist;
                # enrol the ones inventory has not seen so the map is complete.
                source_asset = index.get_or_create(
                    source, classify_neighbor_category(source.name)
                )
                target_asset = index.get_or_create(
                    target, classify_neighbor_category(target.name)
                )
            else:
                source_asset = index.resolve(source)
                target_asset = index.resolve(target)

            vlan_id = _valid_vlan(link.vlan_id)
            # Record the VLAN on the endpoint that sits in it. The source side
            # of an ARP/FDB link is the reporting switch, whose own VLAN this
            # is not.
            if vlan_id and target_asset is not None and not target_asset.vlan_id:
                target_asset.vlan_id = vlan_id

            values = {
                "id": link.link_id,
                "org_id": org_id,
                "scan_id": scan_id,
                "source_key": source.key,
                "source_mac": source.mac,
                "source_ip": source.ip,
                "source_port": source_side[0],
                "source_port_desc": source_side[1],
                "source_asset_id": source_asset.id if source_asset else None,
                "target_key": target.key,
                "target_mac": target.mac,
                "target_ip": target.ip,
                "target_port": target_side[0],
                "target_port_desc": target_side[1],
                "target_asset_id": target_asset.id if target_asset else None,
                "vlan_id": vlan_id,
                "speed_bps": link.speed_bps,
                "link_type": link.link_type,
                "observed_types": ",".join(sorted(link.observed_types)),
                "first_seen_at": now,
                "last_seen_at": now,
                "created_at": now,
            }

            stmt = insert(NetworkLink).values(**values)
            # Endpoints are part of the conflict target's identity, but they are
            # still refreshed: a device that gains a MAC between scans must have
            # it recorded, and first_seen_at must survive.
            stmt = stmt.on_conflict_do_update(
                index_elements=["id"],
                set_={
                    key: values[key]
                    for key in values
                    if key not in ("id", "org_id", "first_seen_at", "created_at")
                },
            )
            db.execute(stmt)

            if link.link_id in existing_ids:
                updated += 1
            else:
                created += 1

        db.commit()
    except Exception:
        db.rollback()
        log.exception("Topology persistence failed for scan %s; rolled back", scan_id)
        raise

    return created, updated


# ─── Graph rendering ─────────────────────────────────────────────────────────


@dataclass
class _GraphNode:
    """A device on the map, accumulated across every link that mentions it."""

    key: str
    label: str = ""
    group: str = "endpoint"
    tier: str = "host"
    ip: str = ""
    mac: str = ""
    vendor: str = ""
    subnet: str = ""
    asset_id: str | None = None
    evidence: dict = field(default_factory=dict)


def get_topology_graph(
    db: Session,
    org_id: str,
    scan_id: str | None = None,
    subnet_mask: int = 24,
    active_within_days: int | None = None,
) -> dict:
    """
    Build a vis-network compatible clustered graph from stored NetworkLink rows.

    Hosts are grouped under subnet clusters (default /24) so the view does not
    collapse into a physics blob; endpoints with no resolved IP go under a
    virtual 'MAC-Only / FDB' cluster.

    `active_within_days` restricts the graph to links seen recently. Without it
    an org-wide map is the union of every link ever recorded — including
    decommissioned hosts — which is history, not topology.
    """
    import hashlib
    import ipaddress
    from datetime import timedelta

    from db.models import NetworkLink
    from sqlalchemy.orm import selectinload

    query = db.query(NetworkLink).filter(NetworkLink.org_id == org_id)
    if scan_id:
        query = query.filter(NetworkLink.scan_id == scan_id)
    if active_within_days:
        cutoff = utcnow() - timedelta(days=active_within_days)
        query = query.filter(NetworkLink.last_seen_at >= cutoff)
    # Both asset relationships are read for every link; without eager loading
    # this is two queries per link.
    query = query.options(
        selectinload(NetworkLink.source_asset),
        selectinload(NetworkLink.target_asset),
    )

    links = query.all()

    try:
        from core.oui_lookup import lookup_vendor
    except Exception:
        lookup_vendor = None

    def _vendor_for(asset, mac: str) -> str:
        if asset:
            vendor = getattr(asset, "vendor", None) or getattr(
                asset, "manufacturer", None
            )
            if vendor:
                return str(vendor)
        if lookup_vendor and mac:
            try:
                return lookup_vendor(mac) or ""
            except Exception:
                return ""
        return ""

    def _endpoint_key(stored_key, mac, ip, asset) -> str:
        """
        Identity for a stored endpoint on the map.

        An asset ID outranks the raw endpoint key: the same device is routinely
        recorded under two identities — by management IP when it is walked
        (inventory may not know its MAC) and by chassis MAC when a neighbour
        reports it over LLDP. Both rows resolve to one asset, so keying on the
        asset collapses them into the one node they describe.
        """
        if asset is not None and asset.id:
            return f"asset:{asset.id}"
        if stored_key:
            return str(stored_key)
        normalized = normalize_mac(mac)
        if normalized:
            return normalized
        if is_valid_ip(ip):
            return f"ip:{ip}"
        return str(mac or ip or "unknown")

    # Resolve every link's endpoint identities once; both passes below and the
    # edge payloads must agree on them.
    resolved: list[tuple] = []
    for link in links:
        src_key = _endpoint_key(
            getattr(link, "source_key", None),
            link.source_mac,
            getattr(link, "source_ip", None),
            link.source_asset,
        )
        tgt_key = _endpoint_key(
            getattr(link, "target_key", None),
            link.target_mac,
            link.target_ip,
            link.target_asset,
        )
        if src_key == tgt_key:
            continue  # self-adjacency carries no topology information
        resolved.append((link, src_key, tgt_key))

    # ── Pass 1: establish node identity and tier ────────────────────────────
    # Every device gets exactly one entry. The previous implementation kept
    # separate infra and host maps, so a switch that was both a walk target and
    # another switch's ARP entry emitted two nodes with the same id — which
    # vis-network rejects, taking the whole map down with it.
    nodes: dict[str, _GraphNode] = {}

    def _touch(key: str, asset, mac, ip, link, is_source: bool) -> _GraphNode:
        node = nodes.get(key)
        if node is None:
            node = _GraphNode(key=key)
            nodes[key] = node

        node.asset_id = node.asset_id or (asset.id if asset else None)
        node.mac = node.mac or (normalize_mac(mac) or "")
        node.ip = node.ip or (str(ip) if is_valid_ip(ip) else "")
        if asset and not node.ip and asset.ip_address:
            node.ip = str(asset.ip_address)

        group = _classify_node_group(link, asset)
        if (
            group == "endpoint"
            and not is_source
            and link.link_type in NEIGHBOR_PROTOCOLS
        ):
            # Neighbour-discovery protocols only run between network devices.
            group = "switch"
        if node.group in ("endpoint", "") or group in INFRA_CATEGORIES:
            node.group = group

        # A device that reports its own neighbour tables is infrastructure,
        # whatever inventory calls it.
        if is_source or group in INFRA_CATEGORIES:
            node.tier = "infra"

        if not node.label:
            label = ""
            if asset:
                label = asset.hostname or (
                    str(asset.ip_address) if asset.ip_address else ""
                )
            node.label = label or node.ip or node.mac or key
        if not node.vendor:
            node.vendor = _vendor_for(asset, node.mac)
        return node

    for link, src_key, tgt_key in resolved:
        _touch(
            src_key,
            link.source_asset,
            link.source_mac,
            getattr(link, "source_ip", None),
            link,
            is_source=True,
        )
        _touch(tgt_key, link.target_asset, link.target_mac, link.target_ip, link, False)

    # ── Pass 2: place hosts into subnets, build edges ───────────────────────
    subnet_map: dict[str, dict] = {}
    infra_edges: list[dict] = []
    seen_edge_ids: set[str] = set()

    def _edge_id(a: str, b: str) -> str:
        return hashlib.md5(
            f"edge:{a}:{b}".encode("utf-8"), usedforsecurity=False
        ).hexdigest()

    for link, src_key, tgt_key in resolved:
        src_node = nodes[src_key]
        tgt_node = nodes[tgt_key]

        if tgt_node.tier == "infra":
            edge_id = _edge_id(src_key, tgt_key)
            if edge_id in seen_edge_ids:
                continue
            seen_edge_ids.add(edge_id)
            infra_edges.append(
                {
                    "id": edge_id,
                    "from": src_key,
                    "to": tgt_key,
                    "label": link.link_type or "physical",
                    "link_type": link.link_type,
                    "observed_types": (
                        getattr(link, "observed_types", None) or link.link_type or ""
                    ),
                    "source_port": link.source_port or "",
                    "source_port_desc": link.source_port_desc or "",
                    "target_port": link.target_port or "",
                    "target_port_desc": link.target_port_desc or "",
                    "vlan_id": link.vlan_id,
                    "speed_bps": link.speed_bps,
                    "tier": "infra",
                }
            )
            continue

        # Host endpoint: bucket it by subnet.
        if tgt_node.ip:
            try:
                subnet_str = str(
                    ipaddress.ip_network(f"{tgt_node.ip}/{subnet_mask}", strict=False)
                )
            except ValueError:
                subnet_str = "MAC-Only / FDB"
        else:
            subnet_str = "MAC-Only / FDB"

        tgt_node.subnet = subnet_str

        # An endpoint is often seen by several switches. Show the strongest
        # evidence rather than whichever row the query happened to return last;
        # a switch that has the endpoint in its FDB says less about where it
        # actually lives than one that resolved its ARP entry.
        incoming_rank = EVIDENCE_PRIORITY.get(link.link_type or "", 0)
        current_rank = EVIDENCE_PRIORITY.get(
            (tgt_node.evidence or {}).get("link_type", ""), -1
        )
        if incoming_rank > current_rank:
            tgt_node.evidence = {
                "source_key": src_key,
                "source_label": src_node.label,
                "source_port": link.source_port or "",
                "source_port_desc": link.source_port_desc or "",
                "target_port": link.target_port or "",
                "target_port_desc": link.target_port_desc or "",
                "link_type": link.link_type or "unknown",
                "observed_types": getattr(link, "observed_types", None)
                or link.link_type
                or "",
                "vlan_id": link.vlan_id,
                "speed_bps": link.speed_bps,
            }

        bucket = subnet_map.setdefault(
            subnet_str,
            {
                "hosts": set(),
                "ip_hosts": set(),
                "asset_matches": set(),
                "link_types": defaultdict(int),
                "sources": {},
            },
        )
        bucket["hosts"].add(tgt_key)
        if tgt_node.ip:
            bucket["ip_hosts"].add(tgt_key)
        if tgt_node.asset_id:
            bucket["asset_matches"].add(tgt_key)

        ltype = link.link_type or "arp"
        bucket["link_types"][ltype] += 1

        source_info = bucket["sources"].setdefault(
            src_key, {"ports": set(), "link_types": set(), "count": 0}
        )
        source_info["count"] += 1
        source_info["link_types"].add(ltype)
        if link.source_port:
            source_info["ports"].add(link.source_port)

    # ── Pass 3: emit the payload ────────────────────────────────────────────
    subnet_nodes: list[dict] = []
    subnet_edges: list[dict] = []

    for subnet_str, info in subnet_map.items():
        count = len(info["hosts"])
        snode_id = f"subnet:{subnet_str}"
        ip_resolved = len(info["ip_hosts"])
        mac_only_count = count - ip_resolved
        has_arp = bool(info["link_types"].get("arp"))
        has_fdb = bool(info["link_types"].get("fdb"))
        has_lldp = bool(info["link_types"].get("lldp"))
        has_cdp = bool(info["link_types"].get("cdp"))
        is_mac_only_cluster = subnet_str == "MAC-Only / FDB"

        recommended_actions = []
        if mac_only_count:
            recommended_actions.extend(
                [
                    "Run ARP-enabled scan",
                    "Add gateway/router SNMP target",
                    "Correlate with asset inventory",
                ]
            )
        if not has_arp:
            recommended_actions.append("Enable ARP table collection")
        if not (has_lldp or has_cdp):
            recommended_actions.append("Enable LLDP/CDP on infrastructure devices")

        subnet_nodes.append(
            {
                "id": snode_id,
                "label": (
                    f"MAC-only endpoints\n({count} devices)"
                    if is_mac_only_cluster
                    else f"{subnet_str}\n({count} hosts)"
                ),
                "group": "mac_only_cluster" if is_mac_only_cluster else "subnet",
                "tier": "subnet",
                "subnet": subnet_str,
                "host_count": count,
                "data_quality": {
                    "ip_resolved": ip_resolved,
                    "mac_only": mac_only_count,
                    "asset_matches": len(info["asset_matches"]),
                    "source_count": len(info["sources"]),
                    "has_arp": has_arp,
                    "has_fdb": has_fdb,
                    "has_lldp": has_lldp,
                    "has_cdp": has_cdp,
                },
                "recommended_actions": recommended_actions,
            }
        )

        ltype_summary = ", ".join(f"{k}: {v}" for k, v in info["link_types"].items())
        for src_key, src_info in info["sources"].items():
            subnet_edges.append(
                {
                    "id": _edge_id(src_key, snode_id),
                    "from": src_key,
                    "to": snode_id,
                    "link_type": (
                        sorted(
                            src_info["link_types"],
                            key=lambda t: -EVIDENCE_PRIORITY.get(t, 0),
                        )[0]
                        if src_info["link_types"]
                        else "arp"
                    ),
                    "host_count": count,
                    "label": (
                        f"{src_info['count']} links" if src_info["count"] > 1 else ""
                    ),
                    "source_port": (
                        ", ".join(sorted(src_info["ports"]))
                        if src_info["ports"]
                        else "unknown"
                    ),
                    "target_port": "",
                    "tier": "subnet",
                    "link_details": {
                        "type_counts": dict(info["link_types"]),
                        "summary": ltype_summary,
                        "ports": sorted(src_info["ports"]),
                    },
                }
            )

    node_payload = []
    infra_count = 0
    host_count = 0
    mac_only_hosts = 0
    asset_matched_hosts = 0

    for node in nodes.values():
        payload = {
            "id": node.key,
            "label": node.label,
            "group": node.group,
            "tier": node.tier,
            "ip": node.ip,
            "mac": node.mac,
            "vendor": node.vendor,
            "asset_id": node.asset_id,
            "asset_match_status": "matched" if node.asset_id else "unmatched",
        }
        if node.tier == "infra":
            infra_count += 1
        else:
            host_count += 1
            if not node.ip:
                mac_only_hosts += 1
            if node.asset_id:
                asset_matched_hosts += 1
            payload["subnet"] = node.subnet
            payload.update(node.evidence)
        node_payload.append(payload)

    # Drop edges whose endpoint never became a node (possible only for rows
    # written before endpoint identity was normalised).
    node_ids = {n["id"] for n in node_payload} | {s["id"] for s in subnet_nodes}
    all_edges = [
        edge
        for edge in (infra_edges + subnet_edges)
        if edge["from"] in node_ids and edge["to"] in node_ids
    ]

    log.info(
        "Topology map generated: %d links read, %d infra nodes, %d subnets, "
        "%d hosts (%d MAC-only, %d asset-matched)",
        len(links),
        infra_count,
        len(subnet_map),
        host_count,
        mac_only_hosts,
        asset_matched_hosts,
    )

    return {
        "graph_version": 3,
        "nodes": node_payload + subnet_nodes,
        "edges": all_edges,
        "subnets": sorted(subnet_map.keys()),
        "stats": {
            "infrastructure": infra_count,
            "subnets": len(subnet_map),
            "hosts": host_count,
            "mac_only": mac_only_hosts,
            "asset_matched": asset_matched_hosts,
            "links": len(links),
        },
    }


#: Exact device_category values, checked before any heuristic.
_CATEGORY_ALIASES = {
    "router": "router",
    "gateway": "gateway",
    "firewall": "firewall",
    "switch": "switch",
    "switchport": "switch",
    "wireless_ap": "wireless_ap",
    "wireless_access_point": "wireless_ap",
    "wap": "wireless_ap",
    "access_point": "wireless_ap",
    "server": "server",
    "storage": "storage",
    "nas": "storage",
    "san": "storage",
    "virtual_machine": "virtual_machine",
    "vm": "virtual_machine",
    "load_balancer": "load_balancer",
    "modem": "modem",
    "printer": "printer",
    "camera": "camera",
    "ip_camera": "camera",
    "plc": "plc",
    "rtu": "rtu",
    "scada_ics": "plc",
    "iot": "iot",
    "mobile": "mobile",
    "laptop": "laptop",
    "desktop": "desktop",
    "workstation": "workstation",
}

#: Token → visual group, applied to hostname/OS/vendor when the category is
#: generic. Token matching (not substring) keeps "smart-plug" from matching
#: "rt" and "camp-server" from matching "cam".
_GROUP_TOKENS = {
    "switch": "switch",
    "sw": "switch",
    "router": "router",
    "rtr": "router",
    "gateway": "gateway",
    "gw": "gateway",
    "firewall": "firewall",
    "fw": "firewall",
    "ap": "wireless_ap",
    "wap": "wireless_ap",
    "server": "server",
    "srv": "server",
    "esxi": "server",
    "printer": "printer",
    "prn": "printer",
    "camera": "camera",
    "cam": "camera",
    "cctv": "camera",
    "plc": "plc",
    "rtu": "rtu",
    "nas": "storage",
    "synology": "storage",
    "qnap": "storage",
    "vm": "virtual_machine",
    "virtualbox": "virtual_machine",
    "lb": "load_balancer",
    "loadbalancer": "load_balancer",
    "modem": "modem",
    "laptop": "laptop",
    "notebook": "laptop",
    "desktop": "desktop",
    "workstation": "workstation",
    "phone": "mobile",
    "mobile": "mobile",
    "android": "mobile",
    "iphone": "mobile",
}


def _classify_node_group(link, asset: Asset | None) -> str:
    """Classify a node into a visual group for the frontend graph."""
    if asset is not None:
        cat = (asset.device_category or "").strip().lower()
        if cat in _CATEGORY_ALIASES:
            return _CATEGORY_ALIASES[cat]

        hints = _tokens(
            asset.hostname,
            getattr(asset, "os_name", None),
            getattr(asset, "vendor", None) or getattr(asset, "manufacturer", None),
            # A category not in the alias table can still carry a usable word.
            cat,
        )
        for token, group in _GROUP_TOKENS.items():
            if token in hints:
                return group

        if cat in ("endpoint", "workstation", "desktop", "laptop", "pc", "client"):
            return "endpoint"

    if link is not None and getattr(link, "link_type", None) in NEIGHBOR_PROTOCOLS:
        return "switch"

    return "endpoint"
