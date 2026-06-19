"""
core/topology/engine.py
───────────────────────
Topology Correlation Engine.

Converts raw SNMP walk results (ARP, LLDP, CDP, FDB) from one or more
switch/router targets into a deduplicated set of NetworkLink records.

Key responsibilities:
  1. Walk all SNMP-capable targets discovered during the scan.
  2. For each walk result, create NetworkLink records correlating
     source ↔ target MACs/IPs.
  3. Resolve Asset IDs where possible by matching IPs/MACs to existing
     Asset records in the database.
  4. Detect the local gateway IP for subnet context.
  5. Persist all links to the database using UPSERT to avoid duplicates.

Design decisions:
  - Gateway resolution uses Scapy's `conf.route.route` with a fallback
    to a simple `.1` assumption for Windows environments where raw sockets
    may not be available.
  - Asset matching is done by IP first, then MAC fallback.
  - All DB writes happen in a single transaction for atomicity.
"""

import logging
from typing import Dict, List, Optional

from sqlalchemy.orm import Session
from sqlalchemy.dialects.postgresql import insert

from db.base import gen_network_link_id, utcnow
from db.models import Asset, Scan, Organization

log = logging.getLogger("ccure.topology.engine")


def _resolve_gateway_ip() -> Optional[str]:
    """
    Detect the default gateway IP using Scapy's routing table.
    Falls back gracefully on Windows / non-root environments.
    """
    try:
        from scapy.config import conf
        # conf.route.route("0.0.0.0") returns (iface, gateway_ip, src_ip)
        _, gw, _ = conf.route.route("0.0.0.0")
        if gw and gw != "0.0.0.0":
            return gw
    except Exception as exc:
        log.debug("Scapy gateway detection failed (expected on Windows): %s", exc)

    # Fallback: try psutil to find the default gateway
    try:
        import psutil
        gateways = psutil.net_if_addrs()
        # This is a best-effort fallback
    except Exception:
        pass

    return None


def _find_asset_by_ip(db: Session, org_id: str, ip: str) -> Optional[Asset]:
    """Find an asset by IP address within the organization."""
    if not ip:
        return None
    return (
        db.query(Asset)
        .filter(Asset.org_id == org_id, Asset.ip_address == ip)
        .first()
    )


def _find_asset_by_mac(db: Session, org_id: str, mac: str) -> Optional[Asset]:
    """Find an asset by MAC address within the organization."""
    if not mac:
        return None
    normalized = mac.lower().replace("-", ":")
    return (
        db.query(Asset)
        .filter(Asset.org_id == org_id, Asset.mac_address == normalized)
        .first()
    )


def run_topology_mapping(
    db: Session,
    scan_id: str,
    org_id: str,
    snmp_config: dict,
    target_ips: Optional[List[str]] = None,
) -> Dict:
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
        dict with keys: success, links_created, links_updated, errors.
    """
    from core.topology.client import SNMPCredentials, walk_target

    creds = SNMPCredentials.from_dict(snmp_config)
    log.info(
        "Starting topology mapping for scan=%s, org=%s, targets=%d, snmp_version=%s",
        scan_id, org_id, len(target_ips or []), creds.version,
    )

    # Resolve org slug for ID generation
    org = db.query(Organization).filter(Organization.id == org_id).first()
    org_slug = org.slug if org else org_id

    # If no targets specified, use all active hosts from the scan
    if not target_ips:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan and scan.target_hosts:
            target_ips = scan.target_hosts
        else:
            log.warning("No target IPs for topology mapping on scan %s", scan_id)
            return {"success": True, "links_created": 0, "links_updated": 0, "errors": ["No targets"]}

    gateway_ip = _resolve_gateway_ip()
    log.info("Detected gateway IP: %s", gateway_ip)

    all_links = []
    all_errors = []

    # Walk each target
    for ip in target_ips:
        try:
            result = walk_target(ip, creds)
            all_errors.extend(result.errors)

            if not result.has_data:
                log.info("No SNMP data from %s (might not be SNMP-capable)", ip)
                continue

            # Dynamically classify target device based on sysServices
            target_device_asset = _find_asset_by_ip(db, org_id, ip)
            if target_device_asset and result.sys_services > 0:
                if result.sys_services & 4:
                    target_device_asset.device_category = "router"
                elif result.sys_services & 2:
                    target_device_asset.device_category = "switch"

            # Source MAC: use the router/switch's system identity
            # For ARP entries, the source is the switch/router, target is the ARP entry
            source_mac = _get_source_mac_for_target(db, org_id, ip)
            if not source_mac:
                # Use a placeholder based on the IP for consistent link IDs
                source_mac = f"sw:{ip.replace('.', ':')}"

            # Helper: resolve interface details from port index
            def _iface_details(port_index_str: str) -> dict:
                """Look up enriched interface info for a port index."""
                iface = result.resolve_interface(port_index_str) if port_index_str else None
                if iface:
                    return {
                        "port_desc": iface.display_name,
                        "speed_bps": iface.speed_bps or None,
                        "vlan_id": iface.vlan_id if iface.vlan_id and iface.vlan_id not in (0, 4095) else None,
                    }
                return {"port_desc": None, "speed_bps": None, "vlan_id": None}

            # Process ARP table entries
            for arp in result.arp_table:
                if _is_broadcast_or_multicast(arp.mac_address):
                    continue
                link_id = gen_network_link_id(org_slug, source_mac, arp.mac_address)
                iface = _iface_details(arp.interface_index)
                all_links.append({
                    "id": link_id,
                    "org_id": org_id,
                    "scan_id": scan_id,
                    "source_mac": source_mac,
                    "source_port": f"if{arp.interface_index}" if arp.interface_index else None,
                    "source_port_desc": iface["port_desc"],
                    "target_mac": arp.mac_address,
                    "target_ip": arp.ip_address,
                    "vlan_id": iface["vlan_id"],
                    "speed_bps": iface["speed_bps"],
                    "link_type": "arp",
                })

            # Process LLDP neighbors
            for neighbor in result.lldp_neighbors:
                if not neighbor.chassis_id:
                    continue
                link_id = gen_network_link_id(org_slug, source_mac, neighbor.chassis_id)
                iface = _iface_details(neighbor.local_port_index)
                all_links.append({
                    "id": link_id,
                    "org_id": org_id,
                    "scan_id": scan_id,
                    "source_mac": source_mac,
                    "source_port": f"lldp:{neighbor.local_port_index}",
                    "source_port_desc": iface["port_desc"],
                    "target_mac": neighbor.chassis_id,
                    "target_port": neighbor.port_id or neighbor.port_desc,
                    "target_port_desc": neighbor.port_desc or neighbor.port_id,
                    "vlan_id": iface["vlan_id"],
                    "speed_bps": iface["speed_bps"],
                    "link_type": "lldp",
                    "target_hostname": neighbor.system_name,
                })

            # Process CDP neighbors
            for neighbor in result.cdp_neighbors:
                target_mac = neighbor.device_id or f"cdp:{neighbor.ip_address}"
                link_id = gen_network_link_id(org_slug, source_mac, target_mac)
                iface = _iface_details(neighbor.local_port_index)
                all_links.append({
                    "id": link_id,
                    "org_id": org_id,
                    "scan_id": scan_id,
                    "source_mac": source_mac,
                    "source_port": f"cdp:{neighbor.local_port_index}",
                    "source_port_desc": iface["port_desc"],
                    "target_mac": target_mac,
                    "target_ip": neighbor.ip_address,
                    "target_port": neighbor.device_port,
                    "target_port_desc": neighbor.device_port,
                    "vlan_id": iface["vlan_id"],
                    "speed_bps": iface["speed_bps"],
                    "link_type": "cdp",
                    "target_hostname": neighbor.device_id,
                })

            # Process FDB entries (direct MAC-to-port)
            for fdb in result.fdb_table:
                if _is_broadcast_or_multicast(fdb.mac_address):
                    continue
                link_id = gen_network_link_id(org_slug, source_mac, fdb.mac_address)
                iface = _iface_details(fdb.port_index)
                fdb_vlan = iface["vlan_id"] or (fdb.vlan_id if fdb.vlan_id and fdb.vlan_id not in (0, 4095) else None)
                all_links.append({
                    "id": link_id,
                    "org_id": org_id,
                    "scan_id": scan_id,
                    "source_mac": source_mac,
                    "source_port": f"port:{fdb.port_index}" if fdb.port_index else None,
                    "source_port_desc": iface["port_desc"],
                    "target_mac": fdb.mac_address,
                    "vlan_id": fdb_vlan,
                    "speed_bps": iface["speed_bps"],
                    "link_type": "fdb",
                })

        except Exception as exc:
            err_msg = f"Walk failed for {ip}: {exc}"
            all_errors.append(err_msg)
            log.exception("Topology walk failed for %s", ip)

    # Deduplicate by link ID (merge to preserve target_ip, port descriptions, VLAN, speed)
    unique_links: Dict[str, dict] = {}
    for link in all_links:
        link_id = link["id"]
        if link_id in unique_links:
            existing = unique_links[link_id]

            # Preserve target_ip if either has it
            target_ip = link.get("target_ip") or existing.get("target_ip")
            if target_ip:
                link["target_ip"] = target_ip

            # Preserve enriched fields from whichever entry has them
            for field in ("source_port", "target_port", "source_port_desc", "target_port_desc", "vlan_id", "speed_bps"):
                if not link.get(field) and existing.get(field):
                    link[field] = existing[field]

        unique_links[link_id] = link

    log.info(
        "Topology mapping produced %d unique links from %d raw entries",
        len(unique_links), len(all_links),
    )

    # Persist to database
    created = 0
    updated = 0
    from db.models import NetworkLink

    # Pre-fetch existing link IDs for this org to accurately count created vs updated
    existing_ids = {
        row[0] for row in db.query(NetworkLink.id).filter(
            NetworkLink.org_id == org_id,
            NetworkLink.id.in_(list(unique_links.keys()))
        ).all()
    }

    for link_data in unique_links.values():
        # Try to resolve asset IDs
        source_asset = _find_asset_by_mac(db, org_id, link_data["source_mac"])
        target_asset = (
            _find_asset_by_ip(db, org_id, link_data.get("target_ip") or "")
            or _find_asset_by_mac(db, org_id, link_data["target_mac"])
        )

        # Sync/Create placeholder assets for LLDP/CDP neighbors
        if link_data["link_type"] in ("lldp", "cdp"):
            # Classify dynamically based on hostname heuristics
            device_category = "switch"
            tgt_hostname = link_data.get("target_hostname") or ""
            if any(r in tgt_hostname.lower() for r in ("router", "rt", "gw", "firewall")):
                device_category = "router"

            if not target_asset:
                target_mac = link_data["target_mac"]
                clean_mac = None
                if target_mac and not target_mac.startswith("cdp:") and not target_mac.startswith("sw:"):
                    clean_mac = target_mac.lower().replace("-", ":")

                target_ip = link_data.get("target_ip")
                if target_ip == "0.0.0.0":
                    target_ip = None

                # Generate deterministic asset ID using gen_asset_id
                from db.base import gen_asset_id
                placeholder_id = gen_asset_id(org_id, target_ip or target_mac)

                target_asset = Asset(
                    id=placeholder_id,
                    org_id=org_id,
                    ip_address=target_ip,
                    mac_address=clean_mac,
                    hostname=tgt_hostname or None,
                    device_category=device_category,
                    discovery_method="topology",
                    last_seen_at=utcnow(),
                    created_at=utcnow(),
                    updated_at=utcnow(),
                )
                db.add(target_asset)
                db.flush()  # Flush so it's available for FK references
            else:
                # Update existing asset classification if missing or generic
                if not target_asset.device_category or target_asset.device_category in ("host", "generic", "unknown"):
                    target_asset.device_category = device_category
                if not target_asset.hostname and tgt_hostname:
                    target_asset.hostname = tgt_hostname

        # Sync VLAN to matched asset if valid (exclude 0 and 4095 sentinels)
        resolved_vlan = link_data.get("vlan_id")
        if resolved_vlan and resolved_vlan not in (0, 4095) and target_asset and not target_asset.vlan_id:
            target_asset.vlan_id = resolved_vlan

        values = {
            **link_data,
            "source_asset_id": source_asset.id if source_asset else None,
            "target_asset_id": target_asset.id if target_asset else None,
            "created_at": utcnow(),
        }

        stmt = insert(NetworkLink).values(**values)
        stmt = stmt.on_conflict_do_update(
            index_elements=["id"],
            set_={
                "scan_id": values["scan_id"],
                "source_port": values.get("source_port"),
                "source_port_desc": values.get("source_port_desc"),
                "target_port": values.get("target_port"),
                "target_port_desc": values.get("target_port_desc"),
                "target_ip": values.get("target_ip"),
                "source_asset_id": values.get("source_asset_id"),
                "target_asset_id": values.get("target_asset_id"),
                "vlan_id": values.get("vlan_id"),
                "speed_bps": values.get("speed_bps"),
                "link_type": values["link_type"],
                "created_at": utcnow(),
            },
        )

        result = db.execute(stmt)
        if result.rowcount:
            if link_data["id"] in existing_ids:
                updated += 1
            else:
                created += 1

    db.commit()

    log.info(
        "Topology mapping complete for scan=%s: %d created, %d updated, %d errors",
        scan_id, created, updated, len(all_errors),
    )

    return {
        "success": True,
        "links_created": created,
        "links_updated": updated,
        "total_links": len(unique_links),
        "errors": all_errors,
        "gateway_ip": gateway_ip,
    }


def _get_source_mac_for_target(db: Session, org_id: str, ip: str) -> Optional[str]:
    """
    Try to find the MAC address of a switch/router target from the Asset registry.
    """
    asset = _find_asset_by_ip(db, org_id, ip)
    if asset and asset.mac_address:
        return asset.mac_address.lower()
    return None


def _is_broadcast_or_multicast(mac: str) -> bool:
    """Filter out broadcast and multicast MAC addresses."""
    if not mac:
        return True
    normalized = mac.lower().replace("-", ":").replace(".", "")
    # Remove separators for comparison
    compact = normalized.replace(":", "")
    if len(compact) != 12:
        return True
    # Broadcast
    if compact == "ffffffffffff" or compact == "000000000000":
        return True
    # Multicast: first byte has LSB set (01:xx:xx:xx:xx:xx)
    try:
        first_byte = int(compact[:2], 16)
        if first_byte & 0x01:
            return True
    except ValueError:
        return True
    return False


def get_topology_graph(db: Session, org_id: str, scan_id: Optional[str] = None, subnet_mask: int = 24) -> Dict:
    """
    Build a vis-network compatible clustered graph from stored NetworkLink records.
    Groups host nodes under subnet clusters (default /24) to avoid dense physics-blob display.
    Places IP-less MAC-only hosts under a virtual 'Unknown / MAC-only' cluster.
    """
    import ipaddress
    import hashlib
    from db.models import NetworkLink

    query = db.query(NetworkLink).filter(NetworkLink.org_id == org_id)
    if scan_id:
        query = query.filter(NetworkLink.scan_id == scan_id)

    links = query.all()

    infra_nodes = {}   # source switch/router/gateway nodes
    subnet_map = {}    # "10.180.4.0/24" -> {"hosts": set(tgt_macs), "link_type": "arp" | "fdb", etc.}
    host_nodes = {}    # target_mac -> node dict
    host_link_meta = {}  # target_mac -> latest link evidence for drill-down panels
    edges = []

    mac_only_hosts = 0
    asset_matches = 0

    try:
        from core.oui_lookup import lookup_vendor
    except Exception:
        lookup_vendor = None

    def _vendor_for(asset, mac: str) -> str:
        if asset:
            vendor = getattr(asset, "vendor", None) or getattr(asset, "manufacturer", None)
            if vendor:
                return str(vendor)
        if lookup_vendor:
            try:
                return lookup_vendor(mac) or ""
            except Exception:
                return ""
        return ""

    for link in links:
        # Determine source (infra) node
        src = link.source_mac
        if src not in infra_nodes:
            src_asset = link.source_asset
            
            # Label resolution: prefer hostname, then ip_address, then formatted MAC/placeholder
            label = ""
            if src_asset:
                label = src_asset.hostname or src_asset.ip_address
            if not label:
                if src.startswith("sw:"):
                    # e.g., sw:10:180:4:1 -> 10.180.4.1
                    label = src.replace("sw:", "").replace(":", ".")
                else:
                    label = src

            group = "switch" if src.startswith("sw:") else _classify_node_group(link, src_asset)
            infra_nodes[src] = {
                "id": src,
                "label": label,
                "group": group,
                "tier": "infra",
                "ip": src_asset.ip_address if src_asset else (label if not src.startswith("sw:") and "." in label else ""),
                "mac": src,
                "asset_id": src_asset.id if src_asset else None,
            }

        # Target classification
        tgt = link.target_mac
        tgt_ip = link.target_ip or ""
        tgt_asset = link.target_asset
        
        # If target has a defined asset, we can check if it is infrastructure
        is_target_infra = False
        tgt_group = "host"
        if tgt_asset:
            tgt_group = _classify_node_group(link, tgt_asset)
            if tgt_group in ("switch", "router"):
                is_target_infra = True
        elif link.link_type in ("lldp", "cdp") or tgt.startswith("sw:"):
            tgt_group = "switch"
            is_target_infra = True

        if is_target_infra:
            if tgt not in infra_nodes:
                label = ""
                if tgt_asset:
                    label = tgt_asset.hostname or tgt_asset.ip_address
                if not label:
                    label = tgt_ip or (tgt.replace("sw:", "").replace(":", ".") if tgt.startswith("sw:") else tgt)
                infra_nodes[tgt] = {
                    "id": tgt,
                    "label": label,
                    "group": tgt_group,
                    "tier": "infra",
                    "ip": tgt_ip or (tgt_asset.ip_address if tgt_asset else ""),
                    "mac": tgt,
                    "asset_id": tgt_asset.id if tgt_asset else None,
                }
            
            # Infra-to-infra edge (LLDP/CDP/etc.) with deterministic ID
            edge_key = f"edge:{src}:{tgt}"
            edge_id = hashlib.md5(edge_key.encode("utf-8")).hexdigest()
            edges.append({
                "id": edge_id,
                "from": src,
                "to": tgt,
                "label": link.link_type or "physical",
                "link_type": link.link_type,
                "source_port": link.source_port or "",
                "source_port_desc": link.source_port_desc or "",
                "target_port": link.target_port or "",
                "target_port_desc": link.target_port_desc or "",
                "vlan_id": link.vlan_id,
                "speed_bps": link.speed_bps,
                "tier": "infra"
            })
            continue

        # Extract subnet for standard host
        subnet_str = ""
        if tgt_ip:
            try:
                # Group into configured subnets
                net = ipaddress.ip_network(f"{tgt_ip}/{subnet_mask}", strict=False)
                subnet_str = str(net)
            except ValueError:
                pass
        else:
            subnet_str = "MAC-Only / FDB"
            mac_only_hosts += 1

        if tgt_asset:
            asset_matches += 1

        vendor = _vendor_for(tgt_asset, tgt)

        host_link_meta[tgt] = {
            "source_mac": src,
            "source_port": link.source_port or "",
            "source_port_desc": link.source_port_desc or "",
            "target_port": link.target_port or "",
            "target_port_desc": link.target_port_desc or "",
            "link_type": link.link_type or "unknown",
            "vlan_id": link.vlan_id,
            "speed_bps": link.speed_bps,
        }

        if tgt not in host_nodes:
            label = ""
            if tgt_asset:
                label = tgt_asset.hostname or tgt_ip or tgt
            else:
                label = tgt_ip or tgt

            host_nodes[tgt] = {
                "id": tgt,
                "label": label,
                "group": "host",
                "tier": "host",
                "ip": tgt_ip,
                "mac": tgt,
                "vendor": vendor,
                "subnet": subnet_str,
                "asset_id": tgt_asset.id if tgt_asset else None,
                "asset_match_status": "matched" if tgt_asset else "unmatched",
                "source_mac": src,
                "source_port": link.source_port or "",
                "source_port_desc": link.source_port_desc or "",
                "target_port": link.target_port or "",
                "target_port_desc": link.target_port_desc or "",
                "link_type": link.link_type or "unknown",
                "vlan_id": link.vlan_id,
                "speed_bps": link.speed_bps,
            }

        # Track host inside its subnet
        if subnet_str:
            if subnet_str not in subnet_map:
                subnet_map[subnet_str] = {
                    "hosts": set(),
                    "ip_hosts": set(),
                    "link_types": {},  # type -> count
                    "sources": {},     # src_mac -> {source_ports: set(), link_types: set()}
                    "asset_matches": set(),
                }
            subnet_map[subnet_str]["hosts"].add(tgt)
            if tgt_ip:
                subnet_map[subnet_str]["ip_hosts"].add(tgt)
            if tgt_asset:
                subnet_map[subnet_str]["asset_matches"].add(tgt)
            
            ltype = link.link_type or "arp"
            subnet_map[subnet_str]["link_types"][ltype] = subnet_map[subnet_str]["link_types"].get(ltype, 0) + 1

            if src not in subnet_map[subnet_str]["sources"]:
                subnet_map[subnet_str]["sources"][src] = {
                    "ports": set(),
                    "link_types": set(),
                    "count": 0
                }
            subnet_map[subnet_str]["sources"][src]["count"] += 1
            subnet_map[subnet_str]["sources"][src]["link_types"].add(ltype)
            if link.source_port:
                subnet_map[subnet_str]["sources"][src]["ports"].add(link.source_port)

    # Build subnet nodes and edges connecting infra to subnets
    subnet_nodes = []
    subnet_edges = []
    for subnet_str, info in subnet_map.items():
        count = len(info["hosts"])
        snode_id = f"subnet:{subnet_str}"
        ip_resolved = len(info["ip_hosts"])
        mac_only_count = count - ip_resolved
        has_arp = bool(info["link_types"].get("arp"))
        has_fdb = bool(info["link_types"].get("fdb"))
        has_lldp = bool(info["link_types"].get("lldp"))
        has_cdp = bool(info["link_types"].get("cdp"))
        source_count = len(info["sources"])
        is_mac_only_cluster = subnet_str == "MAC-Only / FDB"
        recommended_actions = []
        if mac_only_count:
            recommended_actions.extend([
                "Run ARP-enabled scan",
                "Add gateway/router SNMP target",
                "Correlate with asset inventory",
            ])
        if not has_arp:
            recommended_actions.append("Enable ARP table collection")
        if not (has_lldp or has_cdp):
            recommended_actions.append("Enable LLDP/CDP on infrastructure devices")

        subnet_nodes.append({
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
                "source_count": source_count,
                "has_arp": has_arp,
                "has_fdb": has_fdb,
                "has_lldp": has_lldp,
                "has_cdp": has_cdp,
            },
            "recommended_actions": recommended_actions,
        })
        
        # Link every infra source that knows about this subnet's hosts to the subnet node
        for src_id, src_info in info["sources"].items():
            edge_key = f"edge:{src_id}:{snode_id}"
            edge_id = hashlib.md5(edge_key.encode("utf-8")).hexdigest()
            
            # Format summarized link counts: e.g., "arp: 12, fdb: 1"
            ltype_summary = ", ".join(f"{k}: {v}" for k, v in info["link_types"].items())
            ports_summary = ", ".join(sorted(list(src_info["ports"]))) if src_info["ports"] else "unknown"

            subnet_edges.append({
                "id": edge_id,
                "from": src_id,
                "to": snode_id,
                "link_type": list(src_info["link_types"])[0] if src_info["link_types"] else "arp",
                "host_count": count,
                "label": f"{src_info['count']} links" if src_info["count"] > 1 else "",
                "source_port": ports_summary,
                "target_port": "",
                "tier": "subnet",
                "link_details": {
                    "type_counts": info["link_types"],
                    "summary": ltype_summary,
                    "ports": list(src_info["ports"])
                }
            })

    all_nodes = list(infra_nodes.values()) + subnet_nodes + list(host_nodes.values())
    all_edges = edges + subnet_edges

    log.info(
        "Topology map generated: %d links read, %d infra nodes, %d subnets, %d hosts (%d MAC-only)",
        len(links), len(infra_nodes), len(subnet_map), len(host_nodes), mac_only_hosts
    )

    return {
        "graph_version": 2,
        "nodes": all_nodes,
        "edges": all_edges,
        "subnets": sorted(list(subnet_map.keys())),
        "stats": {
            "infrastructure": len(infra_nodes),
            "subnets": len(subnet_map),
            "hosts": len(host_nodes),
            "mac_only": mac_only_hosts,
        }
    }


def _classify_node_group(link, asset: Optional[Asset]) -> str:
    """Classify a node into a visual group for the frontend graph."""
    if asset:
        cat = (asset.device_category or "").lower()
        if "router" in cat or "gateway" in cat or "firewall" in cat:
            return "router"
        if "switch" in cat:
            return "switch"
        if "server" in cat:
            return "server"
        if "printer" in cat:
            return "printer"
        if "iot" in cat or "camera" in cat:
            return "iot"
        
        # Try hostname/IP heuristics
        host = (asset.hostname or "").lower()
        if "switch" in host or "sw" in host:
            return "switch"
        if "router" in host or "rt" in host or "gw" in host:
            return "router"

    # Infer from link type
    if link.link_type in ("lldp", "cdp"):
        return "switch"
        
    return "host"
