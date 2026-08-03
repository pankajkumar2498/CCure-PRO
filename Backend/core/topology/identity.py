"""
core/topology/identity.py
─────────────────────────
Endpoint identity primitives for topology correlation.

Everything the topology pipeline learns about a device arrives as a loosely
typed string: an ARP physical address, an LLDP chassis ID, a CDP device ID, an
FDB entry. Only some of those are MAC addresses. LLDP chassis IDs carry a
subtype — subtype 4 is a MAC, but subtypes 5 (network address) and 7 (locally
assigned) are hostnames or arbitrary text — and CDP device IDs are hostnames
almost by definition.

`Asset.mac_address` is a PostgreSQL ``MACADDR`` column. Handing it anything that
is not a MAC does not return zero rows; it raises ``InvalidTextRepresentation``
and poisons the surrounding transaction. Identity normalisation therefore has to
happen once, at the boundary, rather than being re-derived (and re-forgotten) at
each call site.

`Endpoint` is that boundary. It classifies a raw identifier into exactly one of
three kinds and exposes a stable `key` used for link identity and graph node
identity:

  mac       — a real 48-bit unicast address; safe to query against MACADDR
  ip        — no MAC available, but an IP is known (``ip:10.1.1.1``)
  name      — neither; a chassis/device name we can only match on hostname
              (``name:core-sw-01``)

The ``sw:`` / ``cdp:`` placeholder prefixes used by earlier revisions are still
parsed so that links recorded before this module existed keep resolving.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

#: Locally administered / broadcast / null addresses that carry no identity.
_NULL_MAC = "00:00:00:00:00:00"
_BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

_HEX12 = re.compile(r"^[0-9a-f]{12}$")

#: Legacy placeholder prefixes. ``sw:10:1:1:1`` encoded an IP with dots replaced
#: by colons; ``cdp:10.1.1.1`` kept the dots.
_LEGACY_IP_PREFIXES = ("sw:", "cdp:")


def normalize_mac(value: str | None) -> str | None:
    """
    Return ``value`` as a canonical lower-case colon-delimited MAC, or None.

    Accepts the formats SNMP agents and databases actually emit: raw hex,
    colon-, hyphen- and dot-delimited (Cisco ``0011.2233.4455``) forms. Anything
    that is not exactly 48 bits of hex is not a MAC and returns None — callers
    use that as the signal to keep the value out of MACADDR comparisons.
    """
    if not value:
        return None
    compact = re.sub(r"[^0-9a-fA-F]", "", str(value)).lower()
    if not _HEX12.match(compact):
        return None
    return ":".join(compact[i : i + 2] for i in range(0, 12, 2))


def is_usable_mac(mac: str | None) -> bool:
    """
    True when ``mac`` identifies a specific interface.

    Broadcast, all-zero and group (multicast) addresses are excluded: the
    multicast bit is the low bit of the first octet, so ``01:00:5e:…`` IPv4
    multicast, ``33:33:…`` IPv6 multicast and STP/LLDP reserved addresses are all
    rejected by the same test.
    """
    normalized = normalize_mac(mac)
    if not normalized:
        return False
    if normalized in (_NULL_MAC, _BROADCAST_MAC):
        return False
    first_octet = int(normalized[:2], 16)
    return not (first_octet & 0x01)


def is_valid_ip(value: str | None) -> bool:
    """True when ``value`` is a routable-looking IP literal (not 0.0.0.0)."""
    if not value:
        return False
    try:
        addr = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return False
    return not addr.is_unspecified


def _decode_legacy_placeholder(value: str) -> str | None:
    """Recover the IP from a legacy ``sw:``/``cdp:`` placeholder identifier."""
    for prefix in _LEGACY_IP_PREFIXES:
        if value.startswith(prefix):
            candidate = value[len(prefix) :].replace(":", ".")
            return candidate if is_valid_ip(candidate) else None
    return None


@dataclass(frozen=True)
class Endpoint:
    """
    One end of a discovered link, reduced to a single stable identity.

    ``key`` is what the rest of the pipeline joins on — link IDs, graph node IDs
    and dedup all derive from it — so it must be deterministic for a given
    device regardless of which neighbour reported it.
    """

    kind: str  # "mac" | "ip" | "name"
    key: str
    mac: str | None = None
    ip: str | None = None
    name: str | None = None

    @property
    def is_mac_identified(self) -> bool:
        return self.kind == "mac"

    @property
    def display(self) -> str:
        """Best human-readable label, most specific first."""
        return self.name or self.ip or self.mac or self.key


def make_endpoint(
    raw_id: str | None = None,
    ip: str | None = None,
    name: str | None = None,
) -> Endpoint | None:
    """
    Build an `Endpoint` from whatever a walk produced for one side of a link.

    ``raw_id`` is the primary identifier as reported (ARP physical address, LLDP
    chassis ID, CDP device ID, FDB MAC, or a legacy placeholder). ``ip`` and
    ``name`` are corroborating attributes.

    Returns None when nothing usable was supplied — a link with an
    unidentifiable end is not a link, and silently inventing an identity for it
    is how phantom nodes get into a topology map.
    """
    raw = (str(raw_id).strip() if raw_id else "") or ""
    resolved_ip = str(ip).strip() if ip else None
    resolved_name = str(name).strip() if name else None

    mac = normalize_mac(raw)
    if mac and not is_usable_mac(mac):
        # Group/broadcast address: real frames, but not a device identity.
        return None

    if not mac and raw:
        legacy_ip = _decode_legacy_placeholder(raw)
        if legacy_ip:
            resolved_ip = resolved_ip or legacy_ip
        elif not resolved_name:
            # A non-MAC chassis/device ID is a name, not an address.
            resolved_name = raw

    if not is_valid_ip(resolved_ip):
        resolved_ip = None

    if mac:
        return Endpoint("mac", mac, mac=mac, ip=resolved_ip, name=resolved_name)
    if resolved_ip:
        return Endpoint(
            "ip", f"ip:{resolved_ip}", mac=None, ip=resolved_ip, name=resolved_name
        )
    if resolved_name:
        key = f"name:{resolved_name.lower()}"
        return Endpoint("name", key, mac=None, ip=None, name=resolved_name)
    return None


def canonical_pair(a: Endpoint, b: Endpoint) -> tuple[Endpoint, Endpoint, bool]:
    """
    Order two endpoints deterministically.

    A link is undirected: switch A reporting a neighbour B and switch B
    reporting A are the same wire and must collapse to one record. Sorting the
    endpoints by key gives both reporters the same answer, and the returned
    ``swapped`` flag tells the caller whether its per-side attributes (local
    port, port description) need to be swapped to match.
    """
    if a.key <= b.key:
        return a, b, False
    return b, a, True
