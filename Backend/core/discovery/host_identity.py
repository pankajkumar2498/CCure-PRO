"""
core/discovery/host_identity.py
────────────────────────────────────────────────────────────────────────────
One declared place that decides what a host is called.

Six probes could write ``result["hostname"]`` — the NBNS discovery technique,
PTR, NetBIOS and SNMP enrichment, the OT model probe and the L2 sniffer — and
each guarded its write with "only if nothing is there yet". So the winner was
decided by *execution order* rather than by authority, and that order is spread
across three files. Two consequences, both observed:

  * Reading the code did not tell you which source wins. NBNS runs as a
    discovery *technique*, before enrichment, so on a host answering NetBIOS
    the NetBIOS name won and PTR never overwrote it — the opposite of what the
    probe list in ``enrich_host`` suggests.
  * ``hostname`` held whatever answered first, so it was a FQDN on one host
    ("ccurepro.cdacb.in"), a NetBIOS short name on another ("TEST-PC") and a
    machine name on a third. A consumer could not know which it had.

What a name *is* settles the ordering. ``hostname`` answers "what does this
machine call itself"; ``fqdn`` / ``dns_name`` answer "what does DNS call this
address". They are different questions with different answers, and a scanner
that reports only one of them has thrown away a fact somebody needs — a stale
PTR against a renamed host is exactly the discrepancy an operator wants to see,
not have resolved for them.

So every probe records its own typed field and nothing writes ``hostname``
directly. ``resolve_identity`` is the only writer, it runs after all probing,
and it is idempotent — re-running it on an enriched result changes nothing.
"""

from __future__ import annotations

import logging
import socket
from typing import Optional

log = logging.getLogger("ccure.discovery.identity")

# Values that mean "nothing was established". They exist because several
# probes historically wrote a placeholder rather than leaving the key absent.
PLACEHOLDERS = {"", "unknown", "n/a", "none", "null", "-", "—"}

# The mDNS scope suffix. "PankajM-HPNew.local" is the machine's own name
# wearing a link-local suffix; the name is the part in front of it.
MDNS_SUFFIX = ".local"

# A reverse-lookup string is never a name. Kept here as well as in the mDNS
# probe because this module is the last gate before the value is published.
REVERSE_LOOKUP_SUFFIXES = (".in-addr.arpa", ".ip6.arpa")


# ─────────────────────────────────────────────────────────────────────────────
# The declared precedence
# ─────────────────────────────────────────────────────────────────────────────
#
# Most authoritative first. The ordering principle is *how directly the answer
# came from the machine itself*:
#
#   credentialed   an authenticated session asked the OS its own name
#   snmp_sys_name  the agent's first-party statement of its identity
#   netbios        the host answered a name-service query about itself
#   mdns           the host advertised the name, minus its .local scope
#   lldp/cdp       the device announced itself to the switch fabric
#   ptr            *DNS* answered, about the address — not the host speaking
#   ot_model       a product name, not a hostname; last, and never over a name
#
# PTR sits low deliberately. It is an assertion by whoever administers the
# reverse zone, it is routinely stale after a host is renamed, and it describes
# an address rather than a machine. It is still a legitimate last resort: a
# host with no other name at all is better shown as its DNS name than as
# nothing. When it does win, ``hostname_source`` says so.
#
# An authenticated session is absent from this table on purpose. The
# credentialed path does not produce a discovery result for ranking here — it
# writes ``hostname`` directly and is ranked at *write* time by
# ``asset_syncer.SOURCE_PRIORITY``, where "credentialed" (40) already outranks
# every unauthenticated source. Listing a ``credentialed_hostname`` field
# nothing populates would be a slot that looks wired and is not.
HOSTNAME_PRECEDENCE: tuple[tuple[str, str], ...] = (
    ("snmp_sys_name", "snmp"),
    ("netbios_computer", "netbios"),
    ("mdns_name", "mdns"),
    ("lldp_hostname", "lldp"),
    ("ptr_hostname", "ptr"),
    ("ot_model", "ot_probe"),
)

# What may populate fqdn / dns_name, in order. Only DNS answers a DNS
# question: a NetBIOS or mDNS name is not a DNS name and does not resolve
# outside the segment that answered.
#
# ``ptr_hostname`` leads, and the ordering is load-bearing for more than
# correctness. This function *writes* ``dns_name`` and ``fqdn``, so consulting
# either of them before the PTR would make the second run read the first run's
# own output — which flipped ``fqdn_source`` from "ptr" to "dns" and broke
# idempotence. Reading the probe's field first keeps the result a function of
# the inputs alone, however many times it runs.
FQDN_PRECEDENCE: tuple[tuple[str, str], ...] = (
    ("ptr_hostname", "ptr"),
    ("dns_name", "dns"),
    ("fqdn", "dns"),
)


def _clean(value) -> Optional[str]:
    """Return a usable name, or None for a placeholder or non-string."""
    if value is None or isinstance(value, (dict, list, tuple, set, bool)):
        return None
    text = str(value).strip().rstrip(".")
    if not text or text.lower() in PLACEHOLDERS:
        return None
    if text.lower().endswith(REVERSE_LOOKUP_SUFFIXES):
        return None
    return text


def _machine_name(value: str, source: str) -> str:
    """
    Reduce a source's answer to the machine's own name.

    Only the mDNS suffix is stripped. A PTR's domain part is *not* removed:
    when PTR is the only source we have, the FQDN is the most informative
    thing we can show, and truncating it would discard the domain without
    making the name any more the machine's own.
    """
    if source == "mdns" and value.lower().endswith(MDNS_SUFFIX):
        return value[: -len(MDNS_SUFFIX)]
    return value


def resolve_identity(result: dict) -> dict:
    """
    Decide ``hostname``, ``fqdn`` and ``dns_name`` from the typed fields the
    probes recorded, and write them onto ``result``.

    Idempotent: it reads only the per-source fields, never the values it
    writes, so running it again after more probing simply re-decides with
    whatever is now known.

    Also sets ``hostname_source`` — without it a reader cannot tell a machine's
    own name from a DNS administrator's opinion of its address, which is the
    whole distinction this module exists to preserve.
    """
    for field, source in HOSTNAME_PRECEDENCE:
        value = _clean(result.get(field))
        if value:
            result["hostname"] = _machine_name(value, source)
            result["hostname_source"] = source
            break
    else:
        # Nothing named this host. Leave the key absent rather than writing a
        # placeholder: "we did not establish a name" and "its name is
        # 'Unknown'" are different claims, and only the first is true.
        result.pop("hostname", None)
        result.pop("hostname_source", None)

    for field, source in FQDN_PRECEDENCE:
        value = _clean(result.get(field))
        if value and "." in value:
            result["fqdn"] = value
            result["dns_name"] = value
            result["fqdn_source"] = source
            break

    return result


def forward_confirm(ip: str, name: str, timeout: float = 2.0) -> Optional[bool]:
    """
    Forward-confirmed reverse DNS.

    A PTR record is published by whoever administers the reverse zone and
    nothing in the reply proves it is current. Resolving the name it gave back
    to an address and checking the original IP is among the answers is the
    standard way to tell a maintained mapping from a stale one.

    Returns True when confirmed, False when the name resolves elsewhere, and
    **None when the question could not be asked** — no forward record, DNS
    unreachable, timeout. The third state is not a detail: reading a failed
    lookup as "not confirmed" would brand every host in a split-horizon or
    internal-only zone as suspect, which is most of an enterprise estate.

    The verdict is recorded and never used to discard the PTR. An unconfirmed
    name is still the only name DNS has for that address, and dropping it would
    lose real information to a check that is advisory by design.
    """
    if not name or not ip:
        return None

    original = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        try:
            _host, _aliases, addresses = socket.gethostbyname_ex(name)
        except (socket.herror, socket.gaierror, OSError):
            return None
        if not addresses:
            return None
        return ip in addresses
    finally:
        socket.setdefaulttimeout(original)
