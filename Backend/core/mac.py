"""
core/mac.py
-----------
What counts as a MAC address.

This module holds the *predicate* — is this string 48 bits of hexadecimal? —
and nothing about what any particular caller does with the answer. That split
is the point. Before it there were five ``_normalize_mac`` functions in this
repository, each answering the same question slightly differently, and two of
them answering it by shape rather than by content:

* ``core/oui_lookup.py`` accepted anything six characters or longer, so
  ``"Unknown"`` became a path segment in a request to ``api.macvendors.com``;
* ``core/tasks.py`` accepted anything with six colon-separated groups, so
  ``"zz:zz:zz:zz:zz:zz"`` reached ``Asset.mac_address`` — a PostgreSQL
  ``MACADDR`` column, which raises ``DataError`` and aborts the asset sync.

The callers genuinely disagree about *policy* and that disagreement is
legitimate, so it is deliberately not unified here:

* they return three different things on failure — ``None``, ``""``, and in the
  orchestrator's case the input unchanged;
* they want three different output formats — compact hex for a cache key and a
  URL, lower-case colon for a ``MACADDR`` column, upper-case colon for AMT
  reconciliation, which compares both sides through the same function;
* they treat non-unique addresses oppositely. The collectors must erase
  ``00:00:00:00:00:00``; ``core.oui_lookup`` must keep it, because ``00:00:00``
  is a real assignment (Xerox) and is present in the shipped ``manuf.txt``.

Two normalizers stay outside this module on purpose. ``core.utils.normalize_mac``
returns the upper-case form and is applied to *both* sides of every comparison
it takes part in, so its casing is self-consistent and changing it would risk
AMT matching for no gain. ``core.topology.identity.normalize_mac`` answers a
different question — what may be compared against a ``MACADDR`` column — and
strips every non-hex character to do it, which is the right trade there and the
wrong one here (see ``mac_hex``).
"""

import re

#: Separators that sit between the octets of the forms this codebase receives:
#: colons (Scapy, Nmap), hyphens (Windows ``getmac``), dots (Cisco's
#: ``001a.2b3c.4d5e``) and stray whitespace.
#:
#: Removing exactly these — rather than "every character that is not a hex
#: digit", which is what ``core.topology.identity.normalize_mac`` does — is what
#: makes ``mac_hex`` a rejection instead of a silent salvage. Stripping all
#: non-hex characters turns ``00:1a:2b:3c:4d:5ezz`` into a well-formed address
#: and would hand it onward as though it had been scanned that way. Here the
#: ``z`` survives, fails the hex test, and the value is refused.
_SEPARATORS = re.compile(r"[:.\-\s]")

#: What remains once the separators are gone must be hexadecimal and nothing
#: else. ``\A``/``\Z`` rather than ``^``/``$``: ``$`` also matches before a
#: trailing newline, so a value ending in one would pass a ``$`` anchor.
_HEX_ONLY = re.compile(r"\A[0-9a-f]+\Z")

#: One octet written with or without its leading zero. PostgreSQL accepts
#: ``0:1a:2b:3c:4d:5e`` and normalizes it to ``00:1a:2b:3c:4d:5e``, and macOS
#: ``ifconfig`` emits exactly that unpadded form, so it is a real dialect rather
#: than a typo to be rejected.
_OCTET = re.compile(r"\A[0-9a-f]{1,2}\Z")

#: Hex digits in an EUI-48 — an ordinary MAC address.
EUI48_HEX_DIGITS = 12

_NON_UNIQUE = frozenset({"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"})


def mac_hex(value, lengths=(EUI48_HEX_DIGITS,)) -> str | None:
    """
    Return ``value`` as compact lower-case hex, or None if it is not an address.

    ``lengths`` is the set of accepted digit counts after separators are
    removed. It defaults to 12 (EUI-48) because that is what every caller but
    one wants; ``core.oui_lookup`` passes ``{6, 12, 16}`` because it is indexed
    on 24-bit OUI prefixes and its documented API accepts one.

    Length is checked before content so that a long non-address is refused
    without scanning all of it.
    """
    if not value:
        return None

    compact = _SEPARATORS.sub("", str(value).lower())
    if len(compact) not in lengths:
        return None
    if not _HEX_ONLY.match(compact):
        return None
    return compact


def mac_colon(value) -> str | None:
    """
    Return ``value`` as canonical ``aa:bb:cc:dd:ee:ff``, or None.

    Accepts everything ``mac_hex`` does, plus the unpadded six-group form, and
    pads it. Padding here rather than passing the text through means the
    returned value is the same string whichever dialect it arrived in — the
    caller that previously passed unpadded text along got a value that only
    looked canonical once PostgreSQL had rewritten it on the way into the
    column, and looked different to anything comparing it in Python first.
    """
    compact = mac_hex(value)

    if compact is None:
        groups = str(value or "").strip().lower().replace("-", ":").split(":")
        if len(groups) != 6 or not all(_OCTET.match(g) for g in groups):
            return None
        compact = "".join(g.zfill(2) for g in groups)

    return ":".join(compact[i : i + 2] for i in range(0, EUI48_HEX_DIGITS, 2))


def collector_mac(value) -> str:
    """
    Canonical ``aa:bb:cc:dd:ee:ff`` for a credentialed collector, or ``""``.

    This is the single copy of a function that existed character-for-character
    twice, in ``engines/credentialed/linux_collector.py`` and
    ``windows_collector.py``. It is reproduced here verbatim rather than rebuilt
    on ``mac_colon`` so that deduplicating it cannot change what either
    collector accepts.

    It is deliberately stricter than ``mac_colon``: it takes neither the Cisco
    dotted form nor unpadded octets, because both collectors read from sources
    that emit full colon- or hyphen-separated octets (``ip -j addr`` on Linux,
    ``Get-NetAdapter`` on Windows). Widening it would be safe as far as anyone
    can tell from those two sources, which is not the same as proven, so it is
    left for a change that can validate it on its own.

    Returns ``""`` — not None — because that is what both call sites branch on.
    """
    text = str(value or "").strip().lower().replace("-", ":")
    if not text or text in _NON_UNIQUE:
        return ""
    if re.fullmatch(r"[0-9a-f]{12}", text):
        text = ":".join(text[i : i + 2] for i in range(0, 12, 2))
    return text if re.fullmatch(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", text) else ""
