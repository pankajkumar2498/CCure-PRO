"""
scripts/measure_network_check_coverage.py
─────────────────────────────────────────────────────────────────────────────
Measures GAP-06 coverage — unauthenticated network vulnerability checks.

    python -m scripts.measure_network_check_coverage

Run before and after a change to get a comparable number.

What is being counted
─────────────────────
A **network check area** is one distinct condition an unauthenticated scan can
establish about a host and that a person would triage as its own line in a
report. "SSLv3 is offered" is an area. "Port 443 is open" is not — that is
enumeration, and enumeration is not a finding.

The unit is deliberately the *area*, not the plugin and not the identifier.
Counting plugins rewards splitting one probe into three; counting identifiers
rewards emitting four findings where a reader wanted one. Counting areas
rewards neither, and it is the grain at which the original gap analysis
appears to have been written — this file's own baseline lands at 25.8%
against that analysis's 30% [estimated], which is the closest independent
corroboration available for the grain being about right.

Why the denominator includes things we did not build
────────────────────────────────────────────────────
Phase 5 learned this the hard way: its first scope listed twenty areas, the
phase implemented all twenty, and it reported 100% — a tautology wearing a
percentage. A list written by the same person who then implements every item
measures the list, not the capability.

So ``SCOPE`` below also names real unauthenticated checks a Nessus user would
expect and this build does **not** perform. They are in the denominator on
purpose. A coverage figure is only worth reading if it can go down.

**The denominator is frozen as of Stage 1 of this phase.** Adding an area
later because it turned out to be easy, or removing one because it turned out
to be hard, would make the before and after numbers incomparable — which is
the only thing they are for. If the scope genuinely must change, change it and
say so in the tracker; do not change it quietly.

Three things are counted separately and must never be conflated
───────────────────────────────────────────────────────────────
``implemented``   a check exists and emits a finding through the scan path
``tested``        an automated test names the area and exercises it
``validated``     it has produced a correct result against a real target

**The headline coverage figure is implemented *and* tested.** Implemented
alone is not proven; a check nothing exercises is a check nobody has seen
work — and this phase exists because of six probes that looked implemented
and emitted nothing. Real-target validation is reported beside the number and
never folded into it.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict, FrozenSet, List, Set, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


# ─────────────────────────────────────────────────────────────────────────────
# The denominator. Frozen at Stage 1 of the GAP-06 phase.
# ─────────────────────────────────────────────────────────────────────────────
#: (area id, family, description)
SCOPE: Tuple[Tuple[str, str, str], ...] = (
    # ── TLS / SSL ────────────────────────────────────────────────────────────
    ("tls.deprecated_protocol", "tls", "SSLv2/SSLv3/TLS1.0/TLS1.1 offered"),
    ("tls.no_secure_protocol", "tls", "Neither TLS 1.2 nor TLS 1.3 offered"),
    ("tls.weak_cipher_suite", "tls", "RC4/DES/3DES/NULL/EXPORT/anon suites offered"),
    ("tls.certificate_expired", "tls", "Server certificate has expired"),
    ("tls.certificate_self_signed", "tls", "Server certificate is self-signed"),
    ("tls.certificate_weak_signature", "tls", "Certificate signed with MD5 or SHA-1"),
    ("tls.heartbleed", "tls", "Heartbleed memory disclosure (CVE-2014-0160)"),
    ("tls.robot", "tls", "Bleichenbacher oracle (ROBOT)"),
    ("tls.compression_crime", "tls", "TLS compression enabled (CRIME)"),
    ("tls.certificate_hostname_mismatch", "tls", "Certificate does not match the host"),
    ("tls.certificate_expiring_soon", "tls", "Certificate expires within 30 days"),
    ("tls.weak_dh_parameters", "tls", "Weak Diffie-Hellman group (Logjam)"),
    ("tls.insecure_renegotiation", "tls", "Client-initiated / insecure renegotiation"),
    # ── HTTP ─────────────────────────────────────────────────────────────────
    ("http.missing_security_headers", "http", "HSTS/CSP/X-Frame/nosniff absent"),
    ("http.cleartext_service", "http", "Service offered over cleartext HTTP"),
    ("http.insecure_cookie_flags", "http", "Cookie without HttpOnly or Secure"),
    ("http.sensitive_path_exposed", "http", "/.env, /.git/config, /actuator, backups"),
    ("http.directory_listing", "http", "Directory indexing enabled"),
    ("http.dangerous_methods", "http", "PUT/DELETE/TRACE accepted"),
    ("http.admin_interface_exposed", "http", "Administrative panel reachable"),
    ("http.server_version_disclosure", "http", "Server header discloses a version"),
    ("http.default_credentials", "http", "Default HTTP credentials accepted"),
    ("http.shellshock", "http", "Shellshock via CGI (CVE-2014-6271)"),
    ("http.webdav_enabled", "http", "WebDAV methods enabled"),
    ("http.open_proxy", "http", "Server relays requests as an open proxy"),
    ("http.cors_misconfiguration", "http", "Permissive CORS with credentials"),
    # ── FTP ──────────────────────────────────────────────────────────────────
    ("ftp.anonymous_login", "ftp", "Anonymous login accepted"),
    ("ftp.anonymous_write", "ftp", "Anonymous session can upload"),
    ("ftp.weak_credentials", "ftp", "Documented default credentials accepted"),
    ("ftp.cleartext_protocol", "ftp", "Credentials transmitted in cleartext"),
    # ── SMB ──────────────────────────────────────────────────────────────────
    ("smb.v1_enabled", "smb", "SMBv1 still offered by the server"),
    ("smb.signing_disabled", "smb", "SMB signing not required"),
    ("smb.eternalblue", "smb", "MS17-010 / EternalBlue (CVE-2017-0144)"),
    ("smb.null_session", "smb", "Null session grants share or user enumeration"),
    ("smb.guest_account_enabled", "smb", "Guest account permits share access"),
    # ── SNMP ─────────────────────────────────────────────────────────────────
    ("snmp.default_community", "snmp", "Default or guessable community accepted"),
    ("snmp.v1_v2c_in_use", "snmp", "SNMPv1/v2c — community sent in cleartext"),
    ("snmp.information_disclosure", "snmp", "System/interface/address table readable"),
    ("snmp.write_community", "snmp", "A community string permits SET"),
    ("snmp.v3_weak_security", "snmp", "SNMPv3 noAuthNoPriv or weak auth"),
    # ── SSH ──────────────────────────────────────────────────────────────────
    ("ssh.weak_algorithms", "ssh", "Weak KEX, cipher or MAC algorithms offered"),
    ("ssh.protocol_v1", "ssh", "SSH protocol version 1 offered"),
    ("ssh.weak_host_key", "ssh", "Short or deprecated host key"),
    # ── Other services already reaching the report ───────────────────────────
    ("telnet.cleartext_exposed", "telnet", "Telnet reachable — cleartext credentials"),
    ("redis.no_authentication", "redis", "Redis accepts commands unauthenticated"),
    ("mongodb.no_authentication", "mongodb", "MongoDB accepts unauthenticated access"),
    ("mqtt.no_authentication", "mqtt", "MQTT broker accepts anonymous connections"),
    ("memcached.no_authentication", "memcached", "Memcached reachable without auth"),
    ("ldap.anonymous_bind", "ldap", "Directory readable via anonymous bind"),
    ("dns.zone_transfer", "dns", "AXFR permitted to an arbitrary client"),
    ("dns.open_recursion", "dns", "Recursive resolution for arbitrary clients"),
    # ── Cross-cutting finding producers ──────────────────────────────────────
    ("cve.version_inference", "cve", "CVE candidates from fingerprinted versions"),
    ("nuclei.template_verification", "cve", "Active template verification"),
    # ── In scope, NOT implemented ────────────────────────────────────────────
    ("rdp.nla_disabled", "rdp", "RDP without Network Level Authentication"),
    ("rdp.weak_encryption", "rdp", "RDP offering weak or no encryption"),
    ("vnc.no_authentication", "vnc", "VNC reachable with no authentication"),
    ("nfs.world_readable_export", "nfs", "Export readable by any client"),
    ("rpc.portmapper_exposed", "rpc", "Portmapper enumerable from the network"),
    ("ipmi.cipher_zero", "ipmi", "IPMI 2.0 cipher-zero authentication bypass"),
    ("ntp.monlist_amplification", "ntp", "monlist enabled — amplification source"),
    ("smtp.open_relay", "smtp", "Server relays mail for arbitrary senders"),
    ("smtp.vrfy_expn_enabled", "smtp", "VRFY/EXPN permit user enumeration"),
)

#: Named so the exclusion is visible rather than silent. Excluding these is a
#: scoping decision agreed for this phase, not a way to raise the percentage.
OUT_OF_SCOPE: Tuple[str, ...] = (
    "exploitation of any kind - detection only",
    "denial of service, fuzzing and brute-force template classes",
    "credential spraying beyond the existing documented default lists",
    "web application testing (/web-scans: ffuf, sqlmap, crawling)",
    "database service assessment - GAP-10, not this phase",
    "network device configuration assessment - GAP-11, not this phase",
)


# ─────────────────────────────────────────────────────────────────────────────
# The "before" column. Established by reading the tree at commit e649bdc and
# frozen at Stage 1. Never edit this to make an "after" number look better —
# these two sets are only worth anything as a comparison, and a baseline that
# moves is not a baseline.
# ─────────────────────────────────────────────────────────────────────────────
#: Areas that produced a finding reaching ``host["cves"]`` before this phase.
#: Each was confirmed by tracing the plugin's return value through
#: ``VulnerabilityEngine._merge``, which promotes a *top-level* ``cves`` key
#: and nothing else.
BASELINE_EMITTING: FrozenSet[str] = frozenset(
    {
        "tls.heartbleed",  # heartbleed_probe  -> CVE-2014-0160
        "http.shellshock",  # heartbleed_probe  -> CVE-2014-6271
        "http.default_credentials",  # default_creds     -> MISC-HTTP-DEFAULT-CREDS
        "ftp.anonymous_login",  # default_creds     -> MISC-FTP-ANON
        "telnet.cleartext_exposed",  # default_creds     -> MISC-TELNET-EXPOSURE
        "redis.no_authentication",  # default_creds     -> MISC-REDIS-NOAUTH
        "mongodb.no_authentication",  # default_creds     -> MISC-MONGO-NOAUTH
        "mqtt.no_authentication",  # default_creds     -> MISC-MQTT-NOAUTH
        "memcached.no_authentication",  # default_creds     -> MISC-MEMCACHED-NOAUTH
        "smb.signing_disabled",  # eternalblue_probe -> MISC-SMB-SIGNING
        "smb.eternalblue",  # eternalblue_probe -> CVE-2017-0144
        "ldap.anonymous_bind",  # ldap_probe        -> MISC-LDAP-ANON-BIND
        "dns.zone_transfer",  # dns_probe         -> MISC-DNS-AXFR
        "dns.open_recursion",  # dns_probe         -> MISC-DNS-RECURSION
        "cve.version_inference",  # cve_engine
        "nuclei.template_verification",  # nuclei_probe
    }
)

#: The fifteen plugins, and whether each put anything into ``host["cves"]``
#: before this phase. Frozen at Stage 1 alongside BASELINE_EMITTING.
#:
#: ``ssh_probe`` is the entry worth reading twice. It initialises
#: ``info["cves"] = []``, promotes it with ``if info.get("cves")``, and nothing
#: anywhere in the module ever appends to it — the CVE lookup was deliberately
#: removed and the promotion plumbing was left behind. It therefore reads as a
#: finding-producing plugin and produces nothing, which is precisely the class
#: of defect this phase exists to close.
#:
#: That entry is also why ``_implemented()`` reads a catalogue rather than the
#: plugin sources. An independent AST pass over the same fifteen modules —
#: asking only "can ``run`` return a dict with a top-level ``cves`` key" —
#: answers **8**, because structurally ``ssh_probe`` can. The truth is 7. A
#: measurement that cannot tell live code from dead plumbing would have
#: reported this phase's own starting point one area too high, and every
#: "after" number would have inherited the error.
BASELINE_PLUGIN_EMITS: Dict[str, bool] = {
    "cve_engine": True,
    "nuclei_probe": True,
    "default_creds": True,
    "dns_probe": True,
    "eternalblue_probe": True,
    "heartbleed_probe": True,
    "ldap_probe": True,
    "http_analyzer": False,  # builds cves + issues, returns them nested in http_audit
    "ftp_checker": False,  # builds cves + issues, returns them nested in ftp_info
    "smb_probe": False,  # builds cves, returns it nested in smb_info
    "snmp_probe": False,  # brute-forces 15 communities, emits no finding
    "tls_scanner": False,  # grades the host "F" and emits no finding
    "ssh_probe": False,  # promotion path exists; the list is never appended to
    "udp_scanner": False,  # enumeration only — correctly emits nothing
    "icmp_probe": False,  # liveness only — correctly emits nothing
}

#: Plugins whose job is enumeration rather than assessment. They are expected
#: to emit no findings, now and after this phase, and are excluded from the
#: "plugins that should emit" denominator rather than counted as failures.
ENUMERATION_ONLY: FrozenSet[str] = frozenset({"udp_scanner", "icmp_probe"})


# ─────────────────────────────────────────────────────────────────────────────
# Live measurement
# ─────────────────────────────────────────────────────────────────────────────
def _implemented() -> Dict[str, object]:
    """
    Areas with a declared network check that reaches the findings list.

    Read from the check catalogue rather than from the plugin sources. A
    source scan cannot tell an emitted finding from dead promotion plumbing —
    ``ssh_probe`` above is exactly that, and a measurement fooled by it would
    have reported this phase's own starting point one area too high.
    """
    try:
        from engines.vulnerability.network_checks import NETWORK_CHECKS
    except Exception:
        # Stage 1 runs before the catalogue exists. Nothing is implemented
        # against the new contract yet, which is the correct reading.
        return {}
    return {check.area: check for check in NETWORK_CHECKS}


def _tested() -> Set[str]:
    """
    Areas an automated test names.

    Read from the test sources rather than from a hand-maintained list — a
    list would keep saying "tested" for as long as nobody updated it, which is
    precisely the failure a coverage figure must not have.
    """
    root = Path(__file__).resolve().parents[1] / "tests"
    corpus = ""
    # ``test_tls*.py`` was added by GAP-07 (Phase 11). Three of the thirteen
    # tls.* areas in the scope below were frozen here and implemented there, so
    # their tests live in that phase's files; without this pattern they read as
    # untested and this figure understates itself.
    for pattern in (
        "test_network_check*.py",
        "test_plugin_findings*.py",
        "test_tls*.py",
    ):
        for path in root.rglob(pattern):
            corpus += path.read_text(encoding="utf-8")
    return {area for area, _f, _d in SCOPE if area in corpus}


def _plugins_emitting() -> Dict[str, bool]:
    """
    Which plugins produce at least one finding.

    A plugin counts only where the catalogue declares an area for it **and a
    test names that area**. Counting declarations alone would have reported
    13/15 the moment the catalogue was written and before a single plugin had
    been wired to it — which is the same "looks implemented, emits nothing"
    error the phase exists to fix, committed by the instrument measuring it.
    """
    implemented = _implemented()
    if not implemented:
        return dict(BASELINE_PLUGIN_EMITS)
    tested = _tested()
    emitting = {
        getattr(check, "plugin", "")
        for area, check in implemented.items()
        if area in tested
    }
    return {name: (name in emitting) for name in BASELINE_PLUGIN_EMITS}


def main() -> int:
    implemented = _implemented()
    tested = _tested()

    print("=" * 78)
    print("GAP-06 — UNAUTHENTICATED NETWORK CHECK COVERAGE")
    print("=" * 78)
    print(f"\n{'area':38} {'family':10} {'before':7} {'impl':6} {'test':6}")
    print("-" * 78)

    by_family: Dict[str, List[bool]] = {}
    for area, family, _description in SCOPE:
        before = area in BASELINE_EMITTING
        has = area in implemented
        has_test = area in tested
        by_family.setdefault(family, []).append(has and has_test)
        print(
            f"{area:38} {family:10} {'yes' if before else '-':7} "
            f"{'yes' if has else 'NO':6} {'yes' if has_test else 'NO':6}"
        )

    total = len(SCOPE)
    before = len(BASELINE_EMITTING)
    done = sum(1 for area, _f, _d in SCOPE if area in implemented)
    proven = sum(1 for area, _f, _d in SCOPE if area in implemented and area in tested)

    print("-" * 78)
    for family in sorted(by_family):
        flags = by_family[family]
        print(
            f"  {family:10} proven: {sum(flags)}/{len(flags)} "
            f"({round(100.0 * sum(flags) / len(flags), 1)}%)"
        )

    print(f"\n  areas in scope       : {total}")
    print(
        f"  BEFORE (emitting)    : {before}/{total} = "
        f"{round(100.0 * before / total, 1)}%"
    )
    print(
        f"  implemented          : {done}/{total} = "
        f"{round(100.0 * done / total, 1)}%"
    )
    print(
        f"  implemented + tested : {proven}/{total} = "
        f"**{round(100.0 * proven / total, 1)}%**   <- GAP-06 coverage"
    )
    print("  real-target validated: reported separately, never folded in")
    if done != proven:
        print(
            f"\n  {done - proven} area(s) have a check no automated test names. "
            f"Implemented is not proven, and only proven counts."
        )

    regressed = sorted(BASELINE_EMITTING - set(implemented))
    if regressed and implemented:
        print(
            f"\n  WARNING: {len(regressed)} area(s) emitted a finding BEFORE this "
            f"phase and do not now: {regressed}"
        )
        print("  A phase that adds checks must not remove one.")

    # An area another gap owns is not an orphan. GAP-07 (Phase 11) added
    # fourteen deep-TLS areas to this same catalogue and measures them against
    # its own frozen denominator; reporting them as strays would read as a
    # defect, and counting them would inflate this figure with another phase's
    # work.
    try:
        from scripts.measure_tls_coverage import SCOPE as GAP07_SCOPE

        owned_elsewhere = {a for a, _t, _d in GAP07_SCOPE}
    except Exception:  # pragma: no cover
        owned_elsewhere = set()

    outside = set(implemented) - {a for a, _f, _d in SCOPE}
    elsewhere = sorted(outside & owned_elsewhere)
    if elsewhere:
        print(
            f"\n  {len(elsewhere)} check(s) here belong to GAP-07's denominator, "
            f"measured by scripts/measure_tls_coverage.py:"
        )
        print("    " + ", ".join(elsewhere))

    orphans = sorted(outside - owned_elsewhere)
    if orphans:
        print(
            f"\n  WARNING: {len(orphans)} check(s) declare an area outside the "
            f"frozen scope: {orphans}"
        )
        print("  The denominator is frozen; an area outside it counts for nothing.")

    # ── Plugin-level figure — the phase's headline commitment ────────────────
    print("\n" + "-" * 78)
    print("PLUGIN-LEVEL MEASUREMENT")
    emits = _plugins_emitting()
    should_emit = [n for n in BASELINE_PLUGIN_EMITS if n not in ENUMERATION_ONLY]
    now = sum(1 for n in emits if emits[n])
    was = sum(1 for n in BASELINE_PLUGIN_EMITS if BASELINE_PLUGIN_EMITS[n])
    print(f"  plugins total                     : {len(BASELINE_PLUGIN_EMITS)}")
    print(f"  enumeration-only (never emit)     : {len(ENUMERATION_ONLY)}")
    print(f"  producing findings BEFORE         : {was}/{len(BASELINE_PLUGIN_EMITS)}")
    print(f"  producing findings NOW            : {now}/{len(BASELINE_PLUGIN_EMITS)}")
    print(f"  target                            : {len(should_emit)}/15")
    silent = sorted(n for n in should_emit if not emits.get(n))
    if silent:
        print(f"  detecting but not reporting       : {', '.join(silent)}")

    # ── Identifier hygiene — the second half of the phase ────────────────────
    print("\n" + "-" * 78)
    print("IDENTIFIER TYPING")
    try:
        from core.checks.definitions import (
            DEFINITION_TYPE_CVE,
            definition_type_for_id,
        )

        catalogue = _implemented()
        if not catalogue:
            print("  network check catalogue not present yet")
        else:
            # The identifier that reaches the catalogue, not the check's own
            # short name. Measuring check_id here would have proved nothing:
            # no check_id was ever going to start with MISC-, so the figure
            # would have read zero whatever the product actually wrote.
            ids = [c.definition_id for c in catalogue.values() if not c.dynamic]
            real_cves = [i for i in ids if str(i).upper().startswith("CVE-")]
            mistyped = [
                i
                for i in ids
                if i not in real_cves
                and definition_type_for_id(i) == DEFINITION_TYPE_CVE
            ]
            fabricated = [
                i
                for i in ids
                if str(i).upper().startswith("MISC-")
                or (
                    str(i).upper().startswith("CVE-")
                    and definition_type_for_id(i) != DEFINITION_TYPE_CVE
                )
            ]
            print(f"  declared catalogue identifiers     : {len(ids)}")
            print(f"  filed as real CVEs                 : {len(real_cves)}")
            print(f"  fabricated CVE-shaped identifiers  : {len(fabricated)}")
            print(f"  non-CVE identifiers typed as cve   : {len(mistyped)}")
            if fabricated:
                print(f"    {sorted(fabricated)}")
            legacy = len(
                {
                    old
                    for c in catalogue.values()
                    for old in getattr(c, "legacy_ids", ())
                }
            )
            print(f"  fabricated identifiers with a route: {legacy}")
    except Exception as exc:  # pragma: no cover
        print(f"  (could not measure identifier typing: {exc})")

    print("\n  Deliberately out of scope (not in the denominator):")
    for item in OUT_OF_SCOPE:
        print(f"    - {item}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
