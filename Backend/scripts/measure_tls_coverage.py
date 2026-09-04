"""
scripts/measure_tls_coverage.py
─────────────────────────────────────────────────────────────────────────────
Measures GAP-07 coverage — deep TLS/SSL assessment on the main scan path.

    python -m scripts.measure_tls_coverage

Run before and after a change to get a comparable number.

What this denominator covers, and what it deliberately does not
──────────────────────────────────────────────────────────────
**What a deep TLS engine can establish about a listener that a single
handshake cannot**, and **which transports it can reach at all**.

It does **not** cover the thirteen ``tls.*`` areas in GAP-06's frozen scope.
Ten of those were delivered in Phase 6 and three were not; this phase
implements the remaining three, and **they count towards GAP-06's figure, not
this one**. Counting them twice would inflate this phase by an eighth before a
line of it was written, and misattributing coverage between gaps is a mistake
this programme has had to correct twice already — the Docker daemon in Phase 9,
and the GAP-06 web surface in Phase 8.

``scripts/measure_network_check_coverage.py`` is the authority for those
thirteen. This file names them in :data:`OWNED_BY_GAP06` so the boundary is
visible from both sides rather than only from one.

Two kinds of area, and they are measured from different tables
──────────────────────────────────────────────────────────────
**Findings** — a condition the engine can report. Read from
``NETWORK_CHECKS``, the same catalogue GAP-06 measures against, because a
declared check that reaches the findings list is the only honest definition of
"implemented".

**Transports** — a service the assessment can reach at all. STARTTLS adds no
new finding *types*: an expired certificate on submission port 587 is the same
condition as an expired certificate on 443. What it adds is reach, and reach is
measured from the plugin's own opportunistic-TLS table rather than from the
catalogue, because no catalogue entry would change when a transport is added.

Three things are counted separately and must never be conflated
──────────────────────────────────────────────────────────────
``implemented``   the code supports it, read from its own tables
``tested``        an automated test names the area and exercises it
``validated``     it has produced a correct result against a real listener

**The headline coverage figure is implemented *and* tested.**
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

#: The thirteen areas GAP-06 froze and owns. Three of them are unimplemented at
#: the start of this phase and are delivered by it — their coverage credit
#: belongs to GAP-06, whose harness reads the same live catalogue and will pick
#: them up automatically.
OWNED_BY_GAP06: Tuple[str, ...] = (
    "tls.deprecated_protocol",
    "tls.no_secure_protocol",
    "tls.weak_cipher_suite",
    "tls.certificate_expired",
    "tls.certificate_self_signed",
    "tls.certificate_weak_signature",
    "tls.certificate_hostname_mismatch",
    "tls.heartbleed",
    "tls.robot",
    "tls.compression_crime",
    # Unimplemented before this phase; delivered by it, counted there.
    "tls.certificate_expiring_soon",
    "tls.weak_dh_parameters",
    "tls.insecure_renegotiation",
)

#: (area id, theme, description). **Frozen at the start of Phase 11 and not to
#: be edited to match what was built.**
#:
#: ``starttls.*`` areas are transports; everything else is a finding condition.
SCOPE: Tuple[Tuple[str, str, str], ...] = (
    # ── Transports the assessment can reach ──────────────────────────────────
    ("starttls.smtp", "starttls", "SMTP STARTTLS — ports 25, 587, 2525"),
    ("starttls.imap", "starttls", "IMAP STARTTLS — port 143"),
    ("starttls.pop3", "starttls", "POP3 STLS — port 110"),
    ("starttls.ldap", "starttls", "LDAP STARTTLS — port 389"),
    ("starttls.postgres", "starttls", "PostgreSQL SSLRequest — port 5432"),
    ("starttls.ftp", "starttls", "FTP AUTH TLS — port 21"),
    ("starttls.xmpp", "starttls", "XMPP STARTTLS — ports 5222, 5269"),
    ("starttls.rdp", "starttls", "RDP TLS negotiation — port 3389"),
    ("starttls.mysql", "starttls", "MySQL SSLRequest — port 3306"),
    # ── Certificate chain and trust ──────────────────────────────────────────
    (
        "tls.certificate_untrusted_chain",
        "chain",
        "Leaf does not chain to a trusted root store",
    ),
    (
        "tls.certificate_chain_order",
        "chain",
        "Chain sent out of order, or missing its intermediates",
    ),
    (
        "tls.certificate_sha1_chain",
        "chain",
        "A SHA-1 signature appears in the verified chain",
    ),
    ("tls.certificate_revoked", "chain", "Leaf revoked, by CRL or OCSP"),
    (
        "tls.certificate_legacy_anchor",
        "chain",
        "Chain anchored to a distrusted legacy CA",
    ),
    # ── Certificate content ──────────────────────────────────────────────────
    (
        "tls.certificate_not_yet_valid",
        "cert",
        "notBefore is in the future — the certificate is not yet valid",
    ),
    (
        "tls.certificate_weak_key",
        "cert",
        "Public key below the modern floor (RSA < 2048, EC < 224)",
    ),
    ("tls.ocsp_stapling_absent", "cert", "Server staples no OCSP response"),
    (
        "tls.must_staple_unhonoured",
        "cert",
        "Certificate sets must-staple and the server staples nothing",
    ),
    (
        "tls.certificate_no_sct",
        "cert",
        "No Certificate Transparency SCTs embedded",
    ),
    # ── Downgrade and renegotiation ──────────────────────────────────────────
    (
        "tls.fallback_scsv_unsupported",
        "downgrade",
        "TLS_FALLBACK_SCSV not honoured — downgrade dance is not refused",
    ),
    (
        "tls.client_renegotiation_dos",
        "downgrade",
        "Client-initiated renegotiation permitted — asymmetric CPU cost",
    ),
    # ── Key exchange ─────────────────────────────────────────────────────────
    (
        "tls.weak_ecdh_curve",
        "kex",
        "Ephemeral ECDH group below 224 bits",
    ),
    (
        "tls.no_forward_secrecy",
        "kex",
        "No ECDHE or DHE suite offered — a stolen key decrypts past traffic",
    ),
    (
        "tls.rsa_key_exchange",
        "kex",
        "Static RSA key exchange offered, reported in its own right",
    ),
    # ── Protocol behaviour ───────────────────────────────────────────────────
    (
        "tls.ccs_injection",
        "protocol",
        "OpenSSL ChangeCipherSpec injection (CVE-2014-0224)",
    ),
    (
        "tls.early_data_enabled",
        "protocol",
        "TLS 1.3 0-RTT accepted — replayable early data",
    ),
    (
        "tls.extended_master_secret_absent",
        "protocol",
        "Extended master secret unsupported (triple handshake)",
    ),
    (
        "tls.session_resumption_weak",
        "protocol",
        "Session tickets reused or resumption misconfigured",
    ),
)

#: Areas this build deliberately does not implement, each with its reason.
NOT_PLANNED: Dict[str, str] = {
    "starttls.xmpp": (
        "XMPP STARTTLS needs an `xmpp_to_hostname` the scanner cannot infer — "
        "the server rejects a stream header addressed to the wrong domain, and "
        "guessing one produces a connection error indistinguishable from a "
        "server with no TLS"
    ),
    "starttls.rdp": (
        "RDP's TLS negotiation is reachable, but the port is overwhelmingly "
        "Windows Remote Desktop, whose certificate is self-signed by design on "
        "an unjoined host. Every such host would acquire a finding it cannot "
        "act on, which is how a report gets ignored wholesale"
    ),
    "starttls.mysql": (
        "sslyze 6.3.1 exposes no MySQL opportunistic-TLS handler — its enum has "
        "POSTGRES and not MySQL. Writing one by hand means a second TLS "
        "transport implementation, which is the parallel engine this phase "
        "exists not to build. The database engine's own TLS posture is "
        "assessed by GAP-10 over an authenticated session"
    ),
    "tls.certificate_revoked": (
        "revocation needs a live fetch to the CA's CRL or OCSP responder from "
        "the scanner, which OT segments do not permit and which turns a "
        "network outage into a finding about somebody's certificate. The "
        "*stapled* response is read instead — see tls.ocsp_stapling_absent"
    ),
    "tls.certificate_legacy_anchor": (
        "the distrusted Symantec anchors sslyze reports on all expired years "
        "ago; a check for them would fire on nothing and quietly suggest the "
        "area is covered"
    ),
    "tls.certificate_no_sct": (
        "Certificate Transparency is a browser-policy requirement, not a "
        "server misconfiguration. A privately issued certificate legitimately "
        "carries no SCT, and this deployment's own CA is exactly that"
    ),
    "tls.rsa_key_exchange": (
        "static RSA key exchange is precisely the condition "
        "tls.no_forward_secrecy reports, seen from the other side. Two "
        "findings for one remediation is the duplication Phase 6 removed from "
        "the FTP and SMB probes"
    ),
    "tls.session_resumption_weak": (
        "sslyze reports resumption *support*, and support is the correct and "
        "desirable state. Distinguishing a weak ticket key from a healthy one "
        "needs two scans separated in time, which the scan model has no place "
        "for yet"
    ),
}

#: Named so the exclusion is visible rather than silent.
OUT_OF_SCOPE: Tuple[str, ...] = (
    "the thirteen tls.* areas GAP-06 froze — see OWNED_BY_GAP06",
    "TLS configuration read from a server's config file — GAP-09, over a "
    "credentialed session",
    "the database engine's own TLS settings — GAP-10, over an authenticated " "session",
    "HTTP-layer transport security (HSTS, secure cookie flags) — GAP-06",
    "certificate issuance, renewal and inventory — a different product",
    "client-side TLS posture; this assesses listeners",
)


def _implemented() -> Set[str]:
    """
    Areas this build supports, read from the live tables.

    Findings come from the check catalogue and transports from the plugin's
    opportunistic-TLS map, because those are the two things that actually
    decide whether an area is reachable. A list kept beside them would keep
    claiming coverage after the code was removed.
    """
    areas: Set[str] = set()
    try:
        from engines.vulnerability.network_checks import NETWORK_CHECKS

        areas |= {c.area for c in NETWORK_CHECKS}
    except Exception as exc:  # pragma: no cover - Stage 1 runs before the code
        print(f"  (catalogue not importable yet: {exc})")
    try:
        from engines.vulnerability.plugins.tls_scanner import STARTTLS_SERVICES

        areas |= {f"starttls.{name}" for name in STARTTLS_SERVICES}
    except Exception as exc:  # pragma: no cover
        print(f"  (STARTTLS table not importable yet: {exc})")
    return areas


def _tested() -> Set[str]:
    """Areas an automated test names, read from the test sources."""
    root = Path(__file__).resolve().parents[1] / "tests"
    corpus = ""
    for pattern in ("test_tls*.py", "test_starttls*.py"):
        for path in root.rglob(pattern):
            corpus += path.read_text(encoding="utf-8")
    return {area for area, _t, _d in SCOPE if area in corpus}


def main() -> int:
    implemented = _implemented()
    tested = _tested()
    not_planned = set(NOT_PLANNED)
    areas = [a for a, _t, _d in SCOPE]
    total = len(areas)

    overlap = set(areas) & set(OWNED_BY_GAP06)
    if overlap:
        print(
            f"!! {sorted(overlap)} appear in both this denominator and "
            f"GAP-06's. One gap owns an area; counting it twice inflates both.\n"
        )

    both = [a for a in areas if a in implemented and a in tested]

    print("=" * 78)
    print("GAP-07 — deep TLS/SSL assessment on the main scan path")
    print("=" * 78)
    print()

    by_theme: Dict[str, List[Tuple[str, str]]] = {}
    for area, theme, desc in SCOPE:
        by_theme.setdefault(theme, []).append((area, desc))

    for theme in ("starttls", "chain", "cert", "downgrade", "kex", "protocol"):
        rows = by_theme.get(theme, [])
        print(f"── {theme} " + "─" * (72 - len(theme)))
        for area, desc in rows:
            if area in not_planned:
                mark = "  —  "
            elif area in implemented and area in tested:
                mark = " [x] "
            elif area in implemented:
                mark = " [~] "
            else:
                mark = " [ ] "
            print(f"{mark}{area:38s} {desc[:60]}")
        done = len([a for a, _d in rows if a in implemented and a in tested])
        print(f"      {done}/{len(rows)} implemented and tested\n")

    print("legend: [x] implemented and tested   [~] implemented, untested")
    print("        [ ] not implemented          —   not planned (reason below)")
    print()

    print("── not planned, with reasons " + "─" * 49)
    for area in areas:
        if area in not_planned:
            print(f"  {area}")
            print(f"      {NOT_PLANNED[area]}")
    print()

    print("── owned by GAP-06, measured there " + "─" * 43)
    try:
        from engines.vulnerability.network_checks import NETWORK_CHECKS

        catalogue = {c.area for c in NETWORK_CHECKS}
    except Exception:
        catalogue = set()
    for area in OWNED_BY_GAP06:
        state = "implemented" if area in catalogue else "not implemented"
        print(f"  {area:40s} {state}")
    print()

    print("── out of scope entirely " + "─" * 53)
    for line in OUT_OF_SCOPE:
        print(f"  · {line}")
    print()

    pct = 100.0 * len(both) / total if total else 0.0
    print("=" * 78)
    print(f"  areas in the frozen denominator        : {total}")
    print(f"  not planned (reason recorded)          : {len(not_planned)}")
    print(f"  implemented                            : {len(implemented & set(areas))}")
    print(f"  implemented AND tested                 : {len(both)}")
    print(f"  GAP-07 coverage                        : {pct:.1f}%")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
