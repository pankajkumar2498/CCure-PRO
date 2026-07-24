"""
core/risk.py
------------
OS fingerprinting/inference and host risk scoring.
Pure logic - no I/O, no imports from engines.
"""

from typing import Dict, List, Optional, Tuple

from core.constants import (
    OS_TTL_MAP,
    RISK_LEVELS,
    RISK_WEIGHTS,
    TCP_OPTIONS_FINGERPRINT,
    TCP_WINDOW_OS,
)
from core.vuln_intel import compute_priority, merge_alias_fields

# =============================================================================
# OS Fingerprinting
# =============================================================================


def fingerprint_os(
    ttl: int,
    window: int | None = None,
    tcp_opts: dict | None = None,
) -> tuple[str, str]:
    """
    Returns (os_guess, confidence) from TTL, TCP window, and optional
    TCP option fingerprint data.

    Priority 2-D: when *tcp_opts* is supplied (from a crafted SYN probe),
    MSS + WScale + SAckOK are used as additional discriminators that can
    elevate confidence from Low/Medium to High even when TTL is ambiguous.

    tcp_opts keys (all optional):
        mss      (int)  – Maximum Segment Size
        wscale   (int)  – Window Scale shift count (0 = explicitly 0; None = absent)
        sack_ok  (bool) – SAckOK option present in SYN-ACK
        df_bit   (bool) – Don't Fragment IP flag

    Confidence: Low / Medium / High
    """
    # Step 1: TTL narrowing
    guess = "Unknown"
    for threshold, label in OS_TTL_MAP:
        if ttl <= threshold:
            guess = label
            break

    # Step 2: TCP window refinement
    conf = "Low"
    if window and window in TCP_WINDOW_OS:
        win_os = TCP_WINDOW_OS[window]
        if (
            "Windows" in guess
            and "Windows" in win_os
            or "Linux" in guess
            and "Linux" in win_os
        ):
            guess = win_os
            conf = "High"
        else:
            conf = "Medium"
    elif window:
        conf = "Medium"

    # Step 3: TCP options fingerprint (Priority 2-D)
    if tcp_opts:
        mss = tcp_opts.get("mss")
        wscale = tcp_opts.get("wscale")  # may be 0 (explicit) or None (absent)
        sack_ok = bool(tcp_opts.get("sack_ok", False))
        for mss_lo, mss_hi, ws, sack, label, opt_conf in TCP_OPTIONS_FINGERPRINT:
            mss_ok = (mss is None) or (mss_lo <= mss <= mss_hi)
            ws_ok = (ws is None) or (wscale == ws)
            sack_ok_match = sack_ok == sack
            if mss_ok and ws_ok and sack_ok_match:
                guess = label
                conf = opt_conf
                break

    return guess, conf


def infer_os_from_host(host: dict) -> tuple[str, str]:
    """
    Best-effort unauthenticated OS inference from service-level evidence.

    This is a fallback for TCP-only scans where raw-packet TTL/window
    fingerprinting is unavailable. If the host already has an OS guess from
    packet fingerprints, that result is preserved.
    """
    current_guess = host.get("os_guess", "Unknown")
    current_conf = host.get("os_confidence", "Low")
    if current_guess not in ("", "Unknown"):
        return current_guess, current_conf

    texts: list[str] = []
    open_ports = set()
    for port_info in host.get("open_ports", []):
        port = port_info.get("port")
        if isinstance(port, int):
            open_ports.add(port)
        texts.extend(
            [
                str(port_info.get("service", "")),
                str(port_info.get("banner", "")),
                str(port_info.get("version", "")),
            ]
        )

    ssh_info = host.get("ssh_info", {}) or {}
    http_audit = host.get("http_audit", {}) or {}
    smb_info = host.get("smb_info", {}) or {}
    snmp_info = host.get("snmp_info", {}) or {}

    texts.extend(
        [
            str(ssh_info.get("banner", "")),
            str(ssh_info.get("version", "")),
            str(http_audit.get("server_header", "")),
            str(snmp_info.get("sys_descr", "")),
        ]
    )
    text_blob = " ".join(texts).lower()

    explicit_markers = [
        ("Windows Server (IIS)", ["microsoft-iis"], "High"),
        ("Windows (WinRM)", ["winrm", "microsoft-httpapi"], "High"),
        ("Linux (Ubuntu)", ["ubuntu"], "High"),
        ("Linux (Debian)", ["debian"], "High"),
        (
            "Linux (CentOS/RHEL)",
            ["centos", "red hat", "redhat", "rhel", "rocky linux", "alma linux"],
            "High",
        ),
        ("Linux (Alpine)", ["alpine"], "High"),
        ("FreeBSD", ["freebsd"], "High"),
        ("OpenBSD", ["openbsd"], "High"),
        ("NetBSD", ["netbsd"], "High"),
        ("macOS", ["darwin", "macos", "mac os x"], "High"),
        (
            "Cisco IOS / Network Appliance",
            ["cisco ios", "routeros", "junos", "fortios"],
            "High",
        ),
    ]
    for label, markers, conf in explicit_markers:
        if any(marker in text_blob for marker in markers):
            return label, conf

    scores: dict[str, int] = {
        "Windows": 0,
        "Linux/Unix": 0,
        "BSD/macOS": 0,
        "Network Appliance": 0,
    }

    if 3389 in open_ports:
        scores["Windows"] += 5
    if 5985 in open_ports or 5986 in open_ports:
        scores["Windows"] += 5
    if 135 in open_ports:
        scores["Windows"] += 4
    if 139 in open_ports:
        scores["Windows"] += 3
    if 445 in open_ports:
        if {135, 3389, 5985, 5986} & open_ports:
            scores["Windows"] += 4
        else:
            scores["Windows"] += 2
            scores["Linux/Unix"] += 1

    if 111 in open_ports:
        scores["Linux/Unix"] += 4
    if 2049 in open_ports:
        scores["Linux/Unix"] += 5
    if 548 in open_ports:
        scores["BSD/macOS"] += 4
    if 22 in open_ports and "openssh" in text_blob:
        scores["Linux/Unix"] += 2

    if any(term in text_blob for term in ("apache", "nginx")):
        scores["Linux/Unix"] += 1
    if any(term in text_blob for term in ("cisco", "routeros", "junos", "fortinet")):
        scores["Network Appliance"] += 4

    if (
        smb_info.get("open")
        and smb_info.get("version") == "SMBv2/3"
        and (135 in open_ports or 3389 in open_ports)
    ):
        scores["Windows"] += 2

    ranked = sorted(scores.items(), key=lambda item: item[1], reverse=True)
    top_label, top_score = ranked[0]
    next_score = ranked[1][1] if len(ranked) > 1 else 0

    if top_score < 4:
        return "Unknown", "Low"

    if top_label == "Windows":
        guess = "Windows (service fingerprint)"
    elif top_label == "Linux/Unix":
        guess = "Linux/Unix (service fingerprint)"
    elif top_label == "BSD/macOS":
        guess = "BSD/macOS (service fingerprint)"
    else:
        guess = "Network Appliance (service fingerprint)"

    if top_score >= 8 and (top_score - next_score) >= 4:
        conf = "High"
    elif top_score >= 5 and (top_score - next_score) >= 2:
        conf = "Medium"
    else:
        conf = "Low"

    return guess, conf


# =============================================================================
# Host Risk Scoring
# =============================================================================


def calculate_risk(
    open_ports: list[dict],
    cves: list[dict],
    http_audit: dict,
    tls_info: dict,
) -> tuple[int, str]:
    """
    Returns (score 0-100, risk_level string).
    Aggregates port risk, CVE severity, HTTP audit issues, TLS grade.
    """
    score = 0

    # Port-level risk weights
    for p in open_ports:
        score += RISK_WEIGHTS.get(p.get("risk", "Info"), 0)

    # CVE CVSS scores
    for c in cves:
        cvss = normalize_cve(c).get("cvss_score", 0)
        if cvss >= 9.0:
            score += 20
        elif cvss >= 7.0:
            score += 10
        elif cvss >= 4.0:
            score += 5
        else:
            score += 2

    # HTTP header issues
    if http_audit.get("issues"):
        score += len(http_audit["issues"]) * 2

    # TLS problems
    if tls_info.get("cert_expired"):
        score += 15
    if tls_info.get("cert_self_signed"):
        score += 10
    if tls_info.get("weak_cipher"):
        score += 10
    if tls_info.get("score") == "F":
        score += 20

    score = min(score, 100)

    level = "Info"
    for threshold, lvl in RISK_LEVELS:
        if score >= threshold:
            level = lvl
            break

    return score, level


def normalize_cve(cve: dict) -> dict:
    """Normalize CVE entries to the frontend-facing response contract."""
    return merge_alias_fields(cve)


def deduplicate_cves(cves: list[dict]) -> list[dict]:
    """Remove duplicate CVE entries (same CVE ID)."""
    best_by_id: dict[str, dict] = {}
    for c in cves:
        normalized = normalize_cve(c)
        key = normalized.get("cve_id", "")
        if not key:
            continue

        current = best_by_id.get(key)
        if current is None:
            best_by_id[key] = normalized
            continue

        current_priority = compute_priority(
            cvss_score=current.get("cvss_score"),
            epss_score=current.get("epss_score"),
            in_kev=bool(current.get("in_kev")),
            has_exploit=bool(current.get("has_exploit")),
        )[0]
        new_priority = compute_priority(
            cvss_score=normalized.get("cvss_score"),
            epss_score=normalized.get("epss_score"),
            in_kev=bool(normalized.get("in_kev")),
            has_exploit=bool(normalized.get("has_exploit")),
        )[0]

        if new_priority > current_priority:
            merged = dict(current)
            merged.update(normalized)
            best_by_id[key] = merged
        else:
            merged = dict(normalized)
            merged.update(current)
            best_by_id[key] = merged

    return sorted(
        best_by_id.values(),
        key=lambda item: (
            item.get("priority_score", 0.0),
            item.get("cvss_score", 0.0),
        ),
        reverse=True,
    )
