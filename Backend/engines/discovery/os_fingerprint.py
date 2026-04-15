"""
engines/discovery/os_fingerprint.py
-------------------------------------
Priority 3-H: Multi-probe OS fingerprinting engine.

Sends nine carefully crafted probes against a confirmed-alive target and scores
the responses against a JSON signature database to produce a high-confidence OS
label.

Probes
------
T1  SYN with full TCP options (MSS, NOP, WScale, NOP, NOP, SAckOK, TS, EOL)
T2  SYN with no options, DF bit set
T3  SYN+FIN+URG+PSH  (abnormal flag combination)
T4  ACK to open port with DF bit
U1  UDP to known-closed port  (triggers ICMP type-3/code-3)
IE1 ICMP echo-request, code=9, TOS=0
IE2 ICMP echo-request, code=0, TOS=4   ← TOS-mirroring check
ECN SYN with CWR+ECE flags             ← NEW: ECN negotiation probe
OPS 3× quick SYNs                      ← NEW: IP.id sequence collection

Scoring dimensions (dynamic max: 13 base + up to 4 optional = 17 pts)
----------------------------------------------------------------------
  1. IP TTL from T1                          (2 pts)  — base
  2. TCP window from T1                      (2 pts)  — base
  3. DF bit from T1                          (1 pt)   — base
  4. ISN sequence class                      (2 pts)  — base
  5. T3 response class                       (1 pt)   — base
  6. T4 response class                       (1 pt)   — base
  7. ICMP TTL from IE1                       (1 pt)   — base
  8. TCP options ordered-subsequence match   (2 pts)  — base (FIXED)
  9. WScale value range                      (1 pt)   — base (no longer bonus)
 10. IP ID sequence class (from OPS)         (1 pt)   — optional
 11. SAckOK presence in T1 SYN-ACK          (1 pt)   — optional (now scored)
 12. IE2 TOS mirroring                       (1 pt)   — optional NEW
 13. ECN response class                      (1 pt)   — optional NEW
"""

import json
import logging
import os
import time
from typing import Dict, List, Optional, Tuple

from core.constants import SCAPY_AVAILABLE

log = logging.getLogger("ccure.osfingerprint")

# ---------------------------------------------------------------------------
# Signature database
# ---------------------------------------------------------------------------

_SIG_DB_PATH = os.path.join(os.path.dirname(__file__), "os_signatures.json")
_OS_SIGNATURES: List[Dict] = []


def _load_signatures() -> List[Dict]:
    global _OS_SIGNATURES
    if _OS_SIGNATURES:
        return _OS_SIGNATURES
    try:
        with open(_SIG_DB_PATH, "r", encoding="utf-8") as fh:
            _OS_SIGNATURES = json.load(fh)
        log.info("OS signature DB loaded: %d entries", len(_OS_SIGNATURES))
    except FileNotFoundError:
        log.warning("OS signature DB not found at %s — TTL fallback only", _SIG_DB_PATH)
        _OS_SIGNATURES = []
    except Exception as exc:
        log.warning("OS signature DB load error: %s", exc)
        _OS_SIGNATURES = []
    return _OS_SIGNATURES


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _classify_isn(isn_values: List[int]) -> str:
    """Determine the ISN generation class from observed sequence numbers."""
    if not isn_values:
        return "unknown"
    if all(v == 0 for v in isn_values):
        return "zero"
    unique = set(isn_values)
    if len(unique) == 1:
        return "constant"
    diffs = [isn_values[i + 1] - isn_values[i] for i in range(len(isn_values) - 1)]
    if diffs:
        avg = sum(diffs) / len(diffs)
        var = sum((d - avg) ** 2 for d in diffs) / len(diffs)
        if avg > 0 and var < avg * avg:
            return "time_based"
    return "random"


def _classify_ip_id(ip_id_values: List[int]) -> str:
    """
    Classify IP ID generation pattern from observed IP.id fields.

    Returns: ``"zero"`` / ``"constant"`` / ``"incremental"`` / ``"random"``

    Uses 16-bit wrap-around arithmetic for incremental detection.
    """
    if not ip_id_values or len(ip_id_values) < 2:
        return "unknown"
    if all(v == 0 for v in ip_id_values):
        return "zero"
    unique = set(ip_id_values)
    if len(unique) == 1:
        return "constant"
    diffs = [ip_id_values[i + 1] - ip_id_values[i] for i in range(len(ip_id_values) - 1)]
    # Handle 16-bit wrap-around
    wrapped = [d if d >= 0 else d + 65536 for d in diffs]
    if all(1 <= d <= 15 for d in wrapped):
        return "incremental"
    return "random"


def _extract_opt_names(tcp_layer) -> List[str]:
    """Return TCP option names in wire order, e.g. ``['MSS', 'NOP', 'WScale']``."""
    if tcp_layer is None or not getattr(tcp_layer, "options", None):
        return []
    return [name for name, _ in tcp_layer.options]


def _get_opt_val(tcp_layer, opt_name: str):
    """Return the value of a specific TCP option, or None."""
    if tcp_layer is None or not getattr(tcp_layer, "options", None):
        return None
    for name, val in tcp_layer.options:
        if name == opt_name:
            return val
    return None


def _opts_ordered_score(sig_opts: List[str], feat_opts: List[str]) -> int:
    """
    Score TCP option order match using **ordered-subsequence** matching.

    Walks ``feat_opts`` in wire order, advancing the signature pointer on each
    match.  This correctly differentiates Linux (MSS,SAckOK,TS,NOP,WScale) from
    Windows (MSS,NOP,WScale,SAckOK) even when both contain the same option names,
    because the relative ordering matters.

    Returns
    -------
    2 — sig_opts is a complete ordered subsequence of feat_opts
    1 — ≥ 60 % of sig options matched in order (partial credit)
    0 — poor match (< 60 %)
    """
    if not sig_opts or not feat_opts:
        return 0
    si = 0
    matched = 0
    for opt in feat_opts:
        if si < len(sig_opts) and opt == sig_opts[si]:
            matched += 1
            si += 1
    if len(sig_opts) == 0:
        return 0
    ratio = matched / len(sig_opts)
    if ratio >= 1.0:
        return 2
    if ratio >= 0.60:
        return 1
    return 0


def _max_score_for(sig: Dict) -> int:
    """
    Compute the maximum achievable score for a given signature entry.

    Base dimensions (always scored): 13 pts
    Optional new dimensions (scored only when sig specifies them): up to 4 pts
    """
    max_s = 13  # dims 1-9
    if sig.get("ip_id_class"):          # dim 10
        max_s += 1
    if sig.get("sack_ok") is not None:  # dim 11
        max_s += 1
    if sig.get("tos_mirror") is not None:  # dim 12
        max_s += 1
    if sig.get("ecn_response"):         # dim 13
        max_s += 1
    return max_s


# ---------------------------------------------------------------------------
# Main engine
# ---------------------------------------------------------------------------

class OSFingerprintEngine:
    """
    Multi-probe OS fingerprinting engine (Priority 3-H).

    Usage::

        engine = OSFingerprintEngine()
        result = engine.probe("192.168.1.1", open_port=80, closed_port=33333)
        # result -> {
        #   "os": "Linux 5.x (modern)",
        #   "confidence": "High",
        #   "match_score": 15,
        #   "details": { ... raw feature dict ... }
        # }

    The *open_port* should be a port confirmed open by prior TCP SYN scan.
    The *closed_port* should be a port confirmed closed / likely closed
    (used for the UDP ICMP-unreachable probe).
    """

    def probe(
        self,
        ip:           str,
        open_port:    int = 80,
        closed_port:  int = 33333,
    ) -> Dict:
        """Run all probes and score against the signature database."""
        if not SCAPY_AVAILABLE:
            log.debug("OSFingerprintEngine: Scapy unavailable for %s", ip)
            return {"os": "Unknown", "confidence": "Low", "match_score": 0, "details": {}}

        raw      = self._send_probes(ip, open_port, closed_port)
        features = self._extract_features(raw)
        label, conf, score = self._match_signatures(features)
        return {
            "os":          label,
            "confidence":  conf,
            "match_score": score,
            "details":     features,
        }

    # ------------------------------------------------------------------
    # Probe sending
    # ------------------------------------------------------------------

    def _send_probes(self, ip: str, open_port: int, closed_port: int) -> Dict:
        from scapy.all import IP, TCP, UDP, ICMP, sr1

        raw: Dict = {
            "t1": None, "t2": None, "t3": None,
            "t4": None, "u1": None, "ie1": None, "ie2": None,
            "ecn": None,
            "isn_values":   [],
            "ip_id_values": [],
        }

        _PAUSE = 0.10   # inter-probe gap — enough to dodge rate-limiters

        probes = [
            # (probe_key, packet_builder_lambda)
            ("t1", lambda: IP(dst=ip, flags="DF") / TCP(
                dport=open_port, flags="S",
                options=[
                    ("MSS",       1460),
                    ("NOP",       None),
                    ("WScale",    6),
                    ("NOP",       None),
                    ("NOP",       None),
                    ("SAckOK",    ""),
                    ("Timestamp", (0, 0)),
                    ("EOL",       None),
                ],
            )),
            ("t2",  lambda: IP(dst=ip, flags="DF") / TCP(dport=open_port, flags="S")),
            ("t3",  lambda: IP(dst=ip)              / TCP(dport=open_port, flags="SFUP")),
            ("t4",  lambda: IP(dst=ip, flags="DF") / TCP(dport=open_port, flags="A")),
            ("u1",  lambda: IP(dst=ip)              / UDP(dport=closed_port)),
            ("ie1", lambda: IP(dst=ip, tos=0)      / ICMP(type=8, code=9)),
            ("ie2", lambda: IP(dst=ip, tos=4)      / ICMP(type=8, code=0)),
            # ECN probe: SYN with CWR (0x80) + ECE (0x40) flags set
            ("ecn", lambda: IP(dst=ip)              / TCP(dport=open_port, flags=0xC2)),
        ]

        for key, build in probes:
            try:
                pkt  = build()
                resp = sr1(pkt, timeout=2, verbose=0)
                raw[key] = resp
                if resp is not None:
                    if resp.haslayer(TCP):
                        raw["isn_values"].append(int(resp[TCP].seq))
                    if resp.haslayer(IP):
                        raw["ip_id_values"].append(int(resp[IP].id))
                time.sleep(_PAUSE)
            except Exception as exc:
                log.debug("probe %s → %s error: %s", key, ip, exc)

        # OPS supplemental: 3 quick SYNs to collect IP.id sequence
        raw["ip_id_values"].extend(self._collect_ip_ids(ip, open_port))

        return raw

    @staticmethod
    def _collect_ip_ids(ip: str, open_port: int) -> List[int]:
        """
        Send 3 quick SYN probes and collect IP.id values.

        This mimics Nmap's OPS/WIN/ECN probes that fingerprint the IP ID
        counter behaviour (zero / constant / incremental / random).
        """
        from scapy.all import IP, TCP, sr1
        ids: List[int] = []
        for _ in range(3):
            try:
                resp = sr1(
                    IP(dst=ip) / TCP(dport=open_port, flags="S"),
                    timeout=1, verbose=0,
                )
                if resp is not None and resp.haslayer(IP):
                    ids.append(int(resp[IP].id))
                time.sleep(0.05)
            except Exception:
                pass
        return ids

    # ------------------------------------------------------------------
    # Feature extraction
    # ------------------------------------------------------------------

    def _extract_features(self, raw: Dict) -> Dict:
        from scapy.all import IP, TCP, UDP, ICMP

        f: Dict = {}

        # ── T1: crafted SYN ────────────────────────────────────────────
        t1 = raw.get("t1")
        if t1 and t1.haslayer(IP):
            f["t1_ttl"] = t1[IP].ttl
            f["t1_df"]  = bool(t1[IP].flags & 0x02)
            if t1.haslayer(TCP):
                f["t1_win"]     = t1[TCP].window
                f["t1_synack"]  = bool(t1[TCP].flags & 0x12)
                f["t1_opts"]    = _extract_opt_names(t1[TCP])
                ws = _get_opt_val(t1[TCP], "WScale")
                f["t1_wscale"]  = int(ws) if ws is not None else None
                f["t1_sack_ok"] = "SAckOK" in dict(t1[TCP].options or {})
        else:
            f["t1_synack"] = False

        # ── T2: plain SYN (no opts) ────────────────────────────────────
        t2 = raw.get("t2")
        if t2 and t2.haslayer(IP):
            f["t2_df"]     = bool(t2[IP].flags & 0x02)
            f["t2_synack"] = bool(t2.haslayer(TCP) and (t2[TCP].flags & 0x12))

        # ── T3: abnormal flags ─────────────────────────────────────────
        t3 = raw.get("t3")
        if t3 is None:
            f["t3_response"] = "none"
        elif t3.haslayer(TCP) and (t3[TCP].flags & 0x04):
            f["t3_response"] = "rst"
        else:
            f["t3_response"] = "other"

        # ── T4: ACK to open port ───────────────────────────────────────
        t4 = raw.get("t4")
        if t4 is None:
            f["t4_response"] = "none"
        elif t4.haslayer(TCP):
            flg = t4[TCP].flags
            if flg & 0x04:
                f["t4_response"] = "rst"
            elif flg & 0x12:
                f["t4_response"] = "synack"
            else:
                f["t4_response"] = "other"
        else:
            f["t4_response"] = "none"

        # ── U1: UDP → ICMP unreachable ─────────────────────────────────
        u1 = raw.get("u1")
        if u1 and u1.haslayer(ICMP):
            f["u1_icmp_type"] = u1[ICMP].type
            f["u1_icmp_code"] = u1[ICMP].code
            if u1.haslayer(IP):
                f["u1_ttl"] = u1[IP].ttl

        # ── IE1 / IE2: ICMP echo probes ────────────────────────────────
        for key, label in (("ie1", "ie1"), ("ie2", "ie2")):
            pkt = raw.get(key)
            if pkt and pkt.haslayer(ICMP) and pkt.haslayer(IP):
                f[f"{label}_ttl"]  = pkt[IP].ttl
                f[f"{label}_code"] = pkt[ICMP].code

        # ── IE2 TOS mirroring check ────────────────────────────────────
        # We sent IE2 with TOS=4.  BSD/macOS stacks mirror TOS back;
        # Linux and Windows zero it out.
        ie2 = raw.get("ie2")
        if ie2 and ie2.haslayer(IP):
            f["ie2_tos_mirror"] = (ie2[IP].tos == 4)

        # ── ECN response ───────────────────────────────────────────────
        ecn = raw.get("ecn")
        if ecn is None:
            f["ecn_response"] = "none"
        elif ecn.haslayer(TCP):
            flags = ecn[TCP].flags
            if flags & 0x04:    # RST
                f["ecn_response"] = "rst"
            elif flags & 0x12:  # SYN-ACK
                # ECE bit (0x40) present → host supports ECN
                f["ecn_response"] = "synack_ece" if (flags & 0x40) else "synack"
            else:
                f["ecn_response"] = "other"
        else:
            f["ecn_response"] = "none"

        # ── ISN sequence class ─────────────────────────────────────────
        f["isn_class"] = _classify_isn(raw.get("isn_values", []))

        # ── IP ID sequence class (OPS probes) ──────────────────────────
        f["ip_id_class"] = _classify_ip_id(raw.get("ip_id_values", []))

        return f

    # ------------------------------------------------------------------
    # Signature matching
    # ------------------------------------------------------------------

    def _match_signatures(self, features: Dict) -> Tuple[str, str, int]:
        """
        Score extracted features against every signature.

        Returns ``(os_label, confidence, best_score)``.

        Confidence thresholds (percentage of max achievable score):
            ≥ 78 %  → High
            ≥ 55 %  → Medium
            < 55 %  → Low  (label returned as ``"Unknown"``)
        """
        sigs = _load_signatures()
        if not sigs:
            return self._ttl_fallback(features)

        best_label = "Unknown"
        best_pct   = 0.0
        best_score = 0

        for sig in sigs:
            score  = self._score_one(features, sig)
            max_s  = _max_score_for(sig)
            pct    = score / max_s if max_s > 0 else 0.0
            if pct > best_pct:
                best_pct   = pct
                best_score = score
                best_label = sig.get("os", "Unknown")

        if best_pct >= 0.78:
            conf = "High"
        elif best_pct >= 0.55:
            conf = "Medium"
        else:
            conf       = "Low"
            best_label = "Unknown"

        return best_label, conf, best_score

    def _score_one(self, f: Dict, sig: Dict) -> int:
        """
        Compute a match score against one signature entry.

        Base dimensions (13 pts max)
        ─────────────────────────────
        1+2. TTL range          → 2 pts
          3. TCP window          → 2 pts
          4. DF bit              → 1 pt
          5. ISN class           → 2 pts
          6. T3 response         → 1 pt
          7. T4 response         → 1 pt
          8. ICMP TTL range      → 1 pt
          9. TCP opts order      → 2 pts  (ordered-subsequence, FIXED)
         10. WScale range        → 1 pt   (real dimension, not bonus, FIXED)

        Optional new dimensions (1 pt each when sig specifies them)
        ─────────────────────────────────────────────────────────────
        11. IP ID class
        12. SAckOK presence
        13. IE2 TOS mirror
        14. ECN response
        """
        score = 0

        # 1. TTL range  (2 pts)
        ttl = f.get("t1_ttl")
        if ttl is not None:
            lo, hi = sig.get("ttl_range", [0, 255])
            if lo <= ttl <= hi:
                score += 2

        # 2. TCP window  (2 pts)
        win = f.get("t1_win")
        if win is not None and win in sig.get("windows", []):
            score += 2

        # 3. DF bit  (1 pt)
        if "t1_df" in f and f["t1_df"] == sig.get("df_bit"):
            score += 1

        # 4. ISN class  (2 pts)
        if f.get("isn_class") == sig.get("isn_class"):
            score += 2

        # 5. T3 response  (1 pt)
        if f.get("t3_response") == sig.get("t3_response"):
            score += 1

        # 6. T4 response  (1 pt)
        if f.get("t4_response") == sig.get("t4_response"):
            score += 1

        # 7. ICMP TTL range  (1 pt)
        ie_ttl = f.get("ie1_ttl")
        if ie_ttl is not None:
            lo, hi = sig.get("icmp_ttl_range", [0, 255])
            if lo <= ie_ttl <= hi:
                score += 1

        # 8. TCP options order  (2 pts — ordered-subsequence, FIXED)
        score += _opts_ordered_score(
            sig.get("tcp_opts_order", []),
            f.get("t1_opts", []),
        )

        # 9. WScale range  (1 pt — real dimension, no longer bonus-only, FIXED)
        ws = f.get("t1_wscale")
        ws_range = sig.get("wscale_range")
        if ws is not None and ws_range:
            if ws_range[0] <= ws <= ws_range[1]:
                score += 1

        # ── Optional new dimensions ────────────────────────────────────

        # 10. IP ID class  (1 pt)
        sig_ip_id = sig.get("ip_id_class")
        if sig_ip_id and f.get("ip_id_class") == sig_ip_id:
            score += 1

        # 11. SAckOK presence  (1 pt)
        sig_sack = sig.get("sack_ok")
        if sig_sack is not None and f.get("t1_sack_ok") == sig_sack:
            score += 1

        # 12. IE2 TOS mirroring  (1 pt)
        sig_tos = sig.get("tos_mirror")
        if sig_tos is not None and f.get("ie2_tos_mirror") == sig_tos:
            score += 1

        # 13. ECN response  (1 pt)
        sig_ecn = sig.get("ecn_response")
        if sig_ecn and f.get("ecn_response") == sig_ecn:
            score += 1

        return score

    # ------------------------------------------------------------------
    # Fallback
    # ------------------------------------------------------------------

    @staticmethod
    def _ttl_fallback(features: Dict) -> Tuple[str, str, int]:
        """Simple TTL-bucket fallback when no signature DB is loaded."""
        ttl = features.get("t1_ttl")
        if ttl is None:
            return "Unknown", "Low", 0
        if ttl <= 64:
            return "Linux / Unix", "Low", 1
        if ttl <= 128:
            return "Windows", "Low", 1
        return "Network Appliance / Cisco", "Low", 1
