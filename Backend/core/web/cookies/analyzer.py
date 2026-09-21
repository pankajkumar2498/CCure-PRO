"""
core/web/cookies/analyzer.py
────────────────────────────────────────────────────────────────────────────
Cookie security analysis (Phase 17).

Phase 14 found cookie-flag security was not actually assessed anywhere. This
adds it, deliberately narrow to avoid the false positives that make such a check
worthless: it does NOT flag every cookie the same way. A cookie is classified
first, and only a *sensitive* one (session / authentication / token / CSRF) is
held to the Secure / HttpOnly / SameSite bar. An ordinary preference cookie is
left alone — a site legitimately reads those from JavaScript, so flagging their
missing HttpOnly trains readers to ignore the category.

Evidence never includes the cookie value (it may be a live session token); only
the name and the flag attributes are reported.

Findings use finding_type "insecure_cookie" with the specific CWE per weakness:
  CWE-614  Sensitive cookie without the Secure attribute
  CWE-1004 Sensitive cookie without the HttpOnly attribute
  CWE-1275 Sensitive cookie with a weak/absent SameSite policy
"""

from __future__ import annotations

import re
from typing import List, Optional

# A cookie whose name looks like it carries a session, identity, or anti-CSRF
# token — the cookies whose theft or misuse actually matters.
_SENSITIVE_NAME = re.compile(
    # \bsid\b matches "sid" / "connect.sid" but not "sidebar"; the rest are
    # substrings that reliably indicate a session/identity/CSRF cookie.
    r"(sess|\bsid\b|auth|token|jwt|sso|login|remember|csrf|xsrf|access|refresh)",
    re.I,
)


def classify_cookie(name: str) -> str:
    """'sensitive' (session/auth/token/csrf) or 'preference' (ordinary)."""
    return "sensitive" if _SENSITIVE_NAME.search(name or "") else "preference"


def parse_set_cookie(line: str) -> Optional[dict]:
    """
    Parse one Set-Cookie header value into {name, secure, httponly, samesite}.
    The cookie VALUE is intentionally discarded — it is never needed for the
    security verdict and may be a secret.
    """
    if not line or "=" not in line:
        return None
    parts = [p.strip() for p in line.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    if not name:
        return None
    attrs = {
        p.split("=", 1)[0]
        .strip()
        .lower(): (p.split("=", 1)[1].strip() if "=" in p else True)
        for p in parts[1:]
    }
    samesite = attrs.get("samesite")
    return {
        "name": name,
        "secure": "secure" in attrs,
        "httponly": "httponly" in attrs,
        "samesite": (str(samesite).lower() if isinstance(samesite, str) else None),
    }


def split_set_cookie_header(raw) -> List[str]:
    """
    Split a possibly-folded Set-Cookie header into individual cookie lines.
    httpx exposes them separately via get_list; a single joined string is split
    on the comma that precedes a new ``name=`` (not the comma inside Expires).
    """
    if isinstance(raw, (list, tuple)):
        return [str(x) for x in raw if x]
    s = str(raw or "")
    if not s:
        return []
    # Split before a token that looks like the start of a new cookie.
    return [c for c in re.split(r",(?=\s*[^;,\s]+=)", s) if c.strip()]


def analyze_cookies(
    set_cookie_headers,
    is_https: bool,
    matched_at: str = "",
) -> List[dict]:
    """
    Findings for the sensitive cookies in a set of Set-Cookie headers. Ordinary
    preference cookies are not flagged (see module docstring).
    """
    findings: List[dict] = []
    seen: set = set()
    for line in split_set_cookie_header(set_cookie_headers):
        c = parse_set_cookie(line)
        if not c or c["name"] in seen:
            continue
        seen.add(c["name"])
        if classify_cookie(c["name"]) != "sensitive":
            continue  # do not flag preference cookies — avoids the FP flood

        base = {
            "matched_at": matched_at,
            "request_url": matched_at,
            "detected_by": "ccure-cookies",
            "is_verified": True,
        }
        # Missing HttpOnly — the session cookie is reachable from JavaScript,
        # so an XSS can exfiltrate it.
        if not c["httponly"]:
            findings.append(
                {
                    **base,
                    "finding_type": "insecure_cookie",
                    "cwe_id": "CWE-1004",
                    "severity": "medium",
                    "title": f"Session cookie '{c['name']}' missing HttpOnly",
                    "description": (
                        f"The sensitive cookie '{c['name']}' is set without the "
                        f"HttpOnly attribute, so client-side JavaScript can read it "
                        f"— a cross-site scripting flaw could steal the session."
                    ),
                    "remediation": "Set the HttpOnly attribute on session/auth cookies.",
                    "payload_used": _sanitized(c),
                }
            )
        # Missing Secure over HTTPS — the cookie can be sent over plaintext.
        if is_https and not c["secure"]:
            findings.append(
                {
                    **base,
                    "finding_type": "insecure_cookie",
                    "cwe_id": "CWE-614",
                    "severity": "medium",
                    "title": f"Session cookie '{c['name']}' missing Secure",
                    "description": (
                        f"The sensitive cookie '{c['name']}' is served over HTTPS "
                        f"without the Secure attribute, so it can be transmitted "
                        f"over an unencrypted connection and intercepted."
                    ),
                    "remediation": "Set the Secure attribute on cookies served over HTTPS.",
                    "payload_used": _sanitized(c),
                }
            )
        # Weak/absent SameSite — CSRF exposure. SameSite=None is only acceptable
        # with Secure; absent defaults are treated leniently (browsers default
        # to Lax), so only None-without-Secure is flagged to avoid noise.
        if c["samesite"] == "none" and not c["secure"]:
            findings.append(
                {
                    **base,
                    "finding_type": "insecure_cookie",
                    "cwe_id": "CWE-1275",
                    "severity": "low",
                    "title": f"Session cookie '{c['name']}' uses SameSite=None without Secure",
                    "description": (
                        f"The sensitive cookie '{c['name']}' declares SameSite=None "
                        f"without Secure, which browsers reject and which removes "
                        f"cross-site request protection."
                    ),
                    "remediation": "Use SameSite=Lax or Strict, or None only with Secure.",
                    "payload_used": _sanitized(c),
                }
            )
    return findings


def _sanitized(c: dict) -> str:
    """A value-free description of the cookie's flags, safe to store."""
    return (
        f"{c['name']}; Secure={c['secure']}; HttpOnly={c['httponly']}; "
        f"SameSite={c['samesite'] or 'unset'}"
    )
