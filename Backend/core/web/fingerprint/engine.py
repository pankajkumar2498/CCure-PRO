"""
core/web/fingerprint/engine.py
────────────────────────────────────────────────────────────────────────────
Multi-source technology fingerprinting (Phase 16, Part B).

Phase 14 found the crawler's technology detection was header-only and so missed
the Juice Shop Angular stack (which advertises itself in the DOM, not in a
header). This widens the evidence base — headers, cookies, HTML/body markers,
static asset paths — while keeping the bar high: a technology is reported only
with a concrete piece of evidence and a confidence, and low-confidence guesses
are dropped rather than shown. It is fetch-free: it reasons over a response the
crawler already has, so it adds no requests and no latency per page.

Each result: {name, category, confidence (high|medium), evidence, version?}.
"""

from __future__ import annotations

import re
from typing import List, Optional

_VER = r"(\d+(?:\.\d+){0,3})"

# (header-name, value-regex, tech-name, category, confidence, version-group|None)
_HEADER_SIGS = [
    ("x-powered-by", r"PHP/?" + _VER + r"?", "PHP", "language", "high", 1),
    ("x-powered-by", r"Express", "Express", "framework", "high", None),
    ("x-powered-by", r"ASP\.NET", "ASP.NET", "framework", "high", None),
    ("x-powered-by", r"Next\.js", "Next.js", "framework", "high", None),
    ("x-aspnet-version", r"" + _VER, "ASP.NET", "framework", "high", 1),
    ("x-generator", r"Drupal[ /]?" + _VER + r"?", "Drupal", "cms", "high", 1),
    ("x-drupal-cache", r".", "Drupal", "cms", "high", None),
    ("x-shopify-stage", r".", "Shopify", "cms", "high", None),
    ("server", r"nginx/?" + _VER + r"?", "nginx", "server", "high", 1),
    ("server", r"Apache/?" + _VER + r"?", "Apache", "server", "high", 1),
    ("server", r"Microsoft-IIS/?" + _VER + r"?", "IIS", "server", "high", 1),
    ("server", r"gunicorn/?" + _VER + r"?", "gunicorn", "server", "high", 1),
    ("server", r"Werkzeug/?" + _VER + r"?", "Werkzeug/Flask", "framework", "high", 1),
    ("server", r"cloudflare", "Cloudflare", "cdn", "high", None),
]

# cookie-name-regex -> (tech, category, confidence)
_COOKIE_SIGS = [
    (r"^PHPSESSID$", ("PHP", "language", "high")),
    (r"^JSESSIONID$", ("Java", "language", "high")),
    (r"^laravel_session$", ("Laravel", "framework", "high")),
    (r"^laravel_", ("Laravel", "framework", "medium")),
    (r"^ci_session$", ("CodeIgniter", "framework", "high")),
    (r"^connect\.sid$", ("Express", "framework", "high")),
    (r"^csrftoken$|^django", ("Django", "framework", "medium")),
    (r"^_shopify_", ("Shopify", "cms", "high")),
    (r"^wordpress_|^wp-", ("WordPress", "cms", "high")),
    (r"^ASP\.NET_SessionId$", ("ASP.NET", "framework", "high")),
]

# (body-regex, tech, category, confidence, version-group|None)
_HTML_SIGS = [
    (
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
        "__generator__",
        "cms",
        "high",
        1,
    ),
    (r'\bng-version=["\']' + _VER, "Angular", "framework", "high", 1),
    (r"\bng-app\b|\bng-controller\b", "AngularJS", "framework", "high", None),
    (r"\bdata-reactroot\b|\bdata-reactid\b", "React", "framework", "high", None),
    (r"__NEXT_DATA__", "Next.js", "framework", "high", None),
    (r"window\.__NUXT__", "Nuxt.js", "framework", "high", None),
    (r"\bdata-v-[0-9a-f]{8}\b|window\.__VUE", "Vue.js", "framework", "medium"),
    (r"wp-content/|wp-includes/", "WordPress", "cms", "high", None),
    (r"Drupal\.settings|sites/(?:all|default)/", "Drupal", "cms", "high", None),
    (r"/_next/static/", "Next.js", "framework", "high", None),
    (r"csrf-param|data-turbo", "Ruby on Rails", "framework", "medium", None),
    (
        r"static/js/main\.[0-9a-f]+\.chunk\.js",
        "Create React App",
        "framework",
        "medium",
        None,
    ),
    (r"/sites/default/files/", "Drupal", "cms", "medium", None),
]


class TechFingerprinter:
    def fingerprint(
        self,
        url: str,
        status: int,
        headers: Optional[dict] = None,
        cookies: Optional[dict] = None,
        html: str = "",
    ) -> List[dict]:
        headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
        out: List[dict] = []

        def add(name, category, confidence, evidence, version=None):
            out.append(
                {
                    "name": name,
                    "category": category,
                    "confidence": confidence,
                    "evidence": evidence[:160],
                    "version": version,
                }
            )

        # ── headers ──
        for hname, rx, tech, cat, conf, vg in _HEADER_SIGS:
            val = headers.get(hname)
            if not val:
                continue
            m = re.search(rx, val, re.I)
            if m:
                ver = m.group(vg) if vg and m.lastindex and m.lastindex >= vg else None
                add(tech, cat, conf, f"{hname}: {val}", ver)

        # ── cookies ──
        for cname in cookies or {}:
            for rx, (tech, cat, conf) in _COOKIE_SIGS:
                if re.search(rx, cname, re.I):
                    add(tech, cat, conf, f"cookie: {cname}")

        # ── html / asset markers ──
        body = html or ""
        for entry in _HTML_SIGS:
            rx, tech, cat, conf = entry[0], entry[1], entry[2], entry[3]
            vg = entry[4] if len(entry) > 4 else None
            m = re.search(rx, body, re.I)
            if not m:
                continue
            if tech == "__generator__":
                gen = m.group(1)
                gm = re.match(r"^(.*?)[ /]v?" + _VER, gen)
                if gm:
                    name, ver = gm.group(1).strip()[:40], gm.group(2)
                else:
                    name, ver = (gen.split() or [gen])[0][:40], None
                add(name, "cms", "high", f"meta generator: {gen}", ver)
            else:
                ver = m.group(vg) if vg and m.lastindex and m.lastindex >= vg else None
                add(tech, cat, conf, f"body marker: {m.group(0)[:60]}", ver)

        return dedupe(out)


def dedupe(techs: List[dict]) -> List[dict]:
    """One entry per technology name: keep the highest confidence, prefer a
    version, and merge evidence so multiple sources reinforce one result."""
    rank = {"high": 2, "medium": 1}
    best: dict = {}
    for t in techs:
        key = t["name"].lower()
        cur = best.get(key)
        if cur is None:
            best[key] = dict(t, evidence=[t["evidence"]])
            continue
        cur["evidence"].append(t["evidence"])
        if rank.get(t["confidence"], 0) > rank.get(cur["confidence"], 0):
            cur["confidence"] = t["confidence"]
        if t.get("version") and not cur.get("version"):
            cur["version"] = t["version"]
    # collapse evidence list to a joined, de-duplicated string
    result = []
    for t in best.values():
        ev = "; ".join(dict.fromkeys(t["evidence"]))
        result.append({**t, "evidence": ev})
    return result
