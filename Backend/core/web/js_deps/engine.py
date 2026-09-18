"""
core/web/js_deps/engine.py
────────────────────────────────────────────────────────────────────────────
Vulnerable JavaScript dependency detection (Phase 7).

Collects the JavaScript a page loads — <script src> and inline banners —
identifies the library and version, and matches the version against the
vulnerability intelligence CCureAudit already carries (the OSV feed in
vuln_intel, npm ecosystem). It invents no CVEs: an identifier is reported only
when OSV lists an advisory whose affected range actually contains the detected
version. Severity, CVSS and CWE are enriched from the NVD-backed
vulnerability_definitions catalogue when the CVE is present there; nothing is
fabricated when it is not.

Network use is bounded: each unique script URL is fetched at most once (capped),
and version detection prefers the URL/filename so many libraries need no fetch
at all.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

log = logging.getLogger("ccure.web.jsdeps")

_VER = r"(\d+\.\d+(?:\.\d+)?)"

#: name → npm package + URL token(s) + content banner regex(es).
KNOWN_LIBS = [
    {
        "name": "jquery",
        "npm": "jquery",
        "url": [r"jquery"],
        "banner": [r"jQuery(?: JavaScript Library)?\s+v?" + _VER],
    },
    {
        "name": "jquery-ui",
        "npm": "jquery-ui",
        "url": [r"jquery[.\-]ui"],
        "banner": [r"jQuery UI[ \-]v?" + _VER],
    },
    {
        "name": "jquery-migrate",
        "npm": "jquery-migrate",
        "url": [r"jquery[.\-]migrate"],
        "banner": [r"jQuery Migrate[ \-]v?" + _VER],
    },
    {
        "name": "angularjs",
        "npm": "angular",
        "url": [r"angular"],
        "banner": [r"AngularJS v" + _VER],
    },
    {"name": "vue", "npm": "vue", "url": [r"vue"], "banner": [r"Vue\.js v" + _VER]},
    {
        "name": "react",
        "npm": "react",
        "url": [r"react(?![.\-]dom)"],
        "banner": [r"React v" + _VER],
    },
    {
        "name": "lodash",
        "npm": "lodash",
        "url": [r"lodash"],
        "banner": [r"[Ll]odash[ /]" + _VER, r"VERSION\s*=\s*['\"]" + _VER + r"['\"]"],
    },
    {
        "name": "bootstrap",
        "npm": "bootstrap",
        "url": [r"bootstrap"],
        "banner": [r"Bootstrap v" + _VER],
    },
    {
        "name": "moment",
        "npm": "moment",
        "url": [r"moment"],
        "banner": [r"version['\":=\s]+" + _VER],
    },
    {
        "name": "handlebars",
        "npm": "handlebars",
        "url": [r"handlebars"],
        "banner": [r"Handlebars[^0-9]*v?" + _VER],
    },
    {
        "name": "underscore",
        "npm": "underscore",
        "url": [r"underscore"],
        "banner": [r"[Uu]nderscore[^0-9]*" + _VER],
    },
    {
        "name": "dompurify",
        "npm": "dompurify",
        "url": [r"purify"],
        "banner": [r"DOMPurify[^0-9]*" + _VER],
    },
    {
        "name": "axios",
        "npm": "axios",
        "url": [r"axios"],
        "banner": [r"axios[^0-9]*v?" + _VER],
    },
]
_SCRIPT_SRC = re.compile(r"<script\b[^>]*\bsrc\s*=\s*['\"]([^'\"]+)['\"]", re.I)
_INLINE = re.compile(r"<script\b(?![^>]*\bsrc)[^>]*>(.*?)</script>", re.I | re.S)


def _ver_tuple(v: str):
    parts = re.split(r"[.\-+]", v.strip())
    out = []
    for p in parts[:3]:
        m = re.match(r"\d+", p)
        out.append(int(m.group(0)) if m else 0)
    while len(out) < 3:
        out.append(0)
    return tuple(out)


def detect_from_url(url: str):
    """(name, npm, version) from a script URL, or None. No network."""
    path = urlparse(url).path.lower() + "?" + (urlparse(url).query or "")
    for lib in KNOWN_LIBS:
        if not any(re.search(tok, path) for tok in lib["url"]):
            continue
        # cdnjs: /ajax/libs/<name>/<ver>/ ; unpkg/jsdelivr: <name>@<ver>
        for pat in (
            r"/" + lib["name"] + r"/" + _VER + r"/",
            lib["name"] + r"@" + _VER,
            lib["name"] + r"[.\-]" + _VER,
            r"[?&]ver(?:sion)?=" + _VER,
        ):
            m = re.search(pat, path)
            if m:
                return lib["name"], lib["npm"], m.group(1)
    return None


def detect_from_content(content: str):
    """(name, npm, version) from a JS body banner, or None."""
    head = (content or "")[:4000]
    for lib in KNOWN_LIBS:
        for pat in lib.get("banner", []):
            m = re.search(pat, head)
            if m:
                return lib["name"], lib["npm"], m.group(1)
    return None


class JsDependencyEngine:
    def __init__(
        self,
        *,
        timeout_s: float = 12.0,
        max_scripts: int = 25,
        max_pages: int = 5,
        verify_tls: bool = False,
        osv_query=None,
        cve_enrich=None,
    ) -> None:
        self.timeout_s = timeout_s
        self.max_scripts = max_scripts
        self.max_pages = max_pages
        self.verify_tls = verify_tls
        # Injectable for tests; default to the live feeds.
        self._osv_query = osv_query or self._osv_npm_advisories
        self._cve_enrich = cve_enrich or self._enrich_cve
        self.stats: Dict[str, Any] = {
            "pages": 0,
            "scripts": 0,
            "libraries": 0,
            "requests": 0,
            "findings": 0,
            "duration_s": 0.0,
        }

    def is_available(self) -> bool:
        try:
            import httpx  # noqa: F401

            return True
        except Exception:
            return False

    async def scan(
        self,
        target_url,
        endpoints=None,
        auth_headers=None,
        auth_cookies=None,
        progress_cb=None,
        cancel_cb=None,
    ) -> Dict[str, Any]:
        t0 = time.monotonic()
        findings: List[dict] = []
        if not self.is_available():
            return {"findings": findings, "stats": self.stats, "available": False}
        import httpx

        pages = [target_url] + [
            e.get("url")
            for e in (endpoints or [])
            if isinstance(e, dict)
            and e.get("url")
            and str(e.get("content_type", "")).startswith("text/html")
        ]
        # De-dup pages, cap.
        seen_pages, page_list = set(), []
        for p in pages:
            k = p.split("#")[0]
            if k not in seen_pages:
                seen_pages.add(k)
                page_list.append(k)
        page_list = page_list[: self.max_pages]

        script_urls: dict[str, Optional[str]] = {}  # url -> inline content or None
        inline_scripts: List[str] = []
        async with httpx.AsyncClient(
            verify=self.verify_tls,
            timeout=self.timeout_s,
            follow_redirects=True,
            headers={
                k: v for k, v in (auth_headers or {}).items() if k.lower() != "cookie"
            }
            or None,
            cookies=auth_cookies or None,
        ) as client:
            for page in page_list:
                if cancel_cb and cancel_cb():
                    break
                try:
                    r = await client.get(page)
                    self.stats["requests"] += 1
                    self.stats["pages"] += 1
                except Exception:
                    continue
                html = r.text or ""
                for src in _SCRIPT_SRC.findall(html):
                    script_urls.setdefault(urljoin(page, src), None)
                for body in _INLINE.findall(html):
                    if body.strip():
                        inline_scripts.append(body[:4000])

            # Identify libraries. Prefer URL detection (no fetch).
            libs: dict[tuple, str] = {}  # (name, version) -> resource url
            for url in list(script_urls)[: self.max_scripts]:
                if cancel_cb and cancel_cb():
                    break
                det = detect_from_url(url)
                if not det:
                    # Fetch content for a banner only when the URL was unhelpful.
                    try:
                        jr = await client.get(url)
                        self.stats["requests"] += 1
                        det = detect_from_content(jr.text or "")
                    except Exception:
                        det = None
                if det:
                    name, npm, ver = det
                    libs.setdefault((name, npm, ver), url)
                self.stats["scripts"] += 1
            for body in inline_scripts:
                det = detect_from_content(body)
                if det:
                    name, npm, ver = det
                    libs.setdefault((name, npm, ver), target_url + " (inline)")

        self.stats["libraries"] = len(libs)

        # Match versions against OSV, enrich, dedup by (library, version, vuln).
        seen_findings: set = set()
        for (name, npm, ver), resource in libs.items():
            try:
                advisories = self._osv_query(npm, ver)
            except Exception as exc:
                log.debug("OSV query failed for %s@%s: %s", npm, ver, exc)
                advisories = []
            for adv in advisories:
                vid = adv.get("cve") or adv.get("osv_id")
                if not vid:
                    continue
                key = (name, ver, vid)
                if key in seen_findings:
                    continue
                seen_findings.add(key)
                enrich = {}
                if adv.get("cve"):
                    try:
                        enrich = self._cve_enrich(adv["cve"]) or {}
                    except Exception:
                        enrich = {}
                findings.append(self._finding(name, npm, ver, resource, adv, enrich))

        self.stats["findings"] = len(findings)
        self.stats["duration_s"] = round(time.monotonic() - t0, 2)
        return {"findings": findings, "stats": self.stats, "available": True}

    # ── OSV npm matching (live feed) ───────────────────────────────────────────
    @staticmethod
    def _osv_npm_advisories(npm_pkg: str, version: str) -> List[dict]:
        from sqlalchemy import text as _text

        from core.vuln_intel import get_vuln_engine

        eng = get_vuln_engine()
        with eng.connect() as conn:
            rows = conn.execute(
                _text(
                    """
                SELECT o.id AS osv_id, r.introduced, r.fixed, a.cve_id
                  FROM osv o
                  JOIN osv_ranges r ON r.osv_id = o.id
             LEFT JOIN osv_aliases a ON a.osv_id = o.id
                 WHERE r.ecosystem = 'npm'
                   AND lower(r.package_name) = lower(:pkg)
                """
                ),
                {"pkg": npm_pkg},
            ).fetchall()
        # Group ranges + aliases per advisory.
        adv: dict[str, dict] = {}
        for osv_id, introduced, fixed, cve_id in rows:
            a = adv.setdefault(osv_id, {"osv_id": osv_id, "ranges": [], "cves": set()})
            a["ranges"].append((introduced, fixed))
            if cve_id:
                a["cves"].add(cve_id)
        out = []
        for a in adv.values():
            if JsDependencyEngine._affected(version, a["ranges"]):
                cve = sorted(a["cves"])[0] if a["cves"] else None
                fixed_versions = sorted(
                    {f for _, f in a["ranges"] if f}, key=_ver_tuple
                )
                out.append(
                    {
                        "osv_id": a["osv_id"],
                        "cve": cve,
                        "fixed": fixed_versions[0] if fixed_versions else None,
                    }
                )
        return out

    @staticmethod
    def _affected(version: str, ranges: List[tuple]) -> bool:
        v = _ver_tuple(version)
        for introduced, fixed in ranges:
            lo_ok = (
                not introduced
                or introduced in ("0", "0.0.0")
                or v >= _ver_tuple(introduced)
            )
            hi_ok = (not fixed) or v < _ver_tuple(fixed)
            if lo_ok and hi_ok:
                return True
        return False

    @staticmethod
    def _enrich_cve(cve_id: str) -> dict:
        """CVSS / severity / CWE from the NVD-backed catalogue (best effort)."""
        from sqlalchemy import text as _text

        from db.base import SessionLocal

        db = SessionLocal()
        try:
            row = db.execute(
                _text(
                    """
                SELECT COALESCE(cvss_v3_score, cvss_v4_score, cvss_v2_score) AS cvss,
                       severity, cwe_ids, cvss_vector
                  FROM vulnerability_definitions
                 WHERE cve_id = :cve
                 LIMIT 1
                """
                ),
                {"cve": cve_id},
            ).first()
        finally:
            db.close()
        if not row:
            return {}
        cwe = row[2]
        if isinstance(cwe, str):
            try:
                import json as _json

                cwe = _json.loads(cwe)
            except Exception:
                cwe = [cwe]
        return {
            "cvss": row[0],
            "severity": row[1],
            "cwe": (cwe[0] if isinstance(cwe, list) and cwe else None),
            "cvss_vector": row[3],
        }

    _SEV_BY_CVSS = [(9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.1, "low")]

    def _sev(self, enrich) -> str:
        if enrich.get("severity"):
            return str(enrich["severity"]).lower()
        cvss = enrich.get("cvss")
        if cvss is not None:
            for lo, name in self._SEV_BY_CVSS:
                if float(cvss) >= lo:
                    return name
        return "medium"  # known-vulnerable but unrated — not "none"

    def _finding(self, name, npm, ver, resource, adv, enrich) -> dict:
        cve = adv.get("cve")
        vid = cve or adv.get("osv_id")
        fixed = adv.get("fixed")
        sev = self._sev(enrich)
        cvss = enrich.get("cvss")
        cwe = enrich.get("cwe")
        remediation = (
            f"Upgrade {name} from {ver} to {fixed} or later."
            if fixed
            else f"Upgrade {name} from {ver} to a patched release; consult the "
            f"advisory ({vid})."
        )
        return {
            "finding_type": "vulnerable_js_library",
            "title": f"Vulnerable JavaScript library: {name} {ver} ({vid})"[:255],
            "description": (
                f"The page loads {name} version {ver}, which is affected by "
                f"{vid}"
                + (f" (fixed in {fixed})" if fixed else "")
                + f". Detected from {resource}. Matched against the OSV npm "
                f"advisory feed; "
                + (
                    f"CVSS {cvss} per the NVD catalogue."
                    if cvss is not None
                    else "no published CVSS in the local catalogue."
                )
            ),
            "severity": sev,
            "detected_by": "ccure-js-deps",
            "cwe_id": cwe,
            "cve_id": cve,
            "cvss_score": float(cvss) if cvss is not None else None,
            "cvss_vector": enrich.get("cvss_vector"),
            "matched_at": resource,
            "request_url": resource,
            "request_method": "GET",
            "payload_used": f"{npm}@{ver}",
            "response_evidence": (
                f"library={name}; version={ver}; npm={npm}; advisory={vid}; "
                f"fixed={fixed or 'unknown'}; source=OSV"
            ),
            "remediation": remediation,
            "reference_links": (
                [f"https://osv.dev/vulnerability/{adv.get('osv_id')}"]
                if adv.get("osv_id")
                else []
            ),
            "is_verified": True,
            "confidence": "confirmed",
            "source": "OSV",
        }
