"""
core/web/js_routes.py
────────────────────────────────────────────────────────────────────────────
Static route/endpoint extraction from JavaScript bundles (Phase 22, Codex
item 5 — Crawler 2.0).

The audit found that the crawler discovered API calls only when the browser
*executed* them; endpoints hardcoded in a bundle but never triggered (a route
behind a button the crawl did not click, an admin API the current user cannot
reach) stayed invisible. Burp/Acunetix mine the JS source for these.

This extracts URL/path literals from JavaScript *source* — so an unexecuted
``fetch("/api/admin/users")`` in a bundle becomes part of the attack surface.
It is deliberately conservative (same-origin, plausible-path only) to avoid
turning every string constant into a phantom endpoint.
"""

from __future__ import annotations

import base64
import json
import re
from typing import List, Optional
from urllib.parse import urljoin, urlparse

#: A source-map reference comment at the tail of a bundle:
#: ``//# sourceMappingURL=app.js.map`` or an inline ``data:`` URI.
_SOURCEMAP_RE = re.compile(r"""[#@]\s*sourceMappingURL\s*=\s*(\S+)""", re.IGNORECASE)

# Ordered from most to least specific. Group 1 is always the URL/path.
_PATTERNS = [
    # fetch / axios / XHR call with a string URL
    re.compile(
        r"""(?:fetch|axios(?:\.\w+)?|XMLHttpRequest|\.open)\s*\(\s*['"`]([^'"`]+)['"`]"""
    ),
    # url/endpoint/api/path/route: "literal"
    re.compile(
        r"""(?:url|uri|endpoint|api|apiUrl|baseURL|path|route)\s*[:=]\s*['"`]([^'"`]+)['"`]""",
        re.IGNORECASE,
    ),
    # SPA router route definitions: path: "/x", { path: '/x' }
    re.compile(r"""path\s*:\s*['"`](/[^'"`]*)['"`]"""),
    # <Route path="/x"> (React Router in JSX-in-bundle)
    re.compile(r"""[Rr]oute[^>]{0,40}?path\s*=\s*['"`](/[^'"`]*)['"`]"""),
    # router.push/replace/navigate("/x")
    re.compile(r"""(?:push|replace|navigate|redirect)\s*\(\s*['"`](/[^'"`]+)['"`]"""),
    # an explicit HTTP verb followed by a path
    re.compile(r"""(?:GET|POST|PUT|DELETE|PATCH)\s*['"`]\s*(/[^'"`\s]+)"""),
    # a bare API-looking path literal anywhere in the source
    re.compile(r"""['"`](/(?:api|v\d+|rest|graphql|internal|admin)/[^'"`\s?]*)['"`]"""),
]

#: Not real endpoints even though they parse as paths.
_SKIP_SUFFIX = (
    ".js",
    ".css",
    ".map",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".webp",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".otf",
    ".mp4",
    ".webm",
)
_MIME_RE = re.compile(r"^(?:text|image|application|audio|video|font)/")


def _plausible(path: str) -> bool:
    if not path or len(path) > 300:
        return False
    low = path.lower()
    if low.endswith(_SKIP_SUFFIX):
        return False
    if _MIME_RE.match(path):
        return False
    # A template placeholder that never resolves to a real path.
    if path in ("/", "//") or "${" in path or "{{" in path:
        return False
    return path.startswith("/") or path.startswith("http")


def extract_js_routes(js_text: str, base_url: str) -> List[str]:
    """
    Absolute, same-origin URLs referenced in JavaScript source. De-duplicated.
    Cross-origin and implausible strings are dropped.
    """
    if not js_text:
        return []
    origin = urlparse(base_url).netloc
    found: dict = {}
    for pat in _PATTERNS:
        for m in pat.finditer(js_text):
            raw = (m.group(1) or "").strip()
            if not _plausible(raw):
                continue
            if raw.startswith("http"):
                if urlparse(raw).netloc != origin:
                    continue
                url = raw
            else:
                url = urljoin(base_url, raw)
            # strip a trailing template fragment / query for the surface key
            url = url.split("#")[0]
            found.setdefault(url.split("?")[0], url)
    return list(found.values())


def route_endpoints(js_text: str, base_url: str) -> List[dict]:
    """extract_js_routes as endpoint dicts tagged with the js_static source."""
    return [
        {
            "url": u,
            "method": "GET",
            "source": "js_static",
            "content_type": "",
            "response_code": None,
        }
        for u in extract_js_routes(js_text, base_url)
    ]


# ── source maps (Codex item 9) ──────────────────────────────────────────────────
def sourcemap_ref(js_text: str) -> Optional[str]:
    """The last ``sourceMappingURL`` reference in a bundle, if any (a bundle may
    carry several concatenated; the effective one is the last)."""
    if not js_text:
        return None
    refs = _SOURCEMAP_RE.findall(js_text)
    return refs[-1].strip() if refs else None


def resolve_sourcemap_url(ref: str, bundle_url: str) -> Optional[str]:
    """Resolve a sourceMappingURL reference to an absolute URL, or None for an
    inline ``data:`` map (which is decoded by ``inline_sourcemap`` instead)."""
    if not ref or ref.startswith("data:"):
        return None
    return urljoin(bundle_url, ref)


def inline_sourcemap(ref: str) -> Optional[str]:
    """Decode an inline ``data:`` source-map reference to its JSON text."""
    if not ref or not ref.startswith("data:"):
        return None
    try:
        header, _, payload = ref.partition(",")
        if ";base64" in header:
            return base64.b64decode(payload).decode("utf-8", "replace")
        from urllib.parse import unquote

        return unquote(payload)
    except Exception:
        return None


def parse_sourcemap(map_text: str) -> dict:
    """Parse a source map, returning ``{"sources": [...], "sourcesContent": [...]}``.
    Only ``safe_load``-equivalent JSON parsing; no code is executed."""
    try:
        data = json.loads(map_text) if isinstance(map_text, str) else map_text
    except Exception:
        return {"sources": [], "sourcesContent": []}
    if not isinstance(data, dict):
        return {"sources": [], "sourcesContent": []}
    src = data.get("sources")
    content = data.get("sourcesContent")
    return {
        "sources": (
            [s for s in src if isinstance(s, str)] if isinstance(src, list) else []
        ),
        "sourcesContent": (
            [c for c in content if isinstance(c, str)]
            if isinstance(content, list)
            else []
        ),
    }


def routes_from_sourcemap(map_text: str, base_url: str) -> List[str]:
    """
    Mine routes/endpoints from a source map's original (pre-minification)
    sources. ``sourcesContent`` is the original code the app was written in —
    far cleaner to extract from than a minified bundle — so a route that
    survived minification as an opaque string is recovered here in its original
    form. Falls back to nothing when the map carries no embedded content.
    """
    parsed = parse_sourcemap(map_text)
    found: dict = {}
    for content in parsed.get("sourcesContent") or []:
        for url in extract_js_routes(content, base_url):
            found.setdefault(url.split("?")[0], url)
    return list(found.values())
