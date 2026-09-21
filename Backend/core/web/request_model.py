"""
core/web/request_model.py
────────────────────────────────────────────────────────────────────────────
Unified request-reconstruction model (Phase 22, Codex P0 item 4).

Every vulnerability engine should receive a *normalised request*, not just a
URL: the method, headers, cookies, body, content-type, the parameter locations
it carries, the authenticated identity it was captured under, and a way to
replay it. Without this, engines re-derive candidates narrowly and lose the
auth context and body that make a modern request testable (the Phase 20/21
audit's finding).

``WebRequest`` is that model. It is deliberately a thin, dependency-light value
object built from the endpoints/forms the crawl already produces, plus the
session's auth headers/cookies. It can:

  * enumerate its parameters by location (query / json / form / path),
  * clone itself with one parameter replaced (for a probe),
  * replay itself over httpx,
  * serialise to a raw HTTP request (for ``sqlmap -r``) and to a curl command
    (for finding reproduction).

It does not itself decide *what* to inject — engines do — and it stores no
secrets beyond the auth material an authenticated scan is already using.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode, urlparse, urlunparse

from core.web import surface


@dataclass
class WebRequest:
    method: str = "GET"
    url: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    content_type: Optional[str] = None
    #: {location: [param names]} — query / json / form / path
    params: Dict[str, List[str]] = field(default_factory=dict)
    #: label of the identity this request was captured/authenticated under
    auth_context: Optional[str] = None
    source: str = "crawler"

    # ── construction ─────────────────────────────────────────────────────────
    @classmethod
    def from_endpoint(
        cls,
        endpoint: Dict[str, Any],
        auth_headers: Optional[Dict[str, str]] = None,
        auth_cookies: Optional[Dict[str, str]] = None,
        auth_context: Optional[str] = None,
    ) -> "WebRequest":
        url = endpoint.get("url", "") or ""
        body = endpoint.get("request_body")
        ctype = endpoint.get("request_content_type") or (
            "application/json" if surface.parse_json_object(body) else None
        )
        headers = dict(auth_headers or {})
        return cls(
            method=str(endpoint.get("method") or "GET").upper(),
            url=url,
            headers=headers,
            cookies=dict(auth_cookies or {}),
            body=body,
            content_type=ctype,
            params=endpoint.get("parameters") or surface.describe_parameters(endpoint),
            auth_context=auth_context,
            source=endpoint.get("source", "crawler"),
        )

    @classmethod
    def from_form(
        cls,
        form: Dict[str, Any],
        auth_headers: Optional[Dict[str, str]] = None,
        auth_cookies: Optional[Dict[str, str]] = None,
        auth_context: Optional[str] = None,
    ) -> "WebRequest":
        method = str(form.get("method") or "GET").upper()
        names = [
            i.get("name")
            for i in form.get("inputs") or []
            if isinstance(i, dict) and i.get("name")
        ]
        body = "&".join(f"{n}=1" for n in names) if method == "POST" else None
        return cls(
            method=method,
            url=form.get("url", ""),
            headers=dict(auth_headers or {}),
            cookies=dict(auth_cookies or {}),
            body=body,
            content_type=("application/x-www-form-urlencoded" if body else None),
            params={"form": names} if names else {},
            auth_context=auth_context,
            source="form",
        )

    # ── parameters ───────────────────────────────────────────────────────────
    def iter_params(self):
        """Yield (location, name) for every parameter this request carries."""
        for location, names in (self.params or {}).items():
            for name in names or []:
                yield location, name

    def clone_with_param(self, location: str, name: str, value: str) -> "WebRequest":
        """
        A copy of this request with one parameter set to ``value``. Used by an
        engine to build a probe from the canonical request rather than a bespoke
        candidate dict.
        """
        new = WebRequest(
            method=self.method,
            url=self.url,
            headers=dict(self.headers),
            cookies=dict(self.cookies),
            body=self.body,
            content_type=self.content_type,
            params=self.params,
            auth_context=self.auth_context,
            source=self.source,
        )
        if location == "query":
            parsed = urlparse(self.url)
            from urllib.parse import parse_qsl

            q = [
                (n, value if n == name else v)
                for n, v in parse_qsl(parsed.query, keep_blank_values=True)
            ]
            new.url = urlunparse(parsed._replace(query=urlencode(q)))
        elif location == "json":
            obj = surface.parse_json_object(self.body) or {}
            new.body = surface.inject_json(obj, name, value)
            new.content_type = "application/json"
        elif location == "form":
            from urllib.parse import parse_qsl

            fields = dict(parse_qsl(self.body or "", keep_blank_values=True))
            fields[name] = value
            new.body = urlencode(fields)
            new.content_type = "application/x-www-form-urlencoded"
        elif location == "path":
            # name is the segment index (as a string), per the surface model.
            try:
                new.url = surface.swap_path_segment(self.url, int(name), value)
            except (ValueError, TypeError):
                pass
        return new

    # ── replay ───────────────────────────────────────────────────────────────
    async def replay(self, client) -> Any:
        """Send this request over an httpx.AsyncClient and return the response."""
        hdrs = dict(self.headers)
        if self.content_type:
            hdrs.setdefault("Content-Type", self.content_type)
        kwargs: Dict[str, Any] = {"headers": hdrs or None}
        if self.cookies:
            kwargs["cookies"] = self.cookies
        if self.body is not None and self.method in ("POST", "PUT", "PATCH", "DELETE"):
            kwargs["content"] = self.body.encode()
        return await client.request(self.method, self.url, **kwargs)

    # ── serialisation ────────────────────────────────────────────────────────
    def to_raw_http(self) -> str:
        """
        A raw HTTP/1.1 request, for tools that accept one (``sqlmap -r``). Carries
        the method, path+query, Host, auth headers/cookies and body — so the tool
        tests the request exactly as the authenticated crawl saw it, not a bare
        URL that has lost its session and body.
        """
        parsed = urlparse(self.url)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        lines = [f"{self.method} {path} HTTP/1.1", f"Host: {parsed.netloc}"]
        seen = {"host"}
        for k, v in self.headers.items():
            if k.lower() not in seen:
                lines.append(f"{k}: {v}")
                seen.add(k.lower())
        if self.cookies and "cookie" not in seen:
            cookie = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
            lines.append(f"Cookie: {cookie}")
        if self.body is not None and self.method in ("POST", "PUT", "PATCH", "DELETE"):
            if self.content_type and "content-type" not in seen:
                lines.append(f"Content-Type: {self.content_type}")
            lines.append(f"Content-Length: {len(self.body.encode())}")
            lines.append("")
            lines.append(self.body)
        else:
            lines.append("")
        return "\r\n".join(lines)

    def to_curl(self) -> str:
        """A curl command that reproduces this request (finding evidence)."""
        parts = ["curl", "-i", "-X", self.method]
        for k, v in self.headers.items():
            parts += ["-H", _shq(f"{k}: {v}")]
        if self.cookies:
            parts += [
                "-b",
                _shq("; ".join(f"{k}={v}" for k, v in self.cookies.items())),
            ]
        if self.body is not None and self.method in ("POST", "PUT", "PATCH", "DELETE"):
            if self.content_type:
                parts += ["-H", _shq(f"Content-Type: {self.content_type}")]
            parts += ["--data-raw", _shq(self.body)]
        parts.append(_shq(self.url))
        return " ".join(parts)


def _shq(s: str) -> str:
    """Single-quote a shell argument."""
    return "'" + str(s).replace("'", "'\\''") + "'"


def requests_from_surface(
    endpoints: Optional[List[dict]] = None,
    forms: Optional[List[dict]] = None,
    auth_headers: Optional[Dict[str, str]] = None,
    auth_cookies: Optional[Dict[str, str]] = None,
    auth_context: Optional[str] = None,
) -> List[WebRequest]:
    """Build the canonical WebRequest set from the discovered surface."""
    out: List[WebRequest] = []
    for ep in endpoints or []:
        if isinstance(ep, dict) and ep.get("url"):
            out.append(
                WebRequest.from_endpoint(ep, auth_headers, auth_cookies, auth_context)
            )
    for form in forms or []:
        if isinstance(form, dict) and form.get("url"):
            out.append(
                WebRequest.from_form(form, auth_headers, auth_cookies, auth_context)
            )
    return out
