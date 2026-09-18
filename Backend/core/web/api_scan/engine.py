"""
core/web/api_scan/engine.py
────────────────────────────────────────────────────────────────────────────
Structured API security testing (Phase 5): OpenAPI/Swagger import, GraphQL
discovery/introspection, a normalized API inventory, and API-specific checks.

The design principle is reuse: the importer turns an OpenAPI/GraphQL surface
into ordinary ``endpoints`` and ``forms`` in the exact shape the crawl already
produces, so the existing DETECT engines — sqlmap, the XSS engine, the active
injection engine and the access-control engine — test API parameters, JSON
bodies and path identifiers with no per-engine changes. Only genuinely
API-specific conditions (GraphQL introspection enabled, an endpoint the spec
declares protected that answers anonymously) are raised here, into the existing
finding model.

Nothing assumes GraphQL introspection is on; it is probed and reported only when
the server actually answers an introspection query. Discovery of a spec is a
small, bounded set of well-known paths, not a fuzz.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

log = logging.getLogger("ccure.web.apiscan")

#: Well-known specification locations, tried in order. Bounded on purpose.
_SPEC_PATHS = [
    "/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/swagger.yaml",
    "/v3/api-docs",
    "/v2/api-docs",
    "/api-docs",
    "/swagger/v1/swagger.json",
    "/api/openapi.json",
    "/api/swagger.json",
]
_GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/query", "/graphiql"]

_INTROSPECTION = {
    "query": "query IntrospectionCheck { __schema { queryType { name } "
    "types { name kind } } }"
}


class ApiScanEngine:
    """Import an API surface and raise API-specific findings."""

    def __init__(
        self,
        *,
        timeout_s: float = 15.0,
        same_origin_only: bool = True,
        discover: bool = True,
        verify_tls: bool = False,
        max_operations: int = 200,
    ) -> None:
        self.timeout_s = timeout_s
        self.same_origin_only = same_origin_only
        self.discover = discover
        self.verify_tls = verify_tls
        self.max_operations = max_operations
        self.stats: Dict[str, Any] = {
            "spec_source": None,
            "operations": 0,
            "endpoints": 0,
            "forms": 0,
            "graphql": None,
            "findings": 0,
            "duration_s": 0.0,
        }

    def is_available(self) -> bool:
        try:
            import httpx  # noqa: F401

            return True
        except Exception:
            return False

    async def run(
        self,
        target_url: str,
        options: Optional[dict] = None,
        auth_headers: Optional[dict] = None,
        auth_cookies: Optional[dict] = None,
    ) -> Dict[str, Any]:
        t0 = time.monotonic()
        options = options or {}
        out = {"endpoints": [], "forms": [], "findings": [], "inventory": {}}
        if not self.is_available():
            return {**out, "stats": self.stats, "available": False}

        import httpx

        headers = dict(auth_headers or {})
        cookies = dict(auth_cookies or {})
        async with httpx.AsyncClient(
            verify=self.verify_tls,
            timeout=self.timeout_s,
            follow_redirects=True,
            headers=headers or None,
            cookies=cookies or None,
        ) as client:
            spec, source = await self._obtain_spec(client, target_url, options)
            if spec:
                self.stats["spec_source"] = source
                eps, forms, inv = self._parse_openapi(spec, target_url)
                out["endpoints"] = eps[: self.max_operations]
                out["forms"] = forms[: self.max_operations]
                out["inventory"] = inv
                self.stats["operations"] = inv.get("operation_count", 0)
                self.stats["endpoints"] = len(out["endpoints"])
                self.stats["forms"] = len(out["forms"])
                out["findings"] += await self._openapi_findings(
                    client, out["endpoints"], out["forms"], inv, headers, cookies
                )
            # GraphQL
            gql = await self._graphql(client, target_url, options)
            if gql:
                self.stats["graphql"] = gql.get("status")
                out["findings"] += gql.get("findings", [])
                out["endpoints"] += gql.get("endpoints", [])
                out["inventory"]["graphql"] = gql.get("inventory")

        self.stats["findings"] = len(out["findings"])
        self.stats["duration_s"] = round(time.monotonic() - t0, 2)
        return {**out, "stats": self.stats, "available": True}

    # ── spec acquisition ───────────────────────────────────────────────────────
    async def _obtain_spec(self, client, target_url, options):
        # 1. Inline spec.
        inline = options.get("api_spec")
        if isinstance(inline, dict) and inline:
            return inline, "inline"
        if isinstance(inline, str) and inline.strip():
            parsed = self._loads(inline)
            if parsed:
                return parsed, "inline"
        # 2. Explicit URL.
        spec_url = options.get("api_spec_url")
        if spec_url:
            parsed = await self._fetch_spec(client, spec_url)
            if parsed:
                return parsed, spec_url
        # 3. Discovery.
        if self.discover:
            origin = self._origin(target_url)
            for path in _SPEC_PATHS:
                parsed = await self._fetch_spec(client, urljoin(origin, path))
                if parsed and ("openapi" in parsed or "swagger" in parsed):
                    return parsed, urljoin(origin, path)
        return None, None

    async def _fetch_spec(self, client, url):
        try:
            r = await client.get(url)
            if r.status_code == 200 and r.text:
                return self._loads(r.text)
        except Exception as exc:
            log.debug("spec fetch failed %s: %s", url, exc)
        return None

    @staticmethod
    def _loads(text):
        try:
            return json.loads(text)
        except Exception:
            pass
        try:
            import yaml

            data = yaml.safe_load(text)
            return data if isinstance(data, dict) else None
        except Exception:
            return None

    @staticmethod
    def _origin(url):
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}"

    def _in_scope(self, url, target_url):
        if not self.same_origin_only:
            return True
        return urlparse(url).netloc == urlparse(target_url).netloc

    # ── OpenAPI 2.x / 3.x parsing ──────────────────────────────────────────────
    def _base_url(self, spec, target_url):
        origin = self._origin(target_url)
        if "openapi" in spec:  # 3.x
            servers = spec.get("servers") or []
            if servers and isinstance(servers[0], dict) and servers[0].get("url"):
                return urljoin(origin + "/", servers[0]["url"])
            return origin
        # 2.x
        scheme = (spec.get("schemes") or [urlparse(target_url).scheme or "https"])[0]
        host = spec.get("host") or urlparse(target_url).netloc
        base = spec.get("basePath") or ""
        return f"{scheme}://{host}{base}"

    def _parse_openapi(self, spec, target_url):
        endpoints: List[dict] = []
        forms: List[dict] = []
        base = self._base_url(spec, target_url)
        is3 = "openapi" in spec
        global_security = bool(spec.get("security"))
        components = spec.get("components", {}) if is3 else spec
        op_count = 0
        secured = 0

        for path, item in (spec.get("paths") or {}).items():
            if not isinstance(item, dict):
                continue
            for method, op in item.items():
                if method.lower() not in (
                    "get",
                    "post",
                    "put",
                    "patch",
                    "delete",
                    "head",
                    "options",
                ) or not isinstance(op, dict):
                    continue
                op_count += 1
                method_u = method.upper()
                auth_required = bool(op.get("security")) or global_security
                if auth_required:
                    secured += 1
                # Parameters: path/query/header (+ body/formData in 2.x).
                params = list(op.get("parameters") or [])
                # Path-level parameters apply too.
                params += [p for p in (item.get("parameters") or [])]
                query_params, path_values, body_fields = [], {}, []
                for p in params:
                    if not isinstance(p, dict):
                        continue
                    loc = p.get("in")
                    name = p.get("name")
                    if not name:
                        continue
                    if loc == "query":
                        query_params.append(name)
                    elif loc == "path":
                        path_values[name] = "1"
                    elif loc in ("body", "formData"):
                        schema = p.get("schema") or {}
                        body_fields += self._schema_fields(schema, components)
                        if loc == "formData":
                            body_fields.append(name)
                if is3 and op.get("requestBody"):
                    content = op["requestBody"].get("content") or {}
                    for ctype, media in content.items():
                        body_fields += self._schema_fields(
                            media.get("schema") or {}, components
                        )
                        break
                # Build the concrete URL: fill path params, append a sample query.
                concrete_path = path
                for pname, pval in path_values.items():
                    concrete_path = concrete_path.replace("{%s}" % pname, pval)
                # Any un-filled {param} → sample value 1
                import re as _re

                concrete_path = _re.sub(r"\{[^}]+\}", "1", concrete_path)
                url = urljoin(base + "/", concrete_path.lstrip("/"))
                if not self._in_scope(url, target_url):
                    continue
                if query_params:
                    q = "&".join(f"{n}=1" for n in query_params)
                    url = url + ("&" if urlparse(url).query else "?") + q
                ep = {
                    "url": url,
                    "method": method_u,
                    "is_api": True,
                    "source": "openapi",
                    "auth_required": auth_required,
                    "parameters": {n: "1" for n in query_params},
                }
                endpoints.append(ep)
                # Body-bearing operations → a form so sqlmap/XSS test the fields.
                if body_fields and method_u in ("POST", "PUT", "PATCH"):
                    forms.append(
                        {
                            "url": url.split("?")[0],
                            "method": method_u,
                            "inputs": [
                                {"name": f, "type": "text"}
                                for f in dict.fromkeys(body_fields)
                            ],
                            "is_api": True,
                            "source": "openapi",
                            "page_url": url,
                            "auth_required": auth_required,
                        }
                    )
        inv = {
            "type": "openapi",
            "version": spec.get("openapi") or spec.get("swagger"),
            "base_url": base,
            "operation_count": op_count,
            "secured_operations": secured,
            "global_security": global_security,
            "security_schemes": list(
                (
                    components.get("securitySchemes")
                    or components.get("securityDefinitions")
                    or {}
                ).keys()
            ),
        }
        return endpoints, forms, inv

    def _schema_fields(self, schema, components, depth=0):
        """Top-level property names of a (possibly $ref) object schema."""
        if depth > 3 or not isinstance(schema, dict):
            return []
        if "$ref" in schema:
            schema = self._resolve_ref(schema["$ref"], components)
        props = (schema or {}).get("properties") or {}
        return [k for k in props.keys()]

    @staticmethod
    def _resolve_ref(ref, components):
        # #/components/schemas/X (3.x) or #/definitions/X (2.x)
        try:
            parts = ref.lstrip("#/").split("/")
            node = {"components": components, "definitions": components}
            # components already the schemas container in 2.x path; handle both.
            for key in parts:
                if key in ("components", "definitions"):
                    node = components
                elif key == "schemas":
                    node = components.get("schemas", components)
                elif isinstance(node, dict):
                    node = node.get(key, {})
            return node if isinstance(node, dict) else {}
        except Exception:
            return {}

    # ── OpenAPI-specific findings ──────────────────────────────────────────────
    async def _openapi_findings(self, client, endpoints, forms, inv, headers, cookies):
        findings = []
        # No security scheme declared at all → whole API unauthenticated (info).
        if (
            inv.get("operation_count")
            and not inv.get("security_schemes")
            and not inv.get("global_security")
            and inv.get("secured_operations", 0) == 0
        ):
            findings.append(
                self._finding(
                    "api_missing_auth",
                    inv.get("base_url", ""),
                    "The imported API specification declares no security scheme and no "
                    "operation-level security — every operation is defined as "
                    "unauthenticated. Confirm this is intended for all listed endpoints.",
                    "CWE-306",
                    "medium",
                    evidence=f"{inv.get('operation_count')} operation(s); 0 secured; "
                    f"no securitySchemes.",
                )
            )
        # Missing authentication: a spec-declared-secure GET reachable anonymously.
        checked = 0
        async with __import__("httpx").AsyncClient(
            verify=self.verify_tls, timeout=self.timeout_s, follow_redirects=False
        ) as anon:
            for ep in endpoints:
                if checked >= 15:
                    break
                if ep.get("method") != "GET" or not ep.get("auth_required"):
                    continue
                checked += 1
                try:
                    r = await anon.get(ep["url"])
                except Exception:
                    continue
                if r.status_code == 200 and len(r.text or "") >= 64:
                    findings.append(
                        self._finding(
                            "api_missing_auth",
                            ep["url"],
                            "An operation the API specification marks as requiring "
                            "authentication returned data to an unauthenticated "
                            "request — the auth requirement is not enforced.",
                            "CWE-306",
                            "high",
                            evidence=f"GET {ep['url']} without credentials → HTTP 200, "
                            f"{len(r.text)} bytes.",
                        )
                    )
        return findings

    # ── GraphQL ─────────────────────────────────────────────────────────────────
    async def _graphql(self, client, target_url, options):
        candidates = []
        if options.get("graphql_url"):
            candidates.append(options["graphql_url"])
        if self.discover:
            origin = self._origin(target_url)
            candidates += [urljoin(origin, p) for p in _GRAPHQL_PATHS]
        seen = set()
        for url in candidates:
            if url in seen or not self._in_scope(url, target_url):
                continue
            seen.add(url)
            try:
                r = await client.post(url, json=_INTROSPECTION)
            except Exception:
                continue
            if r.status_code not in (200, 400):
                continue
            try:
                data = r.json()
            except Exception:
                continue
            # A GraphQL endpoint responds with data/errors envelope.
            if not isinstance(data, dict) or (
                "data" not in data and "errors" not in data
            ):
                continue
            schema = (data.get("data") or {}).get("__schema")
            if schema:
                types = schema.get("types") or []
                findings = [
                    self._finding(
                        "graphql_introspection",
                        url,
                        "GraphQL introspection is enabled: the endpoint answered a "
                        "full __schema introspection query, exposing the entire API "
                        "type system (types, queries and mutations) to any client. "
                        "This aids attackers in mapping the API and should be "
                        "disabled in production.",
                        "CWE-200",
                        "medium",
                        evidence=f"POST {url} __schema returned {len(types)} type(s).",
                    )
                ]
                inv = {
                    "endpoint": url,
                    "introspection": True,
                    "type_count": len(types),
                    "query_type": (schema.get("queryType") or {}).get("name"),
                }
                return {
                    "status": "introspection_enabled",
                    "findings": findings,
                    "inventory": inv,
                    "endpoints": [
                        {
                            "url": url,
                            "method": "POST",
                            "is_api": True,
                            "source": "graphql",
                        }
                    ],
                }
            # Endpoint exists but introspection disabled — not a finding.
            return {
                "status": "introspection_disabled",
                "findings": [],
                "inventory": {"endpoint": url, "introspection": False},
                "endpoints": [
                    {"url": url, "method": "POST", "is_api": True, "source": "graphql"}
                ],
            }
        return None

    # ── finding ──────────────────────────────────────────────────────────────────
    def _finding(self, ftype, url, desc, cwe, severity, *, evidence):
        titles = {
            "graphql_introspection": "GraphQL introspection enabled",
            "api_missing_auth": "Missing/insufficient API authentication",
            "excessive_data_exposure": "Excessive data exposure",
        }
        return {
            "finding_type": ftype,
            "title": f"{titles.get(ftype, ftype)} at {url}"[:255],
            "description": desc,
            "severity": severity,
            "detected_by": "ccure-api",
            "cwe_id": cwe,
            "matched_at": url,
            "request_url": url,
            "request_method": "POST" if ftype == "graphql_introspection" else "GET",
            "response_evidence": evidence,
            "remediation": _REMEDIATION.get(ftype, ""),
            "is_verified": True,
            "confidence": "confirmed",
        }


_REMEDIATION = {
    "graphql_introspection": (
        "Disable GraphQL introspection in production (e.g. disable it in the "
        "server config / Apollo), and enforce authentication and query "
        "depth/complexity limits."
    ),
    "api_missing_auth": (
        "Enforce authentication and authorization server-side on every non-public "
        "API operation; do not rely on the specification alone. Deny by default."
    ),
    "excessive_data_exposure": (
        "Return only the fields a client needs; filter sensitive properties "
        "server-side rather than relying on the client to hide them."
    ),
}
