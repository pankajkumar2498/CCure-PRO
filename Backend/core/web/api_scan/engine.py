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

# A fuller query that also returns the Query/Mutation fields and their argument
# names, so operations can be enumerated into testable requests (Phase 22,
# Item 8). Kept separate from the light check above so introspection *detection*
# is unchanged.
_INTROSPECTION_OPS = {
    "query": (
        "query OpEnum { __schema { "
        "queryType { name fields { name args { name } "
        "type { kind name ofType { kind name ofType { kind name } } } } } "
        "mutationType { name fields { name args { name } "
        "type { kind name ofType { kind name ofType { kind name } } } } } } }"
    )
}


def _unwrap_kind(type_ref: dict) -> str:
    """The underlying kind of a (possibly LIST/NON_NULL-wrapped) GraphQL type."""
    t = type_ref or {}
    for _ in range(4):
        kind = t.get("kind")
        if kind in ("SCALAR", "ENUM", "OBJECT", "INTERFACE", "UNION", "INPUT_OBJECT"):
            return kind
        t = t.get("ofType") or {}
        if not t:
            break
    return "OBJECT"  # default to requiring a subselection (safe, valid)


def graphql_operation_request(url: str, op: dict) -> dict:
    """
    Build a valid, minimal GraphQL operation request for one field, as a
    discovered endpoint (POST /graphql, JSON body). Arguments are carried in
    ``variables`` so their values are testable input; the selection set is
    ``__typename`` for object-returning fields (valid on any object) and empty
    for scalars — so the generated query is always syntactically valid.
    """
    import json as _json

    name = op["name"]
    args = op.get("args") or []
    ret_kind = op.get("return_kind", "OBJECT")
    selection = (
        " { __typename }" if ret_kind in ("OBJECT", "INTERFACE", "UNION") else ""
    )
    if args:
        var_defs = ", ".join(f"${a}: String" for a in args)
        arg_use = ", ".join(f"{a}: ${a}" for a in args)
        query = f"{op['operation']} op({var_defs}) {{ {name}({arg_use}){selection} }}"
        variables = {a: "1" for a in args}
    else:
        query = f"{op['operation']} op {{ {name}{selection} }}"
        variables = {}
    body = _json.dumps({"query": query, "variables": variables})
    return {
        "url": url,
        "method": "POST",
        "is_api": True,
        "source": "graphql_op",
        "request_body": body,
        "request_content_type": "application/json",
        "graphql_operation": f"{op['operation']}:{name}",
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
                # Negative testing (Codex item 8): send schema-violating inputs
                # and flag operations that accept them (weak input validation).
                out["findings"] += await self._negative_findings(
                    client, out["endpoints"], headers, cookies
                )
            # GraphQL
            gql = await self._graphql(client, target_url, options)
            if gql:
                self.stats["graphql"] = gql.get("status")
                out["findings"] += gql.get("findings", [])
                out["endpoints"] += gql.get("endpoints", [])
                out["inventory"]["graphql"] = gql.get("inventory")

            # Traffic-based import: HAR / Postman (Phase 23, Item 8). Same-origin
            # captured/authored requests become scan targets alongside the spec.
            from core.web.api_import import import_sources

            imported, import_labels = import_sources(options, target_url)
            if imported:
                out["endpoints"] += imported[: self.max_operations]
                out["inventory"]["imported"] = import_labels
                self.stats["imported"] = len(imported)
                self.stats["endpoints"] = self.stats.get("endpoints", 0) + len(imported)

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
                # Retain each query parameter's schema + required flag so negative
                # testing (Codex item 8) can send a schema-violating value.
                query_schemas: dict = {}
                required_query: list = []
                for p in params:
                    if not isinstance(p, dict):
                        continue
                    loc = p.get("in")
                    name = p.get("name")
                    if not name:
                        continue
                    if loc == "query":
                        query_params.append(name)
                        # OpenAPI 3 puts the schema under "schema"; 2.x inlines it.
                        query_schemas[name] = p.get("schema") or {
                            k: p[k]
                            for k in ("type", "enum", "maxLength", "minimum", "maximum")
                            if k in p
                        }
                        if p.get("required"):
                            required_query.append(name)
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
                    # Retained for negative testing (Codex item 8).
                    "query_schemas": query_schemas,
                    "required_query": required_query,
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
    async def _negative_findings(self, client, endpoints, headers, cookies):
        """
        Negative testing (Codex item 8): for each GET operation that declares a
        constrained query parameter (an enum, a numeric type, a maxLength) or a
        required one, send a request that violates the schema and flag the
        operation when it answers 2xx — the API accepted input its own spec says
        is invalid, which is weak/absent input validation.

        Bounded (a handful of probes per scan) and read-only: it sends GET
        requests with a bad query value, never a state change.
        """
        from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

        from core.web.api_scan.fuzz import violating_value

        findings: List[dict] = []
        probes = 0
        for ep in endpoints or []:
            if probes >= 25:
                break
            if not isinstance(ep, dict) or ep.get("source") != "openapi":
                continue
            if str(ep.get("method") or "GET").upper() != "GET":
                continue  # negative-test only safe, idempotent reads
            schemas = ep.get("query_schemas") or {}
            required = ep.get("required_query") or []
            url = ep.get("url") or ""
            parsed = urlparse(url)
            base_q = dict(parse_qsl(parsed.query, keep_blank_values=True))
            # 1. Schema violation on a constrained parameter.
            for name, schema in schemas.items():
                if probes >= 25:
                    break
                bad = violating_value(schema)
                if bad is None:
                    continue
                probes += 1
                q = dict(base_q)
                q[name] = bad
                probe_url = urlunparse(parsed._replace(query=urlencode(q)))
                status = await self._probe_status(client, probe_url, headers, cookies)
                if status and 200 <= status < 300:
                    findings.append(
                        self._finding(
                            "api_weak_input_validation",
                            probe_url,
                            f"The operation accepted a schema-violating value for "
                            f"query parameter '{name}' (HTTP {status}). Its own API "
                            f"specification constrains this parameter, so the input "
                            f"should have been rejected — missing server-side input "
                            f"validation.",
                            "CWE-20",
                            "low",
                            evidence=f"GET with invalid '{name}' → {status}.",
                        )
                    )
            # 2. Required-parameter omission.
            for name in required:
                if probes >= 25:
                    break
                if name not in base_q:
                    continue
                probes += 1
                q = {k: v for k, v in base_q.items() if k != name}
                probe_url = urlunparse(parsed._replace(query=urlencode(q)))
                status = await self._probe_status(client, probe_url, headers, cookies)
                if status and 200 <= status < 300:
                    findings.append(
                        self._finding(
                            "api_weak_input_validation",
                            probe_url,
                            f"The operation answered 2xx with the required query "
                            f"parameter '{name}' omitted (HTTP {status}). A required "
                            f"parameter should be enforced server-side.",
                            "CWE-20",
                            "low",
                            evidence=f"GET without required '{name}' → {status}.",
                        )
                    )
        return findings

    async def _probe_status(self, client, url, headers, cookies):
        try:
            r = await client.get(url, headers=headers or None, cookies=cookies or None)
            return r.status_code
        except Exception as exc:
            log.debug("negative-test probe failed %s: %s", url[:80], exc)
            return None

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
                # Enumerate operations into testable requests (Phase 22, Item 8):
                # introspection detection alone leaves the Query/Mutation surface
                # untested. Each operation becomes a POST /graphql request whose
                # arguments travel in variables, so it enters the surface,
                # coverage and injection paths like any discovered endpoint.
                ops = await self._enumerate_graphql_ops(client, url)
                op_endpoints = [graphql_operation_request(url, op) for op in ops]
                inv = {
                    "endpoint": url,
                    "introspection": True,
                    "type_count": len(types),
                    "query_type": (schema.get("queryType") or {}).get("name"),
                    "operation_count": len(ops),
                    "operations": [f"{o['operation']}:{o['name']}" for o in ops][:200],
                }
                self.stats["operations"] = self.stats.get("operations", 0) + len(ops)
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
                    ]
                    + op_endpoints,
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

    async def _enumerate_graphql_ops(self, client, url):
        """
        Enumerate Query/Mutation operations (name, args, return kind) from a
        fuller introspection query. Returns a bounded list of operation dicts;
        never raises. Meta-fields (``__*``) are skipped.
        """
        try:
            r = await client.post(url, json=_INTROSPECTION_OPS)
            data = r.json()
        except Exception:
            return []
        schema = (data.get("data") or {}).get("__schema") or {}
        ops = []
        for type_key, op_kind in (("queryType", "query"), ("mutationType", "mutation")):
            t = schema.get(type_key) or {}
            for field in t.get("fields") or []:
                name = field.get("name")
                if not name or name.startswith("__"):
                    continue
                ops.append(
                    {
                        "operation": op_kind,
                        "name": name,
                        "args": [
                            a.get("name")
                            for a in (field.get("args") or [])
                            if a.get("name")
                        ],
                        "return_kind": _unwrap_kind(field.get("type")),
                    }
                )
                if len(ops) >= self.max_operations:
                    return ops
        return ops

    # ── finding ──────────────────────────────────────────────────────────────────
    def _finding(self, ftype, url, desc, cwe, severity, *, evidence):
        titles = {
            "graphql_introspection": "GraphQL introspection enabled",
            "api_missing_auth": "Missing/insufficient API authentication",
            "excessive_data_exposure": "Excessive data exposure",
            "api_weak_input_validation": "Weak API input validation",
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
    "api_weak_input_validation": (
        "Validate every request parameter server-side against its declared "
        "schema — type, enum, length and range — and reject non-conforming or "
        "missing-required input with 4xx. Do not rely on client-side or "
        "specification-only validation."
    ),
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
