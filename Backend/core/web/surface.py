"""
core/web/surface.py
────────────────────────────────────────────────────────────────────────────
Attack-surface parameter model (Phase 22).

A web application's testable surface is not just "URLs the crawler saw" — it is
the set of *request shapes* and the *parameters* inside them, across every
location a value can travel: the query string, an HTML form body, a JSON
request body, and identifiers embedded in the path. Phase 20/21 audit found the
scanner only turned query strings and HTML form fields into injectable targets,
so JSON API bodies (captured by the browser's network interception) and path
identifiers never reached sqlmap, the injection engine or the parameter
inventory — a large modern-application blind spot.

This module is the single place that normalises a discovered request into its
parameter locations, so the crawler (inventory), ``build_injection_targets``
(sqlmap) and the injection engine all agree on what is testable and where.

Nothing here sends a request or mutates a target; it only parses and describes.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

#: A path segment that looks like an object identifier (numeric or a UUID/hash),
#: i.e. a candidate for path-based IDOR / injection. Deliberately conservative:
#: a bare word like "users" is a route, not an id.
_ID_SEGMENT = re.compile(r"^(?:\d+|[0-9a-fA-F]{8,}|[0-9a-fA-F-]{16,})$")

#: JSON value types worth injecting into — scalars a parameter would carry.
_SCALAR = (str, int, float)

#: Request headers worth testing as injection points. Standard hop-by-hop and
#: fetch-metadata headers are excluded — testing them is noise and, for some,
#: actively breaks the request. This is the conventional injectable set (what
#: sqlmap's --level 3 and Burp's header insertion points target) plus any
#: custom application header (``X-*``), which is decided at capture time.
_TESTABLE_HEADERS = frozenset(
    h.lower()
    for h in (
        "User-Agent",
        "Referer",
        "X-Forwarded-For",
        "X-Forwarded-Host",
        "X-Real-IP",
        "X-Api-Version",
        "Authorization",
        "Accept-Language",
    )
)

#: Headers never worth treating as an injection parameter (transport / caching /
#: negotiation), even when custom-looking.
_HEADER_DENYLIST = frozenset(
    h.lower()
    for h in (
        "host",
        "content-type",
        "content-length",
        "accept",
        "accept-encoding",
        "connection",
        "cookie",
        "origin",
        "cache-control",
        "pragma",
        "sec-fetch-mode",
        "sec-fetch-site",
        "sec-fetch-dest",
        "sec-ch-ua",
        "upgrade-insecure-requests",
    )
)


def is_multipart(endpoint: Dict[str, Any]) -> bool:
    """Whether an endpoint's request body is multipart/form-data — the encoding
    a file upload uses, which the injection layer must send differently."""
    ct = str(
        endpoint.get("request_content_type") or endpoint.get("content_type") or ""
    ).lower()
    if "multipart/form-data" in ct:
        return True
    return bool(endpoint.get("has_file_upload"))


def testable_header_names(headers: Any) -> List[str]:
    """Header names worth testing, from a captured header mapping or name list.
    Keeps the conventional injectable set plus custom ``X-*`` application headers,
    and drops transport/negotiation headers. Names only — never values."""
    names: List[str] = []
    seen: set = set()
    if isinstance(headers, dict):
        candidates = list(headers.keys())
    elif isinstance(headers, (list, tuple)):
        candidates = [h for h in headers if isinstance(h, str)]
    else:
        return names
    for raw in candidates:
        h = str(raw).strip()
        low = h.lower()
        if not h or low in _HEADER_DENYLIST or low in seen:
            continue
        if low in _TESTABLE_HEADERS or low.startswith("x-"):
            seen.add(low)
            names.append(h)
    return names


def parse_json_object(body: Optional[str]) -> Optional[Dict[str, Any]]:
    """
    Parse a request body into a JSON object, or None.

    Only a top-level object is useful for per-field injection; a bare array or
    scalar body has no named parameters to target, so it returns None.
    """
    if not body or not isinstance(body, str):
        return None
    body = body.strip()
    if not body or body[0] != "{":
        return None
    try:
        obj = json.loads(body)
    except (ValueError, TypeError):
        return None
    return obj if isinstance(obj, dict) else None


def is_graphql_body(obj: Any) -> bool:
    """A GraphQL POST body: a ``query`` string alongside a ``variables`` object."""
    return (
        isinstance(obj, dict)
        and isinstance(obj.get("query"), str)
        and isinstance(obj.get("variables"), dict)
    )


def json_param_names(obj: Dict[str, Any]) -> List[str]:
    """
    JSON keys whose value is a scalar — the injectable fields.

    For a GraphQL body the injectable inputs are the *variables*, not the
    ``query``/``variables`` envelope, so this descends one level into
    ``variables`` (Phase 22 GraphQL follow-on). For an ordinary body it returns
    the top-level scalar keys; deeper nesting still needs a JSON-pointer model a
    later increment can add.
    """
    if not isinstance(obj, dict):
        return []
    if is_graphql_body(obj):
        return [
            k
            for k, v in obj["variables"].items()
            if isinstance(v, _SCALAR) and not isinstance(v, bool)
        ]
    return [
        k for k, v in obj.items() if isinstance(v, _SCALAR) and not isinstance(v, bool)
    ]


def inject_json(obj: Dict[str, Any], param: str, value: str) -> str:
    """
    Return a JSON string copy of ``obj`` with ``param`` set to ``value``.

    A GraphQL variable (``param`` living inside the ``variables`` object) is set
    there, so injection reaches the actual operation input rather than replacing
    the envelope; otherwise the top-level key is set.
    """
    clone = dict(obj)
    variables = clone.get("variables")
    if isinstance(variables, dict) and param in variables:
        new_vars = dict(variables)
        new_vars[param] = value
        clone["variables"] = new_vars
    else:
        clone[param] = value
    return json.dumps(clone)


def is_json_request(endpoint: Dict[str, Any]) -> bool:
    """Whether an endpoint carries a JSON request body worth testing."""
    ctype = str(
        endpoint.get("request_content_type") or endpoint.get("content_type") or ""
    ).lower()
    body = endpoint.get("request_body")
    if "json" not in ctype:
        # Some captures lack a request content-type; fall back to the body shape.
        return parse_json_object(body) is not None
    return parse_json_object(body) is not None


def path_id_segments(url: str) -> List[Dict[str, Any]]:
    """
    Identifier-looking path segments and their index, e.g. ``/api/users/123``
    yields ``[{"index": 3, "value": "123"}]``. Used for path-parameter testing.
    """
    try:
        path = urlparse(url).path
    except Exception:
        return []
    out: List[Dict[str, Any]] = []
    for idx, seg in enumerate(path.split("/")):
        if seg and _ID_SEGMENT.match(seg):
            out.append({"index": idx, "value": seg})
    return out


def swap_path_segment(url: str, index: int, new_value: str) -> str:
    """Rebuild ``url`` with the path segment at ``index`` replaced."""
    parsed = urlparse(url)
    segs = parsed.path.split("/")
    if 0 <= index < len(segs):
        segs[index] = new_value
    return parsed._replace(path="/".join(segs)).geturl()


def describe_parameters(endpoint: Dict[str, Any]) -> Dict[str, Any]:
    """
    A normalised, value-free description of an endpoint's parameter locations,
    for the durable inventory (WebAsset.parameters). Records *where* parameters
    live and their names — never their captured values.
    """
    from urllib.parse import parse_qsl

    url = endpoint.get("url", "") or ""
    model: Dict[str, Any] = {}
    q = [n for n, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)]
    if q:
        model["query"] = q
    body_obj = parse_json_object(endpoint.get("request_body"))
    if body_obj is not None:
        names = json_param_names(body_obj)
        if names:
            model["json"] = names
    ids = path_id_segments(url)
    if ids:
        model["path"] = [str(i["index"]) for i in ids]
    form_inputs = endpoint.get("inputs") or []
    if form_inputs:
        names = [
            i.get("name") for i in form_inputs if isinstance(i, dict) and i.get("name")
        ]
        # A multipart form's fields live in a multipart/form-data body and must be
        # sent as such by the injection layer — record them under their own
        # location rather than folding them into url-encoded form params.
        model["multipart" if is_multipart(endpoint) else "form"] = names
    # Cookies and headers are attacker-reachable input too (session-fixation,
    # header injection, cookie-based SQLi). Names only, value-free.
    cookies = endpoint.get("request_cookies")
    if isinstance(cookies, dict) and cookies:
        model["cookie"] = list(cookies.keys())
    elif isinstance(cookies, (list, tuple)) and cookies:
        model["cookie"] = [str(c) for c in cookies if c]
    hdrs = testable_header_names(endpoint.get("request_headers"))
    if hdrs:
        model["header"] = hdrs
    return model
