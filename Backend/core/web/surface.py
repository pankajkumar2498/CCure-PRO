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


def json_param_names(obj: Dict[str, Any]) -> List[str]:
    """
    Top-level JSON keys whose value is a scalar — the injectable fields.

    Nested objects/arrays are skipped here: injecting into a nested structure
    needs a JSON-pointer model that a later increment can add. A key whose value
    is a scalar is the common, high-value case (ids, search terms, filters).
    """
    if not isinstance(obj, dict):
        return []
    return [
        k for k, v in obj.items() if isinstance(v, _SCALAR) and not isinstance(v, bool)
    ]


def inject_json(obj: Dict[str, Any], param: str, value: str) -> str:
    """Return a JSON string copy of ``obj`` with ``param`` replaced by ``value``."""
    clone = dict(obj)
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
        model["form"] = [
            i.get("name") for i in form_inputs if isinstance(i, dict) and i.get("name")
        ]
    return model
