"""
core/web/api_import.py
────────────────────────────────────────────────────────────────────────────
Traffic-based API import: HAR and Postman collections (Phase 23, Codex item 8).

OpenAPI/Swagger and GraphQL discovery already turn a *declared* API into scan
targets. This adds two *captured/authored* sources industry scanners import:

  • **HAR** — a browser/proxy export of real requests, the richest source of
    attack surface: exact method, URL, headers, cookies and body, including
    endpoints and parameters no spec lists.
  • **Postman collection (v2)** — an authored request set, often the only
    machine-readable description of an internal API.

Both are normalised into the same endpoint/request shape the crawler produces,
so they flow into the surface model, coverage ledger and every DETECT engine
with no per-engine change. Same-origin filtering keeps an imported HAR from
turning third-party requests into targets of the scanned host.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from core.web import surface

_MAX_IMPORT = 2000


def _same_origin(url: str, origin: str) -> bool:
    try:
        return not origin or urlparse(url).netloc == origin
    except Exception:
        return False


def _endpoint(
    url: str, method: str, body: Optional[str], ctype: Optional[str], source: str
) -> Dict[str, Any]:
    ep = {
        "url": url,
        "method": (method or "GET").upper(),
        "request_body": body,
        "request_content_type": ctype,
        "is_api": True,
        "source": source,
    }
    params = surface.describe_parameters(ep)
    if params:
        ep["parameters"] = params
    return ep


def parse_har(
    har: Any, origin: str = "", max_entries: int = _MAX_IMPORT
) -> List[Dict[str, Any]]:
    """
    Endpoint records from a HAR document. ``origin`` (netloc) restricts the
    import to the scanned host; empty means no restriction. De-duplicated by
    (method, url-without-query? no — query matters) → (method, url, body).
    """
    if isinstance(har, str):
        try:
            har = json.loads(har)
        except Exception:
            return []
    entries = (((har or {}).get("log") or {}).get("entries")) or []
    out: List[Dict[str, Any]] = []
    seen: set = set()
    for e in entries:
        if not isinstance(e, dict):
            continue
        req = e.get("request") or {}
        url = req.get("url") or ""
        method = req.get("method") or "GET"
        if not url.lower().startswith(("http://", "https://")):
            continue
        if not _same_origin(url, origin):
            continue
        post = req.get("postData") or {}
        body = post.get("text")
        ctype = post.get("mimeType") or _header_value(
            req.get("headers"), "content-type"
        )
        key = (method.upper(), url, body or "")
        if key in seen:
            continue
        seen.add(key)
        out.append(_endpoint(url, method, body, ctype, "har"))
        if len(out) >= max_entries:
            break
    return out


def parse_postman(
    collection: Any, origin: str = "", max_items: int = _MAX_IMPORT
) -> List[Dict[str, Any]]:
    """Endpoint records from a Postman v2 collection (folders walked recursively)."""
    if isinstance(collection, str):
        try:
            collection = json.loads(collection)
        except Exception:
            return []
    if not isinstance(collection, dict):
        return []
    out: List[Dict[str, Any]] = []
    seen: set = set()

    def _walk(items):
        for item in items or []:
            if len(out) >= max_items:
                return
            if not isinstance(item, dict):
                continue
            if isinstance(item.get("item"), list):  # a folder
                _walk(item["item"])
                continue
            req = item.get("request")
            if not isinstance(req, dict):
                continue
            url = _postman_url(req.get("url"))
            method = req.get("method") or "GET"
            if not url or not url.lower().startswith(("http://", "https://")):
                continue
            if not _same_origin(url, origin):
                continue
            body_obj = req.get("body") or {}
            body = body_obj.get("raw") if body_obj.get("mode") == "raw" else None
            ctype = _header_value(req.get("header"), "content-type")
            if body and not ctype:
                ctype = "application/json" if surface.parse_json_object(body) else None
            key = (method.upper(), url, body or "")
            if key in seen:
                continue
            seen.add(key)
            out.append(_endpoint(url, method, body, ctype, "postman"))

    _walk(collection.get("item"))
    return out


def parse_wsdl(
    wsdl: Any, origin: str = "", max_ops: int = _MAX_IMPORT
) -> List[Dict[str, Any]]:
    """
    Endpoint records from a WSDL (SOAP) document.

    Extracts the service endpoint (soap:address location) and the operation
    names, and builds a minimal SOAP envelope per operation as a POST body so
    the operation is inventoried and testable (sqlmap detects SOAP/XML params in
    a --data body). Namespace-agnostic (matches local names), and XML is parsed
    with DTD/entity resolution disabled and a DOCTYPE rejected — the WSDL is
    attacker-influenced input, so no XXE surface is opened.
    """
    text = wsdl if isinstance(wsdl, str) else None
    if isinstance(wsdl, (bytes, bytearray)):
        text = wsdl.decode("utf-8", "replace")
    if not text or "<" not in text:
        return []
    if "<!DOCTYPE" in text or "<!ENTITY" in text:
        return []  # reject DTD/entity-bearing documents outright (no XXE)
    try:
        from lxml import etree

        parser = etree.XMLParser(
            resolve_entities=False,
            no_network=True,
            load_dtd=False,
            dtd_validation=False,
        )
        root = etree.fromstring(text.encode("utf-8"), parser)
    except Exception:
        return []

    def _local(tag: str) -> str:
        return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""

    # Service endpoint: any <*:address location="..."> (soap/soap12/http).
    endpoint_url = ""
    for el in root.iter():
        if _local(el.tag) == "address" and el.get("location"):
            endpoint_url = el.get("location")
            break
    if not endpoint_url or not endpoint_url.lower().startswith(("http://", "https://")):
        return []
    if not _same_origin(endpoint_url, origin):
        return []

    # Operations from portType (authoritative), else binding.
    op_names: List[str] = []
    seen_ops: set = set()
    for el in root.iter():
        if _local(el.tag) == "operation" and el.get("name"):
            name = el.get("name")
            if name not in seen_ops:
                seen_ops.add(name)
                op_names.append(name)
        if len(op_names) >= max_ops:
            break

    out: List[Dict[str, Any]] = []
    for name in op_names:
        envelope = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            "<soapenv:Envelope "
            'xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
            f"<soapenv:Body><{name}/></soapenv:Body></soapenv:Envelope>"
        )
        ep = {
            "url": endpoint_url,
            "method": "POST",
            "request_body": envelope,
            "request_content_type": "text/xml; charset=utf-8",
            "is_api": True,
            "source": "wsdl",
            "parameters": {"soap": [name]},
        }
        out.append(ep)
    return out


def _postman_url(url_field: Any) -> str:
    """A Postman url is a raw string or {raw, host[], path[], query[]}."""
    if isinstance(url_field, str):
        return url_field
    if isinstance(url_field, dict):
        if url_field.get("raw"):
            return url_field["raw"]
        host = url_field.get("host")
        host = ".".join(host) if isinstance(host, list) else (host or "")
        path = url_field.get("path")
        path = "/".join(path) if isinstance(path, list) else (path or "")
        if host:
            return f"{host}/{path}" if path else host
    return ""


def _header_value(headers: Any, name: str) -> Optional[str]:
    """Find a header value in a HAR/Postman header list (list of {name/key,value})."""
    name = name.lower()
    for h in headers or []:
        if not isinstance(h, dict):
            continue
        hn = (h.get("name") or h.get("key") or "").lower()
        if hn == name:
            return h.get("value")
    return None


def import_sources(
    options: Dict[str, Any], target_url: str
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    Import endpoints from any HAR/Postman sources in the scan options.
    Returns (endpoints, source_labels). Inline JSON or already-parsed dicts.
    """
    origin = urlparse(target_url).netloc
    endpoints: List[Dict[str, Any]] = []
    labels: List[str] = []
    har = options.get("har")
    if har:
        eps = parse_har(har, origin)
        if eps:
            endpoints += eps
            labels.append(f"har({len(eps)})")
    postman = options.get("postman")
    if postman:
        eps = parse_postman(postman, origin)
        if eps:
            endpoints += eps
            labels.append(f"postman({len(eps)})")
    wsdl = options.get("wsdl")
    if wsdl:
        eps = parse_wsdl(wsdl, origin)
        if eps:
            endpoints += eps
            labels.append(f"wsdl({len(eps)})")
    return endpoints, labels
