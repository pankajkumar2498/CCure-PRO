"""
Phase 23 — traffic-based API import: HAR + Postman (Codex item 8).

OpenAPI/GraphQL cover declared APIs; this imports captured (HAR) and authored
(Postman) requests, the richest sources of real attack surface. These tests pin
normalisation into the crawler's endpoint shape, same-origin filtering, JSON
body parameter modelling, and Postman's folder/url variants.
"""

from core.web.api_import import import_sources, parse_har, parse_postman

ORIGIN = "app.test"


def _har(entries):
    return {"log": {"entries": entries}}


def test_har_imports_requests_with_body_and_params():
    har = _har(
        [
            {
                "request": {
                    "method": "POST",
                    "url": "http://app.test/api/orders?ref=1",
                    "headers": [{"name": "Content-Type", "value": "application/json"}],
                    "postData": {
                        "mimeType": "application/json",
                        "text": '{"item": "x", "qty": 2}',
                    },
                }
            },
            {"request": {"method": "GET", "url": "http://app.test/api/users?id=5"}},
        ]
    )
    eps = parse_har(har, ORIGIN)
    assert len(eps) == 2
    post = next(e for e in eps if e["method"] == "POST")
    assert post["source"] == "har"
    assert post["request_content_type"] == "application/json"
    # JSON body + query modelled as parameters
    assert "json" in post["parameters"] and "query" in post["parameters"]


def test_har_drops_cross_origin():
    har = _har(
        [
            {"request": {"method": "GET", "url": "https://cdn.other.com/api/x"}},
            {"request": {"method": "GET", "url": "http://app.test/api/keep"}},
        ]
    )
    eps = parse_har(har, ORIGIN)
    assert len(eps) == 1 and eps[0]["url"].endswith("/api/keep")


def test_har_dedupes_identical_requests():
    e = {"request": {"method": "GET", "url": "http://app.test/api/x?id=1"}}
    assert len(parse_har(_har([e, e, e]), ORIGIN)) == 1


def test_postman_v2_walks_folders_and_url_variants():
    coll = {
        "info": {"name": "c"},
        "item": [
            {
                "name": "folder",
                "item": [
                    {
                        "name": "raw-url",
                        "request": {
                            "method": "GET",
                            "url": "http://app.test/api/a?q=1",
                        },
                    },
                    {
                        "name": "structured-url",
                        "request": {
                            "method": "POST",
                            "url": {
                                "raw": "http://app.test/api/b",
                                "host": ["app", "test"],
                                "path": ["api", "b"],
                            },
                            "header": [
                                {"key": "Content-Type", "value": "application/json"}
                            ],
                            "body": {"mode": "raw", "raw": '{"name": "z"}'},
                        },
                    },
                ],
            }
        ],
    }
    eps = parse_postman(coll, ORIGIN)
    urls = {e["url"] for e in eps}
    assert any(u.endswith("/api/a?q=1") for u in urls)
    b = next(e for e in eps if e["url"].endswith("/api/b"))
    assert b["method"] == "POST" and "json" in b["parameters"]


def test_import_sources_from_options():
    opts = {
        "har": _har(
            [{"request": {"method": "GET", "url": "http://app.test/api/x?id=1"}}]
        ),
        "postman": {
            "item": [
                {"request": {"method": "GET", "url": "http://app.test/api/y?id=2"}}
            ]
        },
    }
    eps, labels = import_sources(opts, "http://app.test/")
    assert len(eps) == 2
    assert any(lbl.startswith("har(") for lbl in labels)
    assert any(lbl.startswith("postman(") for lbl in labels)


def test_import_accepts_json_string():
    import json

    har = json.dumps(
        _har([{"request": {"method": "GET", "url": "http://app.test/z?a=1"}}])
    )
    eps = parse_har(har, ORIGIN)
    assert len(eps) == 1


# ── SOAP / WSDL import ───────────────────────────────────────────────────────
_WSDL = """<?xml version="1.0"?>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
             xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/">
  <portType name="UserService">
    <operation name="GetUser"/>
    <operation name="DeleteUser"/>
  </portType>
  <binding name="b"><operation name="GetUser">
    <soap:operation soapAction="urn:GetUser"/></operation></binding>
  <service name="svc"><port name="p">
    <soap:address location="http://app.test/soap/UserService"/>
  </port></service>
</definitions>"""


def test_wsdl_extracts_endpoint_and_operations():
    from core.web.api_import import parse_wsdl

    eps = parse_wsdl(_WSDL, ORIGIN)
    assert len(eps) == 2  # GetUser, DeleteUser
    for e in eps:
        assert e["url"] == "http://app.test/soap/UserService"
        assert e["method"] == "POST"
        assert (
            "soap" in (e.get("request_content_type") or "").lower()
            or "xml" in (e.get("request_content_type") or "").lower()
        )
        assert e["source"] == "wsdl"
    ops = {e["parameters"]["soap"][0] for e in eps}
    assert ops == {"GetUser", "DeleteUser"}
    # the SOAP envelope names the operation in its body
    getuser = next(e for e in eps if e["parameters"]["soap"] == ["GetUser"])
    assert "<GetUser/>" in getuser["request_body"]


def test_wsdl_rejects_doctype_xxe():
    from core.web.api_import import parse_wsdl

    malicious = (
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>'
        "<definitions><service><port>"
        '<address location="http://app.test/s"/></port></service></definitions>'
    )
    assert parse_wsdl(malicious, ORIGIN) == []  # DTD/entity → refused, no XXE


def test_wsdl_cross_origin_endpoint_dropped():
    from core.web.api_import import parse_wsdl

    other = _WSDL.replace("http://app.test/soap", "http://evil.test/soap")
    assert parse_wsdl(other, ORIGIN) == []


def test_wsdl_soap_body_becomes_injection_target():
    from core.web.api_import import parse_wsdl
    from orchestrator.web_orchestrator import build_injection_targets

    eps = parse_wsdl(_WSDL, ORIGIN)
    targets = build_injection_targets(eps, [])
    soap_t = [
        t
        for t in targets
        if "soap" in (t.get("content_type") or "").lower()
        or "xml" in (t.get("content_type") or "").lower()
    ]
    assert soap_t, "SOAP XML body did not become an injection target"
    assert soap_t[0]["method"] == "POST" and soap_t[0]["data"].lstrip().startswith("<")
