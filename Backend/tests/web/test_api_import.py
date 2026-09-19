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
