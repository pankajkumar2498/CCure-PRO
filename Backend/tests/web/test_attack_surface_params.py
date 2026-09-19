"""
Phase 22 — attack-surface parameter model: JSON body + path parameters.

Phase 20/21 audit (Codex) found the scanner only turned query strings and HTML
form fields into injectable targets, so JSON API bodies and path identifiers —
the bulk of a modern application's parameters — were never tested and never
inventoried. These tests pin the new surface model and prove those parameter
locations now become sqlmap / injection-engine targets and reach the durable
inventory.
"""

from core.web import surface
from orchestrator.web_orchestrator import build_injection_targets


# ── surface parsing ──────────────────────────────────────────────────────────
def test_json_object_parsing_and_param_names():
    obj = surface.parse_json_object(
        '{"id": 1, "q": "x", "flag": true, "nested": {"a": 1}}'
    )
    assert obj is not None
    names = surface.json_param_names(obj)
    assert "id" in names and "q" in names
    assert "flag" not in names  # bool is not an injectable scalar
    assert "nested" not in names  # nested object skipped in this increment


def test_json_object_rejects_non_objects():
    assert surface.parse_json_object("[1,2,3]") is None
    assert surface.parse_json_object("not json") is None
    assert surface.parse_json_object("") is None
    assert surface.parse_json_object(None) is None


def test_inject_json_replaces_one_field():
    body = surface.inject_json({"id": 1, "q": "x"}, "q", "PAYLOAD")
    assert '"q": "PAYLOAD"' in body
    assert '"id": 1' in body


def test_is_json_request_by_content_type_and_shape():
    assert surface.is_json_request(
        {"request_content_type": "application/json", "request_body": '{"a":1}'}
    )
    # no content-type but a JSON body shape → still detected
    assert surface.is_json_request({"request_body": '{"a":1}'})
    # form body is not JSON
    assert not surface.is_json_request(
        {
            "request_content_type": "application/x-www-form-urlencoded",
            "request_body": "a=1",
        }
    )


def test_path_id_segments_and_swap():
    ids = surface.path_id_segments("http://t/api/users/123/docs/abc")
    # 123 is an id; "abc" is too short to be a hash/uuid → only 123
    vals = [i["value"] for i in ids]
    assert "123" in vals
    swapped = surface.swap_path_segment("http://t/api/users/123", 3, "123*")
    assert swapped == "http://t/api/users/123*"


def test_describe_parameters_covers_all_locations():
    ep = {
        "url": "http://t/api/users/42?sort=asc",
        "method": "POST",
        "request_content_type": "application/json",
        "request_body": '{"name": "a", "role": "b"}',
    }
    model = surface.describe_parameters(ep)
    assert model.get("query") == ["sort"]
    assert set(model.get("json", [])) == {"name", "role"}
    assert model.get("path")  # the /42 segment


# ── build_injection_targets now spans JSON + path ────────────────────────────
def test_build_injection_targets_emits_json_body_target():
    endpoints = [
        {
            "url": "http://t/api/orders",
            "method": "POST",
            "request_content_type": "application/json",
            "request_body": '{"item": "x", "qty": 1}',
        }
    ]
    targets = build_injection_targets(endpoints, [])
    json_targets = [t for t in targets if t.get("content_type") == "application/json"]
    assert json_targets, "no JSON-body injection target built"
    t = json_targets[0]
    assert t["method"] == "POST"
    assert '"item"' in t["data"]


def test_build_injection_targets_emits_path_marker_target():
    endpoints = [{"url": "http://t/api/users/123", "method": "GET"}]
    targets = build_injection_targets(endpoints, [])
    marked = [t for t in targets if t["url"].endswith("123*")]
    assert marked, "no path-parameter (sqlmap '*' marker) target built"


def test_query_and_form_targets_still_built():
    # regression: the original behaviour is preserved
    endpoints = [{"url": "http://t/search?q=1", "method": "GET"}]
    forms = [
        {
            "url": "http://t/login",
            "method": "POST",
            "inputs": [{"name": "user", "type": "text"}],
        }
    ]
    targets = build_injection_targets(endpoints, forms)
    urls = [t["url"] for t in targets]
    assert any("search?q=1" in u for u in urls)
    assert any("/login" in u for u in urls)


# ── injection engine consumes JSON candidates ────────────────────────────────
def test_injection_engine_builds_json_candidates():
    from core.web.injection.engine import InjectionEngine

    ie = InjectionEngine()
    ie._origin_netloc = "t"
    endpoints = [
        {
            "url": "http://t/api/orders",
            "method": "POST",
            "request_content_type": "application/json",
            "request_body": '{"item": "x", "qty": 1}',
        }
    ]
    cands = ie._param_candidates("http://t/", endpoints, [])
    json_cands = [c for c in cands if c.get("kind") == "json"]
    assert json_cands, "injection engine built no JSON candidates"
    assert {c["param"] for c in json_cands} == {"item", "qty"}
    assert json_cands[0]["json_obj"] == {"item": "x", "qty": 1}
