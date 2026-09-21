"""
Phase 22 — JSON-body IDOR discovery (Codex P1 item 7 delta).

The access-control engine already compares a resource across identities, but its
candidate discovery only found identifiers in the path/query — so an object
referenced in a JSON request body ({"docId": 100}) was never tested for IDOR.
These tests pin that JSON-body object identifiers now become access-control
candidates that the cross-identity test can swap and replay as a POST body.
"""

from core.web.access_control.engine import AccessControlEngine


def _eng():
    e = AccessControlEngine()
    e._origin = "t"
    return e


def test_extracts_json_body_id_candidate():
    e = _eng()
    eps = [
        {
            "url": "http://t/api/doc",
            "method": "POST",
            "request_content_type": "application/json",
            "request_body": '{"docId": 100, "note": "x"}',
        }
    ]
    cands = e._candidates("http://t/", eps)
    json_c = [c for c in cands if c.get("loc") == "json"]
    assert json_c, "no JSON-body IDOR candidate extracted"
    c = json_c[0]
    assert c["param"] == "docId"
    assert c["id_value"] == "100"
    assert c["body_obj"] == {"docId": 100, "note": "x"}
    assert c["method"] == "POST"
    # 'note' is not identifier-shaped → not a candidate
    assert all(c["param"] != "note" for c in json_c)


def test_path_and_query_candidates_still_found():
    e = _eng()
    cands = e._candidates(
        "http://t/api/users/123?id=42", [{"url": "http://t/api/users/123?id=42"}]
    )
    locs = {c["loc"] for c in cands}
    assert "path" in locs  # /123
    assert "query" in locs  # id=42


def test_fetch_json_uses_post_with_swapped_body(monkeypatch):
    import asyncio

    e = _eng()
    cand = {
        "url": "http://t/api/doc",
        "loc": "json",
        "param": "docId",
        "id_value": "100",
        "id_kind": "numeric",
        "body_obj": {"docId": 100},
        "method": "POST",
    }
    captured = {}

    class _Resp:
        status_code = 200
        text = "ok"

    class _Client:
        async def post(self, url, json=None):
            captured["url"] = url
            captured["json"] = json
            return _Resp()

    # override the identifier → the swapped body must carry the new id
    status, body = asyncio.run(e._fetch(_Client(), cand, id_value="999"))
    assert status == 200
    assert captured["json"] == {"docId": "999"}
    assert captured["url"] == "http://t/api/doc"
