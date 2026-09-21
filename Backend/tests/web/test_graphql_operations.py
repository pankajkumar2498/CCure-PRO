"""
Phase 22 — GraphQL operation enumeration (Codex P1 item 8).

Phase 21 proved GraphQL introspection *detection*. The audit noted the scanner
did not enumerate operations/variables, so the GraphQL Query/Mutation surface
went untested. These tests pin: valid minimal operation requests are generated
(scalar vs object selection sets), arguments travel in variables (testable
input), and operations are enumerated from an introspection schema.
"""

import asyncio
import json


from core.web.api_scan.engine import (
    ApiScanEngine,
    _unwrap_kind,
    graphql_operation_request,
)


def test_unwrap_kind_through_list_and_nonnull():
    assert _unwrap_kind({"kind": "SCALAR", "name": "String"}) == "SCALAR"
    assert (
        _unwrap_kind({"kind": "NON_NULL", "ofType": {"kind": "OBJECT", "name": "User"}})
        == "OBJECT"
    )
    assert (
        _unwrap_kind(
            {
                "kind": "LIST",
                "ofType": {"kind": "NON_NULL", "ofType": {"kind": "OBJECT"}},
            }
        )
        == "OBJECT"
    )


def test_object_field_gets_typename_selection_and_variable_args():
    op = {"operation": "query", "name": "user", "args": ["id"], "return_kind": "OBJECT"}
    req = graphql_operation_request("http://t/graphql", op)
    body = json.loads(req["request_body"])
    assert req["source"] == "graphql_op" and req["method"] == "POST"
    assert req["request_content_type"] == "application/json"
    # object return → __typename subselection makes the query valid
    assert "__typename" in body["query"]
    # args carried as variables (testable input), not baked into the string
    assert body["variables"] == {"id": "1"}
    assert "$id" in body["query"]


def test_scalar_field_has_no_subselection():
    op = {"operation": "query", "name": "version", "args": [], "return_kind": "SCALAR"}
    body = json.loads(graphql_operation_request("http://t/graphql", op)["request_body"])
    assert "__typename" not in body["query"]
    assert "version" in body["query"]


def test_mutation_operation_kind_preserved():
    op = {
        "operation": "mutation",
        "name": "deleteUser",
        "args": ["id"],
        "return_kind": "OBJECT",
    }
    body = json.loads(graphql_operation_request("http://t/graphql", op)["request_body"])
    assert body["query"].startswith("mutation")


def test_enumerate_operations_from_introspection_schema():
    # Fake httpx-like client returning an ops-introspection schema.
    schema = {
        "data": {
            "__schema": {
                "queryType": {
                    "name": "Query",
                    "fields": [
                        {
                            "name": "users",
                            "args": [{"name": "limit"}],
                            "type": {"kind": "LIST", "ofType": {"kind": "OBJECT"}},
                        },
                        {"name": "__typename", "args": [], "type": {"kind": "SCALAR"}},
                    ],
                },
                "mutationType": {
                    "name": "Mutation",
                    "fields": [
                        {
                            "name": "login",
                            "args": [{"name": "user"}, {"name": "pass"}],
                            "type": {"kind": "OBJECT"},
                        }
                    ],
                },
            }
        }
    }

    class _Resp:
        def json(self):
            return schema

    class _Client:
        async def post(self, url, json=None):
            return _Resp()

    eng = ApiScanEngine()
    ops = asyncio.run(eng._enumerate_graphql_ops(_Client(), "http://t/graphql"))
    names = {(o["operation"], o["name"]) for o in ops}
    assert ("query", "users") in names
    assert ("mutation", "login") in names
    # meta-field __typename is skipped
    assert not any(o["name"].startswith("__") for o in ops)
    login = next(o for o in ops if o["name"] == "login")
    assert login["args"] == ["user", "pass"]


# ── GraphQL variable injection (follow-on): variables are testable inputs ─────
def test_json_param_names_descends_into_graphql_variables():
    from core.web import surface

    body = {
        "query": "query op($id: String) { user(id: $id) { __typename } }",
        "variables": {"id": "1", "limit": 10, "raw": True},
    }
    names = surface.json_param_names(body)
    # the injectable inputs are the variables, not the query/variables envelope
    assert set(names) == {"id", "limit"}  # bool 'raw' excluded
    assert "query" not in names and "variables" not in names


def test_inject_json_sets_graphql_variable_not_envelope():
    import json as _json

    from core.web import surface

    body = {
        "query": "query op($id: String){ user(id:$id){ __typename } }",
        "variables": {"id": "1"},
    }
    out = _json.loads(surface.inject_json(body, "id", "PAYLOAD"))
    assert out["variables"]["id"] == "PAYLOAD"
    assert out["query"] == body["query"]  # envelope untouched


def test_injection_engine_builds_graphql_variable_candidates():

    from core.web.injection.engine import InjectionEngine

    ie = InjectionEngine()
    ie._origin_netloc = "t"
    eps = [
        {
            "url": "http://t/graphql",
            "method": "POST",
            "request_content_type": "application/json",
            "request_body": '{"query": "query op($id: String){ user(id:$id){ __typename } }", "variables": {"id": "1"}}',
        }
    ]
    cands = ie._param_candidates("http://t/", eps, [])
    json_c = [c for c in cands if c.get("kind") == "json"]
    assert json_c and json_c[0]["param"] == "id"  # the variable, not "query"


def test_endpoint_dedup_preserves_distinct_graphql_operations():
    from core.web.crawling.browser import PlaywrightCrawler
    from orchestrator.web_orchestrator import WebScanOrchestrator

    eps = [
        graphql_operation_request(
            "http://t/graphql",
            {
                "operation": "query",
                "name": "user",
                "args": ["id"],
                "return_kind": "OBJECT",
            },
        ),
        graphql_operation_request(
            "http://t/graphql",
            {
                "operation": "query",
                "name": "search",
                "args": ["term"],
                "return_kind": "SCALAR",
            },
        ),
    ]
    assert len(PlaywrightCrawler._deduplicate_endpoints(eps)) == 2
    assert len(WebScanOrchestrator._deduplicate_endpoints(eps)) == 2
