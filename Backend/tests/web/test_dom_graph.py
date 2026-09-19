"""
Phase 23b — DOM state graph (Crawler 2.0 remainder).

A link crawl models a SPA as URLs; this models it as *states* and the
interactions between them, so a scan can prove which states it reached and where
states hide behind a URL that never changed. These tests pin the graph's
identity rules (two states on one URL are distinct; one state from two URLs
collapses), the fingerprint, and the coverage summary — all without a browser.
"""

from core.web.dom_graph import (
    DomStateGraph,
    fingerprint_from_probe,
    normalize_url,
    state_signature,
)


# ── URL normalisation ─────────────────────────────────────────────────────────
def test_normalize_url_drops_anchor_keeps_route():
    assert normalize_url("https://a.test/p#section") == "https://a.test/p"
    # a client route on the fragment is the SPA's state address — kept.
    assert normalize_url("https://a.test/#/settings") == "https://a.test/#/settings"


# ── state identity ─────────────────────────────────────────────────────────────
def test_two_states_on_one_url_are_distinct_nodes():
    """The SPA case a URL list cannot express: same URL, different DOM."""
    g = DomStateGraph()
    a = g.add_state("https://a.test/app", "fp-list-view", "List")
    b = g.add_state("https://a.test/app", "fp-detail-view", "Detail")
    assert a != b
    assert g.node_count == 2
    assert g.summary()["distinct_urls"] == 1
    assert g.summary()["spa_hidden_states"] == 2


def test_one_state_from_two_urls_collapses():
    """Same rendered state reached via two URLs is one node."""
    g = DomStateGraph()
    a = g.add_state("https://a.test/x", "same-fp", "T")
    b = g.add_state("https://a.test/x#", "same-fp", "T")  # anchor stripped
    assert a == b
    assert g.node_count == 1
    assert g._nodes[a]["visits"] == 2


def test_signature_is_stable_and_fingerprint_sensitive():
    s1 = state_signature("https://a.test/p", "fp1")
    s2 = state_signature("https://a.test/p", "fp1")
    s3 = state_signature("https://a.test/p", "fp2")
    assert s1 == s2 and s1 != s3


# ── transitions & summary ──────────────────────────────────────────────────────
def test_transition_records_control_and_summary():
    g = DomStateGraph()
    home = g.add_state("https://a.test/", "home", "Home")
    settings = g.add_state("https://a.test/", "settings-panel", "Settings")
    g.add_transition(home, settings, "open settings", control="button")
    g.add_transition(home, settings, "open settings")  # repeat → count++
    s = g.summary()
    assert s["states"] == 2
    assert s["transitions"] == 1
    assert s["state_changing_controls"] == 1
    edge = g.to_dict()["edges"][0]
    assert edge["from"] == home and edge["to"] == settings
    assert edge["label"] == "open settings" and edge["count"] == 2
    assert edge["self_loop"] is False


def test_self_loop_not_counted_as_transition():
    g = DomStateGraph()
    a = g.add_state("https://a.test/", "fp", "A")
    g.add_transition(a, a, "no-op click")
    assert g.summary()["transitions"] == 0  # a click that changed nothing


def test_to_dict_shape():
    g = DomStateGraph()
    a = g.add_state("https://a.test/", "fp1", "A")
    b = g.add_state("https://a.test/b", "fp2", "B")
    g.add_transition(a, b, "go")
    d = g.to_dict()
    assert set(d) == {"nodes", "edges", "summary"}
    assert len(d["nodes"]) == 2 and len(d["edges"]) == 1
    assert all("url" in n and "id" in n for n in d["nodes"])


# ── fingerprint ────────────────────────────────────────────────────────────────
def test_fingerprint_from_probe_deterministic_and_discriminating():
    p1 = {
        "route": "/app",
        "title": "App",
        "headings": ["dashboard"],
        "skeleton": {"forms": 1, "buttons": 3},
    }
    p2 = dict(p1)
    p3 = {**p1, "skeleton": {"forms": 2, "buttons": 3}}  # a form appeared
    assert fingerprint_from_probe(p1) == fingerprint_from_probe(p2)
    assert fingerprint_from_probe(p1) != fingerprint_from_probe(p3)
    assert fingerprint_from_probe(None) == ""


def test_node_and_edge_bounds():
    g = DomStateGraph()
    # far below the cap — just check counters track
    for i in range(10):
        g.add_state(f"https://a.test/{i}", f"fp{i}", "")
    assert g.node_count == 10
