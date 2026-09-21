"""
core/web/dom_graph.py
────────────────────────────────────────────────────────────────────────────
DOM state graph (Phase 23b, Crawler 2.0 remainder).

A link crawl models an application as a set of URLs. A single-page application
is not a set of URLs — one URL is many *states* reached by interaction, and two
different URLs can render the identical state. The autonomous interaction pass
(``browser._interact_page``) already clicks safe controls to reach those hidden
states; this records the result as a directed graph so a scan can answer

    from state S, control "Open settings" led to state T

rather than just "these URLs exist". That graph is what tells a reviewer which
states were reached, which controls change state, and where SPA states hide
behind a URL that never changed — the coverage question a URL list cannot.

A **state** is identified by its URL *and* a cheap structural fingerprint of the
visible DOM (route markers, headings, form/landmark skeleton), so two states on
one URL are distinct nodes and one state reached from two URLs collapses to one.
It stores no page content, no values and no secrets — only URLs, a hash, short
labels and structural counts — and serialises into ``scans.options`` (no new
table), so the report and API can prove interaction coverage.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, Optional
from urllib.parse import urlparse, urlunparse

_MAX_NODES = 500
_MAX_EDGES = 2000
_LABEL_MAX = 80


def normalize_url(url: str) -> str:
    """URL without fragment query noise stripped to a stable node key. The
    fragment is kept when it is a client route (``#/settings``) because that *is*
    the SPA's state address, but a bare ``#`` anchor is dropped."""
    try:
        p = urlparse(url or "")
        frag = p.fragment
        if frag and not frag.startswith("/"):
            frag = ""  # in-page anchor, not a route
        return urlunparse(p._replace(fragment=frag))
    except Exception:
        return (url or "").split("#")[0]


def state_signature(url: str, fingerprint: str) -> str:
    """A stable node id from the normalized URL plus the DOM fingerprint, so a
    state is identified by *what it shows*, not only where it is."""
    base = normalize_url(url)
    raw = f"{base}\n{fingerprint or ''}"
    return "st_" + hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()[:16]


class DomStateGraph:
    """A directed graph of DOM states and the interactions that connect them."""

    def __init__(self) -> None:
        self._nodes: Dict[str, Dict[str, Any]] = {}
        self._edges: Dict[tuple, Dict[str, Any]] = {}

    # ── construction ──────────────────────────────────────────────────────────
    def add_state(
        self,
        url: str,
        fingerprint: str = "",
        title: str = "",
        skeleton: Optional[Dict[str, int]] = None,
    ) -> str:
        """Register a state and return its signature (the node id)."""
        sig = state_signature(url, fingerprint)
        node = self._nodes.get(sig)
        if node is None:
            if len(self._nodes) >= _MAX_NODES:
                return sig  # bounded; stop growing the graph but keep a valid id
            self._nodes[sig] = {
                "id": sig,
                "url": normalize_url(url),
                "title": (title or "")[:120],
                "fingerprint": fingerprint or "",
                "skeleton": skeleton or {},
                "visits": 1,
            }
        else:
            node["visits"] += 1
            if title and not node.get("title"):
                node["title"] = title[:120]
        return sig

    def add_transition(
        self, from_sig: str, to_sig: str, label: str = "", control: str = ""
    ) -> None:
        """Record that a control in ``from_sig`` led to ``to_sig``."""
        if not from_sig or not to_sig:
            return
        key = (from_sig, to_sig, (label or "")[:_LABEL_MAX])
        edge = self._edges.get(key)
        if edge is None:
            if len(self._edges) >= _MAX_EDGES:
                return
            self._edges[key] = {
                "from": from_sig,
                "to": to_sig,
                "label": (label or "")[:_LABEL_MAX],
                "control": (control or "")[:_LABEL_MAX],
                "count": 1,
                "self_loop": from_sig == to_sig,
            }
        else:
            edge["count"] += 1

    # ── summary / serialisation ───────────────────────────────────────────────
    def summary(self) -> Dict[str, Any]:
        urls: Dict[str, int] = {}
        for n in self._nodes.values():
            urls[n["url"]] = urls.get(n["url"], 0) + 1
        # SPA states: a single URL that renders more than one distinct state.
        spa_states = sum(count for count in urls.values() if count > 1)
        transitions = [e for e in self._edges.values() if not e["self_loop"]]
        return {
            "states": len(self._nodes),
            "distinct_urls": len(urls),
            "spa_hidden_states": spa_states,
            "transitions": len(transitions),
            "state_changing_controls": len(
                {e["label"] for e in transitions if e["label"]}
            ),
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": list(self._nodes.values()),
            "edges": list(self._edges.values()),
            "summary": self.summary(),
        }

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return len(self._edges)


#: The DOM structural probe, run in the page via ``page.evaluate``. It returns a
#: compact fingerprint of the *visible* structure — route hints, headings, and a
#: skeleton of landmark/form counts — never any text values, so two genuinely
#: different states differ and cosmetic churn (a spinner, a timestamp) does not.
DOM_FINGERPRINT_JS = """
() => {
  const vis = (el) => {
    const s = window.getComputedStyle(el);
    return s && s.display !== 'none' && s.visibility !== 'hidden';
  };
  const count = (sel) => document.querySelectorAll(sel).length;
  const heads = Array.from(document.querySelectorAll('h1,h2,[role=heading]'))
    .slice(0, 8).map(h => (h.innerText || '').trim().slice(0, 40).toLowerCase());
  const skeleton = {
    forms: count('form'),
    inputs: count('input,select,textarea'),
    buttons: count('button,[role=button]'),
    links: count('a[href]'),
    tables: count('table'),
    nav: count('nav,[role=navigation]'),
    dialogs: Array.from(document.querySelectorAll('[role=dialog],dialog'))
                  .filter(vis).length,
  };
  const route = location.hash && location.hash.startsWith('#/')
    ? location.hash : (location.pathname || '');
  return {
    route,
    title: (document.title || '').slice(0, 120),
    headings: heads,
    skeleton,
  };
}
"""


def fingerprint_from_probe(probe: Optional[Dict[str, Any]]) -> str:
    """Fold the DOM probe result into a short stable fingerprint string."""
    if not isinstance(probe, dict):
        return ""
    sk = probe.get("skeleton") or {}
    sk_part = ",".join(f"{k}:{sk[k]}" for k in sorted(sk))
    heads = "|".join(probe.get("headings") or [])
    raw = f"{probe.get('route', '')}#{heads}#{sk_part}"
    return hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()[:16]
