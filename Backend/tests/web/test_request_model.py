"""
Phase 22 — unified request-reconstruction model (Codex P0 item 4).

Every engine should receive a normalised, replayable request that carries the
method, headers, cookies, body, content-type, parameter locations and auth
context — not just a URL. These tests pin the model's construction, per-location
parameter cloning, raw-HTTP / curl serialisation, and that sqlmap now consumes a
reconstructed raw request (sqlmap -r) with the session and body intact.
"""

from core.web.request_model import WebRequest, requests_from_surface


def test_from_endpoint_models_json_body_and_params():
    ep = {
        "url": "http://t/api/orders?ref=1",
        "method": "POST",
        "request_content_type": "application/json",
        "request_body": '{"item": "x", "qty": 1}',
        "parameters": {"query": ["ref"], "json": ["item", "qty"]},
    }
    r = WebRequest.from_endpoint(
        ep, auth_headers={"Authorization": "Bearer T"}, auth_cookies={"sid": "abc"}
    )
    assert r.method == "POST"
    assert r.content_type == "application/json"
    assert r.headers["Authorization"] == "Bearer T"
    assert r.cookies["sid"] == "abc"
    locs = dict(_group(r))
    assert "json" in locs and "ref" in locs.get("query", [])


def _group(r):
    out = {}
    for loc, name in r.iter_params():
        out.setdefault(loc, []).append(name)
    return out.items()


def test_clone_with_param_query_json_form_path():
    base = WebRequest(
        method="POST",
        url="http://t/api/users/5?sort=asc",
        body='{"name": "a"}',
        content_type="application/json",
        params={"query": ["sort"], "json": ["name"], "path": ["3"]},
    )
    q = base.clone_with_param("query", "sort", "INJ")
    assert "sort=INJ" in q.url
    j = base.clone_with_param("json", "name", "INJ")
    assert '"name": "INJ"' in j.body
    p = base.clone_with_param("path", "3", "9*")
    assert p.url.endswith("9*?sort=asc") or "/9*" in p.url
    form = WebRequest(
        method="POST",
        url="http://t/login",
        body="user=1&pass=1",
        content_type="application/x-www-form-urlencoded",
        params={"form": ["user", "pass"]},
    )
    f = form.clone_with_param("form", "user", "INJ")
    assert "user=INJ" in f.body


def test_to_raw_http_carries_session_and_body():
    r = WebRequest(
        method="POST",
        url="http://t/api/search?ref=1",
        headers={"Authorization": "Bearer T"},
        cookies={"sid": "abc"},
        body='{"q": "1"}',
        content_type="application/json",
    )
    raw = r.to_raw_http()
    assert raw.startswith("POST /api/search?ref=1 HTTP/1.1")
    assert "Host: t" in raw
    assert "Authorization: Bearer T" in raw
    assert "Cookie: sid=abc" in raw
    assert "Content-Type: application/json" in raw
    assert raw.rstrip().endswith('{"q": "1"}')


def test_to_curl_reproduces_request():
    r = WebRequest(method="GET", url="http://t/s?q=1", cookies={"sid": "abc"})
    c = r.to_curl()
    assert c.startswith("curl -i -X GET")
    assert "http://t/s?q=1" in c
    assert "sid=abc" in c


def test_requests_from_surface_builds_endpoint_and_form_requests():
    reqs = requests_from_surface(
        endpoints=[{"url": "http://t/s?q=1"}],
        forms=[{"url": "http://t/login", "method": "POST", "inputs": [{"name": "u"}]}],
        auth_cookies={"sid": "x"},
    )
    assert len(reqs) == 2
    assert all(r.cookies.get("sid") == "x" for r in reqs)


# ── sqlmap now consumes a reconstructed raw request ──────────────────────────
def test_sqlmap_uses_raw_request_file(monkeypatch):
    from core.web.sqlmap.wrapper import SqlmapWrapper

    captured = {}

    class _R:
        stdout = ""
        stderr = ""
        returncode = 0

    def _fake(self, args, timeout=None, **k):
        captured["args"] = args
        # capture the written request file's contents
        if "-r" in args:
            path = args[args.index("-r") + 1]
            with open(path, encoding="utf-8") as fh:
                captured["req"] = fh.read()
        return _R()

    monkeypatch.setattr(SqlmapWrapper, "require_available", lambda self: None)
    monkeypatch.setattr(SqlmapWrapper, "_run_subprocess", _fake)

    r = WebRequest(
        method="POST",
        url="http://t/api/search",
        cookies={"sid": "abc"},
        body='{"q": "1"}',
        content_type="application/json",
    )
    # target is a bare URL with no params — without raw_request this would skip;
    # raw_request must bypass the gate and drive sqlmap -r.
    res = SqlmapWrapper().run(target=r.url, raw_request=r.to_raw_http())
    assert res["status"] != "skipped"
    assert "-r" in captured["args"]
    assert "-u" not in captured["args"]
    assert "Cookie: sid=abc" in captured["req"]  # session preserved into sqlmap
    assert '{"q": "1"}' in captured["req"]  # body preserved


def test_sqlmap_forces_ssl_for_https_raw_request(monkeypatch):
    """A raw request carries no scheme; sqlmap -r defaults to http, so an https
    target must add --force-ssl or it is silently tested over http (Codex item 4)."""
    from core.web.sqlmap.wrapper import SqlmapWrapper

    captured = {}

    class _R:
        stdout = ""
        stderr = ""
        returncode = 0

    def _fake(self, args, timeout=None, **k):
        captured["args"] = args
        return _R()

    monkeypatch.setattr(SqlmapWrapper, "require_available", lambda self: None)
    monkeypatch.setattr(SqlmapWrapper, "_run_subprocess", _fake)

    https = WebRequest(method="GET", url="https://t/api?id=1")
    SqlmapWrapper().run(target=https.url, raw_request=https.to_raw_http())
    assert "--force-ssl" in captured["args"]

    http = WebRequest(method="GET", url="http://t/api?id=1")
    SqlmapWrapper().run(target=http.url, raw_request=http.to_raw_http())
    assert "--force-ssl" not in captured["args"]
