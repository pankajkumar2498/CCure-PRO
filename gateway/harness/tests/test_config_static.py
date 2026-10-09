"""
Static checks on the committed gateway configuration (Phase 10.2d). They read
files only, so they run in the harness runner and anywhere else /gateway is
mounted.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

GATEWAY = Path("/gateway") if Path("/gateway/nginx").is_dir() else Path(__file__).resolve().parents[2]
CONF = (GATEWAY / "nginx" / "gateway.conf").read_text()
PROXY = (GATEWAY / "nginx" / "proxy_api.conf").read_text()
SITE = (GATEWAY / "nginx" / "site" / "harness.conf").read_text()
COMPOSE = (GATEWAY / "harness" / "docker-compose.yml").read_text()
MAP = (GATEWAY / "policy" / "route_policy.map").read_text()


def _strip_comments(text):
    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


def _block(text, header):
    """The body of the first `header { ... }` block (brace-matched)."""
    start = text.index(header)
    i = text.index("{", start) + 1
    depth = 1
    while depth:
        depth += {"{": 1, "}": -1}.get(text[i], 0)
        i += 1
    return text[start:i]


def _checker_refusals():
    tree = ast.parse((GATEWAY / "token_check" / "checker.py").read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(getattr(t, "id", None) == "REFUSALS" for t in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError("REFUSALS not found in checker.py")


# ── logging ──────────────────────────────────────────────────────────────────

FORBIDDEN_LOG_VARIABLES = ("$request ", "$request\"", "$request'", "$request_uri", "$args", "$query_string",
                           "$arg_", "$http_authorization", "$http_cookie", "$cookie_", "$http_referer",
                           "$http_x_ccure", "$ccure_args_checked", "$request_body")


def test_the_log_format_carries_no_query_credential_cookie_or_referer():
    log_format = CONF[CONF.index("log_format ccure_gw"):]
    log_format = log_format[: log_format.index(";") + 1]
    for variable in FORBIDDEN_LOG_VARIABLES:
        assert variable not in log_format, variable
    assert "$ccure_uri_checked" in log_format
    # captured inside location /api/, never at server level (the auth subrequest re-runs server-level set)
    assert "set $ccure_uri_checked    $uri;" in _block(CONF, "location /api/")
    server_level = _strip_comments(CONF)
    for name in ("location /api/", "location / {"):
        server_level = server_level.replace(_block(_strip_comments(CONF), name), "")
    assert "$ccure_args_checked   $args" not in server_level


def test_only_the_redacted_log_format_is_used():
    code = _strip_comments(CONF)
    assert re.findall(r"access_log\s+([^;]+);", code) == ["/dev/stdout ccure_gw"]
    assert re.findall(r"error_log\s+([^;]+);", code) == ["/dev/stderr crit"]


# ── refusals ─────────────────────────────────────────────────────────────────


def test_refusal_bodies_and_statuses_are_the_checkers():
    refusals = _checker_refusals()
    body_map = _block(CONF, "map $ccure_refusal $ccure_refusal_body")
    refuse = _block(CONF, "location @ccure_refuse")
    for code, (status, message) in refusals.items():
        if code == "ws_refused":
            assert "if ($ccure_refusal = ws_refused)" in refuse
            ws = _block(CONF, "location @ccure_ws_refuse")
            assert "return 403 $ccure_empty;" in ws and "default_type text/plain;" in ws
            assert re.search(r'set \$ccure_empty\s+"";', CONF)
            continue
        body = ('{"success":false,"error_code":"HTTP_%d","message":"%s","detail":"%s","request_id":null}'
                % (status, message, message))
        assert f"{code:<18} '{body}';" in body_map or f"{code} '{body}';" in body_map, code
        assert re.search(rf"if \(\$ccure_refusal = {code}\)\s*\{{ return {status} \$ccure_refusal_body; \}}", refuse), code


def test_no_www_authenticate_anywhere():
    for text in (CONF, PROXY, SITE, MAP):
        assert "www-authenticate" not in _strip_comments(text).lower()


def test_an_unknown_refusal_code_fails_closed():
    refuse = _block(CONF, "location @ccure_refuse")
    assert refuse.rstrip().endswith("}")
    assert "return 503" in refuse.split("# A refusal code this gateway does not know")[1]


# ── header hygiene ───────────────────────────────────────────────────────────


def test_add_header_only_in_the_gateways_own_responses():
    code = _strip_comments(CONF)
    assert "add_header" not in _strip_comments(PROXY)
    assert "add_header" not in _block(code, "location /api/")
    assert "add_header" not in _block(code, "location @ccure_noauth")
    outside = code
    for name in ("location @ccure_refuse", "location @ccure_auth_unavailable"):
        outside = outside.replace(_block(code, name), "")
    assert "add_header" not in outside


def test_identity_headers_are_cleared_and_the_address_is_set_not_appended():
    code = _strip_comments(PROXY)
    for header in ("X-Tenant-ID", "X-Org-ID", "X-User", "X-User-ID", "X-Auth-User", "X-Forwarded-User",
                   "X-Remote-User", "X-Ccure-Policy", "X-Ccure-Args", "X-Ccure-Refusal"):
        assert re.search(rf'proxy_set_header {re.escape(header)}\s+"";', code), header
    for header in ("Sub", "Jti", "Ptype", "Kind"):
        assert re.search(rf"proxy_set_header X-Ccure-Auth-{header}\s+\$ccure_auth_{header.lower()};", code)
    assert "proxy_add_x_forwarded_for" not in code
    assert re.search(r"proxy_set_header X-Forwarded-For\s+\$remote_addr;", code)


def test_the_auth_subrequest_sends_only_what_the_checker_reads():
    auth = _strip_comments(_block(CONF, "location = /_ccure_auth"))
    assert "internal;" in auth and "proxy_pass_request_body off;" in auth
    for header, variable in (("X-Ccure-Policy", "$ccure_policy_checked"), ("X-Ccure-Method", "$ccure_method_checked"),
                             ("X-Ccure-Args", "$ccure_args_checked")):
        assert re.search(rf"proxy_set_header {header}\s+{re.escape(variable)};", auth), header
    assert re.search(r'proxy_set_header Cookie\s+"";', auth)


# ── the generated route policy is consumed, never copied ─────────────────────


def test_the_generated_map_is_included_not_duplicated():
    assert "include /etc/nginx/ccure/route_policy.map;" in CONF
    assert "../policy/route_policy.map:/etc/nginx/ccure/route_policy.map:ro" in COMPOSE
    for text in (CONF, PROXY, SITE):
        code = _strip_comments(text)
        assert "~^http:" not in code and "~^websocket:" not in code and "http:GET:" not in code
        assert "$ccure_route_class {" not in code  # the class map is defined only by the generated file
    # Every route path in the map stays out of the hand-written configuration.
    paths = set(re.findall(r"^\s+http:[A-Z]+:(/[^\s]+)", MAP, re.M))
    for path in paths - {"/"}:
        assert path not in _strip_comments(CONF) and path not in _strip_comments(PROXY), path


def test_the_only_policy_decision_in_the_configuration_is_none():
    code = _strip_comments(CONF)
    assert re.findall(r"\$ccure_policy_checked = (\w+)", code) == ["none"]


# ── trust boundary and exposure ──────────────────────────────────────────────


def test_the_harness_trusts_one_edge_address_only():
    code = _strip_comments(SITE)
    trusted = re.findall(r"set_real_ip_from\s+([^;]+);", code)
    assert trusted == ["10.254.10.10"]
    geo = _block(code, "geo $realip_remote_addr $ccure_from_edge")
    assert re.findall(r"^\s+([0-9./]+)\s+1;", geo, re.M) == ["10.254.10.10"]
    assert "0.0.0.0" not in code and "/8" not in code and "/12" not in code and "/16" not in code


def test_the_harness_publishes_no_port_and_has_no_route_out():
    code = _strip_comments(COMPOSE)
    assert "ports:" not in code and "8082" not in code
    assert "internal: true" in COMPOSE
    assert "network_mode: host" not in COMPOSE


def test_gateway_auth_and_nginx_run_unprivileged_and_read_only():
    gateway = COMPOSE[COMPOSE.index("  gateway:"):COMPOSE.index("  gateway-auth:")]
    checker = COMPOSE[COMPOSE.index("  gateway-auth:"):COMPOSE.index("  stub-api:")]
    for block in (gateway, checker):
        assert "read_only: true" in block and "cap_drop: [ALL]" in block and "no-new-privileges:true" in block
    assert 'user: "101:101"' in gateway
    assert "USER 10001:10001" in (GATEWAY / "token_check" / "Dockerfile").read_text()
    for block in (gateway, checker):
        assert ".env" not in block and "keys" not in block.replace("harness-keys", "")
