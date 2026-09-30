"""
Static guarantees for the Phase 10.4 TLS test listener. Files only.
"""

from __future__ import annotations

import re
from pathlib import Path

GATEWAY = Path("/gateway") if Path("/gateway/edge").is_dir() else Path(__file__).resolve().parents[2]
EDGE_CONF = (GATEWAY / "edge" / "edge-tls.conf").read_text()
COMPOSE = (GATEWAY / "alongside" / "docker-compose.yml").read_text()
HARNESS_COMPOSE = (GATEWAY / "harness" / "docker-compose.yml").read_text()
GATEWAY_CONF = (GATEWAY / "nginx" / "gateway.conf").read_text()
RUN_FULL = (GATEWAY / "alongside" / "run.sh").read_text()
# run.sh fingerprints production (read-only sha256sum/inspect) to prove at the end
# that nothing changed; that function is the only place it may name production.
_LIVE = re.search(r"\nlive_state\(\) \{\n.*?\n\}\n", RUN_FULL, re.S)
RUN = RUN_FULL.replace(_LIVE.group(0), "\n") if _LIVE else RUN_FULL
PRODUCTION_REFERENCES = ("/etc/nginx/ssl", "ccure-fullchain", "ccure.key", "/etc/ssl/ccure", "ccure-internal-ca",
                         "ccure-keys", "certs/", "/etc/nginx/conf.d/ccure.conf", "letsencrypt", ".env")


def _code(text):
    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


def _service(name):
    start = COMPOSE.index(f"\n  {name}:\n")
    nxt = re.search(r"\n  [a-z][a-z0-9-]*:\n", COMPOSE[start + 1:])
    return COMPOSE[start: start + 1 + nxt.start()] if nxt else COMPOSE[start:]


def test_the_listener_binds_only_127_0_0_1_8443():
    edge = _service("edge-tls")
    assert re.findall(r'-\s*"([^"]+)"\s*$', edge.split("ports:")[1].split("networks:")[0], re.M) == ["127.0.0.1:8443:8443"]
    assert re.findall(r"^\s*listen\s+([^;]+);", _code(EDGE_CONF), re.M) == ["8443 ssl"]


def test_no_port_anywhere_is_published_beyond_loopback():
    for compose in (COMPOSE, HARNESS_COMPOSE):
        for mapping in re.findall(r'^\s*-\s*"(\d[^"]*:\d+[^"]*)"\s*$', _code(compose), re.M):
            if mapping.count(":") >= 2 or "/" not in mapping:
                assert mapping.startswith("127.0.0.1:"), mapping
    assert not re.search(r'"0\.0\.0\.0:\d', _code(COMPOSE))  # (uvicorn's in-container bind is not a publication)


def test_only_tls_1_2_and_1_3_with_forward_secrecy():
    assert re.search(r"ssl_protocols\s+TLSv1\.2 TLSv1\.3;", EDGE_CONF)
    ciphers = re.search(r"ssl_ciphers\s+([^;]+);", EDGE_CONF).group(1).split(":")
    assert ciphers and all(c.startswith("ECDHE-") for c in ciphers)
    assert "ssl_session_tickets       off;" in EDGE_CONF


def test_no_production_certificate_key_or_config_is_referenced():
    for text in (EDGE_CONF, COMPOSE, RUN):
        code = _code(text)
        for reference in PRODUCTION_REFERENCES:
            if reference != ".env":
                assert reference not in code, reference
    assert "--exclude='.env*'" in RUN  # the scratch Backend copy carries no .env of any kind
    # the certificate comes from the run's scratch directory, never the repository
    assert re.search(r'"\$\{ALONGSIDE_WORK:\?run via run\.sh\}/tls/edge:/etc/nginx/edge-tls:ro"', COMPOSE)
    assert "ssl_certificate     /etc/nginx/edge-tls/server.pem;" in EDGE_CONF


def test_production_is_only_ever_read_by_the_live_state_fingerprint():
    assert _LIVE, "run.sh must fingerprint production before and after"
    for line in _LIVE.group(0).strip().splitlines()[1:-1]:
        assert line.strip().startswith(("#", "sha256sum ", "docker inspect ", "docker exec ccure-api printenv ",
                                        "docker exec ccure-db psql ")), line
    assert "select version_num from alembic_version" in _LIVE.group(0)


def test_production_host_nginx_is_never_mounted_or_written():
    for text in (COMPOSE, HARNESS_COMPOSE, RUN):
        code = _code(text)
        assert "/etc/nginx/conf.d/ccure.conf" not in code and "/etc/nginx:" not in code
        assert "systemctl" not in code and "nginx -s" not in code


def test_the_test_private_key_cannot_enter_an_image():
    rules = [line.strip() for line in (GATEWAY / "token_check" / "Dockerfile.dockerignore").read_text().splitlines()
             if line.strip() and not line.startswith("#")]
    assert rules[0] == "*"  # an allow-list: nothing enters the gateway-auth image unless named
    allowed = [line[1:] for line in rules[1:]]
    assert not any("tls" in a or "edge" in a or a.endswith((".key", ".pem")) for a in allowed)
    # and no private key is committed anywhere under gateway/
    for path in GATEWAY.rglob("*"):
        if path.is_file() and path.suffix in (".pem", ".key", ".crt", ".p12"):
            raise AssertionError(f"key or certificate file committed: {path}")
        if path.is_file() and path.suffix in (".py", ".conf", ".yml", ".sh", ".map", ".json"):
            assert "-----BEGIN" not in path.read_text(errors="ignore") or path.name in ("make_test_tls.py", "test_tls_static.py"), path


def test_the_edge_keeps_host_nginx_semantics():
    code = _code(EDGE_CONF)
    for header, value in (("X-Real-IP", "$remote_addr"), ("X-Forwarded-For", "$remote_addr"),
                          ("X-Forwarded-Proto", "$scheme"), ("Host", "$host")):
        assert re.search(rf"proxy_set_header {header}\s+{re.escape(value)};", code), header
    assert "proxy_add_x_forwarded_for" not in code
    assert code.count('add_header Strict-Transport-Security "max-age=300" always;') == 3  # server + two /api/ blocks
    assert code.count("proxy_hide_header Strict-Transport-Security;") == 2


def test_the_edge_log_has_no_query_or_credentials():
    fmt = EDGE_CONF[EDGE_CONF.index("log_format edge_redacted"):]
    fmt = fmt[: fmt.index(";") + 1]
    for variable in ("$request ", "$request_uri", "$args", "$http_authorization", "$http_cookie", "$http_referer"):
        assert variable not in fmt, variable


def test_timeouts_are_as_designed():
    assert EDGE_CONF.count("proxy_read_timeout 3600s;") == 1 and EDGE_CONF.count("proxy_send_timeout 3600s;") == 1
    proxy = (GATEWAY / "nginx" / "proxy_api.conf").read_text()
    assert "proxy_read_timeout        3600s;" in proxy and "proxy_send_timeout        3600s;" in proxy
    assert re.search(r"proxy_read_timeout\s+2s;", GATEWAY_CONF)  # the auth subrequest, bounded
