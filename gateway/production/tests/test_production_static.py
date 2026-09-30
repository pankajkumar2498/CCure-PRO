"""
Phase 10.5 — static checks on the production gateway wiring.

Run on a full checkout (the api container mounts only Backend/ and docs/):

    docker run --rm --network none -v "$PWD":/repo:ro -w /repo \
        ccure-audit-pro-backend:latest python -m pytest -q -p no:cacheprovider gateway/production/tests

What is pinned:

* one set of addresses — the compose network's IPAM, the static addresses of
  api / api-gateway / gateway-auth, the gateway's site file (upstreams and the
  one trusted edge), host nginx's proxy_pass, gateway-auth's JWKS URL and the
  api's TRUSTED_PROXIES all name the same values;
* exposure — gateway-auth and api-gateway publish nothing and sit only on the
  internal network; the api keeps 127.0.0.1:8000 (Phase 10.7 is not done);
* the trust list is exact addresses and grows by exactly the gateway;
* host nginx: the gateway file differs from the pre-10.5 file ONLY in the two
  proxy_pass targets (and comments), and both match the switch script's pins;
* the switch script proves the path over :443 after every reload, rolls back
  automatically, and never touches anything but the one nginx file.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[3]
COMPOSE = REPO / "docker-compose.yml"
SITE = REPO / "gateway/nginx/site/production.conf"
DIRECT = REPO / "gateway/edge/host-nginx/ccure.direct.conf"
GATEWAY = REPO / "gateway/edge/host-nginx/ccure.gateway.conf"
SWITCH = REPO / "scripts/linux/gateway_edge_switch.sh"
TRUST = REPO / "gateway/nginx/trust/unix_edge.conf"
LISTEN = REPO / "gateway/nginx/listen/unix_edge.conf"
SOCK_CLEANUP = REPO / "gateway/nginx/entrypoint/30-ccure-edge-socket.sh"
GATEWAY_CONF = REPO / "gateway/nginx/gateway.conf"
EDGE_DIR, SOCK_IN_CONTAINER = "/var/lib/ccure-edge", "/run/ccure-edge/gateway.sock"
TCP_10_5_SHA = "79d4513217a4fb42e53a73ef97faafb9c526c1aa0c7beddecd2d4e868e027428"

NET = ipaddress.ip_network("172.31.254.0/24")
BRIDGE, GW, AUTH, API = "172.31.254.1", "172.31.254.10", "172.31.254.11", "172.31.254.20"


@pytest.fixture(scope="module")
def compose():
    return yaml.safe_load(COMPOSE.read_text())


def _env(service) -> dict:
    env = service.get("environment", {})
    if isinstance(env, dict):
        return env
    return dict(item.split("=", 1) for item in env)


def _strip_comments(text: str) -> list[str]:
    return [ln for ln in (l.split("#", 1)[0].rstrip() for l in text.splitlines()) if ln.strip()]


# ── one set of addresses ─────────────────────────────────────────────────────
def test_network_is_internal_with_the_pinned_ipam(compose):
    net = compose["networks"]["gateway"]
    assert net["internal"] is True
    cfg = net["ipam"]["config"][0]
    assert ipaddress.ip_network(cfg["subnet"]) == NET
    assert cfg["gateway"] == BRIDGE


@pytest.mark.parametrize("name,addr", [("api", API), ("api-gateway", GW), ("gateway-auth", AUTH)])
def test_static_addresses(compose, name, addr):
    assert compose["services"][name]["networks"]["gateway"]["ipv4_address"] == addr


def test_site_names_the_same_addresses():
    text = "\n".join(_strip_comments(SITE.read_text()))
    assert re.search(r"upstream ccure_api \{\s*server %s:8000;\s*\}" % re.escape(API), text)
    assert re.search(r"upstream ccure_gateway_auth \{\s*server %s:8080;\s*\}" % re.escape(AUTH), text)
    # the trust boundary is not in the site file any more: it is the shared
    # trust file, which the trust harness mounts too
    assert "set_real_ip_from" not in text and "ccure_from_edge" not in text
    assert "include /etc/nginx/ccure/edge_trust.conf;" in text


# ── 10.6: the edge is a unix socket, and nothing else is trusted ─────────────
def test_only_the_unix_socket_is_trusted():
    text = "\n".join(_strip_comments(TRUST.read_text()))
    assert re.findall(r"set_real_ip_from\s+(\S+);", text) == ["unix:"]
    m = re.search(r"map \$realip_remote_addr \$ccure_from_edge \{(.*?)\}", text, re.S).group(1)
    assert [l.split() for l in m.strip().splitlines()] == [["default", "0;"], ['"unix:"', "1;"]]
    assert "geo " not in text  # a geo block cannot match "unix:"
    # no IP address, and in particular not the 10.5 bridge, is trusted anywhere
    for f in (TRUST, SITE, GATEWAY_CONF):
        body = "\n".join(_strip_comments(f.read_text()))
        assert not re.search(re.escape(BRIDGE) + r"(?![0-9])", body), f
        assert not re.search(r"set_real_ip_from\s+\d", body), f


def test_the_socket_listener_is_per_deployment():
    assert _strip_comments(LISTEN.read_text()) == [f"listen unix:{SOCK_IN_CONTAINER};"]
    conf = "\n".join(_strip_comments(GATEWAY_CONF.read_text()))
    # the shared config includes per-deployment listeners by a glob, which
    # matches nothing in the harness and the alongside stack
    assert "include /etc/nginx/ccure/listen.d/*.conf;" in conf
    assert "listen 8080;" in conf


def test_compose_mounts_the_socket_directory_and_the_trust_files(compose):
    svc = compose["services"]["api-gateway"]
    assert svc["group_add"] == ["33"]  # host www-data; the switch script checks the gid
    binds = [v for v in svc["volumes"] if isinstance(v, dict)]
    assert binds == [{"type": "bind", "source": EDGE_DIR, "target": "/run/ccure-edge",
                      "bind": {"create_host_path": False}}]
    strs = {v.split(":")[1]: v.split(":")[0] for v in svc["volumes"] if isinstance(v, str)}
    assert strs["/etc/nginx/ccure/edge_trust.conf"] == "./gateway/nginx/trust/unix_edge.conf"
    assert strs["/etc/nginx/ccure/listen.d/unix_edge.conf"] == "./gateway/nginx/listen/unix_edge.conf"
    assert strs["/docker-entrypoint.d/30-ccure-edge-socket.sh"] == "./gateway/nginx/entrypoint/30-ccure-edge-socket.sh"


def test_stale_socket_cleanup_runs_before_nginx():
    script = SOCK_CLEANUP.read_text()
    assert f"sock={SOCK_IN_CONTAINER}" in script
    assert 'rm -f "$sock"' in script and "set -eu" in script
    # the nginx image runs /docker-entrypoint.d/* in name order before nginx
    assert SOCK_CLEANUP.name < "40-ccure-cors-origins.sh"


def test_gateway_auth_reads_the_core_jwks_and_issuer(compose):
    env = _env(compose["services"]["gateway-auth"])
    assert env["CCURE_JWKS_URL"] == f"http://{API}:8000/auth/jwks.json"
    assert env["CCURE_TOKEN_ISSUER"] == "https://ccurepro.cdac.in"
    assert env["CCURE_TOKEN_USER_AUDIENCE"] == "urn:ccure:api"


def test_trusted_proxies_is_exact_and_names_only_the_gateway(compose):
    # Phase 10.7: 172.18.0.1 (host nginx via the published :8000) is gone with
    # that port; the gateway is the only proxy the api believes.
    env = _env(compose["services"]["api"])
    trusted = env["TRUSTED_PROXIES"].split(",")
    assert trusted == ["127.0.0.1", "::1", GW]
    assert "172.18.0.1" not in env["TRUSTED_PROXIES"]
    for entry in trusted:  # addresses, never a range
        assert "/" not in entry
        ipaddress.ip_address(entry)
    # config.py's default is the same list minus the gateway
    config = (REPO / "Backend/config.py").read_text()
    assert '"TRUSTED_PROXIES", "127.0.0.1,::1,172.18.0.1"' in config


def test_host_nginx_targets_the_gateway_socket():
    targets = re.findall(r"proxy_pass\s+(\S+);", "\n".join(_strip_comments(GATEWAY.read_text())))
    sock = f"http://unix:{EDGE_DIR}/gateway.sock"
    assert targets == [sock, sock, "http://127.0.0.1:3200"]


# ── exposure ─────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("name", ["api-gateway", "gateway-auth"])
def test_gateway_services_publish_nothing_and_live_only_on_the_internal_network(compose, name):
    svc = compose["services"][name]
    assert "ports" not in svc and "expose" not in svc
    assert list(svc["networks"]) == ["gateway"]
    assert "network_mode" not in svc
    assert svc.get("profiles") is None  # part of `docker compose up`


@pytest.mark.parametrize("name", ["api-gateway", "gateway-auth"])
def test_gateway_services_are_locked_down(compose, name):
    svc = compose["services"][name]
    assert svc["read_only"] is True
    assert svc["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in svc["security_opt"]
    assert svc["logging"] == compose["services"]["api"]["logging"]  # the rotated default
    assert svc["restart"] == "unless-stopped"


# ── 10.7: no published or direct ingress to the api ──────────────────────────
EMERGENCY = REPO / "docker-compose.emergency-direct.yml"
FRONTEND_NGINX = REPO / "Frontend/nginx.conf"
START_SH = REPO / "Backend/start.sh"
FRONTEND = "172.31.254.30"


def test_api_publishes_no_port(compose):
    api = compose["services"]["api"]
    assert "ports" not in api and "expose" not in api
    assert api["networks"]["default"]["gw_priority"] == 1  # default route stays on the default network


def test_api_listens_on_its_gateway_network_address_only(compose):
    env = _env(compose["services"]["api"])
    assert env["API_BIND_HOST"] == API == compose["services"]["api"]["networks"]["gateway"]["ipv4_address"]
    script = START_SH.read_text()
    # both uvicorn lines take the address, and the default keeps every other
    # user of start.sh (the alongside stack) on 0.0.0.0
    assert script.count("--host ${API_BIND_HOST:-0.0.0.0}") == 2
    assert "--host 0.0.0.0" not in script


def test_frontend_reaches_the_api_only_through_the_gateway(compose):
    fe = compose["services"]["frontend"]
    assert fe["networks"]["gateway"]["ipv4_address"] == FRONTEND
    assert ipaddress.ip_address(FRONTEND) in NET
    assert fe["ports"] == ["127.0.0.1:3200:80"]  # host nginx serves the SPA from it
    conf = "\n".join(_strip_comments(FRONTEND_NGINX.read_text()))
    block = re.search(r"location /api/ \{(.*?)\n  \}", conf, re.S).group(1)
    assert re.findall(r"proxy_pass\s+(\S+);", block) == [f"http://{GW}:8080"]  # no URI: /api kept
    assert "api:8000" not in conf
    # the gateway trusts no TCP peer, so nothing here pretends otherwise
    for header in ("X-Real-IP", "X-Forwarded-For", "X-Forwarded-Proto"):
        assert header not in block, header
    for kept in ("proxy_set_header Upgrade $http_upgrade;", "client_max_body_size 50m;",
                 "proxy_buffering off;", "proxy_read_timeout 3600s;"):
        assert kept in block, kept


def test_frontend_is_not_trusted_anywhere(compose):
    assert FRONTEND not in _env(compose["services"]["api"])["TRUSTED_PROXIES"]
    for f in (TRUST, SITE):
        assert FRONTEND not in f.read_text()


def test_emergency_override_restores_exactly_the_direct_path():
    ov = yaml.safe_load(EMERGENCY.read_text())
    assert list(ov) == ["services"] and list(ov["services"]) == ["api"]
    api = ov["services"]["api"]
    assert set(api) == {"ports", "environment"}
    assert api["ports"] == ["127.0.0.1:8000:8000"]
    assert _env(api) == {"TRUSTED_PROXIES": "127.0.0.1,::1,172.18.0.1," + GW, "API_BIND_HOST": "0.0.0.0"}


def test_nothing_normal_reads_the_emergency_override():
    for f in REPO.glob("docker-compose*.yml"):
        if f != EMERGENCY:
            assert "emergency-direct" not in yaml.safe_dump(yaml.safe_load(f.read_text())), f


def test_gateway_mounts_only_committed_files_read_only(compose):
    vols = compose["services"]["api-gateway"]["volumes"]
    assert all(v.endswith(":ro") for v in vols if isinstance(v, str))
    vols = [v for v in vols if isinstance(v, str)]
    sources = sorted(v.split(":")[0] for v in vols)
    assert sources == sorted([
        "./gateway/nginx/gateway.conf", "./gateway/nginx/proxy_api.conf",
        "./gateway/policy/route_policy.map", "./gateway/nginx/site/production.conf",
        "./gateway/nginx/trust/unix_edge.conf", "./gateway/nginx/listen/unix_edge.conf",
        "./gateway/nginx/entrypoint/30-ccure-edge-socket.sh",
        "./gateway/nginx/entrypoint/40-ccure-cors-origins.sh"])
    for s in sources:
        assert (REPO / s).is_file()


def test_gateway_uses_the_api_cors_list(compose):
    gw_env = _env(compose["services"]["api-gateway"])
    api_env = _env(compose["services"]["api"])
    assert gw_env["CCURE_CORS_ALLOW_ORIGINS"] == api_env["CORS_ALLOW_ORIGINS"]


def test_nothing_secret_reaches_the_gateway_services(compose):
    for name in ("api-gateway", "gateway-auth"):
        svc = compose["services"][name]
        blob = yaml.safe_dump(svc)
        for needle in ("JWT_SECRET", "MFA_ENCRYPTION", "COMPLIANCE_ENCRYPTION", "POSTGRES_PASSWORD",
                       "ccure-keys", "CCURE_TOKEN_KEYS", ".env", "docker.sock"):
            assert needle not in blob, (name, needle)
        assert "env_file" not in svc


# ── host nginx: only the upstream changes ────────────────────────────────────
def test_gateway_file_differs_from_direct_only_in_proxy_pass():
    direct = _strip_comments(DIRECT.read_text())
    gateway = _strip_comments(GATEWAY.read_text())
    assert len(direct) == len(gateway)
    changed = [(a.strip(), b.strip()) for a, b in zip(direct, gateway) if a != b]
    assert changed == [
        ("proxy_pass http://127.0.0.1:8000/auth/;", f"proxy_pass http://unix:{EDGE_DIR}/gateway.sock;"),
        ("proxy_pass http://127.0.0.1:8000/;", f"proxy_pass http://unix:{EDGE_DIR}/gateway.sock;"),
    ]


def test_request_buffering_is_left_as_it_was():
    # 10.5 decision (PHASE10_5_CUTOVER.md §5): host nginx keeps its default
    # request buffering; the gateway behind it streams.
    for f in (DIRECT, GATEWAY):
        assert "proxy_request_buffering" not in "\n".join(_strip_comments(f.read_text()))
    assert "proxy_request_buffering   off;" in (REPO / "gateway/nginx/proxy_api.conf").read_text()


def test_switch_script_pins_match_the_files():
    script = SWITCH.read_text()
    assert f"SHA_DIRECT={hashlib.sha256(DIRECT.read_bytes()).hexdigest()}" in script
    assert f"SHA_GATEWAY={hashlib.sha256(GATEWAY.read_bytes()).hexdigest()}" in script
    # the 10.5 TCP file is recognised as a state, and never installed
    assert f"SHA_GATEWAY_TCP={TCP_10_5_SHA}" in script
    assert "install_conf" not in "".join(l for l in script.splitlines() if "SHA_GATEWAY_TCP" in l and "state" not in l)
    # the pre-10.5 live file as fingerprinted in 10.4 (PHASE10_4_TLS.md §5)
    assert hashlib.sha256(DIRECT.read_bytes()).hexdigest().startswith("638fd33f797229b6")


def test_switch_script_proves_and_rolls_back():
    script = SWITCH.read_text()
    assert "nginx -t" in script and "systemctl reload nginx" in script
    assert "rolling back to direct" in script
    assert "x-request-id" in script.lower()
    assert f"EDGE_DIR={EDGE_DIR}" in script and "--unix-socket" in script
    # it writes one nginx file, its own rollback directory and the socket
    # directory (root:www-data 0770), nothing else
    writes = re.findall(r"install -m 0644 -o root -g root \S+ (\S+)", script)
    assert set(writes) == {'"$LIVE"'}
    assert 'install -d -m 0770 -o root -g www-data "$EDGE_DIR"' in script
    assert 'LIVE=/etc/nginx/conf.d/ccure.conf' in script
    assert 'KEEP=/etc/nginx/ccure-rollback' in script
    # its one docker action: recreate api-gateway alone, in `harden` (the
    # emergency command appears only inside the hint it prints)
    docker_lines = [l.strip() for l in script.splitlines()
                    if not l.lstrip().startswith("#") and re.search(r"\bdocker (compose|run|exec|rm|stop|kill)", l)]
    assert docker_lines == [
        "docker compose -f docker-compose.yml -f docker-compose.emergency-direct.yml up -d --no-deps api",
        'if ! docker compose --project-directory "$REPO" -p "$project" up -d --no-deps api-gateway >>"$LOG" 2>&1; then']
    hint = script.split('EMERGENCY_HINT="', 1)[1].split('"', 1)[0]
    assert docker_lines[0] in hint
    # 10.7: going direct needs :8000 listening, and the recovery never installs
    # the direct file while it is closed
    to_direct = script.split("to_direct() {", 1)[1].split("\n}\n", 1)[0]
    assert to_direct.strip().startswith('direct_available || die "$EMERGENCY_HINT"')
    to_gateway = script.split("to_gateway() {", 1)[1].split("\n}\n", 1)[0]
    assert "if direct_available; then" in to_gateway and "ccure.conf.restore" in to_gateway
    for forbidden in ("psql", "ccure-keys", "rm -", "systemctl restart", "--force-recreate api "):
        assert forbidden not in script, forbidden
    # every failure after the recreate lands on direct
    harden = script.split("harden() {", 1)[1].split("\n}\n", 1)[0]
    assert harden.count("to_direct; exit 1") == 3
