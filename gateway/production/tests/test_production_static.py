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
    lines = _strip_comments(SITE.read_text())
    text = "\n".join(lines)
    assert re.search(r"upstream ccure_api \{\s*server %s:8000;\s*\}" % re.escape(API), text)
    assert re.search(r"upstream ccure_gateway_auth \{\s*server %s:8080;\s*\}" % re.escape(AUTH), text)
    # exactly one trusted edge: the bridge, i.e. host nginx
    assert re.findall(r"set_real_ip_from\s+(\S+);", text) == [BRIDGE]
    geo = re.search(r"geo \$realip_remote_addr \$ccure_from_edge \{(.*?)\}", text, re.S).group(1)
    entries = [l.split() for l in geo.strip().splitlines()]
    assert entries == [["default", "0;"], [BRIDGE, "1;"]]


def test_gateway_auth_reads_the_core_jwks_and_issuer(compose):
    env = _env(compose["services"]["gateway-auth"])
    assert env["CCURE_JWKS_URL"] == f"http://{API}:8000/auth/jwks.json"
    assert env["CCURE_TOKEN_ISSUER"] == "https://ccurepro.cdac.in"
    assert env["CCURE_TOKEN_USER_AUDIENCE"] == "urn:ccure:api"


def test_trusted_proxies_is_exact_and_adds_only_the_gateway(compose):
    env = _env(compose["services"]["api"])
    trusted = env["TRUSTED_PROXIES"].split(",")
    assert trusted == ["127.0.0.1", "::1", "172.18.0.1", GW]
    for entry in trusted:  # addresses, never a range
        assert "/" not in entry
        ipaddress.ip_address(entry)
    # config.py's default is the same list minus the gateway
    config = (REPO / "Backend/config.py").read_text()
    assert '"TRUSTED_PROXIES", "127.0.0.1,::1,172.18.0.1"' in config


def test_host_nginx_targets_the_gateway_address():
    targets = re.findall(r"proxy_pass\s+(\S+);", "\n".join(_strip_comments(GATEWAY.read_text())))
    assert targets == [f"http://{GW}:8080", f"http://{GW}:8080", "http://127.0.0.1:3200"]


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


def test_api_keeps_its_published_port_until_10_7(compose):
    api = compose["services"]["api"]
    assert api["ports"] == ["127.0.0.1:8000:8000"]
    assert api["networks"]["default"]["gw_priority"] == 1  # default route stays on the default network


def test_gateway_mounts_only_committed_files_read_only(compose):
    vols = compose["services"]["api-gateway"]["volumes"]
    assert all(v.endswith(":ro") for v in vols)
    sources = sorted(v.split(":")[0] for v in vols)
    assert sources == sorted([
        "./gateway/nginx/gateway.conf", "./gateway/nginx/proxy_api.conf",
        "./gateway/policy/route_policy.map", "./gateway/nginx/site/production.conf",
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
        ("proxy_pass http://127.0.0.1:8000/auth/;", f"proxy_pass http://{GW}:8080;"),
        ("proxy_pass http://127.0.0.1:8000/;", f"proxy_pass http://{GW}:8080;"),
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
    # the pre-10.5 live file as fingerprinted in 10.4 (PHASE10_4_TLS.md §5)
    assert hashlib.sha256(DIRECT.read_bytes()).hexdigest().startswith("638fd33f797229b6")


def test_switch_script_proves_and_rolls_back():
    script = SWITCH.read_text()
    assert "nginx -t" in script and "systemctl reload nginx" in script
    assert "rolling back to direct" in script
    assert "x-request-id" in script.lower()
    assert f"GATEWAY_ADDR={GW}:8080" in script
    # it writes one nginx file and its own rollback directory, nothing else
    writes = re.findall(r"install -m 0644 -o root -g root \S+ (\S+)", script)
    assert set(writes) == {'"$LIVE"'}
    assert 'LIVE=/etc/nginx/conf.d/ccure.conf' in script
    assert 'KEEP=/etc/nginx/ccure-rollback' in script
    for forbidden in ("docker ", "psql", "ccure-keys", "rm -", "systemctl restart"):
        assert forbidden not in script, forbidden
