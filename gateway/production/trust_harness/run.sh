#!/bin/bash
# Phase 10.6 — run the gateway trust-boundary harness (isolated; nothing live).
#
#   gateway/production/trust_harness/run.sh            # tears down afterwards
#   KEEP=1 gateway/production/trust_harness/run.sh     # leave it up
set -euo pipefail
cd "$(dirname "$0")"
REPO=$(cd ../../.. && pwd)
export TRUST_WORK=${TRUST_WORK:-$(mktemp -d)}
compose() { docker compose -p ccure-gw-trust "$@"; }

cleanup() {
    if [ "${KEEP:-0}" != 1 ]; then
        compose --profile run down -v --remove-orphans >/dev/null 2>&1 || true
        docker run --rm -v "$TRUST_WORK":/w alpine:3 rm -rf /w/tls >/dev/null 2>&1 || true
        rm -rf "$TRUST_WORK"
    fi
}
trap cleanup EXIT

echo "== 1. the edge: the committed host nginx file, four mechanical rewrites"
src="$REPO/gateway/edge/host-nginx/ccure.gateway.conf"
sed -e 's/^\(\s*listen\) 443 ssl http2;/\1 8443 ssl http2;/' \
    -e 's/^\(\s*listen\) 80;/\1 8080;/' \
    -e '/^\s*listen \[::\]/d' "$src" > "$TRUST_WORK/edge.conf"
# exactly: 2 IPv6 listeners dropped, 2 ports changed, nothing else
[ "$(diff "$src" "$TRUST_WORK/edge.conf" | grep -c '^<')" = 4 ] || { echo "unexpected rewrite" >&2; exit 1; }
[ "$(diff "$src" "$TRUST_WORK/edge.conf" | grep -c '^>')" = 2 ] || { echo "unexpected rewrite" >&2; exit 1; }
grep -q 'proxy_pass http://unix:/var/lib/ccure-edge/gateway.sock;' "$TRUST_WORK/edge.conf"

echo "== 1b. the frontend: the committed Frontend/nginx.conf, the gateway address rewritten"
fsrc="$REPO/Frontend/nginx.conf"
[ "$(grep -c '172\.31\.254\.10' "$fsrc")" -ge 1 ] || { echo "Frontend/nginx.conf does not name the gateway" >&2; exit 1; }
sed -e 's/172\.31\.254\.10:8080/10.254.40.10:8080/' "$fsrc" > "$TRUST_WORK/frontend.conf"
[ "$(diff "$fsrc" "$TRUST_WORK/frontend.conf" | grep -c '^>')" = 1 ] || { echo "unexpected frontend rewrite" >&2; exit 1; }

echo "== 2. throwaway TLS for the edge (the Phase 10.4 generator; never a live key)"
mkdir -p "$TRUST_WORK/tls"
docker run --rm --network none --user 0 -v "$REPO/gateway/alongside/make_test_tls.py:/g.py:ro" \
    -v "$TRUST_WORK/tls":/out ccure-audit-pro-backend:latest \
    sh -c 'python /g.py /out >/dev/null && cp /out/edge/server.pem /out/edge/ccure-fullchain.crt && cp /out/edge/server.key /out/edge/ccure.key && chown -R 33:33 /out/edge && chmod 0600 /out/edge/*.key'

echo "== 3. stack up"
compose up -d --quiet-pull edge-init stub-api gateway edge-tls frontend >/dev/null
for _ in $(seq 1 30); do
    [ "$(compose ps --format '{{.Service}} {{.State}}' | grep -c running)" = 4 ] && break; sleep 1
done
compose ps --format '{{.Service}} {{.State}}'
if compose logs gateway edge-tls frontend 2>&1 | grep -E '\[emerg\]'; then echo "nginx refused its configuration" >&2; exit 1; fi

echo "== 4. tests"
compose run --rm -T runner python -m pytest -q -p no:cacheprovider -rs .

echo "== 5. restart with a stale socket left behind (kill -9)"
compose kill -s KILL gateway >/dev/null
compose run --rm -T --entrypoint sh runner -c 'test -S /edge/gateway.sock' \
    || { echo "expected a stale socket after kill -9" >&2; exit 1; }
echo "   stale socket present"
compose up -d --no-deps gateway >/dev/null   # --no-deps: edge-init would delete it first
for _ in $(seq 1 20); do compose logs gateway 2>&1 | grep -q "start worker process" && break; sleep 1; done
compose logs gateway 2>&1 | grep -q "30-ccure-edge-socket: removed a stale socket" \
    || { echo "the clean-up script did not run" >&2; exit 1; }
echo "   clean-up script removed it; nginx started"
compose run --rm -T runner python -m pytest -q -p no:cacheprovider -k legitimate .

echo "== 6. logs: a forged address is never logged as the client of an untrusted peer"
compose logs --no-log-prefix gateway 2>/dev/null | python3 -c '
import json, sys
bad, edge_asserted = [], 0
for line in sys.stdin:
    try:
        j = json.loads(line)
    except ValueError:
        continue
    forged = j["client"].startswith(("203.0.113.", "198.51.100."))
    if forged and j["peer"] == "unix:":
        edge_asserted += 1          # the deliberate www-data socket test
    elif forged:
        bad.append(line.strip())
print(f"   gateway: {edge_asserted} forged client(s), all from the www-data socket test")
sys.exit(1 if bad or edge_asserted != 1 else 0)'
if compose logs --no-log-prefix edge-tls 2>/dev/null | awk '{print $1}' | grep -E '^(203\.0\.113|198\.51\.100)\.'; then
    echo "edge logged a forged client" >&2; exit 1
fi
echo "   edge: every logged client is the socket peer"
echo "== trust harness passed"
