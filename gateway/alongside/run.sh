#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# Phase 10.3/10.4 — run the gateway ALONGSIDE, in front of the real application,
# plain (10.3) and behind an isolated TLS test edge on 127.0.0.1:8443 (10.4).
#
#   gateway/alongside/run.sh           # everything, then tear it all down
#   KEEP=1 gateway/alongside/run.sh    # leave it up for inspection
#
# Own compose project (ccure-gw-alongside), own network, database, Redis and a
# throwaway token keyset; a scratch copy of the working tree's Backend/ with no
# .env file of any kind. Nothing live is read or changed: not the live database,
# keys, credentials, host nginx, :443 or :8000. Published ports: 127.0.0.1 only.
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
export ALONGSIDE_WORK=${ALONGSIDE_WORK:-$(mktemp -d)}
compose() { docker compose -f "$here/docker-compose.yml" --profile run "$@"; }
rand() { python3 -c "import secrets; print(secrets.token_urlsafe($1))"; }
fernet() { python3 -c "import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"; }

# Throwaway secrets for this run only; never printed, gone with the stack.
export ALONGSIDE_DB_PASSWORD=$(rand 24) ALONGSIDE_JWT_SECRET=$(rand 48) ALONGSIDE_MFA_KEY=$(rand 48)
export ALONGSIDE_COMPLIANCE_KEY=$(fernet) ALONGSIDE_USER_PASSWORD="Aa1!$(rand 24)"

cleanup() {
    if [ "${KEEP:-0}" != "1" ]; then
        compose down -v --remove-orphans >/dev/null 2>&1 || true
        docker run --rm -v "$ALONGSIDE_WORK":/w alpine:3 rm -rf /w/Backend /w/keys /w/tls >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

live_state() {
    # What production must still look like at the end: nothing here is changed.
    sha256sum /etc/nginx/conf.d/ccure.conf | cut -c1-16
    docker inspect ccure-api ccure-db --format '{{.Name}} {{.State.StartedAt}}'
    sha256sum /home/cdac/ccure-keys/keyset.json 2>/dev/null | cut -c1-16 || echo "keyset not readable"
    docker exec ccure-api printenv CCURE_TOKEN_SIGNING_ALG CCURE_ACCEPT_LEGACY_HS256 2>/dev/null | tr '\n' ' '; echo
    docker exec ccure-db psql -U postgres -d ccure_db -Atc 'select version_num from alembic_version'
}
live_before=$(live_state)

echo "== 1. scratch copy of Backend/ (no .env of any kind) and a throwaway keyset"
mkdir -p "$ALONGSIDE_WORK/Backend" "$ALONGSIDE_WORK/keys" "$ALONGSIDE_WORK/out"
rsync -a --delete --exclude='.env*' --exclude='.venv' --exclude='__pycache__' --exclude='reports' \
    --exclude='logs' --exclude='backups' "$repo/Backend/" "$ALONGSIDE_WORK/Backend/"
mkdir -p "$ALONGSIDE_WORK/Backend/reports"
if find "$ALONGSIDE_WORK/Backend" -name '.env*' | grep -q .; then echo "   an .env file reached the copy"; exit 1; fi
chmod -R a+rwX "$ALONGSIDE_WORK/Backend" "$ALONGSIDE_WORK/out"
docker run --rm --network none --user 0 -v "$ALONGSIDE_WORK/Backend":/app:ro -v "$ALONGSIDE_WORK/keys":/keys \
    -w /app -e PYTHONDONTWRITEBYTECODE=1 ccure-audit-pro-backend:latest \
    sh -c 'python -m scripts.security.manage_token_keys --keys-dir /keys generate --state active >/dev/null && chown -R 1000:1000 /keys'
echo "   keyset: $(ls "$ALONGSIDE_WORK/keys" | grep -c pem) key(s), throwaway"
mkdir -p "$ALONGSIDE_WORK/tls"
docker run --rm --network none --user 0 -v "$here":/alongside:ro -v "$ALONGSIDE_WORK/tls":/out \
    -e PYTHONDONTWRITEBYTECODE=1 ccure-audit-pro-backend:latest \
    sh -c 'python /alongside/make_test_tls.py /out && chown -R 101:101 /out/edge && chmod 0600 /out/edge/server.key && chmod 0644 /out/ca.pem /out/edge/server.pem'
echo "   TLS: throwaway CA + leaf in the run's scratch directory (CA key never written)"

echo "== 2. stack up (real api image; migrations on a fresh database)"
compose up -d --build --wait db redis api api-edge gateway-auth gateway edge-tls insider
compose exec -T -e ALONGSIDE_USER_PASSWORD api python /alongside/seed_user.py

echo "== 3. gateway-auth has the api's public keys"
for _ in $(seq 60); do
    compose exec -T gateway-auth python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).status == 200 else 1)" \
        >/dev/null 2>&1 && break
    sleep 1
done

echo "== 4. tests (real application)"
compose run --rm -T runner python -m pytest -q -p no:cacheprovider -rs tests

echo "== 4b. TLS listener from the host (published 127.0.0.1:8443) and static checks"
compose run --rm -T -e EDGE_TLS_ADDR=127.0.0.1:8443 -e PYTHONPATH=/gateway:/gateway/alongside/tls_tests runner \
    python -m pytest -q -p no:cacheprovider -rs tls_tests/test_tls_listener.py tls_tests/test_tls_static.py

echo "== 4c. HTTPS through the TLS edge, from inside the network (real client addresses)"
compose run --rm -T runner-tls python -m pytest -q -p no:cacheprovider -rs tls_tests

echo "== 4d. request.client, audit address and rate-limit identity agree"
compose logs --no-color api | grep -o 'RATE_LIMIT_REJECTED[^|]*ip=[0-9a-f.:]*' | grep -o 'ip=[0-9a-f.:]*' | sort | uniq -c | sed 's/^/   /'
if compose logs --no-color api | grep 'RATE_LIMIT_REJECTED' | grep -q 'ip=203\.0\.113\.'; then
    echo "   a forged address became a rate-limit identity"; exit 1
fi
compose logs --no-color api | grep 'RATE_LIMIT_REJECTED' | grep -q "ip=$(cat "$ALONGSIDE_WORK/out/expected_rate_limit_ip.txt")" \
    || { echo "   the HTTPS client's real address never became its rate-limit identity"; exit 1; }
echo "   the HTTPS client was limited under its real address; no forged address was ever a key"

echo "== 5. latency (direct vs gateway, $(python3 -c 'print(250)') requests each)"
python3 - "$ALONGSIDE_WORK/out/latency.json" <<'PY'
import json, sys
for label, r in json.load(open(sys.argv[1])).items():
    print(f"   {label:26} direct p50 {r['direct']['p50']:6.2f} p95 {r['direct']['p95']:6.2f} | "
          f"gateway p50 {r['gateway']['p50']:6.2f} p95 {r['gateway']['p95']:6.2f} | "
          f"overhead p50 {r['overhead_p50_ms']:+.2f} p95 {r['overhead_p95_ms']:+.2f} ms "
          f"({'within' if r['within_5ms_p95'] else 'EXCEEDS'} +5 ms p95)")
PY

echo "== 6. exposure"
ss -ltn | awk 'NR>1 {print $4}' | grep -E ':(8082|8443|18000|18001|18050)$' | sed 's/^/   listening: /'
if ss -ltn | awk 'NR>1 {print $4}' | grep -E ':(8082|8443|18000|18001|18050)$' | grep -vq '^127\.0\.0\.1:'; then
    echo "   a harness port is bound beyond loopback"; exit 1
fi
[ -z "$(docker port "$(compose ps -q gateway-auth)")" ] && echo "   gateway-auth: no published port"
for service in gateway gateway-auth edge-tls; do
    cid=$(compose ps -q "$service")
    docker inspect "$cid" --format "   $service: user={{.Config.User}} read_only={{.HostConfig.ReadonlyRootfs}} cap_drop={{.HostConfig.CapDrop}}"
    allowed_key=""
    [ "$service" = edge-tls ] && allowed_key="/etc/nginx/edge-tls/server.key"
    if docker exec "$cid" sh -c 'grep -rlsE "PRIVATE KEY" /etc /srv /tmp 2>/dev/null; find / -xdev \( -name ".env*" -o -name "keyset.json" \) 2>/dev/null | grep -v ^/proc' \
        | grep -v "^${allowed_key:-^$}$" | grep -q .; then
        echo "   $service holds key or .env material"; exit 1
    fi
done
echo "   gateway and gateway-auth: no private key, keyset or .env; edge-tls: only the throwaway test key"

echo "== 7. logs"
compose logs --no-color gateway gateway-auth edge-tls > "$ALONGSIDE_WORK/out/gateway-logs.txt"
compose logs --no-color api > "$ALONGSIDE_WORK/out/api-logs.txt"
python3 "$repo/gateway/harness/scan_logs.py" "$ALONGSIDE_WORK/out/gateway-logs.txt" "$ALONGSIDE_WORK/out/tokens.txt"
echo "   api (application, not gateway): $(grep -c 'ticket=' "$ALONGSIDE_WORK/out/api-logs.txt" || true) line(s) with a ticket query — uvicorn's WebSocket access line (F10-3, pre-existing)"

echo "== 8. production is untouched"
live_after=$(live_state)
if [ "$live_before" != "$live_after" ]; then echo "   LIVE STATE CHANGED"; diff <(echo "$live_before") <(echo "$live_after"); exit 1; fi
echo "$live_after" | sed 's/^/   /'
echo "   host nginx config, api/db start times, keyset, token settings and schema head: unchanged"

echo "== alongside validation passed (artefacts in $ALONGSIDE_WORK/out)"
