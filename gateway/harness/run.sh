#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# Run the Phase 10.2d gateway harness end to end. LOCAL ONLY.
#
#   gateway/harness/run.sh            # everything, then tear the harness down
#   KEEP=1 gateway/harness/run.sh     # leave it running for inspection
#
# Uses its own compose project (ccure-gw-harness) on its own internal network.
# Touches no live container, no host nginx, no published port.
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
out=${CCURE_HARNESS_OUT:-$(mktemp -d)}
compose() { docker compose -f "$here/docker-compose.yml" --profile run "$@"; }
pytest_in_runner() { compose run --rm -T runner python -m pytest -q -p no:cacheprovider -rs "$@" tests; }

cleanup() {
    if [ "${KEEP:-0}" != "1" ]; then
        compose down -v --remove-orphans >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

echo "== 1. the committed route policy matches the application (drift check)"
docker run --rm --network none -e PYTHONDONTWRITEBYTECODE=1 -v "$repo":/repo:ro -w /repo/Backend \
    ccure-audit-pro-backend:latest python -m scripts.gateway.route_policy --check
echo "   route policy is current"

echo "== 2. harness up"
compose up -d --build gateway gateway-auth stub-api outsider
compose run --rm -T keys-init

echo "== 3. tests with gateway-auth running"
pytest_in_runner -m "not checker_down"

echo "== 4. posture of gateway-auth and nginx"
for service in gateway-auth gateway; do
    cid=$(compose ps -q "$service")
    docker inspect "$cid" --format "   $service: user={{.Config.User}} read_only={{.HostConfig.ReadonlyRootfs}} cap_drop={{.HostConfig.CapDrop}} ports={{.HostConfig.PortBindings}}"
done
checker_image=$(docker inspect "$(compose ps -q gateway-auth)" --format '{{.Image}}')
if docker run --rm --network none --entrypoint sh "$checker_image" -c \
    'find / -xdev \( -name ".env" -o -name "keyset.json" -o -name "*.key" \) 2>/dev/null | grep -v "^/proc" | grep -q . || grep -rqs "PRIVATE KEY" /srv'; then
    echo "   gateway-auth image holds a secret file"; exit 1
fi
echo "   gateway-auth image: no .env, keyset or private key"

echo "== 5. tests with gateway-auth STOPPED (fail closed)"
compose stop gateway-auth
pytest_in_runner -m checker_down
compose start gateway-auth

echo "== 6. logs hold no token, query string or credential header"
compose logs --no-color gateway gateway-auth > "$out/logs.txt"
compose run --rm -T runner cat /harness-out/tokens.txt > "$out/tokens.txt"
python3 "$here/scan_logs.py" "$out/logs.txt" "$out/tokens.txt"

echo "== harness passed (artefacts in $out)"
