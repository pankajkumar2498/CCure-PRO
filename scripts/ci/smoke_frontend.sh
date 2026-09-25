#!/usr/bin/env bash
# Smoke-test a built frontend image.
#
#   scripts/ci/smoke_frontend.sh <image>
#
# nginx.conf proxies /api/ to http://api:8000 and nginx resolves that name at
# startup, so the image cannot start without a host called `api`. A stand-in
# answers on that alias; it lets the test prove the proxy reaches it without
# involving the real backend.
#
# Checks, per docs/ci/CONTAINER_IMAGES.md:
#   /                  200, the SPA shell, CSP and nosniff headers present
#   /some/deep/route   200, served the SPA shell (client-side routing fallback)
#   /assets/<bundle>   200, served with the immutable cache header
#   /api/...           reaches the upstream named `api` on port 8000
#   logs               no [emerg] or [crit] from nginx
set -euo pipefail
# Every "does the output contain X" test reads a here-string, never
# `producer | grep -q X`: see scripts/ci/smoke_backend.sh for why.

IMAGE="${1:?usage: smoke_frontend.sh <image>}"
RUN_ID="ccure-fe-smoke-$$-$RANDOM"
NET="$RUN_ID"
UPSTREAM="$RUN_ID-api"
WEB="$RUN_ID-web"
STUB_IMAGE="${SMOKE_STUB_IMAGE:-busybox:stable}"
MARKER="ccure-smoke-upstream-$RANDOM$RANDOM"
TMP="$(mktemp -d)"

cleanup() {
  local rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "::group::last log lines of the frontend"
    docker logs --tail 40 "$WEB" 2>&1 || true
    echo "::endgroup::"
  fi
  docker rm -f "$WEB" "$UPSTREAM" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$TMP"
  exit "$rc"
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "  ok    $*"; }

docker network create "$NET" >/dev/null
docker run -d --name "$UPSTREAM" --network "$NET" --network-alias api "$STUB_IMAGE" \
  sh -c "mkdir -p /www && echo $MARKER > /www/index.html && exec httpd -f -p 8000 -h /www" >/dev/null
docker run -d --name "$WEB" --network "$NET" -p 127.0.0.1::80 "$IMAGE" >/dev/null
PORT="$(docker port "$WEB" 80/tcp | head -1 | sed 's/.*://')"
BASE="http://127.0.0.1:$PORT"

code=""
for _ in $(seq 1 30); do
  [ "$(docker inspect -f '{{.State.Running}}' "$WEB")" = true ] || fail "frontend container exited during startup"
  code="$(curl -s -o /dev/null -w '%{http_code}' "$BASE/" || true)"
  [ "$code" = 200 ] && break
  sleep 1
done
[ "$code" = 200 ] || fail "GET / did not answer 200 (last: ${code:-no answer})"

curl -s -D "$TMP/root.h" -o "$TMP/root.html" "$BASE/"
grep -q '<div id="root">' "$TMP/root.html" || fail "GET / did not return the SPA shell"
grep -qi '^content-security-policy:' "$TMP/root.h" || fail "GET / carries no Content-Security-Policy"
grep -qi '^x-content-type-options: nosniff' "$TMP/root.h" || fail "GET / carries no X-Content-Type-Options"
pass "GET / answered 200: SPA shell, CSP and nosniff present"

[ "$(curl -s -o "$TMP/deep.html" -w '%{http_code}' "$BASE/dashboard/some/deep/route")" = 200 ] \
  || fail "a client-side route did not fall back to the SPA shell"
grep -q '<div id="root">' "$TMP/deep.html" || fail "a client-side route served something other than the SPA shell"
pass "client-side routes fall back to the SPA shell"

asset="$(grep -oE '/assets/[A-Za-z0-9._-]+\.js' "$TMP/root.html" | head -1)"
[ -n "$asset" ] || fail "the SPA shell references no /assets/*.js bundle"
[ "$(curl -s -D "$TMP/asset.h" -o /dev/null -w '%{http_code}' "$BASE$asset")" = 200 ] || fail "$asset did not answer 200"
grep -qi '^cache-control:.*immutable' "$TMP/asset.h" || fail "$asset is not served as immutable"
pass "bundle $asset served 200 with an immutable cache header"

body="$(curl -s "$BASE/api/")"
grep -q "$MARKER" <<<"$body" || fail "/api/ did not reach the upstream named api:8000"
pass "/api/ is proxied to the upstream named api on port 8000"

grep -qE '\[(emerg|crit)\]' <<<"$(docker logs "$WEB" 2>&1)" && fail "nginx logged an [emerg] or [crit]"
pass "no [emerg] or [crit] in nginx's log"

echo "PASS: frontend image $IMAGE"
