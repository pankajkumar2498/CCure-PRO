#!/usr/bin/env bash
# Smoke-test a built gateway-auth image.
#
#   scripts/ci/smoke_gateway_auth.sh <image>
#
# gateway-auth holds no secret: it fetches the core's public keys from a JWKS
# URL at run time. A stand-in serves the public JWKS of a throwaway P-256 key
# that the image's own Python generates and throws away, on a network of this
# run's own, so nothing reaches the live core and no real key is involved. The
# container runs hardened exactly as docker-compose.yml runs it: read-only root,
# every capability dropped, no-new-privileges, tmpfs /tmp.
#
# Checks, per docs/ci/CONTAINER_IMAGES.md:
#   user               10001:10001, never root
#   /healthz           200 once the key set is loaded
#   /check none        204: a route needing no credential
#   /check bearer      403 with X-Ccure-Refusal when no token is sent (FastAPI
#                      HTTPBearer's answer), 401 for a token that does not verify
#   /check unknown     500: an unknown route policy fails closed
#   image              no .env, keyset or private key anywhere
#   logs               no Python traceback
set -euo pipefail
# Every "does the output contain X" test reads a here-string, never
# `producer | grep -q X`: see scripts/ci/smoke_backend.sh for why.

IMAGE="${1:?usage: smoke_gateway_auth.sh <image>}"
RUN_ID="ccure-gwauth-smoke-$$-$RANDOM"
NET="$RUN_ID"
JWKS="$RUN_ID-jwks"
AUTH="$RUN_ID-auth"
STUB_IMAGE="${SMOKE_STUB_IMAGE:-busybox:stable}"
TMP="$(mktemp -d)"

cleanup() {
  local rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "::group::last log lines of gateway-auth"
    docker logs --tail 40 "$AUTH" 2>&1 || true
    echo "::endgroup::"
  fi
  docker rm -f "$AUTH" "$JWKS" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$TMP"
  exit "$rc"
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "  ok    $*"; }

user="$(docker image inspect -f '{{.Config.User}}' "$IMAGE")"
[ "$user" = "10001:10001" ] || fail "the image runs as '${user:-root}', not 10001:10001"
pass "image user is 10001:10001"

# The public half of a key generated here and discarded; the private half never
# leaves this process.
docker run --rm --network none --entrypoint python "$IMAGE" -c '
import base64, json
from cryptography.hazmat.primitives.asymmetric import ec
n = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()
b = lambda i: base64.urlsafe_b64encode(i.to_bytes(32, "big")).rstrip(b"=").decode()
print(json.dumps({"keys": [{"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig",
                            "kid": "smoke", "x": b(n.x), "y": b(n.y)}]}))
' > "$TMP/jwks.json"

docker network create "$NET" >/dev/null
docker run -d --name "$JWKS" --network "$NET" -v "$TMP/jwks.json:/www/jwks.json:ro" \
  "$STUB_IMAGE" httpd -f -p 8080 -h /www >/dev/null
docker run -d --name "$AUTH" --network "$NET" -p 127.0.0.1::8080 \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true --tmpfs /tmp \
  -e CCURE_JWKS_URL="http://$JWKS:8080/jwks.json" \
  -e CCURE_TOKEN_ISSUER="https://issuer.smoke.test" \
  -e CCURE_TOKEN_USER_AUDIENCE="urn:ccure:api" \
  "$IMAGE" >/dev/null
PORT="$(docker port "$AUTH" 8080/tcp | head -1 | sed 's/.*://')"
BASE="http://127.0.0.1:$PORT"

code=""
for _ in $(seq 1 30); do
  [ "$(docker inspect -f '{{.State.Running}}' "$AUTH")" = true ] || fail "gateway-auth exited during startup"
  code="$(curl -s -o /dev/null -w '%{http_code}' "$BASE/healthz" || true)"
  [ "$code" = 200 ] && break
  sleep 1
done
[ "$code" = 200 ] || fail "/healthz did not answer 200 (last: ${code:-no answer})"
pass "/healthz answered 200 once the key set loaded"

check() { curl -s -D "$TMP/check.h" -o /dev/null -w '%{http_code}' -H "X-Ccure-Policy: $1" "${@:2}" "$BASE/check"; }
[ "$(check none)" = 204 ] || fail "/check with policy 'none' did not answer 204"
pass "/check with policy 'none' answered 204"
[ "$(check bearer)" = 403 ] || fail "/check with policy 'bearer' and no token did not answer 403"
grep -qi '^x-ccure-refusal:' "$TMP/check.h" || fail "the 403 carried no X-Ccure-Refusal header"
pass "/check with policy 'bearer' and no token answered 403 with X-Ccure-Refusal"
[ "$(check bearer -H 'Authorization: Bearer not.a.token')" = 401 ] \
  || fail "/check with policy 'bearer' and a token that does not verify did not answer 401"
pass "/check with policy 'bearer' and a token that does not verify answered 401"
[ "$(check no-such-policy)" = 500 ] || fail "an unknown route policy did not fail closed with 500"
pass "an unknown route policy fails closed with 500"

found="$(docker run --rm --network none --entrypoint sh "$IMAGE" -c \
  'find / -xdev \( -name ".env" -o -name "keyset.json" -o -name "*.key" \) 2>/dev/null | grep -v "^/proc"; grep -rls "PRIVATE KEY" /srv 2>/dev/null' || true)"
[ -z "$found" ] || fail "the image holds a secret-shaped file: $found"
pass "the image holds no .env, keyset or private key"

grep -q 'Traceback' <<<"$(docker logs "$AUTH" 2>&1)" && fail "gateway-auth logged a Python traceback"
pass "no Python traceback in gateway-auth's log"

echo "PASS: gateway-auth image $IMAGE"
