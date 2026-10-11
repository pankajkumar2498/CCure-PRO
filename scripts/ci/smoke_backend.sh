#!/usr/bin/env bash
# Smoke-test a built backend image in each role compose runs it as.
#
#   scripts/ci/smoke_backend.sh <image>
#
# Everything it talks to is created here and removed on exit: a private Docker
# network, a fresh PostgreSQL with no published port, and a Redis. The database
# URL is built from that container alone; nothing is read from the caller's
# environment, so a DATABASE_URL exported in the shell — the one that pointed a
# test run at the live database on 10 Aug 2026 — cannot reach this script. The
# credentials are generated per run and never printed.
#
# Checks, per docs/ci/CONTAINER_IMAGES.md:
#   api        starts as `ccure`, migrates a fresh schema, answers GET / on 8000
#   worker     starts as root (compose's user) and answers a Celery ping
#   beat       starts under setpriv as ccure, compose's own command
#   scanners   nuclei, ffuf, subfinder and sqlmap execute (nmap in the worker)
#   secrets    no generated secret appears in any container's log
set -euo pipefail
# Every "does the output contain X" test below reads a here-string, never
# `producer | grep -q X`. Under pipefail, grep -q exits at the first match, the
# producer dies of SIGPIPE, and the pipeline reports failure: the secret check
# written that way passed an image that printed its JWT key (tested).

IMAGE="${1:?usage: smoke_backend.sh <image>}"
RUN_ID="ccure-smoke-$$-$RANDOM"
NET="$RUN_ID"
DB="$RUN_ID-db"
REDIS="$RUN_ID-redis"
KEYS_VOLUME="$RUN_ID-keys"
PG_IMAGE="${SMOKE_POSTGRES_IMAGE:-postgres:18-alpine}"
REDIS_IMAGE="${SMOKE_REDIS_IMAGE:-redis:7-alpine}"

rand() { head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c "$1"; }
DB_USER="smoke_$(rand 8 | tr '[:upper:]' '[:lower:]')"
DB_PASSWORD="$(rand 32)"
DB_NAME="ccure_smoke"
MFA_ENCRYPTION_KEY="$(rand 48)"
COMPLIANCE_ENCRYPTION_KEY="$(rand 48)"
DATABASE_URL="postgresql://${DB_USER}:${DB_PASSWORD}@${DB}:5432/${DB_NAME}?sslmode=disable"

CONTAINERS=()
cleanup() {
  local rc=$?
  if [ "$rc" -ne 0 ]; then
    for c in "${CONTAINERS[@]}"; do
      echo "::group::last log lines of ${c#"$RUN_ID"-}"
      docker logs --tail 40 "$c" 2>&1 | redact || true
      echo "::endgroup::"
    done
  fi
  docker rm -f "${CONTAINERS[@]}" "$DB" "$REDIS" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  docker volume rm "$KEYS_VOLUME" >/dev/null 2>&1 || true
  exit "$rc"
}
trap cleanup EXIT

redact() {
  sed -e "s/${DB_PASSWORD}/[redacted]/g" -e "s/${MFA_ENCRYPTION_KEY}/[redacted]/g" \
      -e "s/${COMPLIANCE_ENCRYPTION_KEY}/[redacted]/g"
}
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "  ok    $*"; }

# The Phase 1 rule, restated for this script: the URL may name this run's own
# database container and nothing else.
case "$DATABASE_URL" in
  "postgresql://${DB_USER}:"*"@${DB}:5432/${DB_NAME}?"*) ;;
  *) fail "DATABASE_URL does not point at this run's disposable database" ;;
esac

echo "== infrastructure ($PG_IMAGE, $REDIS_IMAGE) on network $NET"
docker network create "$NET" >/dev/null
docker run -d --name "$DB" --network "$NET" \
  -e POSTGRES_USER="$DB_USER" -e POSTGRES_PASSWORD="$DB_PASSWORD" -e POSTGRES_DB="$DB_NAME" \
  "$PG_IMAGE" >/dev/null
docker run -d --name "$REDIS" --network "$NET" "$REDIS_IMAGE" >/dev/null
for _ in $(seq 1 60); do
  docker exec "$DB" pg_isready -U "$DB_USER" -d "$DB_NAME" >/dev/null 2>&1 && break
  sleep 1
done
docker exec "$DB" pg_isready -U "$DB_USER" -d "$DB_NAME" >/dev/null || fail "postgres did not become ready"
[ -z "$(docker port "$DB")" ] || fail "the disposable database publishes a port"
pass "disposable postgres and redis ready; database publishes no port"

# The environment compose gives these services, minus what only the live
# deployment has (TLS trust anchor, bind mounts, host networking).
APP_ENV_ARGS=(
  -e TZ=Asia/Kolkata
  -e APP_ENV=production
  -e RELOAD=false
  -e DATABASE_URL="$DATABASE_URL"
  -e PGSSLMODE=disable
  -e CELERY_BROKER_URL="redis://$REDIS:6379/0"
  -e CELERY_RESULT_BACKEND="redis://$REDIS:6379/0"
  -e VULN_DB_HOST="$DB" -e VULN_DB_PORT=5432 -e VULN_DB_NAME=vuln_intel
  -e VULN_DB_USER="$DB_USER" -e VULN_DB_PASSWORD="$DB_PASSWORD"
  -e MFA_ENCRYPTION_KEY="$MFA_ENCRYPTION_KEY"
  -e COMPLIANCE_ENCRYPTION_KEY="$COMPLIANCE_ENCRYPTION_KEY"
  -e CORS_ALLOW_ORIGINS=http://localhost:3000
  -e FRONTEND_URL=http://localhost:3000
)

# The api refuses to start without a token-signing keyset (Phase 9.6c: ES256 is
# the only scheme, and there is no secret to fall back to). Make a throwaway one
# with the image's own key tool, owned by the unprivileged user, in a volume that
# is removed on exit, and mount it read-only into the api alone: workers hold no
# signing keys, as in compose.
echo "== signing keyset (throwaway, api only)"
docker volume create "$KEYS_VOLUME" >/dev/null
CCURE_UID="$(docker run --rm --entrypoint id "$IMAGE" -u ccure)"
CCURE_GID="$(docker run --rm --entrypoint id "$IMAGE" -g ccure)"
docker run --rm --user root -v "$KEYS_VOLUME:/keys" "$IMAGE" \
  python scripts/security/manage_token_keys.py --keys-dir /keys generate \
  --state active --owner "$CCURE_UID:$CCURE_GID" >/dev/null \
  || fail "could not generate a throwaway token keyset"
pass "throwaway ES256 keyset generated"

echo "== api (image default user and command)"
API="$RUN_ID-api"; CONTAINERS+=("$API")
docker run -d --name "$API" --network "$NET" -p 127.0.0.1::8000 "${APP_ENV_ARGS[@]}" \
  -e CCURE_TOKEN_KEYS_DIR=/keys -v "$KEYS_VOLUME:/keys:ro" "$IMAGE" >/dev/null
PORT="$(docker port "$API" 8000/tcp | head -1 | sed 's/.*://')"
code=""
for _ in $(seq 1 90); do
  [ "$(docker inspect -f '{{.State.Running}}' "$API")" = true ] || fail "api container exited during startup"
  code="$(curl -s -o /tmp/"$RUN_ID"-root.json -w '%{http_code}' "http://127.0.0.1:$PORT/" || true)"
  [ "$code" = 200 ] && break
  sleep 2
done
[ "$code" = 200 ] || fail "GET / did not answer 200 within 180s (last: ${code:-no answer})"
python3 -c "import json,sys; json.load(open(sys.argv[1]))" /tmp/"$RUN_ID"-root.json || fail "GET / did not return JSON"
rm -f /tmp/"$RUN_ID"-root.json
pass "GET / answered 200 with JSON on the published 8000/tcp"
[ "$(docker exec "$API" id -un)" = ccure ] || fail "api is not running as ccure"
pass "api runs as ccure"
grep -q '"8000/tcp"' <<<"$(docker image inspect -f '{{json .Config.ExposedPorts}}' "$IMAGE")" || fail "image does not expose 8000/tcp"
pass "image exposes 8000/tcp"
tables="$(docker exec "$DB" psql -U "$DB_USER" -d "$DB_NAME" -Atc \
  "select count(*) from information_schema.tables where table_schema='public'")"
[ "${tables:-0}" -gt 50 ] || fail "startup created only ${tables:-0} tables"
pass "start.sh initialised the schema ($tables tables)"

echo "== scanners execute inside the image (as ccure)"
docker exec "$API" nuclei -version >/dev/null 2>&1 || fail "nuclei does not run"
docker exec "$API" ffuf -V >/dev/null 2>&1 || fail "ffuf does not run"
docker exec "$API" subfinder -version >/dev/null 2>&1 || fail "subfinder does not run"
docker exec "$API" sqlmap --version >/dev/null 2>&1 || fail "sqlmap does not run"
pass "nuclei, ffuf, subfinder and sqlmap execute"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
docker run --rm --network none --entrypoint python \
  -v "$SCRIPT_DIR/scanner_fixture.py:/tmp/scanner_fixture.py:ro" \
  -v "$SCRIPT_DIR/../../Backend/Dockerfile:/tmp/scanner-Dockerfile:ro" "$IMAGE" \
  /tmp/scanner_fixture.py /tmp/scanner-Dockerfile \
  || fail "scanner detection or JSON output changed"
pass "scanner detection and JSON output work against an isolated loopback fixture"
# nmap is not checked here. The Dockerfile gives it file capabilities including
# cap_net_admin, and a file capability outside the container's bounding set
# makes execve fail with EPERM — as ccure and as root alike. Only the worker,
# which compose starts with cap_add NET_ADMIN, can run it; it is checked there.

echo "== worker (compose: user root, cap_add NET_ADMIN NET_RAW, celery worker)"
WORKER="$RUN_ID-worker"; CONTAINERS+=("$WORKER")
docker run -d --name "$WORKER" --hostname smoke-worker --network "$NET" --user root \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  "${APP_ENV_ARGS[@]}" "$IMAGE" \
  celery -A core.celery_app worker --loglevel=info \
  --queues=scanner,default,compliance --concurrency=1 --prefetch-multiplier=1 >/dev/null
pong=""
for _ in $(seq 1 45); do
  [ "$(docker inspect -f '{{.State.Running}}' "$WORKER")" = true ] || fail "worker exited during startup"
  pong="$(docker exec "$WORKER" celery -A core.celery_app inspect ping \
    -d celery@smoke-worker --timeout 5 2>/dev/null || true)"
  grep -q pong <<<"$pong" && break
  sleep 2
done
grep -q pong <<<"$pong" || fail "worker did not answer a Celery ping"
pass "worker answered a Celery ping"
docker exec "$WORKER" nmap --version >/dev/null 2>&1 || fail "nmap does not run in the worker"
pass "nmap executes with the worker's capabilities"

echo "== beat (compose's command, dropping to ccure with setpriv)"
BEAT="$RUN_ID-beat"; CONTAINERS+=("$BEAT")
docker run -d --name "$BEAT" --network "$NET" --user root --tmpfs /var/lib/ccure-beat \
  "${APP_ENV_ARGS[@]}" "$IMAGE" sh -c \
  'chown ccure:ccure /var/lib/ccure-beat && exec setpriv --reuid=ccure --regid=ccure --init-groups celery -A core.celery_app beat --loglevel=info --schedule=/var/lib/ccure-beat/celerybeat-schedule' >/dev/null
for _ in $(seq 1 30); do
  [ "$(docker inspect -f '{{.State.Running}}' "$BEAT")" = true ] || fail "beat exited during startup"
  grep -q 'beat: Starting' <<<"$(docker logs "$BEAT" 2>&1)" && break
  sleep 2
done
grep -q 'beat: Starting' <<<"$(docker logs "$BEAT" 2>&1)" || fail "beat did not start"
# The slim image has no ps, so read the celery process's real UID from /proc.
beat_uid="$(docker exec "$BEAT" sh -c \
  'for p in /proc/[0-9]*; do tr "\0" " " < "$p/cmdline" 2>/dev/null | grep -q "celery.* beat" \
     && awk "/^Uid:/{print \$2; exit}" "$p/status" && break; done')"
[ -n "$beat_uid" ] || fail "could not find the beat process"
[ "$beat_uid" = "$(docker exec "$BEAT" id -u ccure)" ] || fail "beat runs as uid $beat_uid, not ccure"
pass "beat started and runs as ccure (uid $beat_uid)"

echo "== secrets never appear in a log"
for c in "${CONTAINERS[@]}"; do
  logs="$(docker logs "$c" 2>&1)"
  for secret in "$DB_PASSWORD" "$MFA_ENCRYPTION_KEY" "$COMPLIANCE_ENCRYPTION_KEY"; do
    if grep -qF -- "$secret" <<<"$logs"; then
      fail "a generated secret was printed by ${c#"$RUN_ID"-}"
    fi
  done
done
pass "no database password, MFA key or encryption key in any log"

echo "PASS: backend image $IMAGE"
