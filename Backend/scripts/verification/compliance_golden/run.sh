#!/usr/bin/env bash
# Compliance golden: run the compliance assessment, its evidence, the
# scan-policy catalogue checks and the benchmark loaders on a restored copy of
# the database with one commit's code, and capture what they decide, so two
# commits can be compared byte for byte. capture.py says what is captured, and
# setup.sql what is added to the restored copy first.
#
#   run.sh up <full.dump>          restore the dump into a throwaway PostgreSQL
#                                  and apply setup.sql to it, once
#   run.sh capture <commit> <out>  capture with <commit>'s Backend/ code;
#                                  capture.py and setup.sql are always this
#                                  checkout's, so a commit predating the tool
#                                  can be captured too
#   run.sh compare <out-a> <out-b> byte-for-byte comparison of two captures
#   run.sh down                    remove the containers, network and state
#
# What it does, and what it never does:
#   * the restored copy and every capture run in a PostgreSQL 18 container on
#     an *internal* Docker network (no route out, nothing published), as the
#     superuser and an application role whose password is generated here and
#     kept in a mode-700 state directory until `down`;
#   * it never connects to the live server: `up` reads only the dump file;
#   * each capture works on a fresh copy of the restored template
#     (CREATE DATABASE … TEMPLATE), which it drops afterwards;
#   * the code runs in the backend image as its own user, with no network
#     beyond the internal one, and Celery, the limiter and the evidence cache
#     pointed at a throwaway Redis beside the database.
#
# Requires Docker and the backend image (CCURE_TEST_IMAGE, default
# ccure-audit-pro-backend:latest).
set -euo pipefail

REPO=$(git rev-parse --show-toplevel)
TOOL_DIR="$REPO/Backend/scripts/verification/compliance_golden"
IMAGE=${CCURE_TEST_IMAGE:-ccure-audit-pro-backend:latest}
NET=ccure-compliance-golden-net
PG=ccure-compliance-golden-pg
REDIS=ccure-compliance-golden-redis
STATE=${COMPLIANCE_GOLDEN_STATE:-$HOME/.cache/ccure-compliance-golden}
TEMPLATE=compliance_golden_template

random_hex() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }
pg() { docker exec -i "$PG" psql -X -q -v ON_ERROR_STOP=1 -U postgres "$@"; }

wait_ready() {
  # Over TCP: the image's entrypoint answers on the socket during initdb.
  for _ in $(seq 1 90); do
    docker exec "$PG" pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1 && return 0
    sleep 1
  done
  docker exec "$PG" pg_isready -h 127.0.0.1 -U postgres >/dev/null
}

cmd_up() {
  local dump=$1
  [ -f "$dump" ] || { echo "no such dump: $dump" >&2; exit 2; }
  if docker inspect "$PG" >/dev/null 2>&1; then
    echo "$PG already exists; run '$0 down' first" >&2
    exit 2
  fi
  mkdir -p "$STATE" && chmod 700 "$STATE"
  local app_pw super_pw
  app_pw=$(random_hex 16)
  super_pw=$(random_hex 16)
  printf '%s\n' "$app_pw" >"$STATE/app_password"
  chmod 600 "$STATE/app_password"
  printf '%s\n' "$dump" >"$STATE/dump"

  echo "starting throwaway PostgreSQL 18 on an internal network"
  docker network create --internal "$NET" >/dev/null
  docker run -d --name "$PG" --network "$NET" -e POSTGRES_PASSWORD="$super_pw" \
    postgres:18-alpine >/dev/null
  docker run -d --name "$REDIS" --network "$NET" redis:7-alpine >/dev/null
  wait_ready
  # A query without ORDER BY returns rows in the order the plan produces
  # them; parallel plans and autovacuum would make two captures of the same
  # code differ. Off, for this throwaway server only.
  pg -d postgres <<'SQL' >/dev/null
ALTER SYSTEM SET autovacuum = off;
ALTER SYSTEM SET max_parallel_workers_per_gather = 0;
ALTER SYSTEM SET synchronize_seqscans = off;
SELECT pg_reload_conf();
SQL

  echo "restoring $(basename "$dump") into $TEMPLATE"
  pg -d postgres <<SQL
CREATE ROLE ccure_user LOGIN PASSWORD '$app_pw';
CREATE ROLE audit_chain_writer NOLOGIN;
CREATE ROLE audit_maintenance NOLOGIN;
CREATE DATABASE $TEMPLATE OWNER ccure_user;
SQL
  docker exec -i "$PG" pg_restore -U postgres -d "$TEMPLATE" --exit-on-error <"$dump"
  echo "applying setup.sql"
  pg -d "$TEMPLATE" -t -A <"$TOOL_DIR/setup.sql"
  pg -d "$TEMPLATE" -c "VACUUM ANALYZE" >/dev/null
}

cmd_capture() {
  local commit=$1 out=$2
  docker inspect "$PG" >/dev/null 2>&1 || { echo "run '$0 up <dump>' first" >&2; exit 2; }
  [ ! -e "$out" ] || { echo "$out exists" >&2; exit 2; }
  local app_pw rev work db status
  app_pw=$(cat "$STATE/app_password")
  rev=$(git -C "$REPO" rev-parse --verify "$commit^{commit}")
  work=$(mktemp -d)
  trap 'docker run --rm --network none --user 0 -v "'"$work"':/w" --entrypoint rm "'"$IMAGE"'" -rf /w/repo /w/tool >/dev/null 2>&1 || true; rm -rf "'"$work"'"' RETURN

  mkdir -p "$work/repo" "$work/tool" "$out"
  git -C "$REPO" archive "$rev" Backend | tar -x -C "$work/repo"
  cp "$TOOL_DIR/capture.py" "$work/tool/"
  chmod -R a+rX "$work/repo" "$work/tool"
  chmod a+rwx "$out"
  printf '%s\n' "$rev" >"$out/commit"

  db="compliance_golden_$(random_hex 3)"
  pg -d postgres -c "CREATE DATABASE $db TEMPLATE $TEMPLATE OWNER ccure_user"
  docker exec "$REDIS" redis-cli FLUSHALL >/dev/null
  # Passwords go in an env file, never on a command line.
  (
    umask 077
    cat >"$work/capture.env" <<ENV
SKIP_DOTENV_LOAD=1
PYTHONDONTWRITEBYTECODE=1
PYTHONHASHSEED=0
TZ=UTC
PGSSLMODE=disable
MAC_VENDOR_API_URL=
DATABASE_URL=postgresql://ccure_user:$app_pw@$PG:5432/$db
VULNERABILITY_INTEL_DATABASE_URL=postgresql://ccure_user:$app_pw@$PG:5432/$db
CELERY_BROKER_URL=redis://$REDIS:6379/0
CELERY_RESULT_BACKEND=redis://$REDIS:6379/0
MFA_ENCRYPTION_KEY=$(random_hex 24)
COMPLIANCE_ENCRYPTION_KEY=$(random_hex 24)
ENV
  )
  set +e
  docker run --rm --init --network "$NET" --user 1000:1000 \
    --env-file "$work/capture.env" \
    -v "$work/repo:/repo:ro" -v "$work/tool:/tool:ro" -v "$out:/out" \
    -w /repo/Backend --entrypoint python "$IMAGE" \
    /tool/capture.py --out /out >"$out/capture.log" 2>&1
  status=$?
  set -e
  pg -d postgres -c "DROP DATABASE IF EXISTS $db" >/dev/null
  # The image's user wrote them; hand them back to whoever ran this.
  docker run --rm --network none --user 0 -v "$out:/out" --entrypoint chown "$IMAGE" \
    -R "$(id -u):$(id -g)" /out
  echo "capture of ${rev:0:7} -> $out (exit $status)"
  return "$status"
}

cmd_compare() {
  python3 "$TOOL_DIR/../findings_golden/compare.py" "$1" "$2"
}

cmd_down() {
  docker rm -f "$PG" "$REDIS" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$STATE"
  echo "removed"
}

case "${1:-}" in
  up) cmd_up "${2:?dump}" ;;
  capture) cmd_capture "${2:?commit}" "${3:?out}" ;;
  compare) cmd_compare "${2:?a}" "${3:?b}" ;;
  down) cmd_down ;;
  *) sed -n '2,15p' "$0"; exit 2 ;;
esac
