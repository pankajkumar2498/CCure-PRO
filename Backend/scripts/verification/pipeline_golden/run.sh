#!/usr/bin/env bash
# Phase-pipeline golden: run the network scan's phase tasks, Celery eager, on a
# copy of a restored database with one commit's code, and capture what crosses
# each phase boundary, in what order, and what a failure or a cancellation
# leaves behind. capture.py says what is run and captured.
#
#   ../findings_golden/run.sh up <full.dump>   the restored server this uses
#   run.sh capture <commit> <out>              capture with <commit>'s Backend/
#                                              code; capture.py is always this
#                                              checkout's
#   run.sh compare <out-a> <out-b>             byte-for-byte comparison
#   ../findings_golden/run.sh down             remove the server
#
# It runs on the findings golden's throwaway PostgreSQL and Redis (internal
# network, nothing published) and its frozen vuln_intel subset, on a fresh
# copy of that golden's restored template (CREATE DATABASE … TEMPLATE), which
# it drops afterwards. The code runs in the backend image as its own user,
# with Celery eager, so a scan's phases run one after another in one process.
set -euo pipefail

REPO=$(git rev-parse --show-toplevel)
TOOL_DIR="$REPO/Backend/scripts/verification/pipeline_golden"
IMAGE=${CCURE_TEST_IMAGE:-ccure-audit-pro-backend:latest}
NET=ccure-findings-golden-net
PG=ccure-findings-golden-pg
REDIS=ccure-findings-golden-redis
STATE=${FINDINGS_GOLDEN_STATE:-$HOME/.cache/ccure-findings-golden}
TEMPLATE=findings_golden_template
INTEL=findings_golden_intel

random_hex() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }
pg() { docker exec -i "$PG" psql -X -q -v ON_ERROR_STOP=1 -U postgres "$@"; }

cmd_capture() {
  local commit=$1 out=$2
  docker inspect "$PG" >/dev/null 2>&1 || {
    echo "run '../findings_golden/run.sh up <dump>' first" >&2
    exit 2
  }
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

  db="pipeline_golden_$(random_hex 3)"
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
CELERY_TASK_ALWAYS_EAGER=True
DATABASE_URL=postgresql://ccure_user:$app_pw@$PG:5432/$db
VULNERABILITY_INTEL_DATABASE_URL=postgresql://ccure_user:$app_pw@$PG:5432/$INTEL
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

case "${1:-}" in
  capture) cmd_capture "${2:?commit}" "${3:?out}" ;;
  compare) cmd_compare "${2:?a}" "${3:?b}" ;;
  *) sed -n '2,13p' "$0"; exit 2 ;;
esac
