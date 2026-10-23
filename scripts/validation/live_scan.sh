#!/usr/bin/env bash
# Run live scans with one commit's code against the isolated validation targets.
#
#   scripts/validation/targets.sh up
#   scripts/validation/live_scan.sh before <commit> <out-dir>
#   scripts/validation/live_scan.sh after  <commit> <out-dir>
#   python3 scripts/validation/compare_live_scans.py <out-dir>/before.json <out-dir>/after.json
#
# What it does, and what it never does:
#   * takes the code from `git archive <commit>`, so a result belongs to a hash;
#   * runs it in the backend image (CCURE_TEST_IMAGE, default
#     ccure-audit-pro-backend:latest) the way the scanner worker runs: root,
#     NET_RAW and NET_ADMIN, the worker's scanner settings, Celery eager so a
#     whole scan runs in one process;
#   * gives it a throwaway PostgreSQL 18 and Redis 7 on a second internal
#     network created for this run, bootstrapped as CI does, and removes them,
#     the network and the code copy on exit;
#   * attaches the scanner to the targets' network and the database network.
#     Docker does not guarantee their order, and with no default route Scapy's
#     raw ARP would leave by whichever was attached first, so the harness sets
#     Scapy's interface to the one holding the scanner's address
#     (CCURE_LIVE_SCANNER_ADDRESS) and refuses if none does;
#   * excludes VALIDATION_HOST_ADDRESS, the VM's own address on the bridge,
#     from every scan.
#   It never uses the host network, the live database or a production target.
#
# The credentialed scans use throwaway credentials, made for this run only:
#   * two random passwords, generated here and held in shell variables, never
#     exported, never written to a file and never put in a command's arguments;
#   * set on the targets over `docker exec -i` stdin: `chpasswd` for the SSH
#     target's locked audit account, `psql` for the PostgreSQL target's audit
#     role, in a session that logs no statement, so even a failing one cannot
#     carry the password into the server log;
#   * handed to the harness as one JSON line on its stdin. The harness stores
#     them as the application stores any credential (encrypted, in the
#     throwaway database) and the scans resolve them by id, as production does;
#   * searched for after the scans, in every output this run produced and in a
#     dump of the throwaway database: one found is a failed run (exit 3);
#   * revoked on exit, however the run ends: the account's password set back to
#     "!" and the role to NOLOGIN with no password. Revocation that cannot be
#     confirmed fails the run (exit 4).
#
# The rescans change the targets, and only through targets.sh `state`: the
# harness prints "$RESCAN_MARKER <state>" and waits; this script puts the
# targets in that state and answers "ok <state>" (or "failed <state>") on the
# harness's stdin, after the credentials line. Nothing else is ever written
# there. On exit, however the run ends, the targets go back to `original`;
# a restoration that cannot be confirmed fails the run (exit 7).
#
# Exit status: the harness's (0; 5 a credentialed scan did not authenticate;
# 6 the rescans did not reach every classification), or 3 a credential leaked,
# 4 revocation not confirmed, 7 the targets not restored.
# docs/ci/LIVE_SCAN_VALIDATION.md has the whole procedure.
set -euo pipefail
if [ "$#" -ne 3 ]; then
  echo "usage: $0 <label> <commit> <out-dir>" >&2
  exit 2
fi
LABEL=$1
COMMIT=$2
OUT=$(mkdir -p "$3" && cd "$3" && pwd)
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(git -C "$HERE" rev-parse --show-toplevel)
# shellcheck source=targets.env
. "$HERE/targets.env"
IMAGE=${CCURE_TEST_IMAGE:-ccure-audit-pro-backend:latest}
case "$LABEL" in *[!A-Za-z0-9_-]*|"") echo "label must be [A-Za-z0-9_-]+" >&2; exit 2;; esac
RUN="ccure-live-$LABEL-$$"
INFRA="$RUN-infra"
WORK=$(mktemp -d)
random_hex() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }
# What the harness prints to ask for a target state (live_scan_harness.RESCAN_MARKER).
RESCAN_MARKER="@@ccure-rescan-state@@"

if ! docker network inspect "$VALIDATION_NETWORK" >/dev/null 2>&1; then
  echo "no validation targets; run scripts/validation/targets.sh up first" >&2
  exit 1
fi

# The run's throwaway credentials. Shell variables only: not exported, so no
# child process inherits them, and only ever passed to `printf`, a builtin, so
# they never appear in a process's arguments.
SSH_PW=$(random_hex 16)
DB_PW=$(random_hex 16)
SINCE=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# Both credentials as patterns for `grep -F -f`, through a pipe rather than a file.
secrets() { printf '%s\n' "$SSH_PW" "$DB_PW"; }

grant_credentials() {
  printf '%s:%s\n' "$SSH_AUDIT_USER" "$SSH_PW" | docker exec -i "$SSH_CONTAINER" chpasswd
  {
    printf '%s\n' \
      "SET log_statement = 'none';" \
      "SET log_min_error_statement = 'panic';" \
      "DO \$\$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '$PG_AUDIT_ROLE') THEN CREATE ROLE $PG_AUDIT_ROLE; END IF; END \$\$;" \
      "GRANT pg_read_all_settings, pg_read_all_stats TO $PG_AUDIT_ROLE;"
    printf "ALTER ROLE %s LOGIN PASSWORD '%s';\n" "$PG_AUDIT_ROLE" "$DB_PW"
  } | docker exec -i "$PG_CONTAINER" psql -U postgres -q -v ON_ERROR_STOP=1 >/dev/null
}

# Revoke, then confirm from the targets themselves. Prints the state only.
revoke_credentials() {
  local ssh_state role_state
  docker exec "$SSH_CONTAINER" sh -c \
    "pkill -u '$SSH_AUDIT_USER' >/dev/null 2>&1; usermod --password '!' '$SSH_AUDIT_USER'" \
    >/dev/null 2>&1 || true
  printf '%s\n' \
    "ALTER ROLE $PG_AUDIT_ROLE NOLOGIN PASSWORD NULL;" \
    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = '$PG_AUDIT_ROLE';" \
    | docker exec -i "$PG_CONTAINER" psql -U postgres -q >/dev/null 2>&1 || true
  ssh_state=$(docker exec "$SSH_CONTAINER" getent shadow "$SSH_AUDIT_USER" 2>/dev/null | cut -d: -f2) || true
  role_state=$(docker exec "$PG_CONTAINER" psql -U postgres -tAc \
    "SELECT rolcanlogin::text || ' ' || (rolpassword IS NULL)::text FROM pg_authid WHERE rolname = '$PG_AUDIT_ROLE'" \
    2>/dev/null) || true
  if [ "$ssh_state" = "!" ] && { [ -z "$role_state" ] || [ "$role_state" = "false true" ]; }; then
    echo "credentials revoked: $SSH_AUDIT_USER locked (password field '!'), $PG_AUDIT_ROLE nologin with no password"
    return 0
  fi
  echo "REVOCATION NOT CONFIRMED: $SSH_AUDIT_USER password field '${ssh_state:-unreadable}'," \
    "$PG_AUDIT_ROLE '${role_state:-unreadable}'" >&2
  return 1
}

# Count the lines of a command's output that hold either credential. Reads all
# of it (-c, not -q), so the command is never cut off by SIGPIPE.
holds_secret() { local n; n=$("$@" 2>&1 | grep -cF -f <(secrets) || true); [ "${n:-0}" -gt 0 ]; }

leak_check() {
  local found=() source
  for source in "$OUT/$LABEL.log" "$OUT/$LABEL.json"; do
    if [ -f "$source" ] && grep -qF -f <(secrets) "$source"; then found+=("$source"); fi
  done
  for source in "$SSH_CONTAINER" "$WEB_CONTAINER" "$REDIS_CONTAINER" "$PG_CONTAINER" "$RUN-pg" "$RUN-redis" "$RUN-scan"; do
    if holds_secret docker logs --since "$SINCE" "$source"; then found+=("docker logs $source"); fi
  done
  if holds_secret docker container inspect "$RUN-scan"; then found+=("docker inspect $RUN-scan"); fi
  if holds_secret docker exec "$RUN-pg" pg_dump -U ccure_user pytest_live_validation; then
    found+=("the throwaway database")
  fi
  if [ "${#found[@]}" -gt 0 ]; then
    echo "SECRET LEAK: a throwaway credential appears in: ${found[*]}" >&2
    return 1
  fi
  echo "secret check: neither credential appears in the run's log or result, in the logs of the" \
    "four targets, the scanner or the throwaway database and broker, in the scanner's" \
    "configuration, or anywhere in a dump of the throwaway database"
}

# Answer the harness's requests for a target state, one line each, until its
# container has exited. Only "ok <state>" or "failed <state>" goes to stdout,
# which is the harness's stdin; what targets.sh says goes to stderr.
answer_rescan_requests() {
  local answered=0 request state status
  while :; do
    status=$(docker container inspect -f '{{.State.Status}}' "$RUN-scan" 2>/dev/null) || status=gone
    case "$status" in created | running) ;; *) return 0 ;; esac
    request=$(grep -a "^$RESCAN_MARKER " "$OUT/$LABEL.log" 2>/dev/null | sed -n "$((answered + 1))p")
    if [ -z "$request" ]; then
      sleep 2
      continue
    fi
    state=${request#"$RESCAN_MARKER "}
    if "$HERE/targets.sh" state "$state" >&2; then
      printf 'ok %s\n' "$state"
    else
      printf 'failed %s\n' "$state"
    fi
    answered=$((answered + 1))
  done
}

cleanup() {
  local status=$? revoked=0 restored=0
  "$HERE/targets.sh" state original >&2 || restored=1
  revoke_credentials || revoked=1
  docker rm -f "$RUN-scan" "$RUN-pg" "$RUN-redis" >/dev/null 2>&1 || true
  docker network rm "$INFRA" >/dev/null 2>&1 || true
  docker run --rm --network none --user 0 -v "$WORK:/w" --entrypoint rm "$IMAGE" \
    -rf /w/repo >/dev/null 2>&1 || true
  rm -rf "$WORK"
  if [ "$revoked" -ne 0 ] && [ "$status" -eq 0 ]; then exit 4; fi
  if [ "$restored" -ne 0 ] && [ "$status" -eq 0 ]; then
    echo "TARGETS NOT RESTORED: run '$HERE/targets.sh state original' or 'targets.sh down'" >&2
    exit 7
  fi
}
trap cleanup EXIT

mkdir -p "$WORK/repo"
git -C "$REPO" archive "$COMMIT" | tar -x -C "$WORK/repo"
chmod -R a+rwX "$WORK/repo"
echo "code: $(git -C "$REPO" rev-parse "$COMMIT")"

docker network create --internal "$INFRA" >/dev/null
PW=$(random_hex 16)
docker run -d --name "$RUN-pg" --network "$INFRA" \
  -e POSTGRES_DB=pytest_live_validation -e POSTGRES_USER=ccure_user -e POSTGRES_PASSWORD="$PW" \
  "$PG_IMAGE" >/dev/null
docker run -d --name "$RUN-redis" --network "$INFRA" "$REDIS_IMAGE" >/dev/null
# Over TCP: the image's initdb server answers on the socket only (6b81530).
for _ in $(seq 1 60); do
  docker exec "$RUN-pg" pg_isready -h 127.0.0.1 -U ccure_user -d pytest_live_validation >/dev/null 2>&1 && break
  sleep 1
done
docker exec "$RUN-pg" pg_isready -h 127.0.0.1 -U ccure_user -d pytest_live_validation >/dev/null

TARGETS="$SSH_TARGET,$WEB_TARGET,$REDIS_TARGET,$PG_TARGET,${EMPTY_ADDRESSES// /,}"
URL="postgresql://ccure_user:$PW@$RUN-pg:5432/pytest_live_validation"
ENVS=(
  -e SKIP_DOTENV_LOAD=1 -e PYTHONDONTWRITEBYTECODE=1
  -e DATABASE_URL="$URL" -e TEST_DATABASE_URL="$URL" -e VULNERABILITY_INTEL_DATABASE_URL="$URL"
  -e CELERY_BROKER_URL="redis://$RUN-redis:6379/0" -e CELERY_RESULT_BACKEND="redis://$RUN-redis:6379/0"
  -e CELERY_TASK_ALWAYS_EAGER=True
  -e MFA_ENCRYPTION_KEY="$(random_hex 24)" -e COMPLIANCE_ENCRYPTION_KEY="$(random_hex 24)"
  -e ENV=development -e APP_ENV=development -e TZ=Asia/Kolkata
  -e NUCLEI_TEMPLATES_DIR=/opt/nuclei-templates -e NMAP_THREADS=4 -e MAX_NMAP_PROCESSES=20
  -e CCURE_BROWSER_CHANNEL=chrome -e SCANNER_RUNTIME=container
  -e CCURE_LIVE_TARGETS="$TARGETS" -e CCURE_LIVE_SWEEP="$VALIDATION_SUBNET"
  -e CCURE_LIVE_EXCLUDE="$VALIDATION_HOST_ADDRESS"
  -e CCURE_LIVE_SCANNER_ADDRESS="$VALIDATION_SCANNER_ADDRESS"
  -e CCURE_LIVE_SSH_TARGET="$SSH_TARGET" -e CCURE_LIVE_PG_TARGET="$PG_TARGET"
  -e CCURE_LIVE_WEB_TARGET="$WEB_TARGET"
)

echo "bootstrapping the schema and catalogue"
docker run --rm --init --network "$INFRA" --user 1000:1000 "${ENVS[@]}" \
  -v "$WORK/repo:/repo" -w /repo/Backend --entrypoint sh "$IMAGE" -c \
  'python db/migrate_production_schema.py >/tmp/b.log 2>&1 &&
   python -m scripts.seed_compliance >>/tmp/b.log 2>&1 &&
   python -m scripts.seed_real_rules >>/tmp/b.log 2>&1 || { tail -20 /tmp/b.log; exit 1; }'

echo "granting throwaway credentials to $SSH_AUDIT_USER on $SSH_TARGET and $PG_AUDIT_ROLE on $PG_TARGET"
grant_credentials

echo "scanning $TARGETS unauthenticated, $SSH_TARGET and $PG_TARGET credentialed, all at once;" \
  "then stopping a sweep of $VALIDATION_SUBNET; then rescanning $WEB_TARGET and $SSH_TARGET," \
  "one at a time, as the harness changes them"
docker create --name "$RUN-scan" --init -i --user 0 --cap-add NET_RAW --cap-add NET_ADMIN \
  --network "$VALIDATION_NETWORK" --ip "$VALIDATION_SCANNER_ADDRESS" "${ENVS[@]}" \
  -v "$WORK/repo:/repo" -v "$HERE:/validation:ro" -v "$OUT:/out" \
  -w /repo/Backend --entrypoint python "$IMAGE" /validation/live_scan_harness.py "$LABEL" >/dev/null
docker network connect "$INFRA" "$RUN-scan"
set +e
{
  printf '{"ssh": {"username": "%s", "password": "%s"}, "database": {"username": "%s", "password": "%s", "database": "postgres"}}\n' \
    "$SSH_AUDIT_USER" "$SSH_PW" "$PG_AUDIT_ROLE" "$DB_PW"
  answer_rescan_requests
} | docker start -a -i "$RUN-scan" >"$OUT/$LABEL.log" 2>&1
status=$?
leak_check
leaked=$?
set -e
echo "harness exit $status; result $OUT/$LABEL.json, log $OUT/$LABEL.log"
if [ "$leaked" -ne 0 ]; then exit 3; fi
exit "$status"
