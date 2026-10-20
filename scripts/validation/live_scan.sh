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
#   * connects the scanner to the targets' network first: Scapy's raw ARP, ICMP
#     and SYN leave by the default interface, as on the worker's host network
#     (with the database network first, the raw profiles find no host);
#   * excludes VALIDATION_HOST_ADDRESS, the VM's own address on the bridge,
#     from every scan.
#   It never uses the host network, the live database, a production target or
#   a credential. docs/ci/LIVE_SCAN_VALIDATION.md has the whole procedure.
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

if ! docker network inspect "$VALIDATION_NETWORK" >/dev/null 2>&1; then
  echo "no validation targets; run scripts/validation/targets.sh up first" >&2
  exit 1
fi

cleanup() {
  docker rm -f "$RUN-scan" "$RUN-pg" "$RUN-redis" >/dev/null 2>&1 || true
  docker network rm "$INFRA" >/dev/null 2>&1 || true
  docker run --rm --network none --user 0 -v "$WORK:/w" --entrypoint rm "$IMAGE" \
    -rf /w/repo >/dev/null 2>&1 || true
  rm -rf "$WORK"
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
)

echo "bootstrapping the schema and catalogue"
docker run --rm --init --network "$INFRA" --user 1000:1000 "${ENVS[@]}" \
  -v "$WORK/repo:/repo" -w /repo/Backend --entrypoint sh "$IMAGE" -c \
  'python db/migrate_production_schema.py >/tmp/b.log 2>&1 &&
   python -m scripts.seed_compliance >>/tmp/b.log 2>&1 &&
   python -m scripts.seed_real_rules >>/tmp/b.log 2>&1 || { tail -20 /tmp/b.log; exit 1; }'

echo "scanning $TARGETS, then stopping a sweep of $VALIDATION_SUBNET"
docker create --name "$RUN-scan" --init --user 0 --cap-add NET_RAW --cap-add NET_ADMIN \
  --network "$VALIDATION_NETWORK" --ip "$VALIDATION_SCANNER_ADDRESS" "${ENVS[@]}" \
  -v "$WORK/repo:/repo" -v "$HERE:/validation:ro" -v "$OUT:/out" \
  -w /repo/Backend --entrypoint python "$IMAGE" /validation/live_scan_harness.py "$LABEL" >/dev/null
docker network connect "$INFRA" "$RUN-scan"
set +e
docker start -a "$RUN-scan" >"$OUT/$LABEL.log" 2>&1
status=$?
set -e
echo "harness exit $status; result $OUT/$LABEL.json, log $OUT/$LABEL.log"
exit "$status"
