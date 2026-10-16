#!/usr/bin/env bash
# Run the database-backed guard tests locally, the way CI runs them, without
# touching any live database.
#
#   scripts/ci/local_guard_tests.sh                 # the guard set (below)
#   scripts/ci/local_guard_tests.sh tests/security  # any pytest targets, from Backend/
#
# The architecture ratchets (tests/repo), the sudo-password guard and the
# credential-API authorization tests need the backend's dependencies and a
# PostgreSQL, because tests/conftest.py builds a schema before the first test.
# The stdlib-only half of the same rules is the `architecture-guards`
# pre-commit hook (Backend/scripts/architecture/check.py); this is the rest.
# docs/ci/LOCAL_ENFORCEMENT.md says what runs where.
#
# What it does, and what it never does:
#   * copies the tracked and untracked-but-not-ignored files of this checkout
#     into a temporary directory — never .env, backups/, a venv or node_modules;
#   * starts a throwaway PostgreSQL 18 and Redis 7 on an *internal* Docker
#     network (no route out, nothing published), with credentials generated
#     for this run only;
#   * bootstraps the schema and the compliance catalogue as CI does, runs
#     pytest in the backend image as its own user, and removes everything on
#     exit, whatever the outcome.
#   It never connects to ccure-db or any other running service.
#
# Tests that need the DBA-installed audit chain skip themselves on a throwaway
# database and say "NOT VERIFIED, not passing"; they are reported, not hidden.
#
# Requires Docker and the backend image (CCURE_TEST_IMAGE, default
# ccure-audit-pro-backend:latest). Exit status is pytest's.
set -euo pipefail

REPO=$(git rev-parse --show-toplevel)
IMAGE=${CCURE_TEST_IMAGE:-ccure-audit-pro-backend:latest}
RUN_ID="ccure-guards-$$-$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
NET="$RUN_ID-net"
PG="$RUN_ID-pg"
REDIS="$RUN_ID-redis"
WORK=$(mktemp -d)

DEFAULT_TARGETS=(
  tests/repo
  tests/credentialed/test_sudo_password_safety.py
  tests/security/test_credential_api_consolidation.py
)
if [ "$#" -gt 0 ]; then TARGETS=("$@"); else TARGETS=("${DEFAULT_TARGETS[@]}"); fi

cleanup() {
  docker rm -f "$PG" "$REDIS" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  # Files the tests wrote belong to the image's user; remove them as that user.
  docker run --rm --network none --user 0 -v "$WORK:/w" --entrypoint rm "$IMAGE" \
    -rf /w/repo >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

random_hex() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }
DB_USER=ccure_user
DB_NAME=pytest_local_guards # matches tests/conftest.py's disposable-name guard
DB_PASSWORD=$(random_hex 16)
URL="postgresql://$DB_USER:$DB_PASSWORD@$PG:5432/$DB_NAME"

echo "staging the checkout"
mkdir -p "$WORK/repo"
(cd "$REPO" && git ls-files -co --exclude-standard) >"$WORK/files.txt"
rsync -a --files-from="$WORK/files.txt" "$REPO/" "$WORK/repo/"
chmod -R a+rwX "$WORK/repo"

echo "starting throwaway PostgreSQL and Redis on an internal network"
docker network create --internal "$NET" >/dev/null
docker run -d --name "$PG" --network "$NET" \
  -e POSTGRES_DB="$DB_NAME" -e POSTGRES_USER="$DB_USER" -e POSTGRES_PASSWORD="$DB_PASSWORD" \
  postgres:18-alpine >/dev/null
docker run -d --name "$REDIS" --network "$NET" redis:7-alpine >/dev/null
for _ in $(seq 1 60); do
  docker exec "$PG" pg_isready -U "$DB_USER" -d "$DB_NAME" >/dev/null 2>&1 && break
  sleep 1
done
docker exec "$PG" pg_isready -U "$DB_USER" -d "$DB_NAME" >/dev/null

run_in_image() {
  docker run --rm --init --network "$NET" --user 1000:1000 \
    -e SKIP_DOTENV_LOAD=1 -e PYTHONDONTWRITEBYTECODE=1 -e MOCK_SCANNERS=true \
    -e DATABASE_URL="$URL" -e TEST_DATABASE_URL="$URL" \
    -e VULNERABILITY_INTEL_DATABASE_URL="$URL" \
    -e CELERY_BROKER_URL="redis://$REDIS:6379/0" \
    -e CELERY_RESULT_BACKEND="redis://$REDIS:6379/0" \
    -e MFA_ENCRYPTION_KEY="$(random_hex 24)" \
    -e COMPLIANCE_ENCRYPTION_KEY="$(random_hex 24)" \
    -v "$WORK/repo:/repo" -w /repo/Backend --entrypoint "$1" "$IMAGE" "${@:2}"
}

echo "bootstrapping the schema and catalogue (as CI does)"
run_in_image sh -c 'python db/migrate_production_schema.py >/tmp/b.log 2>&1 &&
  python -m scripts.seed_compliance >>/tmp/b.log 2>&1 &&
  python -m scripts.seed_real_rules >>/tmp/b.log 2>&1 || { tail -20 /tmp/b.log; exit 1; }'

echo "running: ${TARGETS[*]}"
set +e
run_in_image python -m pytest -p no:cacheprovider -q -rfEs "${TARGETS[@]}"
status=$?
set -e
exit "$status"
