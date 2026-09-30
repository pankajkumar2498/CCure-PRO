#!/usr/bin/env bash
# Phase 11.3 rehearsal: the module Alembic branches on a restored copy.
#
#   scripts/db/rehearse_module_branches.sh <full dump> <output dir>
#
# Nothing here touches the live database or the live Backend tree:
#   * every database it creates, migrates or drops is named ccure_rehearsal_*
#     (scripts/db/rehearsal_env.py refuses anything else);
#   * the code runs from a copy of Backend at /tmp/r113 inside ccure-api, with
#     alembic.ini activated by exactly `alembic_module_branches --write`, i.e.
#     the same edit the live step will make. The copy's .env is a symlink to the
#     live one (never copied); DATABASE_URL is rewritten inside the container
#     and never printed.
#
# Steps, each snapshotted with scripts/db/rehearsal_snapshot.sql:
#   0  restore the dump                                   -> 0_restored
#   1  start-up migrator, branches INACTIVE (= a restart   -> 1_inactive
#      after this commit, before activation)
#   2  start-up migrator, branches ACTIVE (= the live step)-> 2_active
#   3  the same again (idempotence)                       -> 3_active_again
#   4  downgrade policy_pro@base and rank@base            -> 4_downgraded
#   5  upgrade heads                                      -> 5_reupgraded
#   6  fresh empty database: start-up migrator, ACTIVE    -> 6_fresh
#   7  CI's reversibility loop on the fresh database      -> 7_fresh_ci_loop
#   8  migration/schema tests, ACTIVE, on a scratch pytest database
#   9  drop every rehearsal database and the copy
set -euo pipefail

DUMP=${1:?full dump}
OUT=${2:?output dir}
DB=ccure_rehearsal_11_3
FRESH=ccure_rehearsal_11_3_fresh
PYDB=ccure_rehearsal_11_3_pytest_db
COPY=/tmp/r113
HERE=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$OUT"
log() { printf '%s %s\n' "$(date '+%F %T')" "$*" | tee -a "$OUT/rehearsal.log"; }

pg() { docker exec -i ccure-db psql -U postgres -X -v ON_ERROR_STOP=1 -q "$@"; }
snap() {  # snap <db> <name>
  pg -At -d "$1" < "$HERE/rehearsal_snapshot.sql" > "$OUT/$2.snap"
  log "snapshot $2: $(grep -c '' "$OUT/$2.snap") facts; alembic=$(grep '^alembic|' "$OUT/$2.snap" | cut -d'|' -f2 | paste -sd,)"
}
in_copy() {  # in_copy <db var> <db> <command…>
  local var=$1 db=$2; shift 2
  docker exec -w "$COPY" ccure-api python -m scripts.db.rehearsal_env "$var" "$db" -- "$@"
}
drop_all() {
  for d in "$DB" "$FRESH" "$PYDB"; do pg -c "DROP DATABASE IF EXISTS $d WITH (FORCE)"; done
  docker exec ccure-api rm -rf "$COPY"
}

trap 'rc=$?; [ $rc -ne 0 ] && log "FAILED (exit $rc); dropping rehearsal databases"; drop_all; exit $rc' EXIT

log "dump $DUMP sha256 $(sha256sum "$DUMP" | cut -d' ' -f1)"
drop_all

log "step 0: restore into $DB"
pg -c "CREATE DATABASE $DB OWNER ccure_user"
docker exec -i ccure-db pg_restore -U postgres -d "$DB" --exit-on-error < "$DUMP"
snap "$DB" 0_restored

log "copy Backend -> ccure-api:$COPY (no .venv, no .env copies, no reports)"
docker exec -w /app ccure-api sh -c "mkdir -p $COPY && tar --exclude=./.venv --exclude='./.env*' \
  --exclude=./reports --exclude=./logs --exclude='*/__pycache__' --exclude='*.db' -cf - . | tar -C $COPY -xf - \
  && ln -s /app/.env $COPY/.env"
docker exec -w "$COPY" ccure-api python -m scripts.db.alembic_module_branches --status | sed 's/^/  ini before: /' | tee -a "$OUT/rehearsal.log"

log "step 1: start-up migrator, branches inactive"
in_copy DATABASE_URL "$DB" python db/migrate_production_schema.py > "$OUT/1_inactive.out" 2>&1
snap "$DB" 1_inactive

log "activate the copy's alembic.ini"
docker exec -w "$COPY" ccure-api python -m scripts.db.alembic_module_branches --write | tee -a "$OUT/rehearsal.log"
docker exec -w /app ccure-api sh -c "diff alembic.ini $COPY/alembic.ini" > "$OUT/alembic_ini.diff" || true
in_copy DATABASE_URL "$DB" python -m alembic heads > "$OUT/heads_active.txt"
in_copy DATABASE_URL "$DB" python -m alembic history > "$OUT/history_active.txt"

log "step 2: start-up migrator, branches active"
in_copy DATABASE_URL "$DB" python db/migrate_production_schema.py > "$OUT/2_active.out" 2>&1
snap "$DB" 2_active

log "step 3: start-up migrator again (idempotence)"
in_copy DATABASE_URL "$DB" python db/migrate_production_schema.py > "$OUT/3_active_again.out" 2>&1
snap "$DB" 3_active_again

log "step 4: downgrade each module branch to base"
in_copy DATABASE_URL "$DB" python -m alembic downgrade policy_pro@base >> "$OUT/4_downgrade.out" 2>&1
in_copy DATABASE_URL "$DB" python -m alembic downgrade rank@base >> "$OUT/4_downgrade.out" 2>&1
snap "$DB" 4_downgraded

log "step 5: upgrade heads"
in_copy DATABASE_URL "$DB" python -m alembic upgrade heads > "$OUT/5_reupgrade.out" 2>&1
snap "$DB" 5_reupgraded

log "step 6: fresh empty database, start-up migrator, active"
pg -c "CREATE DATABASE $FRESH OWNER ccure_user"
in_copy DATABASE_URL "$FRESH" python db/migrate_production_schema.py > "$OUT/6_fresh.out" 2>&1
snap "$FRESH" 6_fresh

log "step 7: CI reversibility loop on the fresh database"
in_copy DATABASE_URL "$FRESH" sh -c 'for rev in $(python -m alembic heads | awk "{print \$1}"); do
    echo "downgrade ${rev}@-1"; python -m alembic downgrade "${rev}@-1" || exit 1
  done; python -m alembic upgrade heads' > "$OUT/7_ci_loop.out" 2>&1
snap "$FRESH" 7_fresh_ci_loop

log "step 8: migration and schema tests, active, on $PYDB"
pg -c "CREATE DATABASE $PYDB OWNER ccure_user"
set +e
in_copy TEST_DATABASE_URL "$PYDB" python -m pytest -q -p no:cacheprovider \
  tests/repo/test_alembic_module_branches.py tests/repo/test_schema_drift.py \
  tests/audit/test_audit_migration_trigger_restore.py tests/audit/test_audit_immutability.py \
  tests/modules tests/repo/test_module_boundaries.py tests/repo/test_module_registry.py \
  > "$OUT/8_pytest.out" 2>&1
rc=$?
set -e
log "pytest exit $rc: $(tail -1 "$OUT/8_pytest.out")"
pg -d "$PYDB" -Atc "SELECT string_agg(version_num, ',' ORDER BY version_num) FROM alembic_version" | sed 's/^/  pytest db alembic: /' | tee -a "$OUT/rehearsal.log"

log "step 9: drop rehearsal databases and the copy"
trap - EXIT
drop_all
pg -Atc "SELECT string_agg(datname, ',' ORDER BY datname) FROM pg_database" | sed 's/^/  databases now: /' | tee -a "$OUT/rehearsal.log"
log "done"
exit $rc
