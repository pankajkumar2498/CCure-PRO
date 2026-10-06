#!/usr/bin/env bash
# rehearse_isolation.sh -- Phase 18 restored-database rehearsal (PREPARED, not run).
#
# Restores a dump into a NEW scratch database, runs `alembic upgrade heads` there,
# applies bootstrap_module_roles.sql, runs prove_isolation.sql, and drops the
# scratch database. It refuses to touch any database that is not a fresh,
# explicitly named rehearsal database, whatever the caller passes.
#
#   scripts/db/phase18/rehearse_isolation.sh backups/ccure_db_<stamp>_full.dump
#
# Everything goes through `docker exec ccure-db` (the 18 client), like backup_db.sh.
set -euo pipefail

DUMP="${1:?usage: rehearse_isolation.sh <full-dump-file>}"
CONTAINER="${CCURE_DB_CONTAINER:-ccure-db}"
STAMP="$(date +%Y%m%d%H%M%S)"
SCRATCH="ccure_rehearsal_p18_${STAMP}"

FORBIDDEN=(ccure_test ccure_db ccure_prod ccure_app ccure_staging ccure_dev vuln_intel postgres template0 template1)
for name in "${FORBIDDEN[@]}"; do
  if [[ "${SCRATCH,,}" == "$name" || "${CCURE_REHEARSAL_DB:-}" == "$name" ]]; then
    echo "refusing: $name is not a scratch database" >&2; exit 2
  fi
done
# The scratch name is generated here and must match this pattern; an override is
# accepted only if it does too, so the script can never be aimed at a live database.
if [[ -n "${CCURE_REHEARSAL_DB:-}" ]]; then SCRATCH="$CCURE_REHEARSAL_DB"; fi
if [[ ! "$SCRATCH" =~ ^ccure_rehearsal_p18_[0-9a-z_]+$ ]]; then
  echo "refusing: '$SCRATCH' does not match ^ccure_rehearsal_p18_" >&2; exit 2
fi
[[ -f "$DUMP" ]] || { echo "no such dump: $DUMP" >&2; exit 2; }
case "$DUMP" in *_full.dump) ;; *) echo "refusing: needs a _full dump (an _ops dump is not restorable alone)" >&2; exit 2;; esac

psql_su() { docker exec -i "$CONTAINER" psql -U postgres -v ON_ERROR_STOP=1 "$@"; }
cleanup() { psql_su -d postgres -c "DROP DATABASE IF EXISTS \"$SCRATCH\"" >/dev/null 2>&1 || true; }
trap cleanup EXIT

if psql_su -d postgres -Atc "select 1 from pg_database where datname='$SCRATCH'" | grep -q 1; then
  echo "refusing: $SCRATCH already exists" >&2; exit 2
fi

echo "== 1. restore into $SCRATCH"
psql_su -d postgres -c "CREATE DATABASE \"$SCRATCH\" OWNER ccure_user"
docker exec -i "$CONTAINER" pg_restore -U postgres -d "$SCRATCH" --exit-on-error < "$DUMP"

echo "== 2. before: fingerprint of every table's row count"
COUNTS="select table_schema||'.'||table_name, (xpath('/row/c/text()', query_to_xml(format('select count(*) as c from %I.%I', table_schema, table_name), false, true, '')))[1]::text from information_schema.tables where table_schema in ('public','policy_pro','rank') and table_type='BASE TABLE' order by 1"
psql_su -d "$SCRATCH" -Atc "$COUNTS" > "/tmp/p18_before_${STAMP}.txt"

echo "== 3. bootstrap the roles (passwords generated now, never stored)"
rand() { head -c 24 /dev/urandom | base64 | tr -d '/+=\n' | head -c 24; }
# psql runs inside the container and cannot see this checkout, so the \i line is
# replaced by the generated grants' text rather than resolved there:
{ sed '/^\\i scripts\/db\/phase18\/generated_grants.sql/,$d' scripts/db/phase18/bootstrap_module_roles.sql
  cat scripts/db/phase18/generated_grants.sql
  sed -n '/^\\i scripts\/db\/phase18\/generated_grants.sql/,$p' scripts/db/phase18/bootstrap_module_roles.sql | tail -n +2
} | psql_su -d "$SCRATCH" \
    -v pw_platform="$(rand)" -v pw_audit="$(rand)" -v pw_policy="$(rand)" -v pw_rank="$(rand)"

echo "== 4. prove cross-module access is refused"
psql_su -d "$SCRATCH" < scripts/db/phase18/prove_isolation.sql

echo "== 5. after: row counts unchanged (the bootstrap grants, it never writes data)"
psql_su -d "$SCRATCH" -Atc "$COUNTS" > "/tmp/p18_after_${STAMP}.txt"
diff -u "/tmp/p18_before_${STAMP}.txt" "/tmp/p18_after_${STAMP}.txt" && echo "row counts identical"

echo "== done; $SCRATCH is dropped on exit"
