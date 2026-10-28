#!/usr/bin/env bash
# Findings golden: replay a restored database's stored scan payloads through
# the findings write paths with one commit's code, and capture the rows,
# exports, scan comparisons and remediation verification outcomes they
# produce, so two commits can be compared byte for byte. capture.py says what
# is replayed and captured.
#
#   run.sh up <full.dump>          restore the dump, and a frozen subset of
#                                  vuln_intel, into a throwaway PostgreSQL
#   run.sh capture <commit> <out>  capture the three modes with <commit>'s
#                                  Backend/ code; capture.py is always this
#                                  checkout's, so a commit predating the tool
#                                  can be captured too
#   run.sh compare <out-a> <out-b> byte-for-byte comparison of two captures
#   run.sh down                    remove the container, network and state
#
# What it does, and what it never does:
#   * the restored copy and every replay run in a PostgreSQL 18 container on an
#     *internal* Docker network (no route out, nothing published), as the
#     superuser and an application role whose passwords are generated here and
#     kept in a mode-700 state directory until `down`;
#   * the only access to the live server is `up`'s, and it only reads: the
#     vuln_intel rows for the CVEs the dump's payloads name, in a read-only
#     transaction. The subset is loaded once, so a feed sync between two
#     captures cannot change them;
#   * each capture works on fresh copies of the restored template
#     (CREATE DATABASE … TEMPLATE), which it drops afterwards;
#   * the code runs in the backend image as its own user, with no network
#     beyond the internal one, the vendor-lookup API disabled, and Celery and the
#     limiter pointed at a throwaway Redis beside the database.
#
# Requires Docker, the backend image (CCURE_TEST_IMAGE, default
# ccure-audit-pro-backend:latest) and the ccure-db container for `up`.
set -euo pipefail

REPO=$(git rev-parse --show-toplevel)
TOOL_DIR="$REPO/Backend/scripts/verification/findings_golden"
IMAGE=${CCURE_TEST_IMAGE:-ccure-audit-pro-backend:latest}
LIVE=${CCURE_LIVE_DB_CONTAINER:-ccure-db}
NET=ccure-findings-golden-net
PG=ccure-findings-golden-pg
REDIS=ccure-findings-golden-redis
STATE=${FINDINGS_GOLDEN_STATE:-$HOME/.cache/ccure-findings-golden}
TEMPLATE=findings_golden_template
INTEL=findings_golden_intel

INTEL_TABLES=(cve cvss epss kev exploits cwe cve_references cpe vulncheck_kev
  csaf_advisory csaf_advisory_cve csaf_affected)

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
  # Imported modules build Redis clients at import; nothing here publishes.
  docker run -d --name "$REDIS" --network "$NET" redis:7-alpine >/dev/null
  wait_ready
  # A query without ORDER BY returns rows in the order the plan produces
  # them. Parallel plans interleave workers, and autovacuum moves tuples and
  # refreshes the statistics plans are chosen from, so either would make two
  # captures of the same code differ. Off, for this throwaway server only.
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
CREATE DATABASE $INTEL OWNER ccure_user;
SQL
  docker exec -i "$PG" pg_restore -U postgres -d "$TEMPLATE" --exit-on-error <"$dump"

  echo "copying the vuln_intel rows the payloads name (read-only)"
  pg -d "$TEMPLATE" -t -A >"$STATE/cves.txt" <<'SQL'
SELECT DISTINCT id FROM (
  SELECT upper(coalesce(f->>'cve_id', f->>'cve', f->>'id')) AS id
  FROM scan_phases p,
       jsonb_array_elements(CASE WHEN jsonb_typeof(p.summary->'_phase_data') = 'array'
                                 THEN p.summary->'_phase_data' ELSE '[]' END) h,
       LATERAL (VALUES (h->'cves'), (h->'vulnerabilities'), (h->'findings')) v(list),
       jsonb_array_elements(CASE WHEN jsonb_typeof(v.list) = 'array' THEN v.list ELSE '[]' END) f
  UNION SELECT upper(vuln_id) FROM asset_vulnerabilities
) ids WHERE id ~ '^CVE-[0-9]{4}-[0-9]+$' ORDER BY 1;
SQL
  local ids
  ids="{$(paste -sd, "$STATE/cves.txt")}"
  # The whole schema, so the tables' trigger functions come with them; rows
  # only for the tables the findings paths read, and only for those CVEs.
  docker exec "$LIVE" pg_dump -U postgres -d vuln_intel --schema-only --no-owner \
    --no-privileges | pg -d "$INTEL" >/dev/null
  for t in "${INTEL_TABLES[@]}"; do
    local where="cve_id = ANY(:'ids'::text[])"
    if [ "$t" = csaf_advisory ]; then
      where="id IN (SELECT advisory_id FROM csaf_advisory_cve WHERE cve_id = ANY(:'ids'::text[]))"
    fi
    docker exec -i -e PGOPTIONS='-c default_transaction_read_only=on' "$LIVE" \
      psql -X -q -v ON_ERROR_STOP=1 -U postgres -d vuln_intel -v ids="$ids" \
      <<<"COPY (SELECT * FROM public.$t WHERE $where) TO STDOUT" |
      pg -d "$INTEL" -c "COPY public.$t FROM STDIN"
  done
  pg -d "$INTEL" -c "GRANT SELECT ON ALL TABLES IN SCHEMA public TO ccure_user" >/dev/null
  echo "intel subset: $(wc -l <"$STATE/cves.txt") CVEs"
  pg -d "$INTEL" -t -A -c "SELECT string_agg(relname || '=' || n_live_tup, ' ' ORDER BY relname) FROM pg_stat_user_tables" || true
  pg -d "$TEMPLATE" -t -A -c "SELECT 'template: ' || count(*) || ' scans' FROM scans"
}

cmd_capture() {
  local commit=$1 out=$2
  docker inspect "$PG" >/dev/null 2>&1 || { echo "run '$0 up <dump>' first" >&2; exit 2; }
  [ ! -e "$out" ] || { echo "$out exists" >&2; exit 2; }
  local app_pw rev work
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

  local -a pids=() modes=(asis on_top from_empty)
  local mode db
  for mode in "${modes[@]}"; do
    db="findings_golden_${mode}_$(random_hex 3)"
    pg -d postgres -c "CREATE DATABASE $db TEMPLATE $TEMPLATE OWNER ccure_user"
    mkdir -p "$out/$mode" && chmod a+rwx "$out/$mode"
    # Passwords go in an env file, never on a command line.
    (
      umask 077
      cat >"$work/$mode.env" <<ENV
SKIP_DOTENV_LOAD=1
PYTHONDONTWRITEBYTECODE=1
PYTHONHASHSEED=0
TZ=UTC
PGSSLMODE=disable
MAC_VENDOR_API_URL=
DATABASE_URL=postgresql://ccure_user:$app_pw@$PG:5432/$db
VULNERABILITY_INTEL_DATABASE_URL=postgresql://ccure_user:$app_pw@$PG:5432/$INTEL
CELERY_BROKER_URL=redis://$REDIS:6379/0
CELERY_RESULT_BACKEND=redis://$REDIS:6379/0
MFA_ENCRYPTION_KEY=$(random_hex 24)
COMPLIANCE_ENCRYPTION_KEY=$(random_hex 24)
ENV
    )
    (
      set +e
      docker run --rm --init --network "$NET" --user 1000:1000 \
        --env-file "$work/$mode.env" \
        -v "$work/repo:/repo:ro" -v "$work/tool:/tool:ro" -v "$out/$mode:/out" \
        -w /repo/Backend --entrypoint python "$IMAGE" \
        /tool/capture.py --mode "$mode" --out /out >"$out/$mode.log" 2>&1
      status=$?
      pg -d postgres -c "DROP DATABASE IF EXISTS $db" >/dev/null
      exit "$status"
    ) &
    pids+=($!)
  done
  local failed=0 i
  for i in "${!pids[@]}"; do
    if ! wait "${pids[$i]}"; then
      echo "mode ${modes[$i]} failed; see $out/${modes[$i]}.log" >&2
      failed=1
    fi
  done
  # The image's user wrote them; hand them back to whoever ran this.
  docker run --rm --network none --user 0 -v "$out:/out" --entrypoint chown "$IMAGE" \
    -R "$(id -u):$(id -g)" /out
  echo "capture of ${rev:0:7} -> $out"
  return "$failed"
}

cmd_compare() {
  python3 "$TOOL_DIR/compare.py" "$1" "$2"
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
