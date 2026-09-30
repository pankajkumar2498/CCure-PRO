#!/bin/bash
# Phase 10.5 — read-only fingerprint of the live deployment, taken before and
# after the cut-over and diffed. Reads files, `docker inspect`, `ss`, the api's
# environment (named variables only) and one SELECT; writes only to stdout.
#
#   scripts/gateway/cutover/fingerprint.sh > before.txt
#
# The token keyset is fingerprinted by its public keyset.json and a listing of
# the directory (names, sizes, mtimes, owners) — the private key file is not
# readable by this account and is never opened.
set -uo pipefail
cd "$(dirname "$0")/../../.."

echo "## host nginx"
sha256sum /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf 2>&1
ls /etc/nginx/sites-enabled/ 2>&1 | sed 's/^/sites-enabled: /'

echo "## listeners (address:port)"
ss -Hltn | awk '{print $4}' | grep -Ev ':(3[0-9]{4}|4[0-9]{4})$' | sort -u | tr '\n' ' '; echo

echo "## containers (name image started compose-hash)"
docker ps -a --format '{{.Names}}' | sort | while read -r c; do
    docker inspect "$c" --format '{{.Name}} {{.Image}} {{.State.Status}} {{.State.StartedAt}} {{index .Config.Labels "com.docker.compose.config-hash"}}' \
        | awk '{printf "%s %s %s %s %s\n", $1, substr($2,8,12), $3, $4, substr($5,1,12)}'
done

echo "## published ports"
docker ps --format '{{.Names}} {{.Ports}}' | sort

echo "## networks"
for n in $(docker network ls --format '{{.Name}}' | sort); do
    docker network inspect "$n" --format '{{.Name}} internal={{.Internal}} {{range .IPAM.Config}}{{.Subnet}} gw={{.Gateway}}{{end}} :{{range .Containers}} {{.Name}}={{.IPv4Address}}{{end}}'
done

echo "## token keyset and settings (no secret values)"
sha256sum /home/cdac/ccure-keys/keyset.json 2>&1
ls -ln --time-style=full-iso /home/cdac/ccure-keys/ | awk 'NR>1{print $1,$3,$4,$5,$6,$7,$9}'
docker exec ccure-api printenv CCURE_TOKEN_SIGNING_ALG CCURE_ACCEPT_LEGACY_HS256 CCURE_TOKEN_KEYS_DIR 2>&1 | tr '\n' ' '; echo
echo "jwks sha256: $(curl -s --max-time 5 http://127.0.0.1:8000/auth/jwks.json | sha256sum | cut -c1-64)"

echo "## trust settings seen by the api process"
docker exec ccure-api printenv TRUSTED_PROXIES 2>/dev/null || echo "TRUSTED_PROXIES unset (config.py default)"
docker exec ccure-api sh -c 'tr "\0" " " < /proc/1/cmdline; echo; for p in /proc/[0-9]*; do c=$(tr "\0" " " < $p/cmdline 2>/dev/null); case "$c" in *uvicorn*) echo "$c";; esac; done' 2>&1 | grep -av "^sh -c tr" | sort -u

echo "## database"
docker exec ccure-db psql -U postgres -d ccure_db -Atc "select 'alembic_version=' || version_num from alembic_version"
docker exec ccure-db psql -U postgres -d ccure_db -Atc "select 'tables=' || count(*) from information_schema.tables where table_schema='public'"
docker exec ccure-db psql -U postgres -d ccure_db -Atc "select 'schema_digest=' || md5(string_agg(table_name||'.'||column_name||':'||data_type||':'||is_nullable, ',' order by table_name, column_name)) from information_schema.columns where table_schema='public'"
docker exec ccure-db psql -U postgres -d ccure_db -Atc "select 'constraint_digest=' || md5(string_agg(conname||':'||pg_get_constraintdef(oid), ',' order by conname)) from pg_constraint where connamespace='public'::regnamespace"

echo "## repository"
git rev-parse HEAD
