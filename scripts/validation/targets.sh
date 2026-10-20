#!/usr/bin/env bash
# The disposable, isolated scan targets for live validation.
#
#   scripts/validation/targets.sh up       # create the network and start the targets
#   scripts/validation/targets.sh status   # show them and probe each from inside the network
#   scripts/validation/targets.sh down     # remove the targets and the network
#
# Everything is defined in targets.env beside this script. The network is
# --internal: no route off the host and no published port, so nothing outside
# this machine can reach a target and no target can reach anything else. The
# targets hold no real data and no real secret. Docker gives the host an address
# on the bridge (VALIDATION_HOST_ADDRESS); that address is the VM itself, and
# live_scan.sh excludes it from every scan.
#
# `up` is idempotent: running targets are left alone and missing ones started.
# The SSH target's image is built once from the pinned base and kept, so a
# later `up` serves the same OpenSSH build; `down --images` removes it too.
# docs/ci/LIVE_SCAN_VALIDATION.md has the whole procedure.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=targets.env
. "$HERE/targets.env"

exists() { docker container inspect "$1" >/dev/null 2>&1; }
running() { [ "$(docker container inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" = "true" ]; }

network_up() {
  if ! docker network inspect "$VALIDATION_NETWORK" >/dev/null 2>&1; then
    docker network create --internal --subnet "$VALIDATION_SUBNET" "$VALIDATION_NETWORK" >/dev/null
    echo "network $VALIDATION_NETWORK ($VALIDATION_SUBNET, internal) created"
  fi
  if [ "$(docker network inspect -f '{{.Internal}}' "$VALIDATION_NETWORK")" != "true" ]; then
    echo "refusing: $VALIDATION_NETWORK exists and is not internal" >&2
    exit 1
  fi
}

start() { # name ip image [docker run args...] -- [command...]
  local name=$1 ip=$2 image=$3
  shift 3
  if running "$name"; then return 0; fi
  if exists "$name"; then docker rm -f "$name" >/dev/null; fi
  docker run -d --name "$name" --network "$VALIDATION_NETWORK" --ip "$ip" \
    --label ccure.validation=target "$@" "$image" >/dev/null
  echo "started $name at $ip"
}

up() {
  network_up
  if ! docker image inspect "$SSH_IMAGE_TAG" >/dev/null 2>&1; then
    echo "building $SSH_IMAGE_TAG from $SSH_BASE_IMAGE"
    docker build -q --build-arg BASE="$SSH_BASE_IMAGE" -t "$SSH_IMAGE_TAG" "$HERE/ssh-target" >/dev/null
  fi
  start "$SSH_CONTAINER" "$SSH_TARGET" "$SSH_IMAGE_TAG"
  start "$WEB_CONTAINER" "$WEB_TARGET" "$WEB_IMAGE"
  # The exposure the web checks and Nuclei must find: a dotenv file and a git
  # config in the document root. Dummy values, written into the container so
  # nothing named .env or .git is ever committed.
  docker exec "$WEB_CONTAINER" sh -c '
    d=/usr/share/nginx/html
    printf "APP_ENV=validation\nAPP_KEY=base64:dmFsaWRhdGlvbi1vbmx5LW5vdC1hLWtleQ==\nDB_HOST=127.0.0.1\nDB_PASSWORD=validation-only-not-a-secret\n" > $d/.env
    mkdir -p $d/.git
    printf "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n[remote \"origin\"]\n\turl = https://example.invalid/validation/target.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n" > $d/.git/config
    printf "<html><body>ccure validation target</body></html>\n" > $d/index.html'
  start "$REDIS_CONTAINER" "$REDIS_TARGET" "$REDIS_IMAGE"
  # Random per start; nothing logs in with it, it only lets the server run.
  start "$PG_CONTAINER" "$PG_TARGET" "$PG_IMAGE" \
    -e POSTGRES_PASSWORD="$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  sleep 3
  status
}

status() {
  if ! docker network inspect "$VALIDATION_NETWORK" >/dev/null 2>&1; then
    echo "no validation network; run: $0 up"
    return 1
  fi
  for name in "$SSH_CONTAINER" "$WEB_CONTAINER" "$REDIS_CONTAINER" "$PG_CONTAINER"; do
    printf '%-24s %s\n' "$name" "$(docker container inspect -f '{{.State.Status}}' "$name" 2>/dev/null || echo missing)"
  done
  docker run --rm --network "$VALIDATION_NETWORK" --ip "$VALIDATION_PROBE_ADDRESS" "$PROBE_IMAGE" sh -c "
    printf 'ssh   %s ' $SSH_TARGET; nc -w 2 $SSH_TARGET 22 </dev/null | head -1 || echo unreachable
    printf 'web   %s .env: ' $WEB_TARGET; wget -q -O- http://$WEB_TARGET/.env | head -1 || echo unreachable
    printf 'redis %s ' $REDIS_TARGET; (printf 'PING\r\n'; sleep 1) | nc -w 2 $REDIS_TARGET 6379 | head -1 || echo unreachable
    printf 'pg    %s port 5432: ' $PG_TARGET; nc -z -w 2 $PG_TARGET 5432 && echo open || echo closed"
}

down() {
  for name in "$SSH_CONTAINER" "$WEB_CONTAINER" "$REDIS_CONTAINER" "$PG_CONTAINER"; do
    if exists "$name"; then docker rm -f "$name" >/dev/null && echo "removed $name"; fi
  done
  if docker network inspect "$VALIDATION_NETWORK" >/dev/null 2>&1; then
    docker network rm "$VALIDATION_NETWORK" >/dev/null && echo "removed network $VALIDATION_NETWORK"
  fi
  if [ "${1:-}" = "--images" ] && docker image inspect "$SSH_IMAGE_TAG" >/dev/null 2>&1; then
    docker rmi "$SSH_IMAGE_TAG" >/dev/null && echo "removed image $SSH_IMAGE_TAG"
  fi
}

case "${1:-}" in
  up) up ;;
  status) status ;;
  down) shift; down "${1:-}" ;;
  *) echo "usage: $0 up|status|down [--images]" >&2; exit 2 ;;
esac
