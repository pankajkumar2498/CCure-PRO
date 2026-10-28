#!/usr/bin/env bash
# The disposable, isolated scan targets for live validation.
#
#   scripts/validation/targets.sh up       # create the network and start the targets
#   scripts/validation/targets.sh status   # show them and probe each from inside the network
#   scripts/validation/targets.sh state <original|web_clean|ssh_hardened>
#                                          # put the targets in a rescan's state
#   scripts/validation/targets.sh down     # remove the targets and the network
#
# Everything is defined in targets.env beside this script. The network is
# --internal: no route off the host and no published port, so nothing outside
# this machine can reach a target and no target can reach anything else. The
# targets hold no real data and no real secret. Docker gives the host an address
# on the bridge (VALIDATION_HOST_ADDRESS); that address is the VM itself, and
# live_scan.sh excludes it from every scan.
#
# `up` is idempotent: a running target holding its defined address and MAC, and
# running its defined image, is left alone; a missing one is started, and one
# holding anything else (created by hand, before the MACs were fixed, or from an
# older SSH image without the audit account) is replaced.
# The SSH target's image is built once from the pinned base and kept, so a
# later `up` serves the same OpenSSH build; `down --images` removes it too.
#
# The audit accounts (SSH_AUDIT_USER, PG_AUDIT_ROLE) cannot log in outside a
# run: live_scan.sh gives them a throwaway password for one run and revokes it.
# `status` shows their state, never a secret.
#
# `state` is what the harness's rescans ask for, through live_scan.sh, so a
# finding can go away and come back (live_scan_harness.RESCANS):
#   original      the web target serves its .env and .git/config; the SSH
#                 target is as its image built it;
#   web_clean     the web target's .env and .git are removed;
#   ssh_hardened  the SSH target's PASS_MAX_DAYS is 90 and
#                 pam_extrausers_chkpwd loses its SGID bit, so the two
#                 configuration checks that fail on it pass.
# Each state is applied and confirmed inside the target, and the exit status
# is the confirmation. The SSH target keeps a copy of the image's own
# login.defs and SGID mode the first time it is asked, so `original` restores
# exactly them. `up` ends in `original`, and live_scan.sh restores it on exit.
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

# The image a container was created from, as `docker run` was given it.
image_of() { docker container inspect -f '{{.Config.Image}}' "$1" 2>/dev/null || true; }

# "<ip> <mac>" of a container on the validation network, empty if it is not on it.
address_of() {
  docker container inspect -f \
    "{{with index .NetworkSettings.Networks \"$VALIDATION_NETWORK\"}}{{.IPAddress}} {{.MacAddress}}{{end}}" \
    "$1" 2>/dev/null || true
}

start() { # name ip mac image [docker run args...]
  local name=$1 ip=$2 mac=$3 image=$4
  shift 4
  if running "$name"; then
    if [ "$(address_of "$name")" = "$ip $mac" ] && [ "$(image_of "$name")" = "$image" ]; then
      return 0
    fi
    echo "replacing $name: it does not hold $ip $mac on $image"
  fi
  if exists "$name"; then docker rm -f "$name" >/dev/null; fi
  docker run -d --name "$name" --network "$VALIDATION_NETWORK" --ip "$ip" --mac-address "$mac" \
    --label ccure.validation=target "$@" "$image" >/dev/null
  echo "started $name at $ip ($mac)"
}

up() {
  network_up
  if ! docker image inspect "$SSH_IMAGE_TAG" >/dev/null 2>&1; then
    echo "building $SSH_IMAGE_TAG from $SSH_BASE_IMAGE"
    docker build -q --build-arg BASE="$SSH_BASE_IMAGE" --build-arg AUDIT_USER="$SSH_AUDIT_USER" \
      -t "$SSH_IMAGE_TAG" "$HERE/ssh-target" >/dev/null
  fi
  start "$SSH_CONTAINER" "$SSH_TARGET" "$SSH_MAC" "$SSH_IMAGE_TAG"
  start "$WEB_CONTAINER" "$WEB_TARGET" "$WEB_MAC" "$WEB_IMAGE"
  start "$REDIS_CONTAINER" "$REDIS_TARGET" "$REDIS_MAC" "$REDIS_IMAGE"
  # Random per start; nothing logs in with it, it only lets the server run.
  start "$PG_CONTAINER" "$PG_TARGET" "$PG_MAC" "$PG_IMAGE" \
    -e POSTGRES_PASSWORD="$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  sleep 3
  set_state original
  status
}

# The exposure the web checks and Nuclei must find: a dotenv file and a git
# config in the document root. Dummy values, written into the container so
# nothing named .env or .git is ever committed.
web_exposed() {
  docker exec "$WEB_CONTAINER" sh -c '
    d=/usr/share/nginx/html
    printf "APP_ENV=validation\nAPP_KEY=base64:dmFsaWRhdGlvbi1vbmx5LW5vdC1hLWtleQ==\nDB_HOST=127.0.0.1\nDB_PASSWORD=validation-only-not-a-secret\n" > $d/.env
    mkdir -p $d/.git
    printf "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n[remote \"origin\"]\n\turl = https://example.invalid/validation/target.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n" > $d/.git/config
    printf "<html><body>ccure validation target</body></html>\n" > $d/index.html
    test -s $d/.env && test -s $d/.git/config'
}

web_clean() {
  docker exec "$WEB_CONTAINER" sh -c '
    d=/usr/share/nginx/html
    rm -rf $d/.env $d/.git
    test ! -e $d/.env && test ! -e $d/.git'
}

# original | hardened. The image's own login.defs and SGID mode are kept the
# first time, whatever is asked, so `original` restores exactly them.
ssh_config() {
  docker exec -i "$SSH_CONTAINER" sh -s "$1" <<'SH'
set -e
keep=/var/lib/ccure-validation
chkpwd=/usr/sbin/pam_extrausers_chkpwd
mkdir -p "$keep"
[ -f "$keep/login.defs" ] || cp -p /etc/login.defs "$keep/login.defs"
[ -f "$keep/chkpwd.mode" ] || stat -c %a "$chkpwd" >"$keep/chkpwd.mode"
case "$1" in
  original)
    cp -p "$keep/login.defs" /etc/login.defs
    chmod "$(cat "$keep/chkpwd.mode")" "$chkpwd"
    cmp -s "$keep/login.defs" /etc/login.defs
    [ "$(stat -c %a "$chkpwd")" = "$(cat "$keep/chkpwd.mode")" ]
    ;;
  hardened)
    sed -i 's/^PASS_MAX_DAYS[[:space:]].*/PASS_MAX_DAYS\t90/' /etc/login.defs
    chmod g-s "$chkpwd"
    grep -q '^PASS_MAX_DAYS[[:space:]]*90$' /etc/login.defs
    [ ! -g "$chkpwd" ]
    ;;
  *) exit 2 ;;
esac
SH
}

set_state() {
  local web ssh
  case "${1:-}" in
    original) web=web_exposed ssh=original ;;
    web_clean) web=web_clean ssh=original ;;
    ssh_hardened) web=web_exposed ssh=hardened ;;
    *) echo "unknown state: ${1:-}" >&2; return 2 ;;
  esac
  if ! "$web" || ! ssh_config "$ssh"; then
    echo "could not put the targets in state $1" >&2
    return 1
  fi
  echo "targets in state $1"
}

status() {
  if ! docker network inspect "$VALIDATION_NETWORK" >/dev/null 2>&1; then
    echo "no validation network; run: $0 up"
    return 1
  fi
  for name in "$SSH_CONTAINER" "$WEB_CONTAINER" "$REDIS_CONTAINER" "$PG_CONTAINER"; do
    printf '%-24s %-8s %s\n' "$name" \
      "$(docker container inspect -f '{{.State.Status}}' "$name" 2>/dev/null || echo missing)" \
      "$(address_of "$name")"
  done
  docker run --rm --network "$VALIDATION_NETWORK" --ip "$VALIDATION_PROBE_ADDRESS" "$PROBE_IMAGE" sh -c "
    printf 'ssh   %s ' $SSH_TARGET; nc -w 2 $SSH_TARGET 22 </dev/null | head -1 || echo unreachable
    printf 'web   %s .env: ' $WEB_TARGET; wget -q -O- http://$WEB_TARGET/.env | head -1 || echo unreachable
    printf 'redis %s ' $REDIS_TARGET; (printf 'PING\r\n'; sleep 1) | nc -w 2 $REDIS_TARGET 6379 | head -1 || echo unreachable
    printf 'pg    %s port 5432: ' $PG_TARGET; nc -z -w 2 $PG_TARGET 5432 && echo open || echo closed"
  audit_accounts
}

# Whether the audit accounts can log in. Outside a run both must say they
# cannot: "L" (locked) for the SSH account, "absent" or "nologin" for the role.
audit_accounts() {
  local ssh_state role_state
  ssh_state=$(docker exec "$SSH_CONTAINER" passwd -S "$SSH_AUDIT_USER" 2>/dev/null) \
    && ssh_state=$(echo "$ssh_state" | awk '{print $2}') || ssh_state="unknown (not answering)"
  role_state=$(docker exec "$PG_CONTAINER" psql -U postgres -tAc \
    "SELECT CASE WHEN rolcanlogin THEN 'login' ELSE 'nologin' END FROM pg_roles WHERE rolname = '$PG_AUDIT_ROLE'" \
    2>/dev/null) || role_state="unknown (not answering)"
  printf 'audit %s on ssh: %s\n' "$SSH_AUDIT_USER" "$ssh_state"
  printf 'audit %s on pg: %s\n' "$PG_AUDIT_ROLE" "${role_state:-absent}"
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
  state) shift; set_state "${1:-}" ;;
  down) shift; down "${1:-}" ;;
  *) echo "usage: $0 up|status|state <name>|down [--images]" >&2; exit 2 ;;
esac
