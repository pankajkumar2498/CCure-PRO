#!/bin/bash
# ──────────────────────────────────────────────────────────────────────────────
# Switch host nginx :443 between the direct path and the gateway (Phase 10.5),
# and move the gateway hop onto its unix socket (Phase 10.6).
#
#   direct       443 → host nginx → 127.0.0.1:8000 (api)                pre-10.5
#   gateway-tcp  443 → host nginx → 172.31.254.10:8080 → …              10.5 (superseded)
#   gateway      443 → host nginx → unix:/var/lib/ccure-edge/gateway.sock
#                                   (api-gateway) → gateway-auth → api  10.6
#
#   sudo scripts/linux/gateway_edge_switch.sh status
#   sudo scripts/linux/gateway_edge_switch.sh harden      # gateway-tcp → gateway (10.6, once)
#   sudo scripts/linux/gateway_edge_switch.sh cutover     # direct → gateway
#   sudo scripts/linux/gateway_edge_switch.sh rollback    # gateway(-tcp) → direct
#   sudo scripts/linux/gateway_edge_switch.sh rehearse    # rollback, verify, cutover, verify
#   sudo scripts/linux/gateway_edge_switch.sh logcount    # F10-3: ticket/token counts in host nginx logs
#   sudo scripts/linux/gateway_edge_switch.sh emergency-status   # 10.7: which state each layer is in
#
# Since Phase 10.7 the api publishes no :8000, so `rollback` (to direct) is
# possible only after the emergency override has put :8000 back:
#   docker compose -f docker-compose.yml -f docker-compose.emergency-direct.yml up -d --no-deps api
# `rollback` checks, and says so, rather than installing a file that can only
# fail. docs/architecture/phase10/PHASE10_7_GATEWAY_ONLY.md §6.
#
# What it touches: /etc/nginx/conf.d/ccure.conf, the directory
# /etc/nginx/ccure-rollback/ (a copy of the file it replaced, and a log), an
# nginx reload, and — `harden` only — the socket directory /var/lib/ccure-edge
# and one `docker compose up -d --no-deps api-gateway`. Nothing else: no other
# container, no database, key or certificate.
#
# Safety properties:
#   * Every file is pinned by SHA-256. A repository copy that does not match its
#     pin is never installed, and a live file matching no known pin is never
#     overwritten (someone changed it by hand; a human decides).
#   * `nginx -t` runs before every reload; a failing test restores the previous
#     file and does not reload.
#   * After every reload the path is PROVEN over :443, not assumed. A request
#     with no credential to a bearer route (GET /api/scans) is refused 403 by
#     either path, but only the application stamps X-Request-ID on it; the
#     gateway's own refusals carry none (frozen decision, Phase 10.1). So the
#     header's presence identifies which hop answered.
#   * A switch whose proof fails is rolled back to the direct file at once, so
#     production is never left half switched. The direct path does not depend on
#     the gateway at all, so it is always the safe place to land.
#   * The 10.5 TCP file is recognised, never installed: from 10.6 the gateway
#     no longer believes a TCP peer, so that file would work but collapse every
#     client to one address. Rolling back 10.6 means `rollback` (to direct).
#
# Graceful: `systemctl reload` lets old workers finish their connections, so a
# WebSocket or SSE stream open at the moment of the switch keeps its old path
# until it closes.
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
SRC_DIRECT="$REPO/gateway/edge/host-nginx/ccure.direct.conf"
SRC_GATEWAY="$REPO/gateway/edge/host-nginx/ccure.gateway.conf"
SHA_DIRECT=638fd33f797229b6791a8ba69531d02e2faee2887d8121e8df16c7229019a52a
SHA_GATEWAY=5682c968fcac0d8f6f878dd7262a0727b132724b4823d9a44888ae7ab2d63a2b
SHA_GATEWAY_TCP=79d4513217a4fb42e53a73ef97faafb9c526c1aa0c7beddecd2d4e868e027428  # 10.5, recognised only

LIVE=/etc/nginx/conf.d/ccure.conf
KEEP=/etc/nginx/ccure-rollback          # not under conf.d: nginx never loads it
LOG="$KEEP/switch.log"
EDGE_DIR=/var/lib/ccure-edge            # root:www-data 0770 — the trust boundary
SOCK="$EDGE_DIR/gateway.sock"
EDGE_NAME=ccurepro.cdac.in

say() { printf '%s %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG"; }
die() { say "ERROR: $*"; exit 1; }
sha() { sha256sum "$1" | cut -d' ' -f1; }

state() {
    case "$(sha "$LIVE")" in
        "$SHA_DIRECT")      echo direct ;;
        "$SHA_GATEWAY")     echo gateway ;;
        "$SHA_GATEWAY_TCP") echo gateway-tcp ;;
        *)                  echo unknown ;;
    esac
}

# Which hop answered :443? Prints "gateway", "direct" or "down:<status>".
path_over_443() {
    local head status
    head=$(curl -sk --max-time 10 --resolve "$EDGE_NAME:443:127.0.0.1" \
        -o /dev/null -D - "https://$EDGE_NAME/api/scans?limit=1" | tr -d '\r') || true
    status=$(printf '%s\n' "$head" | awk 'NR==1{print $2}')
    if [ "$status" != 403 ]; then echo "down:${status:-none}"; return; fi
    if printf '%s\n' "$head" | grep -qi '^x-request-id:'; then echo direct; else echo gateway; fi
}

health_over_443() {
    curl -sk --max-time 10 --resolve "$EDGE_NAME:443:127.0.0.1" \
        -o /dev/null -w '%{http_code}' "https://$EDGE_NAME/api/" || true
}

install_conf() {  # <source> <pin>
    [ "$(sha "$1")" = "$2" ] || die "$1 does not match its pinned SHA-256; refusing to install it"
    cp -p "$LIVE" "$KEEP/ccure.conf.before-last-switch"
    install -m 0644 -o root -g root "$1" "$LIVE"
    if ! nginx -t 2>>"$LOG"; then
        install -m 0644 -o root -g root "$KEEP/ccure.conf.before-last-switch" "$LIVE"
        die "nginx -t failed with $(basename "$1"); previous file restored, nginx NOT reloaded"
    fi
    systemctl reload nginx
    sleep 2
}

edge_dir_ok() {
    [ -d "$EDGE_DIR" ] && [ "$(stat -c '%u:%g:%a' "$EDGE_DIR")" = "0:$(getent group www-data | cut -d: -f3):770" ]
}

preflight_gateway() {
    # The gateway on its socket, before anything points at it: its health route
    # (public class, answered by the application through it) and a refusal that
    # needs gateway-auth to have its key set.
    local h r
    edge_dir_ok || die "preflight: $EDGE_DIR is not root:www-data 0770; nothing changed"
    [ -S "$SOCK" ] || die "preflight: no socket at $SOCK (is api-gateway running?); nothing changed"
    h=$(curl -s --max-time 5 --unix-socket "$SOCK" -o /dev/null -w '%{http_code}' "http://gateway/api/") || true
    [ "$h" = 200 ] || die "preflight: the gateway socket answered '${h}' on /api/, not 200; nothing changed"
    r=$(curl -s --max-time 5 --unix-socket "$SOCK" -o /dev/null -D - "http://gateway/api/scans?limit=1" | tr -d '\r') || true
    printf '%s\n' "$r" | head -1 | grep -q ' 403' \
        || die "preflight: gateway refusal was not 403 (gateway-auth not ready?); nothing changed"
    ! printf '%s\n' "$r" | grep -qi '^x-request-id:' \
        || die "preflight: the refusal carried X-Request-ID, so gateway-auth did not answer; nothing changed"
}

direct_available() {
    # The direct file proxies to 127.0.0.1:8000; since 10.7 that listener exists
    # only while the emergency override is applied.
    ss -Hltn 2>/dev/null | awk '{print $4}' | grep -qx '127.0.0.1:8000'
}

EMERGENCY_HINT="127.0.0.1:8000 is not listening (Phase 10.7: the api publishes no port). Restore it first:
    docker compose -f docker-compose.yml -f docker-compose.emergency-direct.yml up -d --no-deps api
then re-run this command. docs/architecture/phase10/PHASE10_7_GATEWAY_ONLY.md §6"

to_gateway() {
    preflight_gateway
    say "installing ccure.gateway.conf"
    install_conf "$SRC_GATEWAY" "$SHA_GATEWAY"
    local p h
    p=$(path_over_443); h=$(health_over_443)
    if [ "$p" != gateway ] || [ "$h" != 200 ]; then
        if direct_available; then
            say "switch proof FAILED (path=$p, health=$h) — rolling back to direct"
            install_conf "$SRC_DIRECT" "$SHA_DIRECT"
        else
            say "switch proof FAILED (path=$p, health=$h) and :8000 is closed — restoring the previous file"
            # install_conf overwrites before-last-switch first, so restore from a copy
            cp -p "$KEEP/ccure.conf.before-last-switch" "$KEEP/ccure.conf.restore"
            install_conf "$KEEP/ccure.conf.restore" "$(sha "$KEEP/ccure.conf.restore")"
        fi
        say "after automatic recovery: path=$(path_over_443) health=$(health_over_443)"
        exit 1
    fi
    say "OK: :443 → gateway over $SOCK (path=$p, health=$h)"
}

to_direct() {
    direct_available || die "$EMERGENCY_HINT"
    say "installing ccure.direct.conf"
    install_conf "$SRC_DIRECT" "$SHA_DIRECT"
    local p h
    p=$(path_over_443); h=$(health_over_443)
    [ "$p" = direct ] && [ "$h" = 200 ] || die "rollback proof FAILED (path=$p, health=$h) — investigate now"
    say "OK: :443 → direct :8000 (path=$p, health=$h)"
}

# 10.6: gateway-tcp → gateway. The gateway is recreated with its socket and the
# socket-only trust; for the few seconds until host nginx is reloaded onto the
# socket, host nginx still dials TCP and the gateway treats those requests as
# coming from 172.31.254.1 (fails safe: never a forged address). Any failure
# after the recreate lands on direct, which does not involve the gateway.
harden() {
    local project gid
    gid=$(getent group www-data | cut -d: -f3)
    [ "$gid" = 33 ] || die "www-data is gid '$gid', not 33 as docker-compose.yml's group_add assumes; nothing changed"
    if [ ! -e "$EDGE_DIR" ]; then
        install -d -m 0770 -o root -g www-data "$EDGE_DIR"
        say "created $EDGE_DIR root:www-data 0770"
    fi
    edge_dir_ok || die "$EDGE_DIR exists but is not root:www-data 0770; a human decides; nothing changed"
    project=$(docker inspect ccure-api-gateway --format '{{index .Config.Labels "com.docker.compose.project"}}') \
        || die "ccure-api-gateway not found; nothing changed"
    say "recreating api-gateway (compose project $project) with the edge socket"
    if ! docker compose --project-directory "$REPO" -p "$project" up -d --no-deps api-gateway >>"$LOG" 2>&1; then
        say "recreate FAILED — landing on direct"; to_direct; exit 1
    fi
    for _ in $(seq 1 30); do [ -S "$SOCK" ] && break; sleep 1; done
    if ! [ -S "$SOCK" ]; then
        say "no socket after 30 s — landing on direct"; to_direct; exit 1
    fi
    if ! (preflight_gateway); then
        say "gateway preflight FAILED after recreate — landing on direct"; to_direct; exit 1
    fi
    to_gateway
}

# F10-3 measurement: counts only, never a line. Read-only.
logcount() {
    local f
    for f in /var/log/nginx/access.log*; do
        [ -e "$f" ] || continue
        printf '%s ticket=%s token=%s ws-ticket=%s\n' "$(basename "$f")" \
            "$(zgrep -c 'ticket=' "$f" || true)" "$(zgrep -c 'token=' "$f" || true)" \
            "$(zgrep -c '/progress?ticket=' "$f" || true)"
    done
}

[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }
mkdir -p "$KEEP"; chmod 0755 "$KEEP"
[ "$(sha "$SRC_DIRECT")" = "$SHA_DIRECT" ]   || die "repository ccure.direct.conf changed; refusing"
[ "$(sha "$SRC_GATEWAY")" = "$SHA_GATEWAY" ] || die "repository ccure.gateway.conf changed; refusing"
# The pre-10.5 file, kept once and never overwritten: the rollback of last resort.
[ -e "$KEEP/ccure.conf.pre-10.5" ] || { [ "$(state)" = direct ] && cp -p "$LIVE" "$KEEP/ccure.conf.pre-10.5"; }

cmd=${1:-status}
say "== $cmd (live=$(state), sha=$(sha "$LIVE" | cut -c1-16))"
case "$cmd" in
    status)
        say "path over :443 = $(path_over_443), health = $(health_over_443)" ;;
    harden)
        case "$(state)" in
            gateway)     say "already on the gateway socket; path=$(path_over_443)" ;;
            gateway-tcp) harden ;;
            *)           die "harden starts from the 10.5 gateway (gateway-tcp) state" ;;
        esac ;;
    cutover)
        case "$(state)" in
            gateway)     say "already on the gateway; path=$(path_over_443)" ;;
            direct)      to_gateway ;;
            gateway-tcp) die "on the 10.5 TCP gateway; use 'harden'" ;;
            *)           die "live ccure.conf matches no pinned file; not touching it" ;;
        esac ;;
    rollback)
        case "$(state)" in
            direct)              say "already direct; path=$(path_over_443)" ;;
            gateway|gateway-tcp) to_direct ;;
            *)                   die "live ccure.conf matches no pinned file; not touching it" ;;
        esac ;;
    rehearse)
        [ "$(state)" = gateway ] || die "rehearse starts from the gateway state"
        to_direct
        to_gateway
        say "rehearsal complete: rollback and re-cut-over both proven" ;;
    logcount)
        logcount ;;
    emergency-status)
        if direct_available; then d="LISTENING (emergency override applied, or pre-10.7)"; else d="closed (normal since 10.7)"; fi
        say "host nginx file: $(state); path over :443 = $(path_over_443), health = $(health_over_443)"
        say "127.0.0.1:8000: $d"
        say "edge socket: $( [ -S "$SOCK" ] && echo present || echo MISSING )" ;;
    *)
        echo "usage: $0 {status|harden|cutover|rollback|rehearse|logcount|emergency-status}" >&2; exit 2 ;;
esac
