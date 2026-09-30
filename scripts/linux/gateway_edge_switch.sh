#!/bin/bash
# ──────────────────────────────────────────────────────────────────────────────
# Phase 10.5 — switch host nginx :443 between the direct path and the gateway.
#
#   direct   443 → host nginx → 127.0.0.1:8000 (api)                  pre-10.5
#   gateway  443 → host nginx → 172.31.254.10:8080 (api-gateway)
#                                   → gateway-auth → api              10.5
#
#   sudo scripts/linux/gateway_edge_switch.sh status
#   sudo scripts/linux/gateway_edge_switch.sh cutover     # direct  → gateway
#   sudo scripts/linux/gateway_edge_switch.sh rollback    # gateway → direct
#   sudo scripts/linux/gateway_edge_switch.sh rehearse    # rollback, verify, cutover, verify
#
# What it touches: /etc/nginx/conf.d/ccure.conf, the directory
# /etc/nginx/ccure-rollback/ (a copy of the file it replaced, and a log), and an
# nginx reload. Nothing else — no container, database, key or certificate.
#
# Safety properties:
#   * Both files are pinned by SHA-256. A repository copy that does not match
#     its pin is never installed, and a live file matching neither pin is never
#     overwritten (someone changed it by hand; a human decides).
#   * `nginx -t` runs before every reload; a failing test restores the previous
#     file and does not reload.
#   * After every reload the path is PROVEN over :443, not assumed. A request
#     with no credential to a bearer route (GET /api/scans) is refused 403 by
#     either path, but only the application stamps X-Request-ID on it; the
#     gateway's own refusals carry none (frozen decision, Phase 10.1). So the
#     header's presence identifies which hop answered.
#   * A cut-over whose proof fails is rolled back to the direct file at once, so
#     production is never left half switched.
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
SHA_GATEWAY=79d4513217a4fb42e53a73ef97faafb9c526c1aa0c7beddecd2d4e868e027428

LIVE=/etc/nginx/conf.d/ccure.conf
KEEP=/etc/nginx/ccure-rollback          # not under conf.d: nginx never loads it
LOG="$KEEP/switch.log"
GATEWAY_ADDR=172.31.254.10:8080
EDGE_NAME=ccurepro.cdac.in

say() { printf '%s %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG"; }
die() { say "ERROR: $*"; exit 1; }
sha() { sha256sum "$1" | cut -d' ' -f1; }

state() {
    case "$(sha "$LIVE")" in
        "$SHA_DIRECT")  echo direct ;;
        "$SHA_GATEWAY") echo gateway ;;
        *)              echo unknown ;;
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

preflight_gateway() {
    # The gateway itself, before anything points at it: its health route
    # (public class, answered by the application through it) and a refusal
    # that needs gateway-auth to have its key set.
    local h r
    h=$(curl -s --max-time 5 -o /dev/null -w '%{http_code}' "http://$GATEWAY_ADDR/api/") || true
    [ "$h" = 200 ] || die "preflight: http://$GATEWAY_ADDR/api/ answered '${h}', not 200; nothing changed"
    r=$(curl -s --max-time 5 -o /dev/null -D - "http://$GATEWAY_ADDR/api/scans?limit=1" | tr -d '\r') || true
    printf '%s\n' "$r" | head -1 | grep -q ' 403' \
        || die "preflight: gateway refusal was not 403 (gateway-auth not ready?); nothing changed"
    ! printf '%s\n' "$r" | grep -qi '^x-request-id:' \
        || die "preflight: the refusal carried X-Request-ID, so gateway-auth did not answer; nothing changed"
}

to_gateway() {
    preflight_gateway
    say "installing ccure.gateway.conf"
    install_conf "$SRC_GATEWAY" "$SHA_GATEWAY"
    local p h
    p=$(path_over_443); h=$(health_over_443)
    if [ "$p" != gateway ] || [ "$h" != 200 ]; then
        say "cut-over proof FAILED (path=$p, health=$h) — rolling back to direct"
        install_conf "$SRC_DIRECT" "$SHA_DIRECT"
        say "after automatic rollback: path=$(path_over_443) health=$(health_over_443)"
        exit 1
    fi
    say "OK: :443 → gateway (path=$p, health=$h)"
}

to_direct() {
    say "installing ccure.direct.conf"
    install_conf "$SRC_DIRECT" "$SHA_DIRECT"
    local p h
    p=$(path_over_443); h=$(health_over_443)
    [ "$p" = direct ] && [ "$h" = 200 ] || die "rollback proof FAILED (path=$p, health=$h) — investigate now"
    say "OK: :443 → direct :8000 (path=$p, health=$h)"
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
    cutover)
        case "$(state)" in
            gateway) say "already on the gateway; path=$(path_over_443)" ;;
            direct)  to_gateway ;;
            *)       die "live ccure.conf matches neither pinned file; not touching it" ;;
        esac ;;
    rollback)
        case "$(state)" in
            direct)  say "already direct; path=$(path_over_443)" ;;
            gateway) to_direct ;;
            *)       die "live ccure.conf matches neither pinned file; not touching it" ;;
        esac ;;
    rehearse)
        [ "$(state)" = gateway ] || die "rehearse starts from the gateway state"
        to_direct
        to_gateway
        say "rehearsal complete: rollback and re-cut-over both proven" ;;
    *)
        echo "usage: $0 {status|cutover|rollback|rehearse}" >&2; exit 2 ;;
esac
