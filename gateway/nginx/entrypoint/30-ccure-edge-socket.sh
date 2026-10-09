#!/bin/sh
# Remove a stale edge socket before nginx starts (Phase 10.6).
#
# nginx unlinks its unix socket on a clean exit, but a killed container leaves
# the file behind and the next start then fails: "bind() to
# unix:/run/ccure-edge/gateway.sock failed (98: Address in use)" — measured.
# Only one api-gateway container exists (container_name), so a socket present
# at start is never a live listener's.
set -eu
sock=/run/ccure-edge/gateway.sock
dir=$(dirname "$sock")
if [ ! -d "$dir" ] || [ ! -w "$dir" ]; then
    echo "30-ccure-edge-socket: $dir is missing or not writable; host nginx could not reach the gateway" >&2
    exit 1
fi
if [ -S "$sock" ]; then
    rm -f "$sock"
    echo "30-ccure-edge-socket: removed a stale socket"
fi
