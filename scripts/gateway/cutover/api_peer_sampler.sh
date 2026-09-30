#!/bin/bash
# Phase 10.7 V-N1 — read-only sampler of who talks to the api after :8000 closed.
# Reads /proc only; writes only to its own output file. Every INTERVAL seconds:
#   C  <ts> <remote>           sockets inside ccure-api's netns on local :8000,
#                              with the peer (expected: 172.31.254.10, the
#                              gateway; 172.31.254.1 = a host process on the
#                              bridge — the documented 10.8 residual)
#   H  <ts> <dest> <uid>       host sockets dialling the api's container
#                              addresses (172.31.254.20 or 172.18.0.x) on :8000,
#                              with the owning uid — who that host process is
#   T  <ts>                    a sample was taken
#
#   scripts/gateway/cutover/api_peer_sampler.sh <out.log> [interval=10] [seconds=86400]
OUT=${1:?output file}
INTERVAL=${2:-10}
END=$(( $(date +%s) + ${3:-86400} ))
while [ "$(date +%s)" -lt "$END" ]; do
  ts=$(date +%s)
  # host namespace, ESTABLISHED (01), remote port 8000 (1F40) on a 172.x address
  awk -v ts="$ts" 'NR>1 && $4=="01" && $3 ~ /:1F40$/ && $3 !~ /^0100007F/ {print "H", ts, $3, $8}' /proc/net/tcp
  pid=$(docker inspect ccure-api --format '{{.State.Pid}}' 2>/dev/null)
  if [ -n "$pid" ] && [ "$pid" != 0 ]; then
    awk -v ts="$ts" 'NR>1 && $2 ~ /:1F40$/ && $4=="01" {print "C", ts, $3}' /proc/$pid/net/tcp
  fi
  echo "T $ts"
  sleep "$INTERVAL"
done >> "$OUT"
