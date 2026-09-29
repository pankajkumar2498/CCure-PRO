#!/bin/sh
# Render /run/ccure/cors_origins.map from CCURE_CORS_ALLOW_ORIGINS before nginx
# starts (run by the nginx image's /docker-entrypoint.sh).
#
# The value is the core's CORS_ALLOW_ORIGINS, passed through unchanged, so the
# gateway's refusals carry Access-Control-Allow-Origin for exactly the origins
# the application's own refusals do (Phase 10.1: an allowed-origin 403 carries
# it). One source, rendered — never a second list maintained by hand.
#
# An origin that is not scheme://host[:port] stops the container: a malformed
# entry must be a start-up failure, not a silently narrower CORS policy.
set -eu

out_dir=/run/ccure
out="$out_dir/cors_origins.map"
mkdir -p "$out_dir"
tmp="$out.tmp"

{
    echo "# RENDERED at start from CCURE_CORS_ALLOW_ORIGINS - do not edit."
    echo 'map $http_origin $ccure_cors_allow_origin {'
    echo '    default "";'
    old_ifs=$IFS
    IFS=,
    for origin in ${CCURE_CORS_ALLOW_ORIGINS:-}; do
        origin=$(printf '%s' "$origin" | tr -d ' \t')
        [ -n "$origin" ] || continue
        if ! printf '%s' "$origin" | grep -Eq '^https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?$'; then
            echo "40-ccure-cors-origins: refusing malformed origin: $origin" >&2
            exit 1
        fi
        printf '    "%s" "%s";\n' "$origin" "$origin"
    done
    IFS=$old_ifs
    echo '}'
} > "$tmp"
mv "$tmp" "$out"
echo "40-ccure-cors-origins: $(grep -c '^    "' "$out") origin(s) allowed"
