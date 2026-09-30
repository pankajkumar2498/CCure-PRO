#!/bin/bash
set -e

echo "Initializing database and running migrations..."
python db/migrate_production_schema.py

echo "Starting FastAPI server..."
# --no-proxy-headers: uvicorn must not trust forwarding headers itself. It used
# to run with --forwarded-allow-ips='*', which let ANY caller of :8000 choose
# its own client address and scheme (finding F10-1). The application's
# TrustedProxyHeadersMiddleware (core/trusted_proxy.py) now resolves both, and
# only for a peer named in TRUSTED_PROXIES.
if [ "${RELOAD}" = "true" ]; then
    echo "Running in development reload mode..."
    exec uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000} --reload --no-proxy-headers
else
    echo "Running in production mode..."
    exec uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000} --no-proxy-headers
fi
