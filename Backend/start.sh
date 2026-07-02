#!/bin/bash
set -e

echo "Initializing database and running migrations..."
python db/migrate_production_schema.py

echo "Starting FastAPI server..."
if [ "${RELOAD}" = "true" ]; then
    echo "Running in development reload mode..."
    exec uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000} --reload --proxy-headers --forwarded-allow-ips='*'
else
    echo "Running in production mode..."
    exec uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers --forwarded-allow-ips='*'
fi
