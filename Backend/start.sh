#!/bin/bash
set -e

echo "Applying database migrations via Alembic..."
alembic upgrade head

echo "Starting FastAPI server..."
exec uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}
