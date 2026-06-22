#!/bin/sh
# AbuseCVE container entrypoint.
#
# Runs Alembic migrations before uvicorn so schema changes land before
# any request hits the app. Workers and the beat scheduler use a
# different command (set in docker-compose.yml) so they skip this hook
# — only the API container needs to migrate.

set -e

echo "[entrypoint] alembic upgrade head"
alembic upgrade head

echo "[entrypoint] starting uvicorn"
exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 2
