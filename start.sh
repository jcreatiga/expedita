#!/bin/sh
set -e
pip install -r requirements.txt
alembic upgrade head || true
exec uvicorn backend.main:app --host 0.0.0.0 --port 8000