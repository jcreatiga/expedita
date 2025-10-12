#!/bin/sh
set -e
pip install -r requirements.txt
alembic upgrade head || true
# fail fast if backend has Python syntax errors
python -m py_compile backend/main.py || {
  echo "❌ Python syntax error in backend/main.py. Aborting start."
  exit 1
}
exec uvicorn backend.main:app --host 0.0.0.0 --port 8000