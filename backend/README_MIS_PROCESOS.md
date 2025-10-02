# MIS PROCESOS — Alembic migrations & Railway Cron

This document explains how the Alembic scaffold and migration added to this repository work, and the exact commands to run migrations locally and on Railway.

Files added by the migration task
- [`alembic.ini:1`](alembic.ini:1)
- [`backend/alembic/__init__.py:1`](backend/alembic/__init__.py:1)
- [`backend/alembic/env.py:1`](backend/alembic/env.py:1)
- [`backend/alembic/versions/0001_create_projects_and_project_cases.py:1`](backend/alembic/versions/0001_create_projects_and_project_cases.py:1)

Purpose
- Add database schema for "Mis Procesos" (projects) and "project_cases" to let users group saved expedientes.
- Provide a reproducible Alembic workflow so you can create further migrations in the future.
- Ensure migrations run on Railway during deploy (example Procfile/start scripts included below).

Prerequisites
- Python environment with required packages installed:
  - alembic
  - sqlalchemy
  - psycopg2-binary (or psycopg)
- DATABASE_URL environment variable pointing to your Postgres instance.
- Run commands from the repository root (where `alembic.ini` is located).

Quick local commands

1) Export DATABASE_URL (bash / macOS / Linux)
export DATABASE_URL="postgresql+psycopg://user:pass@host:port/db"

2) Run migrations (apply all)
alembic upgrade head

Windows (cmd.exe)
set DATABASE_URL=postgresql+psycopg://user:pass@host:port/db
alembic upgrade head

Create a new migration after model changes
alembic revision --autogenerate -m "describe change"
alembic upgrade head

Important: run these from the repository root (same directory as `alembic.ini`).

How env.py is configured
- `backend/alembic/env.py` imports `Base` from [`backend/main.py:1`](backend/main.py:1) and sets `target_metadata = Base.metadata`. This ensures autogenerate sees your SQLAlchemy models.
- `env.py` reads `DATABASE_URL` from the environment and sets it as `sqlalchemy.url` for Alembic.
- `compare_type=True` is enabled to detect column type changes during autogenerate.

Migration included (summary)
File: [`backend/alembic/versions/0001_create_projects_and_project_cases.py:1`](backend/alembic/versions/0001_create_projects_and_project_cases.py:1)

It creates:

projects
- id SERIAL PRIMARY KEY
- user_id INTEGER NOT NULL
- name VARCHAR(255) NOT NULL
- color_hex VARCHAR(7) NOT NULL DEFAULT '#2563EB'
- total_cases INTEGER NOT NULL DEFAULT 0
- created_at TIMESTAMP DEFAULT now()
- updated_at TIMESTAMP DEFAULT now()
- UNIQUE(user_id, name)
- INDEX on user_id

project_cases
- id SERIAL PRIMARY KEY
- project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE
- saved_process_id INTEGER REFERENCES saved_processes(id) ON DELETE SET NULL
- radicado VARCHAR(23) NULL (fallback when not linked)
- created_at TIMESTAMP DEFAULT now()
- updated_at TIMESTAMP DEFAULT now()
- UNIQUE(project_id, saved_process_id)
- UNIQUE(project_id, radicado)
- INDEX on project_id

Downgrade drops `project_cases` then `projects`.

Notes about types and constraints
- `user_id` is an INTEGER in the migration (matching current user table id in `backend/main.py:1`). If your auth uses string IDs, change it to `sa.String(length=64)` before applying.
- `saved_processes` table already exists in the code; the migration references it for FK with `ON DELETE SET NULL`. If your DB differs, review and adapt.

Railway / Deploy-time migration
Recommended: run `alembic upgrade head` as part of the start command so migrations are applied automatically during deployment.

Example Procfile entry:
web: sh -c "alembic upgrade head && uvicorn backend.main:app --host 0.0.0.0 --port 8000"

Or adjust start.sh (example):
#!/bin/sh
alembic upgrade head
exec uvicorn backend.main:app --host 0.0.0.0 --port ${PORT:-8000}

Make sure Railway project has the environment variable DATABASE_URL set (Railway normally provides this) and that the container can run alembic (alembic package installed).

Verifications after running migrations
1) Run: alembic upgrade head
2) Connect to DB (psql or admin UI) and confirm tables exist:
   - projects
   - project_cases
3) Check indexes and constraints (UNIQUEs and FK behavior).
4) Start app:
   uvicorn backend.main:app --host 0.0.0.0 --port 8000
5) Test endpoints that depend on the new tables:
   - GET /api/projects (requires auth)
   - POST /api/projects (create project)
   - POST /api/projects/:id/cases (add case)

Troubleshooting
- If Alembic autogenerate does not detect models, ensure `backend/main.py` exposes `Base` and model classes at import time. `env.py` imports `backend.main` directly.
- If you change model import locations, update `env.py` to import the module that defines `Base`.
- If DATABASE_URL uses `postgresql://` without `+psycopg`, Alembic/SQLAlchemy still accepts it, but the recommended driver string is `postgresql+psycopg://`.

Security note for CRON
- The cron endpoint `/api/cron/refresh-all-projects` is protected by the `CRON_TOKEN` environment variable.
- When configuring Railway Scheduled job, set header `Authorization: Bearer ${CRON_TOKEN}`.

Railway Scheduled Job example
- URL: https://<your-app>.railway.app/api/cron/refresh-all-projects
- Method: POST
- Headers:
  - Authorization: Bearer ${CRON_TOKEN}
  - Content-Type: application/json
- Body: {}
- Schedule: Daily at 06:00 (adjust to your timezone)
- Timeout: choose a timeout (e.g. 10 min). If you expect very large datasets, consider splitting by ranges.

If you want, I can:
- run `alembic revision --autogenerate` locally to create an autogenerated migration (but I can't execute commands here — I prepared the hand-written migration already),
- or modify the migration to change `user_id` -> string if you prefer non-integer user IDs.

Acceptance checklist (what I added)
- Alembic scaffold under `backend/alembic/` with `env.py` that imports `Base`.
- Migration `0001_create_projects_and_project_cases.py` under `backend/alembic/versions/` that creates the `projects` and `project_cases` tables.
- `alembic.ini` in repo root with `script_location = backend/alembic`.
- README updated with exact commands and examples.

Next steps I can take (pick one):
- Update the migration if your auth uses non-integer user IDs (change `user_id` column type).
- Add a small test script to run after migrations to verify schema exists.
- Wire the "Guardar" flow in `backend/static/index.html` to optionally choose a project when saving a process.
