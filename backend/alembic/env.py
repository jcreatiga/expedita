from __future__ import with_statement
import os
import sys
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool
from alembic import context

# Ensure project path is importable (so we can import backend.main and Base)
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

# Alembic Config object
config = context.config

# Configure logging from config file
if config.config_file_name:
    fileConfig(config.config_file_name)

# Import target metadata from the application (backend.main -> Base)
try:
    from backend.main import Base  # noqa: E402
    target_metadata = Base.metadata
except Exception as e:
    # If import fails, keep target_metadata = None; autogenerate will be limited
    print("WARNING: Could not import Base from backend.main:", e)
    target_metadata = None

# Support DATABASE_URL environment variable (Railway)
db_url = os.getenv("DATABASE_URL")
if db_url:
    # allow both postgresql:// and postgresql+psycopg:// styles
    config.set_main_option("sqlalchemy.url", db_url)

# Other options
def run_migrations_offline():
    """Run migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    """Run migrations in 'online' mode."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()