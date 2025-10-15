"""make idProceso not null and update unique constraints

Revision ID: 35d7217f1143
Revises: eef5dd070c55
Create Date: 2025-10-15 16:49:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '35d7217f1143'
down_revision = 'eef5dd070c55'
branch_labels = None
depends_on = None


def upgrade():
    # Eliminar la restricción de unicidad existente 'uq_project_savedprocess'
    op.drop_constraint('uq_project_savedprocess', 'project_cases', type_='unique')
    
    # Hacer idProceso NOT NULL
    op.alter_column('project_cases', 'idProceso', nullable=False)
    
    # Agregar nueva restricción de unicidad para (project_id, idProceso)
    op.create_unique_constraint('uq_project_idProceso', 'project_cases', ['project_id', 'idProceso'])
    
    # Mantener 'uq_project_radicado' (ya existe)


def downgrade():
    # Eliminar la nueva constraint
    op.drop_constraint('uq_project_idProceso', 'project_cases', type_='unique')
    
    # Hacer idProceso nullable de nuevo
    op.alter_column('project_cases', 'idProceso', nullable=True)
    
    # Recrear la constraint original
    op.create_unique_constraint('uq_project_savedprocess', 'project_cases', ['project_id', 'idProceso'])