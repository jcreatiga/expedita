"""create projects and project_cases

Revision ID: 0001_create_projects_and_project_cases
Revises: 
Create Date: 2025-10-02 17:48:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0001_create_projects_and_project_cases'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # Create projects table
    op.create_table(
        'projects',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('color_hex', sa.String(length=7), nullable=False, server_default=sa.text("'#2563EB'")),
        sa.Column('total_cases', sa.Integer(), nullable=False, server_default=sa.text('0')),
        sa.Column('updated_at', sa.DateTime(), nullable=True, server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.UniqueConstraint('user_id', 'name', name='uq_user_project_name'),
    )
    # Index on user_id for faster lookup by user
    op.create_index('ix_projects_user_id', 'projects', ['user_id'])

    # Create procesos table (formerly saved_processes)
    op.create_table(
        'procesos', # Renamed from 'saved_processes'
        sa.Column('idProceso', sa.Integer(), primary_key=True), # Renamed from 'id'
        sa.Column('idUsuario', sa.Integer(), index=True), # Renamed from 'user_id'
        sa.Column('radicado', sa.String(length=23), nullable=False),
        sa.Column('id_expediente', sa.String(length=50)), # Renamed from 'id_proceso'
        sa.Column('demandante', sa.String(length=255)),
        sa.Column('demandado', sa.String(length=255)),
        sa.Column('juzgado', sa.String(length=255)),
        sa.Column('clase', sa.String(length=255)),
        sa.Column('subclase', sa.String(length=255)),
        sa.Column('ubicacion', sa.String(length=255)),
        sa.Column('fecha_ultima_actuacion', sa.Date()),
        sa.Column('snapshot_consulta', sa.Text()),
        sa.Column('snapshot_detalle', sa.Text()),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('updated_at', sa.DateTime(), nullable=True, server_default=sa.text('CURRENT_TIMESTAMP'), onupdate=sa.text('CURRENT_TIMESTAMP')),
    )
    op.create_index('ix_procesos_idUsuario', 'procesos', ['idUsuario'])
    op.create_index('ix_procesos_radicado', 'procesos', ['radicado'], unique=True)


    # Create project_cases table
    op.create_table(
        'project_cases',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('project_id', sa.Integer(), sa.ForeignKey('projects.id', ondelete='CASCADE'), nullable=False),
        sa.Column('idProceso', sa.Integer(), sa.ForeignKey('procesos.idProceso', ondelete='SET NULL'), nullable=True), # Updated FK
        sa.Column('radicado', sa.String(length=23), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.Column('updated_at', sa.DateTime(), nullable=True, server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.UniqueConstraint('project_id', 'idProceso', name='uq_project_savedprocess'), # Updated constraint name
        sa.UniqueConstraint('project_id', 'radicado', name='uq_project_radicado'),
    )
    # Index for project lookup
    op.create_index('ix_project_cases_project_id', 'project_cases', ['project_id'])


def downgrade():
    # Drop in reverse order
    op.drop_index('ix_project_cases_project_id', table_name='project_cases')
    op.drop_table('project_cases')

    op.drop_index('ix_procesos_radicado', table_name='procesos')
    op.drop_index('ix_procesos_idUsuario', table_name='procesos')
    op.drop_table('procesos')

    op.drop_index('ix_projects_user_id', table_name='projects')
    op.drop_table('projects')