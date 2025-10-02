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
        sa.Column('updated_at', sa.DateTime(), nullable=True, server_default=sa.text('now()')),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        sa.UniqueConstraint('user_id', 'name', name='uq_user_project_name'),
    )
    # Index on user_id for faster lookup by user
    op.create_index('ix_projects_user_id', 'projects', ['user_id'])

    # Create project_cases table
    op.create_table(
        'project_cases',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('project_id', sa.Integer(), sa.ForeignKey('projects.id', ondelete='CASCADE'), nullable=False),
        sa.Column('saved_process_id', sa.Integer(), sa.ForeignKey('saved_processes.id', ondelete='SET NULL'), nullable=True),
        sa.Column('radicado', sa.String(length=23), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        sa.Column('updated_at', sa.DateTime(), nullable=True, server_default=sa.text('now()')),
        sa.UniqueConstraint('project_id', 'saved_process_id', name='uq_project_savedprocess'),
        sa.UniqueConstraint('project_id', 'radicado', name='uq_project_radicado'),
    )
    # Index for project lookup
    op.create_index('ix_project_cases_project_id', 'project_cases', ['project_id'])


def downgrade():
    # Drop in reverse order
    op.drop_index('ix_project_cases_project_id', table_name='project_cases')
    op.drop_table('project_cases')

    op.drop_index('ix_projects_user_id', table_name='projects')
    op.drop_table('projects')