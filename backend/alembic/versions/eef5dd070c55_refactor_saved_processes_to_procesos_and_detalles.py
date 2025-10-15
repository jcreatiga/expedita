"""refactor saved_processes to procesos and detalles

Revision ID: eef5dd070c55
Revises: 0001_create_projects_and_project_cases
Create Date: 2025-10-14 17:48:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'eef5dd070c55'
down_revision = '0001_create_projects_and_project_cases'
branch_labels = None
depends_on = None


def upgrade():
    # Renombrar tabla 'saved_processes' a 'procesos'
    op.rename_table('saved_processes', 'procesos')
    
    # Cambiar nombres de columnas en 'procesos'
    op.alter_column('procesos', 'id', new_column_name='idProceso')
    op.alter_column('procesos', 'user_id', new_column_name='idUsuario')
    op.alter_column('procesos', 'id_proceso', new_column_name='id_expediente')
    
    # Agregar columna 'deleted_at' (tipo Boolean, nullable, default NULL)
    op.add_column('procesos', sa.Column('deleted_at', sa.Boolean(), nullable=True, default=None))
    
    # Crear nueva tabla 'ProcesosDetalles'
    op.create_table(
        'ProcesosDetalles',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('idProceso', sa.Integer(), sa.ForeignKey('procesos.idProceso', ondelete='CASCADE'), nullable=False),
        sa.Column('demandante', sa.String(length=255)),
        sa.Column('demandado', sa.String(length=255)),
        sa.Column('juzgado', sa.String(length=255)),
        sa.Column('clase', sa.String(length=255)),
        sa.Column('subclase', sa.String(length=255)),
        sa.Column('ubicacion', sa.String(length=255)),
        sa.Column('fecha_ultima_actuacion', sa.Date()),
        sa.Column('snapshot_detalle', sa.Text()),
        sa.Column('created_at', sa.DateTime(), default=sa.text('now()')),
        sa.Column('updated_at', sa.DateTime(), default=sa.text('now()'), onupdate=sa.text('now()'))
    )
    
    # Migrar datos existentes de saved_processes a las nuevas tablas
    # Copiar datos a 'procesos'
    op.execute("""
        INSERT INTO procesos (idProceso, idUsuario, radicado, id_expediente, snapshot_consulta, created_at, updated_at, deleted_at)
        SELECT id, user_id, radicado, id_proceso, snapshot_consulta, created_at, updated_at, NULL
        FROM saved_processes
    """)
    
    # Copiar datos a 'ProcesosDetalles'
    op.execute("""
        INSERT INTO ProcesosDetalles (idProceso, demandante, demandado, juzgado, clase, subclase, ubicacion, fecha_ultima_actuacion, snapshot_detalle, created_at, updated_at)
        SELECT id, demandante, demandado, juzgado, clase, subclase, ubicacion, fecha_ultima_actuacion, snapshot_detalle, created_at, updated_at
        FROM saved_processes
    """)
    
    # Actualizar foreign keys en project_cases de saved_process_id a idProceso (referenciando procesos.idProceso)
    op.alter_column('project_cases', 'saved_process_id', new_column_name='idProceso')
    op.execute("""
        UPDATE project_cases
        SET idProceso = procesos.idProceso
        FROM procesos
        WHERE project_cases.idProceso = procesos.idProceso
    """)
    
    # Eliminar la tabla antigua saved_processes después de la migración
    op.drop_table('saved_processes')


def downgrade():
    # Recrear tabla saved_processes
    op.create_table(
        'saved_processes',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('user_id', sa.Integer()),
        sa.Column('radicado', sa.String(length=23), nullable=False),
        sa.Column('id_proceso', sa.String(length=50)),
        sa.Column('demandante', sa.String(length=255)),
        sa.Column('demandado', sa.String(length=255)),
        sa.Column('juzgado', sa.String(length=255)),
        sa.Column('clase', sa.String(length=255)),
        sa.Column('subclase', sa.String(length=255)),
        sa.Column('ubicacion', sa.String(length=255)),
        sa.Column('fecha_ultima_actuacion', sa.Date()),
        sa.Column('snapshot_consulta', sa.Text()),
        sa.Column('snapshot_detalle', sa.Text()),
        sa.Column('created_at', sa.DateTime(), default=sa.text('now()')),
        sa.Column('updated_at', sa.DateTime(), default=sa.text('now()'), onupdate=sa.text('now()'))
    )
    
    # Migrar datos de vuelta a saved_processes
    op.execute("""
        INSERT INTO saved_processes (id, user_id, radicado, id_proceso, demandante, demandado, juzgado, clase, subclase, ubicacion, fecha_ultima_actuacion, snapshot_consulta, snapshot_detalle, created_at, updated_at)
        SELECT pd.id, p.idUsuario, p.radicado, p.id_expediente, pd.demandante, pd.demandado, pd.juzgado, pd.clase, pd.subclase, pd.ubicacion, pd.fecha_ultima_actuacion, p.snapshot_consulta, pd.snapshot_detalle, pd.created_at, pd.updated_at
        FROM ProcesosDetalles pd
        JOIN procesos p ON pd.idProceso = p.idProceso
        WHERE p.deleted_at IS NULL
    """)
    
    # Actualizar foreign keys en project_cases de vuelta a saved_process_id
    op.alter_column('project_cases', 'idProceso', new_column_name='saved_process_id')
    op.execute("""
        UPDATE project_cases
        SET saved_process_id = saved_processes.id
        FROM saved_processes
        WHERE project_cases.saved_process_id = saved_processes.id
    """)
    
    # Eliminar tabla ProcesosDetalles
    op.drop_table('ProcesosDetalles')
    
    # Revertir cambios en procesos
    op.alter_column('procesos', 'idProceso', new_column_name='id')
    op.alter_column('procesos', 'idUsuario', new_column_name='user_id')
    op.alter_column('procesos', 'id_expediente', new_column_name='id_proceso')
    op.drop_column('procesos', 'deleted_at')
    
    # Renombrar tabla procesos de vuelta a saved_processes
    op.rename_table('procesos', 'saved_processes')