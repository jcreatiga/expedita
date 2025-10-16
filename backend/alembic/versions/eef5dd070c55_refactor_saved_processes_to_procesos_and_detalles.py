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
    # op.rename_table('saved_processes', 'procesos') # Eliminado, ya se crea como 'procesos' en 0001
    
    # Cambiar nombres de columnas en 'procesos'
    # op.alter_column('procesos', 'id', new_column_name='idProceso') # Eliminado, ya se crea como 'idProceso' en 0001
    # op.alter_column('procesos', 'user_id', new_column_name='idUsuario') # Eliminado, ya se crea como 'idUsuario' en 0001
    # op.alter_column('procesos', 'id_proceso', new_column_name='id_expediente') # Eliminado, ya se crea como 'id_expediente' en 0001
    
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
    # Copiar datos a 'procesos' (ya no es necesario, la tabla 'procesos' ya existe con los datos)
    # op.execute("""
    #     INSERT INTO procesos (idProceso, idUsuario, radicado, id_expediente, snapshot_consulta, created_at, updated_at, deleted_at)
    #     SELECT id, user_id, radicado, id_proceso, snapshot_consulta, created_at, updated_at, NULL
    #     FROM saved_processes
    # """)
    
    # Copiar datos de detalle de 'procesos' a 'ProcesosDetalles'
    op.execute("""
        INSERT INTO ProcesosDetalles (idProceso, demandante, demandado, juzgado, clase, subclase, ubicacion, fecha_ultima_actuacion, snapshot_detalle, created_at, updated_at)
        SELECT idProceso, demandante, demandado, juzgado, clase, subclase, ubicacion, fecha_ultima_actuacion, snapshot_detalle, created_at, updated_at
        FROM procesos
    """)
    
    # Eliminar columnas de detalle de la tabla 'procesos'
    op.drop_column('procesos', 'demandante')
    op.drop_column('procesos', 'demandado')
    op.drop_column('procesos', 'juzgado')
    op.drop_column('procesos', 'clase')
    op.drop_column('procesos', 'subclase')
    op.drop_column('procesos', 'ubicacion')
    op.drop_column('procesos', 'fecha_ultima_actuacion')
    op.drop_column('procesos', 'snapshot_detalle')

    # Actualizar foreign keys en project_cases de saved_process_id a idProceso (referenciando procesos.idProceso)
    # op.alter_column('project_cases', 'saved_process_id', new_column_name='idProceso') # Eliminado, ya se llama idProceso en 0001
    op.execute("""
        UPDATE project_cases
        SET idProceso = procesos.idProceso
        FROM procesos
        WHERE project_cases.idProceso = procesos.idProceso
    """)
    
    # Eliminar la tabla antigua saved_processes después de la migración (ya no existe)
    # op.drop_table('saved_processes') # Eliminado


def downgrade():
    # Revertir cambios en procesos: agregar columnas de detalle
    op.add_column('procesos', sa.Column('demandante', sa.String(length=255), nullable=True))
    op.add_column('procesos', sa.Column('demandado', sa.String(length=255), nullable=True))
    op.add_column('procesos', sa.Column('juzgado', sa.String(length=255), nullable=True))
    op.add_column('procesos', sa.Column('clase', sa.String(length=255), nullable=True))
    op.add_column('procesos', sa.Column('subclase', sa.String(length=255), nullable=True))
    op.add_column('procesos', sa.Column('ubicacion', sa.String(length=255), nullable=True))
    op.add_column('procesos', sa.Column('fecha_ultima_actuacion', sa.Date(), nullable=True))
    op.add_column('procesos', sa.Column('snapshot_detalle', sa.Text(), nullable=True))

    # Migrar datos de ProcesosDetalles de vuelta a procesos
    op.execute("""
        UPDATE procesos
        SET
            demandante = pd.demandante,
            demandado = pd.demandado,
            juzgado = pd.juzgado,
            clase = pd.clase,
            subclase = pd.subclase,
            ubicacion = pd.ubicacion,
            fecha_ultima_actuacion = pd.fecha_ultima_actuacion,
            snapshot_detalle = pd.snapshot_detalle
        FROM ProcesosDetalles pd
        WHERE procesos.idProceso = pd.idProceso
    """)
    
    # Eliminar tabla ProcesosDetalles
    op.drop_table('ProcesosDetalles')
    
    # Eliminar columna 'deleted_at'
    op.drop_column('procesos', 'deleted_at')

    # Revertir foreign keys en project_cases (ya no es necesario renombrar)
    # op.alter_column('project_cases', 'idProceso', new_column_name='saved_process_id') # Eliminado