#!/usr/bin/env python3
"""
Script de limpieza para eliminar procesos huérfanos que no tienen proyecto asignado.
Los procesos huérfanos son aquellos en la tabla 'procesos' que no están referenciados
en la tabla 'project_cases'.
"""

import os
import sys
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

# Configuración de la base de datos (igual que en main.py)
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./backend/sql_app.db")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def cleanup_orphaned_processes():
    """
    Función principal que realiza la limpieza de procesos huérfanos.
    """
    db = SessionLocal()
    try:
        # Paso 1: Identificar procesos huérfanos
        # Procesos en 'saved_processes' que no están en 'project_cases'
        query_orphaned = text("""
            SELECT sp.id, sp.radicado
            FROM saved_processes sp
            LEFT JOIN project_cases pc ON sp.id = pc.saved_process_id
            WHERE pc.saved_process_id IS NULL
        """)

        orphaned_processes = db.execute(query_orphaned).fetchall()

        if not orphaned_processes:
            print("No se encontraron procesos huérfanos.")
            return

        # Mostrar procesos a eliminar
        print(f"Se encontraron {len(orphaned_processes)} procesos huérfanos:")
        for process in orphaned_processes:
            print(f"  - ID: {process.id}, Radicado: {process.radicado}")

        # Confirmar eliminación (aunque el usuario dijo limpieza brusca, agregamos confirmación por seguridad)
        confirm = input(f"\n¿Desea eliminar estos {len(orphaned_processes)} procesos? (sí/no): ").strip().lower()
        if confirm not in ['sí', 'si', 'yes', 'y']:
            print("Operación cancelada.")
            return

        # Paso 2: Eliminar procesos huérfanos
        # Usar una transacción para asegurar atomicidad
        with db.begin():
            delete_query = text("""
                DELETE FROM saved_processes
                WHERE id IN (
                    SELECT sp.id
                    FROM saved_processes sp
                    LEFT JOIN project_cases pc ON sp.id = pc.saved_process_id
                    WHERE pc.saved_process_id IS NULL
                )
            """)

            result = db.execute(delete_query)
            deleted_count = result.rowcount

        # Paso 3: Mostrar resumen
        print(f"\nLimpieza completada exitosamente.")
        print(f"Procesos eliminados: {deleted_count}")

    except Exception as e:
        print(f"Error durante la limpieza: {e}")
        db.rollback()
        sys.exit(1)
    finally:
        db.close()

if __name__ == "__main__":
    print("Iniciando limpieza de procesos huérfanos...")
    cleanup_orphaned_processes()
    print("Script finalizado.")