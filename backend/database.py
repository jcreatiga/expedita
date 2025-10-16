import os
import datetime
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Date, ForeignKey, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session

# Database configuration
DB_AVAILABLE = True
try:
    Base = declarative_base()
except Exception as e:
    print(f"WARNING: SQLAlchemy Base creation failed. Error: {e}")
    DB_AVAILABLE = False
    Base = None

if DB_AVAILABLE:
    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./sql_app.db")
    print(f"DEBUG: Attempting to connect to database at {DATABASE_URL}")
    engine = create_engine(DATABASE_URL)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    try:
        with engine.connect() as connection:
            print("DEBUG: Successfully connected to the database.")
    except Exception as e:
        print(f"ERROR: Could not connect to the database. Error: {e}")
        DB_AVAILABLE = False

# SQLAlchemy models
if DB_AVAILABLE:
    class Proceso(Base):
        __tablename__ = "procesos"
        
        idProceso = Column(Integer, primary_key=True, index=True)
        idUsuario = Column(Integer, index=True)
        radicado = Column(String(23), nullable=False)
        id_expediente = Column(String(50))
        snapshot_consulta = Column(Text)
        created_at = Column(DateTime, default=datetime.datetime.utcnow)
        updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
        deleted_at = Column(Boolean, nullable=True, default=None)
        
        detalles = relationship("ProcesosDetalles", back_populates="proceso", cascade="all, delete-orphan")

    class ProcesosDetalles(Base):
        __tablename__ = "ProcesosDetalles"
        
        id = Column(Integer, primary_key=True, index=True)
        idProceso = Column(Integer, ForeignKey("procesos.idProceso", ondelete="CASCADE"), nullable=False)
        demandante = Column(String(255))
        demandado = Column(String(255))
        juzgado = Column(String(255))
        clase = Column(String(255))
        subclase = Column(String(255))
        ubicacion = Column(String(255))
        fecha_ultima_actuacion = Column(Date)
        snapshot_detalle = Column(Text)
        created_at = Column(DateTime, default=datetime.datetime.utcnow)
        updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
        
        proceso = relationship("Proceso", back_populates="detalles")

    class Project(Base):
        __tablename__ = "projects"
        
        id = Column(Integer, primary_key=True, index=True)
        user_id = Column(Integer, nullable=False)
        name = Column(String(255), nullable=False)
        color_hex = Column(String(7), nullable=False, default="#2563EB")
        total_cases = Column(Integer, nullable=False, default=0)
        created_at = Column(DateTime, default=datetime.datetime.utcnow)
        updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
        
        cases = relationship("ProjectCase", back_populates="project", cascade="all, delete-orphan")

    class ProjectCase(Base):
        __tablename__ = "project_cases"
        
        id = Column(Integer, primary_key=True, index=True)
        project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
        idProceso = Column(Integer, ForeignKey("procesos.idProceso", ondelete="SET NULL"), nullable=True)
        radicado = Column(String(23), nullable=True)
        created_at = Column(DateTime, default=datetime.datetime.utcnow)
        updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
        
        project = relationship("Project", back_populates="cases")

    class User(Base):
        __tablename__ = "users"
        
        id = Column(Integer, primary_key=True, index=True)
        username = Column(String(50), unique=True, nullable=False)
        email = Column(String(255), unique=True, nullable=False)
        hashed_password = Column(String(255), nullable=False)
        is_active = Column(Boolean, default=True)
        created_at = Column(DateTime, default=datetime.datetime.utcnow)
        updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

def get_db():
    if not DB_AVAILABLE:
        raise HTTPException(status_code=500, detail="Database not available")
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()