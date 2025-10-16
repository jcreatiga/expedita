from fastapi import FastAPI, HTTPException, Depends, status, Request, Response
from pathlib import Path
from fastapi.staticfiles import StaticFiles
import datetime
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from selenium.webdriver.common.by import By
from passlib.context import CryptContext
from jose import JWTError, jwt
from pydantic import BaseModel
from typing import Optional, List, Any, Dict
import os
import json
import requests
import urllib3
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Date, ForeignKey, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session
# Suppress InsecureRequestWarning for external API calls that use verify=False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import asyncio
import time
import uuid
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

# Try to import SQLAlchemy lazily so the app can start even if the environment's Python
# / SQLAlchemy combination is incompatible. If import fails we set DB_AVAILABLE=False
# and avoid defining models / creating sessions at import time.
DB_AVAILABLE = True
try:
    from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Date, ForeignKey, Boolean
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy.orm import sessionmaker, relationship, Session
    Base = declarative_base()
except Exception as e:
    print(f"WARNING: SQLAlchemy import failed - running without DB. Error: {e}")
    DB_AVAILABLE = False
    Base = None
    create_engine = None
    sessionmaker = None
    relationship = None

print(f"DEBUG: DB_AVAILABLE is {DB_AVAILABLE}")
if DB_AVAILABLE:
    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./sql_app.db")
    print(f"DEBUG: Attempting to connect to database at {DATABASE_URL}")
    engine = create_engine(DATABASE_URL)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    try:
        # Try to connect to validate the engine
        with engine.connect() as connection:
            print("DEBUG: Successfully connected to the database.")
    except Exception as e:
        print(f"ERROR: Could not connect to the database. Error: {e}")
        DB_AVAILABLE = False

# Authentication configuration
SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key-change-in-production')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 24 * 60  # 24 hours

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# Rate limiting
limiter = Limiter(key_func=get_remote_address)

# Pydantic models
# Comprehensive Proceso model 
# Pydantic models for API
class ProcesoBase(BaseModel):
    radicado: str
    id_expediente: Optional[str] = None
    snapshot_consulta: Optional[str] = None

class ProcesoCreate(ProcesoBase):
    pass

class Proceso(ProcesoBase):
    idProceso: int
    idUsuario: Optional[int]
    created_at: datetime.datetime
    updated_at: datetime.datetime
    deleted_at: Optional[bool] = None
    
    class Config:
        from_attributes = True

class ProcesosDetallesBase(BaseModel):
    demandante: Optional[str] = None
    demandado: Optional[str] = None
    juzgado: Optional[str] = None
    clase: Optional[str] = None
    subclase: Optional[str] = None
    ubicacion: Optional[str] = None
    fecha_ultima_actuacion: Optional[datetime.date] = None
    snapshot_detalle: Optional[str] = None

class ProcesosDetallesCreate(ProcesosDetallesBase):
    pass

class ProcesosDetalles(ProcesosDetallesBase):
    id: int
    idProceso: int
    created_at: datetime.datetime
    updated_at: datetime.datetime
    
    class Config:
        from_attributes = True

# Pydantic models for Projects
class ProjectBase(BaseModel):
    name: str
    color_hex: Optional[str] = "#2563EB"

class ProjectCreate(ProjectBase):
    pass

class Project(ProjectBase):
    id: int
    user_id: int
    total_cases: int
    created_at: datetime.datetime
    updated_at: datetime.datetime
    
    class Config:
        from_attributes = True

class ProjectCaseBase(BaseModel):
    radicado: Optional[str] = None

class ProjectCaseCreate(ProjectCaseBase):
    pass

class ProjectCase(ProjectCaseBase):
    id: int
    project_id: int
    idProceso: Optional[int]
    created_at: datetime.datetime
    updated_at: datetime.datetime
    
    class Config:
        from_attributes = True

# Pydantic models for User
class UserBase(BaseModel):
    username: str
    email: str
    is_active: Optional[bool] = True

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: int
    created_at: datetime.datetime
    updated_at: datetime.datetime
    
    class Config:
        from_attributes = True

class UserLogin(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

# Database setup
if DB_AVAILABLE:
    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./sql_app.db")
    engine = create_engine(DATABASE_URL)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Dependency to get DB session
def get_db():
    if not DB_AVAILABLE:
        raise HTTPException(status_code=500, detail="Database not available")
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# FastAPI app instance
app = FastAPI()

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate limiting middleware
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

@app.get("/", response_class=HTMLResponse)
async def read_root():
    with open("static/index.html", "r") as f:
        return HTMLResponse(content=f.read(), status_code=200)

# Authentication functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[datetime.timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.datetime.utcnow() + expires_delta
    else:
        expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        
        user = db.query(User).filter(User.username == username).first()
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")

async def validate_radicado_exists(radicado: str) -> bool:
    url = f"https://consultaprocesos.ramajudicial.gov.co:448/api/v2/Procesos/Consulta/NumeroRadicacion?numero={radicado}&SoloActivos=false&pagina=1"
    try:
        response = requests.get(url, verify=False, timeout=10)
        if response.status_code == 200:
            data = response.json()
            # Verificar si contiene procesos válidos
            if 'procesos' in data and isinstance(data['procesos'], list) and len(data['procesos']) > 0:
                return True
        return False
    except Exception as e:
        print(f"Error validating radicado: {e}")
        return False

# Helper function to get user ID from username
def get_user_id_from_username(username: str, db: Session) -> int:
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    return user.id

# Authentication routes
@app.post("/auth/register", response_model=User)
async def register(user: UserCreate, db: Session = Depends(get_db)):
    # Check if user already exists
    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create new user
    hashed_password = get_password_hash(user.password)
    db_user = User(
        username=user.username,
        email=user.email,
        hashed_password=hashed_password,
        is_active=True
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.post("/auth/login", response_model=Token)
async def login(user_credentials: UserLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == user_credentials.username).first()
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    
    if not verify_password(user_credentials.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    
    if not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    
    access_token_expires = datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/auth/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

@app.post("/auth/logout")
async def logout():
    # For JWT, logout is handled client-side by removing the token
    return {"message": "Successfully logged out"}

@app.post("/auth/forgot-password")
async def forgot_password(email: str, db: Session = Depends(get_db)):
    # Find user by email
    user = db.query(User).filter(User.email == email).first()
    if not user:
        # Don't reveal if email exists or not for security
        return {"message": "If the email exists, a password reset link has been sent"}
    
    # In a real implementation, you would:
    # 1. Generate a password reset token
    # 2. Store it in the database with expiration
    # 3. Send an email with the reset link
    # For now, just return a success message
    return {"message": "If the email exists, a password reset link has been sent"}

# API endpoints

# Endpoint to save a process (from consulta) - requires project_id
@app.post("/api/saved")
async def save_process(
    process: ProcesoCreate,
    project_id: int,
    current_user: str = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Validate that project_id is provided and project exists
    if not project_id:
        raise HTTPException(status_code=400, detail="project_id es requerido para guardar un proceso")
    
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Proyecto no encontrado")
    
    # Check if user owns the project
    user_id = get_user_id_from_username(current_user.username, db)
    if project.user_id != user_id:
        raise HTTPException(status_code=403, detail="No tienes permisos para acceder a este proyecto")
    
    # Validate radicado exists in Rama Judicial API
    if not await validate_radicado_exists(process.radicado):
        raise HTTPException(status_code=400, detail="El radicado no existe en la Rama Judicial")
    
    # Check if process already exists
    existing_process = db.query(Proceso).filter(Proceso.radicado == process.radicado).first()
    if existing_process:
        raise HTTPException(status_code=400, detail="El proceso ya está guardado")
    
    # Create the process
    db_process = Proceso(
        radicado=process.radicado,
        id_expediente=process.id_expediente,
        snapshot_consulta=process.snapshot_consulta,
        idUsuario=user_id
    )
    db.add(db_process)
    db.commit()
    db.refresh(db_process)
    
    # Add to project
    project_case = ProjectCase(
        project_id=project_id,
        idProceso=db_process.idProceso,
        radicado=process.radicado
    )
    db.add(project_case)
    db.commit()
    
    # Update project total_cases
    project.total_cases += 1
    db.commit()
    
    return {"message": "Proceso guardado exitosamente", "idProceso": db_process.idProceso}

# Endpoint to add case to project
@app.post("/api/projects/{project_id}/cases")
async def add_case_to_project(
    project_id: int,
    case_data: dict,  # Expecting {"radicado": "..."} or {"idProceso": ...}
    current_user: str = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Validate project exists and user owns it
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Proyecto no encontrado")
    
    user_id = get_user_id_from_username(current_user.username, db)
    if project.user_id != user_id:
        raise HTTPException(status_code=403, detail="No tienes permisos para acceder a este proyecto")
    
    # Extract radicado or idProceso from request
    radicado = case_data.get("radicado")
    idProceso = case_data.get("idProceso")
    
    if not radicado and not idProceso:
        raise HTTPException(status_code=400, detail="Se requiere radicado o idProceso")
    
    # Find the process
    if idProceso:
        process = db.query(Proceso).filter(Proceso.idProceso == idProceso).first()
    else:
        process = db.query(Proceso).filter(Proceso.radicado == radicado).first()
    
    # If process doesn't exist and we have radicado, validate it exists in Rama Judicial API
    if not process and radicado:
        if not await validate_radicado_exists(radicado):
            raise HTTPException(status_code=400, detail="El radicado no existe en la Rama Judicial")
        # Create the process since it doesn't exist
        db_process = Proceso(
            radicado=radicado,
            idUsuario=user_id
        )
        db.add(db_process)
        db.commit()
        db.refresh(db_process)
        process = db_process
    
    if not process:
        raise HTTPException(status_code=404, detail="Proceso no encontrado")
    
    # Check if already in project
    existing_case = db.query(ProjectCase).filter(
        ProjectCase.project_id == project_id,
        ProjectCase.idProceso == process.idProceso
    ).first()
    if existing_case:
        raise HTTPException(status_code=400, detail="El caso ya está en este proyecto")
    
    # Add to project
    project_case = ProjectCase(
        project_id=project_id,
        idProceso=process.idProceso,
        radicado=process.radicado
    )
    db.add(project_case)
    db.commit()
    
    # Update project total_cases
    project.total_cases += 1
    db.commit()
    
    return {"message": "Caso añadido al proyecto exitosamente"}

# Endpoint to delete a saved process
@app.delete("/api/saved/{saved_id}")
async def delete_saved_process(
    saved_id: int,
    current_user: str = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Find the process
    process = db.query(Proceso).filter(Proceso.idProceso == saved_id).first()
    if not process:
        raise HTTPException(status_code=404, detail="Proceso no encontrado")
    
    # Check if user owns the process
    user_id = get_user_id_from_username(current_user.username, db)
    if process.idUsuario != user_id:
        raise HTTPException(status_code=403, detail="No tienes permisos para eliminar este proceso")
    
    # Check if process is used in any project
    project_cases = db.query(ProjectCase).filter(ProjectCase.idProceso == saved_id).all()
    if project_cases:
        # Remove from all projects and update counts
        for project_case in project_cases:
            project = db.query(Project).filter(Project.id == project_case.project_id).first()
            if project:
                project.total_cases -= 1
            db.delete(project_case)
    
    # Delete the process (details will be deleted via cascade)
    db.delete(process)
    db.commit()
    
    return {"message": "Proceso eliminado exitosamente"}

# Endpoint to get all saved processes for the current user
@app.get("/api/saved")
async def get_saved_processes(
    current_user: str = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user_id = get_user_id_from_username(current_user.username, db)
    
    # Get processes with their details
    processes = db.query(Proceso).options(
        db.joinedload(Proceso.detalles)
    ).filter(Proceso.idUsuario == user_id).all()
    
    # Convert to response format
    result = []
    for process in processes:
        process_dict = {
            "idProceso": process.idProceso,
            "radicado": process.radicado,
            "id_expediente": process.id_expediente,
            "snapshot_consulta": process.snapshot_consulta,
            "created_at": process.created_at,
            "updated_at": process.updated_at,
            "deleted_at": process.deleted_at,
            "detalles": None
        }
        
        if process.detalles:
            process_dict["detalles"] = {
                "demandante": process.detalles.demandante,
                "demandado": process.detalles.demandado,
                "juzgado": process.detalles.juzgado,
                "clase": process.detalles.clase,
                "subclase": process.detalles.subclase,
                "ubicacion": process.detalles.ubicacion,
                "fecha_ultima_actuacion": process.detalles.fecha_ultima_actuacion,
                "snapshot_detalle": process.detalles.snapshot_detalle,
                "created_at": process.detalles.created_at,
                "updated_at": process.detalles.updated_at
            }
        
        result.append(process_dict)
    
    return result

# Endpoint to refresh all saved processes
@app.post("/api/saved/refresh")
async def refresh_saved_processes(
    current_user: str = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user_id = get_user_id_from_username(current_user.username, db)
    
    # Get all processes for the user
    processes = db.query(Proceso).filter(Proceso.idUsuario == user_id).all()
    
    updated_count = 0
    for process in processes:
        # Refresh process details from Rama Judicial API
        try:
            # This would need to be implemented based on the actual API structure
            # For now, just mark as updated
            process.updated_at = datetime.datetime.utcnow()
            updated_count += 1
        except Exception as e:
            print(f"Error refreshing process {process.idProceso}: {e}")
    
    db.commit()
    
    return {"message": f"{updated_count} procesos actualizados"}

# Endpoint to refresh all cases in a project
@app.post("/api/projects/{project_id}/refresh")
async def refresh_project_cases(
    project_id: int,
    current_user: str = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Validate project exists and user owns it
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Proyecto no encontrado")
    
    user_id = get_user_id_from_username(current_user.username, db)
    if project.user_id != user_id:
        raise HTTPException(status_code=403, detail="No tienes permisos para acceder a este proyecto")
    
    # Get all cases in the project
    project_cases = db.query(ProjectCase).filter(ProjectCase.project_id == project_id).all()
    
    updated_count = 0
    for project_case in project_cases:
        if project_case.idProceso:
            # Refresh process details
            process = db.query(Proceso).filter(Proceso.idProceso == project_case.idProceso).first()
            if process:
                try:
                    # This would need to be implemented based on the actual API structure
                    process.updated_at = datetime.datetime.utcnow()
                    updated_count += 1
                except Exception as e:
                    print(f"Error refreshing process {process.idProceso}: {e}")
    
    db.commit()
    
    return {"message": f"{updated_count} casos actualizados en el proyecto"}

# Endpoint to refresh selected cases in a project
@app.post("/api/projects/{project_id}/refresh-selected")
async def refresh_selected_project_cases(
    project_id: int,
    case_ids: list[int],  # List of ProjectCase IDs to refresh
    current_user: str = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user_id = get_user_id_from_username(current_user.username, db)
    # Validate project exists and user owns it
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Proyecto no encontrado")
    
    if project.user_id != user_id:
        raise HTTPException(status_code=403, detail="No tienes permisos para acceder a este proyecto")
    
    updated_count = 0
    for case_id in case_ids:
        project_case = db.query(ProjectCase).filter(
            ProjectCase.id == case_id,
            ProjectCase.project_id == project_id
        ).first()
        
        if project_case and project_case.idProceso:
            process = db.query(Proceso).filter(Proceso.idProceso == project_case.idProceso).first()
            if process:
                try:
                    # This would need to be implemented based on the actual API structure
                    process.updated_at = datetime.datetime.utcnow()
                    updated_count += 1
                except Exception as e:
                    print(f"Error refreshing process {process.idProceso}: {e}")
    
    db.commit()
    
    return {"message": f"{updated_count} casos seleccionados actualizados"}

# Endpoint to refresh all projects (cron job)
@app.post("/api/cron/refresh-all-projects")
async def refresh_all_projects(
    db: Session = Depends(get_db)
):
    # This endpoint doesn't require authentication as it's meant for cron jobs
    # In production, you should add proper authentication/authorization
    
    # Get all projects
    projects = db.query(Project).all()
    
    total_updated = 0
    for project in projects:
        # Get all cases in the project
        project_cases = db.query(ProjectCase).filter(ProjectCase.project_id == project.id).all()
        
        for project_case in project_cases:
            if project_case.idProceso:
                process = db.query(Proceso).filter(Proceso.idProceso == project_case.idProceso).first()
                if process:
                    try:
                        # This would need to be implemented based on the actual API structure
                        process.updated_at = datetime.datetime.utcnow()
                        total_updated += 1
                    except Exception as e:
                        print(f"Error refreshing process {process.idProceso}: {e}")
    
    db.commit()
    
    return {"message": f"{total_updated} procesos actualizados en todos los proyectos"}

# Rate limiting middleware
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

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
        
        # Relationship to ProcesosDetalles
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
        
        # Relationship back to Proceso
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
        
        # Relationship to ProjectCase
        cases = relationship("ProjectCase", back_populates="project", cascade="all, delete-orphan")

    class ProjectCase(Base):
        __tablename__ = "project_cases"
        
        id = Column(Integer, primary_key=True, index=True)
        project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
        idProceso = Column(Integer, ForeignKey("procesos.idProceso", ondelete="SET NULL"), nullable=True)
        radicado = Column(String(23), nullable=True)
        created_at = Column(DateTime, default=datetime.datetime.utcnow)
        updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
        
        # Relationship back to Project
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
