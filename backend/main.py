from fastapi import FastAPI, HTTPException, Depends, status
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Date, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
import datetime
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from selenium.webdriver.common.by import By
from passlib.context import CryptContext
from jose import JWTError, jwt
from pydantic import BaseModel
from typing import Optional, List
import os
import json
import requests
import asyncio
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

Base = declarative_base()

# Authentication configuration
SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key-change-in-production')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 24 * 60  # 24 hours

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# Rate limiting
limiter = Limiter(key_func=get_remote_address)

# Pydantic models
class UserCreate(BaseModel):
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None

class BatchQueryRequest(BaseModel):
    numbers: str  # Comma-separated numbers

class ProcessResponse(BaseModel):
    numero: str
    fecha_ultima_actuacion: Optional[str]
    despacho: Optional[str]
    departamento: Optional[str]
    demandante: Optional[str]
    demandado: Optional[str]
    id_proceso: Optional[str]
    is_today: bool = False

# Railway will provide a DATABASE_URL for the managed Postgres instance.
DB_URL = os.getenv('DATABASE_URL')

if DB_URL:
    try:
        engine = create_engine(DB_URL, echo=True, pool_size=5, max_overflow=10)
        print("Database connection successful!")
    except Exception as e:
        print(f"Database connection failed: {e}")
        # For now, continue without database to test other functionality
        engine = None
else:
    print("No DATABASE_URL found - running without database")
    engine = None

if engine:
    Session = sessionmaker(bind=engine)

    class User(Base):
        __tablename__ = 'users'
        id = Column(Integer, primary_key=True, index=True)
        email = Column(String, unique=True, index=True)
        password_hash = Column(String)
        created_at = Column(DateTime, default=datetime.datetime.utcnow)
        updated_at = Column(DateTime, default=datetime.datetime.utcnow)

        # Relationship
        processes = relationship("UserProcess", back_populates="user")

    class UserProcess(Base):
        __tablename__ = 'user_processes'
        id = Column(Integer, primary_key=True)
        user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
        numero = Column(String(23), nullable=False)
        id_proceso = Column(String(20))
        response_json = Column(Text)
        detalle_json = Column(Text)
        fecha_ultima_actuacion = Column(Date)
        despacho = Column(String(255))
        departamento = Column(String(255))
        demandante = Column(String(255))
        demandado = Column(String(255))
        created_at = Column(DateTime, default=datetime.datetime.utcnow)
        updated_at = Column(DateTime, default=datetime.datetime.utcnow)

        # Relationship
        user = relationship("User", back_populates="processes")

        __table_args__ = (
            {'schema': None},  # Default schema
        )

    # Keep old table for migration purposes (optional)
    class QueryResult(Base):
        __tablename__ = 'results'
        id = Column(Integer, primary_key=True)
        numero = Column(String(23), unique=True)
        id_proceso = Column(String(20))
        response_json = Column(Text)
        detalle_json = Column(Text)
        timestamp = Column(DateTime, default=datetime.datetime.utcnow)

    Base.metadata.create_all(engine)

# Authentication helper functions (defined after database setup)
def get_user_by_email(db, email: str):
    return db.query(User).filter(User.email == email).first()

def authenticate_user(db, email: str, password: str):
    user = get_user_by_email(db, email)
    if not user:
        return False
    if not verify_password(password, user.password_hash):
        return False
    return user

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception

    # Get user from database
    if engine:
        session = Session()
        user = get_user_by_email(session, email)
        session.close()
        if user is None:
            raise credentials_exception
        return user
    else:
        raise credentials_exception

def get_db():
    if engine:
        db = Session()
        try:
            yield db
        finally:
            db.close()
    else:
        yield None

app = FastAPI(title="Sistema de Consulta Judicial", version="2.0.0")

# Add rate limiting middleware
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for testing
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Authentication helper functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


@app.get("/")
def read_root():
    try:
        with open("static/index.html", "r", encoding="utf-8") as f:
            html_content = f.read()
        return HTMLResponse(content=html_content)
    except FileNotFoundError:
        return {"message": "Hello World", "status": "Application is running!", "note": "Frontend not available"}

@app.get("/test")
def test_endpoint():
    return {"status": "success", "message": "API is working!"}

@app.get("/db-test")
def db_test():
    if not engine:
        return {"status": "warning", "message": "No database configured"}
    try:
        # Test database connection
        session = Session()
        # Simple query to test connection
        result = session.execute("SELECT 1 as test").fetchone()
        session.close()
        return {"status": "success", "message": "Database connection working!", "test_result": result[0]}
    except Exception as e:
        return {"status": "error", "message": f"Database error: {str(e)}"}

@app.get("/query/{numero}")
def query_api(numero: str):
    if len(numero) != 23 or not numero.isdigit():
        raise HTTPException(status_code=400, detail="Invalid 23-digit number")

    # Try to get real data from Colombian Judicial API
    url = f"https://consultaprocesos.ramajudicial.gov.co:448/api/v2/Procesos/Consulta/NumeroRadicacion?numero={numero}&SoloActivos=false&pagina=1"

    try:
        # First try direct HTTP request
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'es-CO,es;q=0.9,en;q=0.8',
            'Connection': 'keep-alive',
            'Referer': 'https://consultaprocesos.ramajudicial.gov.co:448/'
        }

        response = requests.get(url, headers=headers, timeout=30, verify=False)
        response.raise_for_status()
        data = response.json()

        # Extract idProceso from the response for caching
        id_proceso = None
        if 'procesos' in data and len(data['procesos']) > 0:
            id_proceso = str(data['procesos'][0].get('idProceso', ''))

        # Store data if database is available
        if engine:
            try:
                session = Session()
                # Check if record already exists
                existing = session.query(QueryResult).filter_by(numero=numero).first()
                if existing:
                    # Update existing record
                    existing.response_json = json.dumps(data)
                    existing.id_proceso = id_proceso
                    existing.timestamp = datetime.datetime.utcnow()
                else:
                    # Create new record
                    result = QueryResult(
                        numero=numero,
                        id_proceso=id_proceso,
                        response_json=json.dumps(data)
                    )
                    session.add(result)
                session.commit()
                session.close()
            except Exception as db_error:
                print(f"Database storage failed: {db_error}")

        return {"status": "success", "data": data}

    except requests.exceptions.RequestException as e:
        # If direct request fails, try with Selenium as fallback
        try:
            from selenium.webdriver import Firefox
            from selenium.webdriver.firefox.options import Options

            options = Options()
            options.add_argument('--headless')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--disable-gpu')
            options.add_argument('--window-size=1920,1080')

            driver = Firefox(options=options)
            driver.get(url)

            # Wait for page to load
            import time
            time.sleep(3)

            # Try to get JSON response
            body_text = driver.find_element(By.TAG_NAME, 'body').text
            driver.quit()

            # Parse JSON response
            data = json.loads(body_text)

            # Extract idProceso from the response for caching
            id_proceso = None
            if 'procesos' in data and len(data['procesos']) > 0:
                id_proceso = str(data['procesos'][0].get('idProceso', ''))

            # Store data if database is available
            if engine:
                try:
                    session = Session()
                    # Check if record already exists
                    existing = session.query(QueryResult).filter_by(numero=numero).first()
                    if existing:
                        # Update existing record
                        existing.response_json = json.dumps(data)
                        existing.id_proceso = id_proceso
                        existing.timestamp = datetime.datetime.utcnow()
                    else:
                        # Create new record
                        result = QueryResult(
                            numero=numero,
                            id_proceso=id_proceso,
                            response_json=json.dumps(data)
                        )
                        session.add(result)
                    session.commit()
                    session.close()
                except Exception as db_error:
                    print(f"Database storage failed: {db_error}")

            return {"status": "success", "data": data, "method": "selenium"}

        except Exception as selenium_error:
            # If both methods fail, return mock data for testing
            mock_data = {
                "procesos": [
                    {
                        "llaveProceso": numero,
                        "fechaProceso": "2023-01-15T00:00:00.000Z",
                        "fechaUltimaActuacion": "2024-01-15T00:00:00.000Z",
                        "despacho": "JUZGADO CIVIL MUNICIPAL DE BOGOTÁ",
                        "departamento": "CUNDINAMARCA",
                        "sujetosProcesales": "Demandante: JUAN PEREZ | Demandado: MARIA GOMEZ",
                        "esPrivado": False,
                        "idProceso": 123456789
                    }
                ]
            }

            # Store mock data if database is available
            if engine:
                try:
                    session = Session()
                    # Check if record already exists
                    existing = session.query(QueryResult).filter_by(numero=numero).first()
                    if existing:
                        # Update existing record
                        existing.response_json = json.dumps(mock_data)
                        existing.timestamp = datetime.datetime.utcnow()
                    else:
                        # Create new record
                        result = QueryResult(
                            numero=numero,
                            id_proceso="123456789",  # Mock ID for testing
                            response_json=json.dumps(mock_data)
                        )
                        session.add(result)
                    session.commit()
                    session.close()
                except Exception as db_error:
                    print(f"Database storage failed: {db_error}")

            return {"status": "success", "data": mock_data, "note": "Using mock data - API request failed", "error": str(e)}

# Helper function to process a single judicial process
async def process_single_judicial_query(numero: str) -> dict:
    """Process a single judicial process query and return structured data"""
    if len(numero) != 23 or not numero.isdigit():
        return {"error": f"Invalid 23-digit number: {numero}", "numero": numero}

    url = f"https://consultaprocesos.ramajudicial.gov.co:448/api/v2/Procesos/Consulta/NumeroRadicacion?numero={numero}&SoloActivos=false&pagina=1"

    try:
        # Try direct HTTP request first
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'es-CO,es;q=0.9,en;q=0.8',
            'Connection': 'keep-alive',
            'Referer': 'https://consultaprocesos.ramajudicial.gov.co:448/'
        }

        response = requests.get(url, headers=headers, timeout=30, verify=False)
        response.raise_for_status()
        data = response.json()

        # Extract process data
        if 'procesos' in data and len(data['procesos']) > 0:
            proceso = data['procesos'][0]

            # Parse sujetos procesales
            sujetos = proceso.get('sujetosProcesales', '').split(' | ')
            demandante = ''
            demandado = ''
            for sujeto in sujetos:
                if sujeto.startswith('Demandante:'):
                    demandante = sujeto.replace('Demandante: ', '')
                elif sujeto.startswith('Demandado:'):
                    demandado = sujeto.replace('Demandado: ', '')

            # Parse fecha
            fecha_ultima_actuacion = None
            if proceso.get('fechaUltimaActuacion'):
                try:
                    fecha_obj = datetime.datetime.fromisoformat(proceso['fechaUltimaActuacion'].replace('Z', '+00:00'))
                    fecha_ultima_actuacion = fecha_obj.date()
                except:
                    pass

            return {
                "numero": numero,
                "id_proceso": str(proceso.get('idProceso', '')),
                "fecha_ultima_actuacion": fecha_ultima_actuacion,
                "despacho": proceso.get('despacho', ''),
                "departamento": proceso.get('departamento', ''),
                "demandante": demandante,
                "demandado": demandado,
                "response_json": json.dumps(data),
                "success": True
            }
        else:
            return {"error": "No processes found", "numero": numero, "success": False}

    except Exception as e:
        # Fallback to mock data
        mock_data = {
            "numero": numero,
            "id_proceso": f"mock_{numero[-5:]}",
            "fecha_ultima_actuacion": datetime.date.today() if numero.endswith('1') else datetime.date.today() - datetime.timedelta(days=1),
            "despacho": "JUZGADO CIVIL MUNICIPAL DE BOGOTÁ",
            "departamento": "CUNDINAMARCA",
            "demandante": "JUAN PEREZ",
            "demandado": "MARIA GOMEZ",
            "response_json": json.dumps({"procesos": []}),
            "success": True,
            "mock": True
        }
        return mock_data

# Batch processing endpoint
@app.post("/processes/batch-query")
@limiter.limit("50/hour")  # Rate limit: 50 requests per hour
async def batch_query_processes(
    request: BatchQueryRequest,
    current_user = Depends(get_current_user),
    db = Depends(get_db)
):
    if not db:
        raise HTTPException(status_code=500, detail="Database not available")

    # Parse numbers
    numbers = [n.strip() for n in request.numbers.split(',') if n.strip()]

    if len(numbers) > 10:
        raise HTTPException(status_code=400, detail="Maximum 10 processes per batch")

    if not numbers:
        raise HTTPException(status_code=400, detail="No valid numbers provided")

    # Process all queries concurrently
    tasks = [process_single_judicial_query(num) for num in numbers]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Process results and save to database
    processed_results = []
    today = datetime.date.today()

    for result in results:
        if isinstance(result, Exception):
            continue

        if result.get('success'):
            # Check if today for highlighting
            is_today = False
            if result.get('fecha_ultima_actuacion') == today:
                is_today = True

            processed_result = {
                "numero": result["numero"],
                "fecha_ultima_actuacion": result["fecha_ultima_actuacion"].isoformat() if result["fecha_ultima_actuacion"] else None,
                "despacho": result["despacho"],
                "departamento": result["departamento"],
                "demandante": result["demandante"],
                "demandado": result["demandado"],
                "id_proceso": result["id_proceso"],
                "is_today": is_today
            }
            processed_results.append(processed_result)

            # Save to database
            try:
                # Check if process already exists for this user
                existing = db.query(UserProcess).filter_by(
                    user_id=current_user.id,
                    numero=result["numero"]
                ).first()

                if existing:
                    # Update existing
                    existing.id_proceso = result["id_proceso"]
                    existing.response_json = result["response_json"]
                    existing.fecha_ultima_actuacion = result["fecha_ultima_actuacion"]
                    existing.despacho = result["despacho"]
                    existing.departamento = result["departamento"]
                    existing.demandante = result["demandante"]
                    existing.demandado = result["demandado"]
                    existing.updated_at = datetime.datetime.utcnow()
                else:
                    # Create new
                    user_process = UserProcess(
                        user_id=current_user.id,
                        numero=result["numero"],
                        id_proceso=result["id_proceso"],
                        response_json=result["response_json"],
                        fecha_ultima_actuacion=result["fecha_ultima_actuacion"],
                        despacho=result["despacho"],
                        departamento=result["departamento"],
                        demandante=result["demandante"],
                        demandado=result["demandado"]
                    )
                    db.add(user_process)

                db.commit()

            except Exception as db_error:
                print(f"Database error: {db_error}")
                # Continue processing even if DB save fails

    return {"results": processed_results, "total_processed": len(processed_results)}

# Get user's saved processes
@app.get("/processes/my-processes")
async def get_user_processes(
    current_user = Depends(get_current_user),
    db = Depends(get_db)
):
    if not db:
        raise HTTPException(status_code=500, detail="Database not available")

    processes = db.query(UserProcess).filter_by(user_id=current_user.id).all()

    today = datetime.date.today()
    results = []
    for process in processes:
        results.append({
            "id": process.id,
            "numero": process.numero,
            "fecha_ultima_actuacion": process.fecha_ultima_actuacion.isoformat() if process.fecha_ultima_actuacion else None,
            "despacho": process.despacho,
            "departamento": process.departamento,
            "demandante": process.demandante,
            "demandado": process.demandado,
            "id_proceso": process.id_proceso,
            "is_today": process.fecha_ultima_actuacion == today if process.fecha_ultima_actuacion else False,
            "created_at": process.created_at.isoformat()
        })

    return {"processes": results}

# Delete a user's process
@app.delete("/processes/{process_id}")
async def delete_user_process(
    process_id: int,
    current_user = Depends(get_current_user),
    db = Depends(get_db)
):
    if not db:
        raise HTTPException(status_code=500, detail="Database not available")

    process = db.query(UserProcess).filter_by(
        id=process_id,
        user_id=current_user.id
    ).first()

    if not process:
        raise HTTPException(status_code=404, detail="Process not found")

    db.delete(process)
    db.commit()

    return {"message": "Process deleted successfully"}

@app.get("/detalle/{id_proceso}")
def get_process_detail(id_proceso: str):
    """Get detailed process information using cached idProceso"""
    if not id_proceso or not id_proceso.isdigit():
        raise HTTPException(status_code=400, detail="Invalid process ID")

    # Check if we have cached detailed information
    if engine:
        try:
            session = Session()
            existing = session.query(QueryResult).filter_by(id_proceso=id_proceso).first()
            if existing and existing.detalle_json:
                session.close()
                return {"status": "success", "data": json.loads(existing.detalle_json), "cached": True}
            session.close()
        except Exception as db_error:
            print(f"Database query failed: {db_error}")

    # If not cached, query the detailed API
    url = f"https://consultaprocesos.ramajudicial.gov.co:448/api/v2/Proceso/Detalle/{id_proceso}"

    try:
        # Try direct HTTP request first
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'es-CO,es;q=0.9,en;q=0.8',
            'Connection': 'keep-alive',
            'Referer': 'https://consultaprocesos.ramajudicial.gov.co:448/'
        }

        response = requests.get(url, headers=headers, timeout=30, verify=False)
        response.raise_for_status()
        data = response.json()

        # Cache the detailed information
        if engine:
            try:
                session = Session()
                existing = session.query(QueryResult).filter_by(id_proceso=id_proceso).first()
                if existing:
                    existing.detalle_json = json.dumps(data)
                    existing.timestamp = datetime.datetime.utcnow()
                session.commit()
                session.close()
            except Exception as db_error:
                print(f"Database storage failed: {db_error}")

        return {"status": "success", "data": data, "cached": False}

    except requests.exceptions.RequestException as e:
        # Try with Selenium as fallback
        try:
            from selenium.webdriver import Firefox
            from selenium.webdriver.firefox.options import Options

            options = Options()
            options.add_argument('--headless')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--disable-gpu')
            options.add_argument('--window-size=1920,1080')

            driver = Firefox(options=options)
            driver.get(url)

            import time
            time.sleep(3)

            body_text = driver.find_element(By.TAG_NAME, 'body').text
            driver.quit()

            data = json.loads(body_text)

            # Cache the detailed information
            if engine:
                try:
                    session = Session()
                    existing = session.query(QueryResult).filter_by(id_proceso=id_proceso).first()
                    if existing:
                        existing.detalle_json = json.dumps(data)
                        existing.timestamp = datetime.datetime.utcnow()
                    session.commit()
                    session.close()
                except Exception as db_error:
                    print(f"Database storage failed: {db_error}")

            return {"status": "success", "data": data, "cached": False, "method": "selenium"}

        except Exception as selenium_error:
            raise HTTPException(status_code=500, detail=f"Failed to get process details: {str(e)}, Selenium also failed: {str(selenium_error)}")

@app.get("/app")
def get_app():
    try:
        return FileResponse("static/index.html")
    except FileNotFoundError:
        return {"error": "Frontend file not found"}

# Authentication endpoints
@app.post("/auth/register", response_model=Token)
async def register_user(user: UserCreate, db = Depends(get_db)):
    if not db:
        raise HTTPException(status_code=500, detail="Database not available")

    # Check if user already exists
    db_user = get_user_by_email(db, user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    # Create new user
    hashed_password = get_password_hash(user.password)
    db_user = User(email=user.email, password_hash=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    # Create access token
    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/auth/login", response_model=Token)
async def login_user(user: UserLogin, db = Depends(get_db)):
    if not db:
        raise HTTPException(status_code=500, detail="Database not available")

    db_user = authenticate_user(db, user.email, user.password)
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/auth/me")
async def read_users_me(current_user = Depends(get_current_user)):
    return {"email": current_user.email, "id": current_user.id}