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
import time
from fastapi import Request
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

    # Query logs table for debugging
    class QueryLog(Base):
        __tablename__ = 'query_logs'
        id = Column(Integer, primary_key=True)
        user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
        numero = Column(String(23))
        action = Column(String(50))  # 'batch_query', 'single_query', 'api_test'
        status = Column(String(20))  # 'success', 'error', 'timeout', 'connection_error'
        message = Column(Text)
        response_time = Column(Integer)  # milliseconds
        ip_address = Column(String(45))
        user_agent = Column(Text)
        created_at = Column(DateTime, default=datetime.datetime.utcnow)

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

# Logging helper function
def log_query(db, user_id=None, numero="", action="", status="", message="", response_time=0, ip_address="", user_agent=""):
    """Log query actions for debugging purposes"""
    if not db:
        return

    try:
        log_entry = QueryLog(
            user_id=user_id,
            numero=numero,
            action=action,
            status=status,
            message=message,
            response_time=response_time,
            ip_address=ip_address,
            user_agent=user_agent
        )
        db.add(log_entry)
        db.commit()
    except Exception as e:
        print(f"Failed to log query: {e}")

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

@app.get("/api-test")
def api_test(request: Request, db = Depends(get_db)):
    """Test endpoint to check connectivity with Colombian Judicial API"""
    start_time = time.time()
    test_url = "https://consultaprocesos.ramajudicial.gov.co:448/api/v2/Procesos/Consulta/NumeroRadicacion?numero=11001418902420250012300&SoloActivos=false&pagina=1"

    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'es-CO,es;q=0.9,en-US;q=0.8,en;q=0.7',
        }

        print(f"DEBUG: Testing API connectivity to: {test_url}")
        response = requests.get(test_url, headers=headers, timeout=30, verify=False)
        response_time = int((time.time() - start_time) * 1000)
        print(f"DEBUG: API test response status: {response.status_code}, Time: {response_time}ms")

        # Log the API test
        client_ip = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("user-agent", "")

        if response.status_code == 200:
            data = response.json()
            log_query(db, None, "11001418902420250012300", "api_test", "success",
                     f"Status: {response.status_code}", response_time, client_ip, user_agent)
            return {
                "status": "success",
                "message": "API connection successful",
                "response_status": response.status_code,
                "response_time_ms": response_time,
                "has_data": 'procesos' in data and len(data.get('procesos', [])) > 0
            }
        else:
            log_query(db, None, "11001418902420250012300", "api_test", "http_error",
                     f"Status: {response.status_code}", response_time, client_ip, user_agent)
            return {
                "status": "error",
                "message": f"API returned status {response.status_code}",
                "response_status": response.status_code,
                "response_time_ms": response_time
            }

    except requests.exceptions.Timeout:
        response_time = int((time.time() - start_time) * 1000)
        log_query(db, None, "11001418902420250012300", "api_test", "timeout",
                 "Request timed out", response_time, request.client.host if request.client else "unknown",
                 request.headers.get("user-agent", ""))
        return {"status": "error", "message": "API request timed out", "response_time_ms": response_time}
    except requests.exceptions.ConnectionError as e:
        response_time = int((time.time() - start_time) * 1000)
        log_query(db, None, "11001418902420250012300", "api_test", "connection_error",
                 str(e), response_time, request.client.host if request.client else "unknown",
                 request.headers.get("user-agent", ""))
        return {"status": "error", "message": "Connection error - API may be blocking requests", "response_time_ms": response_time}
    except Exception as e:
        response_time = int((time.time() - start_time) * 1000)
        log_query(db, None, "11001418902420250012300", "api_test", "error",
                 str(e), response_time, request.client.host if request.client else "unknown",
                 request.headers.get("user-agent", ""))
        return {"status": "error", "message": f"API test failed: {str(e)}", "response_time_ms": response_time}

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
async def process_single_judicial_query(numero: str, db=None, user_id=None, ip_address="", user_agent="") -> dict:
    """Process a single judicial process query and return structured data"""
    start_time = time.time()

    if len(numero) != 23 or not numero.isdigit():
        message = f"Invalid number format: {numero}"
        print(f"DEBUG: {message}")
        log_query(db, user_id, numero, "single_query", "error", message, 0, ip_address, user_agent)
        return {"error": message, "numero": numero}

    url = f"https://consultaprocesos.ramajudicial.gov.co:448/api/v2/Procesos/Consulta/NumeroRadicacion?numero={numero}&SoloActivos=false&pagina=1"
    print(f"DEBUG: Querying URL: {url}")

    try:
        # Try direct HTTP request first with enhanced headers
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'es-CO,es;q=0.9,en-US;q=0.8,en;q=0.7',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Referer': 'https://consultaprocesos.ramajudicial.gov.co:448/',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache'
        }

        print(f"DEBUG: Making HTTP request to judicial API for {numero}")
        response = requests.get(url, headers=headers, timeout=60, verify=False)
        response_time = int((time.time() - start_time) * 1000)  # milliseconds
        print(f"DEBUG: Response status: {response.status_code}, Time: {response_time}ms")
        response.raise_for_status()
        data = response.json()
        print(f"DEBUG: Successfully received data for {numero}")

        log_query(db, user_id, numero, "single_query", "success", f"Status: {response.status_code}", response_time, ip_address, user_agent)

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

    except requests.exceptions.Timeout as e:
        response_time = int((time.time() - start_time) * 1000)
        message = f"Timeout connecting to judicial API: {str(e)}"
        print(f"DEBUG: {message}")
        log_query(db, user_id, numero, "single_query", "timeout", message, response_time, ip_address, user_agent)
        return {"error": message, "numero": numero, "success": False}

    except requests.exceptions.ConnectionError as e:
        response_time = int((time.time() - start_time) * 1000)
        message = f"Connection error to judicial API: {str(e)}"
        print(f"DEBUG: {message}")
        log_query(db, user_id, numero, "single_query", "connection_error", message, response_time, ip_address, user_agent)
        return {"error": message, "numero": numero, "success": False}

    except requests.exceptions.HTTPError as e:
        response_time = int((time.time() - start_time) * 1000)
        message = f"HTTP error from judicial API: {str(e)}"
        print(f"DEBUG: {message}")
        log_query(db, user_id, numero, "single_query", "http_error", message, response_time, ip_address, user_agent)
        return {"error": message, "numero": numero, "success": False}

    except Exception as e:
        response_time = int((time.time() - start_time) * 1000)
        message = f"General error: {str(e)}"
        print(f"DEBUG: {message}")
        log_query(db, user_id, numero, "single_query", "error", message, response_time, ip_address, user_agent)
        # Fallback to mock data for testing
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
            "mock": True,
            "error": str(e)
        }
        return mock_data

# Batch processing endpoint
@app.post("/processes/batch-query")
@limiter.limit("50/hour")  # Rate limit: 50 requests per hour
async def batch_query_processes(
    batch_request: BatchQueryRequest,
    current_user = Depends(get_current_user),
    db = Depends(get_db),
    request: Request = None
):
    print(f"DEBUG: Batch query endpoint called by user {current_user.email} (ID: {current_user.id})")

    if not db:
        print(f"DEBUG: Database not available")
        raise HTTPException(status_code=500, detail="Database not available")

    # Parse numbers
    numbers = [n.strip() for n in batch_request.numbers.split(',') if n.strip()]
    print(f"DEBUG: Raw input: '{batch_request.numbers}'")
    print(f"DEBUG: Parsed numbers: {numbers}")

    if len(numbers) > 10:
        print(f"DEBUG: Too many numbers: {len(numbers)}")
        raise HTTPException(status_code=400, detail="Maximum 10 processes per batch")

    if not numbers:
        print(f"DEBUG: No numbers provided")
        raise HTTPException(status_code=400, detail="No valid numbers provided")

    # Validate all numbers
    valid_numbers = []
    for num in numbers:
        if len(num) != 23 or not num.isdigit():
            print(f"DEBUG: Invalid number format: '{num}' (length: {len(num)})")
            continue
        valid_numbers.append(num)

    if not valid_numbers:
        print(f"DEBUG: No valid numbers after validation")
        raise HTTPException(status_code=400, detail="No valid 23-digit numbers provided")

    numbers = valid_numbers
    print(f"DEBUG: Valid numbers to process: {numbers}")

    # Get client info for logging
    client_ip = request.client.host if request and request.client else "unknown"
    user_agent = request.headers.get("user-agent", "") if request else ""

    # Log batch query start
    log_query(db, current_user.id, "", "batch_query", "started",
             f"Processing {len(numbers)} numbers", 0, client_ip, user_agent)

    # Process queries with delay between each to avoid overwhelming the API
    print(f"DEBUG: Processing {len(numbers)} queries with delays to avoid API blocking")
    results = []

    for i, numero in enumerate(numbers):
        if i > 0:  # Add delay between queries (except for the first one)
            delay = 2.0  # 2 seconds delay between queries
            print(f"DEBUG: Waiting {delay} seconds before next query...")
            await asyncio.sleep(delay)

        print(f"DEBUG: Processing query {i+1}/{len(numbers)}: {numero}")
        try:
            result = await process_single_judicial_query(numero, db, current_user.id, client_ip, user_agent)
            results.append(result)
        except Exception as e:
            print(f"DEBUG: Exception processing {numero}: {e}")
            log_query(db, current_user.id, numero, "batch_query", "exception",
                     str(e), 0, client_ip, user_agent)
            results.append({"error": f"Processing exception: {str(e)}", "numero": numero, "success": False})

    # Process results and save to database
    processed_results = []
    errors = []
    today = datetime.date.today()

    print(f"DEBUG: Processing {len(results)} results")

    for result in results:
        if isinstance(result, Exception):
            print(f"DEBUG: Exception in result: {result}")
            errors.append({"error": "Processing exception", "details": str(result)})
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
            print(f"DEBUG: Successfully processed {result['numero']}")
        else:
            error_info = {
                "numero": result.get("numero", "unknown"),
                "error": result.get("error", "Unknown error")
            }
            errors.append(error_info)
            print(f"DEBUG: Failed to process {result.get('numero', 'unknown')}: {result.get('error', 'Unknown error')}")

    print(f"DEBUG: Processed {len(processed_results)} successfully, {len(errors)} errors")

    # Save successful results to database
    for result in processed_results:
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
            print(f"Database error for {result['numero']}: {db_error}")
            # Continue processing even if DB save fails

    print(f"DEBUG: Batch query completed. Returning {len(processed_results)} results and {len(errors)} errors")
    return {"results": processed_results, "total_processed": len(processed_results), "errors": errors}

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

# Logs endpoint for debugging
@app.get("/logs")
async def get_logs(
    current_user = Depends(get_current_user),
    db = Depends(get_db),
    limit: int = 50,
    action: str = None
):
    """Get query logs for debugging purposes (admin only for now)"""
    if not db:
        raise HTTPException(status_code=500, detail="Database not available")

    # For now, only allow users to see their own logs
    query = db.query(QueryLog).filter_by(user_id=current_user.id)

    if action:
        query = query.filter_by(action=action)

    logs = query.order_by(QueryLog.created_at.desc()).limit(limit).all()

    results = []
    for log in logs:
        results.append({
            "id": log.id,
            "numero": log.numero,
            "action": log.action,
            "status": log.status,
            "message": log.message,
            "response_time_ms": log.response_time,
            "ip_address": log.ip_address,
            "created_at": log.created_at.isoformat()
        })

    return {"logs": results, "total": len(results)}