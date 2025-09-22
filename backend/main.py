from fastapi import FastAPI, HTTPException
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import datetime
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from selenium.webdriver.common.by import By
import os
import json
import requests

Base = declarative_base()

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

    class QueryResult(Base):
        __tablename__ = 'results'
        id = Column(Integer, primary_key=True)
        numero = Column(String(23), unique=True)  # Make numero unique for caching
        id_proceso = Column(String(20))  # Store the process ID for detailed queries
        response_json = Column(Text)
        detalle_json = Column(Text)  # Store detailed process information
        timestamp = Column(DateTime, default=datetime.datetime.utcnow)

    Base.metadata.create_all(engine)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for testing
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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