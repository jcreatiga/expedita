from fastapi import FastAPI, HTTPException
import requests
import json
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import datetime
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.common.by import By

Base = declarative_base()
import os
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Railway will provide a DATABASE_URL for the managed Postgres instance.
DB_URL = os.getenv('DATABASE_URL')

# Detect whether the sqlite3 C-extension is importable in this runtime
try:
    import sqlite3  # type: ignore
    SQLITE_AVAILABLE = True
except Exception:
    SQLITE_AVAILABLE = False

def make_engine_from_url(db_url: str):
    """Create SQLAlchemy engine with sensible defaults depending on DB type."""
    if db_url.startswith('postgresql'):
        return create_engine(db_url, echo=True, pool_size=5, max_overflow=10)
    return create_engine(db_url, echo=True)

# Choose DB strategy:
# 1) If DATABASE_URL is set, use it (Postgres on Railway) - no fallback
# 2) Else if sqlite3 is available, use a local file SQLite (development)
# 3) Otherwise fail early with a clear error (ask user to set DATABASE_URL in Railway)
if DB_URL:
    try:
        engine = make_engine_from_url(DB_URL)
        logger.info("Using DATABASE_URL from environment")
    except Exception as e:
        logger.exception(f"Failed to create engine from DATABASE_URL: {e}")
        raise RuntimeError(
            f"Failed to connect to database using DATABASE_URL. "
            f"Error: {e}. "
            f"Please check your DATABASE_URL configuration in Railway."
        )
else:
    if SQLITE_AVAILABLE:
        db_file = os.path.join('data', 'results.db')
        os.makedirs(os.path.dirname(os.path.abspath(db_file)), exist_ok=True)
        try:
            engine = create_engine(f"sqlite:///{db_file}", echo=True)
            logger.info(f"Using local SQLite DB at {db_file}")
        except Exception as e:
            logger.exception(f"Failed to create local SQLite engine: {e}")
            raise
    else:
        # Runtime lacks sqlite shared library and no DATABASE_URL provided.
        # Fail with a clear error so the user can set DATABASE_URL in Railway.
        raise RuntimeError(
            "No usable database available: sqlite3 C-extension not present and DATABASE_URL not set. "
            "Set the Railway environment variable DATABASE_URL to your PostgreSQL connection string."
        )

Session = sessionmaker(bind=engine)

class QueryResult(Base):
    __tablename__ = 'results'
    id = Column(Integer, primary_key=True)
    numero = Column(String(23))
    response_json = Column(Text)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

Base.metadata.create_all(engine)

stored_numero = None

def query_and_store(numero: str):
    if len(numero) != 23 or not numero.isdigit():
        return  # or log error
    url = f"https://consultaprocesos.ramajudicial.gov.co:448/api/v2/Procesos/Consulta/NumeroRadicacion?numero={numero}&SoloActivos=false&pagina=1"

    # Try direct HTTP request first
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'es-CO,es;q=0.9,en;q=0.8',
            'Connection': 'keep-alive'
        }
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        data = response.json()

        # Store data
        session = Session()
        result = QueryResult(numero=numero, response_json=json.dumps(data))
        session.add(result)
        session.commit()
        session.close()
        return
    except Exception as e:
        pass  # Continue to Selenium fallback

    # Fallback to Selenium if direct request fails
    try:
        from selenium.webdriver import Firefox
        options = Options()
        options.add_argument('--headless')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        driver = Firefox(options=options)
        driver.get(url)
        body_text = driver.find_element(By.TAG_NAME, 'body').text
        data = json.loads(body_text)
        driver.quit()

        # Store data
        session = Session()
        result = QueryResult(numero=numero, response_json=json.dumps(data))
        session.add(result)
        session.commit()
        session.close()
    except Exception as e:
        pass  # log error

from apscheduler.schedulers.background import BackgroundScheduler

scheduler = BackgroundScheduler()
scheduler.add_job(func=lambda: query_and_store(stored_numero) if stored_numero else None, trigger="cron", hour=0)
scheduler.start()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:8001", "https://expedita-production.up.railway.app"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    with open("backend/static/index.html", "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)

@app.get("/test")
def test_endpoint():
    return {"status": "success", "message": "API is working!"}

@app.get("/query/{numero}")
def query_api(numero: str):
    if len(numero) != 23 or not numero.isdigit():
        raise HTTPException(status_code=400, detail="Invalid 23-digit number")

    # For now, return mock data to test the API structure
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

    # Store mock data
    try:
        session = Session()
        result = QueryResult(numero=numero, response_json=json.dumps(mock_data))
        session.add(result)
        session.commit()
        session.close()
    except Exception as db_error:
        raise HTTPException(status_code=500, detail=f"Database error: {str(db_error)}")

    return {"status": "success", "data": mock_data}

@app.post("/set_numero/{numero}")
def set_numero(numero: str):
    if len(numero) != 23 or not numero.isdigit():
        raise HTTPException(status_code=400, detail="Invalid 23-digit number")
    global stored_numero
    stored_numero = numero
    return {"status": "numero set"}

@app.get("/app")
def get_app():
    return FileResponse("backend/static/index.html")