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
from selenium.webdriver import Edge
from selenium.webdriver.edge.options import Options
from selenium.webdriver.edge.service import Service
from selenium.webdriver.common.by import By

Base = declarative_base()
import os
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Decide database URL from environment (Railway provides DATABASE_URL for Postgres)
DB_URL = os.getenv('DATABASE_URL')

def make_engine_from_url(db_url: str):
    """Create SQLAlchemy engine with sensible defaults depending on DB type."""
    if db_url.startswith('postgresql'):
        # production (Railway) - use a small pool
        return create_engine(db_url, echo=True, pool_size=5, max_overflow=10)
    else:
        # sqlite or other - default creation
        return create_engine(db_url, echo=True)

# If DATABASE_URL is set (in Railway), use it; otherwise use local SQLite file
if DB_URL:
    try:
        engine = make_engine_from_url(DB_URL)
        logger.info(f"Using DATABASE_URL from environment: {DB_URL}")
    except Exception as e:
        logger.error(f"Failed to create engine from DATABASE_URL: {e}. Falling back to in-memory SQLite.")
        engine = create_engine('sqlite:///:memory:', echo=True)
else:
    # Local/development: use a file-based SQLite database in ./data/results.db
    db_file = os.path.join('data', 'results.db')
    os.makedirs(os.path.dirname(os.path.abspath(db_file)), exist_ok=True)
    try:
        engine = create_engine(f"sqlite:///{db_file}", echo=True)
        logger.info(f"Using local SQLite DB at {db_file}")
    except Exception as e:
        logger.error(f"Failed to create local SQLite engine: {e}. Falling back to in-memory SQLite.")
        engine = create_engine('sqlite:///:memory:', echo=True)

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
    try:
        service = Service('msedgedriver.exe')
        options = Options()
        options.add_argument('--headless')
        driver = Edge(service=service, options=options)
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
    allow_origins=["http://localhost:3000", "http://127.0.0.1:8001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    with open("static/index.html", "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)

@app.get("/query/{numero}")
def query_api(numero: str):
    if len(numero) != 23 or not numero.isdigit():
        raise HTTPException(status_code=400, detail="Invalid 23-digit number")
    
    url = f"https://consultaprocesos.ramajudicial.gov.co:448/api/v2/Procesos/Consulta/NumeroRadicacion?numero={numero}&SoloActivos=false&pagina=1"
    try:
        service = Service('msedgedriver.exe')
        options = Options()
        options.add_argument('--headless')
        driver = Edge(service=service, options=options)
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
        return {"status": "success", "data": data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"API request failed: {str(e)}")

@app.post("/set_numero/{numero}")
def set_numero(numero: str):
    if len(numero) != 23 or not numero.isdigit():
        raise HTTPException(status_code=400, detail="Invalid 23-digit number")
    global stored_numero
    stored_numero = numero
    return {"status": "numero set"}

@app.get("/app")
def get_app():
    return FileResponse("static/index.html")