from fastapi import FastAPI, HTTPException
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import datetime
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
import os
import json

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
        numero = Column(String(23))
        response_json = Column(Text)
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

    # Return mock data for testing
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

    # Store data if database is available
    if engine:
        try:
            session = Session()
            result = QueryResult(numero=numero, response_json=json.dumps(mock_data))
            session.add(result)
            session.commit()
            session.close()
        except Exception as db_error:
            print(f"Database storage failed: {db_error}")

    return {"status": "success", "data": mock_data}

@app.get("/app")
def get_app():
    try:
        return FileResponse("static/index.html")
    except FileNotFoundError:
        return {"error": "Frontend file not found"}