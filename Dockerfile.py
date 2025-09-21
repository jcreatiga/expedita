FROM python:3.9-slim

# Instalar dependencias del sistema necesarias para SQLite
RUN apt-get update && apt-get install -y \
    sqlite3 \
    libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copiar archivos de requisitos y backend
COPY requirements.txt .
COPY backend/ backend/

# Instalar dependencias de Python
RUN pip install --no-cache-dir -r requirements.txt

# Exponer puerto
EXPOSE 8000

# Comando para ejecutar la aplicación
CMD cd backend && uvicorn main:app --host 0.0.0.0 --port $PORT
