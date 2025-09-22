FROM python:3.9-slim

# Install system dependencies for Firefox and PostgreSQL
RUN apt-get update && apt-get install -y \
    firefox-esr \
    wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend code
COPY backend/ backend/

# Expose port
EXPOSE 8000

# Command to run the application
CMD cd backend && uvicorn main:app --host 0.0.0.0 --port 8000