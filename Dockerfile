FROM python:3.9-slim

# Install system dependencies for Firefox and PostgreSQL
RUN apt-get update && apt-get install -y \
    firefox-esr \
    wget \
    xvfb \
    && rm -rf /var/lib/apt/lists/*

# Set up virtual display for headless Firefox
ENV DISPLAY=:99

WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend code
COPY backend/ backend/

# Expose port
EXPOSE 8000

# Command to run the application with virtual display
CMD Xvfb :99 -screen 0 1024x768x24 > /dev/null 2>&1 & cd backend && uvicorn main:app --host 0.0.0.0 --port 8000