FROM python:3.12-slim

WORKDIR /app

# Install system dependencies for YARA
RUN apt-get update && apt-get install -y --no-install-recommends \
    yara \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY agent/ ./agent/

# Create directories for volumes
RUN mkdir -p /var/ossec/logs/alerts /rules /data

EXPOSE 8000

CMD ["uvicorn", "agent.main:app", "--host", "0.0.0.0", "--port", "8000"]
