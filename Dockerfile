FROM python:3.12-slim

WORKDIR /app

# Install system dependencies for YARA
RUN apt-get update && apt-get install -y --no-install-recommends \
    yara \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install the sigma-cli Wazuh backend plugin.
# pysigma-backend-wazuh is not published on PyPI; the official mechanism
# is sigma-cli's plugin system.  The `sigma` binary comes from sigma-cli
# (already in requirements.txt); this step installs the Wazuh conversion
# backend into sigma-cli's plugin registry so `sigma convert -t wazuh`
# works.  If the plugin registry is unavailable at build time the image
# still builds — the startup probe (REQ-P0-P25-003) will detect the
# missing backend and set sigmac_available=False at runtime.
RUN sigma plugin install wazuh || true

COPY agent/ ./agent/

# Create directories for volumes
RUN mkdir -p /var/ossec/logs/alerts /rules /data

EXPOSE 8000

CMD ["uvicorn", "agent.main:app", "--host", "0.0.0.0", "--port", "8000"]
