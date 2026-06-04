FROM python:3.12-slim

# Install system dependencies including nmap for validation engines
# libglib2.0-0 + libpango* + libharfbuzz0b + libfontconfig1 are required by weasyprint
RUN apt-get update && apt-get install -y \
    nmap \
    curl \
    unzip \
    libpcap-dev \
    libglib2.0-0 \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libharfbuzz0b \
    libfontconfig1 \
    fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install nuclei v3.3.5 (v3 required — v2 -json flag removed; adapter uses -jsonl-export)
RUN curl -sSL https://github.com/projectdiscovery/nuclei/releases/download/v3.3.5/nuclei_3.3.5_linux_amd64.zip \
        -o /tmp/nuclei.zip \
    && unzip /tmp/nuclei.zip nuclei -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip \
    && nuclei -version

# Copy dependency definition first for layer caching
COPY pyproject.toml .

# Install Python dependencies (runtime only, not dev)
RUN pip install --no-cache-dir -e .

# Copy application code
COPY core/ ./core/
COPY sdk/ ./sdk/
COPY apps/ ./apps/
COPY frontend/ ./frontend/

# Config directory — read-only at runtime
COPY config/ ./config/

# Create non-root user with home directory (nuclei stores templates under ~/)
RUN useradd --create-home --shell /bin/sh appuser

# Data directory for SQLite — must be writable by appuser
RUN mkdir -p /app/data && chown appuser:appuser /app/data

# Pre-fetch nuclei templates (best-effort; skipped silently if no internet at build time)
RUN HOME=/home/appuser nuclei -update-templates || true

RUN chown -R appuser:appuser /app /home/appuser
USER appuser

EXPOSE 8000

# Production: uvicorn without reload
CMD ["uvicorn", "core.main:app", "--host", "0.0.0.0", "--port", "8000"]
