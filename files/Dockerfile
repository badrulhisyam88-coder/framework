FROM python:3.12-slim

# Install system dependencies including nmap for validation
RUN apt-get update && apt-get install -y \
    nmap \
    curl \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency definition first for layer caching
COPY pyproject.toml .

# Install Python dependencies (runtime only, not dev)
RUN pip install --no-cache-dir -e .

# Copy application code
COPY core/ ./core/
COPY sdk/ ./sdk/
COPY apps/ ./apps/
COPY frontend/ ./frontend/

# Create non-root user
RUN useradd --no-create-home --shell /bin/false appuser

# Data directory for SQLite — must be writable by appuser
RUN mkdir -p /app/data && chown appuser:appuser /app/data

# Config directory — read-only at runtime
COPY config/ ./config/

RUN chown -R appuser:appuser /app
USER appuser

# Production: uvicorn without reload
CMD ["uvicorn", "core.main:app", "--host", "0.0.0.0", "--port", "8000"]
