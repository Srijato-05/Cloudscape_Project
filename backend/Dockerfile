# ==============================================================================
# CLOUDSCAPE CORE - BACKEND ORCHESTRATOR (PRODUCTION HARDENED)
# ==============================================================================
# Stage 1: Build & Dependency Resolution
FROM python:3.12-slim as builder

WORKDIR /build

# System Dependencies for Cryptography
RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# Stage 2: Runtime Environment
FROM python:3.12-slim

WORKDIR /app

# Forensic & Intelligence Metadata
LABEL version="5.2"
LABEL type="Orchestrator"
LABEL security="Hardened"

# Install Runtime-only dependencies
RUN apt-get update && apt-get install -y \
    curl \
    netcat-traditional \
    && rm -rf /var/lib/apt/lists/*

# Copy dependencies from builder
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

# Application Source
COPY . .

# Environment Defaults & Security Hardening
ENV PYTHONPATH=/app/src
ENV LOG_LEVEL=INFO
ENV PYTHONIOENCODING=utf-8
ENV PYTHONUNBUFFERED=1

# Healthcheck logic (Pre-flight validation)
HEALTHCHECK --interval=30s --timeout=15s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

ENTRYPOINT ["python", "main.py"]
