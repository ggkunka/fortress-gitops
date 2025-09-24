FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir \
    fastapi==0.104.1 \
    uvicorn[standard]==0.24.0 \
    structlog==23.2.0

# Copy application code
COPY main.py .

# Create non-root user
RUN useradd -r -s /bin/false appuser
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8083/health/live || exit 1

EXPOSE 8083

CMD ["python", "main.py"]
