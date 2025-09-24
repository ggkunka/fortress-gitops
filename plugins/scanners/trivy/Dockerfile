# Multi-stage build for Trivy Plugin
FROM python:3.11-slim as python-builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Trivy binary stage
FROM aquasec/trivy:latest as trivy-binary

# Production stage
FROM python:3.11-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r appuser && useradd -r -g appuser appuser

# Copy Python virtual environment
COPY --from=python-builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy Trivy binary
COPY --from=trivy-binary /usr/local/bin/trivy /usr/local/bin/trivy

# Set working directory
WORKDIR /app

# Copy application code
COPY . .

# Copy shared libraries
COPY ../../../shared /app/shared
RUN pip install -e /app/shared

# Create cache directory
RUN mkdir -p /app/cache && chown -R appuser:appuser /app
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Expose port
EXPOSE 8080

# Default command
CMD ["python", "trivy_plugin.py"]