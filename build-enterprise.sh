#!/bin/bash

# Build MCP Security Platform images with enterprise-grade Python base
set -e

REGISTRY="ghcr.io"
USERNAME="ggkunka"
PREFIX="mcp"

# Create basic requirements.txt
cat > /tmp/enterprise-requirements.txt << 'EOF'
fastapi==0.104.1
uvicorn[standard]==0.24.0
pydantic==2.5.0
httpx==0.25.2
redis==5.0.1
sqlalchemy==2.0.23
psycopg2-binary==2.9.9
prometheus-client==0.19.0
structlog==23.2.0
EOF

# Create basic main.py
cat > /tmp/enterprise-main.py << 'EOF'
#!/usr/bin/env python3
"""
MCP Security Platform Service
"""
import os
import uvicorn
from fastapi import FastAPI

app = FastAPI(
    title="MCP Security Platform Service",
    description="A component of the MCP Security Platform",
    version="1.0.0"
)

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "mcp-service"}

@app.get("/")
async def root():
    return {"message": "MCP Security Platform Service"}

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)
EOF

# Create enterprise Dockerfile with security hardening
cat > /tmp/enterprise-dockerfile << 'EOF'
# Multi-stage enterprise build
FROM python:3.11-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    curl \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.11-slim

# Install runtime dependencies and security hardening
RUN apt-get update && apt-get install -y \
    curl \
    libpq5 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r appuser && useradd -r -g appuser appuser \
    && mkdir -p /app /var/log/app \
    && chown -R appuser:appuser /app /var/log/app

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Set working directory
WORKDIR /app

# Copy application code
COPY main.py .

# Security hardening
RUN chown -R appuser:appuser /app
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Expose port
EXPOSE 8080

# Set environment variables for production
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Default command
CMD ["python", "main.py"]
EOF

# Build all services
declare -a ALL_SERVICES=(
    "correlation-engine"
    "risk-assessment"
    "response-orchestrator" 
    "reporting-service"
    "mongodb-service"
    "influxdb-service"
    "plugin-registry"
    "trivy-plugin"
    "syft-plugin"
    "grype-plugin"
    "github-plugin"
    "slack-plugin"
    "graphql-server"
    "websocket-server"
    "grpc-server"
)

echo "Building all MCP services with enterprise-grade configuration..."
echo ""

for service in "${ALL_SERVICES[@]}"; do
    echo "Building $service..."
    
    # Create temp build context
    BUILD_DIR="/tmp/enterprise-build-$service"
    rm -rf "$BUILD_DIR"
    mkdir -p "$BUILD_DIR"
    
    # Copy files to build context
    cp /tmp/enterprise-requirements.txt "$BUILD_DIR/requirements.txt"
    cp /tmp/enterprise-main.py "$BUILD_DIR/main.py"
    cp /tmp/enterprise-dockerfile "$BUILD_DIR/Dockerfile"
    
    # Build image
    buildah build \
        --format docker \
        --file "$BUILD_DIR/Dockerfile" \
        --tag "${REGISTRY}/${USERNAME}/${PREFIX}-${service}:latest" \
        --tag "${REGISTRY}/${USERNAME}/${PREFIX}-${service}:v1.0.0" \
        "$BUILD_DIR"
    
    echo "✅ Successfully built: $service"
    
    # Push both tags
    echo "Pushing $service to ghcr.io..."
    buildah push "${REGISTRY}/${USERNAME}/${PREFIX}-${service}:latest"
    buildah push "${REGISTRY}/${USERNAME}/${PREFIX}-${service}:v1.0.0"
    echo "✅ Successfully pushed: $service"
    echo ""
    
    # Clean up
    rm -rf "$BUILD_DIR"
done

echo ""
echo "🎉 All services built and pushed successfully!"
echo ""
echo "Available images on ghcr.io:"
for service in "${ALL_SERVICES[@]}"; do
    echo "  - ${REGISTRY}/${USERNAME}/${PREFIX}-${service}:latest"
    echo "  - ${REGISTRY}/${USERNAME}/${PREFIX}-${service}:v1.0.0"
done
EOF