#!/bin/bash

# Build MCP Security Platform images using Rocky Linux 9 minimal
set -e

REGISTRY="ghcr.io"
USERNAME="ggkunka"
PREFIX="mcp"

# Create basic requirements.txt
cat > /tmp/rocky-requirements.txt << 'EOF'
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
cat > /tmp/rocky-main.py << 'EOF'
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

# Create Rocky Linux 9 based Dockerfile
cat > /tmp/rocky-dockerfile << 'EOF'
# Multi-stage build using Rocky Linux 9 minimal
FROM rockylinux:9-minimal as builder

# Install Python and build dependencies
RUN microdnf update -y && \
    microdnf install -y \
        python3.11 \
        python3.11-pip \
        python3.11-devel \
        gcc \
        gcc-c++ \
        postgresql-devel \
    && microdnf clean all

# Create virtual environment
RUN python3.11 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Production stage
FROM rockylinux:9-minimal

# Install runtime dependencies
RUN microdnf update -y && \
    microdnf install -y \
        python3.11 \
        curl \
        postgresql \
        shadow-utils \
    && microdnf clean all \
    && groupadd -r appuser && useradd -r -g appuser appuser

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Set working directory
WORKDIR /app

# Copy application code
COPY main.py .

# Set ownership and permissions
RUN chown -R appuser:appuser /app
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Expose port
EXPOSE 8080

# Default command
CMD ["python3.11", "main.py"]
EOF

# Build all services with Rocky Linux base
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

echo "Building all MCP services with Rocky Linux 9 minimal..."
echo ""

for service in "${ALL_SERVICES[@]}"; do
    echo "Building $service with Rocky Linux 9..."
    
    # Create temp build context
    BUILD_DIR="/tmp/rocky-build-$service"
    rm -rf "$BUILD_DIR"
    mkdir -p "$BUILD_DIR"
    
    # Copy files to build context
    cp /tmp/rocky-requirements.txt "$BUILD_DIR/requirements.txt"
    cp /tmp/rocky-main.py "$BUILD_DIR/main.py"
    cp /tmp/rocky-dockerfile "$BUILD_DIR/Dockerfile"
    
    # Build image
    buildah build \
        --format docker \
        --file "$BUILD_DIR/Dockerfile" \
        --tag "${REGISTRY}/${USERNAME}/${PREFIX}-${service}:latest" \
        --tag "${REGISTRY}/${USERNAME}/${PREFIX}-${service}:rocky9" \
        "$BUILD_DIR"
    
    echo "✅ Successfully built: $service"
    
    # Clean up
    rm -rf "$BUILD_DIR"
done

echo ""
echo "🎉 All services built successfully with Rocky Linux 9!"
echo ""
echo "Built images:"
buildah images | grep "ghcr.io/ggkunka/mcp-"
EOF