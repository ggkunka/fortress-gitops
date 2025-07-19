#!/bin/bash

# Simple build script for MCP Security Platform images
set -e

REGISTRY="ghcr.io"
USERNAME="ggkunka"
PREFIX="mcp"

# Create basic requirements.txt
cat > /tmp/basic-requirements.txt << 'EOF'
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
cat > /tmp/basic-main.py << 'EOF'
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

# Create basic Dockerfile
cat > /tmp/basic-dockerfile << 'EOF'
FROM python:3.11-slim

# Install basic dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r appuser && useradd -r -g appuser appuser

# Set working directory
WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app
COPY main.py .

# Set ownership
RUN chown -R appuser:appuser /app
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

EXPOSE 8080
CMD ["python", "main.py"]
EOF

# Build core services
declare -a CORE_SERVICES=(
    "correlation-engine"
    "risk-assessment" 
    "response-orchestrator"
    "reporting-service"
)

echo "Building core MCP services..."

for service in "${CORE_SERVICES[@]}"; do
    echo "Building $service..."
    
    # Create temp build context
    BUILD_DIR="/tmp/build-$service"
    rm -rf "$BUILD_DIR"
    mkdir -p "$BUILD_DIR"
    
    # Copy files to build context
    cp /tmp/basic-requirements.txt "$BUILD_DIR/requirements.txt"
    cp /tmp/basic-main.py "$BUILD_DIR/main.py"
    cp /tmp/basic-dockerfile "$BUILD_DIR/Dockerfile"
    
    # Build image
    buildah build \
        --format docker \
        --file "$BUILD_DIR/Dockerfile" \
        --tag "${REGISTRY}/${USERNAME}/${PREFIX}-${service}:latest" \
        "$BUILD_DIR"
    
    # Push image
    buildah push "${REGISTRY}/${USERNAME}/${PREFIX}-${service}:latest"
    
    echo "✅ Successfully built and pushed: $service"
    
    # Clean up
    rm -rf "$BUILD_DIR"
done

echo "🎉 Core services built and pushed successfully!"
EOF