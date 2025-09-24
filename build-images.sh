#!/bin/bash

# Build and push all MCP Security Platform images to ghcr.io
set -e

REGISTRY="ghcr.io"
USERNAME="ggkunka"
PREFIX="mcp"

# List of services to build
declare -A SERVICES=(
    ["correlation-engine"]="services/core/correlation"
    ["risk-assessment"]="services/core/risk_assessment"
    ["response-orchestrator"]="services/core/response"
    ["reporting-service"]="services/core/reporting"
    ["mongodb-service"]="services/mongodb-service"
    ["influxdb-service"]="services/influxdb-service"
    ["plugin-registry"]="shared/plugins"
    ["trivy-plugin"]="plugins/scanners/trivy"
    ["syft-plugin"]="plugins/scanners/syft"
    ["grype-plugin"]="plugins/scanners/grype"
    ["github-plugin"]="plugins/integrations/github"
    ["slack-plugin"]="plugins/integrations/slack"
    ["graphql-server"]="services/api"
    ["websocket-server"]="services/api"
    ["grpc-server"]="services/api"
)

# Function to create a basic Dockerfile if it doesn't exist
create_dockerfile() {
    local service_path=$1
    local dockerfile_path="$service_path/Dockerfile"
    
    if [ ! -f "$dockerfile_path" ]; then
        echo "Creating Dockerfile for $service_path"
        cat > "$dockerfile_path" << 'EOF'
# Multi-stage build for Python service
FROM python:3.11-slim as builder

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
COPY requirements.txt* ./
RUN if [ -f requirements.txt ]; then pip install --no-cache-dir -r requirements.txt; fi

# Production stage
FROM python:3.11-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r appuser && useradd -r -g appuser appuser

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Set working directory
WORKDIR /app

# Copy application code
COPY . .

# Set ownership and permissions
RUN chown -R appuser:appuser /app
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Expose port
EXPOSE 8080

# Default command
CMD ["python", "main.py"]
EOF
    fi
}

# Function to create a basic main.py if it doesn't exist
create_main_py() {
    local service_path=$1
    local main_py_path="$service_path/main.py"
    
    if [ ! -f "$main_py_path" ]; then
        echo "Creating main.py for $service_path"
        cat > "$main_py_path" << 'EOF'
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
    fi
}

# Function to create basic requirements.txt if it doesn't exist
create_requirements() {
    local service_path=$1
    local req_path="$service_path/requirements.txt"
    
    if [ ! -f "$req_path" ]; then
        echo "Creating requirements.txt for $service_path"
        cat > "$req_path" << 'EOF'
fastapi==0.104.1
uvicorn[standard]==0.24.0
pydantic==2.5.0
httpx==0.25.2
redis==5.0.1
sqlalchemy==2.0.23
psycopg2-binary==2.9.9
prometheus-client==0.19.0
opentelemetry-api==1.21.0
opentelemetry-sdk==1.21.0
structlog==23.2.0
EOF
    fi
}

echo "Building and pushing MCP Security Platform images..."

for service in "${!SERVICES[@]}"; do
    context_path="${SERVICES[$service]}"
    image_name="${REGISTRY}/${USERNAME}/${PREFIX}-${service}"
    
    echo "Processing service: $service"
    echo "Context path: $context_path"
    echo "Image name: $image_name"
    
    # Create directory if it doesn't exist
    mkdir -p "$context_path"
    
    # Create required files
    create_requirements "$context_path"
    create_main_py "$context_path"
    create_dockerfile "$context_path"
    
    echo "Building image: $image_name"
    
    # Build with buildah
    buildah build \
        --format docker \
        --file "$context_path/Dockerfile" \
        --tag "$image_name:latest" \
        --tag "$image_name:$(date +%Y%m%d-%H%M%S)" \
        "$context_path"
    
    echo "Pushing image: $image_name"
    
    # Push latest tag
    buildah push "$image_name:latest"
    
    # Push timestamped tag
    buildah push "$image_name:$(date +%Y%m%d-%H%M%S)"
    
    echo "✅ Successfully built and pushed: $service"
    echo "---"
done

echo "🎉 All images built and pushed successfully!"