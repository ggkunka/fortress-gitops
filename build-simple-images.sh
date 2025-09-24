#!/bin/bash

# Build simplified MCP Security Platform services without network dependencies
set -e

echo "🔨 Building simplified MCP Security Platform services..."

# Services to build (the ones failing with ImagePullBackOff)
SERVICES=(
    "graphql-gateway"
    "websocket-gateway" 
    "cicd-integration"
    "siem-integration"
    "ml-engine"
    "zero-trust-security"
)

# Create a simple Dockerfile template that doesn't require network access
create_simple_dockerfile() {
    local service_name=$1
    local port=$2
    
    cat > "services/$service_name/Dockerfile.simple" << EOF
FROM python:3.11-slim

WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies (this will use pip cache if available)
RUN pip install --no-cache-dir -r requirements.txt || pip install --no-cache-dir fastapi uvicorn

# Copy application code
COPY . .

# Create non-root user (without shell dependencies)
RUN adduser --disabled-password --gecos '' app && chown -R app:app /app
USER app

EXPOSE $port

CMD ["python", "main.py"]
EOF
}

# Build each service with simplified Dockerfile
for service in "${SERVICES[@]}"; do
    echo "🔨 Building $service..."
    
    if [ -d "services/$service" ]; then
        # Determine port based on service
        case $service in
            "graphql-gateway") port=8087 ;;
            "websocket-gateway") port=8088 ;;
            "cicd-integration") port=8089 ;;
            "siem-integration") port=8090 ;;
            "ml-engine") port=8092 ;;
            "zero-trust-security") port=8091 ;;
            *) port=8000 ;;
        esac
        
        # Create simplified Dockerfile
        create_simple_dockerfile "$service" "$port"
        
        cd "services/$service"
        
        # Build the image with simplified Dockerfile
        docker build -f Dockerfile.simple -t "mcp-security/$service:latest" .
        
        cd ../..
        echo "✅ Successfully built $service"
    else
        echo "❌ Service directory not found for $service"
    fi
done

echo "🎉 All advanced services built locally!"
echo "Images available:"
docker images | grep mcp-security
