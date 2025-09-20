#!/bin/bash

# Build advanced MCP Security Platform services locally
set -e

echo "🔨 Building advanced MCP Security Platform services locally..."

# Services to build (the ones failing with ImagePullBackOff)
SERVICES=(
    "graphql-gateway"
    "websocket-gateway" 
    "cicd-integration"
    "siem-integration"
    "ml-engine"
    "zero-trust-security"
)

# Build each service
for service in "${SERVICES[@]}"; do
    echo "🔨 Building $service..."
    
    if [ -d "services/$service" ] && [ -f "services/$service/Dockerfile" ]; then
        cd "services/$service"
        
        # Build the image
        docker build -t "mcp-security/$service:latest" .
        
        cd ../..
        echo "✅ Successfully built $service"
    else
        echo "❌ Service directory or Dockerfile not found for $service"
    fi
done

echo "🎉 All advanced services built locally!"
echo "Images available:"
docker images | grep mcp-security
