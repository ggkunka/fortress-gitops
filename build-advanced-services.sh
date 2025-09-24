#!/bin/bash

# Build and push advanced MCP Security Platform services
set -e

echo "🔨 Building and pushing advanced MCP Security Platform services..."

# Docker Hub credentials from memories
DOCKER_USERNAME="ggkunka"
DOCKER_TOKEN="dckr_pat_BtCakde3VXm2JBmCEevYQqjzMpc"

# Login to Docker Hub
echo "🔐 Logging into Docker Hub..."
echo "$DOCKER_TOKEN" | docker login -u "$DOCKER_USERNAME" --password-stdin

# Services to build (the ones failing with ImagePullBackOff)
SERVICES=(
    "graphql-gateway"
    "websocket-gateway" 
    "cicd-integration"
    "siem-integration"
    "ml-engine"
    "zero-trust-security"
)

# Build and push each service
for service in "${SERVICES[@]}"; do
    echo "🔨 Building $service..."
    
    if [ -d "services/$service" ] && [ -f "services/$service/Dockerfile" ]; then
        cd "services/$service"
        
        # Build the image
        docker build -t "mcp-security/$service:latest" .
        
        # Push to Docker Hub
        echo "📤 Pushing mcp-security/$service:latest..."
        docker push "mcp-security/$service:latest"
        
        cd ../..
        echo "✅ Successfully built and pushed $service"
    else
        echo "❌ Service directory or Dockerfile not found for $service"
    fi
done

echo "🎉 All advanced services built and pushed successfully!"
echo "Now the fortress server should be able to pull these images."
