#!/bin/bash

# Transfer Docker images to fortress server
set -e

echo "📦 Saving and transferring Docker images to fortress server..."

# Services that were built
SERVICES=(
    "graphql-gateway"
    "websocket-gateway" 
    "cicd-integration"
    "siem-integration"
    "ml-engine"
    "zero-trust-security"
)

# Create directory for image files
mkdir -p /tmp/mcp-images

# Save each image as tar file
for service in "${SERVICES[@]}"; do
    echo "💾 Saving mcp-security/$service:latest..."
    docker save "mcp-security/$service:latest" -o "/tmp/mcp-images/$service.tar"
done

# Create a script to load images on fortress
cat > /tmp/mcp-images/load-images.sh << 'EOF'
#!/bin/bash
echo "🔄 Loading MCP Security Platform images into K3s..."

SERVICES=(
    "graphql-gateway"
    "websocket-gateway" 
    "cicd-integration"
    "siem-integration"
    "ml-engine"
    "zero-trust-security"
)

for service in "${SERVICES[@]}"; do
    echo "📥 Loading $service..."
    k3s ctr images import "$service.tar"
    echo "✅ Loaded $service"
done

echo "🎉 All images loaded successfully!"
echo "Checking loaded images:"
k3s ctr images list | grep mcp-security
EOF

chmod +x /tmp/mcp-images/load-images.sh

# Transfer all files to fortress
echo "🚀 Transferring images to fortress server..."
scp -r /tmp/mcp-images/* fortadmin@10.63.89.182:/home/fortadmin/

echo "✅ Images transferred to fortress server!"
echo "Now run the following on fortress to load the images:"
echo "ssh fortadmin@10.63.89.182 'cd /home/fortadmin && ./load-images.sh'"
