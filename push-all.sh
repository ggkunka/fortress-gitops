#!/bin/bash

# Push all built MCP Security Platform images to ghcr.io
set -e

USERNAME="ggkunka"
PREFIX="mcp"

echo "Pushing all built MCP Security Platform images to ghcr.io..."
echo ""

# Get all built images
IMAGES=$(buildah images --format "{{.Repository}}:{{.Tag}}" | grep "ghcr.io/${USERNAME}/${PREFIX}-" | sort -u)

for image in $IMAGES; do
    echo "Pushing: $image"
    buildah push "$image"
    echo "✅ Successfully pushed: $image"
    echo ""
done

echo "🎉 All built images pushed successfully to ghcr.io!"
echo ""
echo "Available images:"
for image in $IMAGES; do
    echo "  - $image"
done
EOF