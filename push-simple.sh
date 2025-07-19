#!/bin/bash

# Push all built MCP Security Platform images to ghcr.io
set -e

USERNAME="ggkunka"
PREFIX="mcp"

echo "Pushing all built MCP Security Platform images to ghcr.io..."
echo ""

# Get all built images (simpler approach)
IMAGES=$(buildah images | grep "ghcr.io/${USERNAME}/${PREFIX}-" | awk '{print $1":"$2}')

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