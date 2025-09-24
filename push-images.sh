#!/bin/bash

# Push all MCP Security Platform images to ghcr.io
set -e

USERNAME="ggkunka"
PREFIX="mcp"

# Get list of built images
IMAGES=$(buildah images --format "{{.Repository}}:{{.Tag}}" | grep "ghcr.io/${USERNAME}/${PREFIX}-" | grep ":latest$")

echo "Pushing MCP Security Platform images to ghcr.io..."
echo ""

for image in $IMAGES; do
    echo "Pushing: $image"
    buildah push "$image"
    echo "✅ Successfully pushed: $image"
    echo ""
done

echo "🎉 All images pushed successfully to ghcr.io!"
echo ""
echo "Available images:"
for image in $IMAGES; do
    echo "- $image"
done