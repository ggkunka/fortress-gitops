#!/bin/bash
# Fortress Harbor Image Sync Script
set -e

HARBOR_REGISTRY="10.63.89.182:30500"
HARBOR_USER="admin" 
HARBOR_PASSWORD="Harbor12345"

echo "🏗️ Starting Fortress Harbor Image Sync"

# Login to Harbor
echo "$HARBOR_PASSWORD" | docker login $HARBOR_REGISTRY -u $HARBOR_USER --password-stdin

# Security Tool Images
IMAGES=(
    "aquasec/trivy:latest security/trivy:latest"
    "anchore/syft:latest security/syft:latest"
    "anchore/grype:latest security/grype:latest"
    "falcosecurity/falco-no-driver:latest security/falco:latest"
    "aquasec/kube-bench:latest security/kube-bench:latest"
    "aquasec/kube-hunter:latest security/kube-hunter:latest"
    "zricethezav/gitleaks:latest security/gitleaks:latest"
)

# Sync each image
for image_pair in "${IMAGES[@]}"; do
    SOURCE=$(echo $image_pair | cut -d' ' -f1)
    TARGET=$(echo $image_pair | cut -d' ' -f2)
    
    echo "🔄 Syncing: $SOURCE -> $TARGET"
    
    # Pull from Docker Hub
    docker pull $SOURCE
    
    # Tag for Harbor
    docker tag $SOURCE $HARBOR_REGISTRY/$TARGET
    
    # Push to Harbor
    docker push $HARBOR_REGISTRY/$TARGET
    
    # Cleanup
    docker rmi $SOURCE $HARBOR_REGISTRY/$TARGET
    
    echo "✅ Synced $SOURCE"
done

echo "🎯 Harbor sync completed!"
