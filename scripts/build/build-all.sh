#!/bin/bash

# Build script for all MCP Security Platform services
# Uses Buildah for container image building with Rocky Linux 9 base

set -euo pipefail

# Configuration
PROJECT_NAME="mcp-security-platform"
REGISTRY="${REGISTRY:-ghcr.io}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
VCS_REF="${GITHUB_SHA:-$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')}"
VERSION="${VERSION:-0.1.0}"
PYTHON_VERSION="3.11"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Services to build
SERVICES=(
    "auth"
    "gateway"
    "scanner-manager"
    "vulnerability-analyzer"
    "report-generator"
    "notification"
)

# Functions
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
}

success() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] SUCCESS: $1${NC}"
}

check_requirements() {
    log "Checking build requirements..."
    
    # Check if buildah is available
    if ! command -v buildah &> /dev/null; then
        error "buildah is not installed. Please install buildah to continue."
        exit 1
    fi
    
    # Check if we're in the project root
    if [[ ! -f "requirements.txt" ]] || [[ ! -d "services" ]]; then
        error "Script must be run from the project root directory"
        exit 1
    fi
    
    success "Build requirements check passed"
}

build_base_image() {
    log "Building base image..."
    
    local image_name="${REGISTRY}/${PROJECT_NAME}-base:${IMAGE_TAG}"
    
    buildah build \
        --format=docker \
        --tag="${image_name}" \
        --build-arg="PYTHON_VERSION=${PYTHON_VERSION}" \
        --build-arg="BUILD_DATE=${BUILD_DATE}" \
        --build-arg="VCS_REF=${VCS_REF}" \
        --build-arg="VERSION=${VERSION}" \
        --file="deployments/docker/Containerfile.base" \
        .
    
    success "Base image built: ${image_name}"
}

build_service_image() {
    local service=$1
    local image_name="${REGISTRY}/${PROJECT_NAME}-${service}:${IMAGE_TAG}"
    
    log "Building ${service} service image..."
    
    # Check if Containerfile exists
    local containerfile="deployments/docker/Containerfile.${service}"
    if [[ ! -f "${containerfile}" ]]; then
        error "Containerfile not found: ${containerfile}"
        return 1
    fi
    
    # Build the image
    buildah build \
        --format=docker \
        --tag="${image_name}" \
        --build-arg="SERVICE=${service}" \
        --build-arg="VERSION=${VERSION}" \
        --build-arg="COMMIT_SHA=${VCS_REF}" \
        --build-arg="BUILD_DATE=${BUILD_DATE}" \
        --build-arg="VCS_REF=${VCS_REF}" \
        --build-arg="PYTHON_VERSION=${PYTHON_VERSION}" \
        --file="${containerfile}" \
        .
    
    success "${service} service image built: ${image_name}"
}

scan_image() {
    local image_name=$1
    local service=$2
    
    log "Scanning ${service} image for vulnerabilities..."
    
    # Check if trivy is available
    if command -v trivy &> /dev/null; then
        trivy image --exit-code 0 --severity HIGH,CRITICAL "${image_name}" || {
            warn "Vulnerability scan found issues in ${service} image"
        }
    else
        warn "Trivy not available, skipping vulnerability scan"
    fi
}

push_image() {
    local image_name=$1
    local service=$2
    
    if [[ "${PUSH_IMAGES:-false}" == "true" ]]; then
        log "Pushing ${service} image to registry..."
        buildah push "${image_name}"
        success "${service} image pushed: ${image_name}"
    else
        log "Skipping image push (PUSH_IMAGES not set to true)"
    fi
}

build_all_services() {
    log "Building all service images..."
    
    # Build base image first
    build_base_image
    
    # Build each service
    for service in "${SERVICES[@]}"; do
        build_service_image "${service}"
        
        # Scan image for vulnerabilities
        scan_image "${REGISTRY}/${PROJECT_NAME}-${service}:${IMAGE_TAG}" "${service}"
        
        # Push image if requested
        push_image "${REGISTRY}/${PROJECT_NAME}-${service}:${IMAGE_TAG}" "${service}"
    done
    
    success "All service images built successfully"
}

cleanup() {
    log "Cleaning up build artifacts..."
    
    # Remove intermediate containers
    buildah rm --all || true
    
    # Prune unused images if requested
    if [[ "${CLEANUP_IMAGES:-false}" == "true" ]]; then
        buildah rmi --prune || true
    fi
    
    success "Cleanup completed"
}

print_summary() {
    echo ""
    echo "================================================"
    echo "           BUILD SUMMARY"
    echo "================================================"
    echo "Project: ${PROJECT_NAME}"
    echo "Version: ${VERSION}"
    echo "Tag: ${IMAGE_TAG}"
    echo "Registry: ${REGISTRY}"
    echo "Build Date: ${BUILD_DATE}"
    echo "VCS Ref: ${VCS_REF}"
    echo ""
    echo "Built Images:"
    echo "  - ${REGISTRY}/${PROJECT_NAME}-base:${IMAGE_TAG}"
    for service in "${SERVICES[@]}"; do
        echo "  - ${REGISTRY}/${PROJECT_NAME}-${service}:${IMAGE_TAG}"
    done
    echo "================================================"
}

# Main execution
main() {
    log "Starting build process for MCP Security Platform"
    
    # Check requirements
    check_requirements
    
    # Build all services
    build_all_services
    
    # Cleanup
    cleanup
    
    # Print summary
    print_summary
    
    success "Build process completed successfully"
}

# Handle script arguments
case "${1:-all}" in
    "all")
        main
        ;;
    "base")
        check_requirements
        build_base_image
        ;;
    "auth"|"gateway"|"scanner-manager"|"vulnerability-analyzer"|"report-generator"|"notification")
        check_requirements
        build_service_image "$1"
        ;;
    "clean")
        cleanup
        ;;
    "help"|"-h"|"--help")
        echo "Usage: $0 [all|base|SERVICE_NAME|clean|help]"
        echo ""
        echo "Options:"
        echo "  all                    Build all services (default)"
        echo "  base                   Build base image only"
        echo "  SERVICE_NAME           Build specific service"
        echo "  clean                  Clean up build artifacts"
        echo "  help                   Show this help message"
        echo ""
        echo "Available services:"
        for service in "${SERVICES[@]}"; do
            echo "  - ${service}"
        done
        echo ""
        echo "Environment variables:"
        echo "  REGISTRY               Container registry (default: ghcr.io)"
        echo "  IMAGE_TAG              Image tag (default: latest)"
        echo "  VERSION                Application version (default: 0.1.0)"
        echo "  PUSH_IMAGES            Push images to registry (default: false)"
        echo "  CLEANUP_IMAGES         Clean up unused images (default: false)"
        ;;
    *)
        error "Unknown option: $1"
        echo "Run '$0 help' for usage information"
        exit 1
        ;;
esac