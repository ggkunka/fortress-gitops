#!/bin/bash

# Build script for a single MCP Security Platform service
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

usage() {
    echo "Usage: $0 <service_name> [options]"
    echo ""
    echo "Services:"
    echo "  auth                   Authentication service"
    echo "  gateway                API Gateway service"
    echo "  scanner-manager        Scanner Manager service"
    echo "  vulnerability-analyzer Vulnerability Analyzer service"
    echo "  report-generator       Report Generator service"
    echo "  notification           Notification service"
    echo ""
    echo "Options:"
    echo "  --push                 Push image to registry after build"
    echo "  --scan                 Scan image for vulnerabilities"
    echo "  --no-cache             Build without cache"
    echo "  --help                 Show this help message"
    echo ""
    echo "Environment variables:"
    echo "  REGISTRY               Container registry (default: ghcr.io)"
    echo "  IMAGE_TAG              Image tag (default: latest)"
    echo "  VERSION                Application version (default: 0.1.0)"
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

build_service_image() {
    local service=$1
    local no_cache=$2
    local image_name="${REGISTRY}/${PROJECT_NAME}-${service}:${IMAGE_TAG}"
    
    log "Building ${service} service image..."
    
    # Check if Containerfile exists
    local containerfile="deployments/docker/Containerfile.${service}"
    if [[ ! -f "${containerfile}" ]]; then
        error "Containerfile not found: ${containerfile}"
        return 1
    fi
    
    # Build arguments
    local build_args=(
        --format=docker
        --tag="${image_name}"
        --build-arg="SERVICE=${service}"
        --build-arg="VERSION=${VERSION}"
        --build-arg="COMMIT_SHA=${VCS_REF}"
        --build-arg="BUILD_DATE=${BUILD_DATE}"
        --build-arg="VCS_REF=${VCS_REF}"
        --build-arg="PYTHON_VERSION=${PYTHON_VERSION}"
        --file="${containerfile}"
    )
    
    # Add no-cache if requested
    if [[ "${no_cache}" == "true" ]]; then
        build_args+=(--no-cache)
    fi
    
    # Build the image
    buildah build "${build_args[@]}" .
    
    success "${service} service image built: ${image_name}"
    echo "${image_name}"
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
    
    log "Pushing ${service} image to registry..."
    buildah push "${image_name}"
    success "${service} image pushed: ${image_name}"
}

get_image_info() {
    local image_name=$1
    
    log "Image information:"
    buildah inspect "${image_name}" | jq -r '.Docker.Config.Labels // {}'
}

# Main execution
main() {
    local service=""
    local push_image_flag="false"
    local scan_image_flag="false"
    local no_cache="false"
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --push)
                push_image_flag="true"
                shift
                ;;
            --scan)
                scan_image_flag="true"
                shift
                ;;
            --no-cache)
                no_cache="true"
                shift
                ;;
            --help)
                usage
                exit 0
                ;;
            auth|gateway|scanner-manager|vulnerability-analyzer|report-generator|notification)
                service="$1"
                shift
                ;;
            *)
                error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
    
    # Validate service name
    if [[ -z "${service}" ]]; then
        error "Service name is required"
        usage
        exit 1
    fi
    
    log "Starting build process for ${service} service"
    
    # Check requirements
    check_requirements
    
    # Build service image
    local image_name
    image_name=$(build_service_image "${service}" "${no_cache}")
    
    # Scan image if requested
    if [[ "${scan_image_flag}" == "true" ]]; then
        scan_image "${image_name}" "${service}"
    fi
    
    # Push image if requested
    if [[ "${push_image_flag}" == "true" ]]; then
        push_image "${image_name}" "${service}"
    fi
    
    # Show image info
    get_image_info "${image_name}"
    
    success "Build process completed successfully for ${service}"
    echo ""
    echo "Built image: ${image_name}"
}

# Execute main function with all arguments
main "$@"