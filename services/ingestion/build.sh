#!/bin/bash

# Build script for MCP Security Platform - Ingestion Service
# This script builds the container image using Buildah

set -euo pipefail

# Configuration
REGISTRY="${REGISTRY:-quay.io}"
NAMESPACE="${NAMESPACE:-mcp-security}"
IMAGE_NAME="${IMAGE_NAME:-ingestion-service}"
VERSION="${VERSION:-latest}"
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GIT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Parse command line arguments
STAGE="production"
PUSH=false
SCAN=false
TEST=false
VERBOSE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --stage)
            STAGE="$2"
            shift 2
            ;;
        --push)
            PUSH=true
            shift
            ;;
        --scan)
            SCAN=true
            shift
            ;;
        --test)
            TEST=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  --stage STAGE     Build stage (development|production|testing|security-scan)"
            echo "  --push            Push image to registry"
            echo "  --scan            Run security scan"
            echo "  --test            Run tests"
            echo "  --verbose         Verbose output"
            echo "  --help            Show this help"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Validate stage
if [[ ! "$STAGE" =~ ^(development|production|testing|security-scan|build)$ ]]; then
    log_error "Invalid stage: $STAGE"
    exit 1
fi

# Build configuration
FULL_IMAGE_NAME="${REGISTRY}/${NAMESPACE}/${IMAGE_NAME}:${VERSION}"
BUILD_CONTEXT="."
CONTAINERFILE="Containerfile"

log_info "Starting build process..."
log_info "Image: ${FULL_IMAGE_NAME}"
log_info "Stage: ${STAGE}"
log_info "Build Date: ${BUILD_DATE}"
log_info "Git Commit: ${GIT_COMMIT}"
log_info "Git Branch: ${GIT_BRANCH}"

# Check if buildah is available
if ! command -v buildah &> /dev/null; then
    log_error "buildah is not installed or not in PATH"
    exit 1
fi

# Check if context directory exists
if [[ ! -d "$BUILD_CONTEXT" ]]; then
    log_error "Build context directory does not exist: $BUILD_CONTEXT"
    exit 1
fi

# Check if Containerfile exists
if [[ ! -f "$CONTAINERFILE" ]]; then
    log_error "Containerfile does not exist: $CONTAINERFILE"
    exit 1
fi

# Build arguments
BUILD_ARGS=(
    --build-arg "BUILD_DATE=${BUILD_DATE}"
    --build-arg "GIT_COMMIT=${GIT_COMMIT}"
    --build-arg "GIT_BRANCH=${GIT_BRANCH}"
    --build-arg "VERSION=${VERSION}"
)

# Verbose output
if [[ "$VERBOSE" == "true" ]]; then
    BUILD_ARGS+=(--log-level debug)
fi

# Build the image
log_info "Building image for stage: ${STAGE}"

if [[ "$STAGE" == "production" ]]; then
    # Multi-stage build for production
    buildah build \
        --file "$CONTAINERFILE" \
        --target final \
        --tag "${FULL_IMAGE_NAME}" \
        --tag "${REGISTRY}/${NAMESPACE}/${IMAGE_NAME}:${STAGE}" \
        "${BUILD_ARGS[@]}" \
        "$BUILD_CONTEXT"
else
    # Single stage build
    buildah build \
        --file "$CONTAINERFILE" \
        --target "$STAGE" \
        --tag "${FULL_IMAGE_NAME}-${STAGE}" \
        --tag "${REGISTRY}/${NAMESPACE}/${IMAGE_NAME}:${STAGE}" \
        "${BUILD_ARGS[@]}" \
        "$BUILD_CONTEXT"
fi

if [[ $? -eq 0 ]]; then
    log_success "Image built successfully"
else
    log_error "Image build failed"
    exit 1
fi

# Run tests if requested
if [[ "$TEST" == "true" ]]; then
    log_info "Running tests..."
    
    # Build test image
    buildah build \
        --file "$CONTAINERFILE" \
        --target testing \
        --tag "${REGISTRY}/${NAMESPACE}/${IMAGE_NAME}:test" \
        "${BUILD_ARGS[@]}" \
        "$BUILD_CONTEXT"
    
    # Run tests in container
    if buildah run "${REGISTRY}/${NAMESPACE}/${IMAGE_NAME}:test" python3 run_tests.py --full; then
        log_success "Tests passed"
    else
        log_error "Tests failed"
        exit 1
    fi
fi

# Run security scan if requested
if [[ "$SCAN" == "true" ]]; then
    log_info "Running security scan..."
    
    # Build security scan image
    buildah build \
        --file "$CONTAINERFILE" \
        --target security-scan \
        --tag "${REGISTRY}/${NAMESPACE}/${IMAGE_NAME}:security-scan" \
        "${BUILD_ARGS[@]}" \
        "$BUILD_CONTEXT"
    
    # Run security scan
    if buildah run "${REGISTRY}/${NAMESPACE}/${IMAGE_NAME}:security-scan"; then
        log_success "Security scan completed"
    else
        log_warning "Security scan found issues"
    fi
fi

# Push image if requested
if [[ "$PUSH" == "true" ]]; then
    log_info "Pushing image to registry..."
    
    # Login check
    if ! buildah login --get-login "$REGISTRY" &> /dev/null; then
        log_error "Not logged into registry: $REGISTRY"
        log_info "Please run: buildah login $REGISTRY"
        exit 1
    fi
    
    # Push image
    if [[ "$STAGE" == "production" ]]; then
        buildah push "${FULL_IMAGE_NAME}"
        buildah push "${REGISTRY}/${NAMESPACE}/${IMAGE_NAME}:${STAGE}"
    else
        buildah push "${FULL_IMAGE_NAME}-${STAGE}"
        buildah push "${REGISTRY}/${NAMESPACE}/${IMAGE_NAME}:${STAGE}"
    fi
    
    if [[ $? -eq 0 ]]; then
        log_success "Image pushed successfully"
    else
        log_error "Image push failed"
        exit 1
    fi
fi

# Clean up intermediate images
log_info "Cleaning up..."
buildah system prune -f &> /dev/null || true

# Display image information
log_info "Image information:"
if [[ "$STAGE" == "production" ]]; then
    buildah inspect "${FULL_IMAGE_NAME}" | jq '.Config.Labels' || true
else
    buildah inspect "${FULL_IMAGE_NAME}-${STAGE}" | jq '.Config.Labels' || true
fi

log_success "Build process completed successfully!"

# Display usage instructions
log_info "Usage instructions:"
if [[ "$STAGE" == "production" ]]; then
    echo "  To run the container:"
    echo "    podman run -p 8080:8080 ${FULL_IMAGE_NAME}"
    echo "  To run with docker-compose:"
    echo "    docker-compose up ingestion-prod"
else
    echo "  To run the container:"
    echo "    podman run -p 8080:8080 ${FULL_IMAGE_NAME}-${STAGE}"
    echo "  To run with docker-compose:"
    echo "    docker-compose up ingestion-${STAGE}"
fi

echo "  Health check:"
echo "    curl http://localhost:8080/health/"
echo "  Metrics:"
echo "    curl http://localhost:8080/metrics/"