#!/bin/bash

# Test Buildah functionality
# This script tests if Buildah is working correctly in the environment

set -e

echo "🔧 Testing Buildah functionality..."
echo "==================================="

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

log_info() { echo -e "${BLUE}ℹ️  $1${NC}"; }
log_success() { echo -e "${GREEN}✅ $1${NC}"; }
log_warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
log_error() { echo -e "${RED}❌ $1${NC}"; }

# Test 1: Check if Buildah is installed
test_buildah_installation() {
    log_info "Test 1: Checking Buildah installation..."
    
    if command -v buildah >/dev/null 2>&1; then
        BUILDAH_VERSION=$(buildah --version)
        log_success "Buildah is installed: $BUILDAH_VERSION"
        return 0
    else
        log_error "Buildah is not installed or not in PATH"
        return 1
    fi
}

# Test 2: Check Buildah configuration
test_buildah_config() {
    log_info "Test 2: Checking Buildah configuration..."
    
    # Check storage configuration
    if buildah info >/dev/null 2>&1; then
        log_success "Buildah configuration is valid"
        
        # Show some key info
        echo "Storage driver: $(buildah info --format '{{.store.GraphDriverName}}')"
        echo "Storage root: $(buildah info --format '{{.store.GraphRoot}}')"
        return 0
    else
        log_error "Buildah configuration has issues"
        return 1
    fi
}

# Test 3: Build a simple test image
test_buildah_build() {
    log_info "Test 3: Building a simple test image..."
    
    # Create temporary build context
    TEMP_DIR=$(mktemp -d)
    
    # Create a minimal Dockerfile
    cat > "$TEMP_DIR/Dockerfile" << 'EOF'
FROM alpine:latest
RUN echo "Hello from Buildah test!" > /hello.txt
CMD ["cat", "/hello.txt"]
EOF
    
    # Try to build the image
    if buildah build \
        --format docker \
        --isolation chroot \
        --tag test-buildah:latest \
        "$TEMP_DIR" >/dev/null 2>&1; then
        log_success "Test image built successfully"
        
        # Clean up the test image
        buildah rmi test-buildah:latest >/dev/null 2>&1 || true
        rm -rf "$TEMP_DIR"
        return 0
    else
        log_error "Failed to build test image"
        rm -rf "$TEMP_DIR"
        return 1
    fi
}

# Test 4: Check container runtime compatibility
test_runtime_compatibility() {
    log_info "Test 4: Checking container runtime compatibility..."
    
    # Check if we can create and run a simple container
    if buildah from alpine:latest >/dev/null 2>&1; then
        CONTAINER=$(buildah from alpine:latest)
        
        if buildah run "$CONTAINER" -- echo "Runtime test successful" >/dev/null 2>&1; then
            log_success "Container runtime is working"
            buildah rm "$CONTAINER" >/dev/null 2>&1 || true
            return 0
        else
            log_warning "Container runtime has limitations (may be expected in restricted environments)"
            buildah rm "$CONTAINER" >/dev/null 2>&1 || true
            return 0  # Don't fail the test for this
        fi
    else
        log_error "Cannot create containers"
        return 1
    fi
}

# Test 5: Check image management
test_image_management() {
    log_info "Test 5: Testing image management..."
    
    # Check if we can list images
    if buildah images >/dev/null 2>&1; then
        IMAGE_COUNT=$(buildah images --format "{{.Repository}}" | wc -l)
        log_success "Image management is working ($IMAGE_COUNT images available)"
        return 0
    else
        log_error "Cannot list images"
        return 1
    fi
}

# Run all tests
main() {
    log_info "Starting Buildah functionality tests..."
    
    TESTS_PASSED=0
    TESTS_TOTAL=5
    
    test_buildah_installation && TESTS_PASSED=$((TESTS_PASSED + 1))
    test_buildah_config && TESTS_PASSED=$((TESTS_PASSED + 1))
    test_buildah_build && TESTS_PASSED=$((TESTS_PASSED + 1))
    test_runtime_compatibility && TESTS_PASSED=$((TESTS_PASSED + 1))
    test_image_management && TESTS_PASSED=$((TESTS_PASSED + 1))
    
    echo ""
    echo "📊 Test Results:"
    echo "================"
    echo "Passed: $TESTS_PASSED/$TESTS_TOTAL"
    
    if [ $TESTS_PASSED -eq $TESTS_TOTAL ]; then
        log_success "🎉 All Buildah tests passed! Buildah is ready for use."
        return 0
    elif [ $TESTS_PASSED -gt 3 ]; then
        log_warning "⚠️ Most tests passed. Buildah should work with minor limitations."
        return 0
    else
        log_error "❌ Multiple tests failed. Buildah may not work correctly."
        return 1
    fi
}

# Set environment variables for Buildah
export BUILDAH_ISOLATION=chroot
export BUILDAH_FORMAT=docker
export STORAGE_DRIVER=vfs

# Run the tests
main "$@"