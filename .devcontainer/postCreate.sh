#!/bin/bash

# MCP Security Platform - Post Create Command
# This script runs after the devcontainer is created

set -e

echo "🔧 Initializing MCP Security Platform development environment..."
echo "================================================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${BLUE}ℹ️  $1${NC}"; }
log_success() { echo -e "${GREEN}✅ $1${NC}"; }
log_warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
log_error() { echo -e "${RED}❌ $1${NC}"; }

# Install Python dependencies
install_python_deps() {
    log_info "Installing Python dependencies..."
    
    # Install requirements from all services
    if [ -f requirements.txt ]; then
        pip install --user -r requirements.txt
    fi
    
    # Install development tools
    pip install --user \
        black \
        isort \
        pylint \
        mypy \
        pytest \
        pytest-cov \
        pytest-asyncio \
        httpx \
        uvicorn \
        fastapi
    
    log_success "Python dependencies installed"
}

# Set up Git configuration
setup_git() {
    log_info "Setting up Git configuration..."
    
    # Set safe directory
    git config --global --add safe.directory /workspace
    
    # Set default branch
    git config --global init.defaultBranch main
    
    log_success "Git configuration completed"
}

# Create required directories
create_directories() {
    log_info "Creating required directories..."
    
    mkdir -p ~/.kube
    mkdir -p ~/.local/bin
    mkdir -p /workspace/logs
    mkdir -p /workspace/tmp
    
    log_success "Directories created"
}

# Set up shell environment
setup_shell() {
    log_info "Setting up shell environment..."
    
    # Add to bashrc if not already present
    if ! grep -q "MCP Security Platform" ~/.bashrc; then
        cat >> ~/.bashrc << 'EOF'

# MCP Security Platform aliases and functions
export PATH="$HOME/.local/bin:$PATH"
export KUBECONFIG="/workspace/.kube/config"
export PYTHONPATH="/workspace:$PYTHONPATH"

# Useful aliases
alias k=kubectl
alias ll="ls -la"
alias mcp-status="kubectl get pods -n mcp-security"
alias mcp-logs="kubectl logs -f deployment/mcp-platform-correlation -n mcp-security"
alias mcp-forward="kubectl port-forward -n mcp-security svc/mcp-platform-gateway 8000:8000"

# MCP helper functions
mcp-health() {
    echo "Checking MCP service health..."
    for port in 8000 8001 8080; do
        echo "=== Port $port ==="
        curl -s http://localhost:$port/health | jq . || echo "Service not available"
    done
}

mcp-restart() {
    echo "Restarting MCP POC..."
    ./scripts/codespace-setup.sh
}

# Enable kubectl completion
source <(kubectl completion bash)
EOF
    fi
    
    log_success "Shell environment configured"
}

# Build container images locally
build_images() {
    log_info "Building container images locally..."
    
    # Check if we already have images
    if buildah images | grep -q "ghcr.io/ggkunka/mcp-"; then
        log_warning "Images already exist, skipping build"
        return 0
    fi
    
    # Build core services with simple FastAPI apps
    services=("correlation-engine" "risk-assessment" "response-orchestrator" "reporting-service" "auth-service" "gateway-service")
    
    for service in "${services[@]}"; do
        log_info "Building $service..."
        
        # Create build directory
        BUILD_DIR="/tmp/build-${service}"
        mkdir -p "$BUILD_DIR"
        
        # Create Dockerfile
        cat > "$BUILD_DIR/Dockerfile" << 'EOF'
FROM python:3.11-slim

# Install dependencies
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*
RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app

# Install Python packages
RUN pip install fastapi uvicorn[standard] httpx structlog

# Copy app
COPY main.py .
RUN chown -R appuser:appuser /app
USER appuser

HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

EXPOSE 8080
CMD ["python", "main.py"]
EOF
        
        # Create main.py
        cat > "$BUILD_DIR/main.py" << EOF
#!/usr/bin/env python3
"""
MCP Security Platform - ${service}
"""
import os
import asyncio
from datetime import datetime
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="MCP ${service}",
    description="MCP Security Platform ${service} service",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Service state
service_state = {
    "status": "healthy",
    "service": "${service}",
    "started_at": datetime.utcnow().isoformat(),
    "version": "1.0.0"
}

@app.get("/")
async def root():
    return {"message": "MCP ${service} is running", **service_state}

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "${service}"}

@app.get("/metrics")
async def metrics():
    return {
        "service": "${service}",
        "uptime": "healthy",
        "requests_total": 42,
        "response_time_avg": 0.1
    }

# Service-specific endpoints
if "${service}" == "auth-service":
    @app.post("/auth/login")
    async def login(credentials: dict):
        return {
            "access_token": "demo-jwt-token-12345",
            "token_type": "bearer",
            "expires_in": 3600
        }
    
    @app.get("/auth/me")
    async def get_current_user():
        return {
            "username": "admin",
            "email": "admin@mcp-security.local",
            "is_active": True
        }

elif "${service}" == "correlation-engine":
    @app.post("/correlate")
    async def correlate_events():
        return {
            "correlation_id": "corr-12345",
            "events_processed": 15,
            "patterns_detected": 3
        }

elif "${service}" == "risk-assessment":
    @app.post("/assess")
    async def assess_risk():
        return {
            "risk_score": 7.5,
            "risk_level": "HIGH",
            "factors": ["CVE-2023-1234", "Exposed port", "Missing patches"]
        }

elif "${service}" == "response-orchestrator":
    @app.post("/orchestrate")
    async def orchestrate_response():
        return {
            "response_id": "resp-12345",
            "actions": ["isolate", "patch", "notify"],
            "status": "initiated"
        }

elif "${service}" == "reporting-service":
    @app.get("/reports")
    async def get_reports():
        return {
            "reports": [
                {"id": 1, "name": "Security Summary", "type": "dashboard"},
                {"id": 2, "name": "Vulnerability Report", "type": "detailed"}
            ]
        }

elif "${service}" == "gateway-service":
    @app.get("/api/v1/status")
    async def api_status():
        return {
            "api_version": "v1",
            "services": {
                "auth": "healthy",
                "correlation": "healthy", 
                "risk": "healthy",
                "response": "healthy",
                "reporting": "healthy"
            }
        }

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)
EOF
        
        # Build image with Buildah
        buildah build \
            --format docker \
            --isolation chroot \
            --tag "ghcr.io/ggkunka/mcp-${service}:latest" \
            "$BUILD_DIR"
        
        # Cleanup
        rm -rf "$BUILD_DIR"
    done
    
    log_success "Container images built successfully"
}

# Wait for Docker to be ready
wait_for_docker() {
    log_info "Waiting for Docker to be ready..."
    
    for i in {1..30}; do
        if docker info >/dev/null 2>&1; then
            log_success "Docker is ready"
            return 0
        fi
        sleep 2
    done
    
    log_error "Docker failed to start"
    return 1
}

# Main execution
main() {
    log_info "Starting post-create setup..."
    
    create_directories
    setup_git
    install_python_deps
    setup_shell
    wait_for_docker
    build_images
    
    log_success "Post-create setup completed!"
    log_info "Run './scripts/codespace-setup.sh' to deploy the POC"
}

# Run main function
main "$@"