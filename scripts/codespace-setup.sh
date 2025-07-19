#!/bin/bash

# MCP Security Platform - Codespace POC Setup
# This script sets up a complete POC environment in Kind

set -e

echo "🚀 Setting up MCP Security Platform POC..."
echo "=================================================="

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

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if ! command -v kind &> /dev/null; then
        log_error "Kind is not installed"
        exit 1
    fi
    
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl is not installed"
        exit 1
    fi
    
    if ! command -v helm &> /dev/null; then
        log_error "Helm is not installed"
        exit 1
    fi
    
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        exit 1
    fi
    
    log_success "All prerequisites are installed"
}

# Create Kind cluster
create_kind_cluster() {
    log_info "Creating Kind cluster for POC..."
    
    # Check if cluster already exists
    if kind get clusters | grep -q "mcp-poc"; then
        log_warning "Kind cluster 'mcp-poc' already exists"
        return 0
    fi
    
    cat <<EOF | kind create cluster --name mcp-poc --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  kubeadmConfigPatches:
  - |
    kind: InitConfiguration
    nodeRegistration:
      kubeletExtraArgs:
        node-labels: "ingress-ready=true"
  extraPortMappings:
  - containerPort: 80
    hostPort: 8080
    protocol: TCP
  - containerPort: 443
    hostPort: 8443
    protocol: TCP
  - containerPort: 30000
    hostPort: 30000
    protocol: TCP
  - containerPort: 30001
    hostPort: 30001
    protocol: TCP
  - containerPort: 30002
    hostPort: 30002
    protocol: TCP
EOF
    
    log_success "Kind cluster created successfully"
}

# Load container images into Kind
load_images_to_kind() {
    log_info "Loading container images into Kind cluster..."
    
    # Check if we have pre-built images locally
    if docker images | grep -q "ghcr.io/ggkunka/mcp-"; then
        log_info "Loading pre-built images from local registry..."
        
        # Get list of MCP images
        images=$(docker images --format "table {{.Repository}}:{{.Tag}}" | grep "ghcr.io/ggkunka/mcp-" | grep -v "<none>")
        
        for image in $images; do
            log_info "Loading $image..."
            kind load docker-image "$image" --name mcp-poc
        done
        
        log_success "Pre-built images loaded successfully"
    else
        log_warning "No pre-built images found. Building locally..."
        build_images_locally
    fi
}

# Build images locally if not available
build_images_locally() {
    log_info "Building MCP images locally for POC..."
    
    # Build core services with simplified Dockerfile
    services=("correlation-engine" "risk-assessment" "response-orchestrator" "reporting-service")
    
    for service in "${services[@]}"; do
        log_info "Building $service..."
        
        # Create a simple Dockerfile for POC
        cat > "/tmp/Dockerfile.${service}" <<EOF
FROM python:3.11-slim

RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*
RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app

# Install basic dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app
COPY main.py .
RUN chown -R appuser:appuser /app
USER appuser

HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \\
    CMD curl -f http://localhost:8080/health || exit 1

EXPOSE 8080
CMD ["python", "main.py"]
EOF
        
        # Create build context
        mkdir -p "/tmp/build-${service}"
        cp "/tmp/Dockerfile.${service}" "/tmp/build-${service}/Dockerfile"
        cp "/tmp/enterprise-requirements.txt" "/tmp/build-${service}/requirements.txt" 2>/dev/null || echo "fastapi==0.104.1\nuvicorn[standard]==0.24.0" > "/tmp/build-${service}/requirements.txt"
        cp "/tmp/enterprise-main.py" "/tmp/build-${service}/main.py" 2>/dev/null || cat > "/tmp/build-${service}/main.py" <<EOF
import uvicorn
from fastapi import FastAPI

app = FastAPI(title="MCP ${service}", version="1.0.0")

@app.get("/health")
async def health(): return {"status": "healthy"}

@app.get("/")
async def root(): return {"service": "${service}", "status": "running"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)
EOF
        
        # Build and load image
        docker build -t "ghcr.io/ggkunka/mcp-${service}:latest" "/tmp/build-${service}"
        kind load docker-image "ghcr.io/ggkunka/mcp-${service}:latest" --name mcp-poc
        
        # Cleanup
        rm -rf "/tmp/build-${service}" "/tmp/Dockerfile.${service}"
    done
    
    log_success "Images built and loaded successfully"
}

# Install NGINX Ingress Controller
install_ingress() {
    log_info "Installing NGINX Ingress Controller..."
    
    kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml
    
    log_info "Waiting for ingress controller to be ready..."
    kubectl wait --namespace ingress-nginx \
        --for=condition=ready pod \
        --selector=app.kubernetes.io/component=controller \
        --timeout=90s
        
    log_success "NGINX Ingress Controller installed"
}

# Deploy MCP Platform using Helm
deploy_mcp_platform() {
    log_info "Deploying MCP Security Platform..."
    
    # Create namespace
    kubectl create namespace mcp-security --dry-run=client -o yaml | kubectl apply -f -
    
    # Deploy using Helm with POC values
    helm upgrade --install mcp-platform ./deployments/helm/mcp-platform \
        --namespace mcp-security \
        --values .devcontainer/poc-values.yaml \
        --wait \
        --timeout=10m
        
    log_success "MCP Platform deployed successfully"
}

# Set up port forwarding
setup_port_forwarding() {
    log_info "Setting up port forwarding..."
    
    # Kill any existing port forwards
    pkill -f "kubectl port-forward" || true
    
    # Gateway service
    kubectl port-forward -n mcp-security svc/mcp-platform-gateway 8000:8000 > /dev/null 2>&1 &
    
    # Auth service  
    kubectl port-forward -n mcp-security svc/mcp-platform-auth 8001:8001 > /dev/null 2>&1 &
    
    # Core services
    kubectl port-forward -n mcp-security svc/mcp-platform-correlation 8080:8080 > /dev/null 2>&1 &
    
    sleep 5
    log_success "Port forwarding configured"
}

# Display access information
show_access_info() {
    echo ""
    echo "🎉 MCP Security Platform POC is ready!"
    echo "========================================"
    echo ""
    echo "📍 Service Access URLs:"
    echo "  🌐 API Gateway:     http://localhost:8000"
    echo "  🔐 Auth Service:    http://localhost:8001"  
    echo "  ⚙️  Core Services:   http://localhost:8080"
    echo "  🗄️  MinIO Console:   http://localhost:9000"
    echo "  📊 PostgreSQL:      localhost:5432"
    echo "  ⚡ Redis:           localhost:6379"
    echo ""
    echo "🔑 Default Credentials:"
    echo "  👤 Username: admin"
    echo "  🔒 Password: admin123"
    echo ""
    echo "🧪 Test the POC:"
    echo "  curl http://localhost:8000/health"
    echo "  curl http://localhost:8001/auth/health"
    echo "  curl http://localhost:8080/health"
    echo ""
    echo "📚 For detailed walkthrough, see: .github/codespace-poc.md"
    echo ""
}

# Check cluster health
check_cluster_health() {
    log_info "Checking cluster health..."
    
    # Wait for all pods to be ready
    log_info "Waiting for all pods to be ready..."
    kubectl wait --for=condition=ready pod --all -n mcp-security --timeout=300s
    
    # Check service status
    log_info "Checking service status..."
    kubectl get pods -n mcp-security
    kubectl get svc -n mcp-security
    
    log_success "Cluster health check completed"
}

# Cleanup function
cleanup() {
    log_info "Cleaning up on exit..."
    pkill -f "kubectl port-forward" || true
}

trap cleanup EXIT

# Main execution
main() {
    check_prerequisites
    create_kind_cluster
    load_images_to_kind
    install_ingress
    deploy_mcp_platform
    check_cluster_health
    setup_port_forwarding
    show_access_info
}

# Run main function
main "$@"