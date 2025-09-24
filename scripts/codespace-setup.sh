#!/bin/bash

# MCP Security Platform - Codespace POC Setup
# This script sets up a complete POC environment in Kind

set -e

# Check if running automatically (from devcontainer lifecycle)
if [ "${1:-}" = "--auto" ] || [ "${CODESPACE_NAME:-}" != "" ]; then
    echo "🤖 Automatic Codespace setup detected"
    AUTO_SETUP=true
    # Add logging for automatic setup
    exec > >(tee -a /tmp/mcp-setup.log)
    exec 2>&1
    echo "📋 Setup log will be saved to /tmp/mcp-setup.log"
else
    AUTO_SETUP=false
fi

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
        cp "/tmp/enterprise-requirements.txt" "/tmp/build-${service}/requirements.txt" 2>/dev/null || cat > "/tmp/build-${service}/requirements.txt" <<EOF
fastapi==0.104.1
uvicorn[standard]==0.24.0
httpx==0.25.2
structlog==23.2.0
EOF
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

# Setup Helm repositories and dependencies
setup_helm_dependencies() {
    log_info "Setting up Helm repositories and dependencies..."
    
    # Add required Helm repositories
    log_info "Adding Helm repositories..."
    helm repo add bitnami https://charts.bitnami.com/bitnami
    helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
    helm repo add grafana https://grafana.github.io/helm-charts
    helm repo update
    
    # Build chart dependencies
    log_info "Building Helm chart dependencies..."
    helm dependency build ./deployments/helm/mcp-platform/
    
    log_success "Helm dependencies configured"
}

# Deploy MCP Platform using Helm
deploy_mcp_platform() {
    log_info "Deploying MCP Security Platform..."
    
    # Cleanup any existing deployment that might have image pull issues
    if helm list -n mcp-security | grep -q mcp-platform; then
        log_warning "Existing MCP Platform deployment found, cleaning up..."
        helm uninstall mcp-platform -n mcp-security || true
        kubectl delete pods --all -n mcp-security || true
        sleep 10
    fi
    
    # Create namespace
    kubectl create namespace mcp-security --dry-run=client -o yaml | kubectl apply -f -
    
    # Use Codespaces-optimized values
    # Use the new simplified configuration for Codespaces
    local values_file="./deployments/helm/mcp-platform/codespace-simple-values.yaml"
    if [ ! -f "$values_file" ]; then
        log_warning "Codespace simple values not found, falling back to POC values"
        values_file="./deployments/helm/mcp-platform/codespaces-poc-values.yaml"
        if [ ! -f "$values_file" ]; then
            log_warning "Codespaces POC values not found, using default minimal config"
            values_file="./deployments/helm/mcp-platform/values.yaml"
        fi
    fi
    
    log_info "Building and loading required container images..."
    
    # Build all required MCP service images
    build_mcp_images
    
    log_info "Deploying with Codespaces-optimized configuration..."
    log_info "Using values file: $values_file"
    
    # Deploy using Helm with Codespaces POC values and shorter timeout
    helm upgrade --install mcp-platform ./deployments/helm/mcp-platform \
        --namespace mcp-security \
        --values "$values_file" \
        --timeout=5m \
        --wait=false \
        --create-namespace
        
    # Wait for core pods to be ready with custom timeout
    log_info "Waiting for core services to be ready..."
    kubectl wait --for=condition=ready pod \
        --selector=app.kubernetes.io/name=mcp-platform \
        --namespace=mcp-security \
        --timeout=300s || log_warning "Some pods may still be starting"
        
    log_success "MCP Platform deployment initiated"
}

# Build and load MCP service images using the comprehensive build script
build_mcp_images() {
    log_info "Building MCP service container images using build-all-services.sh..."
    
    # Check if our comprehensive build script exists
    if [ -f "./build-all-services.sh" ]; then
        log_info "Using comprehensive build script with proper business logic..."
        
        # Make sure it's executable
        chmod +x ./build-all-services.sh
        
        # Run the comprehensive build script
        ./build-all-services.sh
        
        log_success "All MCP services built with proper business logic"
    else
        log_warning "Comprehensive build script not found, falling back to simple builds..."
        
        # Fallback to simple builds
        build_simple_mcp_images
    fi
}

# Fallback function for simple image builds
build_simple_mcp_images() {
    log_info "Building simple MCP service container images..."
    
    # Create a simple Dockerfile for MCP services
    cat > /tmp/Dockerfile.mcp << 'EOF'
FROM python:3.11-slim
WORKDIR /app
RUN pip install fastapi uvicorn
COPY << 'EOPY' app.py
from fastapi import FastAPI
import os

app = FastAPI()

@app.get("/health")
def health():
    return {"status": "healthy", "service": os.environ.get("SERVICE_NAME", "mcp-service")}

@app.get("/")
def root():
    return {"service": os.environ.get("SERVICE_NAME", "mcp-service"), "status": "running"}

@app.get("/api/v1/status")
def status():
    return {"status": "operational", "version": "1.0.0"}
EOPY
EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
EOF

    # Build all required images
    local images=(
        "ghcr.io/ggkunka/mcp-correlation-engine"
        "ghcr.io/ggkunka/mcp-risk-assessment"
        "ghcr.io/ggkunka/mcp-websocket-server"
        "ghcr.io/ggkunka/mcp-graphql-server"
        "ghcr.io/ggkunka/mcp-response-orchestrator"
        "ghcr.io/ggkunka/mcp-reporting-service"
    )
    
    for image in "${images[@]}"; do
        log_info "Building $image:latest..."
        docker build -f /tmp/Dockerfile.mcp -t "$image:latest" . > /dev/null 2>&1 || log_warning "Failed to build $image"
        
        log_info "Loading $image:latest into Kind cluster..."
        kind load docker-image "$image:latest" --name mcp-poc > /dev/null 2>&1 || log_warning "Failed to load $image into Kind"
    done
    
    # Also load the Bitnami database images
    log_info "Ensuring database images are loaded..."
    docker pull bitnami/redis:7.2 > /dev/null 2>&1 || log_warning "Failed to pull Redis"
    docker pull bitnami/postgresql:13 > /dev/null 2>&1 || log_warning "Failed to pull PostgreSQL"
    kind load docker-image bitnami/redis:7.2 --name mcp-poc > /dev/null 2>&1
    kind load docker-image bitnami/postgresql:13 --name mcp-poc > /dev/null 2>&1
    
    # Cleanup
    rm -f /tmp/Dockerfile.mcp
    log_success "Container images built and loaded"
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
    
    # Check pod status (non-blocking for Codespaces)
    log_info "Checking pod status..."
    kubectl get pods -n mcp-security
    
    # Check service status
    log_info "Checking service status..."
    kubectl get svc -n mcp-security
    
    # Wait for core services with timeout
    log_info "Waiting for core services to respond..."
    local max_wait=60
    local count=0
    
    while [ $count -lt $max_wait ]; do
        if kubectl get pods -n mcp-security | grep -q "Running"; then
            log_success "Core services are starting up"
            break
        fi
        sleep 5
        count=$((count + 5))
        log_info "Waiting for pods to start... (${count}s/${max_wait}s)"
    done
    
    if [ $count -ge $max_wait ]; then
        log_warning "Services taking longer than expected to start"
        log_info "Check pod status with: kubectl get pods -n mcp-security"
    fi
    
    log_success "Cluster health check completed"
}

# Cleanup function
cleanup() {
    if [ "$AUTO_SETUP" = true ]; then
        log_info "Automatic setup completed - check /tmp/mcp-setup.log for details"
        log_info "Setup log contents:"
        echo "===================="
        tail -20 /tmp/mcp-setup.log 2>/dev/null || echo "No log file found"
        echo "===================="
    fi
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
    setup_helm_dependencies
    deploy_mcp_platform
    check_cluster_health
    setup_port_forwarding
    show_access_info
}

# Run main function
main "$@"