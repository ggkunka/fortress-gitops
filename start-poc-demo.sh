#!/bin/bash

# MCP Security Platform - Manual Startup Script
# Run this script after host reboot to start the interactive POC demo

set -e

echo "🚀 Starting MCP Security Platform Interactive POC Demo"
echo "=" * 60

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

log_info() { echo -e "${BLUE}ℹ️  $1${NC}"; }
log_success() { echo -e "${GREEN}✅ $1${NC}"; }
log_warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
log_error() { echo -e "${RED}❌ $1${NC}"; }

# Step 1: Check Docker Desktop
log_info "Checking Docker Desktop status..."
if ! docker ps >/dev/null 2>&1; then
    log_error "Docker Desktop is not running"
    echo "Please start Docker Desktop and enable Kubernetes, then run this script again"
    exit 1
fi
log_success "Docker Desktop is running"

# Step 2: Check Kubernetes
log_info "Checking Kubernetes cluster..."
if ! kubectl cluster-info >/dev/null 2>&1; then
    log_error "Kubernetes cluster is not accessible"
    echo "Please ensure Kubernetes is enabled in Docker Desktop"
    exit 1
fi
log_success "Kubernetes cluster is accessible"

# Step 3: Check/Start databases
log_info "Checking database deployments..."

# Check if Redis is running
if kubectl get deployment redis-master >/dev/null 2>&1; then
    log_success "Redis is already deployed"
else
    log_info "Deploying Redis..."
    helm repo add bitnami https://charts.bitnami.com/bitnami >/dev/null 2>&1 || true
    helm repo update >/dev/null 2>&1
    helm install redis bitnami/redis --set auth.enabled=false --set architecture=standalone
    log_success "Redis deployed"
fi

# Check if PostgreSQL is running
if kubectl get deployment postgresql >/dev/null 2>&1; then
    log_success "PostgreSQL is already deployed"
else
    log_info "Deploying PostgreSQL..."
    helm install postgresql bitnami/postgresql --set auth.postgresPassword=password --set architecture=standalone
    log_success "PostgreSQL deployed"
fi

# Step 4: Wait for pods to be ready
log_info "Waiting for database pods to be ready..."
kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=redis --timeout=120s
kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=postgresql --timeout=120s
log_success "Database pods are ready"

# Step 5: Start port forwarding for databases (in background)
log_info "Setting up database port forwarding..."
pkill -f "kubectl port-forward.*redis" 2>/dev/null || true
pkill -f "kubectl port-forward.*postgresql" 2>/dev/null || true
kubectl port-forward svc/redis-master 6379:6379 >/dev/null 2>&1 &
kubectl port-forward svc/postgresql 5432:5432 >/dev/null 2>&1 &
sleep 3
log_success "Database port forwarding established"

# Step 6: Check scanning tools
log_info "Checking vulnerability scanning tools..."
export PATH="$HOME/bin:$PATH"

if [[ ! -f "$HOME/bin/syft" ]]; then
    log_warning "Syft not found, installing..."
    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b ~/bin
fi

if [[ ! -f "$HOME/bin/grype" ]]; then
    log_warning "Grype not found, installing..."
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b ~/bin
fi

log_success "Scanning tools are available"

# Step 7: Check Python dependencies
log_info "Checking Python dependencies..."
python3 -c "import fastapi, uvicorn, anthropic" 2>/dev/null || {
    log_warning "Installing Python dependencies..."
    pip install fastapi uvicorn python-multipart anthropic >/dev/null 2>&1
}
log_success "Python dependencies are ready"

# Step 8: Start the web server
log_info "Starting MCP Security Platform Web Server..."
pkill -f "web-poc-server.py" 2>/dev/null || true
sleep 2

# Start server in background
nohup python3 web-poc-server.py > poc-server.log 2>&1 &
SERVER_PID=$!

# Wait for server to start
log_info "Waiting for server to start..."
for i in {1..10}; do
    if curl -s http://localhost:8080/api/status >/dev/null 2>&1; then
        break
    fi
    sleep 2
    if [ $i -eq 10 ]; then
        log_error "Server failed to start"
        exit 1
    fi
done

log_success "Web server is running (PID: $SERVER_PID)"

# Step 9: Display access information
echo ""
echo "🎉 MCP Security Platform POC is now running!"
echo "=" * 60
echo ""
echo "🌐 Web Dashboard: http://localhost:8080"
echo "📚 API Documentation: http://localhost:8080/docs"
echo "📊 Quick Test: curl http://localhost:8080/api/status"
echo ""
echo "🔧 Services Status:"
echo "   ✅ Redis: localhost:6379"
echo "   ✅ PostgreSQL: localhost:5432"
echo "   ✅ Web Server: localhost:8080"
echo "   ✅ Vulnerability Scanners: Syft & Grype"
echo ""
echo "🚀 Ready for Interactive POC Demo!"
echo ""
echo "To stop all services:"
echo "   pkill -f 'web-poc-server.py'"
echo "   pkill -f 'kubectl port-forward'"
echo "   helm uninstall redis postgresql"
echo ""

# Save PIDs for cleanup
echo $SERVER_PID > .server.pid
echo "Port forwarding and server PIDs saved for cleanup"