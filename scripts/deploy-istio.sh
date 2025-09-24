#!/bin/bash

# MCP Security Platform - Istio Service Mesh Deployment Script
# This script deploys and configures Istio service mesh for the MCP Security Platform

set -euo pipefail

# Configuration
ISTIO_VERSION="1.19.0"
NAMESPACE="mcp-security"
MONITORING_NAMESPACE="mcp-security-monitoring"
ISTIO_DIR="./istio"
LOG_FILE="/tmp/istio-deploy-$(date +%Y%m%d_%H%M%S).log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if kubectl is installed
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl is not installed. Please install kubectl first."
        exit 1
    fi
    
    # Check if istioctl is installed
    if ! command -v istioctl &> /dev/null; then
        log_warning "istioctl is not installed. Installing Istio CLI..."
        install_istioctl
    fi
    
    # Check cluster connection
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster. Please check your kubeconfig."
        exit 1
    fi
    
    # Check if kustomize is installed
    if ! command -v kustomize &> /dev/null; then
        log_warning "kustomize is not installed. Installing kustomize..."
        install_kustomize
    fi
    
    log_success "Prerequisites check completed"
}

# Install Istio CLI
install_istioctl() {
    log_info "Installing istioctl version $ISTIO_VERSION..."
    
    # Download and install istioctl
    curl -L https://istio.io/downloadIstio | ISTIO_VERSION=$ISTIO_VERSION sh -
    
    # Add to PATH
    export PATH="$PWD/istio-$ISTIO_VERSION/bin:$PATH"
    
    # Verify installation
    if istioctl version --client &> /dev/null; then
        log_success "istioctl installed successfully"
    else
        log_error "Failed to install istioctl"
        exit 1
    fi
}

# Install kustomize
install_kustomize() {
    log_info "Installing kustomize..."
    
    # Install kustomize
    curl -s "https://raw.githubusercontent.com/kubernetes-sigs/kustomize/master/hack/install_kustomize.sh" | bash
    sudo mv kustomize /usr/local/bin/
    
    log_success "kustomize installed successfully"
}

# Install Istio
install_istio() {
    log_info "Installing Istio control plane..."
    
    # Create Istio system namespace if it doesn't exist
    kubectl create namespace istio-system --dry-run=client -o yaml | kubectl apply -f -
    
    # Install Istio with production configuration
    istioctl install --set values.global.meshID=mcp-security \
        --set values.global.meshConfig.defaultConfig.discoveryRefreshDelay=10s \
        --set values.global.meshConfig.defaultConfig.proxyStatsMatcher.inclusionRegexps=".*outlier_detection.*,.*circuit_breakers.*,.*upstream_rq_retry.*,.*upstream_rq_pending.*,.*_cx_.*" \
        --set values.pilot.traceSampling=1.0 \
        --set values.global.proxy.resources.requests.cpu=100m \
        --set values.global.proxy.resources.requests.memory=128Mi \
        --set values.global.proxy.resources.limits.cpu=200m \
        --set values.global.proxy.resources.limits.memory=256Mi \
        --set values.gateways.istio-ingressgateway.type=LoadBalancer \
        --set values.gateways.istio-ingressgateway.ports[0].port=80 \
        --set values.gateways.istio-ingressgateway.ports[0].targetPort=8080 \
        --set values.gateways.istio-ingressgateway.ports[0].name=http2 \
        --set values.gateways.istio-ingressgateway.ports[1].port=443 \
        --set values.gateways.istio-ingressgateway.ports[1].targetPort=8443 \
        --set values.gateways.istio-ingressgateway.ports[1].name=https \
        --skip-confirmation
    
    # Wait for Istio control plane to be ready
    log_info "Waiting for Istio control plane to be ready..."
    kubectl wait --for=condition=Ready pods -l app=istiod -n istio-system --timeout=300s
    
    log_success "Istio control plane installed successfully"
}

# Create namespaces
create_namespaces() {
    log_info "Creating application namespaces..."
    
    # Apply namespace configuration
    kubectl apply -f "$ISTIO_DIR/base/namespace.yaml"
    
    # Wait for namespaces to be ready
    kubectl wait --for=condition=Ready --timeout=60s namespace/$NAMESPACE
    kubectl wait --for=condition=Ready --timeout=60s namespace/$MONITORING_NAMESPACE
    
    log_success "Namespaces created successfully"
}

# Deploy Istio configuration
deploy_istio_config() {
    log_info "Deploying Istio configuration..."
    
    # Apply Istio configuration using kustomize
    kustomize build "$ISTIO_DIR" | kubectl apply -f -
    
    # Wait for gateways to be ready
    log_info "Waiting for gateways to be ready..."
    kubectl wait --for=condition=Programmed gateway/mcp-security-gateway -n $NAMESPACE --timeout=300s
    
    log_success "Istio configuration deployed successfully"
}

# Install observability addons
install_observability() {
    log_info "Installing observability addons..."
    
    # Install Prometheus
    kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-1.19/samples/addons/prometheus.yaml
    
    # Install Grafana
    kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-1.19/samples/addons/grafana.yaml
    
    # Install Jaeger
    kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-1.19/samples/addons/jaeger.yaml
    
    # Install Kiali
    kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-1.19/samples/addons/kiali.yaml
    
    # Wait for addons to be ready
    log_info "Waiting for observability addons to be ready..."
    kubectl wait --for=condition=Ready pods -l app=prometheus -n istio-system --timeout=300s
    kubectl wait --for=condition=Ready pods -l app=grafana -n istio-system --timeout=300s
    kubectl wait --for=condition=Ready pods -l app=jaeger -n istio-system --timeout=300s
    kubectl wait --for=condition=Ready pods -l app=kiali -n istio-system --timeout=300s
    
    log_success "Observability addons installed successfully"
}

# Verify installation
verify_installation() {
    log_info "Verifying Istio installation..."
    
    # Check Istio control plane status
    istioctl verify-install
    
    # Check proxy status
    istioctl proxy-status
    
    # Check configuration
    istioctl analyze -n $NAMESPACE
    
    # Get ingress gateway external IP
    INGRESS_IP=$(kubectl get svc istio-ingressgateway -n istio-system -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
    if [ -n "$INGRESS_IP" ]; then
        log_success "Istio ingress gateway is available at: $INGRESS_IP"
    else
        log_warning "Ingress gateway external IP is not yet available. Check service status with: kubectl get svc istio-ingressgateway -n istio-system"
    fi
    
    log_success "Istio installation verification completed"
}

# Generate observability dashboard access
setup_dashboard_access() {
    log_info "Setting up dashboard access..."
    
    # Create port-forward scripts for easy access
    cat > /tmp/start-kiali.sh << EOF
#!/bin/bash
echo "Starting Kiali dashboard..."
echo "Access Kiali at: http://localhost:20001"
kubectl port-forward svc/kiali 20001:20001 -n istio-system
EOF
    
    cat > /tmp/start-grafana.sh << EOF
#!/bin/bash
echo "Starting Grafana dashboard..."
echo "Access Grafana at: http://localhost:3000"
kubectl port-forward svc/grafana 3000:3000 -n istio-system
EOF
    
    cat > /tmp/start-jaeger.sh << EOF
#!/bin/bash
echo "Starting Jaeger dashboard..."
echo "Access Jaeger at: http://localhost:16686"
kubectl port-forward svc/jaeger 16686:16686 -n istio-system
EOF
    
    chmod +x /tmp/start-*.sh
    
    log_success "Dashboard access scripts created in /tmp/"
    log_info "Use the following commands to access dashboards:"
    log_info "  Kiali:   /tmp/start-kiali.sh"
    log_info "  Grafana: /tmp/start-grafana.sh"
    log_info "  Jaeger:  /tmp/start-jaeger.sh"
}

# Print summary
print_summary() {
    log_success "\n=== MCP Security Platform - Istio Deployment Summary ==="
    log_info "✓ Istio control plane installed"
    log_info "✓ Application namespaces created with sidecar injection enabled"
    log_info "✓ Security policies applied (mTLS, AuthZ, AuthN)"
    log_info "✓ Traffic management configured (Gateways, VirtualServices, DestinationRules)"
    log_info "✓ Observability addons installed (Prometheus, Grafana, Jaeger, Kiali)"
    log_info "✓ Rate limiting and WAF enabled"
    log_info "✓ Security headers configured"
    
    log_info "\nNext steps:"
    log_info "1. Deploy your MCP Security Platform applications"
    log_info "2. Verify sidecar injection is working: kubectl get pods -n $NAMESPACE"
    log_info "3. Access observability dashboards using the scripts in /tmp/"
    log_info "4. Monitor service mesh health: istioctl proxy-status"
    
    log_info "\nConfiguration files applied from: $ISTIO_DIR"
    log_info "Deployment log saved to: $LOG_FILE"
}

# Cleanup function
cleanup() {
    log_warning "Deployment interrupted. Cleaning up..."
    # Add cleanup logic here if needed
    exit 1
}

# Main deployment function
main() {
    log_info "Starting MCP Security Platform Istio deployment..."
    log_info "Deployment log: $LOG_FILE"
    
    # Set trap for cleanup on interrupt
    trap cleanup INT TERM
    
    # Run deployment steps
    check_prerequisites
    install_istio
    create_namespaces
    deploy_istio_config
    install_observability
    verify_installation
    setup_dashboard_access
    print_summary
    
    log_success "MCP Security Platform Istio deployment completed successfully!"
}

# Script options
case "${1:-}" in
    "--help" | "-h")
        echo "Usage: $0 [options]"
        echo "Options:"
        echo "  --help, -h    Show this help message"
        echo "  --verify      Verify existing installation"
        echo "  --cleanup     Remove Istio installation"
        exit 0
        ;;
    "--verify")
        verify_installation
        exit 0
        ;;
    "--cleanup")
        log_warning "Removing Istio installation..."
        kubectl delete -f "$ISTIO_DIR" --ignore-not-found=true
        istioctl uninstall --purge -y
        kubectl delete namespace istio-system --ignore-not-found=true
        kubectl delete namespace $NAMESPACE --ignore-not-found=true
        kubectl delete namespace $MONITORING_NAMESPACE --ignore-not-found=true
        log_success "Istio cleanup completed"
        exit 0
        ;;
    "")
        main
        ;;
    *)
        log_error "Unknown option: $1"
        echo "Use --help for usage information"
        exit 1
        ;;
esac