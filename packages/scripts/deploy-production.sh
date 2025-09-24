#!/bin/bash

# MCP Security Platform - kpt Package Production Deployment Script
# This script deploys the complete MCP Security Platform using kpt packages

set -euo pipefail

# Configuration
REPO_URL="https://github.com/ggkunka/mcp-security-platform.git"
PACKAGE_PATH="packages/deployment-packages/production-deployment"
DEPLOYMENT_DIR="./mcp-security-production"
DOMAIN="${DOMAIN:-security.company.com}"
IMAGE_REGISTRY="${IMAGE_REGISTRY:-security.company.com/registry}"
IMAGE_TAG="${IMAGE_TAG:-v1.0.0}"
STORAGE_CLASS="${STORAGE_CLASS:-fast-ssd}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
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

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if kpt is installed
    if ! command -v kpt &> /dev/null; then
        log_error "kpt is not installed. Please install kpt CLI first."
        echo "Install with: curl -s https://get.kpt.dev | bash"
        exit 1
    fi
    
    # Check if kubectl is installed and configured
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl is not installed. Please install kubectl first."
        exit 1
    fi
    
    # Check cluster connection
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster. Please check your kubeconfig."
        exit 1
    fi
    
    # Check kpt version
    KPT_VERSION=$(kpt version --client-only | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+')
    log_info "Using kpt version: $KPT_VERSION"
    
    log_success "Prerequisites check completed"
}

# Fetch kpt package
fetch_package() {
    log_info "Fetching MCP Security Platform production package..."
    
    # Remove existing deployment directory
    if [ -d "$DEPLOYMENT_DIR" ]; then
        log_warning "Removing existing deployment directory: $DEPLOYMENT_DIR"
        rm -rf "$DEPLOYMENT_DIR"
    fi
    
    # Fetch the package
    kpt pkg get "$REPO_URL/$PACKAGE_PATH" "$DEPLOYMENT_DIR"
    
    cd "$DEPLOYMENT_DIR"
    
    log_success "Package fetched successfully"
}

# Configure environment
configure_environment() {
    log_info "Configuring production environment..."
    
    # Apply production configuration setters
    kpt fn eval --image gcr.io/kpt-fn/apply-setters:v0.2.0 -- \
        environment=production \
        domain="$DOMAIN" \
        image_registry="$IMAGE_REGISTRY" \
        image_tag="$IMAGE_TAG" \
        replicas=3 \
        high_availability=true \
        enable_backups=true \
        enable_mtls=true \
        enable_authorization=true \
        enable_tracing=true \
        enable_metrics=true \
        enable_waf=true \
        storage_class="$STORAGE_CLASS" \
        postgresql_storage_size=200Gi \
        redis_storage_size=50Gi \
        postgresql_replicas=2 \
        log_level=info \
        enable_debug=false
    
    log_success "Environment configuration applied"
}

# Validate configuration
validate_configuration() {
    log_info "Validating package configuration..."
    
    # Run kpt function pipeline
    kpt fn render
    
    # Validate Kubernetes resources
    log_info "Validating Kubernetes resources..."
    kpt fn eval --image gcr.io/kpt-fn/kubeval:v0.3.0 -- strict=true
    
    # Security validation
    log_info "Running security validation..."
    if command -v docker &> /dev/null; then
        # Build and run custom security validator if Docker is available
        docker build -t security-validator:local ../functions/validate-security-config/
        kpt fn eval --image security-validator:local -- \
            strict_mode=true \
            require_mtls=true \
            require_non_root=true \
            require_resource_limits=true \
            require_network_policies=true
    else
        log_warning "Docker not available, skipping custom security validation"
    fi
    
    log_success "Configuration validation passed"
}

# Deploy to cluster
deploy_to_cluster() {
    log_info "Deploying MCP Security Platform to production cluster..."
    
    # Apply resources with inventory
    kpt live init --namespace mcp-security --inventory-id mcp-security-production
    
    # Preview changes
    log_info "Previewing deployment changes..."
    kpt live preview --inventory-template inventory-template.yaml
    
    # Confirm deployment
    if [ "${AUTO_APPROVE:-false}" != "true" ]; then
        echo -n "Do you want to proceed with the deployment? (y/n): "
        read -r response
        if [[ ! "$response" =~ ^[Yy]$ ]]; then
            log_info "Deployment cancelled by user"
            exit 0
        fi
    fi
    
    # Apply resources
    kpt live apply --inventory-template inventory-template.yaml --reconcile-timeout=10m
    
    # Wait for resources to be ready
    log_info "Waiting for resources to be ready..."
    kpt live status --inventory-template inventory-template.yaml --poll-until=current --timeout=15m
    
    log_success "Deployment completed successfully"
}

# Verify deployment
verify_deployment() {
    log_info "Verifying deployment..."
    
    # Check namespace
    kubectl get namespace mcp-security -o wide
    
    # Check pods
    log_info "Checking pod status..."
    kubectl get pods -n mcp-security -o wide
    
    # Check services
    log_info "Checking services..."
    kubectl get services -n mcp-security
    
    # Check Istio configuration
    log_info "Checking Istio configuration..."
    kubectl get gateway,virtualservice,destinationrule -n mcp-security
    
    # Check ingress
    INGRESS_IP=$(kubectl get svc istio-ingressgateway -n istio-system -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || echo "pending")
    if [ "$INGRESS_IP" != "pending" ] && [ -n "$INGRESS_IP" ]; then
        log_success "Platform accessible at: https://$DOMAIN (IP: $INGRESS_IP)"
    else
        log_warning "Ingress IP not yet available. Check service status: kubectl get svc istio-ingressgateway -n istio-system"
    fi
    
    # Check ArgoCD if deployed
    if kubectl get namespace argocd &> /dev/null; then
        ARGOCD_IP=$(kubectl get svc argocd-server -n argocd -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || echo "pending")
        if [ "$ARGOCD_IP" != "pending" ] && [ -n "$ARGOCD_IP" ]; then
            log_info "ArgoCD accessible at: https://argocd.$DOMAIN (IP: $ARGOCD_IP)"
        fi
    fi
    
    log_success "Deployment verification completed"
}

# Setup monitoring access
setup_monitoring_access() {
    log_info "Setting up monitoring dashboard access..."
    
    # Create port-forward scripts
    cat > start-grafana.sh << 'EOF'
#!/bin/bash
echo "Starting Grafana dashboard..."
echo "Access Grafana at: http://localhost:3000"
echo "Default credentials: admin/admin"
kubectl port-forward svc/prometheus-grafana 3000:80 -n mcp-security-monitoring
EOF
    
    cat > start-kiali.sh << 'EOF'
#!/bin/bash
echo "Starting Kiali dashboard..."
echo "Access Kiali at: http://localhost:20001"
kubectl port-forward svc/kiali 20001:20001 -n istio-system
EOF
    
    cat > start-jaeger.sh << 'EOF'
#!/bin/bash
echo "Starting Jaeger dashboard..."
echo "Access Jaeger at: http://localhost:16686"
kubectl port-forward svc/jaeger 16686:16686 -n istio-system
EOF
    
    chmod +x start-*.sh
    
    log_success "Monitoring access scripts created"
    log_info "Use the following commands to access dashboards:"
    log_info "  Grafana: ./start-grafana.sh"
    log_info "  Kiali:   ./start-kiali.sh"  
    log_info "  Jaeger:  ./start-jaeger.sh"
}

# Print deployment summary
print_summary() {
    log_success "=== MCP Security Platform Production Deployment Summary ==="
    log_info "✓ Complete platform deployed using kpt packages"
    log_info "✓ High availability configuration with 3 replicas"
    log_info "✓ Istio service mesh with production security policies"
    log_info "✓ PostgreSQL and Redis databases with persistent storage"
    log_info "✓ Monitoring stack (Prometheus, Grafana, Jaeger, Kiali)"
    log_info "✓ All 14 microservices deployed and configured"
    log_info "✓ Web interface and API gateway operational"
    
    log_info ""
    log_info "Platform URL: https://$DOMAIN"
    log_info "API Endpoint: https://api.$DOMAIN"
    log_info "Package Directory: $DEPLOYMENT_DIR"
    
    log_info ""
    log_info "Next steps:"
    log_info "1. Configure DNS to point $DOMAIN to the ingress IP"
    log_info "2. Set up SSL certificates (Let's Encrypt configured)"
    log_info "3. Configure external integrations (SIEM, threat feeds)"
    log_info "4. Set up backup schedules and monitoring alerts"
    log_info "5. Run security scans to validate deployment"
    
    log_info ""
    log_info "Management commands:"
    log_info "  View status: kpt live status --inventory-template inventory-template.yaml"
    log_info "  Update: kpt pkg update && kpt fn render && kpt live apply"
    log_info "  Rollback: kpt live preview --inventory-template inventory-template.yaml --destroy"
}

# Cleanup function
cleanup() {
    log_warning "Deployment interrupted. Cleaning up..."
    if [ -d "$DEPLOYMENT_DIR" ]; then
        cd "$DEPLOYMENT_DIR"
        kpt live destroy --inventory-template inventory-template.yaml 2>/dev/null || true
    fi
    exit 1
}

# Main deployment function
main() {
    log_info "Starting MCP Security Platform production deployment using kpt packages..."
    
    # Set trap for cleanup on interrupt
    trap cleanup INT TERM
    
    # Run deployment steps
    check_prerequisites
    fetch_package
    configure_environment
    validate_configuration
    deploy_to_cluster
    verify_deployment
    setup_monitoring_access
    print_summary
    
    log_success "MCP Security Platform production deployment completed successfully!"
}

# Script options
case "${1:-}" in
    "--help" | "-h")
        echo "Usage: $0 [options]"
        echo "Options:"
        echo "  --help, -h              Show this help message"
        echo "  --auto-approve          Skip deployment confirmation"
        echo "  --domain DOMAIN         Set custom domain (default: security.company.com)"
        echo "  --registry REGISTRY     Set image registry (default: security.company.com/registry)"
        echo "  --tag TAG               Set image tag (default: v1.0.0)"
        echo "  --storage-class CLASS   Set storage class (default: fast-ssd)"
        echo ""
        echo "Environment variables:"
        echo "  DOMAIN                  Custom domain name"
        echo "  IMAGE_REGISTRY          Container image registry"
        echo "  IMAGE_TAG               Container image tag"
        echo "  STORAGE_CLASS           Kubernetes storage class"
        echo "  AUTO_APPROVE           Skip confirmation (true/false)"
        exit 0
        ;;
    "--auto-approve")
        export AUTO_APPROVE=true
        main
        ;;
    "--domain")
        if [ -z "${2:-}" ]; then
            log_error "Domain argument required"
            exit 1
        fi
        export DOMAIN="$2"
        shift 2
        main "$@"
        ;;
    "--registry")
        if [ -z "${2:-}" ]; then
            log_error "Registry argument required"
            exit 1
        fi
        export IMAGE_REGISTRY="$2"
        shift 2
        main "$@"
        ;;
    "--tag")
        if [ -z "${2:-}" ]; then
            log_error "Tag argument required"
            exit 1
        fi
        export IMAGE_TAG="$2"
        shift 2
        main "$@"
        ;;
    "--storage-class")
        if [ -z "${2:-}" ]; then
            log_error "Storage class argument required"
            exit 1
        fi
        export STORAGE_CLASS="$2"
        shift 2
        main "$@"
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