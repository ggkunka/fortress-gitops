# MCP Security Platform - kpt Package Deployment Guide

This guide provides comprehensive instructions for deploying the MCP Security Platform using kpt packages. The kpt package-based approach provides superior configuration management, validation, and deployment capabilities compared to traditional GitOps methods.

## Architecture Overview

The MCP Security Platform is organized into a hierarchical package structure:

```
packages/
├── platform-packages/           # Core reusable packages
│   ├── infrastructure/          # Infrastructure layer
│   ├── core-services/          # Platform core services  
│   └── applications/           # Business applications
├── deployment-packages/        # Environment-specific deployments
│   ├── production-deployment/  # Production configuration
│   ├── staging-deployment/     # Staging configuration
│   └── development-deployment/ # Development configuration
├── functions/                  # Custom kpt functions
└── scripts/                   # Deployment automation
```

## Prerequisites

### System Requirements
- **Kubernetes cluster** v1.24+ with:
  - Minimum: 16 CPU cores, 64GB RAM, 500GB storage
  - Recommended: 24+ CPU cores, 128GB+ RAM, 1TB+ storage
- **Storage class** configured (e.g., `fast-ssd`)
- **Load balancer** for ingress (MetalLB, cloud provider, etc.)
- **DNS** configuration capability

### Required Tools
- **kpt CLI** v1.0.0+
- **kubectl** configured for your cluster
- **Docker** (optional, for building custom functions)
- **Git** for package management

### Installation Commands
```bash
# Install kpt CLI
curl -s https://get.kpt.dev | bash

# Verify installation
kpt version
kubectl version --client
```

## Quick Start Deployment

### 1. Production Deployment (Automated)
```bash
# Clone repository
git clone https://github.com/ggkunka/mcp-security-platform.git
cd mcp-security-platform/packages

# Run automated production deployment
./scripts/deploy-production.sh \
  --domain security.yourdomain.com \
  --registry your-registry.com \
  --tag v1.0.0 \
  --storage-class fast-ssd
```

### 2. Manual Deployment (Step-by-step)
```bash
# 1. Fetch production package
kpt pkg get https://github.com/ggkunka/mcp-security-platform.git/packages/deployment-packages/production-deployment mcp-security-prod

cd mcp-security-prod

# 2. Configure environment
kpt fn eval --image gcr.io/kpt-fn/apply-setters:v0.2.0 -- \
  environment=production \
  domain=security.yourdomain.com \
  image_registry=your-registry.com \
  image_tag=v1.0.0 \
  replicas=3 \
  storage_class=fast-ssd

# 3. Validate configuration
kpt fn render
kpt fn eval --image gcr.io/kpt-fn/kubeval:v0.3.0

# 4. Initialize and deploy
kpt live init --namespace mcp-security
kpt live apply --reconcile-timeout=10m

# 5. Check status
kpt live status --poll-until=current
```

## Environment-Specific Deployments

### Production Environment
```bash
# Production-optimized configuration
kpt fn eval --image gcr.io/kpt-fn/apply-setters:v0.2.0 -- \
  environment=production \
  replicas=3 \
  high_availability=true \
  enable_backups=true \
  enable_mtls=true \
  storage_class=fast-ssd \
  postgresql_storage_size=200Gi \
  postgresql_replicas=2 \
  log_level=info
```

### Staging Environment
```bash
# Staging configuration  
kpt fn eval --image gcr.io/kpt-fn/apply-setters:v0.2.0 -- \
  environment=staging \
  replicas=2 \
  high_availability=false \
  enable_backups=false \
  storage_class=standard \
  postgresql_storage_size=50Gi \
  postgresql_replicas=1 \
  log_level=debug
```

### Development Environment
```bash
# Development configuration
kpt fn eval --image gcr.io/kpt-fn/apply-setters:v0.2.0 -- \
  environment=development \
  replicas=1 \
  high_availability=false \
  enable_backups=false \
  storage_class=standard \
  postgresql_storage_size=20Gi \
  redis_storage_size=5Gi \
  log_level=debug \
  enable_debug=true
```

## Package Configuration

### Available Setters

#### Global Configuration
| Setter | Description | Default | Example |
|--------|-------------|---------|---------|
| `environment` | Target environment | `production` | `development`, `staging`, `production` |
| `domain` | Base domain | `security.company.com` | `security.yourdomain.com` |
| `image_registry` | Container registry | `security.company.com/registry` | `your-registry.com` |
| `image_tag` | Image tag | `v1.0.0` | `v1.1.0`, `latest` |

#### Scaling Configuration
| Setter | Description | Default | Production | Staging | Development |
|--------|-------------|---------|------------|---------|-------------|
| `replicas` | Default replicas | `3` | `3` | `2` | `1` |
| `high_availability` | Enable HA | `true` | `true` | `false` | `false` |
| `postgresql_replicas` | DB replicas | `2` | `2` | `1` | `1` |

#### Security Configuration
| Setter | Description | Default | Notes |
|--------|-------------|---------|--------|
| `enable_mtls` | Mutual TLS | `true` | Required for production |
| `enable_authorization` | AuthZ policies | `true` | Istio authorization |
| `enable_tracing` | Distributed tracing | `true` | Jaeger integration |
| `enable_waf` | Web Application Firewall | `true` | Envoy filters |

#### Resource Configuration
| Setter | Description | Default | Production | Development |
|--------|-------------|---------|------------|-------------|
| `cpu_requests` | CPU requests | `500m` | `1000m` | `200m` |
| `memory_requests` | Memory requests | `1Gi` | `2Gi` | `512Mi` |
| `cpu_limits` | CPU limits | `2000m` | `4000m` | `500m` |
| `memory_limits` | Memory limits | `4Gi` | `8Gi` | `1Gi` |

#### Storage Configuration
| Setter | Description | Default | Production | Development |
|--------|-------------|---------|------------|-------------|
| `storage_class` | Storage class | `fast-ssd` | `fast-ssd` | `standard` |
| `postgresql_storage_size` | PostgreSQL storage | `200Gi` | `500Gi` | `20Gi` |
| `redis_storage_size` | Redis storage | `50Gi` | `100Gi` | `5Gi` |

### Example Configuration Commands
```bash
# Minimal configuration
kpt fn eval --image gcr.io/kpt-fn/apply-setters:v0.2.0 -- \
  domain=security.example.com

# Full production configuration
kpt fn eval --image gcr.io/kpt-fn/apply-setters:v0.2.0 -- \
  environment=production \
  domain=security.example.com \
  image_registry=registry.example.com \
  image_tag=v1.2.0 \
  replicas=3 \
  high_availability=true \
  enable_backups=true \
  storage_class=premium-ssd \
  postgresql_storage_size=500Gi \
  postgresql_replicas=3 \
  cpu_requests=1000m \
  memory_requests=2Gi
```

## Validation and Security

### Built-in Validations
The kpt packages include multiple validation layers:

#### Kubernetes Resource Validation
```bash
# Validate Kubernetes resources
kpt fn eval --image gcr.io/kpt-fn/kubeval:v0.3.0 -- strict=true
```

#### Security Validation
```bash
# Run security validation function
kpt fn eval --image security.company.com/kpt-functions/security-validator:v1.0.0 -- \
  strict_mode=true \
  require_mtls=true \
  require_non_root=true \
  require_resource_limits=true \
  require_network_policies=true
```

#### Production Readiness Validation
```bash
# Validate production readiness
kpt fn eval --image security.company.com/kpt-functions/production-validator:v1.0.0 -- \
  require_high_availability=true \
  require_backups=true \
  min_replicas=2
```

### Custom Validation Rules
The security validator checks for:
- **Container security contexts** (non-root, read-only filesystem)
- **Resource limits** and requests
- **Istio mTLS** configuration
- **Network policies** presence
- **Pod security standards** compliance
- **Authorization policies** validation

## ArgoCD Integration

### Install ArgoCD with kpt Plugin
```bash
# Install ArgoCD
kubectl create namespace argocd
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml

# Install kpt plugin for ArgoCD
kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: argocd-cm
  namespace: argocd
data:
  configManagementPlugins: |
    - name: kpt
      generate:
        command: [sh, -c]
        args: ["kpt fn render && kpt fn eval --image gcr.io/kpt-fn/apply-setters:v0.2.0"]
EOF
```

### Create ArgoCD Application
```bash
# Apply ArgoCD application
kubectl apply -f packages/deployment-packages/production-deployment/argocd-application.yaml
```

### ArgoCD Configuration
The ArgoCD application automatically:
- Syncs kpt packages from Git repository
- Applies environment-specific setters
- Runs validation functions
- Deploys resources with proper dependency ordering
- Provides drift detection and self-healing

## Monitoring and Observability

### Access Monitoring Dashboards
```bash
# Grafana (metrics and dashboards)
kubectl port-forward svc/prometheus-grafana 3000:80 -n mcp-security-monitoring
# Access: http://localhost:3000 (admin/admin)

# Kiali (service mesh visualization)
kubectl port-forward svc/kiali 20001:20001 -n istio-system
# Access: http://localhost:20001

# Jaeger (distributed tracing)
kubectl port-forward svc/jaeger 16686:16686 -n istio-system
# Access: http://localhost:16686

# ArgoCD (GitOps management)
kubectl port-forward svc/argocd-server 8080:443 -n argocd
# Access: https://localhost:8080
```

### Monitoring Stack Components
- **Prometheus**: Metrics collection and alerting
- **Grafana**: Dashboards and visualization
- **Jaeger**: Distributed tracing
- **Kiali**: Service mesh observability
- **AlertManager**: Alert routing and notifications

## Package Management

### Updating Packages
```bash
# Update to latest version
kpt pkg update mcp-security-prod@v1.1.0

# Update all dependencies
kpt pkg update --strategy force-delete-replace

# Apply updates
kpt fn render
kpt live apply --reconcile-timeout=10m
```

### Package Dependencies
Dependencies are automatically managed:
```yaml
dependencies:
- name: databases-infrastructure
  upstream:
    type: git
    git:
      repo: https://github.com/ggkunka/mcp-security-platform
      directory: /packages/platform-packages/infrastructure/databases-package
      ref: v1.0.0
```

### Rollback Procedures
```bash
# Preview rollback
kpt live preview --destroy

# Rollback to previous version
git checkout v1.0.0
kpt fn render
kpt live apply

# Check rollback status
kpt live status --poll-until=current
```

## Troubleshooting

### Common Issues

#### 1. Package Fetch Failures
```bash
# Issue: Cannot fetch package
# Solution: Check repository access and path
kpt pkg get --help
git ls-remote https://github.com/ggkunka/mcp-security-platform.git
```

#### 2. Validation Failures
```bash
# Issue: Security validation fails
# Solution: Review and fix security contexts
kpt fn eval --image gcr.io/kpt-fn/kubeval:v0.3.0 -- strict=false
```

#### 3. Resource Conflicts
```bash
# Issue: Resource already exists
# Solution: Use live operations or force update
kpt live preview --inventory-template inventory-template.yaml
kpt live apply --force-conflicts
```

#### 4. Storage Class Issues
```bash
# Issue: Storage class not found
# Solution: Check available storage classes
kubectl get storageclass
kpt fn eval --image gcr.io/kpt-fn/apply-setters:v0.2.0 -- storage_class=standard
```

### Debug Commands
```bash
# Check package structure
kpt pkg tree

# Validate package
kpt pkg validate

# Check live resources
kpt live status --inventory-template inventory-template.yaml

# View resource details
kubectl describe pods -n mcp-security
kubectl get events -n mcp-security --sort-by='.lastTimestamp'
```

### Log Analysis
```bash
# Application logs
kubectl logs -f deployment/mcp-server -n mcp-security

# Istio proxy logs
kubectl logs -f deployment/mcp-server -c istio-proxy -n mcp-security

# Controller logs
kubectl logs -f deployment/istiod -n istio-system
```

## Security Considerations

### Production Security Checklist
- [ ] **mTLS enabled** across all services
- [ ] **Authorization policies** configured
- [ ] **Network policies** in place
- [ ] **Pod security contexts** properly set
- [ ] **Resource limits** configured
- [ ] **Non-root containers** enforced
- [ ] **Read-only root filesystems** where possible
- [ ] **Secrets management** properly configured
- [ ] **Image scanning** enabled
- [ ] **Backup procedures** tested

### Security Validation Commands
```bash
# Run comprehensive security check
kpt fn eval --image security.company.com/kpt-functions/security-validator:v1.0.0 -- \
  strict_mode=true \
  require_mtls=true \
  require_non_root=true \
  require_read_only_fs=true \
  require_resource_limits=true \
  require_network_policies=true \
  scan_for_vulnerabilities=true
```

## Performance Tuning

### Resource Optimization
```bash
# Optimize for production environment
kpt fn eval --image security.company.com/kpt-functions/resource-optimizer:v1.0.0 -- \
  environment=production \
  cpu_multiplier=1.5 \
  memory_multiplier=2.0 \
  enable_affinity_rules=true
```

### Scaling Configuration
```bash
# Configure horizontal pod autoscaling
kpt fn eval --image gcr.io/kpt-fn/apply-setters:v0.2.0 -- \
  enable_hpa=true \
  min_replicas=3 \
  max_replicas=10 \
  target_cpu_utilization=70
```

## Backup and Recovery

### Backup Procedures
```bash
# Backup kpt package configuration
kpt pkg tree > package-backup.yaml
kubectl get all,pv,pvc,secrets,configmaps -n mcp-security -o yaml > resources-backup.yaml

# Backup database
kubectl exec -n mcp-security postgresql-0 -- pg_dump -U mcp_user mcp_security > database-backup.sql
```

### Disaster Recovery
```bash
# Complete platform recovery
kpt pkg get https://github.com/ggkunka/mcp-security-platform.git/packages/deployment-packages/production-deployment mcp-security-recovery
cd mcp-security-recovery
kpt fn render
kpt live init --namespace mcp-security
kpt live apply --reconcile-timeout=15m
```

This comprehensive deployment guide provides everything needed to successfully deploy and manage the MCP Security Platform using kpt packages. The package-based approach ensures consistent, secure, and maintainable deployments across all environments.