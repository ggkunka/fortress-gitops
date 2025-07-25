# MCP Security Platform - kpt Packages

This directory contains the kpt package-based deployment configuration for the MCP Security Platform. The architecture follows a package-centric approach with proper dependency management, configuration functions, and environment-specific deployments.

## Package Architecture

```
packages/
├── platform-packages/           # Core platform packages
│   ├── infrastructure/          # Infrastructure layer packages
│   │   ├── istio-package/       # Service mesh package
│   │   ├── monitoring-package/  # Observability stack package
│   │   └── databases-package/   # Database layer package
│   ├── core-services/          # Platform core services
│   │   ├── mcp-server-package/ # MCP protocol server
│   │   ├── auth-service-package/ # Authentication service
│   │   ├── gateway-package/    # API gateway service
│   │   └── notification-package/ # Notification service
│   └── applications/           # Business application packages
│       ├── security-services-package/ # Security analysis services
│       ├── web-ui-package/     # React web interface
│       ├── integrations-package/ # External integrations
│       └── marketplace-package/ # Plugin marketplace
├── deployment-packages/        # Environment-specific deployments
│   ├── production-deployment/  # Production environment
│   ├── staging-deployment/     # Staging environment
│   └── development-deployment/ # Development environment  
├── functions/                  # Custom kpt functions
│   ├── validate-security-config/ # Security policy validation
│   ├── generate-certificates/  # Certificate generation
│   ├── optimize-resources/     # Resource optimization
│   └── update-image-tags/      # Image tag management
└── shared/                     # Shared configurations
    ├── base-configs/           # Common configurations
    └── setters/                # Configuration setters
```

## kpt Package Benefits

### 1. **Package Composition**
- **Modular architecture** with clear dependencies
- **Reusable components** across environments
- **Version-controlled packages** with semantic versioning
- **Automatic dependency resolution**

### 2. **Configuration Functions**
- **Built-in validation** for security policies
- **Automated resource optimization** based on environment
- **Certificate management** and injection
- **Image tag updates** with rollback capabilities

### 3. **Environment Management**
- **Declarative environment configuration** using setters
- **Package hydration** for environment-specific values
- **Consistent deployments** across dev/staging/production
- **Configuration drift detection** and remediation

## Package Dependency Graph

```
deployment-packages/production-deployment/
├── depends on: platform-packages/infrastructure/
│   ├── istio-package/
│   ├── monitoring-package/
│   └── databases-package/
├── depends on: platform-packages/core-services/
│   ├── mcp-server-package/ (depends on: databases-package)
│   ├── auth-service-package/ (depends on: databases-package)
│   ├── gateway-package/ (depends on: auth-service-package)
│   └── notification-package/ (depends on: databases-package)
└── depends on: platform-packages/applications/
    ├── security-services-package/ (depends on: core-services/)
    ├── web-ui-package/ (depends on: gateway-package)
    ├── integrations-package/ (depends on: core-services/)
    └── marketplace-package/ (depends on: core-services/)
```

## Quick Start

### Prerequisites
- **kpt CLI** v1.0.0+
- **kubectl** configured for your cluster
- **ArgoCD** with kpt plugin enabled

### 1. Fetch Package for Production Deployment
```bash
# Fetch the production deployment package
kpt pkg get https://github.com/ggkunka/mcp-security-platform.git/packages/deployment-packages/production-deployment mcp-security-prod

cd mcp-security-prod
```

### 2. Configure Environment
```bash
# Set environment-specific values
kpt fn eval --image gcr.io/kpt-fn/apply-setters:v0.2.0 -- \
  environment=production \
  replicas=3 \
  domain=security.company.com \
  resource_cpu=1000m \
  resource_memory=2Gi
```

### 3. Validate Configuration
```bash
# Run validation functions
kpt fn eval --image gcr.io/kpt-fn/validate:v0.2.0
kpt fn eval --image security.company.com/kpt-functions/security-validator:v1.0.0
```

### 4. Deploy with ArgoCD
```bash
# Apply to cluster via ArgoCD
kubectl apply -f argocd-application.yaml
```

## Package Development Workflow

### Creating a New Package
```bash
# Initialize new package
kpt pkg init my-new-service-package
cd my-new-service-package

# Add dependencies
kpt pkg get https://github.com/ggkunka/mcp-security-platform.git/packages/platform-packages/infrastructure/databases-package databases

# Create Kptfile with dependencies
cat > Kptfile << EOF
apiVersion: kpt.dev/v1
kind: Kptfile
metadata:
  name: my-new-service
dependencies:
- name: databases
  upstream:
    type: git
    git:
      repo: https://github.com/ggkunka/mcp-security-platform
      directory: /packages/platform-packages/infrastructure/databases-package
      ref: v1.0.0
pipeline:
  validators:
  - image: gcr.io/kpt-fn/validate-security-policies:v0.1.0
EOF
```

### Updating Packages
```bash
# Update to latest version
kpt pkg update my-package@v1.1.0

# Update all dependencies
kpt pkg update --strategy force-delete-replace
```

### Package Validation
```bash
# Validate package structure
kpt pkg validate

# Run all pipeline functions
kpt fn render

# Check for configuration drift
kpt live status --inventory-template inventory-template.yaml
```

## Configuration Functions

### Security Validation Function
```yaml
# Validates security policies and configurations
apiVersion: v1
kind: ConfigMap
metadata:
  name: security-validator-config
data:
  config.yaml: |
    rules:
    - name: require-istio-mtls
      message: "All services must have Istio mTLS enabled"
      check: "spec.mtls.mode == 'STRICT'"
    - name: require-resource-limits
      message: "All containers must have resource limits"
      check: "spec.containers[*].resources.limits != null"
    - name: require-non-root
      message: "Containers must not run as root"
      check: "spec.securityContext.runAsNonRoot == true"
```

### Resource Optimization Function
```yaml
# Optimizes resources based on environment
apiVersion: v1
kind: ConfigMap
metadata:
  name: resource-optimizer-config
data:
  config.yaml: |
    environments:
      development:
        cpu_multiplier: 0.5
        memory_multiplier: 0.5
        replicas: 1
      staging:
        cpu_multiplier: 0.8
        memory_multiplier: 0.8
        replicas: 2
      production:
        cpu_multiplier: 1.5
        memory_multiplier: 2.0
        replicas: 3
```

## Environment-Specific Deployments

### Production Configuration
```yaml
# Kptfile for production deployment
apiVersion: kpt.dev/v1
kind: Kptfile
metadata:
  name: mcp-security-production
pipeline:
  mutators:
  - image: gcr.io/kpt-fn/apply-setters:v0.2.0
    configMap:
      environment: production
      domain: security.company.com
      replicas: "3"
      enable_high_availability: "true"
      enable_backup: "true"
      log_level: "info"
  validators:
  - image: security.company.com/kpt-functions/security-validator:v1.0.0
    configMap:
      strict_mode: "true"
      require_mtls: "true"
      require_resource_limits: "true"
```

### Development Configuration
```yaml
# Kptfile for development deployment
apiVersion: kpt.dev/v1
kind: Kptfile
metadata:
  name: mcp-security-development
pipeline:
  mutators:
  - image: gcr.io/kpt-fn/apply-setters:v0.2.0
    configMap:
      environment: development
      domain: dev.security.company.com
      replicas: "1"
      enable_high_availability: "false"
      enable_backup: "false"
      log_level: "debug"
  validators:
  - image: gcr.io/kpt-fn/validate:v0.2.0
```

## Integration with ArgoCD

### ArgoCD Application with kpt Plugin
```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: mcp-security-platform
  namespace: argocd
spec:
  project: mcp-security-platform
  source:
    repoURL: https://github.com/ggkunka/mcp-security-platform
    path: packages/deployment-packages/production-deployment
    plugin:
      name: kpt
      env:
      - name: KPT_FN_CONFIG_ENVIRONMENT
        value: production
      - name: KPT_FN_CONFIG_DOMAIN
        value: security.company.com
  destination:
    server: https://kubernetes.default.svc
    namespace: mcp-security
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
    - CreateNamespace=true
```

## Best Practices

### Package Versioning
- Use **semantic versioning** (v1.0.0, v1.1.0, v2.0.0)
- **Tag releases** for stable package versions
- **Pin dependencies** to specific versions in production
- **Test package updates** in development first

### Configuration Management
- Use **setters** for environment-specific values
- **Validate configurations** with pipeline functions
- **Keep secrets** in external secret management systems
- **Document configuration** options in package README

### Dependency Management
- **Minimize dependencies** where possible
- **Version lock** dependencies in production
- **Test dependency updates** in isolation
- **Document dependency** requirements and compatibility

This kpt package-based approach provides superior configuration management, validation, and deployment capabilities for the MCP Security Platform, ensuring consistent, secure, and maintainable deployments across all environments.