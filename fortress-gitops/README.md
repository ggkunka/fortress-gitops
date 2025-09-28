# Fortress Security Platform - GitOps Deployment

## 🏰 Cloud Native Application Protection Platform

This repository contains GitOps manifests for deploying the **Fortress Security Platform** - a comprehensive container registry security scanning and vulnerability management platform.

### 🎯 What is Fortress?

Fortress is a modern CNAPP (Cloud Native Application Protection Platform) that provides:

- **📦 Container Registry Integration** - Scans multiple registry types (Quay, Docker Hub, Harbor, ECR, GCR)
- **🔍 Vulnerability Scanning** - Deep image security analysis and reporting
- **🚀 Deployment Tracking** - GitOps vs Direct deployment visibility
- **📊 Security Dashboard** - Comprehensive security posture management
- **🗄️ Database Backend** - SQLite/PostgreSQL for persistent data storage
- **🌐 Modern UI** - React-based responsive security interface

### 🏗️ Platform Components

#### 🔧 **Fortress Backend**
- **FastAPI Server** - REST API for security operations
- **Repository Manager** - Multi-registry integration
- **Vulnerability Scanner** - Security analysis engine
- **Deployment Tracker** - GitOps detection and tracking
- **Database Service** - Data persistence layer

#### 🌐 **Fortress Frontend** 
- **React Application** - Modern security dashboard
- **Material-UI Design** - Professional responsive interface
- **Nginx Proxy** - Static file serving and API routing
- **Real-time Updates** - Live security status monitoring

#### 🗄️ **Fortress Database**
- **PostgreSQL** - Production database (or SQLite for dev)
- **SQLAlchemy Models** - Repository and image metadata
- **Migration Support** - Schema versioning and upgrades

### 🚀 GitOps Deployment Architecture

```
environments/
├── dev/           # Development environment
├── staging/       # Staging environment  
└── prod/          # Production environment

applications/      # ArgoCD Application manifests
base/             # Base Kubernetes manifests
helm-charts/      # Helm charts for Fortress components
```

### 📊 Target Registry Integration

**Currently Integrated:**
- ✅ **Nokia OpenShift Quay Registry** - 81 container images
- ✅ **Private Authentication** - Docker Registry v2 token auth
- ✅ **Multi-Project Support** - Quay project/namespace scanning

**Expandable To:**
- 🔧 Docker Hub repositories
- 🔧 Harbor enterprise registries
- 🔧 AWS ECR, Google GCR, Azure ACR

### 🎯 Security Features

- **🔐 Registry Authentication** - Secure credential management
- **📈 Vulnerability Tracking** - CVE identification and scoring
- **🚀 Deployment Monitoring** - Track GitOps vs direct deployments
- **📊 Compliance Reporting** - Security posture dashboards
- **🔄 Automated Scanning** - Continuous security monitoring

### 🚀 Quick Start

1. **Deploy ArgoCD**:
   ```bash
   kubectl create namespace argocd
   kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml
   ```

2. **Deploy Fortress Platform**:
   ```bash
   kubectl apply -f applications/
   ```

3. **Access Fortress Dashboard**:
   ```bash
   kubectl port-forward -n fortress-prod svc/fortress-frontend 3000:80
   ```

### 📋 What Fortress Monitors

The platform currently monitors and secures:
- **41 IMS Core Network Functions** (nokia-ims-icscf, nokia-ims-scscf, etc.)
- **12 IMS Support Services** (admin, CLI, health monitoring)
- **16 Infrastructure Components** (controllers, monitoring, security)
- **12 Base/Utility Components** (init containers, proxies)

**Total: 81 container images under security management** 🔒

---

**Deployed from**: https://github.com/ggkunka/fortress-gitops
