# MCP Security Platform - Manual Startup Guide

## After Host Reboot - Quick Start

### 1. One-Command Startup (Recommended)
```bash
cd /mnt/c/Users/nsjay/mcp-security-platform
./start-poc-demo.sh
```

### 2. Manual Step-by-Step Startup

#### Prerequisites Check
```bash
# Ensure Docker Desktop is running with Kubernetes enabled
docker ps
kubectl cluster-info
```

#### Start Infrastructure
```bash
# Add Helm repositories
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo update

# Deploy databases
helm install redis bitnami/redis --set auth.enabled=false --set architecture=standalone
helm install postgresql bitnami/postgresql --set auth.postgresPassword=password --set architecture=standalone

# Wait for pods
kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=redis --timeout=120s
kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=postgresql --timeout=120s
```

#### Setup Port Forwarding
```bash
# Database access
kubectl port-forward svc/redis-master 6379:6379 &
kubectl port-forward svc/postgresql 5432:5432 &
```

#### Start Web Server
```bash
# Ensure scanning tools are in PATH
export PATH="$HOME/bin:$PATH"

# Start the interactive web server
python3 web-poc-server.py &
```

### 3. Verify Everything is Running

```bash
# Check system status
curl http://localhost:8080/api/status

# Check Kubernetes pods
kubectl get pods

# Check port forwarding
netstat -tlnp | grep -E "(6379|5432|8080)"
```

## Access Points

- **🌐 Web Dashboard:** http://localhost:8080
- **📚 API Documentation:** http://localhost:8080/docs  
- **🔴 Redis:** localhost:6379
- **🐘 PostgreSQL:** localhost:5432 (password: `password`)

## Quick Demo Test

1. Open browser → http://localhost:8080
2. Enter container image: `redis:8.0.3`
3. Click "Start Vulnerability Scan"
4. After scan completes, click "Analyze with AI"
5. View results in dashboard

## Cleanup Commands

```bash
# Stop web server
pkill -f 'web-poc-server.py'

# Stop port forwarding
pkill -f 'kubectl port-forward'

# Remove databases (optional)
helm uninstall redis postgresql
```

## Troubleshooting

### Docker/Kubernetes Issues
- Restart Docker Desktop
- Ensure Kubernetes is enabled in Docker Desktop settings
- Check available resources (CPU/Memory)

### Web Server Issues
```bash
# Check server logs
tail -f poc-server.log

# Restart server
pkill -f 'web-poc-server.py'
python3 web-poc-server.py &
```

### Scanning Tools Issues
```bash
# Reinstall scanning tools
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b ~/bin
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b ~/bin
```

## Production Considerations

For production deployment:
1. Use proper secrets management
2. Configure persistent storage for databases
3. Set up proper TLS certificates
4. Implement authentication and authorization
5. Use environment-specific configurations
6. Set up monitoring and logging