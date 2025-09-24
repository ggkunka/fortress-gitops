# GitHub Codespaces Troubleshooting Guide

## 🚨 **Common Issues and Solutions**

### **Issue 1: Codespace Disconnection/Terminal Freezing**

**Symptoms:**
- Terminal becomes unresponsive after running setup scripts
- Codespace disconnects during Helm deployment
- Browser shows "Disconnected" or loading indefinitely

**Root Cause:**
- Resource optimization may be too aggressive for 2-core/8GB Codespace
- Kubernetes cluster consuming too much memory/CPU
- Multiple concurrent processes overwhelming the environment

**Recovery Steps:**

#### **Option A: Reconnect Existing Codespace**
```bash
# 1. Go to GitHub → Your Repo → Code → Codespaces
# 2. Click "Open in browser" on existing Codespace
# 3. If still frozen, proceed to Option B
```

#### **Option B: Restart Codespace**
```bash
# 1. In GitHub Codespaces settings, find your Codespace
# 2. Click "Stop" → Wait 30 seconds → Click "Start"
# 3. Once restarted, check resource usage:
df -h
free -h
docker ps
```

#### **Option C: Create New Codespace**
```bash
# 1. Delete problematic Codespace in GitHub settings
# 2. Create fresh Codespace from repository
# 3. Use Docker Compose instead of Kubernetes (see below)
```

### **Issue 2: Helm Deployment Timeout**

**Symptoms:**
- "context deadline exceeded" errors
- Helm deployment hangs during installation
- Pods stuck in Pending state

**Solutions:**

#### **Quick Fix: Use Docker Compose**
```bash
# Instead of Kubernetes, use lightweight Docker setup:
cd .devcontainer/
docker-compose up -d postgres redis

# Start minimal services manually:
cd ../services/gateway/
python main.py &

cd ../auth/
python main.py &
```

#### **Conservative Kubernetes Deployment**
```bash
# Use more conservative resource settings:
helm upgrade --install mcp-platform ./deployments/helm/mcp-platform \
    --namespace mcp-security \
    --set postgresql.primary.resources.requests.memory="512Mi" \
    --set redis.master.resources.requests.memory="256Mi" \
    --timeout=3m \
    --wait=false
```

### **Issue 3: Resource Exhaustion**

**Symptoms:**
- Pods in Pending state with "Insufficient memory" errors
- Node resource allocation warnings
- Slow performance or freezing

**Diagnostics:**
```bash
# Check resource usage:
kubectl describe nodes
kubectl top nodes
kubectl get pods -n mcp-security -o wide

# Check events for resource issues:
kubectl get events -n mcp-security --sort-by='.lastTimestamp'
```

**Solutions:**
```bash
# Scale down resource-heavy services:
kubectl scale deployment mcp-platform-postgresql --replicas=0 -n mcp-security
kubectl scale deployment mcp-platform-redis-master --replicas=0 -n mcp-security

# Use minimal configuration:
helm upgrade mcp-platform ./deployments/helm/mcp-platform \
    --set prometheus.enabled=false \
    --set grafana.enabled=false \
    --set postgresql.primary.persistence.enabled=false \
    --set redis.master.persistence.enabled=false
```

## 🛠️ **Fallback Deployment Methods**

### **Method 1: Docker Compose (Recommended for Codespaces)**

Create minimal `docker-compose-poc.yml`:
```yaml
version: '3.8'
services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: mcp_security
      POSTGRES_USER: mcp_user
      POSTGRES_PASSWORD: mcp_password
    ports:
      - "5432:5432"
    tmpfs: /var/lib/postgresql/data  # No persistence for speed
    
  redis:
    image: redis:7-alpine
    command: redis-server --requirepass redis_password
    ports:
      - "6379:6379"
    tmpfs: /data  # No persistence for speed
    
  gateway:
    build: ./services/gateway/
    ports:
      - "8000:8000"
    depends_on:
      - postgres
      - redis
    environment:
      DATABASE_URL: postgresql://mcp_user:mcp_password@postgres:5432/mcp_security
      REDIS_URL: redis://:redis_password@redis:6379
```

Deploy:
```bash
cd .devcontainer/
docker-compose -f docker-compose-poc.yml up -d
```

### **Method 2: Local Python Services**

```bash
# Start services directly with Python:
cd services/gateway/
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000 &

cd ../auth/
uvicorn main:app --host 0.0.0.0 --port 8001 &

# Test:
curl http://localhost:8000/health
curl http://localhost:8001/health
```

## 🔧 **Prevention Strategies**

### **For Future Sessions:**

1. **Use 4-core/16GB Codespace** if available
2. **Start with Docker Compose** instead of Kubernetes
3. **Monitor resources** before deployment:
   ```bash
   free -h && df -h
   ```
4. **Deploy incrementally**:
   ```bash
   # Start with databases only:
   helm install postgres bitnami/postgresql
   # Then add services one by one
   ```

### **Resource Monitoring Commands:**
```bash
# Check before deployment:
free -h                    # Memory usage
df -h                     # Disk usage
docker system df          # Docker space usage
kubectl top nodes         # Kubernetes resource usage

# Clean up if needed:
docker system prune -f    # Clean Docker
kind delete cluster --name mcp-poc  # Reset cluster
```

## 📞 **Emergency Recovery Checklist**

If Codespace becomes completely unresponsive:

- [ ] Try browser refresh (Ctrl+F5)
- [ ] Check GitHub Codespaces status page
- [ ] Stop/Start Codespace in GitHub settings
- [ ] Create new Codespace if needed
- [ ] Use Docker Compose instead of Kubernetes
- [ ] Contact GitHub Support if recurring issues

## ✅ **Success Indicators**

A working POC should have:
- [ ] Terminal responsive and accessible
- [ ] Basic services responding: `curl http://localhost:8000/health`
- [ ] Demo script completes without timeouts
- [ ] Resource usage under 4GB RAM, 1.5 CPU cores
- [ ] No persistent "Insufficient resources" errors

**Remember: The goal is a working demo, not perfect resource optimization!**