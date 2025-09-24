# Agent-Harbor On-Demand Image Workflow

## 🔄 Process Flow

### 1. Agent Image Request
```python
# Agent requests image from Fortress
response = requests.post("http://fortress:8001/request-image", 
    json={"tool_name": "trivy", "agent_id": "agent-001"})
request_id = response.json()["request_id"]
```

### 2. Fortress Sync Process  
```bash
# Fortress pulls from Docker Hub
docker pull aquasec/trivy:latest

# Tag for Harbor
docker tag aquasec/trivy:latest 10.63.89.182:30500/security/trivy:latest

# Push to Harbor
docker push 10.63.89.182:30500/security/trivy:latest
```

### 3. Agent Job Creation
```yaml
# Agent creates job with Harbor image
spec:
  containers:
  - image: 10.63.89.182:30500/security/trivy:latest
    imagePullSecrets:
    - name: harbor-registry-secret
```

### 4. Post-Scan Cleanup
```python
# Delete job and cleanup images
kubectl delete job trivy-scan-001
docker system prune -f  # On compute node
```

## 🔧 Implementation Files

1. **fortress-image-api.py** - Image sync service
2. **harbor-integration.py** - Agent Harbor client  
3. **agent-harbor-config.yaml** - K8s secrets & config
4. **harbor-deployment.yaml** - Harbor registry setup

## 🎯 Key Benefits

- ✅ On-demand image availability
- ✅ No pre-loading required
- ✅ Automatic cleanup after scan
- ✅ Air-gapped security maintained
