# 🏰 Adding Clusters to Fortress Security Platform

## Overview
The Fortress Security Platform supports multi-cluster management, allowing you to monitor and manage multiple Kubernetes clusters from a single interface.

## Methods to Add Clusters

### Method 1: Automated Script (Recommended)

Use the provided script to automatically add clusters:

```bash
cd /home/ubuntu/mcp-security-platform
./scripts/add-cluster.sh <cluster-name> <cluster-type> <kubeconfig-path>
```

**Example:**
```bash
# Add AWS EKS cluster
./scripts/add-cluster.sh production-aws eks ~/.kube/aws-config

# Add Azure AKS cluster  
./scripts/add-cluster.sh staging-azure aks ~/.kube/azure-config

# Add Google GKE cluster
./scripts/add-cluster.sh dev-gcp gke ~/.kube/gcp-config

# Add another K3s cluster
./scripts/add-cluster.sh edge-k3s k3s ~/.kube/edge-config
```

**Supported Cluster Types:**
- `eks` - Amazon EKS
- `aks` - Azure AKS
- `gke` - Google GKE
- `k3s` - Rancher K3s
- `k8s` - Standard Kubernetes
- `openshift` - Red Hat OpenShift

### Method 2: Manual Configuration

#### Step 1: Prepare Kubeconfig
Ensure you have a valid kubeconfig file for your cluster:

```bash
# Test connectivity
kubectl --kubeconfig=/path/to/your/kubeconfig cluster-info
```

#### Step 2: Deploy Fortress Agent
Deploy the Fortress agent to your target cluster:

```bash
# Create namespace
kubectl --kubeconfig=/path/to/your/kubeconfig create namespace fortress-system

# Deploy agent (modify cluster-agent.yaml with your cluster details)
kubectl --kubeconfig=/path/to/your/kubeconfig apply -f cluster-config/cluster-agent.yaml
```

#### Step 3: Register with Fortress
Add cluster configuration to the Fortress platform:

```bash
kubectl apply -f cluster-config/add-cluster.yaml
```

### Method 3: Via Web Interface

1. **Access Fortress Platform:**
   - URL: http://10.63.89.182:30080
   - Login: `admin` / `admin123`

2. **Navigate to Cluster Management:**
   - Click "Live Cluster" tab
   - Click "Add Cluster" button
   - Fill in cluster details
   - Upload kubeconfig file

## Cluster Requirements

### Prerequisites
- Kubernetes cluster (v1.20+)
- Network connectivity to Fortress platform (10.63.89.182:30080)
- Cluster admin permissions
- Valid kubeconfig file

### Network Requirements
- Outbound HTTPS (443) access from cluster to Fortress
- Outbound HTTP (30080) access to 10.63.89.182
- DNS resolution for fortress endpoints

### RBAC Permissions
The Fortress agent requires these permissions:
- Read access to pods, services, nodes, namespaces
- Read access to deployments, replicasets, daemonsets
- Read access to ingresses

## Cloud Provider Specific Instructions

### AWS EKS
```bash
# Get kubeconfig
aws eks update-kubeconfig --region us-west-2 --name your-cluster-name

# Add to Fortress
./scripts/add-cluster.sh production-aws eks ~/.kube/config
```

### Azure AKS
```bash
# Get kubeconfig
az aks get-credentials --resource-group myResourceGroup --name myAKSCluster

# Add to Fortress
./scripts/add-cluster.sh production-azure aks ~/.kube/config
```

### Google GKE
```bash
# Get kubeconfig
gcloud container clusters get-credentials your-cluster-name --zone us-central1-a

# Add to Fortress
./scripts/add-cluster.sh production-gcp gke ~/.kube/config
```

### Rancher K3s
```bash
# Copy kubeconfig from K3s server
scp user@k3s-server:/etc/rancher/k3s/k3s.yaml ~/.kube/k3s-config
# Edit server URL in kubeconfig

# Add to Fortress
./scripts/add-cluster.sh edge-k3s k3s ~/.kube/k3s-config
```

## Verification

### Check Agent Status
```bash
# On target cluster
kubectl --kubeconfig=/path/to/kubeconfig get pods -n fortress-system

# Should show fortress-agent pod running
```

### Check Fortress Dashboard
1. Login to http://10.63.89.182:30080
2. Navigate to "Live Cluster" tab
3. Your cluster should appear in the list
4. Status should show "Connected" with live metrics

### Check Logs
```bash
# Agent logs
kubectl --kubeconfig=/path/to/kubeconfig logs -n fortress-system deployment/fortress-agent

# Fortress platform logs
kubectl logs -n mcp-security deployment/web-interface
```

## Troubleshooting

### Common Issues

**1. Connection Refused**
- Check network connectivity: `telnet 10.63.89.182 30080`
- Verify firewall rules
- Check kubeconfig server URL

**2. Permission Denied**
- Verify RBAC permissions
- Check service account configuration
- Ensure cluster admin access

**3. Agent Not Starting**
- Check image availability
- Verify resource limits
- Check namespace creation

**4. Cluster Not Appearing**
- Check agent logs
- Verify token configuration
- Check Fortress platform logs

### Debug Commands
```bash
# Test connectivity
curl -v http://10.63.89.182:30080/health

# Check agent status
kubectl --kubeconfig=/path/to/kubeconfig describe pod -n fortress-system

# Check fortress configuration
kubectl get configmap cluster-registry -n mcp-security -o yaml
```

## Security Considerations

### Network Security
- Use VPN or private networks when possible
- Implement network policies
- Monitor agent communications

### RBAC Security
- Use least privilege principle
- Regular token rotation
- Monitor agent permissions

### Data Security
- Kubeconfig files contain sensitive data
- Store securely and encrypt at rest
- Regular credential rotation

## Support

For issues or questions:
1. Check logs first
2. Verify network connectivity
3. Review RBAC permissions
4. Contact platform administrator

## Next Steps

After adding clusters:
1. Configure monitoring alerts
2. Set up security policies
3. Enable compliance scanning
4. Configure backup strategies
5. Set up disaster recovery
