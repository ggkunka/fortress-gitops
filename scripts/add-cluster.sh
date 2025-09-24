#!/bin/bash

# Fortress Security Platform - Add Cluster Script
# Usage: ./add-cluster.sh <cluster-name> <cluster-type> <kubeconfig-path>

set -e

CLUSTER_NAME=$1
CLUSTER_TYPE=$2
KUBECONFIG_PATH=$3

if [ $# -ne 3 ]; then
    echo "Usage: $0 <cluster-name> <cluster-type> <kubeconfig-path>"
    echo "Example: $0 production-aws eks ~/.kube/aws-config"
    echo ""
    echo "Supported cluster types: eks, aks, gke, k3s, k8s, openshift"
    exit 1
fi

echo "🏰 Adding cluster to Fortress Security Platform..."
echo "Cluster Name: $CLUSTER_NAME"
echo "Cluster Type: $CLUSTER_TYPE"
echo "Kubeconfig: $KUBECONFIG_PATH"

# Validate kubeconfig exists
if [ ! -f "$KUBECONFIG_PATH" ]; then
    echo "❌ Error: Kubeconfig file not found at $KUBECONFIG_PATH"
    exit 1
fi

# Test cluster connectivity
echo "🔍 Testing cluster connectivity..."
if ! kubectl --kubeconfig="$KUBECONFIG_PATH" cluster-info > /dev/null 2>&1; then
    echo "❌ Error: Cannot connect to cluster using provided kubeconfig"
    exit 1
fi

# Get cluster info
CLUSTER_VERSION=$(kubectl --kubeconfig="$KUBECONFIG_PATH" version --short --client=false 2>/dev/null | grep "Server Version" | cut -d' ' -f3 || echo "unknown")
NODE_COUNT=$(kubectl --kubeconfig="$KUBECONFIG_PATH" get nodes --no-headers 2>/dev/null | wc -l || echo "0")

echo "✅ Cluster connectivity verified"
echo "   Version: $CLUSTER_VERSION"
echo "   Nodes: $NODE_COUNT"

# Create namespace for fortress agent
echo "🚀 Creating fortress-system namespace..."
kubectl --kubeconfig="$KUBECONFIG_PATH" create namespace fortress-system --dry-run=client -o yaml | \
kubectl --kubeconfig="$KUBECONFIG_PATH" apply -f -

# Generate agent token
AGENT_TOKEN=$(openssl rand -hex 32)
AGENT_TOKEN_B64=$(echo -n "$AGENT_TOKEN" | base64 -w 0)

# Create agent deployment with cluster-specific values
echo "📦 Deploying Fortress agent..."
sed -e "s/REPLACE_WITH_CLUSTER_NAME/$CLUSTER_NAME/g" \
    -e "s/REPLACE_WITH_CLUSTER_TYPE/$CLUSTER_TYPE/g" \
    -e "s/Zm9ydHJlc3MtYWdlbnQtdG9rZW4tMTIzNDU2Nzg5MA==/$AGENT_TOKEN_B64/g" \
    ../cluster-config/cluster-agent.yaml | \
kubectl --kubeconfig="$KUBECONFIG_PATH" apply -f -

# Encode kubeconfig for storage
KUBECONFIG_B64=$(base64 -w 0 < "$KUBECONFIG_PATH")

# Add cluster to fortress registry
echo "📋 Registering cluster with Fortress..."
cat << EOF > /tmp/cluster-entry.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: cluster-$CLUSTER_NAME
  namespace: mcp-security
data:
  cluster.yaml: |
    name: "$CLUSTER_NAME"
    type: "$CLUSTER_TYPE"
    status: "active"
    version: "$CLUSTER_VERSION"
    nodes: $NODE_COUNT
    agent_token: "$AGENT_TOKEN"
    added_date: "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
---
apiVersion: v1
kind: Secret
metadata:
  name: cluster-$CLUSTER_NAME-kubeconfig
  namespace: mcp-security
type: Opaque
data:
  kubeconfig: $KUBECONFIG_B64
EOF

# Apply to fortress cluster
kubectl apply -f /tmp/cluster-entry.yaml
rm /tmp/cluster-entry.yaml

echo "✅ Cluster $CLUSTER_NAME successfully added to Fortress Security Platform!"
echo ""
echo "🔗 Access your cluster in the web interface:"
echo "   URL: http://10.63.89.182:30080"
echo "   Login: admin / admin123"
echo "   Navigate to: Live Cluster tab"
echo ""
echo "📊 The agent will start reporting cluster data within 2-3 minutes."
echo "🔍 Monitor agent status: kubectl --kubeconfig='$KUBECONFIG_PATH' get pods -n fortress-system"
