#!/bin/bash

echo "🗄️ Deploying simple Redis and PostgreSQL..."

# Remove problematic StatefulSets
kubectl delete statefulset mcp-platform-redis-master -n mcp-security --ignore-not-found=true
kubectl delete statefulset mcp-platform-postgresql -n mcp-security --ignore-not-found=true

# Wait for cleanup
sleep 5

# Deploy simple Redis and PostgreSQL
kubectl apply -f simple-redis-postgres.yaml

# Wait for pods to be ready
echo "Waiting for database pods to be ready..."
kubectl wait --for=condition=ready pod --selector=app=redis -n mcp-security --timeout=60s
kubectl wait --for=condition=ready pod --selector=app=postgresql -n mcp-security --timeout=60s

# Show status
echo "Database deployment status:"
kubectl get pods -n mcp-security -l app=redis
kubectl get pods -n mcp-security -l app=postgresql

echo "✅ Simple Redis and PostgreSQL deployed!"