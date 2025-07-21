#!/bin/bash

echo "🔧 Fixing MCP Platform deployment images..."

# Patch Redis StatefulSet to use correct image
echo "Patching Redis master..."
kubectl patch statefulset mcp-platform-redis-master -n mcp-security -p='{"spec":{"template":{"spec":{"containers":[{"name":"redis","image":"redis:7.2-alpine","command":["redis-server"],"args":["--requirepass","redis_password"]}]}}}}'

# Patch PostgreSQL StatefulSet  
echo "Patching PostgreSQL..."
kubectl patch statefulset mcp-platform-postgresql -n mcp-security -p='{"spec":{"template":{"spec":{"containers":[{"name":"postgresql","image":"postgres:13-alpine","env":[{"name":"POSTGRES_PASSWORD","value":"mcp_password"},{"name":"POSTGRES_USER","value":"mcp_user"},{"name":"POSTGRES_DB","value":"mcp_security"}]}]}}}}'

# Delete existing problematic pods to force recreation
echo "Deleting problematic pods..."
kubectl delete pod mcp-platform-redis-master-0 -n mcp-security --ignore-not-found=true
kubectl delete pod mcp-platform-postgresql-0 -n mcp-security --ignore-not-found=true

# Scale down replica counts to save resources
echo "Scaling down services to single replicas..."
kubectl scale deployment mcp-platform-analysis-service --replicas=1 -n mcp-security
kubectl scale deployment mcp-platform-auth-service --replicas=1 -n mcp-security
kubectl scale deployment mcp-platform-enrichment-service --replicas=1 -n mcp-security
kubectl scale deployment mcp-platform-gateway-service --replicas=1 -n mcp-security
kubectl scale deployment mcp-platform-ingestion-service --replicas=1 -n mcp-security
kubectl scale deployment mcp-platform-notification-service --replicas=1 -n mcp-security

# Wait for pods to start
echo "Waiting for pods to restart..."
sleep 15

# Show current status
echo "Current pod status:"
kubectl get pods -n mcp-security

echo "✅ Deployment fix completed!"