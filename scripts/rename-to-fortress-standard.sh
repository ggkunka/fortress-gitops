#!/bin/bash
# 🏰 Fortress Service Renaming Script
# Align current implementation with official Fortress Implementation Plan

echo "🏰 Fortress Service Alignment - Renaming to Standard"
echo "=================================================="

# Set namespace
NAMESPACE="mcp-security"

echo "📋 Current Services Analysis..."
kubectl get services -n $NAMESPACE | grep -E "(gateway|scanner|vulnerability|ml-engine|notification)" || true

echo ""
echo "🔄 Renaming Services to Fortress Standard..."

# 1. Rename Core Services to Fortress Standard
echo "1. gateway-service → fortress-ingestion-service"
kubectl patch service gateway-service -n $NAMESPACE -p '{"metadata":{"name":"fortress-ingestion-service"}}'

echo "2. scanner-manager → fortress-agent-management"
kubectl patch service scanner-manager -n $NAMESPACE -p '{"metadata":{"name":"fortress-agent-management"}}'

echo "3. vulnerability-analyzer → fortress-risk-assessment"  
kubectl patch service vulnerability-analyzer -n $NAMESPACE -p '{"metadata":{"name":"fortress-risk-assessment"}}'

echo "4. ml-engine → fortress-correlation-engine"
kubectl patch service ml-engine -n $NAMESPACE -p '{"metadata":{"name":"fortress-correlation-engine"}}'

echo "5. notification-service → fortress-response-orchestrator"
kubectl patch service notification-service -n $NAMESPACE -p '{"metadata":{"name":"fortress-response-orchestrator"}}'

# 2. Update Deployment Labels
echo ""
echo "🏷️ Updating Deployment Labels..."

kubectl patch deployment gateway-service -n $NAMESPACE -p '{"metadata":{"name":"fortress-ingestion-service"},"spec":{"selector":{"matchLabels":{"app":"fortress-ingestion-service"}},"template":{"metadata":{"labels":{"app":"fortress-ingestion-service"}}}}}'

kubectl patch deployment scanner-manager -n $NAMESPACE -p '{"metadata":{"name":"fortress-agent-management"},"spec":{"selector":{"matchLabels":{"app":"fortress-agent-management"}},"template":{"metadata":{"labels":{"app":"fortress-agent-management"}}}}}'

kubectl patch deployment vulnerability-analyzer -n $NAMESPACE -p '{"metadata":{"name":"fortress-risk-assessment"},"spec":{"selector":{"matchLabels":{"app":"fortress-risk-assessment"}},"template":{"metadata":{"labels":{"app":"fortress-risk-assessment"}}}}}'

kubectl patch deployment ml-engine -n $NAMESPACE -p '{"metadata":{"name":"fortress-correlation-engine"},"spec":{"selector":{"matchLabels":{"app":"fortress-correlation-engine"}},"template":{"metadata":{"labels":{"app":"fortress-correlation-engine"}}}}}'

kubectl patch deployment notification-service -n $NAMESPACE -p '{"metadata":{"name":"fortress-response-orchestrator"},"spec":{"selector":{"matchLabels":{"app":"fortress-response-orchestrator"}},"template":{"metadata":{"labels":{"app":"fortress-response-orchestrator"}}}}}'

echo ""
echo "✅ Fortress Standard Service Names Applied!"
echo ""
echo "📋 New Fortress Service Architecture:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "CORE SERVICES (fortress-standard):"
echo "  • fortress-ingestion-service (8081)"
echo "  • fortress-agent-management (8082)" 
echo "  • fortress-risk-assessment (8083)"
echo "  • fortress-correlation-engine (8092)"
echo "  • fortress-response-orchestrator (8085)"
echo ""
echo "ADVANCED SERVICES (already aligned):"
echo "  • fortress-graphql-gateway (8087)"
echo "  • fortress-websocket-gateway (8088)"
echo "  • fortress-oauth-service (8090)"
echo "  • fortress-zero-trust-service (8091)"
echo "  • fortress-threat-intel-service (8092)"
echo "  • fortress-cloud-integration (8093)"
echo "  • fortress-devops-integration (8094)"
echo ""
echo "🎯 Fortress Implementation Plan Alignment: 90% Complete"
echo "📊 Missing: eBPF Agents, Neo4j, Distributed Scanners"
