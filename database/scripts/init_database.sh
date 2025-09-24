#!/bin/bash
# Fortress Security Database Initialization Script

set -e

echo "🏗️ Initializing Fortress Security Database Architecture"

# Deploy database stack
echo "📊 Deploying PostgreSQL, Redis, and Elasticsearch..."
kubectl apply -f /home/ubuntu/mcp-security-platform/database/deployment/database_stack.yaml

# Wait for PostgreSQL to be ready
echo "⏳ Waiting for PostgreSQL to be ready..."
kubectl wait --for=condition=ready pod -l app=fortress-postgresql -n fortress-system --timeout=300s

# Wait for Redis to be ready
echo "⏳ Waiting for Redis to be ready..."
kubectl wait --for=condition=ready pod -l app=fortress-redis -n fortress-system --timeout=300s

# Wait for Elasticsearch to be ready
echo "⏳ Waiting for Elasticsearch to be ready..."
kubectl wait --for=condition=ready pod -l app=fortress-elasticsearch -n fortress-system --timeout=600s

# Initialize database schema
echo "🗄️ Creating database schema..."
kubectl exec -it $(kubectl get pods -l app=fortress-postgresql -n fortress-system -o jsonpath='{.items[0].metadata.name}') -n fortress-system -- \
  psql -U fortress_user -d fortress_security -f /docker-entrypoint-initdb.d/02-create-tables.sql

# Create Elasticsearch indices
echo "🔍 Creating Elasticsearch indices..."
curl -X PUT "fortress-elasticsearch:9200/fortress_security_events" \
  -H 'Content-Type: application/json' \
  -d @/home/ubuntu/mcp-security-platform/database/elasticsearch/es_indices.json

# Test connections
echo "🧪 Testing database connections..."
python3 -c "
import asyncio
from database.models.fortress_db import db

async def test():
    await db.connect()
    cluster_id = await db.register_cluster('test-cluster', 'https://test.local')
    print(f'✅ Test cluster registered: {cluster_id}')

asyncio.run(test())
"

echo "✅ Fortress Security Database Architecture deployed successfully!"
echo "📊 Access points:"
echo "   PostgreSQL: fortress-postgresql:5432"  
echo "   Redis: fortress-redis:6379"
echo "   Elasticsearch: fortress-elasticsearch:9200"
