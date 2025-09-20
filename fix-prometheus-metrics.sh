#!/bin/bash

# Fix Prometheus metrics collision in advanced services
set -e

echo "🔧 Fixing Prometheus metrics collision in advanced services..."

# Fix GraphQL Gateway
echo "Fixing GraphQL Gateway..."
cd services/graphql-gateway

# Create a backup
cp main.py main.py.backup

# Fix the Prometheus metrics registration
sed -i 's/graphql_requests = Counter/try:\n    graphql_requests = Counter/g' main.py
sed -i 's/graphql_duration = Histogram/    graphql_duration = Histogram/g' main.py
sed -i '/graphql_duration = Histogram/a except ValueError:\n    # Metrics already registered, get existing ones\n    from prometheus_client import REGISTRY\n    graphql_requests = None\n    graphql_duration = None\n    for collector in list(REGISTRY._collector_to_names.keys()):\n        if hasattr(collector, "_name"):\n            if collector._name == "graphql_requests_total":\n                graphql_requests = collector\n            elif collector._name == "graphql_request_duration_seconds":\n                graphql_duration = collector' main.py

cd ../..

# Fix WebSocket Gateway
echo "Fixing WebSocket Gateway..."
cd services/websocket-gateway

# Create a backup
cp main.py main.py.backup

# Fix the Prometheus metrics registration
sed -i 's/websocket_connections = Gauge/try:\n    websocket_connections = Gauge/g' main.py
sed -i '/websocket_connections = Gauge/a except ValueError:\n    # Metrics already registered, get existing one\n    from prometheus_client import REGISTRY\n    websocket_connections = None\n    for collector in list(REGISTRY._collector_to_names.keys()):\n        if hasattr(collector, "_name") and collector._name == "websocket_connections_active":\n            websocket_connections = collector\n            break' main.py

cd ../..

echo "✅ Prometheus metrics fixes applied!"
echo "Now rebuilding the images..."
