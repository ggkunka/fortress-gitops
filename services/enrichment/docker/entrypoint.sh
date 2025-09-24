#!/bin/bash
set -e

# Enrichment Service Entrypoint Script

echo "Starting MCP Security Platform - Enrichment Service"
echo "Timestamp: $(date -Iseconds)"
echo "User: $(whoami)"
echo "Working Directory: $(pwd)"

# Environment configuration
export PYTHONPATH="/app:${PYTHONPATH}"

# Default configuration
export ENRICHMENT_HOST="${ENRICHMENT_HOST:-0.0.0.0}"
export ENRICHMENT_PORT="${ENRICHMENT_PORT:-8082}"
export ENRICHMENT_WORKERS="${ENRICHMENT_WORKERS:-1}"
export LOG_LEVEL="${LOG_LEVEL:-info}"

# Redis configuration
export REDIS_URL="${REDIS_URL:-redis://redis:6379/0}"
export REDIS_PASSWORD="${REDIS_PASSWORD:-}"
export REDIS_MAX_CONNECTIONS="${REDIS_MAX_CONNECTIONS:-10}"

# Service configuration
export MAX_CONCURRENT_TASKS="${MAX_CONCURRENT_TASKS:-10}"
export ENRICHMENT_TIMEOUT="${ENRICHMENT_TIMEOUT:-300}"
export CACHE_TTL="${CACHE_TTL:-3600}"

# Threat intelligence API configuration (optional)
export MISP_URL="${MISP_URL:-}"
export MISP_API_KEY="${MISP_API_KEY:-}"
export VIRUSTOTAL_API_KEY="${VIRUSTOTAL_API_KEY:-}"
export OTX_API_KEY="${OTX_API_KEY:-}"
export URLVOID_API_KEY="${URLVOID_API_KEY:-}"

# Wait for dependencies
wait_for_service() {
    local host=$1
    local port=$2
    local service_name=$3
    local max_attempts=30
    local attempt=1

    echo "Waiting for $service_name at $host:$port..."
    
    while [ $attempt -le $max_attempts ]; do
        if timeout 5 bash -c "</dev/tcp/$host/$port" 2>/dev/null; then
            echo "$service_name is available!"
            return 0
        fi
        
        echo "Attempt $attempt/$max_attempts: $service_name not yet available, waiting..."
        sleep 2
        attempt=$((attempt + 1))
    done
    
    echo "WARNING: $service_name at $host:$port is not available after $max_attempts attempts"
    return 1
}

# Extract Redis host and port from URL for dependency check
REDIS_HOST=$(echo "$REDIS_URL" | sed -n 's/redis:\/\/\([^:]*\):.*/\1/p')
REDIS_PORT=$(echo "$REDIS_URL" | sed -n 's/redis:\/\/[^:]*:\([0-9]*\).*/\1/p')

if [ -n "$REDIS_HOST" ] && [ -n "$REDIS_PORT" ]; then
    wait_for_service "$REDIS_HOST" "$REDIS_PORT" "Redis"
else
    echo "WARNING: Could not parse Redis connection details from REDIS_URL: $REDIS_URL"
fi

# Pre-flight checks
echo "Performing pre-flight checks..."

# Check Python version
python3.11 --version

# Check required modules
python3.11 -c "
import sys
required_modules = [
    'fastapi', 'uvicorn', 'redis', 'httpx', 'structlog', 
    'pydantic', 'asyncio', 'json', 'hashlib'
]

missing = []
for module in required_modules:
    try:
        __import__(module)
        print(f'✓ {module}')
    except ImportError:
        missing.append(module)
        print(f'✗ {module}')

if missing:
    print(f'ERROR: Missing required modules: {missing}')
    sys.exit(1)
else:
    print('All required modules are available')
"

# Validate configuration
python3.11 -c "
import os
import sys

# Check critical environment variables
critical_vars = ['REDIS_URL', 'ENRICHMENT_HOST', 'ENRICHMENT_PORT']
missing_vars = []

for var in critical_vars:
    if not os.getenv(var):
        missing_vars.append(var)

if missing_vars:
    print(f'ERROR: Missing critical environment variables: {missing_vars}')
    sys.exit(1)

print('Configuration validation passed')
"

# Create log directory if it doesn't exist
mkdir -p /app/logs

# Set up logging configuration
cat > /app/logging.conf << EOF
[loggers]
keys=root

[handlers]
keys=consoleHandler,fileHandler

[formatters]
keys=structuredFormatter

[logger_root]
level=${LOG_LEVEL^^}
handlers=consoleHandler,fileHandler

[handler_consoleHandler]
class=StreamHandler
level=${LOG_LEVEL^^}
formatter=structuredFormatter
args=(sys.stdout,)

[handler_fileHandler]
class=FileHandler
level=${LOG_LEVEL^^}
formatter=structuredFormatter
args=('/app/logs/enrichment.log',)

[formatter_structuredFormatter]
format=%(asctime)s - %(name)s - %(levelname)s - %(message)s
datefmt=%Y-%m-%d %H:%M:%S
EOF

echo "Configuration:"
echo "  Service: Enrichment"
echo "  Host: $ENRICHMENT_HOST"
echo "  Port: $ENRICHMENT_PORT"
echo "  Workers: $ENRICHMENT_WORKERS"
echo "  Log Level: $LOG_LEVEL"
echo "  Redis URL: ${REDIS_URL%%@*}@***"  # Hide credentials
echo "  Max Concurrent Tasks: $MAX_CONCURRENT_TASKS"
echo "  Python Path: $PYTHONPATH"

# Handle shutdown gracefully
shutdown() {
    echo "Received shutdown signal, gracefully stopping enrichment service..."
    kill -TERM "$child" 2>/dev/null
    wait "$child"
    echo "Enrichment service stopped"
    exit 0
}

trap 'shutdown' SIGTERM SIGINT

# Start the service
echo "Starting enrichment service..."
echo "Command: $*"

if [ $# -eq 0 ]; then
    # Default command
    exec python3.11 -m services.enrichment.main
else
    # Execute provided command
    exec "$@" &
    child=$!
    wait "$child"
fi