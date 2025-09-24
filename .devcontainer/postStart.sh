#!/bin/bash

# MCP Security Platform - Post Start Command  
# This script runs after the devcontainer starts

set -e

echo "🚀 Starting MCP Security Platform POC..."
echo "========================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${BLUE}ℹ️  $1${NC}"; }
log_success() { echo -e "${GREEN}✅ $1${NC}"; }
log_warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }

# Check if POC should auto-deploy
AUTO_DEPLOY=${MCP_AUTO_DEPLOY:-true}

if [ "$AUTO_DEPLOY" = "true" ]; then
    log_info "Auto-deploying MCP Security Platform POC..."
    
    # Wait a bit for Docker to be fully ready
    sleep 10
    
    # Run the setup script in background
    nohup bash ./scripts/codespace-setup.sh > /workspace/logs/poc-setup.log 2>&1 &
    
    log_info "POC deployment started in background"
    log_info "Check progress: tail -f /workspace/logs/poc-setup.log"
    log_info "Manual setup: ./scripts/codespace-setup.sh"
else
    log_warning "Auto-deploy disabled. Run './scripts/codespace-setup.sh' manually"
fi

# Display welcome message
cat << 'EOF'

   ╔═══════════════════════════════════════════════════════════╗
   ║                                                           ║
   ║        🛡️  MCP Security Platform POC                      ║
   ║                                                           ║
   ║  Welcome to GitHub Codespaces!                           ║
   ║                                                           ║
   ║  📚 Quick Start Guide: .github/codespace-poc.md          ║
   ║  🚀 Setup POC:         ./scripts/codespace-setup.sh      ║
   ║  📊 Check Status:      mcp-status                        ║
   ║  🏥 Health Check:      mcp-health                        ║
   ║                                                           ║
   ║  🔗 Service URLs (when ready):                           ║
   ║     API Gateway:    http://localhost:8000                ║
   ║     Auth Service:   http://localhost:8001                ║
   ║     Core Services:  http://localhost:8080                ║
   ║     MinIO Console:  http://localhost:9000                ║
   ║                                                           ║
   ╚═══════════════════════════════════════════════════════════╝

EOF

log_success "Environment ready! Happy hacking! 🎉"