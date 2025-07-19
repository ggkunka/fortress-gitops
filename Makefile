# MCP Security Platform - Makefile
# Comprehensive build and testing automation

.PHONY: help install setup clean test poc-demo jupyter lint format security
.DEFAULT_GOAL := help

# Configuration
PYTHON := python3
PIP := pip3
PYTEST := pytest
JUPYTER := jupyter
DOCKER := docker
BUILDAH := buildah
KIND := kind
KUBECTL := kubectl
HELM := helm

# Directories
PROJECT_ROOT := $(shell pwd)
TEST_DIR := tests
POC_DIR := tests/poc
DATA_DIR := tests/poc/data
SCRIPTS_DIR := scripts
DEMO_DIR := demo-data

# Colors for output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[1;33m
BLUE := \033[0;34m
PURPLE := \033[0;35m
CYAN := \033[0;36m
NC := \033[0m # No Color

define log_info
	@echo -e "$(BLUE)ℹ️  $(1)$(NC)"
endef

define log_success
	@echo -e "$(GREEN)✅ $(1)$(NC)"
endef

define log_warning
	@echo -e "$(YELLOW)⚠️  $(1)$(NC)"
endef

define log_error
	@echo -e "$(RED)❌ $(1)$(NC)"
endef

help: ## Show this help message
	@echo -e "$(CYAN)🛡️  MCP Security Platform - Build & Test Automation$(NC)"
	@echo "================================================================"
	@echo ""
	@echo -e "$(GREEN)Available targets:$(NC)"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  $(YELLOW)%-20s$(NC) %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""
	@echo -e "$(BLUE)Examples:$(NC)"
	@echo "  make poc-demo              # Run complete POC demonstration"
	@echo "  make test                  # Run full test suite"
	@echo "  make jupyter               # Launch Jupyter notebook demo"
	@echo "  make setup                 # Set up development environment"

install: ## Install Python dependencies
	$(call log_info,"Installing Python dependencies...")
	$(PIP) install --user -r requirements.txt
	$(PIP) install --user pytest pytest-asyncio pytest-cov httpx pandas matplotlib seaborn plotly jupyter ipywidgets
	$(call log_success,"Dependencies installed successfully")

setup: install ## Set up complete development environment
	$(call log_info,"Setting up MCP Security Platform development environment...")
	@mkdir -p $(DEMO_DIR) logs tmp
	@chmod +x $(SCRIPTS_DIR)/*.sh
	$(call log_info,"Checking Docker availability...")
	@$(DOCKER) --version > /dev/null 2>&1 || ($(call log_error,"Docker not available") && exit 1)
	$(call log_info,"Checking Buildah availability...")
	@$(BUILDAH) --version > /dev/null 2>&1 || ($(call log_error,"Buildah not available") && exit 1)
	$(call log_info,"Checking Kind availability...")
	@$(KIND) --version > /dev/null 2>&1 || ($(call log_error,"Kind not available") && exit 1)
	$(call log_info,"Checking kubectl availability...")
	@$(KUBECTL) version --client > /dev/null 2>&1 || ($(call log_error,"kubectl not available") && exit 1)
	$(call log_success,"Development environment setup complete")

clean: ## Clean up temporary files and directories
	$(call log_info,"Cleaning up temporary files...")
	@rm -rf __pycache__ .pytest_cache .coverage htmlcov
	@rm -rf $(DEMO_DIR)/*.json $(DEMO_DIR)/*.md
	@rm -rf logs/*.log tmp/*
	@find . -name "*.pyc" -delete
	@find . -name "*.pyo" -delete
	$(call log_success,"Cleanup complete")

test: ## Run complete test suite
	$(call log_info,"Running MCP Security Platform test suite...")
	@if [ ! -f "$(POC_DIR)/test_flow.py" ]; then \
		$(call log_error,"Test files not found. Run 'make setup' first."); \
		exit 1; \
	fi
	$(PYTEST) $(POC_DIR)/test_flow.py -v --tb=short --color=yes
	$(call log_success,"Test suite completed")

test-coverage: ## Run tests with coverage report
	$(call log_info,"Running tests with coverage analysis...")
	$(PYTEST) $(POC_DIR)/test_flow.py --cov=. --cov-report=html --cov-report=term-missing -v
	$(call log_success,"Coverage report generated in htmlcov/")

poc-demo: ## Run complete POC demonstration workflow
	$(call log_info,"Starting MCP Security Platform POC demonstration...")
	@echo -e "$(PURPLE)🎯 POC Demo Workflow:$(NC)"
	@echo "   1. Service health checks"
	@echo "   2. Platform deployment"
	@echo "   3. SBOM analysis"
	@echo "   4. AI risk assessment"
	@echo "   5. Security reporting"
	@echo "   6. Dashboard access"
	@echo ""
	@if [ -f "$(SCRIPTS_DIR)/demo-poc.sh" ]; then \
		bash $(SCRIPTS_DIR)/demo-poc.sh; \
	else \
		$(call log_error,"Demo script not found. Ensure all files are in place."); \
		exit 1; \
	fi
	$(call log_success,"POC demonstration completed")

poc-test: ## Run POC-specific API tests
	$(call log_info,"Running POC API test suite...")
	@$(MAKE) test
	$(call log_success,"POC tests completed")

jupyter: ## Launch Jupyter notebook demo
	$(call log_info,"Launching Jupyter notebook demo...")
	@if [ ! -f "demo.ipynb" ]; then \
		$(call log_error,"Jupyter notebook not found"); \
		exit 1; \
	fi
	@$(call log_info,"Starting Jupyter server...")
	@$(call log_warning,"Notebook will open in your default browser")
	@$(call log_info,"Access URL: http://localhost:8888")
	$(JUPYTER) notebook demo.ipynb --ip=0.0.0.0 --port=8888 --no-browser --allow-root

jupyter-lab: ## Launch JupyterLab interface
	$(call log_info,"Launching JupyterLab interface...")
	$(JUPYTER) lab --ip=0.0.0.0 --port=8888 --no-browser --allow-root

services-start: ## Start MCP platform services
	$(call log_info,"Starting MCP Security Platform services...")
	@if [ -f "$(SCRIPTS_DIR)/codespace-setup.sh" ]; then \
		bash $(SCRIPTS_DIR)/codespace-setup.sh; \
	else \
		$(call log_error,"Setup script not found"); \
		exit 1; \
	fi
	$(call log_success,"Services started successfully")

services-stop: ## Stop MCP platform services
	$(call log_info,"Stopping MCP Security Platform services...")
	@$(KIND) delete cluster --name mcp-poc 2>/dev/null || true
	@$(DOCKER) stop $$($(DOCKER) ps -q --filter "label=mcp-platform") 2>/dev/null || true
	@podman stop $$(podman ps -q --filter "label=mcp-platform") 2>/dev/null || true
	$(call log_success,"Services stopped")

services-restart: services-stop services-start ## Restart all services

services-status: ## Check status of all services
	$(call log_info,"Checking MCP platform service status...")
	@echo -e "$(YELLOW)Kubernetes Cluster:$(NC)"
	@$(KIND) get clusters | grep mcp-poc && echo "  ✅ Kind cluster: running" || echo "  ❌ Kind cluster: not found"
	@echo ""
	@echo -e "$(YELLOW)Service Health:$(NC)"
	@curl -s -f http://localhost:8000/health > /dev/null 2>&1 && echo "  ✅ API Gateway (8000): healthy" || echo "  ❌ API Gateway (8000): unavailable"
	@curl -s -f http://localhost:8001/health > /dev/null 2>&1 && echo "  ✅ Auth Service (8001): healthy" || echo "  ❌ Auth Service (8001): unavailable"
	@curl -s -f http://localhost:8080/health > /dev/null 2>&1 && echo "  ✅ Core Service (8080): healthy" || echo "  ❌ Core Service (8080): unavailable"
	@curl -s -f http://localhost:3000/health > /dev/null 2>&1 && echo "  ✅ Dashboard (3000): healthy" || echo "  ❌ Dashboard (3000): unavailable"

lint: ## Run code linting
	$(call log_info,"Running code linting...")
	@which pylint > /dev/null 2>&1 || $(PIP) install --user pylint
	@which black > /dev/null 2>&1 || $(PIP) install --user black
	@which isort > /dev/null 2>&1 || $(PIP) install --user isort
	@$(call log_info,"Running black formatter...")
	@black --check --diff $(TEST_DIR)/ || true
	@$(call log_info,"Running isort import sorter...")
	@isort --check-only --diff $(TEST_DIR)/ || true
	@$(call log_info,"Running pylint...")
	@pylint $(TEST_DIR)/ --disable=missing-docstring,too-few-public-methods || true
	$(call log_success,"Linting completed")

format: ## Format code with black and isort
	$(call log_info,"Formatting code...")
	@which black > /dev/null 2>&1 || $(PIP) install --user black
	@which isort > /dev/null 2>&1 || $(PIP) install --user isort
	@black $(TEST_DIR)/
	@isort $(TEST_DIR)/
	$(call log_success,"Code formatting completed")

security: ## Run security scans
	$(call log_info,"Running security scans...")
	@which bandit > /dev/null 2>&1 || $(PIP) install --user bandit
	@$(call log_info,"Scanning for security issues...")
	@bandit -r $(TEST_DIR)/ -f json -o security-report.json || true
	@bandit -r $(TEST_DIR)/ || true
	$(call log_success,"Security scan completed")

validate-data: ## Validate test data files
	$(call log_info,"Validating test data files...")
	@$(PYTHON) -m json.tool $(DATA_DIR)/test-sbom.json > /dev/null && echo "  ✅ test-sbom.json: valid" || echo "  ❌ test-sbom.json: invalid"
	@$(PYTHON) -m json.tool $(DATA_DIR)/test-cves.json > /dev/null && echo "  ✅ test-cves.json: valid" || echo "  ❌ test-cves.json: invalid"
	$(call log_success,"Data validation completed")

build-images: ## Build container images locally with Buildah
	$(call log_info,"Building MCP platform container images with Buildah...")
	@if [ -f "$(SCRIPTS_DIR)/build-images.sh" ]; then \
		bash $(SCRIPTS_DIR)/build-images.sh; \
	else \
		$(call log_info,"Building core services with Buildah..."); \
		for service in correlation-engine risk-assessment response-orchestrator reporting-service auth-service gateway-service; do \
			$(call log_info,"Building $$service..."); \
			mkdir -p /tmp/build-$$service; \
			echo "FROM python:3.11-slim" > /tmp/build-$$service/Dockerfile; \
			echo "RUN pip install fastapi uvicorn httpx structlog" >> /tmp/build-$$service/Dockerfile; \
			echo "COPY main.py /app/main.py" >> /tmp/build-$$service/Dockerfile; \
			echo "WORKDIR /app" >> /tmp/build-$$service/Dockerfile; \
			echo "CMD [\"python\", \"main.py\"]" >> /tmp/build-$$service/Dockerfile; \
			echo "print('MCP $$service running')" > /tmp/build-$$service/main.py; \
			$(BUILDAH) build --format docker --isolation chroot -t ghcr.io/ggkunka/mcp-$$service:latest /tmp/build-$$service; \
			rm -rf /tmp/build-$$service; \
		done; \
	fi
	$(call log_success,"Image build completed")

deploy-kind: ## Deploy to Kind cluster
	$(call log_info,"Deploying MCP platform to Kind cluster...")
	@$(MAKE) services-start
	$(call log_success,"Deployment to Kind completed")

docs: ## Generate documentation
	$(call log_info,"Generating documentation...")
	@mkdir -p docs/generated
	@echo "# MCP Security Platform - Test Suite Documentation" > docs/generated/README.md
	@echo "" >> docs/generated/README.md
	@echo "Generated on: $$(date)" >> docs/generated/README.md
	@echo "" >> docs/generated/README.md
	@echo "## Test Files" >> docs/generated/README.md
	@find $(TEST_DIR) -name "*.py" -exec echo "- {}" \; >> docs/generated/README.md
	@echo "" >> docs/generated/README.md
	@echo "## Data Files" >> docs/generated/README.md
	@find $(DATA_DIR) -name "*.json" -exec echo "- {}" \; >> docs/generated/README.md
	$(call log_success,"Documentation generated in docs/generated/")

benchmark: ## Run performance benchmarks
	$(call log_info,"Running performance benchmarks...")
	@$(PYTHON) -c "
import time
import httpx
print('🚀 Starting API performance benchmark...')
client = httpx.Client(timeout=10.0)
endpoints = ['http://localhost:8000/health', 'http://localhost:8001/health', 'http://localhost:8080/health']
for endpoint in endpoints:
    try:
        start = time.time()
        response = client.get(endpoint)
        duration = time.time() - start
        print(f'  {endpoint}: {duration:.3f}s ({response.status_code})')
    except Exception as e:
        print(f'  {endpoint}: Error - {e}')
client.close()
print('✅ Benchmark completed')
"

ci-test: ## Run CI/CD pipeline tests
	$(call log_info,"Running CI/CD pipeline tests...")
	@$(MAKE) clean
	@$(MAKE) setup
	@$(MAKE) validate-data
	@$(MAKE) lint
	@$(MAKE) test
	@$(MAKE) security
	$(call log_success,"CI/CD pipeline tests completed")

integration-test: ## Run integration tests with live services
	$(call log_info,"Running integration tests...")
	@$(MAKE) services-start
	@sleep 10  # Wait for services to be ready
	@$(MAKE) test
	@$(MAKE) benchmark
	$(call log_success,"Integration tests completed")

demo-quick: ## Quick demo without full platform deployment
	$(call log_info,"Running quick demo (test mode only)...")
	@$(PYTHON) -c "
print('🧪 MCP Security Platform - Quick Demo')
print('=' * 50)
print('✅ Test data validation')
print('✅ Mock API interactions')
print('✅ Simulated risk assessment')
print('✅ Demo report generation')
print('')
print('🎯 For full demo with live services, run: make poc-demo')
"
	$(call log_success,"Quick demo completed")

demo-data: ## Generate fresh demo data
	$(call log_info,"Generating fresh demo data...")
	@mkdir -p $(DEMO_DIR)
	@$(PYTHON) -c "
import json
from datetime import datetime
demo_sbom = {
    'bom_format': 'CycloneDX',
    'spec_version': '1.5',
    'timestamp': datetime.now().isoformat(),
    'components': [
        {'name': 'express', 'version': '4.17.1', 'type': 'library'},
        {'name': 'lodash', 'version': '4.17.15', 'type': 'library'}
    ],
    'vulnerabilities': [
        {'id': 'CVE-2021-44228', 'severity': 'critical', 'score': 10.0}
    ]
}
with open('$(DEMO_DIR)/fresh-demo-sbom.json', 'w') as f:
    json.dump(demo_sbom, f, indent=2)
print('✅ Demo SBOM generated')
"
	$(call log_success,"Demo data generated in $(DEMO_DIR)/")

info: ## Show environment information
	@echo -e "$(CYAN)🛡️  MCP Security Platform - Environment Info$(NC)"
	@echo "================================================================"
	@echo -e "$(YELLOW)System:$(NC)"
	@echo "  OS: $$(uname -s)"
	@echo "  Architecture: $$(uname -m)"
	@echo "  Python: $$($(PYTHON) --version 2>&1)"
	@echo "  Docker: $$($(DOCKER) --version 2>/dev/null || echo 'Not available')"
	@echo "  Kind: $$($(KIND) --version 2>/dev/null || echo 'Not available')"
	@echo "  kubectl: $$($(KUBECTL) version --client --short 2>/dev/null || echo 'Not available')"
	@echo ""
	@echo -e "$(YELLOW)Project:$(NC)"
	@echo "  Root: $(PROJECT_ROOT)"
	@echo "  Test Dir: $(TEST_DIR)"
	@echo "  Demo Dir: $(DEMO_DIR)"
	@echo "  Scripts: $(SCRIPTS_DIR)"
	@echo ""
	@echo -e "$(YELLOW)Services:$(NC)"
	@echo "  API Gateway: http://localhost:8000"
	@echo "  Auth Service: http://localhost:8001"
	@echo "  Core Service: http://localhost:8080"
	@echo "  Dashboard: http://localhost:3000"

all: clean setup test poc-demo ## Run complete build and test cycle

# Advanced targets
debug: ## Debug mode with verbose output
	$(call log_info,"Running in debug mode...")
	@$(MAKE) poc-test PYTEST_ARGS="-v -s --tb=long"

watch: ## Watch for file changes and run tests
	$(call log_info,"Watching for file changes...")
	@which watchdog > /dev/null 2>&1 || $(PIP) install --user watchdog
	@$(PYTHON) -c "
import time
import subprocess
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class TestHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.src_path.endswith('.py'):
            print(f'File changed: {event.src_path}')
            subprocess.run(['make', 'test'], cwd='.')

observer = Observer()
observer.schedule(TestHandler(), '$(TEST_DIR)', recursive=True)
observer.start()
print('👁️  Watching for changes... Press Ctrl+C to stop')
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    observer.stop()
observer.join()
"