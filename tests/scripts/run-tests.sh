#!/bin/bash

# Main test runner script for MCP Security Platform
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
TEST_TYPE="all"
VERBOSE=false
PARALLEL=4
TIMEOUT=300
REPORT_DIR="/app/results"

# Function to print colored output
print_status() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

print_success() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

print_error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

# Function to show usage
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -t, --type TYPE       Test type: all, integration, e2e, performance, chaos, security, contracts"
    echo "  -v, --verbose         Enable verbose output"
    echo "  -p, --parallel N      Number of parallel workers (default: 4)"
    echo "  -T, --timeout N       Test timeout in seconds (default: 300)"
    echo "  -r, --report-dir DIR  Report output directory (default: /app/results)"
    echo "  -h, --help           Show this help message"
    exit 1
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--type)
            TEST_TYPE="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -p|--parallel)
            PARALLEL="$2"
            shift 2
            ;;
        -T|--timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        -r|--report-dir)
            REPORT_DIR="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# Create report directory
mkdir -p "$REPORT_DIR"

# Wait for services to be ready
wait_for_services() {
    print_status "Waiting for services to be ready..."
    
    services=(
        "redis:6379"
        "postgresql:5432"
        "gateway-service:8081"
        "auth-service:8085"
        "ingestion-service:8080"
        "enrichment-service:8082"
        "analysis-service:8083"
        "notification-service:8084"
        "plugin-registry:8090"
    )
    
    for service in "${services[@]}"; do
        host=$(echo $service | cut -d: -f1)
        port=$(echo $service | cut -d: -f2)
        
        print_status "Waiting for $host:$port..."
        while ! nc -z $host $port; do
            sleep 2
        done
        print_success "$host:$port is ready"
    done
}

# Run health checks
run_health_checks() {
    print_status "Running health checks..."
    
    health_endpoints=(
        "http://gateway-service:8081/health"
        "http://auth-service:8085/health"
        "http://ingestion-service:8080/health"
        "http://enrichment-service:8082/health"
        "http://analysis-service:8083/health"
        "http://notification-service:8084/health"
        "http://plugin-registry:8090/health"
    )
    
    for endpoint in "${endpoints[@]}"; do
        if curl -f -s "$endpoint" > /dev/null; then
            print_success "Health check passed: $endpoint"
        else
            print_error "Health check failed: $endpoint"
            return 1
        fi
    done
}

# Run integration tests
run_integration_tests() {
    print_status "Running integration tests..."
    
    pytest_args=(
        "integration/"
        "--timeout=$TIMEOUT"
        "--cov=../services"
        "--cov-report=html:$REPORT_DIR/coverage"
        "--cov-report=xml:$REPORT_DIR/coverage.xml"
        "--junitxml=$REPORT_DIR/integration-results.xml"
        "-n $PARALLEL"
    )
    
    if [ "$VERBOSE" = true ]; then
        pytest_args+=("-v" "-s")
    fi
    
    if pytest "${pytest_args[@]}"; then
        print_success "Integration tests passed"
        return 0
    else
        print_error "Integration tests failed"
        return 1
    fi
}

# Run end-to-end tests
run_e2e_tests() {
    print_status "Running end-to-end tests..."
    
    pytest_args=(
        "e2e/"
        "--timeout=$TIMEOUT"
        "--junitxml=$REPORT_DIR/e2e-results.xml"
        "-n $PARALLEL"
    )
    
    if [ "$VERBOSE" = true ]; then
        pytest_args+=("-v" "-s")
    fi
    
    if pytest "${pytest_args[@]}"; then
        print_success "End-to-end tests passed"
        return 0
    else
        print_error "End-to-end tests failed"
        return 1
    fi
}

# Run performance tests
run_performance_tests() {
    print_status "Running performance tests..."
    
    # Run Locust performance tests
    if python performance/run_load_tests.py \
        --host http://gateway-service:8081 \
        --users 100 \
        --spawn-rate 10 \
        --time 300 \
        --html "$REPORT_DIR/performance-report.html" \
        --csv "$REPORT_DIR/performance"; then
        print_success "Performance tests completed"
        return 0
    else
        print_error "Performance tests failed"
        return 1
    fi
}

# Run chaos engineering tests
run_chaos_tests() {
    print_status "Running chaos engineering tests..."
    
    if python chaos/run_chaos_tests.py \
        --output-dir "$REPORT_DIR/chaos"; then
        print_success "Chaos tests completed"
        return 0
    else
        print_error "Chaos tests failed"
        return 1
    fi
}

# Run security tests
run_security_tests() {
    print_status "Running security tests..."
    
    # Run security test suite
    if python security/run_security_tests.py \
        --output-dir "$REPORT_DIR/security"; then
        print_success "Security tests completed"
        return 0
    else
        print_error "Security tests failed"
        return 1
    fi
}

# Run contract tests
run_contract_tests() {
    print_status "Running contract tests..."
    
    if python contracts/run_contract_tests.py \
        --output-dir "$REPORT_DIR/contracts"; then
        print_success "Contract tests completed"
        return 0
    else
        print_error "Contract tests failed"
        return 1
    fi
}

# Main execution
main() {
    print_status "Starting MCP Security Platform test suite"
    print_status "Test type: $TEST_TYPE"
    print_status "Report directory: $REPORT_DIR"
    
    # Wait for services
    wait_for_services
    
    # Run health checks
    if ! run_health_checks; then
        print_error "Health checks failed, aborting tests"
        exit 1
    fi
    
    # Initialize results
    failed_tests=()
    
    # Run tests based on type
    case $TEST_TYPE in
        "all")
            test_types=("integration" "e2e" "performance" "chaos" "security" "contracts")
            ;;
        "integration"|"e2e"|"performance"|"chaos"|"security"|"contracts")
            test_types=("$TEST_TYPE")
            ;;
        *)
            print_error "Invalid test type: $TEST_TYPE"
            usage
            ;;
    esac
    
    # Execute tests
    for test in "${test_types[@]}"; do
        case $test in
            "integration")
                run_integration_tests || failed_tests+=("integration")
                ;;
            "e2e")
                run_e2e_tests || failed_tests+=("e2e")
                ;;
            "performance")
                run_performance_tests || failed_tests+=("performance")
                ;;
            "chaos")
                run_chaos_tests || failed_tests+=("chaos")
                ;;
            "security")
                run_security_tests || failed_tests+=("security")
                ;;
            "contracts")
                run_contract_tests || failed_tests+=("contracts")
                ;;
        esac
    done
    
    # Generate summary report
    echo "# Test Results Summary" > "$REPORT_DIR/summary.md"
    echo "Generated: $(date)" >> "$REPORT_DIR/summary.md"
    echo "" >> "$REPORT_DIR/summary.md"
    
    if [ ${#failed_tests[@]} -eq 0 ]; then
        print_success "All tests passed!"
        echo "## ✅ All tests passed" >> "$REPORT_DIR/summary.md"
        exit 0
    else
        print_error "Some tests failed: ${failed_tests[*]}"
        echo "## ❌ Failed tests: ${failed_tests[*]}" >> "$REPORT_DIR/summary.md"
        exit 1
    fi
}

# Run main function
main