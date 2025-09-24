#!/usr/bin/env python3
"""
Test runner script for MCP Security Platform.

This script provides a convenient way to run tests with different configurations
and filters. It handles test database setup, cleanup, and provides detailed
reporting options.

Usage:
    python run_tests.py                    # Run all tests
    python run_tests.py --unit             # Run only unit tests
    python run_tests.py --integration      # Run only integration tests
    python run_tests.py --api              # Run only API tests
    python run_tests.py --auth             # Run only auth tests
    python run_tests.py --security         # Run only security tests
    python run_tests.py --smoke            # Run only smoke tests
    python run_tests.py --performance      # Run only performance tests
    python run_tests.py --coverage         # Run with coverage report
    python run_tests.py --parallel         # Run tests in parallel
    python run_tests.py --verbose          # Verbose output
    python run_tests.py --debug            # Debug mode
    python run_tests.py --file test_auth   # Run specific test file
    python run_tests.py --class TestAuth   # Run specific test class
    python run_tests.py --method test_login # Run specific test method
"""

import argparse
import asyncio
import os
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))


class TestRunner:
    """Test runner with various configuration options."""
    
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.test_dir = self.project_root / "tests"
        
    def setup_test_environment(self):
        """Setup test environment variables."""
        test_env = os.environ.copy()
        test_env.update({
            "TESTING": "true",
            "DATABASE_URL": "postgresql+asyncpg://test:test@localhost/mcp_security_test",
            "SECRET_KEY": "test-secret-key-for-testing-only",
            "REDIS_URL": "redis://localhost:6379/1",
            "PYTHONPATH": str(self.project_root),
        })
        return test_env
    
    def build_pytest_command(self, args) -> List[str]:
        """Build pytest command with appropriate options."""
        cmd = ["python", "-m", "pytest"]
        
        # Add test directory
        cmd.append(str(self.test_dir))
        
        # Test type filters
        if args.unit:
            cmd.extend(["-m", "unit"])
        elif args.integration:
            cmd.extend(["-m", "integration"])
        elif args.api:
            cmd.extend(["-m", "api"])
        elif args.auth:
            cmd.extend(["-m", "auth"])
        elif args.security:
            cmd.extend(["-m", "security"])
        elif args.smoke:
            cmd.extend(["-m", "smoke"])
        elif args.performance:
            cmd.extend(["-m", "performance"])
        
        # Specific file, class, or method
        if args.file:
            cmd.append(f"test_{args.file}.py")
        if args.class_name:
            cmd.extend(["-k", args.class_name])
        if args.method:
            cmd.extend(["-k", args.method])
        
        # Output options
        if args.verbose:
            cmd.append("-v")
        if args.debug:
            cmd.extend(["--pdb", "--capture=no"])
        if args.parallel:
            cmd.extend(["-n", "auto"])
        
        # Coverage options
        if args.coverage:
            cmd.extend([
                "--cov=.",
                "--cov-report=term-missing",
                "--cov-report=html:htmlcov",
                "--cov-report=xml:coverage.xml",
                "--cov-branch"
            ])
        
        # Additional pytest options
        if args.failfast:
            cmd.append("-x")
        if args.last_failed:
            cmd.append("--lf")
        if args.failed_first:
            cmd.append("--ff")
        
        return cmd
    
    def check_dependencies(self) -> bool:
        """Check if required dependencies are available."""
        try:
            import pytest
            import pytest_asyncio
            import httpx
            import sqlalchemy
            return True
        except ImportError as e:
            print(f"Missing required dependency: {e}")
            print("Please install test dependencies: pip install -r requirements-test.txt")
            return False
    
    def setup_test_database(self) -> bool:
        """Setup test database if needed."""
        print("Setting up test database...")
        try:
            # Here you would normally create/migrate the test database
            # For now, we'll just check if PostgreSQL is running
            result = subprocess.run(
                ["pg_isready", "-h", "localhost", "-p", "5432"],
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                print("PostgreSQL is not running. Please start PostgreSQL first.")
                return False
            return True
        except FileNotFoundError:
            print("PostgreSQL client tools not found. Please install PostgreSQL.")
            return False
    
    def cleanup_test_database(self):
        """Cleanup test database after tests."""
        print("Cleaning up test database...")
        # Database cleanup happens automatically in test fixtures
        pass
    
    def generate_test_report(self, coverage: bool = False):
        """Generate test reports."""
        print("\n" + "="*60)
        print("TEST REPORT SUMMARY")
        print("="*60)
        
        if coverage and os.path.exists("htmlcov/index.html"):
            print(f"Coverage report generated: file://{os.path.abspath('htmlcov/index.html')}")
        
        if os.path.exists("coverage.xml"):
            print(f"Coverage XML: {os.path.abspath('coverage.xml')}")
        
        print("="*60)
    
    def run_tests(self, args) -> int:
        """Run tests with specified configuration."""
        print("MCP Security Platform Test Runner")
        print("="*50)
        
        # Check dependencies
        if not self.check_dependencies():
            return 1
        
        # Setup test database
        if not self.setup_test_database():
            return 1
        
        # Setup environment
        env = self.setup_test_environment()
        
        # Build pytest command
        cmd = self.build_pytest_command(args)
        
        print(f"Running command: {' '.join(cmd)}")
        print("-" * 50)
        
        try:
            # Run tests
            result = subprocess.run(cmd, env=env, cwd=self.project_root)
            
            # Generate reports
            self.generate_test_report(coverage=args.coverage)
            
            return result.returncode
            
        except KeyboardInterrupt:
            print("\nTests interrupted by user")
            return 130
        except Exception as e:
            print(f"Error running tests: {e}")
            return 1
        finally:
            # Cleanup
            self.cleanup_test_database()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Test runner for MCP Security Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python run_tests.py                    # Run all tests
    python run_tests.py --unit --coverage # Run unit tests with coverage
    python run_tests.py --api --verbose   # Run API tests with verbose output
    python run_tests.py --file auth       # Run tests in test_auth.py
    python run_tests.py --smoke --parallel # Run smoke tests in parallel
        """
    )
    
    # Test type filters
    test_group = parser.add_argument_group("Test Types")
    test_group.add_argument("--unit", action="store_true", help="Run unit tests only")
    test_group.add_argument("--integration", action="store_true", help="Run integration tests only")
    test_group.add_argument("--api", action="store_true", help="Run API tests only")
    test_group.add_argument("--auth", action="store_true", help="Run authentication tests only")
    test_group.add_argument("--security", action="store_true", help="Run security tests only")
    test_group.add_argument("--smoke", action="store_true", help="Run smoke tests only")
    test_group.add_argument("--performance", action="store_true", help="Run performance tests only")
    
    # Specific test selection
    selection_group = parser.add_argument_group("Test Selection")
    selection_group.add_argument("--file", help="Run specific test file (e.g., 'auth' for test_auth.py)")
    selection_group.add_argument("--class", dest="class_name", help="Run specific test class")
    selection_group.add_argument("--method", help="Run specific test method")
    
    # Output options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    output_group.add_argument("--debug", action="store_true", help="Debug mode (enter PDB on failures)")
    output_group.add_argument("--coverage", action="store_true", help="Generate coverage report")
    
    # Execution options
    execution_group = parser.add_argument_group("Execution Options")
    execution_group.add_argument("--parallel", action="store_true", help="Run tests in parallel")
    execution_group.add_argument("--failfast", "-x", action="store_true", help="Stop on first failure")
    execution_group.add_argument("--last-failed", "--lf", action="store_true", help="Run only last failed tests")
    execution_group.add_argument("--failed-first", "--ff", action="store_true", help="Run failed tests first")
    
    args = parser.parse_args()
    
    # Create and run test runner
    runner = TestRunner()
    exit_code = runner.run_tests(args)
    
    sys.exit(exit_code)


if __name__ == "__main__":
    main()