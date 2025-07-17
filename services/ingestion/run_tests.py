#!/usr/bin/env python3
"""Test runner script for the ingestion service."""

import sys
import subprocess
import argparse
from pathlib import Path


def run_command(command, description):
    """Run a command and handle errors."""
    print(f"\n{'='*60}")
    print(f"Running: {description}")
    print(f"Command: {' '.join(command)}")
    print(f"{'='*60}")
    
    try:
        result = subprocess.run(
            command,
            cwd=Path(__file__).parent,
            check=True,
            capture_output=False,
            text=True
        )
        print(f"✅ {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed with exit code {e.returncode}")
        return False


def run_unit_tests(coverage=True, verbose=False):
    """Run unit tests."""
    command = ["python", "-m", "pytest", "tests/", "-m", "unit or not integration"]
    
    if coverage:
        command.extend(["--cov=services.ingestion", "--cov-report=term-missing"])
    
    if verbose:
        command.append("-v")
    
    return run_command(command, "Unit Tests")


def run_integration_tests(verbose=False):
    """Run integration tests."""
    command = ["python", "-m", "pytest", "tests/", "-m", "integration"]
    
    if verbose:
        command.append("-v")
    
    return run_command(command, "Integration Tests")


def run_all_tests(coverage=True, verbose=False):
    """Run all tests."""
    command = ["python", "-m", "pytest", "tests/"]
    
    if coverage:
        command.extend([
            "--cov=services.ingestion",
            "--cov-report=term-missing",
            "--cov-report=html:htmlcov",
            "--cov-report=xml:coverage.xml"
        ])
    
    if verbose:
        command.append("-v")
    
    return run_command(command, "All Tests")


def run_specific_test(test_path, verbose=False):
    """Run a specific test."""
    command = ["python", "-m", "pytest", test_path]
    
    if verbose:
        command.append("-v")
    
    return run_command(command, f"Test: {test_path}")


def run_linting():
    """Run code linting."""
    commands = [
        (["python", "-m", "flake8", "services/ingestion/", "--max-line-length=100"], "Flake8 Linting"),
        (["python", "-m", "black", "--check", "services/ingestion/"], "Black Formatting Check"),
        (["python", "-m", "isort", "--check-only", "services/ingestion/"], "Import Sorting Check"),
    ]
    
    success = True
    for command, description in commands:
        if not run_command(command, description):
            success = False
    
    return success


def run_type_checking():
    """Run type checking."""
    command = ["python", "-m", "mypy", "services/ingestion/", "--ignore-missing-imports"]
    return run_command(command, "Type Checking")


def install_dependencies():
    """Install test dependencies."""
    commands = [
        (["pip", "install", "-r", "requirements.txt"], "Install Main Dependencies"),
        (["pip", "install", "-r", "requirements-test.txt"], "Install Test Dependencies"),
    ]
    
    success = True
    for command, description in commands:
        if not run_command(command, description):
            success = False
    
    return success


def main():
    """Main test runner function."""
    parser = argparse.ArgumentParser(description="Run tests for the ingestion service")
    parser.add_argument("--unit", action="store_true", help="Run unit tests only")
    parser.add_argument("--integration", action="store_true", help="Run integration tests only")
    parser.add_argument("--all", action="store_true", help="Run all tests")
    parser.add_argument("--test", type=str, help="Run specific test file or path")
    parser.add_argument("--lint", action="store_true", help="Run linting")
    parser.add_argument("--type-check", action="store_true", help="Run type checking")
    parser.add_argument("--install-deps", action="store_true", help="Install dependencies")
    parser.add_argument("--no-coverage", action="store_true", help="Skip coverage reporting")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--quick", action="store_true", help="Run quick tests only")
    parser.add_argument("--full", action="store_true", help="Run full test suite with quality checks")
    
    args = parser.parse_args()
    
    # If no specific action is specified, run all tests
    if not any([args.unit, args.integration, args.all, args.test, args.lint, 
                args.type_check, args.install_deps, args.quick, args.full]):
        args.all = True
    
    success = True
    
    # Install dependencies if requested
    if args.install_deps:
        if not install_dependencies():
            success = False
    
    # Run specific test
    if args.test:
        if not run_specific_test(args.test, args.verbose):
            success = False
    
    # Run unit tests
    if args.unit:
        if not run_unit_tests(not args.no_coverage, args.verbose):
            success = False
    
    # Run integration tests
    if args.integration:
        if not run_integration_tests(args.verbose):
            success = False
    
    # Run all tests
    if args.all:
        if not run_all_tests(not args.no_coverage, args.verbose):
            success = False
    
    # Run quick tests (unit tests without coverage)
    if args.quick:
        if not run_unit_tests(False, args.verbose):
            success = False
    
    # Run full test suite
    if args.full:
        print("\n🚀 Running full test suite...")
        
        # Install dependencies
        if not install_dependencies():
            success = False
        
        # Run linting
        if not run_linting():
            success = False
        
        # Run type checking
        if not run_type_checking():
            success = False
        
        # Run all tests with coverage
        if not run_all_tests(True, args.verbose):
            success = False
    
    # Run linting
    if args.lint:
        if not run_linting():
            success = False
    
    # Run type checking
    if args.type_check:
        if not run_type_checking():
            success = False
    
    # Final result
    if success:
        print("\n✅ All operations completed successfully!")
        return 0
    else:
        print("\n❌ Some operations failed!")
        return 1


if __name__ == "__main__":
    sys.exit(main())