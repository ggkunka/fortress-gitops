"""
Pytest configuration and fixtures for MCP Security Platform POC tests
"""

import pytest
import httpx
from pathlib import Path


@pytest.fixture(scope="session")
def test_data_dir():
    """Fixture providing path to test data directory"""
    return Path(__file__).parent / "data"


@pytest.fixture(scope="session")
def api_client():
    """Fixture providing HTTP client for API testing"""
    client = httpx.Client(timeout=30.0)
    yield client
    client.close()


@pytest.fixture(scope="session")
def test_credentials():
    """Fixture providing test credentials"""
    return {
        "username": "admin",
        "password": "admin123"
    }


@pytest.fixture(scope="session")
def service_urls():
    """Fixture providing service URLs"""
    return {
        "api_base": "http://localhost:8000",
        "auth_base": "http://localhost:8001",
        "core_base": "http://localhost:8080",
        "ui_base": "http://localhost:3000"
    }