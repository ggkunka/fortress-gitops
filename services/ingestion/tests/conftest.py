"""Test configuration and fixtures for the ingestion service."""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock
from typing import Dict, Any, AsyncGenerator

from fastapi.testclient import TestClient
from httpx import AsyncClient
import redis.asyncio as redis

from services.ingestion.main import app
from services.ingestion.services.event_bus import EventBusService
from services.ingestion.services.validation import ValidationService
from services.ingestion.services.metrics import MetricsService
from shared.config import get_settings


@pytest.fixture
def settings():
    """Get test settings."""
    return get_settings()


@pytest.fixture
def client():
    """Create test client."""
    return TestClient(app)


@pytest.fixture
async def async_client():
    """Create async test client."""
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac


@pytest.fixture
def mock_redis():
    """Mock Redis client."""
    mock_client = AsyncMock(spec=redis.Redis)
    mock_client.ping.return_value = True
    mock_client.publish.return_value = 1
    mock_client.pubsub_numsub.return_value = {"test_channel": 1}
    mock_client.pubsub_channels.return_value = ["test_channel"]
    mock_client.info.return_value = {
        "redis_version": "7.0.0",
        "uptime_in_seconds": 3600,
    }
    return mock_client


@pytest.fixture
def mock_event_bus(mock_redis):
    """Mock event bus service."""
    service = EventBusService()
    service.redis_client = mock_redis
    service.is_connected = True
    return service


@pytest.fixture
def validation_service():
    """Create validation service."""
    return ValidationService()


@pytest.fixture
def metrics_service():
    """Create metrics service."""
    return MetricsService()


@pytest.fixture
def sample_sbom_data():
    """Sample SBOM data for testing."""
    return {
        "sbom_version": "1.0.0",
        "serial_number": "12345678-1234-1234-1234-123456789012",
        "components": [
            {
                "id": "pkg:npm/lodash@4.17.21",
                "type": "library",
                "name": "lodash",
                "version": "4.17.21",
                "purl": "pkg:npm/lodash@4.17.21",
                "hashes": [
                    {
                        "algorithm": "SHA-256",
                        "value": "a188b96df4c7e5fdf8b6e8b73a8e2e5c3e6a5b2e3a7c5f7c2e1a3b4c5d6e7f8g9h0"
                    }
                ],
                "licenses": ["MIT"],
                "supplier": "John Doe",
                "originator": "John Doe",
                "download_location": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                "homepage": "https://lodash.com",
                "dependencies": []
            }
        ],
        "vulnerabilities": [
            {
                "id": "CVE-2021-23337",
                "component_id": "pkg:npm/lodash@4.17.21",
                "description": "Test vulnerability",
                "severity": "HIGH",
                "cvss_score": 7.5,
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-23337"],
                "published_date": "2021-02-15T00:00:00Z",
                "modified_date": "2021-02-15T00:00:00Z"
            }
        ],
        "metadata": {
            "tools": ["test-tool"],
            "authors": ["Test Author"],
            "timestamp": "2023-01-01T00:00:00Z",
            "scan_id": "test-scan-123"
        }
    }


@pytest.fixture
def sample_cve_data():
    """Sample CVE data for testing."""
    return {
        "cve_id": "CVE-2023-12345",
        "published_date": "2023-01-01T00:00:00Z",
        "last_modified": "2023-01-01T00:00:00Z",
        "description": "Test CVE description",
        "references": [
            {
                "url": "https://example.com/advisory",
                "source": "example.com"
            }
        ],
        "metrics": {
            "cvss_v3": {
                "version": "3.1",
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "baseScore": 9.8,
                "baseSeverity": "CRITICAL"
            }
        },
        "weaknesses": [
            {
                "cwe_id": "CWE-79",
                "description": "Cross-site Scripting"
            }
        ],
        "configurations": [
            {
                "operator": "AND",
                "cpe_match": [
                    {
                        "vulnerable": True,
                        "cpe23Uri": "cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*"
                    }
                ]
            }
        ],
        "impact": {
            "base_metric_v3": {
                "exploitability_score": 3.9,
                "impact_score": 5.9
            }
        }
    }


@pytest.fixture
def sample_runtime_data():
    """Sample runtime behavior data for testing."""
    return {
        "session_id": "runtime-session-123",
        "host_name": "test-host",
        "container_id": "container-123",
        "start_time": "2023-01-01T00:00:00Z",
        "end_time": "2023-01-01T01:00:00Z",
        "events": [
            {
                "event_id": "event-001",
                "timestamp": "2023-01-01T00:30:00Z",
                "event_type": "process_start",
                "data": {
                    "process_name": "nginx",
                    "process_id": 1234,
                    "parent_process_id": 1,
                    "command_line": "/usr/sbin/nginx -g 'daemon off;'",
                    "user": "www-data",
                    "working_directory": "/var/www"
                }
            },
            {
                "event_id": "event-002",
                "timestamp": "2023-01-01T00:31:00Z",
                "event_type": "network_connection",
                "data": {
                    "source_ip": "192.168.1.100",
                    "source_port": 80,
                    "destination_ip": "192.168.1.200",
                    "destination_port": 443,
                    "protocol": "TCP",
                    "bytes_sent": 1024,
                    "bytes_received": 2048
                }
            }
        ],
        "metrics": {
            "cpu_usage": {
                "min": 0.1,
                "max": 85.5,
                "average": 45.2
            },
            "memory_usage": {
                "min": 128000000,
                "max": 512000000,
                "average": 256000000
            }
        },
        "anomalies": [
            {
                "anomaly_id": "anomaly-001",
                "timestamp": "2023-01-01T00:45:00Z",
                "type": "suspicious_process",
                "severity": "MEDIUM",
                "description": "Unusual process spawning pattern detected",
                "confidence": 0.85,
                "metadata": {
                    "process_name": "unknown_binary",
                    "process_id": 9999
                }
            }
        ]
    }


@pytest.fixture
def sample_batch_data(sample_sbom_data):
    """Sample batch data for testing."""
    return [
        sample_sbom_data,
        {
            **sample_sbom_data,
            "serial_number": "12345678-1234-1234-1234-123456789013",
            "components": [
                {
                    "id": "pkg:npm/express@4.18.2",
                    "type": "library",
                    "name": "express",
                    "version": "4.18.2",
                    "purl": "pkg:npm/express@4.18.2",
                    "hashes": [
                        {
                            "algorithm": "SHA-256",
                            "value": "b188b96df4c7e5fdf8b6e8b73a8e2e5c3e6a5b2e3a7c5f7c2e1a3b4c5d6e7f8g9h1"
                        }
                    ],
                    "licenses": ["MIT"],
                    "supplier": "TJ Holowaychuk",
                    "originator": "TJ Holowaychuk",
                    "download_location": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
                    "homepage": "https://expressjs.com",
                    "dependencies": []
                }
            ],
            "vulnerabilities": []
        }
    ]


@pytest.fixture
def invalid_sbom_data():
    """Invalid SBOM data for testing validation errors."""
    return {
        "sbom_version": "1.0.0",
        # Missing required serial_number
        "components": [
            {
                "id": "pkg:npm/lodash@4.17.21",
                "type": "library",
                "name": "lodash",
                # Missing required version
                "purl": "pkg:npm/lodash@4.17.21",
                "hashes": [
                    {
                        "algorithm": "INVALID_ALGORITHM",  # Invalid algorithm
                        "value": "short"  # Too short hash
                    }
                ],
                "licenses": ["MIT"],
                "dependencies": []
            }
        ],
        "vulnerabilities": [],
        "metadata": {
            "tools": ["test-tool"],
            "authors": ["Test Author"],
            "timestamp": "invalid-timestamp",  # Invalid timestamp format
        }
    }


@pytest.fixture
def mock_app_with_services(mock_event_bus, validation_service, metrics_service):
    """Mock app with initialized services."""
    app.state.event_bus_service = mock_event_bus
    app.state.validation_service = validation_service
    app.state.metrics_service = metrics_service
    
    # Update module-level service instances
    import services.ingestion.api.ingestion as ingestion_api
    import services.ingestion.api.health as health_api
    import services.ingestion.api.metrics as metrics_api
    
    ingestion_api.event_bus = mock_event_bus
    ingestion_api.validation_service = validation_service
    ingestion_api.metrics_service = metrics_service
    
    health_api.event_bus = mock_event_bus
    health_api.validation_service = validation_service
    health_api.metrics_service = metrics_service
    
    metrics_api.metrics_service = metrics_service
    
    return app


@pytest.fixture
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def mock_publish_methods(mock_event_bus):
    """Mock event bus publish methods."""
    mock_event_bus.publish_sbom_ingested = AsyncMock(return_value=True)
    mock_event_bus.publish_cve_ingested = AsyncMock(return_value=True)
    mock_event_bus.publish_runtime_ingested = AsyncMock(return_value=True)
    mock_event_bus.publish_validation_failed = AsyncMock(return_value=True)
    mock_event_bus.publish_ingestion_error = AsyncMock(return_value=True)
    return mock_event_bus


@pytest.fixture
def mock_validation_service():
    """Mock validation service."""
    service = AsyncMock(spec=ValidationService)
    service.get_schema_info.return_value = {
        "data_type": "sbom",
        "schema_name": "SBOMSchema",
        "schema_version": "1.0.0",
        "fields": ["sbom_version", "serial_number", "components"],
        "required_fields": ["sbom_version", "serial_number", "components"],
    }
    service.get_all_schema_info.return_value = {
        "sbom": {"data_type": "sbom", "schema_name": "SBOMSchema"},
        "cve": {"data_type": "cve", "schema_name": "CVESchema"},
        "runtime": {"data_type": "runtime", "schema_name": "RuntimeBehaviorSchema"},
    }
    return service


@pytest.fixture
def mock_metrics_service():
    """Mock metrics service."""
    service = MagicMock(spec=MetricsService)
    service.get_metrics_summary.return_value = {
        "timestamp": "2023-01-01T00:00:00Z",
        "uptime_seconds": 3600,
        "ingestion_requests": {"sbom_success": 10, "cve_success": 5},
        "validation_results": {"sbom_valid": 10, "cve_valid": 5},
        "event_publications": {"sbom.ingested_success": 10},
        "error_counts": {},
        "processing_times": {},
        "data_sizes": {},
    }
    service.get_health_metrics.return_value = {
        "status": "healthy",
        "total_requests": 15,
        "total_errors": 0,
        "uptime_seconds": 3600,
    }
    return service