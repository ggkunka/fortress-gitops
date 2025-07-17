"""Tests for the ingestion API endpoints."""

import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient
from httpx import AsyncClient

from services.ingestion.main import app
from services.ingestion.services.validation import ValidationResult


class TestIngestionAPI:
    """Test cases for ingestion API endpoints."""

    @pytest.fixture(autouse=True)
    def setup_services(self, mock_app_with_services, mock_publish_methods):
        """Setup services for each test."""
        self.app = mock_app_with_services
        self.mock_event_bus = mock_publish_methods

    def test_ingest_sbom_sync_success(self, client, sample_sbom_data):
        """Test successful synchronous SBOM ingestion."""
        response = client.post(
            "/api/v1/ingestion/sbom",
            json=sample_sbom_data,
            params={"async_processing": False}
        )
        
        assert response.status_code == 200
        response_data = response.json()
        
        assert response_data["message"] == "SBOM data ingested successfully"
        assert "ingestion_id" in response_data
        assert response_data["processing_mode"] == "sync"
        assert "components_count" in response_data
        assert "vulnerabilities_count" in response_data

    def test_ingest_sbom_async_success(self, client, sample_sbom_data):
        """Test successful asynchronous SBOM ingestion."""
        response = client.post(
            "/api/v1/ingestion/sbom",
            json=sample_sbom_data,
            params={"async_processing": True}
        )
        
        assert response.status_code == 202
        response_data = response.json()
        
        assert response_data["message"] == "SBOM data accepted for processing"
        assert "ingestion_id" in response_data
        assert response_data["processing_mode"] == "async"

    def test_ingest_sbom_validation_error(self, client, invalid_sbom_data):
        """Test SBOM ingestion with validation errors."""
        response = client.post(
            "/api/v1/ingestion/sbom",
            json=invalid_sbom_data,
            params={"async_processing": False}
        )
        
        assert response.status_code == 400
        response_data = response.json()
        
        assert response_data["message"] == "SBOM validation failed"
        assert "ingestion_id" in response_data
        assert "errors" in response_data
        assert len(response_data["errors"]) > 0

    def test_ingest_sbom_invalid_json(self, client):
        """Test SBOM ingestion with invalid JSON."""
        response = client.post(
            "/api/v1/ingestion/sbom",
            data="invalid json",
            headers={"Content-Type": "application/json"}
        )
        
        assert response.status_code == 400
        response_data = response.json()
        assert "Invalid JSON" in response_data["detail"]

    def test_ingest_cve_sync_success(self, client, sample_cve_data):
        """Test successful synchronous CVE ingestion."""
        response = client.post(
            "/api/v1/ingestion/cve",
            json=sample_cve_data,
            params={"async_processing": False}
        )
        
        assert response.status_code == 200
        response_data = response.json()
        
        assert response_data["message"] == "CVE data ingested successfully"
        assert "ingestion_id" in response_data
        assert response_data["processing_mode"] == "sync"
        assert "cve_id" in response_data
        assert "severity" in response_data

    def test_ingest_cve_async_success(self, client, sample_cve_data):
        """Test successful asynchronous CVE ingestion."""
        response = client.post(
            "/api/v1/ingestion/cve",
            json=sample_cve_data,
            params={"async_processing": True}
        )
        
        assert response.status_code == 202
        response_data = response.json()
        
        assert response_data["message"] == "CVE data accepted for processing"
        assert "ingestion_id" in response_data
        assert response_data["processing_mode"] == "async"

    def test_ingest_runtime_sync_success(self, client, sample_runtime_data):
        """Test successful synchronous runtime data ingestion."""
        response = client.post(
            "/api/v1/ingestion/runtime",
            json=sample_runtime_data,
            params={"async_processing": False}
        )
        
        assert response.status_code == 200
        response_data = response.json()
        
        assert response_data["message"] == "Runtime data ingested successfully"
        assert "ingestion_id" in response_data
        assert response_data["processing_mode"] == "sync"
        assert "session_id" in response_data
        assert "host_name" in response_data
        assert "events_count" in response_data

    def test_ingest_runtime_async_success(self, client, sample_runtime_data):
        """Test successful asynchronous runtime data ingestion."""
        response = client.post(
            "/api/v1/ingestion/runtime",
            json=sample_runtime_data,
            params={"async_processing": True}
        )
        
        assert response.status_code == 202
        response_data = response.json()
        
        assert response_data["message"] == "Runtime data accepted for processing"
        assert "ingestion_id" in response_data
        assert response_data["processing_mode"] == "async"

    def test_ingest_batch_sync_success(self, client, sample_batch_data):
        """Test successful synchronous batch ingestion."""
        response = client.post(
            "/api/v1/ingestion/batch",
            json=sample_batch_data,
            params={"data_type": "sbom", "async_processing": False}
        )
        
        assert response.status_code == 200
        response_data = response.json()
        
        assert response_data["message"] == "Batch sbom data ingested successfully"
        assert "ingestion_id" in response_data
        assert response_data["processing_mode"] == "sync"
        assert response_data["batch_size"] == len(sample_batch_data)
        assert "success_count" in response_data
        assert "validation_results" in response_data

    def test_ingest_batch_async_success(self, client, sample_batch_data):
        """Test successful asynchronous batch ingestion."""
        response = client.post(
            "/api/v1/ingestion/batch",
            json=sample_batch_data,
            params={"data_type": "sbom", "async_processing": True}
        )
        
        assert response.status_code == 202
        response_data = response.json()
        
        assert response_data["message"] == "Batch sbom data accepted for processing"
        assert "ingestion_id" in response_data
        assert response_data["processing_mode"] == "async"
        assert response_data["batch_size"] == len(sample_batch_data)

    def test_ingest_batch_invalid_format(self, client):
        """Test batch ingestion with invalid format."""
        response = client.post(
            "/api/v1/ingestion/batch",
            json={"not": "a list"},
            params={"data_type": "sbom"}
        )
        
        assert response.status_code == 400
        response_data = response.json()
        assert "Batch data must be a JSON array" in response_data["detail"]

    def test_ingest_batch_empty(self, client):
        """Test batch ingestion with empty data."""
        response = client.post(
            "/api/v1/ingestion/batch",
            json=[],
            params={"data_type": "sbom"}
        )
        
        assert response.status_code == 400
        response_data = response.json()
        assert "Batch cannot be empty" in response_data["detail"]

    def test_get_schemas(self, client):
        """Test get schemas endpoint."""
        response = client.get("/api/v1/ingestion/schemas")
        
        assert response.status_code == 200
        response_data = response.json()
        
        assert response_data["message"] == "Supported data schemas"
        assert "schemas" in response_data
        assert "sbom" in response_data["schemas"]
        assert "cve" in response_data["schemas"]
        assert "runtime" in response_data["schemas"]

    def test_get_schema_by_type(self, client):
        """Test get schema by type endpoint."""
        response = client.get("/api/v1/ingestion/schemas/sbom")
        
        assert response.status_code == 200
        response_data = response.json()
        
        assert response_data["message"] == "Schema for sbom"
        assert "schema" in response_data
        assert response_data["schema"]["data_type"] == "sbom"

    def test_get_schema_not_found(self, client):
        """Test get schema for non-existent type."""
        response = client.get("/api/v1/ingestion/schemas/nonexistent")
        
        assert response.status_code == 404
        response_data = response.json()
        assert "Schema not found" in response_data["detail"]

    def test_source_system_parameter(self, client, sample_sbom_data):
        """Test source system parameter in ingestion."""
        response = client.post(
            "/api/v1/ingestion/sbom",
            json=sample_sbom_data,
            params={"source_system": "test-system", "async_processing": False}
        )
        
        assert response.status_code == 200

    @patch('services.ingestion.services.event_bus.EventBusService.publish_sbom_ingested')
    def test_event_publication_failure(self, mock_publish, client, sample_sbom_data):
        """Test handling of event publication failure."""
        mock_publish.return_value = False
        
        response = client.post(
            "/api/v1/ingestion/sbom",
            json=sample_sbom_data,
            params={"async_processing": False}
        )
        
        assert response.status_code == 500
        response_data = response.json()
        assert "Failed to publish SBOM event" in response_data["detail"]["message"]

    def test_correlation_id_header(self, client, sample_sbom_data):
        """Test correlation ID header handling."""
        correlation_id = "test-correlation-123"
        
        response = client.post(
            "/api/v1/ingestion/sbom",
            json=sample_sbom_data,
            headers={"X-Correlation-ID": correlation_id},
            params={"async_processing": False}
        )
        
        assert response.status_code == 200
        assert response.headers.get("X-Correlation-ID") == correlation_id

    def test_request_id_header(self, client, sample_sbom_data):
        """Test request ID header generation."""
        response = client.post(
            "/api/v1/ingestion/sbom",
            json=sample_sbom_data,
            params={"async_processing": False}
        )
        
        assert response.status_code == 200
        assert "X-Request-ID" in response.headers
        assert len(response.headers["X-Request-ID"]) > 0


class TestIngestionAPIAsync:
    """Test cases for async ingestion API endpoints."""

    @pytest.fixture(autouse=True)
    def setup_services(self, mock_app_with_services, mock_publish_methods):
        """Setup services for each test."""
        self.app = mock_app_with_services
        self.mock_event_bus = mock_publish_methods

    @pytest.mark.asyncio
    async def test_async_client_sbom_ingestion(self, async_client, sample_sbom_data):
        """Test SBOM ingestion with async client."""
        response = await async_client.post(
            "/api/v1/ingestion/sbom",
            json=sample_sbom_data,
            params={"async_processing": False}
        )
        
        assert response.status_code == 200
        response_data = response.json()
        assert response_data["message"] == "SBOM data ingested successfully"

    @pytest.mark.asyncio
    async def test_async_client_cve_ingestion(self, async_client, sample_cve_data):
        """Test CVE ingestion with async client."""
        response = await async_client.post(
            "/api/v1/ingestion/cve",
            json=sample_cve_data,
            params={"async_processing": False}
        )
        
        assert response.status_code == 200
        response_data = response.json()
        assert response_data["message"] == "CVE data ingested successfully"

    @pytest.mark.asyncio
    async def test_async_client_runtime_ingestion(self, async_client, sample_runtime_data):
        """Test runtime data ingestion with async client."""
        response = await async_client.post(
            "/api/v1/ingestion/runtime",
            json=sample_runtime_data,
            params={"async_processing": False}
        )
        
        assert response.status_code == 200
        response_data = response.json()
        assert response_data["message"] == "Runtime data ingested successfully"

    @pytest.mark.asyncio
    async def test_async_client_batch_ingestion(self, async_client, sample_batch_data):
        """Test batch ingestion with async client."""
        response = await async_client.post(
            "/api/v1/ingestion/batch",
            json=sample_batch_data,
            params={"data_type": "sbom", "async_processing": False}
        )
        
        assert response.status_code == 200
        response_data = response.json()
        assert response_data["message"] == "Batch sbom data ingested successfully"


class TestIngestionAPIValidation:
    """Test cases for validation in ingestion API."""

    @pytest.fixture(autouse=True)
    def setup_services(self, mock_app_with_services):
        """Setup services for each test."""
        self.app = mock_app_with_services

    def test_missing_required_fields(self, client):
        """Test ingestion with missing required fields."""
        invalid_data = {
            "sbom_version": "1.0.0",
            # Missing serial_number and components
        }
        
        response = client.post(
            "/api/v1/ingestion/sbom",
            json=invalid_data,
            params={"async_processing": False}
        )
        
        assert response.status_code == 400
        response_data = response.json()
        assert "validation failed" in response_data["detail"]["message"]

    def test_invalid_field_values(self, client):
        """Test ingestion with invalid field values."""
        invalid_data = {
            "sbom_version": "1.0.0",
            "serial_number": "12345678-1234-1234-1234-123456789012",
            "components": [
                {
                    "id": "pkg:npm/test@1.0.0",
                    "type": "invalid_type",  # Invalid component type
                    "name": "test",
                    "version": "1.0.0",
                    "purl": "pkg:npm/test@1.0.0",
                    "hashes": [],
                    "licenses": [],
                    "dependencies": []
                }
            ],
            "vulnerabilities": [],
            "metadata": {
                "tools": [],
                "authors": [],
                "timestamp": "2023-01-01T00:00:00Z"
            }
        }
        
        response = client.post(
            "/api/v1/ingestion/sbom",
            json=invalid_data,
            params={"async_processing": False}
        )
        
        assert response.status_code == 400

    def test_invalid_cve_format(self, client):
        """Test CVE ingestion with invalid format."""
        invalid_cve = {
            "cve_id": "INVALID-CVE-ID",  # Invalid CVE ID format
            "published_date": "invalid-date",  # Invalid date format
            "description": "Test",
            "references": [],
            "metrics": {},
            "weaknesses": [],
            "configurations": [],
            "impact": {}
        }
        
        response = client.post(
            "/api/v1/ingestion/cve",
            json=invalid_cve,
            params={"async_processing": False}
        )
        
        assert response.status_code == 400

    def test_invalid_runtime_format(self, client):
        """Test runtime data ingestion with invalid format."""
        invalid_runtime = {
            "session_id": "test-session",
            "host_name": "test-host",
            "start_time": "invalid-time",  # Invalid timestamp
            "events": [
                {
                    "event_id": "test-event",
                    "timestamp": "2023-01-01T00:00:00Z",
                    "event_type": "invalid_type",  # Invalid event type
                    "data": {}
                }
            ],
            "metrics": {},
            "anomalies": []
        }
        
        response = client.post(
            "/api/v1/ingestion/runtime",
            json=invalid_runtime,
            params={"async_processing": False}
        )
        
        assert response.status_code == 400


class TestIngestionAPIMetrics:
    """Test cases for metrics in ingestion API."""

    @pytest.fixture(autouse=True)
    def setup_services(self, mock_app_with_services):
        """Setup services for each test."""
        self.app = mock_app_with_services

    def test_metrics_recording_on_success(self, client, sample_sbom_data):
        """Test that metrics are recorded on successful ingestion."""
        response = client.post(
            "/api/v1/ingestion/sbom",
            json=sample_sbom_data,
            params={"async_processing": False}
        )
        
        assert response.status_code == 200
        
        # Verify metrics service was called
        metrics_service = self.app.state.metrics_service
        assert metrics_service.record_ingestion_request.called
        assert metrics_service.record_validation_result.called
        assert metrics_service.record_data_size.called

    def test_metrics_recording_on_failure(self, client, invalid_sbom_data):
        """Test that metrics are recorded on failed ingestion."""
        response = client.post(
            "/api/v1/ingestion/sbom",
            json=invalid_sbom_data,
            params={"async_processing": False}
        )
        
        assert response.status_code == 400
        
        # Verify metrics service was called
        metrics_service = self.app.state.metrics_service
        assert metrics_service.record_ingestion_request.called
        assert metrics_service.record_validation_result.called