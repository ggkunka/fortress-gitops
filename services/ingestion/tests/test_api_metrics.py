"""Tests for the metrics API endpoints."""

import pytest
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient

from services.ingestion.main import app


class TestMetricsAPI:
    """Test cases for metrics API endpoints."""

    @pytest.fixture(autouse=True)
    def setup_services(self, mock_app_with_services):
        """Setup services for each test."""
        self.app = mock_app_with_services

    def test_get_prometheus_metrics(self, client):
        """Test Prometheus metrics endpoint."""
        response = client.get("/metrics/")
        
        assert response.status_code == 200
        assert "text/plain" in response.headers["content-type"]
        
        # Check for some expected Prometheus metrics
        content = response.content.decode()
        assert "ingestion_requests_total" in content
        assert "validation_results_total" in content
        assert "events_published_total" in content

    def test_get_metrics_summary(self, client):
        """Test metrics summary endpoint."""
        response = client.get("/metrics/summary")
        
        assert response.status_code == 200
        response_data = response.json()
        
        assert "timestamp" in response_data
        assert "uptime_seconds" in response_data
        assert "ingestion_requests" in response_data
        assert "validation_results" in response_data
        assert "event_publications" in response_data
        assert "error_counts" in response_data
        assert "processing_times" in response_data
        assert "data_sizes" in response_data

    def test_get_health_metrics(self, client):
        """Test health metrics endpoint."""
        response = client.get("/metrics/health")
        
        assert response.status_code == 200
        response_data = response.json()
        
        assert "status" in response_data
        assert "total_requests" in response_data
        assert "total_errors" in response_data
        assert "uptime_seconds" in response_data
        assert "timestamp" in response_data

    def test_get_data_type_metrics_sbom(self, client):
        """Test data type metrics for SBOM."""
        response = client.get("/metrics/data-type/sbom")
        
        assert response.status_code == 200
        response_data = response.json()
        
        assert response_data["data_type"] == "sbom"
        assert "requests" in response_data
        assert "validations" in response_data
        assert "events" in response_data
        assert "processing_times" in response_data
        assert "data_sizes" in response_data

    def test_get_data_type_metrics_cve(self, client):
        """Test data type metrics for CVE."""
        response = client.get("/metrics/data-type/cve")
        
        assert response.status_code == 200
        response_data = response.json()
        
        assert response_data["data_type"] == "cve"

    def test_get_data_type_metrics_runtime(self, client):
        """Test data type metrics for runtime."""
        response = client.get("/metrics/data-type/runtime")
        
        assert response.status_code == 200
        response_data = response.json()
        
        assert response_data["data_type"] == "runtime"

    def test_get_data_type_metrics_invalid(self, client):
        """Test data type metrics for invalid type."""
        response = client.get("/metrics/data-type/invalid")
        
        assert response.status_code == 400
        response_data = response.json()
        
        assert "Invalid data type" in response_data["detail"]

    def test_get_ingestion_metrics(self, client):
        """Test ingestion metrics endpoint."""
        response = client.get("/metrics/ingestion")
        
        assert response.status_code == 200
        response_data = response.json()
        
        assert "timestamp" in response_data
        assert "uptime_seconds" in response_data
        assert "total_requests" in response_data
        assert "validation_results" in response_data
        assert "event_publications" in response_data
        assert "error_counts" in response_data
        assert "processing_times" in response_data
        assert "data_sizes" in response_data

    def test_get_ingestion_metrics_filtered(self, client):
        """Test ingestion metrics filtered by data type."""
        response = client.get("/metrics/ingestion", params={"data_type": "sbom"})
        
        assert response.status_code == 200
        response_data = response.json()
        
        assert response_data["data_type"] == "sbom"
        assert "requests" in response_data
        assert "validations" in response_data
        assert "events" in response_data

    def test_get_performance_metrics(self, client):
        """Test performance metrics endpoint."""
        response = client.get("/metrics/performance")
        
        assert response.status_code == 200
        response_data = response.json()
        
        assert "timestamp" in response_data
        assert "uptime_seconds" in response_data
        assert "processing_times" in response_data
        assert "data_sizes" in response_data
        assert "throughput" in response_data
        assert "error_rate" in response_data

    def test_get_error_metrics(self, client):
        """Test error metrics endpoint."""
        response = client.get("/metrics/errors")
        
        assert response.status_code == 200
        response_data = response.json()
        
        assert "timestamp" in response_data
        assert "uptime_seconds" in response_data
        assert "total_errors" in response_data
        assert "validation_failures" in response_data
        assert "failed_requests" in response_data

    def test_reset_metrics(self, client):
        """Test metrics reset endpoint."""
        response = client.post("/metrics/reset")
        
        assert response.status_code == 200
        response_data = response.json()
        
        assert "reset successfully" in response_data["message"]
        assert "timestamp" in response_data

    def test_cleanup_metrics(self, client):
        """Test metrics cleanup endpoint."""
        response = client.post("/metrics/cleanup", params={"max_age_hours": 12})
        
        assert response.status_code == 200
        response_data = response.json()
        
        assert "cleaned up" in response_data["message"]
        assert "timestamp" in response_data

    def test_cleanup_metrics_default(self, client):
        """Test metrics cleanup with default parameters."""
        response = client.post("/metrics/cleanup")
        
        assert response.status_code == 200
        response_data = response.json()
        
        assert "24 hours" in response_data["message"]

    @patch('services.ingestion.services.metrics.generate_latest')
    def test_prometheus_metrics_generation_error(self, mock_generate, client):
        """Test Prometheus metrics generation error."""
        mock_generate.side_effect = Exception("Metrics generation failed")
        
        response = client.get("/metrics/")
        
        assert response.status_code == 500
        content = response.content.decode()
        assert "Error generating metrics" in content

    @patch('services.ingestion.services.metrics.MetricsService.get_metrics_summary')
    def test_metrics_summary_error(self, mock_summary, client):
        """Test metrics summary error handling."""
        mock_summary.side_effect = Exception("Summary generation failed")
        
        response = client.get("/metrics/summary")
        
        assert response.status_code == 500
        response_data = response.json()
        
        assert "error" in response_data

    @patch('services.ingestion.services.metrics.MetricsService.get_health_metrics')
    def test_health_metrics_error(self, mock_health, client):
        """Test health metrics error handling."""
        mock_health.side_effect = Exception("Health metrics failed")
        
        response = client.get("/metrics/health")
        
        assert response.status_code == 500
        response_data = response.json()
        
        assert "error" in response_data

    @patch('services.ingestion.services.metrics.MetricsService.get_data_type_metrics')
    def test_data_type_metrics_error(self, mock_data_type, client):
        """Test data type metrics error handling."""
        mock_data_type.side_effect = Exception("Data type metrics failed")
        
        response = client.get("/metrics/data-type/sbom")
        
        assert response.status_code == 500
        response_data = response.json()
        
        assert "error" in response_data

    @patch('services.ingestion.services.metrics.MetricsService.reset_metrics')
    def test_reset_metrics_error(self, mock_reset, client):
        """Test reset metrics error handling."""
        mock_reset.side_effect = Exception("Reset failed")
        
        response = client.post("/metrics/reset")
        
        assert response.status_code == 500
        response_data = response.json()
        
        assert "error" in response_data

    @patch('services.ingestion.services.metrics.MetricsService.cleanup_old_data')
    def test_cleanup_metrics_error(self, mock_cleanup, client):
        """Test cleanup metrics error handling."""
        mock_cleanup.side_effect = Exception("Cleanup failed")
        
        response = client.post("/metrics/cleanup")
        
        assert response.status_code == 500
        response_data = response.json()
        
        assert "error" in response_data


class TestMetricsAPIAsync:
    """Test cases for async metrics API endpoints."""

    @pytest.fixture(autouse=True)
    def setup_services(self, mock_app_with_services):
        """Setup services for each test."""
        self.app = mock_app_with_services

    @pytest.mark.asyncio
    async def test_async_prometheus_metrics(self, async_client):
        """Test Prometheus metrics with async client."""
        response = await async_client.get("/metrics/")
        
        assert response.status_code == 200
        assert "text/plain" in response.headers["content-type"]

    @pytest.mark.asyncio
    async def test_async_metrics_summary(self, async_client):
        """Test metrics summary with async client."""
        response = await async_client.get("/metrics/summary")
        
        assert response.status_code == 200
        response_data = response.json()
        assert "timestamp" in response_data

    @pytest.mark.asyncio
    async def test_async_health_metrics(self, async_client):
        """Test health metrics with async client."""
        response = await async_client.get("/metrics/health")
        
        assert response.status_code == 200
        response_data = response.json()
        assert "status" in response_data

    @pytest.mark.asyncio
    async def test_async_data_type_metrics(self, async_client):
        """Test data type metrics with async client."""
        response = await async_client.get("/metrics/data-type/sbom")
        
        assert response.status_code == 200
        response_data = response.json()
        assert response_data["data_type"] == "sbom"

    @pytest.mark.asyncio
    async def test_async_ingestion_metrics(self, async_client):
        """Test ingestion metrics with async client."""
        response = await async_client.get("/metrics/ingestion")
        
        assert response.status_code == 200
        response_data = response.json()
        assert "total_requests" in response_data

    @pytest.mark.asyncio
    async def test_async_performance_metrics(self, async_client):
        """Test performance metrics with async client."""
        response = await async_client.get("/metrics/performance")
        
        assert response.status_code == 200
        response_data = response.json()
        assert "throughput" in response_data

    @pytest.mark.asyncio
    async def test_async_error_metrics(self, async_client):
        """Test error metrics with async client."""
        response = await async_client.get("/metrics/errors")
        
        assert response.status_code == 200
        response_data = response.json()
        assert "total_errors" in response_data

    @pytest.mark.asyncio
    async def test_async_reset_metrics(self, async_client):
        """Test metrics reset with async client."""
        response = await async_client.post("/metrics/reset")
        
        assert response.status_code == 200
        response_data = response.json()
        assert "reset successfully" in response_data["message"]

    @pytest.mark.asyncio
    async def test_async_cleanup_metrics(self, async_client):
        """Test metrics cleanup with async client."""
        response = await async_client.post("/metrics/cleanup")
        
        assert response.status_code == 200
        response_data = response.json()
        assert "cleaned up" in response_data["message"]


class TestMetricsAPIIntegration:
    """Integration tests for metrics API endpoints."""

    @pytest.fixture(autouse=True)
    def setup_services(self, mock_app_with_services):
        """Setup services for each test."""
        self.app = mock_app_with_services

    def test_metrics_flow_after_ingestion(self, client, sample_sbom_data):
        """Test metrics flow after data ingestion."""
        # First, ingest some data
        response = client.post(
            "/api/v1/ingestion/sbom",
            json=sample_sbom_data,
            params={"async_processing": False}
        )
        assert response.status_code == 200
        
        # Now check metrics
        response = client.get("/metrics/summary")
        assert response.status_code == 200
        
        response_data = response.json()
        assert "ingestion_requests" in response_data
        assert "validation_results" in response_data

    def test_error_metrics_after_validation_failure(self, client, invalid_sbom_data):
        """Test error metrics after validation failure."""
        # First, trigger validation failure
        response = client.post(
            "/api/v1/ingestion/sbom",
            json=invalid_sbom_data,
            params={"async_processing": False}
        )
        assert response.status_code == 400
        
        # Now check error metrics
        response = client.get("/metrics/errors")
        assert response.status_code == 200
        
        response_data = response.json()
        assert "validation_failures" in response_data
        assert "failed_requests" in response_data

    def test_data_type_specific_metrics(self, client, sample_sbom_data, sample_cve_data):
        """Test data type specific metrics."""
        # Ingest different data types
        client.post("/api/v1/ingestion/sbom", json=sample_sbom_data)
        client.post("/api/v1/ingestion/cve", json=sample_cve_data)
        
        # Check SBOM metrics
        response = client.get("/metrics/data-type/sbom")
        assert response.status_code == 200
        sbom_metrics = response.json()
        
        # Check CVE metrics
        response = client.get("/metrics/data-type/cve")
        assert response.status_code == 200
        cve_metrics = response.json()
        
        assert sbom_metrics["data_type"] == "sbom"
        assert cve_metrics["data_type"] == "cve"

    def test_performance_metrics_calculation(self, client, sample_sbom_data):
        """Test performance metrics calculation."""
        # Ingest data to generate metrics
        for i in range(5):
            client.post("/api/v1/ingestion/sbom", json=sample_sbom_data)
        
        # Check performance metrics
        response = client.get("/metrics/performance")
        assert response.status_code == 200
        
        response_data = response.json()
        assert "throughput" in response_data
        assert "error_rate" in response_data
        assert "processing_times" in response_data

    def test_metrics_reset_functionality(self, client, sample_sbom_data):
        """Test metrics reset functionality."""
        # Generate some metrics
        client.post("/api/v1/ingestion/sbom", json=sample_sbom_data)
        
        # Check metrics exist
        response = client.get("/metrics/summary")
        assert response.status_code == 200
        
        # Reset metrics
        response = client.post("/metrics/reset")
        assert response.status_code == 200
        
        # Check metrics are reset
        response = client.get("/metrics/summary")
        assert response.status_code == 200
        
        # Verify metrics service reset was called
        metrics_service = self.app.state.metrics_service
        assert metrics_service.reset_metrics.called

    def test_metrics_cleanup_functionality(self, client):
        """Test metrics cleanup functionality."""
        # Test cleanup with different parameters
        response = client.post("/metrics/cleanup", params={"max_age_hours": 6})
        assert response.status_code == 200
        
        # Verify cleanup was called
        metrics_service = self.app.state.metrics_service
        assert metrics_service.cleanup_old_data.called