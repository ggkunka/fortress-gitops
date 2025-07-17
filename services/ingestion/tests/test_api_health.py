"""Tests for the health API endpoints."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient

from services.ingestion.main import app


class TestHealthAPI:
    """Test cases for health API endpoints."""

    @pytest.fixture(autouse=True)
    def setup_services(self, mock_app_with_services):
        """Setup services for each test."""
        self.app = mock_app_with_services

    def test_health_check_healthy(self, client):
        """Test health check when all services are healthy."""
        response = client.get("/health/")
        
        assert response.status_code == 200
        response_data = response.json()
        
        assert response_data["service"] == "ingestion"
        assert response_data["status"] == "healthy"
        assert "timestamp" in response_data
        assert "version" in response_data
        assert "components" in response_data
        assert "metrics" in response_data
        
        # Check component health
        components = response_data["components"]
        assert "event_bus" in components
        assert "validation" in components
        assert "metrics" in components

    def test_health_check_degraded(self, client):
        """Test health check when some services are degraded."""
        # Mock event bus as disconnected
        event_bus = self.app.state.event_bus_service
        event_bus.is_connected = False
        event_bus.health_check = AsyncMock(return_value={"status": "degraded"})
        
        response = client.get("/health/")
        
        assert response.status_code == 503
        response_data = response.json()
        assert response_data["status"] == "degraded"

    def test_readiness_check_ready(self, client):
        """Test readiness check when service is ready."""
        response = client.get("/health/ready")
        
        assert response.status_code == 200
        response_data = response.json()
        
        assert response_data["ready"] is True
        assert "message" in response_data
        assert "timestamp" in response_data

    def test_readiness_check_not_ready(self, client):
        """Test readiness check when service is not ready."""
        # Mock event bus as disconnected
        event_bus = self.app.state.event_bus_service
        event_bus.is_connected = False
        
        response = client.get("/health/ready")
        
        assert response.status_code == 503
        response_data = response.json()
        
        assert response_data["ready"] is False
        assert "Event bus not connected" in response_data["message"]

    def test_liveness_check(self, client):
        """Test liveness check."""
        response = client.get("/health/live")
        
        assert response.status_code == 200
        response_data = response.json()
        
        assert response_data["live"] is True
        assert "message" in response_data
        assert "timestamp" in response_data

    def test_startup_check_complete(self, client):
        """Test startup check when service is fully started."""
        response = client.get("/health/startup")
        
        assert response.status_code == 200
        response_data = response.json()
        
        assert response_data["started"] is True
        assert "message" in response_data
        assert "checks" in response_data
        assert "timestamp" in response_data
        
        # Check startup checks
        checks = response_data["checks"]
        assert "event_bus_connected" in checks
        assert "validation_service_ready" in checks
        assert "metrics_service_ready" in checks

    def test_startup_check_incomplete(self, client):
        """Test startup check when service startup is incomplete."""
        # Mock event bus as disconnected
        event_bus = self.app.state.event_bus_service
        event_bus.is_connected = False
        
        response = client.get("/health/startup")
        
        assert response.status_code == 503
        response_data = response.json()
        
        assert response_data["started"] is False
        assert "incomplete" in response_data["message"]
        assert response_data["checks"]["event_bus_connected"] is False

    def test_service_status(self, client):
        """Test service status endpoint."""
        response = client.get("/health/services")
        
        assert response.status_code == 200
        response_data = response.json()
        
        assert "services" in response_data
        assert "timestamp" in response_data
        
        services = response_data["services"]
        assert "event_bus" in services
        assert "validation" in services
        assert "metrics" in services

    def test_dependency_check_healthy(self, client):
        """Test dependency check when all dependencies are healthy."""
        response = client.get("/health/dependencies")
        
        assert response.status_code == 200
        response_data = response.json()
        
        assert response_data["status"] == "healthy"
        assert "dependencies" in response_data
        assert "timestamp" in response_data
        
        dependencies = response_data["dependencies"]
        assert "redis" in dependencies
        assert dependencies["redis"]["connected"] is True

    def test_dependency_check_degraded(self, client):
        """Test dependency check when dependencies are degraded."""
        # Mock event bus as disconnected
        event_bus = self.app.state.event_bus_service
        event_bus.is_connected = False
        
        response = client.get("/health/dependencies")
        
        assert response.status_code == 200
        response_data = response.json()
        
        assert response_data["status"] == "degraded"
        assert response_data["dependencies"]["redis"]["connected"] is False

    @patch('services.ingestion.services.event_bus.EventBusService.health_check')
    def test_health_check_exception(self, mock_health_check, client):
        """Test health check when service raises exception."""
        mock_health_check.side_effect = Exception("Service unavailable")
        
        response = client.get("/health/")
        
        assert response.status_code == 500
        response_data = response.json()
        
        assert response_data["service"] == "ingestion"
        assert response_data["status"] == "unhealthy"
        assert "error" in response_data

    @patch('services.ingestion.services.event_bus.EventBusService.health_check')
    def test_readiness_check_exception(self, mock_health_check, client):
        """Test readiness check when service raises exception."""
        mock_health_check.side_effect = Exception("Service unavailable")
        
        response = client.get("/health/ready")
        
        assert response.status_code == 500
        response_data = response.json()
        
        assert response_data["ready"] is False
        assert "failed" in response_data["message"]

    @patch('services.ingestion.services.event_bus.EventBusService.health_check')
    def test_startup_check_exception(self, mock_health_check, client):
        """Test startup check when service raises exception."""
        mock_health_check.side_effect = Exception("Service unavailable")
        
        response = client.get("/health/startup")
        
        assert response.status_code == 500
        response_data = response.json()
        
        assert response_data["started"] is False
        assert "failed" in response_data["message"]

    @patch('services.ingestion.services.event_bus.EventBusService.health_check')
    def test_service_status_exception(self, mock_health_check, client):
        """Test service status when service raises exception."""
        mock_health_check.side_effect = Exception("Service unavailable")
        
        response = client.get("/health/services")
        
        assert response.status_code == 500
        response_data = response.json()
        
        assert "error" in response_data

    def test_liveness_check_exception(self, client):
        """Test liveness check exception handling."""
        with patch('services.ingestion.api.health.datetime') as mock_datetime:
            mock_datetime.utcnow.side_effect = Exception("Time service unavailable")
            
            response = client.get("/health/live")
            
            assert response.status_code == 500
            response_data = response.json()
            
            assert response_data["live"] is False
            assert "failed" in response_data["message"]


class TestHealthAPIAsync:
    """Test cases for async health API endpoints."""

    @pytest.fixture(autouse=True)
    def setup_services(self, mock_app_with_services):
        """Setup services for each test."""
        self.app = mock_app_with_services

    @pytest.mark.asyncio
    async def test_async_health_check(self, async_client):
        """Test health check with async client."""
        response = await async_client.get("/health/")
        
        assert response.status_code == 200
        response_data = response.json()
        assert response_data["service"] == "ingestion"

    @pytest.mark.asyncio
    async def test_async_readiness_check(self, async_client):
        """Test readiness check with async client."""
        response = await async_client.get("/health/ready")
        
        assert response.status_code == 200
        response_data = response.json()
        assert response_data["ready"] is True

    @pytest.mark.asyncio
    async def test_async_liveness_check(self, async_client):
        """Test liveness check with async client."""
        response = await async_client.get("/health/live")
        
        assert response.status_code == 200
        response_data = response.json()
        assert response_data["live"] is True

    @pytest.mark.asyncio
    async def test_async_startup_check(self, async_client):
        """Test startup check with async client."""
        response = await async_client.get("/health/startup")
        
        assert response.status_code == 200
        response_data = response.json()
        assert response_data["started"] is True

    @pytest.mark.asyncio
    async def test_async_service_status(self, async_client):
        """Test service status with async client."""
        response = await async_client.get("/health/services")
        
        assert response.status_code == 200
        response_data = response.json()
        assert "services" in response_data

    @pytest.mark.asyncio
    async def test_async_dependency_check(self, async_client):
        """Test dependency check with async client."""
        response = await async_client.get("/health/dependencies")
        
        assert response.status_code == 200
        response_data = response.json()
        assert "dependencies" in response_data


class TestHealthAPIIntegration:
    """Integration tests for health API endpoints."""

    @pytest.fixture(autouse=True)
    def setup_services(self, mock_app_with_services):
        """Setup services for each test."""
        self.app = mock_app_with_services

    def test_health_check_flow(self, client):
        """Test complete health check flow."""
        # Test liveness first
        response = client.get("/health/live")
        assert response.status_code == 200
        
        # Test readiness
        response = client.get("/health/ready")
        assert response.status_code == 200
        
        # Test startup
        response = client.get("/health/startup")
        assert response.status_code == 200
        
        # Test full health check
        response = client.get("/health/")
        assert response.status_code == 200

    def test_health_check_with_degraded_services(self, client):
        """Test health check with degraded services."""
        # Mock event bus as disconnected
        event_bus = self.app.state.event_bus_service
        event_bus.is_connected = False
        event_bus.health_check = AsyncMock(return_value={"status": "degraded"})
        
        # Liveness should still pass
        response = client.get("/health/live")
        assert response.status_code == 200
        
        # Readiness should fail
        response = client.get("/health/ready")
        assert response.status_code == 503
        
        # Startup should fail
        response = client.get("/health/startup")
        assert response.status_code == 503
        
        # Full health check should be degraded
        response = client.get("/health/")
        assert response.status_code == 503

    def test_metrics_integration_in_health(self, client):
        """Test metrics integration in health endpoints."""
        # Mock metrics service to return specific health data
        metrics_service = self.app.state.metrics_service
        metrics_service.get_health_metrics.return_value = {
            "status": "healthy",
            "total_requests": 100,
            "total_errors": 0,
            "uptime_seconds": 3600,
        }
        
        response = client.get("/health/")
        assert response.status_code == 200
        
        response_data = response.json()
        assert "metrics" in response_data
        
        health_metrics = response_data["metrics"]
        assert health_metrics["status"] == "healthy"
        assert health_metrics["total_requests"] == 100
        assert health_metrics["total_errors"] == 0

    def test_event_bus_health_integration(self, client):
        """Test event bus health integration."""
        # Mock event bus health check
        event_bus = self.app.state.event_bus_service
        event_bus.health_check = AsyncMock(return_value={
            "connected": True,
            "redis_ping": True,
            "redis_version": "7.0.0",
            "active_channels": 5,
        })
        
        response = client.get("/health/services")
        assert response.status_code == 200
        
        response_data = response.json()
        event_bus_health = response_data["services"]["event_bus"]
        assert event_bus_health["connected"] is True
        assert event_bus_health["redis_ping"] is True
        assert event_bus_health["active_channels"] == 5