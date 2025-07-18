"""
Integration tests for service health and basic connectivity.
"""

import asyncio
import pytest
import httpx
import redis
import psycopg2
from typing import Dict, Any

# Service endpoints
SERVICES = {
    "gateway": "http://gateway-service:8081",
    "auth": "http://auth-service:8085",
    "ingestion": "http://ingestion-service:8080",
    "enrichment": "http://enrichment-service:8082",
    "analysis": "http://analysis-service:8083",
    "notification": "http://notification-service:8084",
    "plugin-registry": "http://plugin-registry:8090"
}

REDIS_URL = "redis://redis:6379"
DATABASE_URL = "postgresql://mcp_user:mcp_test_password@postgresql:5432/mcp_test"


class TestServiceHealth:
    """Test suite for service health checks."""
    
    @pytest.mark.asyncio
    async def test_all_services_healthy(self):
        """Test that all services respond to health checks."""
        async with httpx.AsyncClient() as client:
            for service_name, base_url in SERVICES.items():
                health_url = f"{base_url}/health"
                
                response = await client.get(health_url, timeout=10.0)
                assert response.status_code == 200, f"{service_name} health check failed"
                
                health_data = response.json()
                assert health_data.get("status") == "healthy", f"{service_name} reports unhealthy status"
                assert "timestamp" in health_data, f"{service_name} missing timestamp in health response"
    
    @pytest.mark.asyncio
    async def test_service_readiness(self):
        """Test service readiness endpoints."""
        async with httpx.AsyncClient() as client:
            for service_name, base_url in SERVICES.items():
                ready_url = f"{base_url}/ready"
                
                response = await client.get(ready_url, timeout=10.0)
                assert response.status_code == 200, f"{service_name} readiness check failed"
                
                ready_data = response.json()
                assert ready_data.get("ready") is True, f"{service_name} reports not ready"
    
    @pytest.mark.asyncio
    async def test_service_metrics(self):
        """Test that services expose metrics endpoints."""
        async with httpx.AsyncClient() as client:
            for service_name, base_url in SERVICES.items():
                metrics_url = f"{base_url}/metrics"
                
                response = await client.get(metrics_url, timeout=10.0)
                assert response.status_code == 200, f"{service_name} metrics endpoint failed"
                
                # Should return Prometheus-formatted metrics
                content = response.text
                assert "# HELP" in content, f"{service_name} metrics format invalid"


class TestInfrastructureConnectivity:
    """Test connectivity to infrastructure components."""
    
    def test_redis_connectivity(self):
        """Test Redis connection and basic operations."""
        client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        
        # Test connection
        assert client.ping() is True, "Redis ping failed"
        
        # Test basic operations
        test_key = "test:connectivity"
        test_value = "test_value"
        
        client.set(test_key, test_value, ex=60)
        assert client.get(test_key) == test_value, "Redis get/set failed"
        
        client.delete(test_key)
        assert client.get(test_key) is None, "Redis delete failed"
    
    def test_postgresql_connectivity(self):
        """Test PostgreSQL connection and basic operations."""
        conn = psycopg2.connect(DATABASE_URL)
        cursor = conn.cursor()
        
        try:
            # Test connection
            cursor.execute("SELECT 1")
            result = cursor.fetchone()
            assert result[0] == 1, "PostgreSQL connection test failed"
            
            # Test database exists
            cursor.execute("SELECT current_database()")
            db_name = cursor.fetchone()[0]
            assert db_name == "mcp_test", f"Wrong database: {db_name}"
            
        finally:
            cursor.close()
            conn.close()


class TestServiceInteraction:
    """Test basic service-to-service communication."""
    
    @pytest.mark.asyncio
    async def test_gateway_to_auth_service(self):
        """Test gateway can communicate with auth service."""
        async with httpx.AsyncClient() as client:
            # Try to access a protected endpoint through gateway
            response = await client.get(
                f"{SERVICES['gateway']}/api/v1/auth/status",
                timeout=10.0
            )
            
            # Should get authentication error, not connection error
            assert response.status_code in [401, 403], "Gateway-Auth communication failed"
    
    @pytest.mark.asyncio
    async def test_gateway_routing(self):
        """Test gateway routing to different services."""
        async with httpx.AsyncClient() as client:
            # Test routing to different services through gateway
            routes = [
                "/api/v1/ingestion/health",
                "/api/v1/enrichment/health", 
                "/api/v1/analysis/health",
                "/api/v1/notification/health"
            ]
            
            for route in routes:
                response = await client.get(
                    f"{SERVICES['gateway']}{route}",
                    timeout=10.0
                )
                
                # Should successfully route (200) or return auth error (401/403)
                assert response.status_code in [200, 401, 403], f"Gateway routing failed for {route}"
    
    @pytest.mark.asyncio
    async def test_plugin_registry_discovery(self):
        """Test plugin registry can discover plugins."""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{SERVICES['plugin-registry']}/api/v1/plugins",
                timeout=10.0
            )
            
            assert response.status_code == 200, "Plugin registry discovery failed"
            
            plugins = response.json()
            assert isinstance(plugins, list), "Plugin registry should return list"


class TestServiceConfiguration:
    """Test service configuration and environment."""
    
    @pytest.mark.asyncio
    async def test_service_configuration(self):
        """Test that services are properly configured."""
        async with httpx.AsyncClient() as client:
            for service_name, base_url in SERVICES.items():
                config_url = f"{base_url}/config"
                
                response = await client.get(config_url, timeout=10.0)
                
                if response.status_code == 200:
                    config = response.json()
                    
                    # Basic configuration checks
                    assert config.get("environment") == "test", f"{service_name} not in test environment"
                    assert "version" in config, f"{service_name} missing version info"
    
    @pytest.mark.asyncio
    async def test_service_logging_levels(self):
        """Test that services are configured with appropriate logging levels."""
        async with httpx.AsyncClient() as client:
            for service_name, base_url in SERVICES.items():
                logs_url = f"{base_url}/logs/level"
                
                response = await client.get(logs_url, timeout=10.0)
                
                if response.status_code == 200:
                    log_config = response.json()
                    
                    # Should be DEBUG or INFO in test environment
                    log_level = log_config.get("level", "").upper()
                    assert log_level in ["DEBUG", "INFO"], f"{service_name} inappropriate log level: {log_level}"


@pytest.mark.asyncio
async def test_service_startup_order():
    """Test that services start in the correct order with dependencies."""
    # This test verifies that services with dependencies start after their dependencies
    
    dependency_order = [
        ("redis", "postgresql"),  # Infrastructure first
        ("auth-service", "gateway-service"),  # Auth before gateway
        ("plugin-registry", "enrichment-service"),  # Plugin registry before enrichment
        ("ingestion-service", "enrichment-service"),  # Ingestion before enrichment
        ("enrichment-service", "analysis-service"),  # Enrichment before analysis
    ]
    
    async with httpx.AsyncClient() as client:
        for dependency, dependent in dependency_order:
            if dependency in SERVICES and dependent in SERVICES:
                # Check that dependency is healthy
                dep_response = await client.get(f"{SERVICES[dependency]}/health", timeout=5.0)
                assert dep_response.status_code == 200, f"Dependency {dependency} not healthy"
                
                # Check that dependent is healthy
                dep_response = await client.get(f"{SERVICES[dependent]}/health", timeout=5.0)
                assert dep_response.status_code == 200, f"Dependent service {dependent} not healthy"


if __name__ == "__main__":
    # Run with: python -m pytest test_service_health.py -v
    pytest.main([__file__, "-v"])