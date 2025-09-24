"""
Tests for integrations API endpoints.
"""
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from shared.database.models.integrations import Integration


class TestIntegrationsAPI:
    """Test integrations CRUD operations."""

    async def test_get_integrations(self, async_client: AsyncClient, auth_headers, test_integration):
        """Test retrieving integrations list."""
        response = await async_client.get(
            "/api/v1/integrations",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "integrations" in data
        assert "total" in data
        assert len(data["integrations"]) >= 1
        assert data["integrations"][0]["id"] == test_integration.id
        assert data["integrations"][0]["name"] == test_integration.name

    async def test_get_integration_by_id(self, async_client: AsyncClient, auth_headers, test_integration):
        """Test retrieving specific integration."""
        response = await async_client.get(
            f"/api/v1/integrations/{test_integration.id}",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == test_integration.id
        assert data["name"] == test_integration.name
        assert data["type"] == test_integration.type
        assert data["provider"] == test_integration.provider
        assert data["status"] == test_integration.status
        assert "config" in data
        assert "health" in data
        assert "metrics" in data

    async def test_get_integration_not_found(self, async_client: AsyncClient, auth_headers):
        """Test retrieving non-existent integration."""
        response = await async_client.get(
            "/api/v1/integrations/nonexistent-id",
            headers=auth_headers
        )
        
        assert response.status_code == 404

    async def test_create_integration(self, async_client: AsyncClient, auth_headers, sample_integration_data):
        """Test creating a new integration."""
        response = await async_client.post(
            "/api/v1/integrations",
            headers=auth_headers,
            json=sample_integration_data
        )
        
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == sample_integration_data["name"]
        assert data["type"] == sample_integration_data["type"]
        assert data["provider"] == sample_integration_data["provider"]
        assert data["status"] == "testing"
        assert data["enabled"] == sample_integration_data["enabled"]
        assert "id" in data
        assert "created_at" in data

    async def test_create_integration_invalid_data(self, async_client: AsyncClient, auth_headers):
        """Test creating integration with invalid data."""
        invalid_data = {
            "name": "",  # Empty name
            "type": "invalid_type",
            "provider": "invalid_provider"
        }
        
        response = await async_client.post(
            "/api/v1/integrations",
            headers=auth_headers,
            json=invalid_data
        )
        
        assert response.status_code == 422

    async def test_update_integration(self, async_client: AsyncClient, auth_headers, test_integration):
        """Test updating an existing integration."""
        update_data = {
            "name": "Updated Integration Name",
            "sync_frequency": 30,
            "config": {
                "endpoint": "https://updated-endpoint.com",
                "timeout": 60
            }
        }
        
        response = await async_client.patch(
            f"/api/v1/integrations/{test_integration.id}",
            headers=auth_headers,
            json=update_data
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == update_data["name"]
        assert data["sync_frequency"] == update_data["sync_frequency"]
        assert data["config"]["endpoint"] == update_data["config"]["endpoint"]
        assert data["id"] == test_integration.id

    async def test_delete_integration(self, async_client: AsyncClient, auth_headers, db_session: AsyncSession, test_user):
        """Test deleting an integration."""
        # Create an integration to delete
        integration = Integration(
            name="Integration to Delete",
            type="siem",
            provider="splunk",
            status="connected",
            enabled=True,
            sync_frequency=15,
            organization_id=test_user.organization_id,
            created_by=test_user.id,
            config={"endpoint": "https://test.com"}
        )
        db_session.add(integration)
        await db_session.commit()
        await db_session.refresh(integration)
        
        response = await async_client.delete(
            f"/api/v1/integrations/{integration.id}",
            headers=auth_headers
        )
        
        assert response.status_code == 204
        
        # Verify integration is deleted
        get_response = await async_client.get(
            f"/api/v1/integrations/{integration.id}",
            headers=auth_headers
        )
        assert get_response.status_code == 404

    async def test_toggle_integration(self, async_client: AsyncClient, auth_headers, test_integration):
        """Test toggling integration enabled status."""
        original_enabled = test_integration.enabled
        
        response = await async_client.post(
            f"/api/v1/integrations/{test_integration.id}/toggle",
            headers=auth_headers,
            json={"enabled": not original_enabled}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["enabled"] == (not original_enabled)
        assert data["message"] == "Integration toggled successfully"

    async def test_test_integration_connection(self, async_client: AsyncClient, auth_headers, test_integration):
        """Test testing integration connection."""
        response = await async_client.post(
            f"/api/v1/integrations/{test_integration.id}/test",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "connection_status" in data
        assert "test_results" in data
        assert "message" in data

    async def test_sync_integration(self, async_client: AsyncClient, auth_headers, test_integration):
        """Test manually syncing an integration."""
        response = await async_client.post(
            f"/api/v1/integrations/{test_integration.id}/sync",
            headers=auth_headers
        )
        
        assert response.status_code == 202
        data = response.json()
        assert data["message"] == "Integration sync started"
        assert "sync_id" in data

    async def test_get_integration_logs(self, async_client: AsyncClient, auth_headers, test_integration):
        """Test retrieving integration logs."""
        response = await async_client.get(
            f"/api/v1/integrations/{test_integration.id}/logs",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "logs" in data
        assert "total" in data
        assert isinstance(data["logs"], list)

    async def test_get_integration_stats(self, async_client: AsyncClient, auth_headers):
        """Test retrieving integration statistics."""
        response = await async_client.get(
            "/api/v1/integrations/stats",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "total_integrations" in data
        assert "connected_integrations" in data
        assert "enabled_integrations" in data
        assert "failed_integrations" in data
        assert "by_type" in data
        assert "by_provider" in data

    async def test_get_integration_providers(self, async_client: AsyncClient, auth_headers):
        """Test retrieving available integration providers."""
        response = await async_client.get(
            "/api/v1/integrations/providers",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "providers" in data
        assert isinstance(data["providers"], list)
        
        if data["providers"]:
            provider = data["providers"][0]
            assert "name" in provider
            assert "type" in provider
            assert "description" in provider
            assert "config_schema" in provider

    async def test_unauthorized_access(self, async_client: AsyncClient):
        """Test unauthorized access to integrations."""
        response = await async_client.get("/api/v1/integrations")
        assert response.status_code == 401

    async def test_pagination(self, async_client: AsyncClient, auth_headers):
        """Test integrations pagination."""
        response = await async_client.get(
            "/api/v1/integrations?page=1&limit=10",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "integrations" in data
        assert "total" in data
        assert "page" in data
        assert "limit" in data
        assert len(data["integrations"]) <= 10

    async def test_filtering_by_type(self, async_client: AsyncClient, auth_headers):
        """Test filtering integrations by type."""
        response = await async_client.get(
            "/api/v1/integrations?type=siem",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "integrations" in data
        for integration in data["integrations"]:
            assert integration["type"] == "siem"

    async def test_filtering_by_status(self, async_client: AsyncClient, auth_headers):
        """Test filtering integrations by status."""
        response = await async_client.get(
            "/api/v1/integrations?status=connected",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "integrations" in data
        for integration in data["integrations"]:
            assert integration["status"] == "connected"

    async def test_filtering_by_enabled(self, async_client: AsyncClient, auth_headers):
        """Test filtering integrations by enabled status."""
        response = await async_client.get(
            "/api/v1/integrations?enabled=true",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "integrations" in data
        for integration in data["integrations"]:
            assert integration["enabled"] == True


class TestIntegrationWebhooks:
    """Test integration webhook functionality."""

    async def test_create_webhook(self, async_client: AsyncClient, auth_headers, test_integration):
        """Test creating a webhook for an integration."""
        webhook_data = {
            "url": "https://webhook.example.com/integration",
            "events": ["sync_completed", "sync_failed", "connection_lost"],
            "secret": "webhook-secret-key",
            "enabled": True
        }
        
        response = await async_client.post(
            f"/api/v1/integrations/{test_integration.id}/webhooks",
            headers=auth_headers,
            json=webhook_data
        )
        
        assert response.status_code == 201
        data = response.json()
        assert data["url"] == webhook_data["url"]
        assert data["events"] == webhook_data["events"]
        assert data["enabled"] == webhook_data["enabled"]
        assert "id" in data
        assert "secret" not in data  # Secret should not be returned

    async def test_get_integration_webhooks(self, async_client: AsyncClient, auth_headers, test_integration):
        """Test retrieving integration webhooks."""
        response = await async_client.get(
            f"/api/v1/integrations/{test_integration.id}/webhooks",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "webhooks" in data
        assert isinstance(data["webhooks"], list)

    async def test_test_webhook(self, async_client: AsyncClient, auth_headers, test_integration):
        """Test testing a webhook endpoint."""
        # First create a webhook
        webhook_data = {
            "url": "https://webhook.example.com/test",
            "events": ["test_event"],
            "enabled": True
        }
        
        create_response = await async_client.post(
            f"/api/v1/integrations/{test_integration.id}/webhooks",
            headers=auth_headers,
            json=webhook_data
        )
        webhook_id = create_response.json()["id"]
        
        # Test the webhook
        response = await async_client.post(
            f"/api/v1/integrations/{test_integration.id}/webhooks/{webhook_id}/test",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "test_result" in data
        assert "response_time" in data
        assert "status_code" in data


class TestIntegrationSecurity:
    """Test integration security and access control."""

    async def test_organization_isolation(self, async_client: AsyncClient, auth_headers, db_session: AsyncSession):
        """Test that users can only access their organization's integrations."""
        from shared.database.models.organizations import Organization
        from shared.database.models.users import User
        from core.security import get_password_hash
        
        # Create another organization and integration
        other_org = Organization(
            name="Other Organization",
            domain="other.com",
            subscription_tier="basic",
            is_active=True
        )
        db_session.add(other_org)
        await db_session.flush()
        
        other_user = User(
            username="otheruser",
            email="other@other.com",
            hashed_password=get_password_hash("password123"),
            first_name="Other",
            last_name="User",
            organization_id=other_org.id,
            is_active=True,
            is_verified=True,
        )
        db_session.add(other_user)
        await db_session.flush()
        
        other_integration = Integration(
            name="Other Organization Integration",
            type="siem",
            provider="splunk",
            status="connected",
            enabled=True,
            sync_frequency=15,
            organization_id=other_org.id,
            created_by=other_user.id,
            config={"endpoint": "https://other.com"}
        )
        db_session.add(other_integration)
        await db_session.commit()
        
        # Try to access other organization's integration
        response = await async_client.get(
            f"/api/v1/integrations/{other_integration.id}",
            headers=auth_headers
        )
        
        assert response.status_code == 404

    async def test_permissions_required(self, async_client: AsyncClient, auth_headers, sample_integration_data):
        """Test that proper permissions are required for integration operations."""
        response = await async_client.post(
            "/api/v1/integrations",
            headers=auth_headers,
            json=sample_integration_data
        )
        
        # Should succeed with proper permissions
        assert response.status_code == 201

    async def test_sensitive_config_masking(self, async_client: AsyncClient, auth_headers, test_integration):
        """Test that sensitive configuration data is masked in responses."""
        response = await async_client.get(
            f"/api/v1/integrations/{test_integration.id}",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Sensitive fields should be masked or excluded
        if "config" in data:
            config = data["config"]
            for key, value in config.items():
                if key.lower() in ['password', 'secret', 'token', 'key', 'credential']:
                    assert value == "***masked***" or value is None


class TestIntegrationMetrics:
    """Test integration metrics and monitoring."""

    async def test_get_integration_metrics(self, async_client: AsyncClient, auth_headers, test_integration):
        """Test retrieving integration metrics."""
        response = await async_client.get(
            f"/api/v1/integrations/{test_integration.id}/metrics",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "metrics" in data
        assert "time_range" in data
        
        metrics = data["metrics"]
        assert "events_ingested" in metrics
        assert "data_exported" in metrics
        assert "sync_errors" in metrics
        assert "uptime_percentage" in metrics

    async def test_get_integration_health(self, async_client: AsyncClient, auth_headers, test_integration):
        """Test retrieving integration health status."""
        response = await async_client.get(
            f"/api/v1/integrations/{test_integration.id}/health",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "last_check" in data
        assert "checks" in data
        
        assert data["status"] in ["healthy", "warning", "error"]
        assert isinstance(data["checks"], list)
