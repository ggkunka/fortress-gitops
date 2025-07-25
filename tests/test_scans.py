"""
Tests for scans API endpoints.
"""
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from shared.database.models.scans import Scan


class TestScansAPI:
    """Test scans CRUD operations."""

    async def test_get_scans(self, async_client: AsyncClient, auth_headers, test_scan):
        """Test retrieving scans list."""
        response = await async_client.get(
            "/api/v1/scans",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "scans" in data
        assert "total" in data
        assert len(data["scans"]) >= 1
        assert data["scans"][0]["id"] == test_scan.id
        assert data["scans"][0]["name"] == test_scan.name

    async def test_get_scan_by_id(self, async_client: AsyncClient, auth_headers, test_scan):
        """Test retrieving specific scan."""
        response = await async_client.get(
            f"/api/v1/scans/{test_scan.id}",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == test_scan.id
        assert data["name"] == test_scan.name
        assert data["type"] == test_scan.type
        assert data["status"] == test_scan.status
        assert "scan_config" in data
        assert "results_summary" in data

    async def test_get_scan_not_found(self, async_client: AsyncClient, auth_headers):
        """Test retrieving non-existent scan."""
        response = await async_client.get(
            "/api/v1/scans/nonexistent-id",
            headers=auth_headers
        )
        
        assert response.status_code == 404

    async def test_create_scan(self, async_client: AsyncClient, auth_headers, sample_scan_data):
        """Test creating a new scan."""
        response = await async_client.post(
            "/api/v1/scans",
            headers=auth_headers,
            json=sample_scan_data
        )
        
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == sample_scan_data["name"]
        assert data["type"] == sample_scan_data["type"]
        assert data["target"] == sample_scan_data["target"]
        assert data["status"] == "pending"
        assert "id" in data
        assert "created_at" in data

    async def test_create_scan_invalid_data(self, async_client: AsyncClient, auth_headers):
        """Test creating scan with invalid data."""
        invalid_data = {
            "name": "",  # Empty name
            "type": "invalid_type",
            "target": ""
        }
        
        response = await async_client.post(
            "/api/v1/scans",
            headers=auth_headers,
            json=invalid_data
        )
        
        assert response.status_code == 422

    async def test_update_scan(self, async_client: AsyncClient, auth_headers, test_scan):
        """Test updating an existing scan."""
        update_data = {
            "name": "Updated Scan Name",
            "description": "Updated description"
        }
        
        response = await async_client.patch(
            f"/api/v1/scans/{test_scan.id}",
            headers=auth_headers,
            json=update_data
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == update_data["name"]
        assert data["description"] == update_data["description"]
        assert data["id"] == test_scan.id

    async def test_delete_scan(self, async_client: AsyncClient, auth_headers, db_session: AsyncSession):
        """Test deleting a scan."""
        # Create a scan to delete
        scan = Scan(
            name="Scan to Delete",
            type="web",
            target="https://test.example.com",
            status="completed",
            created_by="test-user-id",
            organization_id="test-org-id"
        )
        db_session.add(scan)
        await db_session.commit()
        await db_session.refresh(scan)
        
        response = await async_client.delete(
            f"/api/v1/scans/{scan.id}",
            headers=auth_headers
        )
        
        assert response.status_code == 204
        
        # Verify scan is deleted
        get_response = await async_client.get(
            f"/api/v1/scans/{scan.id}",
            headers=auth_headers
        )
        assert get_response.status_code == 404

    async def test_start_scan(self, async_client: AsyncClient, auth_headers, test_scan):
        """Test starting a scan."""
        response = await async_client.post(
            f"/api/v1/scans/{test_scan.id}/start",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Scan started successfully"
        assert "scan_id" in data

    async def test_stop_scan(self, async_client: AsyncClient, auth_headers, test_scan):
        """Test stopping a scan."""
        response = await async_client.post(
            f"/api/v1/scans/{test_scan.id}/stop",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Scan stopped successfully"

    async def test_get_scan_results(self, async_client: AsyncClient, auth_headers, test_scan):
        """Test retrieving scan results."""
        response = await async_client.get(
            f"/api/v1/scans/{test_scan.id}/results",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "results" in data
        assert "summary" in data
        assert isinstance(data["results"], list)

    async def test_get_scan_logs(self, async_client: AsyncClient, auth_headers, test_scan):
        """Test retrieving scan logs."""
        response = await async_client.get(
            f"/api/v1/scans/{test_scan.id}/logs",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "logs" in data
        assert isinstance(data["logs"], list)

    async def test_get_scan_stats(self, async_client: AsyncClient, auth_headers):
        """Test retrieving scan statistics."""
        response = await async_client.get(
            "/api/v1/scans/stats",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "total_scans" in data
        assert "running_scans" in data
        assert "completed_scans" in data
        assert "failed_scans" in data
        assert "scan_types" in data

    async def test_unauthorized_access(self, async_client: AsyncClient):
        """Test unauthorized access to scans."""
        response = await async_client.get("/api/v1/scans")
        assert response.status_code == 401

    async def test_pagination(self, async_client: AsyncClient, auth_headers):
        """Test scans pagination."""
        response = await async_client.get(
            "/api/v1/scans?page=1&limit=5",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "scans" in data
        assert "total" in data
        assert "page" in data
        assert "limit" in data
        assert len(data["scans"]) <= 5

    async def test_filtering(self, async_client: AsyncClient, auth_headers):
        """Test scans filtering."""
        response = await async_client.get(
            "/api/v1/scans?type=network&status=completed",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "scans" in data
        for scan in data["scans"]:
            assert scan["type"] == "network"
            assert scan["status"] == "completed"


class TestScanSecurity:
    """Test scan security and access control."""

    async def test_organization_isolation(self, async_client: AsyncClient, auth_headers, db_session: AsyncSession):
        """Test that users can only access their organization's scans."""
        from shared.database.models.organizations import Organization
        from shared.database.models.users import User
        from core.security import get_password_hash
        
        # Create another organization and scan
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
        
        other_scan = Scan(
            name="Other Organization Scan",
            type="network",
            target="10.0.0.0/24",
            status="completed",
            created_by=other_user.id,
            organization_id=other_org.id
        )
        db_session.add(other_scan)
        await db_session.commit()
        
        # Try to access other organization's scan
        response = await async_client.get(
            f"/api/v1/scans/{other_scan.id}",
            headers=auth_headers
        )
        
        assert response.status_code == 404

    async def test_permissions_required(self, async_client: AsyncClient, auth_headers):
        """Test that proper permissions are required for scan operations."""
        # Test creating scan requires permission
        scan_data = {
            "name": "Permission Test Scan",
            "type": "network",
            "target": "192.168.1.0/24"
        }
        
        response = await async_client.post(
            "/api/v1/scans",
            headers=auth_headers,
            json=scan_data
        )
        
        # Should succeed with proper permissions
        assert response.status_code == 201
