"""
Tests for vulnerabilities API endpoints.
"""
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from shared.database.models.vulnerabilities import Vulnerability


class TestVulnerabilitiesAPI:
    """Test vulnerabilities CRUD operations."""

    async def test_get_vulnerabilities(self, async_client: AsyncClient, auth_headers, test_vulnerability):
        """Test retrieving vulnerabilities list."""
        response = await async_client.get(
            "/api/v1/vulnerabilities",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "vulnerabilities" in data
        assert "total" in data
        assert len(data["vulnerabilities"]) >= 1
        assert data["vulnerabilities"][0]["id"] == test_vulnerability.id
        assert data["vulnerabilities"][0]["title"] == test_vulnerability.title

    async def test_get_vulnerability_by_id(self, async_client: AsyncClient, auth_headers, test_vulnerability):
        """Test retrieving specific vulnerability."""
        response = await async_client.get(
            f"/api/v1/vulnerabilities/{test_vulnerability.id}",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == test_vulnerability.id
        assert data["title"] == test_vulnerability.title
        assert data["severity"] == test_vulnerability.severity
        assert data["cvss_score"] == test_vulnerability.cvss_score
        assert data["status"] == test_vulnerability.status

    async def test_get_vulnerability_not_found(self, async_client: AsyncClient, auth_headers):
        """Test retrieving non-existent vulnerability."""
        response = await async_client.get(
            "/api/v1/vulnerabilities/nonexistent-id",
            headers=auth_headers
        )
        
        assert response.status_code == 404

    async def test_create_vulnerability(self, async_client: AsyncClient, auth_headers, sample_vulnerability_data, test_scan):
        """Test creating a new vulnerability."""
        vuln_data = {
            **sample_vulnerability_data,
            "scan_id": test_scan.id
        }
        
        response = await async_client.post(
            "/api/v1/vulnerabilities",
            headers=auth_headers,
            json=vuln_data
        )
        
        assert response.status_code == 201
        data = response.json()
        assert data["title"] == vuln_data["title"]
        assert data["severity"] == vuln_data["severity"]
        assert data["cvss_score"] == vuln_data["cvss_score"]
        assert data["asset"] == vuln_data["asset"]
        assert data["status"] == "open"
        assert "id" in data
        assert "created_at" in data

    async def test_create_vulnerability_invalid_data(self, async_client: AsyncClient, auth_headers):
        """Test creating vulnerability with invalid data."""
        invalid_data = {
            "title": "",  # Empty title
            "severity": "invalid_severity",
            "cvss_score": 15.0  # Invalid CVSS score
        }
        
        response = await async_client.post(
            "/api/v1/vulnerabilities",
            headers=auth_headers,
            json=invalid_data
        )
        
        assert response.status_code == 422

    async def test_update_vulnerability(self, async_client: AsyncClient, auth_headers, test_vulnerability):
        """Test updating an existing vulnerability."""
        update_data = {
            "status": "resolved",
            "remediation": "Updated remediation steps",
            "risk_score": 75
        }
        
        response = await async_client.patch(
            f"/api/v1/vulnerabilities/{test_vulnerability.id}",
            headers=auth_headers,
            json=update_data
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == update_data["status"]
        assert data["remediation"] == update_data["remediation"]
        assert data["risk_score"] == update_data["risk_score"]
        assert data["id"] == test_vulnerability.id

    async def test_delete_vulnerability(self, async_client: AsyncClient, auth_headers, db_session: AsyncSession, test_scan, test_user):
        """Test deleting a vulnerability."""
        # Create a vulnerability to delete
        vuln = Vulnerability(
            title="Vulnerability to Delete",
            description="Test vulnerability for deletion",
            severity="medium",
            cvss_score=5.0,
            asset="test.example.com",
            port=443,
            service="HTTPS",
            status="open",
            scan_id=test_scan.id,
            organization_id=test_user.organization_id,
            created_by=test_user.id
        )
        db_session.add(vuln)
        await db_session.commit()
        await db_session.refresh(vuln)
        
        response = await async_client.delete(
            f"/api/v1/vulnerabilities/{vuln.id}",
            headers=auth_headers
        )
        
        assert response.status_code == 204
        
        # Verify vulnerability is deleted
        get_response = await async_client.get(
            f"/api/v1/vulnerabilities/{vuln.id}",
            headers=auth_headers
        )
        assert get_response.status_code == 404

    async def test_bulk_update_vulnerabilities(self, async_client: AsyncClient, auth_headers, test_vulnerability):
        """Test bulk updating vulnerabilities."""
        bulk_update_data = {
            "vulnerability_ids": [test_vulnerability.id],
            "updates": {
                "status": "in_progress",
                "assigned_to": "security-team@company.com"
            }
        }
        
        response = await async_client.patch(
            "/api/v1/vulnerabilities/bulk-update",
            headers=auth_headers,
            json=bulk_update_data
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["updated_count"] == 1
        assert "updated_vulnerabilities" in data

    async def test_get_vulnerability_stats(self, async_client: AsyncClient, auth_headers):
        """Test retrieving vulnerability statistics."""
        response = await async_client.get(
            "/api/v1/vulnerabilities/stats",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "total_vulnerabilities" in data
        assert "by_severity" in data
        assert "by_status" in data
        assert "avg_cvss_score" in data
        assert "trending" in data

    async def test_export_vulnerabilities(self, async_client: AsyncClient, auth_headers):
        """Test exporting vulnerabilities."""
        response = await async_client.get(
            "/api/v1/vulnerabilities/export?format=csv",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        assert "text/csv" in response.headers["content-type"]

    async def test_vulnerability_search(self, async_client: AsyncClient, auth_headers):
        """Test searching vulnerabilities."""
        response = await async_client.get(
            "/api/v1/vulnerabilities/search?q=SQL injection",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "results" in data
        assert "total" in data

    async def test_unauthorized_access(self, async_client: AsyncClient):
        """Test unauthorized access to vulnerabilities."""
        response = await async_client.get("/api/v1/vulnerabilities")
        assert response.status_code == 401

    async def test_pagination(self, async_client: AsyncClient, auth_headers):
        """Test vulnerabilities pagination."""
        response = await async_client.get(
            "/api/v1/vulnerabilities?page=1&limit=10",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "vulnerabilities" in data
        assert "total" in data
        assert "page" in data
        assert "limit" in data
        assert len(data["vulnerabilities"]) <= 10

    async def test_filtering_by_severity(self, async_client: AsyncClient, auth_headers):
        """Test filtering vulnerabilities by severity."""
        response = await async_client.get(
            "/api/v1/vulnerabilities?severity=high",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "vulnerabilities" in data
        for vuln in data["vulnerabilities"]:
            assert vuln["severity"] == "high"

    async def test_filtering_by_status(self, async_client: AsyncClient, auth_headers):
        """Test filtering vulnerabilities by status."""
        response = await async_client.get(
            "/api/v1/vulnerabilities?status=open",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "vulnerabilities" in data
        for vuln in data["vulnerabilities"]:
            assert vuln["status"] == "open"

    async def test_filtering_by_asset(self, async_client: AsyncClient, auth_headers):
        """Test filtering vulnerabilities by asset."""
        response = await async_client.get(
            "/api/v1/vulnerabilities?asset=test.example.com",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "vulnerabilities" in data


class TestVulnerabilityRiskScoring:
    """Test vulnerability risk scoring functionality."""

    async def test_calculate_risk_score(self, async_client: AsyncClient, auth_headers, test_vulnerability):
        """Test risk score calculation."""
        response = await async_client.post(
            f"/api/v1/vulnerabilities/{test_vulnerability.id}/calculate-risk",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "risk_score" in data
        assert "risk_factors" in data
        assert isinstance(data["risk_score"], (int, float))
        assert 0 <= data["risk_score"] <= 100

    async def test_update_risk_score(self, async_client: AsyncClient, auth_headers, test_vulnerability):
        """Test manual risk score update."""
        update_data = {
            "risk_score": 95,
            "risk_justification": "Critical asset with public exposure"
        }
        
        response = await async_client.patch(
            f"/api/v1/vulnerabilities/{test_vulnerability.id}/risk",
            headers=auth_headers,
            json=update_data
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["risk_score"] == update_data["risk_score"]
        assert data["risk_justification"] == update_data["risk_justification"]


class TestVulnerabilitySecurity:
    """Test vulnerability security and access control."""

    async def test_organization_isolation(self, async_client: AsyncClient, auth_headers, db_session: AsyncSession):
        """Test that users can only access their organization's vulnerabilities."""
        from shared.database.models.organizations import Organization
        from shared.database.models.users import User
        from shared.database.models.scans import Scan
        from core.security import get_password_hash
        
        # Create another organization and vulnerability
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
            name="Other Scan",
            type="network",
            target="10.0.0.0/24",
            status="completed",
            created_by=other_user.id,
            organization_id=other_org.id
        )
        db_session.add(other_scan)
        await db_session.flush()
        
        other_vulnerability = Vulnerability(
            title="Other Organization Vulnerability",
            description="Test vulnerability",
            severity="high",
            cvss_score=8.0,
            asset="other.example.com",
            port=443,
            service="HTTPS",
            status="open",
            scan_id=other_scan.id,
            organization_id=other_org.id,
            created_by=other_user.id
        )
        db_session.add(other_vulnerability)
        await db_session.commit()
        
        # Try to access other organization's vulnerability
        response = await async_client.get(
            f"/api/v1/vulnerabilities/{other_vulnerability.id}",
            headers=auth_headers
        )
        
        assert response.status_code == 404

    async def test_permissions_required(self, async_client: AsyncClient, auth_headers, sample_vulnerability_data, test_scan):
        """Test that proper permissions are required for vulnerability operations."""
        vuln_data = {
            **sample_vulnerability_data,
            "scan_id": test_scan.id
        }
        
        response = await async_client.post(
            "/api/v1/vulnerabilities",
            headers=auth_headers,
            json=vuln_data
        )
        
        # Should succeed with proper permissions
        assert response.status_code == 201
