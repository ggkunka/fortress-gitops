"""
Tests for reports API endpoints.
"""
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from shared.database.models.reports import Report


class TestReportsAPI:
    """Test reports CRUD operations."""

    async def test_get_reports(self, async_client: AsyncClient, auth_headers):
        """Test retrieving reports list."""
        response = await async_client.get(
            "/api/v1/reports",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "reports" in data
        assert "total" in data
        assert isinstance(data["reports"], list)

    async def test_get_report_by_id(self, async_client: AsyncClient, auth_headers, db_session: AsyncSession, test_user):
        """Test retrieving specific report."""
        # Create a test report
        report = Report(
            name="Test Security Report",
            type="security",
            format="pdf",
            status="completed",
            organization_id=test_user.organization_id,
            created_by=test_user.id,
            config={
                "date_range": "30_days",
                "severities": ["high", "critical"],
                "include_charts": True
            },
            size=1024000,
            download_url="https://storage.example.com/reports/test-report.pdf"
        )
        db_session.add(report)
        await db_session.commit()
        await db_session.refresh(report)
        
        response = await async_client.get(
            f"/api/v1/reports/{report.id}",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == report.id
        assert data["name"] == report.name
        assert data["type"] == report.type
        assert data["status"] == report.status
        assert "config" in data

    async def test_get_report_not_found(self, async_client: AsyncClient, auth_headers):
        """Test retrieving non-existent report."""
        response = await async_client.get(
            "/api/v1/reports/nonexistent-id",
            headers=auth_headers
        )
        
        assert response.status_code == 404

    async def test_create_report(self, async_client: AsyncClient, auth_headers):
        """Test creating a new report."""
        report_data = {
            "name": "Monthly Security Assessment",
            "type": "security",
            "format": "pdf",
            "config": {
                "date_range": "30_days",
                "severities": ["high", "critical"],
                "include_executive_summary": True,
                "include_charts": True
            },
            "schedule": {
                "frequency": "monthly",
                "day_of_month": 1,
                "enabled": True
            }
        }
        
        response = await async_client.post(
            "/api/v1/reports",
            headers=auth_headers,
            json=report_data
        )
        
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == report_data["name"]
        assert data["type"] == report_data["type"]
        assert data["format"] == report_data["format"]
        assert data["status"] == "pending"
        assert "id" in data
        assert "created_at" in data

    async def test_create_report_invalid_data(self, async_client: AsyncClient, auth_headers):
        """Test creating report with invalid data."""
        invalid_data = {
            "name": "",  # Empty name
            "type": "invalid_type",
            "format": "invalid_format"
        }
        
        response = await async_client.post(
            "/api/v1/reports",
            headers=auth_headers,
            json=invalid_data
        )
        
        assert response.status_code == 422

    async def test_generate_report(self, async_client: AsyncClient, auth_headers, db_session: AsyncSession, test_user):
        """Test generating a report."""
        # Create a pending report
        report = Report(
            name="Report to Generate",
            type="security",
            format="pdf",
            status="pending",
            organization_id=test_user.organization_id,
            created_by=test_user.id,
            config={"date_range": "7_days"}
        )
        db_session.add(report)
        await db_session.commit()
        await db_session.refresh(report)
        
        response = await async_client.post(
            f"/api/v1/reports/{report.id}/generate",
            headers=auth_headers
        )
        
        assert response.status_code == 202
        data = response.json()
        assert data["message"] == "Report generation started"
        assert "report_id" in data

    async def test_download_report(self, async_client: AsyncClient, auth_headers, db_session: AsyncSession, test_user):
        """Test downloading a completed report."""
        # Create a completed report
        report = Report(
            name="Completed Report",
            type="security",
            format="pdf",
            status="completed",
            organization_id=test_user.organization_id,
            created_by=test_user.id,
            config={"date_range": "7_days"},
            size=1024000,
            download_url="https://storage.example.com/reports/completed-report.pdf"
        )
        db_session.add(report)
        await db_session.commit()
        await db_session.refresh(report)
        
        response = await async_client.get(
            f"/api/v1/reports/{report.id}/download",
            headers=auth_headers
        )
        
        assert response.status_code == 302  # Redirect to download URL
        assert "location" in response.headers

    async def test_delete_report(self, async_client: AsyncClient, auth_headers, db_session: AsyncSession, test_user):
        """Test deleting a report."""
        # Create a report to delete
        report = Report(
            name="Report to Delete",
            type="security",
            format="pdf",
            status="completed",
            organization_id=test_user.organization_id,
            created_by=test_user.id,
            config={"date_range": "7_days"}
        )
        db_session.add(report)
        await db_session.commit()
        await db_session.refresh(report)
        
        response = await async_client.delete(
            f"/api/v1/reports/{report.id}",
            headers=auth_headers
        )
        
        assert response.status_code == 204
        
        # Verify report is deleted
        get_response = await async_client.get(
            f"/api/v1/reports/{report.id}",
            headers=auth_headers
        )
        assert get_response.status_code == 404

    async def test_get_report_stats(self, async_client: AsyncClient, auth_headers):
        """Test retrieving report statistics."""
        response = await async_client.get(
            "/api/v1/reports/stats",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "total_reports" in data
        assert "completed_reports" in data
        assert "failed_reports" in data
        assert "scheduled_reports" in data
        assert "report_types" in data

    async def test_get_report_templates(self, async_client: AsyncClient, auth_headers):
        """Test retrieving available report templates."""
        response = await async_client.get(
            "/api/v1/reports/templates",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "templates" in data
        assert isinstance(data["templates"], list)
        
        if data["templates"]:
            template = data["templates"][0]
            assert "id" in template
            assert "name" in template
            assert "type" in template
            assert "description" in template
            assert "config_schema" in template

    async def test_unauthorized_access(self, async_client: AsyncClient):
        """Test unauthorized access to reports."""
        response = await async_client.get("/api/v1/reports")
        assert response.status_code == 401

    async def test_pagination(self, async_client: AsyncClient, auth_headers):
        """Test reports pagination."""
        response = await async_client.get(
            "/api/v1/reports?page=1&limit=10",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "reports" in data
        assert "total" in data
        assert "page" in data
        assert "limit" in data
        assert len(data["reports"]) <= 10

    async def test_filtering_by_type(self, async_client: AsyncClient, auth_headers):
        """Test filtering reports by type."""
        response = await async_client.get(
            "/api/v1/reports?type=security",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "reports" in data
        for report in data["reports"]:
            assert report["type"] == "security"

    async def test_filtering_by_status(self, async_client: AsyncClient, auth_headers):
        """Test filtering reports by status."""
        response = await async_client.get(
            "/api/v1/reports?status=completed",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "reports" in data
        for report in data["reports"]:
            assert report["status"] == "completed"


class TestReportScheduling:
    """Test report scheduling functionality."""

    async def test_schedule_report(self, async_client: AsyncClient, auth_headers, db_session: AsyncSession, test_user):
        """Test scheduling a report."""
        # Create a report to schedule
        report = Report(
            name="Scheduled Report",
            type="security",
            format="pdf",
            status="pending",
            organization_id=test_user.organization_id,
            created_by=test_user.id,
            config={"date_range": "30_days"}
        )
        db_session.add(report)
        await db_session.commit()
        await db_session.refresh(report)
        
        schedule_data = {
            "frequency": "weekly",
            "day_of_week": 1,  # Monday
            "time": "09:00",
            "enabled": True,
            "recipients": ["security@company.com", "management@company.com"]
        }
        
        response = await async_client.post(
            f"/api/v1/reports/{report.id}/schedule",
            headers=auth_headers,
            json=schedule_data
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Report scheduled successfully"
        assert "schedule" in data

    async def test_update_report_schedule(self, async_client: AsyncClient, auth_headers, db_session: AsyncSession, test_user):
        """Test updating a report schedule."""
        # Create a scheduled report
        report = Report(
            name="Scheduled Report",
            type="security",
            format="pdf",
            status="pending",
            organization_id=test_user.organization_id,
            created_by=test_user.id,
            config={"date_range": "30_days"},
            schedule={
                "frequency": "weekly",
                "day_of_week": 1,
                "time": "09:00",
                "enabled": True
            }
        )
        db_session.add(report)
        await db_session.commit()
        await db_session.refresh(report)
        
        update_data = {
            "frequency": "monthly",
            "day_of_month": 1,
            "time": "10:00",
            "enabled": False
        }
        
        response = await async_client.patch(
            f"/api/v1/reports/{report.id}/schedule",
            headers=auth_headers,
            json=update_data
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["schedule"]["frequency"] == "monthly"
        assert data["schedule"]["enabled"] == False

    async def test_disable_report_schedule(self, async_client: AsyncClient, auth_headers, db_session: AsyncSession, test_user):
        """Test disabling a report schedule."""
        # Create a scheduled report
        report = Report(
            name="Scheduled Report",
            type="security",
            format="pdf",
            status="pending",
            organization_id=test_user.organization_id,
            created_by=test_user.id,
            config={"date_range": "30_days"},
            schedule={
                "frequency": "weekly",
                "enabled": True
            }
        )
        db_session.add(report)
        await db_session.commit()
        await db_session.refresh(report)
        
        response = await async_client.delete(
            f"/api/v1/reports/{report.id}/schedule",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Report schedule disabled"


class TestReportSecurity:
    """Test report security and access control."""

    async def test_organization_isolation(self, async_client: AsyncClient, auth_headers, db_session: AsyncSession):
        """Test that users can only access their organization's reports."""
        from shared.database.models.organizations import Organization
        from shared.database.models.users import User
        from core.security import get_password_hash
        
        # Create another organization and report
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
        
        other_report = Report(
            name="Other Organization Report",
            type="security",
            format="pdf",
            status="completed",
            organization_id=other_org.id,
            created_by=other_user.id,
            config={"date_range": "30_days"}
        )
        db_session.add(other_report)
        await db_session.commit()
        
        # Try to access other organization's report
        response = await async_client.get(
            f"/api/v1/reports/{other_report.id}",
            headers=auth_headers
        )
        
        assert response.status_code == 404

    async def test_permissions_required(self, async_client: AsyncClient, auth_headers):
        """Test that proper permissions are required for report operations."""
        report_data = {
            "name": "Permission Test Report",
            "type": "security",
            "format": "pdf",
            "config": {"date_range": "7_days"}
        }
        
        response = await async_client.post(
            "/api/v1/reports",
            headers=auth_headers,
            json=report_data
        )
        
        # Should succeed with proper permissions
        assert response.status_code == 201
