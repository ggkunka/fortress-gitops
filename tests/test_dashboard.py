"""
Tests for dashboard API endpoints.
"""
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession


class TestDashboardAPI:
    """Test dashboard statistics and metrics."""

    async def test_get_dashboard_stats(self, async_client: AsyncClient, auth_headers):
        """Test retrieving dashboard statistics."""
        response = await async_client.get(
            "/api/v1/dashboard/stats",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Check required dashboard metrics
        assert "total_scans" in data
        assert "active_scans" in data
        assert "total_vulnerabilities" in data
        assert "critical_vulnerabilities" in data
        assert "high_vulnerabilities" in data
        assert "medium_vulnerabilities" in data
        assert "low_vulnerabilities" in data
        assert "total_assets" in data
        assert "total_integrations" in data
        assert "active_integrations" in data
        
        # Verify data types
        assert isinstance(data["total_scans"], int)
        assert isinstance(data["active_scans"], int)
        assert isinstance(data["total_vulnerabilities"], int)
        assert isinstance(data["critical_vulnerabilities"], int)
        assert isinstance(data["high_vulnerabilities"], int)
        assert isinstance(data["medium_vulnerabilities"], int)
        assert isinstance(data["low_vulnerabilities"], int)
        assert isinstance(data["total_assets"], int)
        assert isinstance(data["total_integrations"], int)
        assert isinstance(data["active_integrations"], int)

    async def test_get_recent_scans(self, async_client: AsyncClient, auth_headers):
        """Test retrieving recent scans for dashboard."""
        response = await async_client.get(
            "/api/v1/dashboard/recent-scans?limit=10",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "scans" in data
        assert isinstance(data["scans"], list)
        assert len(data["scans"]) <= 10
        
        if data["scans"]:
            scan = data["scans"][0]
            assert "id" in scan
            assert "name" in scan
            assert "type" in scan
            assert "status" in scan
            assert "created_at" in scan
            assert "progress" in scan

    async def test_get_recent_vulnerabilities(self, async_client: AsyncClient, auth_headers):
        """Test retrieving recent vulnerabilities for dashboard."""
        response = await async_client.get(
            "/api/v1/dashboard/recent-vulnerabilities?limit=15",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "vulnerabilities" in data
        assert isinstance(data["vulnerabilities"], list)
        assert len(data["vulnerabilities"]) <= 15
        
        if data["vulnerabilities"]:
            vuln = data["vulnerabilities"][0]
            assert "id" in vuln
            assert "title" in vuln
            assert "severity" in vuln
            assert "asset" in vuln
            assert "status" in vuln
            assert "created_at" in vuln
            assert "cvss_score" in vuln

    async def test_get_vulnerability_trends(self, async_client: AsyncClient, auth_headers):
        """Test retrieving vulnerability trends for dashboard charts."""
        response = await async_client.get(
            "/api/v1/dashboard/vulnerability-trends?days=30",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "trends" in data
        assert "time_range" in data
        assert isinstance(data["trends"], list)
        
        if data["trends"]:
            trend_point = data["trends"][0]
            assert "date" in trend_point
            assert "critical" in trend_point
            assert "high" in trend_point
            assert "medium" in trend_point
            assert "low" in trend_point
            assert "total" in trend_point

    async def test_get_scan_activity(self, async_client: AsyncClient, auth_headers):
        """Test retrieving scan activity for dashboard."""
        response = await async_client.get(
            "/api/v1/dashboard/scan-activity?days=7",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "activity" in data
        assert "summary" in data
        assert isinstance(data["activity"], list)
        
        summary = data["summary"]
        assert "total_scans" in summary
        assert "completed_scans" in summary
        assert "failed_scans" in summary
        assert "running_scans" in summary

    async def test_get_asset_overview(self, async_client: AsyncClient, auth_headers):
        """Test retrieving asset overview for dashboard."""
        response = await async_client.get(
            "/api/v1/dashboard/assets",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "total_assets" in data
        assert "asset_types" in data
        assert "critical_assets" in data
        assert "recently_scanned" in data
        
        assert isinstance(data["total_assets"], int)
        assert isinstance(data["asset_types"], dict)
        assert isinstance(data["critical_assets"], int)
        assert isinstance(data["recently_scanned"], list)

    async def test_get_compliance_status(self, async_client: AsyncClient, auth_headers):
        """Test retrieving compliance status for dashboard."""
        response = await async_client.get(
            "/api/v1/dashboard/compliance",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "frameworks" in data
        assert "overall_score" in data
        assert "trending" in data
        
        assert isinstance(data["frameworks"], list)
        assert isinstance(data["overall_score"], (int, float))
        assert 0 <= data["overall_score"] <= 100
        
        if data["frameworks"]:
            framework = data["frameworks"][0]
            assert "name" in framework
            assert "score" in framework
            assert "status" in framework

    async def test_get_integration_health(self, async_client: AsyncClient, auth_headers):
        """Test retrieving integration health for dashboard."""
        response = await async_client.get(
            "/api/v1/dashboard/integration-health",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "integrations" in data
        assert "summary" in data
        
        summary = data["summary"]
        assert "total" in summary
        assert "healthy" in summary
        assert "warning" in summary
        assert "error" in summary
        
        assert isinstance(data["integrations"], list)
        
        if data["integrations"]:
            integration = data["integrations"][0]
            assert "id" in integration
            assert "name" in integration
            assert "type" in integration
            assert "status" in integration
            assert "health" in integration

    async def test_get_risk_metrics(self, async_client: AsyncClient, auth_headers):
        """Test retrieving risk metrics for dashboard."""
        response = await async_client.get(
            "/api/v1/dashboard/risk-metrics",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "overall_risk_score" in data
        assert "risk_distribution" in data
        assert "top_risks" in data
        assert "trending" in data
        
        assert isinstance(data["overall_risk_score"], (int, float))
        assert 0 <= data["overall_risk_score"] <= 100
        assert isinstance(data["risk_distribution"], dict)
        assert isinstance(data["top_risks"], list)

    async def test_get_alerts_summary(self, async_client: AsyncClient, auth_headers):
        """Test retrieving alerts summary for dashboard."""
        response = await async_client.get(
            "/api/v1/dashboard/alerts",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "total_alerts" in data
        assert "critical_alerts" in data
        assert "unread_alerts" in data
        assert "recent_alerts" in data
        
        assert isinstance(data["total_alerts"], int)
        assert isinstance(data["critical_alerts"], int)
        assert isinstance(data["unread_alerts"], int)
        assert isinstance(data["recent_alerts"], list)
        
        if data["recent_alerts"]:
            alert = data["recent_alerts"][0]
            assert "id" in alert
            assert "title" in alert
            assert "severity" in alert
            assert "created_at" in alert
            assert "read" in alert

    async def test_unauthorized_access(self, async_client: AsyncClient):
        """Test unauthorized access to dashboard endpoints."""
        endpoints = [
            "/api/v1/dashboard/stats",
            "/api/v1/dashboard/recent-scans",
            "/api/v1/dashboard/recent-vulnerabilities",
            "/api/v1/dashboard/vulnerability-trends",
            "/api/v1/dashboard/scan-activity",
            "/api/v1/dashboard/assets",
            "/api/v1/dashboard/compliance",
            "/api/v1/dashboard/integration-health",
            "/api/v1/dashboard/risk-metrics",
            "/api/v1/dashboard/alerts"
        ]
        
        for endpoint in endpoints:
            response = await async_client.get(endpoint)
            assert response.status_code == 401

    async def test_dashboard_data_filtering(self, async_client: AsyncClient, auth_headers):
        """Test that dashboard data is filtered by organization."""
        response = await async_client.get(
            "/api/v1/dashboard/stats",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # All counts should be non-negative
        for key, value in data.items():
            if isinstance(value, int):
                assert value >= 0

    async def test_dashboard_performance(self, async_client: AsyncClient, auth_headers):
        """Test dashboard endpoint performance and response times."""
        import time
        
        start_time = time.time()
        response = await async_client.get(
            "/api/v1/dashboard/stats",
            headers=auth_headers
        )
        end_time = time.time()
        
        assert response.status_code == 200
        # Dashboard should respond within 2 seconds
        assert (end_time - start_time) < 2.0

    async def test_dashboard_caching(self, async_client: AsyncClient, auth_headers):
        """Test dashboard response caching headers."""
        response = await async_client.get(
            "/api/v1/dashboard/stats",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        # Check for appropriate cache headers
        headers = response.headers
        assert "cache-control" in headers or "etag" in headers


class TestDashboardCustomization:
    """Test dashboard customization features."""

    async def test_get_user_dashboard_config(self, async_client: AsyncClient, auth_headers):
        """Test retrieving user dashboard configuration."""
        response = await async_client.get(
            "/api/v1/dashboard/config",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "widgets" in data
        assert "layout" in data
        assert "preferences" in data
        
        assert isinstance(data["widgets"], list)
        assert isinstance(data["layout"], dict)
        assert isinstance(data["preferences"], dict)

    async def test_update_dashboard_config(self, async_client: AsyncClient, auth_headers):
        """Test updating user dashboard configuration."""
        config_data = {
            "widgets": [
                {"type": "vulnerability_chart", "position": {"x": 0, "y": 0}, "size": {"w": 6, "h": 4}},
                {"type": "recent_scans", "position": {"x": 6, "y": 0}, "size": {"w": 6, "h": 4}},
            ],
            "preferences": {
                "theme": "dark",
                "auto_refresh": True,
                "refresh_interval": 30
            }
        }
        
        response = await async_client.patch(
            "/api/v1/dashboard/config",
            headers=auth_headers,
            json=config_data
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Dashboard configuration updated"
        assert "config" in data

    async def test_reset_dashboard_config(self, async_client: AsyncClient, auth_headers):
        """Test resetting dashboard configuration to defaults."""
        response = await async_client.post(
            "/api/v1/dashboard/config/reset",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Dashboard configuration reset to defaults"
        assert "config" in data


class TestDashboardExport:
    """Test dashboard data export functionality."""

    async def test_export_dashboard_data(self, async_client: AsyncClient, auth_headers):
        """Test exporting dashboard data."""
        response = await async_client.get(
            "/api/v1/dashboard/export?format=json",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        assert "application/json" in response.headers["content-type"]
        
        data = response.json()
        assert "dashboard_data" in data
        assert "exported_at" in data
        assert "organization" in data

    async def test_export_dashboard_pdf_report(self, async_client: AsyncClient, auth_headers):
        """Test exporting dashboard as PDF report."""
        response = await async_client.get(
            "/api/v1/dashboard/export?format=pdf",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        assert "application/pdf" in response.headers["content-type"]
        assert "content-disposition" in response.headers
        assert "attachment" in response.headers["content-disposition"]

    async def test_scheduled_dashboard_reports(self, async_client: AsyncClient, auth_headers):
        """Test creating scheduled dashboard reports."""
        schedule_data = {
            "name": "Weekly Dashboard Report",
            "frequency": "weekly",
            "day_of_week": 1,  # Monday
            "time": "09:00",
            "format": "pdf",
            "recipients": ["management@company.com"],
            "enabled": True
        }
        
        response = await async_client.post(
            "/api/v1/dashboard/scheduled-reports",
            headers=auth_headers,
            json=schedule_data
        )
        
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == schedule_data["name"]
        assert data["frequency"] == schedule_data["frequency"]
        assert data["enabled"] == schedule_data["enabled"]
        assert "id" in data
        assert "next_run" in data
