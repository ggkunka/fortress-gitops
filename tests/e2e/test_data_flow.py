"""
End-to-end tests for complete data flow: Ingestion → Enrichment → Analysis → Notification
"""

import asyncio
import json
import pytest
import httpx
import redis
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional

# Service endpoints
GATEWAY_URL = "http://gateway-service:8081"
AUTH_URL = "http://auth-service:8085"
REDIS_URL = "redis://redis:6379"

# Test data
SAMPLE_SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.4",
    "version": 1,
    "metadata": {
        "timestamp": datetime.now().isoformat(),
        "tools": [{"name": "test-generator", "version": "1.0.0"}]
    },
    "components": [
        {
            "type": "library",
            "name": "vulnerable-lib",
            "version": "1.0.0",
            "purl": "pkg:npm/vulnerable-lib@1.0.0",
            "hashes": [{"alg": "SHA-256", "content": "abc123"}]
        },
        {
            "type": "library", 
            "name": "secure-lib",
            "version": "2.1.0",
            "purl": "pkg:npm/secure-lib@2.1.0",
            "hashes": [{"alg": "SHA-256", "content": "def456"}]
        }
    ]
}

SAMPLE_CVE_DATA = {
    "cve_id": "CVE-2023-12345",
    "description": "Test vulnerability in vulnerable-lib",
    "severity": "HIGH",
    "cvss_score": 8.5,
    "affected_components": ["vulnerable-lib@1.0.0"],
    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-12345"]
}

SAMPLE_RUNTIME_DATA = {
    "container_id": "test-container-123",
    "image": "test-app:latest",
    "processes": [
        {"pid": 1234, "name": "node", "cmdline": "node server.js"},
        {"pid": 1235, "name": "nginx", "cmdline": "nginx -g daemon off;"}
    ],
    "network_connections": [
        {"local_port": 3000, "remote_host": "api.external.com", "remote_port": 443}
    ],
    "file_access": [
        {"path": "/etc/passwd", "operation": "read"},
        {"path": "/tmp/sensitive.key", "operation": "write"}
    ]
}


class TestAuthenticationFlow:
    """Test authentication and authorization for E2E flow."""
    
    @pytest.fixture
    async def auth_token(self):
        """Get authentication token for testing."""
        async with httpx.AsyncClient() as client:
            # Create test user
            user_data = {
                "username": f"test_user_{uuid.uuid4().hex[:8]}",
                "email": f"test_{uuid.uuid4().hex[:8]}@example.com",
                "password": "TestPassword123!",
                "organization_id": "test-org"
            }
            
            # Register user
            response = await client.post(
                f"{AUTH_URL}/api/v1/auth/register",
                json=user_data,
                timeout=10.0
            )
            assert response.status_code in [200, 201], f"User registration failed: {response.text}"
            
            # Login and get token
            login_data = {
                "username": user_data["username"],
                "password": user_data["password"]
            }
            
            response = await client.post(
                f"{AUTH_URL}/api/v1/auth/login",
                json=login_data,
                timeout=10.0
            )
            assert response.status_code == 200, f"Login failed: {response.text}"
            
            token_data = response.json()
            return token_data["access_token"]


class TestDataIngestionFlow:
    """Test data ingestion through the complete pipeline."""
    
    @pytest.mark.asyncio
    async def test_sbom_ingestion_flow(self, auth_token):
        """Test SBOM ingestion → enrichment → analysis → notification flow."""
        correlation_id = str(uuid.uuid4())
        
        async with httpx.AsyncClient() as client:
            headers = {"Authorization": f"Bearer {auth_token}"}
            
            # Step 1: Ingest SBOM data
            ingestion_data = {
                "data_type": "sbom",
                "source": "test-scanner",
                "correlation_id": correlation_id,
                "data": SAMPLE_SBOM
            }
            
            response = await client.post(
                f"{GATEWAY_URL}/api/v1/ingestion/sbom",
                json=ingestion_data,
                headers=headers,
                timeout=30.0
            )
            
            assert response.status_code in [200, 202], f"SBOM ingestion failed: {response.text}"
            ingestion_result = response.json()
            ingestion_id = ingestion_result["ingestion_id"]
            
            # Step 2: Wait for enrichment to process
            await self._wait_for_enrichment(correlation_id, timeout=60)
            
            # Step 3: Check analysis results
            analysis_results = await self._get_analysis_results(client, headers, correlation_id)
            assert len(analysis_results) > 0, "No analysis results found"
            
            # Step 4: Verify vulnerabilities were detected
            vulnerabilities = [r for r in analysis_results if r.get("type") == "vulnerability"]
            assert len(vulnerabilities) > 0, "No vulnerabilities detected"
            
            # Step 5: Check notifications were sent
            notifications = await self._get_notifications(client, headers, correlation_id)
            assert len(notifications) > 0, "No notifications sent"
            
            return {
                "ingestion_id": ingestion_id,
                "correlation_id": correlation_id,
                "vulnerabilities": vulnerabilities,
                "notifications": notifications
            }
    
    @pytest.mark.asyncio
    async def test_cve_data_ingestion_flow(self, auth_token):
        """Test CVE data ingestion and correlation."""
        correlation_id = str(uuid.uuid4())
        
        async with httpx.AsyncClient() as client:
            headers = {"Authorization": f"Bearer {auth_token}"}
            
            # Step 1: Ingest CVE data
            cve_data = {
                "data_type": "cve", 
                "source": "nvd-feed",
                "correlation_id": correlation_id,
                "data": SAMPLE_CVE_DATA
            }
            
            response = await client.post(
                f"{GATEWAY_URL}/api/v1/ingestion/cve",
                json=cve_data,
                headers=headers,
                timeout=30.0
            )
            
            assert response.status_code in [200, 202], f"CVE ingestion failed: {response.text}"
            
            # Step 2: Wait for processing
            await asyncio.sleep(5)
            
            # Step 3: Verify CVE was stored and processed
            response = await client.get(
                f"{GATEWAY_URL}/api/v1/analysis/cve/{SAMPLE_CVE_DATA['cve_id']}",
                headers=headers,
                timeout=10.0
            )
            
            assert response.status_code == 200, f"CVE retrieval failed: {response.text}"
            stored_cve = response.json()
            assert stored_cve["cve_id"] == SAMPLE_CVE_DATA["cve_id"]
    
    @pytest.mark.asyncio
    async def test_runtime_data_analysis_flow(self, auth_token):
        """Test runtime data ingestion and behavioral analysis."""
        correlation_id = str(uuid.uuid4())
        
        async with httpx.AsyncClient() as client:
            headers = {"Authorization": f"Bearer {auth_token}"}
            
            # Step 1: Ingest runtime data
            runtime_data = {
                "data_type": "runtime",
                "source": "runtime-monitor",
                "correlation_id": correlation_id,
                "data": SAMPLE_RUNTIME_DATA
            }
            
            response = await client.post(
                f"{GATEWAY_URL}/api/v1/ingestion/runtime",
                json=runtime_data,
                headers=headers,
                timeout=30.0
            )
            
            assert response.status_code in [200, 202], f"Runtime ingestion failed: {response.text}"
            
            # Step 2: Wait for behavioral analysis
            await self._wait_for_analysis(correlation_id, timeout=60)
            
            # Step 3: Check for behavioral anomalies
            response = await client.get(
                f"{GATEWAY_URL}/api/v1/analysis/behavioral/{correlation_id}",
                headers=headers,
                timeout=10.0
            )
            
            assert response.status_code == 200, f"Behavioral analysis retrieval failed: {response.text}"
            behavioral_results = response.json()
            
            # Should detect suspicious file access
            suspicious_activities = [
                r for r in behavioral_results.get("findings", [])
                if "sensitive" in r.get("description", "").lower()
            ]
            assert len(suspicious_activities) > 0, "No suspicious activities detected"


class TestCrossCorrelationFlow:
    """Test cross-correlation between different data types."""
    
    @pytest.mark.asyncio
    async def test_sbom_cve_correlation(self, auth_token):
        """Test correlation between SBOM components and CVE data."""
        correlation_id = str(uuid.uuid4())
        
        async with httpx.AsyncClient() as client:
            headers = {"Authorization": f"Bearer {auth_token}"}
            
            # Step 1: Ingest SBOM first
            sbom_data = {
                "data_type": "sbom",
                "source": "test-scanner",
                "correlation_id": correlation_id,
                "data": SAMPLE_SBOM
            }
            
            await client.post(
                f"{GATEWAY_URL}/api/v1/ingestion/sbom",
                json=sbom_data,
                headers=headers,
                timeout=30.0
            )
            
            # Step 2: Ingest related CVE data
            cve_data = {
                "data_type": "cve",
                "source": "nvd-feed", 
                "correlation_id": correlation_id,
                "data": SAMPLE_CVE_DATA
            }
            
            await client.post(
                f"{GATEWAY_URL}/api/v1/ingestion/cve",
                json=cve_data,
                headers=headers,
                timeout=30.0
            )
            
            # Step 3: Wait for correlation analysis
            await self._wait_for_correlation(correlation_id, timeout=60)
            
            # Step 4: Check correlation results
            response = await client.get(
                f"{GATEWAY_URL}/api/v1/analysis/correlation/{correlation_id}",
                headers=headers,
                timeout=10.0
            )
            
            assert response.status_code == 200, f"Correlation analysis failed: {response.text}"
            correlation_results = response.json()
            
            # Should find correlation between SBOM component and CVE
            correlations = correlation_results.get("correlations", [])
            sbom_cve_correlations = [
                c for c in correlations
                if c.get("type") == "sbom_cve_match"
            ]
            assert len(sbom_cve_correlations) > 0, "No SBOM-CVE correlations found"


class TestRiskAssessmentFlow:
    """Test risk assessment and prioritization."""
    
    @pytest.mark.asyncio
    async def test_risk_calculation_flow(self, auth_token):
        """Test end-to-end risk calculation and prioritization."""
        correlation_id = str(uuid.uuid4())
        
        async with httpx.AsyncClient() as client:
            headers = {"Authorization": f"Bearer {auth_token}"}
            
            # Ingest comprehensive data for risk assessment
            await self._ingest_comprehensive_data(client, headers, correlation_id)
            
            # Wait for complete processing
            await asyncio.sleep(30)
            
            # Get risk assessment results
            response = await client.get(
                f"{GATEWAY_URL}/api/v1/analysis/risk/{correlation_id}",
                headers=headers,
                timeout=10.0
            )
            
            assert response.status_code == 200, f"Risk assessment failed: {response.text}"
            risk_results = response.json()
            
            # Verify risk calculation
            assert "overall_risk_score" in risk_results
            assert "risk_factors" in risk_results
            assert "recommendations" in risk_results
            
            overall_score = risk_results["overall_risk_score"]
            assert 0 <= overall_score <= 10, f"Invalid risk score: {overall_score}"


class TestNotificationFlow:
    """Test notification delivery and escalation."""
    
    @pytest.mark.asyncio
    async def test_notification_escalation_flow(self, auth_token):
        """Test notification escalation based on severity."""
        correlation_id = str(uuid.uuid4())
        
        async with httpx.AsyncClient() as client:
            headers = {"Authorization": f"Bearer {auth_token}"}
            
            # Create high-severity vulnerability
            high_severity_cve = {
                **SAMPLE_CVE_DATA,
                "cve_id": "CVE-2023-99999",
                "severity": "CRITICAL",
                "cvss_score": 9.8
            }
            
            cve_data = {
                "data_type": "cve",
                "source": "nvd-feed",
                "correlation_id": correlation_id,
                "data": high_severity_cve
            }
            
            await client.post(
                f"{GATEWAY_URL}/api/v1/ingestion/cve",
                json=cve_data,
                headers=headers,
                timeout=30.0
            )
            
            # Wait for notification processing
            await asyncio.sleep(10)
            
            # Check escalation notifications
            response = await client.get(
                f"{GATEWAY_URL}/api/v1/notifications/escalated/{correlation_id}",
                headers=headers,
                timeout=10.0
            )
            
            assert response.status_code == 200, f"Escalated notifications retrieval failed: {response.text}"
            escalated_notifications = response.json()
            
            # Should have escalated notifications for critical severity
            assert len(escalated_notifications) > 0, "No escalated notifications found"
            
            critical_notifications = [
                n for n in escalated_notifications
                if n.get("severity") == "CRITICAL"
            ]
            assert len(critical_notifications) > 0, "No critical notifications escalated"


    # Helper methods
    
    async def _wait_for_enrichment(self, correlation_id: str, timeout: int = 60):
        """Wait for enrichment to complete."""
        redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        
        start_time = datetime.now()
        while (datetime.now() - start_time).seconds < timeout:
            # Check for enrichment completion event
            event_key = f"events:enrichment:completed:{correlation_id}"
            if redis_client.exists(event_key):
                return True
            
            await asyncio.sleep(2)
        
        raise TimeoutError(f"Enrichment did not complete within {timeout} seconds")
    
    async def _wait_for_analysis(self, correlation_id: str, timeout: int = 60):
        """Wait for analysis to complete."""
        redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        
        start_time = datetime.now()
        while (datetime.now() - start_time).seconds < timeout:
            # Check for analysis completion event
            event_key = f"events:analysis:completed:{correlation_id}"
            if redis_client.exists(event_key):
                return True
            
            await asyncio.sleep(2)
        
        raise TimeoutError(f"Analysis did not complete within {timeout} seconds")
    
    async def _wait_for_correlation(self, correlation_id: str, timeout: int = 60):
        """Wait for correlation analysis to complete."""
        redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        
        start_time = datetime.now()
        while (datetime.now() - start_time).seconds < timeout:
            # Check for correlation completion event
            event_key = f"events:correlation:completed:{correlation_id}"
            if redis_client.exists(event_key):
                return True
            
            await asyncio.sleep(2)
        
        raise TimeoutError(f"Correlation did not complete within {timeout} seconds")
    
    async def _get_analysis_results(self, client: httpx.AsyncClient, headers: Dict, correlation_id: str) -> List[Dict]:
        """Get analysis results for correlation ID."""
        response = await client.get(
            f"{GATEWAY_URL}/api/v1/analysis/results/{correlation_id}",
            headers=headers,
            timeout=10.0
        )
        
        if response.status_code == 200:
            return response.json().get("results", [])
        return []
    
    async def _get_notifications(self, client: httpx.AsyncClient, headers: Dict, correlation_id: str) -> List[Dict]:
        """Get notifications for correlation ID."""
        response = await client.get(
            f"{GATEWAY_URL}/api/v1/notifications/{correlation_id}",
            headers=headers,
            timeout=10.0
        )
        
        if response.status_code == 200:
            return response.json().get("notifications", [])
        return []
    
    async def _ingest_comprehensive_data(self, client: httpx.AsyncClient, headers: Dict, correlation_id: str):
        """Ingest comprehensive test data for risk assessment."""
        # SBOM data
        sbom_data = {
            "data_type": "sbom",
            "source": "test-scanner",
            "correlation_id": correlation_id,
            "data": SAMPLE_SBOM
        }
        
        await client.post(
            f"{GATEWAY_URL}/api/v1/ingestion/sbom",
            json=sbom_data,
            headers=headers,
            timeout=30.0
        )
        
        # CVE data
        cve_data = {
            "data_type": "cve",
            "source": "nvd-feed",
            "correlation_id": correlation_id,
            "data": SAMPLE_CVE_DATA
        }
        
        await client.post(
            f"{GATEWAY_URL}/api/v1/ingestion/cve",
            json=cve_data,
            headers=headers,
            timeout=30.0
        )
        
        # Runtime data
        runtime_data = {
            "data_type": "runtime",
            "source": "runtime-monitor",
            "correlation_id": correlation_id,
            "data": SAMPLE_RUNTIME_DATA
        }
        
        await client.post(
            f"{GATEWAY_URL}/api/v1/ingestion/runtime",
            json=runtime_data,
            headers=headers,
            timeout=30.0
        )


if __name__ == "__main__":
    # Run with: python -m pytest test_data_flow.py -v
    pytest.main([__file__, "-v"])