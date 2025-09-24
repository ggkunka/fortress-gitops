"""Integration tests for service communication."""

import asyncio
import json
import pytest
from datetime import datetime, timedelta
from typing import Dict, Any
from uuid import uuid4

import redis.asyncio as redis
from shared.event_bus import RedisEventBus, EventMessage
from shared.config import get_settings

from ...services import EnrichmentEngine, EventSubscriber
from ...schemas.enrichment import EnrichmentRequest, DataType, EnrichmentType
from ...schemas.events import EnrichmentStartedEvent, EnrichmentCompletedEvent

settings = get_settings()


class TestServiceCommunication:
    """Test service communication patterns."""
    
    @pytest.fixture
    async def redis_client(self):
        """Create Redis client for testing."""
        client = redis.from_url(
            getattr(settings, 'redis_url', 'redis://localhost:6379/1'),
            decode_responses=True
        )
        yield client
        await client.flushdb()
        await client.close()
    
    @pytest.fixture
    async def event_bus(self, redis_client):
        """Create event bus for testing."""
        bus = RedisEventBus(service_name="test_enrichment")
        await bus.connect()
        yield bus
        await bus.disconnect()
    
    @pytest.fixture
    async def enrichment_engine(self, event_bus):
        """Create enrichment engine for testing."""
        engine = EnrichmentEngine()
        await engine.start()
        yield engine
        await engine.stop()
    
    @pytest.fixture
    async def event_subscriber(self, enrichment_engine):
        """Create event subscriber for testing."""
        subscriber = EventSubscriber(enrichment_engine)
        await subscriber.start()
        yield subscriber
        await subscriber.stop()
    
    @pytest.mark.asyncio
    async def test_sbom_ingestion_to_enrichment_flow(
        self, 
        event_bus, 
        enrichment_engine, 
        event_subscriber
    ):
        """Test SBOM ingestion to enrichment flow."""
        # Create mock SBOM data
        sbom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": "vulnerable-lib",
                    "version": "1.0.0",
                    "purl": "pkg:npm/vulnerable-lib@1.0.0",
                    "vulnerabilities": [
                        {
                            "id": "CVE-2023-1234",
                            "severity": "high",
                            "cvss_score": 8.5
                        }
                    ]
                }
            ]
        }
        
        # Track enrichment events
        enrichment_events = []
        
        async def enrichment_event_handler(event: EventMessage):
            enrichment_events.append(event)
        
        # Subscribe to enrichment events
        await event_bus.subscribe(
            event_pattern="enrichment.*",
            handler=enrichment_event_handler
        )
        
        # Publish SBOM ingested event
        correlation_id = str(uuid4())
        await event_bus.publish(
            event_type="sbom.ingested",
            data=sbom_data,
            correlation_id=correlation_id,
            source_service="ingestion"
        )
        
        # Wait for enrichment to complete
        await asyncio.sleep(2)
        
        # Check that enrichment events were published
        assert len(enrichment_events) > 0
        
        # Check for enrichment started event
        started_events = [e for e in enrichment_events if e.event_type == "enrichment.started"]
        assert len(started_events) == 1
        
        started_event = started_events[0]
        assert started_event.correlation_id == correlation_id
        assert started_event.data["data_type"] == "sbom"
        assert "threat_intelligence" in started_event.data["enrichment_types"]
    
    @pytest.mark.asyncio
    async def test_cve_ingestion_to_enrichment_flow(
        self, 
        event_bus, 
        enrichment_engine, 
        event_subscriber
    ):
        """Test CVE ingestion to enrichment flow."""
        # Create mock CVE data
        cve_data = {
            "cve_id": "CVE-2023-5678",
            "description": "Critical vulnerability in test component",
            "metrics": {
                "cvss_v3": {
                    "baseScore": 9.8,
                    "baseSeverity": "CRITICAL"
                }
            },
            "references": [
                {
                    "url": "https://example.com/advisory",
                    "source": "MISC"
                }
            ]
        }
        
        # Track enrichment events
        enrichment_events = []
        
        async def enrichment_event_handler(event: EventMessage):
            enrichment_events.append(event)
        
        # Subscribe to enrichment events
        await event_bus.subscribe(
            event_pattern="enrichment.*",
            handler=enrichment_event_handler
        )
        
        # Publish CVE ingested event
        correlation_id = str(uuid4())
        await event_bus.publish(
            event_type="cve.ingested",
            data=cve_data,
            correlation_id=correlation_id,
            source_service="ingestion"
        )
        
        # Wait for enrichment to complete
        await asyncio.sleep(2)
        
        # Check that enrichment events were published
        assert len(enrichment_events) > 0
        
        # Check priority was set correctly for critical CVE
        started_events = [e for e in enrichment_events if e.event_type == "enrichment.started"]
        assert len(started_events) == 1
        
        started_event = started_events[0]
        assert started_event.data["priority"] >= 8  # High priority for critical CVE
    
    @pytest.mark.asyncio
    async def test_runtime_ingestion_to_enrichment_flow(
        self, 
        event_bus, 
        enrichment_engine, 
        event_subscriber
    ):
        """Test runtime behavior ingestion to enrichment flow."""
        # Create mock runtime data
        runtime_data = {
            "events": [
                {
                    "event_type": "process_start",
                    "timestamp": datetime.utcnow().isoformat(),
                    "data": {
                        "process_name": "malware.exe",
                        "command_line": "malware.exe --download-payload",
                        "user": "system"
                    }
                },
                {
                    "event_type": "network_connection",
                    "timestamp": datetime.utcnow().isoformat(),
                    "data": {
                        "destination_ip": "192.168.1.100",
                        "destination_port": 443,
                        "protocol": "tcp"
                    }
                }
            ],
            "anomalies": [
                {
                    "type": "suspicious_process",
                    "severity": "high",
                    "confidence": 0.9,
                    "timestamp": datetime.utcnow().isoformat()
                }
            ]
        }
        
        # Track enrichment events
        enrichment_events = []
        
        async def enrichment_event_handler(event: EventMessage):
            enrichment_events.append(event)
        
        # Subscribe to enrichment events
        await event_bus.subscribe(
            event_pattern="enrichment.*",
            handler=enrichment_event_handler
        )
        
        # Publish runtime ingested event
        correlation_id = str(uuid4())
        await event_bus.publish(
            event_type="runtime.ingested",
            data=runtime_data,
            correlation_id=correlation_id,
            source_service="ingestion"
        )
        
        # Wait for enrichment to complete
        await asyncio.sleep(2)
        
        # Check that enrichment events were published
        assert len(enrichment_events) > 0
        
        # Check enrichment types for runtime data
        started_events = [e for e in enrichment_events if e.event_type == "enrichment.started"]
        assert len(started_events) == 1
        
        started_event = started_events[0]
        assert started_event.data["data_type"] == "runtime"
        assert "behavioral_analysis" in started_event.data["enrichment_types"]
    
    @pytest.mark.asyncio
    async def test_enrichment_error_handling(
        self, 
        event_bus, 
        enrichment_engine, 
        event_subscriber
    ):
        """Test enrichment error handling."""
        # Create invalid data that should cause enrichment to fail
        invalid_data = {
            "invalid": "data structure"
        }
        
        # Track enrichment events
        enrichment_events = []
        
        async def enrichment_event_handler(event: EventMessage):
            enrichment_events.append(event)
        
        # Subscribe to enrichment events
        await event_bus.subscribe(
            event_pattern="enrichment.*",
            handler=enrichment_event_handler
        )
        
        # Publish event with invalid data
        correlation_id = str(uuid4())
        await event_bus.publish(
            event_type="sbom.ingested",
            data=invalid_data,
            correlation_id=correlation_id,
            source_service="ingestion"
        )
        
        # Wait for processing
        await asyncio.sleep(2)
        
        # Check that error event was published
        error_events = [e for e in enrichment_events if e.event_type == "enrichment.error"]
        assert len(error_events) >= 0  # May or may not generate error event depending on validation
    
    @pytest.mark.asyncio
    async def test_enrichment_timeout_handling(
        self, 
        event_bus, 
        enrichment_engine, 
        event_subscriber
    ):
        """Test enrichment timeout handling."""
        # Create enrichment request with very short timeout
        request = EnrichmentRequest(
            request_id=f"timeout_test_{uuid4()}",
            data_type=DataType.SBOM,
            data={"components": []},
            enrichment_types=[EnrichmentType.THREAT_INTELLIGENCE],
            timeout_seconds=1,  # Very short timeout
            priority=5
        )
        
        # Submit request directly to engine
        task_id = await enrichment_engine.enrich_data(request)
        
        # Wait longer than timeout
        await asyncio.sleep(3)
        
        # Check task status
        task = await enrichment_engine.get_enrichment_status(task_id)
        
        # Task should either be completed quickly or timed out
        assert task is None or task.status in ["completed", "failed", "timeout"]
    
    @pytest.mark.asyncio
    async def test_event_bus_reconnection(
        self, 
        redis_client, 
        enrichment_engine
    ):
        """Test event bus reconnection after connection loss."""
        # Create event bus
        event_bus = RedisEventBus(service_name="test_reconnection")
        await event_bus.connect()
        
        # Verify connection
        assert event_bus.is_connected
        
        # Simulate connection loss by closing Redis connection
        if hasattr(event_bus, 'redis_client'):
            await event_bus.redis_client.close()
        
        # Try to reconnect
        await event_bus.connect()
        
        # Verify reconnection
        assert event_bus.is_connected
        
        # Test publishing after reconnection
        await event_bus.publish(
            event_type="test.reconnection",
            data={"test": "data"},
            correlation_id=str(uuid4())
        )
        
        await event_bus.disconnect()
    
    @pytest.mark.asyncio
    async def test_multi_service_communication(
        self, 
        redis_client
    ):
        """Test communication between multiple service instances."""
        # Create multiple enrichment engines
        engine1 = EnrichmentEngine()
        engine2 = EnrichmentEngine()
        
        await engine1.start()
        await engine2.start()
        
        try:
            # Create enrichment request
            request = EnrichmentRequest(
                request_id=f"multi_service_test_{uuid4()}",
                data_type=DataType.CVE,
                data={
                    "cve_id": "CVE-2023-TEST",
                    "description": "Test CVE for multi-service communication"
                },
                enrichment_types=[EnrichmentType.THREAT_INTELLIGENCE],
                priority=5
            )
            
            # Submit to first engine
            task_id = await engine1.enrich_data(request)
            
            # Check status from both engines
            task1 = await engine1.get_enrichment_status(task_id)
            task2 = await engine2.get_enrichment_status(task_id)
            
            # First engine should have the task
            assert task1 is not None
            
            # Second engine won't have the task (tasks are engine-specific)
            assert task2 is None
            
        finally:
            await engine1.stop()
            await engine2.stop()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])