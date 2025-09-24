"""Tests for the ingestion service components."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

from services.ingestion.services.event_bus import EventBusService, EventMessage
from services.ingestion.services.validation import ValidationService, ValidationResult
from services.ingestion.services.metrics import MetricsService


class TestEventBusService:
    """Test cases for EventBusService."""

    @pytest.fixture
    def event_bus(self, mock_redis):
        """Create event bus service with mock Redis."""
        service = EventBusService()
        service.redis_client = mock_redis
        service.is_connected = True
        return service

    @pytest.mark.asyncio
    async def test_connect_success(self, mock_redis):
        """Test successful Redis connection."""
        service = EventBusService()
        
        with patch('redis.asyncio.from_url', return_value=mock_redis):
            await service.connect()
            
            assert service.is_connected is True
            assert service.redis_client is not None
            mock_redis.ping.assert_called_once()

    @pytest.mark.asyncio
    async def test_connect_failure(self):
        """Test Redis connection failure."""
        service = EventBusService()
        
        with patch('redis.asyncio.from_url') as mock_from_url:
            mock_redis = AsyncMock()
            mock_redis.ping.side_effect = Exception("Connection failed")
            mock_from_url.return_value = mock_redis
            
            with pytest.raises(Exception):
                await service.connect()
            
            assert service.is_connected is False

    @pytest.mark.asyncio
    async def test_disconnect(self, event_bus):
        """Test Redis disconnection."""
        await event_bus.disconnect()
        
        assert event_bus.is_connected is False
        event_bus.redis_client.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_publish_event_success(self, event_bus):
        """Test successful event publication."""
        event_bus.redis_client.publish.return_value = 1
        
        result = await event_bus.publish_event(
            event_type="test.event",
            data={"key": "value"},
            event_id="test-123"
        )
        
        assert result is True
        event_bus.redis_client.publish.assert_called_once()

    @pytest.mark.asyncio
    async def test_publish_event_not_connected(self, event_bus):
        """Test event publication when not connected."""
        event_bus.is_connected = False
        
        result = await event_bus.publish_event(
            event_type="test.event",
            data={"key": "value"}
        )
        
        assert result is False

    @pytest.mark.asyncio
    async def test_publish_event_failure(self, event_bus):
        """Test event publication failure."""
        event_bus.redis_client.publish.side_effect = Exception("Publish failed")
        
        result = await event_bus.publish_event(
            event_type="test.event",
            data={"key": "value"}
        )
        
        assert result is False

    @pytest.mark.asyncio
    async def test_publish_sbom_ingested(self, event_bus):
        """Test SBOM ingested event publication."""
        event_bus.redis_client.publish.return_value = 1
        
        sbom_data = {
            "components": [{"id": "comp1"}],
            "vulnerabilities": [{"id": "vuln1"}]
        }
        
        result = await event_bus.publish_sbom_ingested(
            sbom_data=sbom_data,
            ingestion_id="test-123",
            source_system="test-system"
        )
        
        assert result is True
        event_bus.redis_client.publish.assert_called_once()

    @pytest.mark.asyncio
    async def test_publish_cve_ingested(self, event_bus):
        """Test CVE ingested event publication."""
        event_bus.redis_client.publish.return_value = 1
        
        cve_data = {
            "cve_id": "CVE-2023-12345",
            "metrics": {
                "cvss_v3": {"baseSeverity": "HIGH"}
            }
        }
        
        result = await event_bus.publish_cve_ingested(
            cve_data=cve_data,
            ingestion_id="test-123",
            source_system="test-system"
        )
        
        assert result is True
        event_bus.redis_client.publish.assert_called_once()

    @pytest.mark.asyncio
    async def test_publish_runtime_ingested(self, event_bus):
        """Test runtime ingested event publication."""
        event_bus.redis_client.publish.return_value = 1
        
        runtime_data = {
            "session_id": "session-123",
            "host_name": "test-host",
            "events": [{"event_id": "event1"}],
            "anomalies": [{"anomaly_id": "anomaly1"}]
        }
        
        result = await event_bus.publish_runtime_ingested(
            runtime_data=runtime_data,
            ingestion_id="test-123",
            source_system="test-system"
        )
        
        assert result is True
        event_bus.redis_client.publish.assert_called_once()

    @pytest.mark.asyncio
    async def test_publish_validation_failed(self, event_bus):
        """Test validation failed event publication."""
        event_bus.redis_client.publish.return_value = 1
        
        result = await event_bus.publish_validation_failed(
            data_type="sbom",
            errors=["Field required", "Invalid format"],
            ingestion_id="test-123",
            raw_data={"invalid": "data"}
        )
        
        assert result is True
        event_bus.redis_client.publish.assert_called_once()

    @pytest.mark.asyncio
    async def test_publish_ingestion_error(self, event_bus):
        """Test ingestion error event publication."""
        event_bus.redis_client.publish.return_value = 1
        
        result = await event_bus.publish_ingestion_error(
            error_type="validation_error",
            error_message="Data validation failed",
            ingestion_id="test-123",
            additional_data={"field": "value"}
        )
        
        assert result is True
        event_bus.redis_client.publish.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_channel_subscribers(self, event_bus):
        """Test getting channel subscribers."""
        event_bus.redis_client.pubsub_numsub.return_value = {"test_channel": 5}
        
        count = await event_bus.get_channel_subscribers("test_channel")
        
        assert count == 5
        event_bus.redis_client.pubsub_numsub.assert_called_once_with("test_channel")

    @pytest.mark.asyncio
    async def test_get_all_channels(self, event_bus):
        """Test getting all channels."""
        event_bus.redis_client.pubsub_channels.return_value = ["channel1", "channel2"]
        
        channels = await event_bus.get_all_channels()
        
        assert channels == ["channel1", "channel2"]
        event_bus.redis_client.pubsub_channels.assert_called_once()

    @pytest.mark.asyncio
    async def test_health_check_connected(self, event_bus):
        """Test health check when connected."""
        event_bus.redis_client.info.return_value = {
            "redis_version": "7.0.0",
            "uptime_in_seconds": 3600
        }
        event_bus.redis_client.pubsub_channels.return_value = ["channel1"]
        
        health = await event_bus.health_check()
        
        assert health["connected"] is True
        assert health["redis_ping"] is True
        assert health["redis_version"] == "7.0.0"
        assert health["active_channels"] == 1

    @pytest.mark.asyncio
    async def test_health_check_disconnected(self, event_bus):
        """Test health check when disconnected."""
        event_bus.is_connected = False
        event_bus.redis_client = None
        
        health = await event_bus.health_check()
        
        assert health["connected"] is False

    def test_extract_cve_severity_v3(self, event_bus):
        """Test CVE severity extraction from CVSS v3."""
        cve_data = {
            "metrics": {
                "cvss_v3": {"baseSeverity": "CRITICAL"}
            }
        }
        
        severity = event_bus._extract_cve_severity(cve_data)
        assert severity == "CRITICAL"

    def test_extract_cve_severity_v2(self, event_bus):
        """Test CVE severity extraction from CVSS v2."""
        cve_data = {
            "metrics": {
                "cvss_v2": {"baseScore": 8.5}
            }
        }
        
        severity = event_bus._extract_cve_severity(cve_data)
        assert severity == "HIGH"

    def test_extract_cve_severity_none(self, event_bus):
        """Test CVE severity extraction when no metrics."""
        cve_data = {"metrics": {}}
        
        severity = event_bus._extract_cve_severity(cve_data)
        assert severity is None


class TestValidationService:
    """Test cases for ValidationService."""

    @pytest.fixture
    def validation_service(self):
        """Create validation service."""
        return ValidationService()

    @pytest.mark.asyncio
    async def test_validate_sbom_success(self, validation_service, sample_sbom_data):
        """Test successful SBOM validation."""
        result = await validation_service.validate_sbom(sample_sbom_data)
        
        assert result.is_valid is True
        assert result.data is not None
        assert result.errors == []

    @pytest.mark.asyncio
    async def test_validate_sbom_failure(self, validation_service, invalid_sbom_data):
        """Test failed SBOM validation."""
        result = await validation_service.validate_sbom(invalid_sbom_data)
        
        assert result.is_valid is False
        assert len(result.errors) > 0

    @pytest.mark.asyncio
    async def test_validate_cve_success(self, validation_service, sample_cve_data):
        """Test successful CVE validation."""
        result = await validation_service.validate_cve(sample_cve_data)
        
        assert result.is_valid is True
        assert result.data is not None
        assert result.errors == []

    @pytest.mark.asyncio
    async def test_validate_runtime_success(self, validation_service, sample_runtime_data):
        """Test successful runtime validation."""
        result = await validation_service.validate_runtime(sample_runtime_data)
        
        assert result.is_valid is True
        assert result.data is not None
        assert result.errors == []

    @pytest.mark.asyncio
    async def test_validate_data_type_unknown(self, validation_service):
        """Test validation with unknown data type."""
        result = await validation_service.validate_data_type({}, "unknown")
        
        assert result.is_valid is False
        assert "Unknown data type" in result.errors[0]

    @pytest.mark.asyncio
    async def test_validate_batch_success(self, validation_service, sample_batch_data):
        """Test successful batch validation."""
        result = await validation_service.validate_batch(sample_batch_data, "sbom")
        
        assert result["total"] == len(sample_batch_data)
        assert result["valid"] > 0
        assert result["invalid"] == 0

    @pytest.mark.asyncio
    async def test_validate_batch_with_errors(self, validation_service, sample_batch_data):
        """Test batch validation with errors."""
        # Add invalid data to batch
        invalid_item = {"invalid": "data"}
        batch_data = sample_batch_data + [invalid_item]
        
        result = await validation_service.validate_batch(batch_data, "sbom")
        
        assert result["total"] == len(batch_data)
        assert result["valid"] > 0
        assert result["invalid"] > 0
        assert len(result["errors"]) > 0

    @pytest.mark.asyncio
    async def test_validate_batch_stop_on_error(self, validation_service, sample_batch_data):
        """Test batch validation stopping on first error."""
        # Add invalid data to batch
        invalid_item = {"invalid": "data"}
        batch_data = [invalid_item] + sample_batch_data
        
        result = await validation_service.validate_batch(
            batch_data, "sbom", stop_on_first_error=True
        )
        
        assert result["total"] == len(batch_data)
        assert result["invalid"] == 1
        assert len(result["results"]) == 1  # Should stop after first error

    @pytest.mark.asyncio
    async def test_pre_validate_json_success(self, validation_service):
        """Test successful JSON pre-validation."""
        json_data = '{"key": "value"}'
        
        is_valid, data, errors = await validation_service.pre_validate_json(json_data)
        
        assert is_valid is True
        assert data == {"key": "value"}
        assert errors == []

    @pytest.mark.asyncio
    async def test_pre_validate_json_invalid(self, validation_service):
        """Test invalid JSON pre-validation."""
        json_data = '{"invalid": json}'
        
        is_valid, data, errors = await validation_service.pre_validate_json(json_data)
        
        assert is_valid is False
        assert data is None
        assert len(errors) > 0

    @pytest.mark.asyncio
    async def test_pre_validate_json_empty(self, validation_service):
        """Test empty JSON pre-validation."""
        json_data = '{}'
        
        is_valid, data, errors = await validation_service.pre_validate_json(json_data)
        
        assert is_valid is False
        assert "cannot be empty" in errors[0]

    def test_get_schema_info(self, validation_service):
        """Test getting schema information."""
        schema_info = validation_service.get_schema_info("sbom")
        
        assert schema_info is not None
        assert schema_info["data_type"] == "sbom"
        assert "schema_name" in schema_info
        assert "fields" in schema_info
        assert "required_fields" in schema_info

    def test_get_schema_info_unknown(self, validation_service):
        """Test getting schema info for unknown type."""
        schema_info = validation_service.get_schema_info("unknown")
        
        assert schema_info is None

    def test_get_all_schema_info(self, validation_service):
        """Test getting all schema information."""
        all_schemas = validation_service.get_all_schema_info()
        
        assert "sbom" in all_schemas
        assert "cve" in all_schemas
        assert "runtime" in all_schemas

    @pytest.mark.asyncio
    async def test_validate_field_constraints(self, validation_service, sample_sbom_data):
        """Test field constraint validation."""
        constraints = {
            "sbom_version": {
                "allowed_values": ["1.0.0", "2.0.0"]
            }
        }
        
        result = await validation_service.validate_field_constraints(
            sample_sbom_data, "sbom", constraints
        )
        
        assert result.is_valid is True

    @pytest.mark.asyncio
    async def test_validate_field_constraints_violation(self, validation_service, sample_sbom_data):
        """Test field constraint validation violation."""
        constraints = {
            "sbom_version": {
                "allowed_values": ["2.0.0"]  # Not matching sample data
            }
        }
        
        result = await validation_service.validate_field_constraints(
            sample_sbom_data, "sbom", constraints
        )
        
        assert result.is_valid is False
        assert len(result.errors) > 0

    @pytest.mark.asyncio
    async def test_health_check(self, validation_service):
        """Test validation service health check."""
        health = await validation_service.health_check()
        
        assert health["service"] == "validation"
        assert health["status"] == "healthy"
        assert "supported_schemas" in health
        assert "timestamp" in health


class TestMetricsService:
    """Test cases for MetricsService."""

    @pytest.fixture
    def metrics_service(self):
        """Create metrics service."""
        return MetricsService()

    def test_record_ingestion_request(self, metrics_service):
        """Test recording ingestion request."""
        metrics_service.record_ingestion_request("sbom", "success")
        
        summary = metrics_service.get_metrics_summary()
        assert summary["ingestion_requests"]["sbom_success"] == 1

    def test_record_validation_result(self, metrics_service):
        """Test recording validation result."""
        metrics_service.record_validation_result("sbom", "valid")
        
        summary = metrics_service.get_metrics_summary()
        assert summary["validation_results"]["sbom_valid"] == 1

    def test_record_event_publication(self, metrics_service):
        """Test recording event publication."""
        metrics_service.record_event_publication("sbom.ingested", "success")
        
        summary = metrics_service.get_metrics_summary()
        assert summary["event_publications"]["sbom.ingested_success"] == 1

    def test_record_error(self, metrics_service):
        """Test recording error."""
        metrics_service.record_error("validation_error", "sbom")
        
        summary = metrics_service.get_metrics_summary()
        assert summary["error_counts"]["validation_error_sbom"] == 1

    def test_record_request_duration(self, metrics_service):
        """Test recording request duration."""
        metrics_service.record_request_duration("sbom", "ingest", 1.5)
        
        summary = metrics_service.get_metrics_summary()
        assert "sbom_ingest" in summary["processing_times"]
        assert summary["processing_times"]["sbom_ingest"]["avg"] == 1.5

    def test_record_data_size(self, metrics_service):
        """Test recording data size."""
        metrics_service.record_data_size("sbom", 1024)
        
        summary = metrics_service.get_metrics_summary()
        assert summary["data_sizes"]["sbom"]["total"] == 1024

    def test_get_health_metrics(self, metrics_service):
        """Test getting health metrics."""
        # Generate some data
        metrics_service.record_ingestion_request("sbom", "success")
        metrics_service.record_error("test_error", "test_component")
        
        health = metrics_service.get_health_metrics()
        
        assert health["total_requests"] == 1
        assert health["total_errors"] == 1
        assert health["status"] == "degraded"  # Has errors

    def test_get_data_type_metrics(self, metrics_service):
        """Test getting data type specific metrics."""
        # Generate some SBOM metrics
        metrics_service.record_ingestion_request("sbom", "success")
        metrics_service.record_validation_result("sbom", "valid")
        
        sbom_metrics = metrics_service.get_data_type_metrics("sbom")
        
        assert sbom_metrics["data_type"] == "sbom"
        assert sbom_metrics["requests"]["success"] == 1
        assert sbom_metrics["validations"]["valid"] == 1

    def test_reset_metrics(self, metrics_service):
        """Test resetting metrics."""
        # Generate some data
        metrics_service.record_ingestion_request("sbom", "success")
        
        # Reset metrics
        metrics_service.reset_metrics()
        
        # Check metrics are reset
        summary = metrics_service.get_metrics_summary()
        assert summary["ingestion_requests"] == {}

    def test_cleanup_old_data(self, metrics_service):
        """Test cleaning up old data."""
        # Generate lots of data
        for i in range(2000):
            metrics_service.record_request_duration("sbom", "ingest", 1.0)
        
        # Cleanup
        metrics_service.cleanup_old_data()
        
        # Check data is limited
        summary = metrics_service.get_metrics_summary()
        assert summary["processing_times"]["sbom_ingest"]["count"] <= 1000

    @pytest.mark.asyncio
    async def test_health_check(self, metrics_service):
        """Test metrics service health check."""
        health = await metrics_service.health_check()
        
        assert health["service"] == "metrics"
        assert health["status"] == "healthy"
        assert "uptime_seconds" in health
        assert "timestamp" in health


class TestEventMessage:
    """Test cases for EventMessage model."""

    def test_event_message_creation(self):
        """Test creating an event message."""
        event_data = {
            "event_id": "test-123",
            "event_type": "test.event",
            "timestamp": datetime.utcnow(),
            "source_service": "ingestion",
            "data": {"key": "value"}
        }
        
        message = EventMessage(**event_data)
        
        assert message.event_id == "test-123"
        assert message.event_type == "test.event"
        assert message.source_service == "ingestion"
        assert message.data == {"key": "value"}

    def test_event_message_serialization(self):
        """Test event message serialization."""
        event_data = {
            "event_id": "test-123",
            "event_type": "test.event",
            "timestamp": datetime.utcnow(),
            "source_service": "ingestion",
            "data": {"key": "value"}
        }
        
        message = EventMessage(**event_data)
        json_data = message.model_dump_json()
        
        assert isinstance(json_data, str)
        assert "test-123" in json_data
        assert "test.event" in json_data


class TestValidationResult:
    """Test cases for ValidationResult model."""

    def test_validation_result_valid(self):
        """Test creating valid validation result."""
        result = ValidationResult(
            is_valid=True,
            data={"key": "value"},
            errors=[]
        )
        
        assert result.is_valid is True
        assert result.data == {"key": "value"}
        assert result.errors == []

    def test_validation_result_invalid(self):
        """Test creating invalid validation result."""
        result = ValidationResult(
            is_valid=False,
            data=None,
            errors=["Field required", "Invalid format"]
        )
        
        assert result.is_valid is False
        assert result.data == {}
        assert len(result.errors) == 2

    def test_validation_result_to_dict(self):
        """Test converting validation result to dict."""
        result = ValidationResult(
            is_valid=True,
            data={"key": "value"},
            errors=[]
        )
        
        result_dict = result.to_dict()
        
        assert result_dict["is_valid"] is True
        assert result_dict["data"] == {"key": "value"}
        assert result_dict["errors"] == []