"""Event subscriber for enrichment service."""

import asyncio
from typing import Dict, Any, Optional, Callable, List
from datetime import datetime

import structlog
from shared.event_bus import RedisEventBus, EventMessage, EventPattern, PatternType
from shared.config import get_settings

from ..schemas.enrichment import EnrichmentRequest, DataType, EnrichmentType
from .enrichment_engine import EnrichmentEngine

settings = get_settings()
logger = structlog.get_logger()


class EventSubscriber:
    """Event subscriber for processing incoming events from other services."""
    
    def __init__(self, enrichment_engine: EnrichmentEngine):
        self.enrichment_engine = enrichment_engine
        self.event_bus = RedisEventBus(service_name="enrichment")
        self.logger = logger.bind(service="enrichment", component="event_subscriber")
        self.is_running = False
        self.subscriptions: Dict[str, str] = {}
        
        # Event type to handler mapping
        self.event_handlers = {
            "sbom.ingested": self._handle_sbom_ingested,
            "cve.ingested": self._handle_cve_ingested,
            "runtime.ingested": self._handle_runtime_ingested,
            "validation.failed": self._handle_validation_failed,
            "ingestion.error": self._handle_ingestion_error,
        }
    
    async def start(self) -> None:
        """Start the event subscriber."""
        try:
            # Connect to event bus
            await self.event_bus.connect()
            
            # Subscribe to events
            await self._subscribe_to_events()
            
            self.is_running = True
            self.logger.info("Event subscriber started successfully")
            
        except Exception as e:
            self.logger.error("Failed to start event subscriber", error=str(e))
            raise
    
    async def stop(self) -> None:
        """Stop the event subscriber."""
        try:
            self.is_running = False
            
            # Unsubscribe from events
            await self._unsubscribe_from_events()
            
            # Disconnect from event bus
            await self.event_bus.disconnect()
            
            self.logger.info("Event subscriber stopped successfully")
            
        except Exception as e:
            self.logger.error("Error stopping event subscriber", error=str(e))
            raise
    
    async def _subscribe_to_events(self) -> None:
        """Subscribe to relevant events."""
        # Subscribe to ingestion events
        for event_type, handler in self.event_handlers.items():
            try:
                subscription_id = await self.event_bus.subscribe(
                    event_pattern=event_type,
                    handler=handler,
                    options={"auto_ack": True}
                )
                self.subscriptions[event_type] = subscription_id
                
                self.logger.info(
                    "Subscribed to event type",
                    event_type=event_type,
                    subscription_id=subscription_id
                )
                
            except Exception as e:
                self.logger.error(
                    "Failed to subscribe to event type",
                    event_type=event_type,
                    error=str(e)
                )
                raise
    
    async def _unsubscribe_from_events(self) -> None:
        """Unsubscribe from events."""
        for event_type, subscription_id in self.subscriptions.items():
            try:
                await self.event_bus.unsubscribe(subscription_id)
                self.logger.info(
                    "Unsubscribed from event type",
                    event_type=event_type,
                    subscription_id=subscription_id
                )
            except Exception as e:
                self.logger.error(
                    "Failed to unsubscribe from event type",
                    event_type=event_type,
                    error=str(e)
                )
        
        self.subscriptions.clear()
    
    async def _handle_sbom_ingested(self, event: EventMessage) -> None:
        """Handle SBOM ingested events."""
        try:
            self.logger.info(
                "Processing SBOM ingested event",
                event_id=event.event_id,
                correlation_id=event.correlation_id
            )
            
            # Extract SBOM data
            sbom_data = event.data
            
            # Create enrichment request
            enrichment_request = EnrichmentRequest(
                request_id=f"sbom_{event.event_id}",
                data_type=DataType.SBOM,
                data=sbom_data,
                enrichment_types=[
                    EnrichmentType.THREAT_INTELLIGENCE,
                    EnrichmentType.MITRE_ATTACK,
                    EnrichmentType.VULNERABILITY_ANALYSIS,
                ],
                source_service=event.source_service,
                correlation_id=event.correlation_id,
                priority=self._determine_priority(sbom_data),
                metadata={
                    "original_event_id": event.event_id,
                    "ingestion_timestamp": event.timestamp.isoformat(),
                }
            )
            
            # Submit for enrichment
            await self.enrichment_engine.enrich_data(enrichment_request)
            
            self.logger.info(
                "SBOM enrichment request submitted",
                request_id=enrichment_request.request_id,
                event_id=event.event_id
            )
            
        except Exception as e:
            self.logger.error(
                "Error processing SBOM ingested event",
                event_id=event.event_id,
                error=str(e)
            )
            await self._publish_error_event(event, str(e))
    
    async def _handle_cve_ingested(self, event: EventMessage) -> None:
        """Handle CVE ingested events."""
        try:
            self.logger.info(
                "Processing CVE ingested event",
                event_id=event.event_id,
                correlation_id=event.correlation_id
            )
            
            # Extract CVE data
            cve_data = event.data
            
            # Create enrichment request
            enrichment_request = EnrichmentRequest(
                request_id=f"cve_{event.event_id}",
                data_type=DataType.CVE,
                data=cve_data,
                enrichment_types=[
                    EnrichmentType.THREAT_INTELLIGENCE,
                    EnrichmentType.MITRE_ATTACK,
                    EnrichmentType.VULNERABILITY_ANALYSIS,
                ],
                source_service=event.source_service,
                correlation_id=event.correlation_id,
                priority=self._determine_priority(cve_data),
                metadata={
                    "original_event_id": event.event_id,
                    "ingestion_timestamp": event.timestamp.isoformat(),
                }
            )
            
            # Submit for enrichment
            await self.enrichment_engine.enrich_data(enrichment_request)
            
            self.logger.info(
                "CVE enrichment request submitted",
                request_id=enrichment_request.request_id,
                event_id=event.event_id
            )
            
        except Exception as e:
            self.logger.error(
                "Error processing CVE ingested event",
                event_id=event.event_id,
                error=str(e)
            )
            await self._publish_error_event(event, str(e))
    
    async def _handle_runtime_ingested(self, event: EventMessage) -> None:
        """Handle runtime behavior ingested events."""
        try:
            self.logger.info(
                "Processing runtime ingested event",
                event_id=event.event_id,
                correlation_id=event.correlation_id
            )
            
            # Extract runtime data
            runtime_data = event.data
            
            # Create enrichment request
            enrichment_request = EnrichmentRequest(
                request_id=f"runtime_{event.event_id}",
                data_type=DataType.RUNTIME,
                data=runtime_data,
                enrichment_types=[
                    EnrichmentType.THREAT_INTELLIGENCE,
                    EnrichmentType.MITRE_ATTACK,
                    EnrichmentType.BEHAVIORAL_ANALYSIS,
                ],
                source_service=event.source_service,
                correlation_id=event.correlation_id,
                priority=self._determine_priority(runtime_data),
                metadata={
                    "original_event_id": event.event_id,
                    "ingestion_timestamp": event.timestamp.isoformat(),
                }
            )
            
            # Submit for enrichment
            await self.enrichment_engine.enrich_data(enrichment_request)
            
            self.logger.info(
                "Runtime enrichment request submitted",
                request_id=enrichment_request.request_id,
                event_id=event.event_id
            )
            
        except Exception as e:
            self.logger.error(
                "Error processing runtime ingested event",
                event_id=event.event_id,
                error=str(e)
            )
            await self._publish_error_event(event, str(e))
    
    async def _handle_validation_failed(self, event: EventMessage) -> None:
        """Handle validation failed events."""
        try:
            self.logger.warning(
                "Validation failed event received",
                event_id=event.event_id,
                correlation_id=event.correlation_id
            )
            
            # Extract validation failure data
            validation_data = event.data
            data_type = validation_data.get("data_type", "unknown")
            errors = validation_data.get("errors", [])
            
            # Log validation failure
            self.logger.warning(
                "Data validation failed",
                event_id=event.event_id,
                data_type=data_type,
                error_count=len(errors),
                errors=errors[:5]  # Log first 5 errors
            )
            
            # Optionally, we could still attempt enrichment for partially valid data
            # For now, we'll just log and skip enrichment
            
        except Exception as e:
            self.logger.error(
                "Error processing validation failed event",
                event_id=event.event_id,
                error=str(e)
            )
    
    async def _handle_ingestion_error(self, event: EventMessage) -> None:
        """Handle ingestion error events."""
        try:
            self.logger.warning(
                "Ingestion error event received",
                event_id=event.event_id,
                correlation_id=event.correlation_id
            )
            
            # Extract ingestion error data
            error_data = event.data
            error_type = error_data.get("error_type", "unknown")
            error_message = error_data.get("error_message", "")
            
            # Log ingestion error
            self.logger.warning(
                "Ingestion error occurred",
                event_id=event.event_id,
                error_type=error_type,
                error_message=error_message
            )
            
        except Exception as e:
            self.logger.error(
                "Error processing ingestion error event",
                event_id=event.event_id,
                error=str(e)
            )
    
    def _determine_priority(self, data: Dict[str, Any]) -> int:
        """Determine processing priority based on data content."""
        priority = 5  # Default priority
        
        try:
            # Higher priority for high-severity vulnerabilities
            if "vulnerabilities" in data:
                for vuln in data["vulnerabilities"]:
                    severity = vuln.get("severity", "").lower()
                    if severity in ["critical", "high"]:
                        priority = max(priority, 8)
                    elif severity == "medium":
                        priority = max(priority, 6)
            
            # Higher priority for CVEs with high CVSS scores
            if "cvss_score" in data:
                cvss_score = data.get("cvss_score", 0)
                if cvss_score >= 9.0:
                    priority = max(priority, 9)
                elif cvss_score >= 7.0:
                    priority = max(priority, 7)
                elif cvss_score >= 4.0:
                    priority = max(priority, 6)
            
            # Higher priority for runtime anomalies
            if "anomalies" in data:
                anomaly_count = len(data["anomalies"])
                if anomaly_count > 0:
                    priority = max(priority, 7)
            
            # Higher priority for suspicious processes
            if "events" in data:
                for event in data["events"]:
                    if event.get("event_type") == "suspicious_process":
                        priority = max(priority, 8)
                        break
            
        except Exception as e:
            self.logger.warning(
                "Error determining priority, using default",
                error=str(e)
            )
        
        return min(priority, 10)  # Cap at maximum priority
    
    async def _publish_error_event(self, original_event: EventMessage, error: str) -> None:
        """Publish an error event."""
        try:
            await self.event_bus.publish(
                event_type="enrichment.error",
                data={
                    "original_event_id": original_event.event_id,
                    "original_event_type": original_event.event_type,
                    "error_message": error,
                    "timestamp": datetime.utcnow().isoformat(),
                },
                correlation_id=original_event.correlation_id
            )
        except Exception as e:
            self.logger.error(
                "Failed to publish error event",
                original_event_id=original_event.event_id,
                error=str(e)
            )
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on the event subscriber."""
        health_status = {
            "service": "event_subscriber",
            "status": "healthy" if self.is_running else "stopped",
            "subscriptions": len(self.subscriptions),
            "subscribed_events": list(self.subscriptions.keys()),
            "timestamp": datetime.utcnow().isoformat(),
        }
        
        # Check event bus health
        if self.event_bus.is_connected:
            try:
                bus_health = await self.event_bus.health_check()
                health_status["event_bus"] = bus_health
            except Exception as e:
                health_status["event_bus"] = {
                    "status": "unhealthy",
                    "error": str(e)
                }
        else:
            health_status["event_bus"] = {
                "status": "disconnected"
            }
        
        return health_status
    
    def get_stats(self) -> Dict[str, Any]:
        """Get subscriber statistics."""
        return {
            "service": "event_subscriber",
            "is_running": self.is_running,
            "subscriptions": len(self.subscriptions),
            "subscribed_events": list(self.subscriptions.keys()),
            "event_handlers": len(self.event_handlers),
            "timestamp": datetime.utcnow().isoformat(),
        }