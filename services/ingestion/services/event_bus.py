"""Event bus service for publishing validated events to Redis Pub/Sub."""

import json
import asyncio
from datetime import datetime
from typing import Any, Dict, Optional
from uuid import UUID

import redis.asyncio as redis
import structlog
from pydantic import BaseModel

from shared.config import get_settings

settings = get_settings()
logger = structlog.get_logger()


class EventMessage(BaseModel):
    """Event message model for the event bus."""
    
    event_id: str
    event_type: str
    timestamp: datetime
    source_service: str
    data: Dict[str, Any]
    metadata: Optional[Dict[str, Any]] = None
    
    class Config:
        """Pydantic configuration."""
        json_encoders = {
            datetime: lambda v: v.isoformat(),
            UUID: lambda v: str(v),
        }


class EventBusService:
    """Event bus service for publishing and subscribing to events."""
    
    def __init__(self, redis_url: Optional[str] = None):
        """Initialize the event bus service."""
        self.redis_url = redis_url or str(settings.redis_url)
        self.redis_client: Optional[redis.Redis] = None
        self.is_connected = False
        
        # Event type to channel mapping
        self.event_channels = {
            "sbom.ingested": "ingestion.sbom",
            "cve.ingested": "ingestion.cve", 
            "runtime.ingested": "ingestion.runtime",
            "validation.failed": "ingestion.validation_failed",
            "ingestion.error": "ingestion.error",
        }
    
    async def connect(self) -> None:
        """Connect to Redis."""
        try:
            self.redis_client = redis.from_url(
                self.redis_url,
                **settings.get_connection_config(),
            )
            
            # Test connection
            await self.redis_client.ping()
            self.is_connected = True
            
            logger.info("Event bus connected to Redis", redis_url=self.redis_url)
        
        except Exception as e:
            logger.error("Failed to connect to Redis", error=str(e))
            self.is_connected = False
            raise
    
    async def disconnect(self) -> None:
        """Disconnect from Redis."""
        if self.redis_client:
            await self.redis_client.close()
            self.is_connected = False
            logger.info("Event bus disconnected from Redis")
    
    async def publish_event(
        self,
        event_type: str,
        data: Dict[str, Any],
        event_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Publish an event to the event bus."""
        if not self.is_connected or not self.redis_client:
            logger.error("Event bus not connected")
            return False
        
        try:
            # Create event message
            event_message = EventMessage(
                event_id=event_id or f"event_{int(datetime.utcnow().timestamp() * 1000)}",
                event_type=event_type,
                timestamp=datetime.utcnow(),
                source_service="ingestion",
                data=data,
                metadata=metadata or {},
            )
            
            # Get channel for event type
            channel = self.event_channels.get(event_type, "ingestion.default")
            
            # Serialize message
            message_json = event_message.model_dump_json()
            
            # Publish to Redis
            result = await self.redis_client.publish(channel, message_json)
            
            if result > 0:
                logger.info(
                    "Event published successfully",
                    event_type=event_type,
                    event_id=event_message.event_id,
                    channel=channel,
                    subscribers=result,
                )
                return True
            else:
                logger.warning(
                    "Event published but no subscribers",
                    event_type=event_type,
                    event_id=event_message.event_id,
                    channel=channel,
                )
                return True
        
        except Exception as e:
            logger.error(
                "Failed to publish event",
                event_type=event_type,
                error=str(e),
            )
            return False
    
    async def publish_sbom_ingested(
        self,
        sbom_data: Dict[str, Any],
        ingestion_id: str,
        source_system: Optional[str] = None,
    ) -> bool:
        """Publish SBOM ingested event."""
        metadata = {
            "ingestion_id": ingestion_id,
            "source_system": source_system,
            "component_count": len(sbom_data.get("components", [])),
            "vulnerability_count": len(sbom_data.get("vulnerabilities", [])),
        }
        
        return await self.publish_event(
            event_type="sbom.ingested",
            data=sbom_data,
            event_id=f"sbom_{ingestion_id}",
            metadata=metadata,
        )
    
    async def publish_cve_ingested(
        self,
        cve_data: Dict[str, Any],
        ingestion_id: str,
        source_system: Optional[str] = None,
    ) -> bool:
        """Publish CVE ingested event."""
        metadata = {
            "ingestion_id": ingestion_id,
            "source_system": source_system,
            "cve_id": cve_data.get("cve_id"),
            "severity": self._extract_cve_severity(cve_data),
        }
        
        return await self.publish_event(
            event_type="cve.ingested",
            data=cve_data,
            event_id=f"cve_{ingestion_id}",
            metadata=metadata,
        )
    
    async def publish_runtime_ingested(
        self,
        runtime_data: Dict[str, Any],
        ingestion_id: str,
        source_system: Optional[str] = None,
    ) -> bool:
        """Publish runtime behavior ingested event."""
        metadata = {
            "ingestion_id": ingestion_id,
            "source_system": source_system,
            "session_id": runtime_data.get("session_id"),
            "host_name": runtime_data.get("host_name"),
            "event_count": len(runtime_data.get("events", [])),
            "anomaly_count": len(runtime_data.get("anomalies", [])),
        }
        
        return await self.publish_event(
            event_type="runtime.ingested",
            data=runtime_data,
            event_id=f"runtime_{ingestion_id}",
            metadata=metadata,
        )
    
    async def publish_validation_failed(
        self,
        data_type: str,
        errors: list,
        ingestion_id: str,
        raw_data: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Publish validation failed event."""
        metadata = {
            "ingestion_id": ingestion_id,
            "data_type": data_type,
            "error_count": len(errors),
        }
        
        return await self.publish_event(
            event_type="validation.failed",
            data={
                "data_type": data_type,
                "errors": errors,
                "raw_data": raw_data,
            },
            event_id=f"validation_failed_{ingestion_id}",
            metadata=metadata,
        )
    
    async def publish_ingestion_error(
        self,
        error_type: str,
        error_message: str,
        ingestion_id: str,
        additional_data: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Publish ingestion error event."""
        metadata = {
            "ingestion_id": ingestion_id,
            "error_type": error_type,
        }
        
        return await self.publish_event(
            event_type="ingestion.error",
            data={
                "error_type": error_type,
                "error_message": error_message,
                "additional_data": additional_data or {},
            },
            event_id=f"error_{ingestion_id}",
            metadata=metadata,
        )
    
    def _extract_cve_severity(self, cve_data: Dict[str, Any]) -> Optional[str]:
        """Extract CVE severity from metrics data."""
        try:
            metrics = cve_data.get("metrics", {})
            
            # Try CVSS v3 first
            cvss_v3 = metrics.get("cvss_v3", {})
            if cvss_v3.get("baseSeverity"):
                return cvss_v3["baseSeverity"]
            
            # Fall back to CVSS v2
            cvss_v2 = metrics.get("cvss_v2", {})
            if cvss_v2.get("baseScore"):
                score = cvss_v2["baseScore"]
                if score >= 7.0:
                    return "HIGH"
                elif score >= 4.0:
                    return "MEDIUM"
                else:
                    return "LOW"
            
            return None
        
        except Exception:
            return None
    
    async def subscribe_to_channel(
        self,
        channel: str,
        callback: callable,
        timeout: Optional[float] = None,
    ) -> None:
        """Subscribe to a specific channel."""
        if not self.is_connected or not self.redis_client:
            logger.error("Event bus not connected")
            return
        
        try:
            pubsub = self.redis_client.pubsub()
            await pubsub.subscribe(channel)
            
            logger.info("Subscribed to channel", channel=channel)
            
            # Listen for messages
            while True:
                try:
                    message = await pubsub.get_message(timeout=timeout)
                    
                    if message is None:
                        continue
                    
                    if message["type"] == "message":
                        try:
                            # Parse message
                            event_data = json.loads(message["data"])
                            
                            # Call callback
                            await callback(event_data)
                        
                        except json.JSONDecodeError:
                            logger.error(
                                "Failed to parse event message",
                                channel=channel,
                                message=message["data"],
                            )
                        except Exception as e:
                            logger.error(
                                "Error processing event message",
                                channel=channel,
                                error=str(e),
                            )
                
                except asyncio.TimeoutError:
                    continue
                except Exception as e:
                    logger.error(
                        "Error receiving message from channel",
                        channel=channel,
                        error=str(e),
                    )
                    break
        
        except Exception as e:
            logger.error(
                "Failed to subscribe to channel",
                channel=channel,
                error=str(e),
            )
        
        finally:
            try:
                await pubsub.close()
            except Exception:
                pass
    
    async def get_channel_subscribers(self, channel: str) -> int:
        """Get number of subscribers for a channel."""
        if not self.is_connected or not self.redis_client:
            return 0
        
        try:
            result = await self.redis_client.pubsub_numsub(channel)
            return result.get(channel, 0)
        except Exception:
            return 0
    
    async def get_all_channels(self) -> list:
        """Get all active channels."""
        if not self.is_connected or not self.redis_client:
            return []
        
        try:
            return await self.redis_client.pubsub_channels()
        except Exception:
            return []
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on the event bus."""
        health_status = {
            "connected": self.is_connected,
            "redis_url": self.redis_url,
            "timestamp": datetime.utcnow().isoformat(),
        }
        
        if self.is_connected and self.redis_client:
            try:
                # Test Redis connection
                await self.redis_client.ping()
                health_status["redis_ping"] = True
                
                # Get Redis info
                redis_info = await self.redis_client.info()
                health_status["redis_version"] = redis_info.get("redis_version")
                health_status["redis_uptime"] = redis_info.get("uptime_in_seconds")
                
                # Get channel information
                channels = await self.get_all_channels()
                health_status["active_channels"] = len(channels)
                
            except Exception as e:
                health_status["redis_ping"] = False
                health_status["error"] = str(e)
        
        return health_status