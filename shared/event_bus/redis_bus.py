"""Redis-based event bus implementation."""

import asyncio
import json
import fnmatch
from typing import Any, Dict, Optional, List, Callable
from datetime import datetime

import redis.asyncio as redis
from pydantic import ValidationError

from .base import EventBusBase, EventMessage, EventHandler
from .exceptions import EventBusError, EventPublishError, EventSubscribeError
from .serializers import JSONEventSerializer
from shared.config import get_settings

settings = get_settings()


class RedisEventBus(EventBusBase):
    """Redis-based event bus implementation."""
    
    def __init__(
        self,
        service_name: str,
        redis_url: Optional[str] = None,
        serializer: Optional[Any] = None,
        channel_prefix: str = "mcp",
    ):
        super().__init__(service_name)
        self.redis_url = redis_url or str(settings.redis_url)
        self.serializer = serializer or JSONEventSerializer()
        self.channel_prefix = channel_prefix
        self.redis_client: Optional[redis.Redis] = None
        self.subscriber_tasks: Dict[str, asyncio.Task] = {}
        self.subscriptions: Dict[str, List[str]] = {}  # handler_id -> channels
        self.channel_handlers: Dict[str, List[EventHandler]] = {}  # channel -> handlers
        
        # Event type to channel mapping
        self.event_channel_map = {
            "sbom.ingested": f"{channel_prefix}.ingestion.sbom",
            "cve.ingested": f"{channel_prefix}.ingestion.cve",
            "runtime.ingested": f"{channel_prefix}.ingestion.runtime",
            "validation.failed": f"{channel_prefix}.ingestion.validation_failed",
            "ingestion.error": f"{channel_prefix}.ingestion.error",
            "enrichment.completed": f"{channel_prefix}.enrichment.completed",
            "enrichment.failed": f"{channel_prefix}.enrichment.failed",
            "threat.detected": f"{channel_prefix}.threat.detected",
            "mitre.mapped": f"{channel_prefix}.mitre.mapped",
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
            
            self.logger.info("Connected to Redis event bus", redis_url=self.redis_url)
        
        except Exception as e:
            self.logger.error("Failed to connect to Redis", error=str(e))
            self.is_connected = False
            raise EventBusError(f"Failed to connect to Redis: {str(e)}")
    
    async def disconnect(self) -> None:
        """Disconnect from Redis."""
        try:
            # Cancel all subscriber tasks
            for task in self.subscriber_tasks.values():
                task.cancel()
            
            # Wait for tasks to complete
            if self.subscriber_tasks:
                await asyncio.gather(*self.subscriber_tasks.values(), return_exceptions=True)
            
            # Close Redis connection
            if self.redis_client:
                await self.redis_client.close()
                self.redis_client = None
            
            self.is_connected = False
            self.subscriber_tasks.clear()
            self.subscriptions.clear()
            self.channel_handlers.clear()
            
            self.logger.info("Disconnected from Redis event bus")
        
        except Exception as e:
            self.logger.error("Error during disconnect", error=str(e))
            raise EventBusError(f"Failed to disconnect from Redis: {str(e)}")
    
    async def publish(
        self,
        event_type: str,
        data: Dict[str, Any],
        correlation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Publish an event to Redis."""
        if not self.is_connected or not self.redis_client:
            raise EventBusError("Event bus not connected")
        
        try:
            # Create event message
            event = self._create_event_message(
                event_type=event_type,
                data=data,
                correlation_id=correlation_id,
                metadata=metadata,
            )
            
            # Apply outbound middleware
            event = await self._apply_middleware(event, "outbound")
            
            # Get channel for event type
            channel = self.event_channel_map.get(event_type, f"{self.channel_prefix}.default")
            
            # Serialize event
            serialized_event = self.serializer.serialize(event)
            
            # Publish to Redis
            subscribers = await self.redis_client.publish(channel, serialized_event)
            
            if subscribers > 0:
                self.logger.info(
                    "Event published successfully",
                    event_type=event_type,
                    event_id=event.event_id,
                    channel=channel,
                    subscribers=subscribers,
                )
                return True
            else:
                self.logger.warning(
                    "Event published but no subscribers",
                    event_type=event_type,
                    event_id=event.event_id,
                    channel=channel,
                )
                return True
        
        except Exception as e:
            self.logger.error(
                "Failed to publish event",
                event_type=event_type,
                error=str(e),
            )
            raise EventPublishError(f"Failed to publish event: {str(e)}")
    
    async def subscribe(
        self,
        event_pattern: str,
        handler: Callable,
        options: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Subscribe to events matching a pattern."""
        if not self.is_connected or not self.redis_client:
            raise EventBusError("Event bus not connected")
        
        try:
            # Create event handler
            event_handler = EventHandler(
                handler=handler,
                event_pattern=event_pattern,
                service_name=self.service_name,
                options=options or {},
            )
            
            # Register handler
            self.handlers[event_handler.handler_id] = event_handler
            
            # Get channels for pattern
            channels = self._get_channels_for_pattern(event_pattern)
            self.subscriptions[event_handler.handler_id] = channels
            
            # Add handler to channel handlers
            for channel in channels:
                if channel not in self.channel_handlers:
                    self.channel_handlers[channel] = []
                self.channel_handlers[channel].append(event_handler)
            
            # Start subscriber tasks for new channels
            for channel in channels:
                if channel not in self.subscriber_tasks:
                    task = asyncio.create_task(self._subscribe_to_channel(channel))
                    self.subscriber_tasks[channel] = task
            
            self.logger.info(
                "Subscribed to events",
                event_pattern=event_pattern,
                handler_id=event_handler.handler_id,
                channels=channels,
            )
            
            return event_handler.handler_id
        
        except Exception as e:
            self.logger.error(
                "Failed to subscribe to events",
                event_pattern=event_pattern,
                error=str(e),
            )
            raise EventSubscribeError(f"Failed to subscribe to events: {str(e)}")
    
    async def unsubscribe(self, handler_id: str) -> bool:
        """Unsubscribe from events."""
        if handler_id not in self.handlers:
            return False
        
        try:
            # Get handler and channels
            handler = self.handlers[handler_id]
            channels = self.subscriptions.get(handler_id, [])
            
            # Remove handler from channel handlers
            for channel in channels:
                if channel in self.channel_handlers:
                    self.channel_handlers[channel] = [
                        h for h in self.channel_handlers[channel]
                        if h.handler_id != handler_id
                    ]
                    
                    # Cancel subscriber task if no more handlers
                    if not self.channel_handlers[channel]:
                        if channel in self.subscriber_tasks:
                            self.subscriber_tasks[channel].cancel()
                            del self.subscriber_tasks[channel]
                        del self.channel_handlers[channel]
            
            # Remove handler and subscription
            del self.handlers[handler_id]
            del self.subscriptions[handler_id]
            
            self.logger.info(
                "Unsubscribed from events",
                handler_id=handler_id,
                event_pattern=handler.event_pattern,
                channels=channels,
            )
            
            return True
        
        except Exception as e:
            self.logger.error(
                "Failed to unsubscribe from events",
                handler_id=handler_id,
                error=str(e),
            )
            return False
    
    async def _subscribe_to_channel(self, channel: str) -> None:
        """Subscribe to a specific Redis channel."""
        try:
            pubsub = self.redis_client.pubsub()
            await pubsub.subscribe(channel)
            
            self.logger.info("Subscribed to channel", channel=channel)
            
            # Listen for messages
            while True:
                try:
                    message = await pubsub.get_message(timeout=1.0)
                    
                    if message is None:
                        continue
                    
                    if message["type"] == "message":
                        await self._handle_channel_message(channel, message["data"])
                
                except asyncio.TimeoutError:
                    continue
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    self.logger.error(
                        "Error processing message",
                        channel=channel,
                        error=str(e),
                    )
        
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.logger.error(
                "Error in channel subscription",
                channel=channel,
                error=str(e),
            )
        finally:
            try:
                await pubsub.close()
            except Exception:
                pass
    
    async def _handle_channel_message(self, channel: str, message_data: bytes) -> None:
        """Handle a message from a Redis channel."""
        try:
            # Deserialize event
            event = self.serializer.deserialize(message_data)
            
            # Get handlers for this channel
            handlers = self.channel_handlers.get(channel, [])
            
            # Process event with each handler
            for handler in handlers:
                try:
                    # Check if event matches handler pattern
                    if self._matches_pattern(event.event_type, handler.event_pattern):
                        await self._handle_event(handler, event)
                except Exception as e:
                    self.logger.error(
                        "Error handling event",
                        event_type=event.event_type,
                        event_id=event.event_id,
                        handler_id=handler.handler_id,
                        error=str(e),
                    )
        
        except Exception as e:
            self.logger.error(
                "Error processing channel message",
                channel=channel,
                error=str(e),
            )
    
    def _get_channels_for_pattern(self, pattern: str) -> List[str]:
        """Get Redis channels for an event pattern."""
        channels = []
        
        # If pattern is a specific event type, get its channel
        if pattern in self.event_channel_map:
            channels.append(self.event_channel_map[pattern])
        else:
            # Check for wildcard patterns
            for event_type, channel in self.event_channel_map.items():
                if fnmatch.fnmatch(event_type, pattern):
                    channels.append(channel)
        
        # If no matches, use default channel
        if not channels:
            channels.append(f"{self.channel_prefix}.default")
        
        return channels
    
    def _matches_pattern(self, event_type: str, pattern: str) -> bool:
        """Check if an event type matches a pattern."""
        return fnmatch.fnmatch(event_type, pattern)
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on the Redis event bus."""
        health_status = {
            "service": self.service_name,
            "connected": self.is_connected,
            "redis_url": self.redis_url,
            "handlers_count": len(self.handlers),
            "subscriptions_count": len(self.subscriptions),
            "active_channels": len(self.subscriber_tasks),
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
                active_channels = list(self.channel_handlers.keys())
                health_status["active_channels_list"] = active_channels
                
                # Get subscription counts
                subscription_counts = {}
                for channel in active_channels:
                    try:
                        result = await self.redis_client.pubsub_numsub(channel)
                        subscription_counts[channel] = result.get(channel, 0)
                    except Exception:
                        subscription_counts[channel] = 0
                
                health_status["subscription_counts"] = subscription_counts
                health_status["status"] = "healthy"
                
            except Exception as e:
                health_status["redis_ping"] = False
                health_status["error"] = str(e)
                health_status["status"] = "unhealthy"
        else:
            health_status["status"] = "disconnected"
        
        return health_status
    
    async def get_channel_stats(self) -> Dict[str, Any]:
        """Get statistics for all channels."""
        stats = {}
        
        if self.is_connected and self.redis_client:
            for channel in self.channel_handlers.keys():
                try:
                    # Get subscriber count
                    result = await self.redis_client.pubsub_numsub(channel)
                    subscriber_count = result.get(channel, 0)
                    
                    # Get handler count
                    handler_count = len(self.channel_handlers[channel])
                    
                    stats[channel] = {
                        "subscribers": subscriber_count,
                        "handlers": handler_count,
                        "handler_ids": [h.handler_id for h in self.channel_handlers[channel]],
                    }
                except Exception as e:
                    stats[channel] = {"error": str(e)}
        
        return stats
    
    async def publish_batch(
        self,
        events: List[Dict[str, Any]],
        correlation_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Publish multiple events as a batch."""
        results = {
            "total": len(events),
            "successful": 0,
            "failed": 0,
            "errors": [],
        }
        
        for i, event_data in enumerate(events):
            try:
                event_type = event_data.get("event_type")
                data = event_data.get("data", {})
                metadata = event_data.get("metadata", {})
                
                success = await self.publish(
                    event_type=event_type,
                    data=data,
                    correlation_id=correlation_id,
                    metadata=metadata,
                )
                
                if success:
                    results["successful"] += 1
                else:
                    results["failed"] += 1
                    results["errors"].append(f"Event {i}: Publication failed")
            
            except Exception as e:
                results["failed"] += 1
                results["errors"].append(f"Event {i}: {str(e)}")
        
        return results