"""
Event bus implementation for plugin communication.
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional, Set
from collections import defaultdict, deque
import weakref

import redis.asyncio as redis
from pydantic import ValidationError

from .types import (
    SecurityEvent, PluginEvent, EventSubscription, EventFilter,
    EventMetrics, EventPriority, EventStatus
)
from ..utils.exceptions import EventError
from ..utils.logger import get_logger


class EventBus:
    """
    Async event bus for plugin communication.
    
    Provides pub/sub messaging, event filtering, delivery guarantees,
    and integration with Redis for distributed scenarios.
    """
    
    def __init__(
        self,
        redis_url: Optional[str] = None,
        max_queue_size: int = 10000,
        delivery_timeout: int = 30,
        cleanup_interval: int = 300
    ):
        self.redis_url = redis_url
        self.max_queue_size = max_queue_size
        self.delivery_timeout = delivery_timeout
        self.cleanup_interval = cleanup_interval
        
        # Redis connection
        self._redis: Optional[redis.Redis] = None
        
        # Local state
        self._subscriptions: Dict[str, EventSubscription] = {}
        self._subscribers: Dict[str, Callable] = {}
        self._event_queues: Dict[str, asyncio.Queue] = {}
        self._delivery_tasks: Dict[str, asyncio.Task] = {}
        
        # Metrics and monitoring
        self._metrics = EventMetrics()
        self._event_history: deque = deque(maxlen=1000)
        
        # Background tasks
        self._cleanup_task: Optional[asyncio.Task] = None
        self._running = False
        
        # Logger
        self.logger = get_logger(f"event_bus")
    
    async def start(self) -> None:
        """Start the event bus."""
        if self._running:
            return
            
        self.logger.info("Starting event bus")
        
        # Connect to Redis if configured
        if self.redis_url:
            try:
                self._redis = redis.from_url(self.redis_url)
                await self._redis.ping()
                self.logger.info("Connected to Redis event store")
            except Exception as e:
                self.logger.warning(f"Failed to connect to Redis: {e}")
                self._redis = None
        
        # Start background tasks
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        self._running = True
        
        self.logger.info("Event bus started")
    
    async def stop(self) -> None:
        """Stop the event bus."""
        if not self._running:
            return
            
        self.logger.info("Stopping event bus")
        self._running = False
        
        # Cancel background tasks
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        
        # Cancel delivery tasks
        for task in self._delivery_tasks.values():
            task.cancel()
        
        if self._delivery_tasks:
            await asyncio.gather(*self._delivery_tasks.values(), return_exceptions=True)
        
        # Close Redis connection
        if self._redis:
            await self._redis.close()
        
        self.logger.info("Event bus stopped")
    
    async def subscribe(
        self,
        subscriber_id: str,
        callback: Callable,
        filters: Optional[EventFilter] = None,
        **kwargs
    ) -> EventSubscription:
        """
        Subscribe to events.
        
        Args:
            subscriber_id: Unique subscriber identifier
            callback: Async callback function to handle events
            filters: Event filters
            **kwargs: Additional subscription parameters
            
        Returns:
            EventSubscription: Subscription configuration
        """
        if not self._running:
            await self.start()
        
        subscription = EventSubscription(
            subscriber_id=subscriber_id,
            filters=filters or EventFilter(),
            **kwargs
        )
        
        self._subscriptions[subscription.subscription_id] = subscription
        self._subscribers[subscription.subscription_id] = callback
        
        # Create event queue
        queue = asyncio.Queue(maxsize=subscription.max_queue_size)
        self._event_queues[subscription.subscription_id] = queue
        
        # Start delivery task
        delivery_task = asyncio.create_task(
            self._delivery_loop(subscription.subscription_id)
        )
        self._delivery_tasks[subscription.subscription_id] = delivery_task
        
        self.logger.info(f"Created subscription {subscription.subscription_id} for {subscriber_id}")
        self._metrics.active_subscriptions += 1
        
        return subscription
    
    async def unsubscribe(self, subscription_id: str) -> bool:
        """
        Unsubscribe from events.
        
        Args:
            subscription_id: Subscription identifier
            
        Returns:
            True if subscription was removed
        """
        if subscription_id not in self._subscriptions:
            return False
        
        # Cancel delivery task
        if subscription_id in self._delivery_tasks:
            self._delivery_tasks[subscription_id].cancel()
            try:
                await self._delivery_tasks[subscription_id]
            except asyncio.CancelledError:
                pass
            del self._delivery_tasks[subscription_id]
        
        # Clean up
        self._subscriptions.pop(subscription_id, None)
        self._subscribers.pop(subscription_id, None)
        self._event_queues.pop(subscription_id, None)
        
        self.logger.info(f"Removed subscription {subscription_id}")
        self._metrics.active_subscriptions -= 1
        
        return True
    
    async def publish(self, event: SecurityEvent) -> None:
        """
        Publish a security event.
        
        Args:
            event: Security event to publish
        """
        if not self._running:
            await self.start()
        
        try:
            # Update metrics
            self._metrics.total_events += 1
            self._metrics.events_by_type[event.event_type] = (
                self._metrics.events_by_type.get(event.event_type, 0) + 1
            )
            self._metrics.events_by_source[event.source] = (
                self._metrics.events_by_source.get(event.source, 0) + 1
            )
            self._metrics.events_by_priority[event.priority] = (
                self._metrics.events_by_priority.get(event.priority, 0) + 1
            )
            
            # Store in history
            self._event_history.append({
                'event_id': event.event_id,
                'event_type': event.event_type,
                'timestamp': event.timestamp,
                'source': event.source
            })
            
            # Persist to Redis if available
            if self._redis:
                await self._store_event_redis(event)
            
            # Deliver to subscribers
            await self._deliver_event(event)
            
            self.logger.debug(f"Published event {event.event_id} of type {event.event_type}")
            
        except Exception as e:
            self.logger.error(f"Failed to publish event {event.event_id}: {e}")
            self._metrics.failed_events += 1
            raise EventError(f"Failed to publish event: {e}")
    
    async def publish_plugin_event(self, event: PluginEvent) -> None:
        """
        Publish a plugin-specific event.
        
        Args:
            event: Plugin event to publish
        """
        # Convert to SecurityEvent for unified handling
        security_event = SecurityEvent(
            event_id=event.event_id,
            event_type=event.event_type,
            timestamp=event.timestamp,
            source=event.plugin_id,
            source_type="plugin",
            data=event.data,
            metadata=event.context,
            priority=event.priority,
            correlation_id=event.correlation_id
        )
        
        await self.publish(security_event)
    
    async def get_subscription(self, subscription_id: str) -> Optional[EventSubscription]:
        """Get subscription by ID."""
        return self._subscriptions.get(subscription_id)
    
    async def list_subscriptions(self, subscriber_id: Optional[str] = None) -> List[EventSubscription]:
        """List subscriptions, optionally filtered by subscriber."""
        subscriptions = list(self._subscriptions.values())
        
        if subscriber_id:
            subscriptions = [s for s in subscriptions if s.subscriber_id == subscriber_id]
        
        return subscriptions
    
    async def get_metrics(self) -> EventMetrics:
        """Get event bus metrics."""
        # Update current queue sizes
        self._metrics.current_queue_size = sum(
            queue.qsize() for queue in self._event_queues.values()
        )
        
        return self._metrics
    
    async def get_event_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent event history."""
        return list(self._event_history)[-limit:]
    
    def _match_filters(self, event: SecurityEvent, filters: EventFilter) -> bool:
        """Check if event matches subscription filters."""
        # Type filtering
        if filters.event_types and event.event_type not in filters.event_types:
            return False
        
        if filters.exclude_types and event.event_type in filters.exclude_types:
            return False
        
        # Source filtering
        if filters.sources and event.source not in filters.sources:
            return False
        
        if filters.exclude_sources and event.source in filters.exclude_sources:
            return False
        
        # Priority filtering
        if filters.min_priority:
            priority_order = {p: i for i, p in enumerate(EventPriority)}
            if priority_order.get(event.priority, 999) < priority_order.get(filters.min_priority, 0):
                return False
        
        if filters.max_priority:
            priority_order = {p: i for i, p in enumerate(EventPriority)}
            if priority_order.get(event.priority, 0) > priority_order.get(filters.max_priority, 999):
                return False
        
        # Tag filtering
        if filters.required_tags:
            if not all(tag in event.tags for tag in filters.required_tags):
                return False
        
        if filters.forbidden_tags:
            if any(tag in event.tags for tag in filters.forbidden_tags):
                return False
        
        # Label filtering
        if filters.required_labels:
            for key, value in filters.required_labels.items():
                if event.labels.get(key) != value:
                    return False
        
        if filters.forbidden_labels:
            for key, value in filters.forbidden_labels.items():
                if event.labels.get(key) == value:
                    return False
        
        # Age filtering
        if filters.min_age_seconds or filters.max_age_seconds:
            age = (datetime.now() - event.timestamp).total_seconds()
            
            if filters.min_age_seconds and age < filters.min_age_seconds:
                return False
            
            if filters.max_age_seconds and age > filters.max_age_seconds:
                return False
        
        return True
    
    async def _deliver_event(self, event: SecurityEvent) -> None:
        """Deliver event to matching subscribers."""
        for subscription_id, subscription in self._subscriptions.items():
            if not subscription.active:
                continue
            
            if not self._match_filters(event, subscription.filters):
                continue
            
            # Add to subscriber queue
            queue = self._event_queues.get(subscription_id)
            if queue:
                try:
                    if subscription.backpressure_policy == "drop" and queue.full():
                        self.logger.warning(f"Dropping event for full queue: {subscription_id}")
                        continue
                    
                    await asyncio.wait_for(
                        queue.put(event),
                        timeout=1.0 if subscription.backpressure_policy == "error" else None
                    )
                    
                except asyncio.TimeoutError:
                    if subscription.backpressure_policy == "error":
                        self.logger.error(f"Queue timeout for subscription: {subscription_id}")
                    continue
                except Exception as e:
                    self.logger.error(f"Failed to queue event for {subscription_id}: {e}")
    
    async def _delivery_loop(self, subscription_id: str) -> None:
        """Background loop for event delivery to a subscriber."""
        subscription = self._subscriptions.get(subscription_id)
        if not subscription:
            return
        
        callback = self._subscribers.get(subscription_id)
        if not callback:
            return
        
        queue = self._event_queues.get(subscription_id)
        if not queue:
            return
        
        while self._running and subscription.active:
            try:
                # Get event from queue
                event = await asyncio.wait_for(queue.get(), timeout=1.0)
                
                # Deliver event
                retry_count = 0
                delivered = False
                
                while retry_count <= subscription.max_retries and not delivered:
                    try:
                        await asyncio.wait_for(
                            callback(event),
                            timeout=self.delivery_timeout
                        )
                        
                        delivered = True
                        subscription.events_delivered += 1
                        subscription.last_delivery = datetime.now()
                        self._metrics.total_deliveries += 1
                        
                    except Exception as e:
                        retry_count += 1
                        self.logger.warning(
                            f"Delivery failed for {subscription_id} "
                            f"(attempt {retry_count}): {e}"
                        )
                        
                        if retry_count <= subscription.max_retries:
                            await asyncio.sleep(subscription.retry_delay)
                
                if not delivered:
                    subscription.events_failed += 1
                    self._metrics.failed_deliveries += 1
                    self.logger.error(
                        f"Failed to deliver event to {subscription_id} "
                        f"after {subscription.max_retries} retries"
                    )
                
                queue.task_done()
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                self.logger.error(f"Error in delivery loop for {subscription_id}: {e}")
                await asyncio.sleep(1)
    
    async def _store_event_redis(self, event: SecurityEvent) -> None:
        """Store event in Redis."""
        if not self._redis:
            return
        
        try:
            event_data = event.dict()
            await self._redis.hset(
                f"events:{event.event_id}",
                mapping={
                    "data": json.dumps(event_data),
                    "timestamp": event.timestamp.isoformat(),
                    "type": event.event_type
                }
            )
            
            # Set TTL if specified
            if event.ttl_seconds:
                await self._redis.expire(f"events:{event.event_id}", event.ttl_seconds)
            
            # Add to time-based index
            await self._redis.zadd(
                "events:timeline",
                {event.event_id: event.timestamp.timestamp()}
            )
            
        except Exception as e:
            self.logger.warning(f"Failed to store event in Redis: {e}")
    
    async def _cleanup_loop(self) -> None:
        """Background cleanup loop."""
        while self._running:
            try:
                await asyncio.sleep(self.cleanup_interval)
                
                # Clean up old events from timeline
                if self._redis:
                    cutoff = datetime.now() - timedelta(hours=24)
                    await self._redis.zremrangebyscore(
                        "events:timeline",
                        0,
                        cutoff.timestamp()
                    )
                
                # Clean up inactive subscriptions
                inactive_subs = [
                    sub_id for sub_id, sub in self._subscriptions.items()
                    if not sub.active
                ]
                
                for sub_id in inactive_subs:
                    await self.unsubscribe(sub_id)
                
            except Exception as e:
                self.logger.error(f"Error in cleanup loop: {e}")