"""
Event Repository Service - EventStore-based event sourcing storage

This service provides comprehensive event sourcing capabilities using EventStore,
including immutable event storage, stream management, and temporal queries.
"""

import asyncio
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple
import uuid

try:
    from esdbclient import EventStoreDBClient, NewEvent, StreamState
    from esdbclient.exceptions import NotFound, WrongExpectedVersion
except ImportError:
    # Fallback for development without EventStore client
    EventStoreDBClient = None
    NewEvent = None
    StreamState = None
    NotFound = Exception
    WrongExpectedVersion = Exception

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced
from shared.config.settings import get_settings

from ..models.events import (
    Event, EventStream, EventMetadata, Snapshot, 
    EventType, AggregateType
)

logger = get_logger(__name__)
metrics = get_metrics()


class EventRepository:
    """
    EventStore-based repository for event sourcing.
    
    This repository provides:
    1. Immutable event storage
    2. Stream management and versioning
    3. Event querying and filtering
    4. Snapshot management
    5. Projection support
    6. Temporal queries and event replay
    """
    
    def __init__(self):
        self.client: Optional[EventStoreDBClient] = None
        self.settings = get_settings()
        
        # EventStore connection settings
        self.connection_string = getattr(
            self.settings, 'eventstore_connection_string', 
            'esdb://localhost:2113?tls=false'
        )
        self.username = getattr(self.settings, 'eventstore_username', 'admin')
        self.password = getattr(self.settings, 'eventstore_password', 'changeit')
        
        # Configuration
        self.default_batch_size = 1000
        self.max_append_size = 10000
        self.snapshot_prefix = "$snapshot-"
        self.metadata_prefix = "$metadata-"
        
        # Stream metadata storage (would use MongoDB in production)
        self.stream_metadata = {}
        
        logger.info("Event repository initialized")
    
    async def initialize(self):
        """Initialize repository with EventStore connection."""
        try:
            if EventStoreDBClient is None:
                logger.warning("EventStore client not available, using mock implementation")
                self.client = MockEventStoreClient()
            else:
                # Create EventStore client
                self.client = EventStoreDBClient(
                    uri=self.connection_string,
                    root_certificates=None,  # For development
                    username=self.username,
                    password=self.password
                )
            
            # Test connection
            await self._test_connection()
            
            logger.info("Event repository connected to EventStore")
            
        except Exception as e:
            logger.error(f"Failed to initialize event repository: {e}")
            raise
    
    async def close(self):
        """Close EventStore connection."""
        if self.client and hasattr(self.client, 'close'):
            self.client.close()
            logger.info("Event repository connection closed")
    
    @traced("event_repository_create_stream")
    async def create_stream(self, stream: EventStream) -> str:
        """Create a new event stream."""
        try:
            # Store stream metadata
            self.stream_metadata[stream.stream_name] = {
                "id": stream.id,
                "stream_name": stream.stream_name,
                "aggregate_type": stream.aggregate_type,
                "description": stream.description,
                "retention_days": stream.retention_days,
                "snapshot_frequency": stream.snapshot_frequency,
                "created_at": stream.created_at.isoformat(),
                "current_version": stream.current_version,
                "event_count": stream.event_count,
                "metadata": stream.metadata
            }
            
            logger.debug(f"Event stream created: {stream.id}")
            metrics.event_repository_streams_created.inc()
            
            return stream.id
            
        except Exception as e:
            logger.error(f"Error creating event stream: {e}")
            metrics.event_repository_errors.inc()
            raise
    
    @traced("event_repository_append_event")
    async def append_event(
        self, 
        event: Event, 
        expected_version: Optional[int] = None
    ) -> Tuple[str, int]:
        """Append an event to a stream."""
        try:
            # Convert event to EventStore format
            new_event = await self._event_to_eventstore_event(event)
            
            # Determine expected stream state
            if expected_version is None:
                expected_state = StreamState.ANY
            elif expected_version == -1:
                expected_state = StreamState.NO_STREAM
            else:
                expected_state = expected_version
            
            # Append to EventStore
            commit_position = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.client.append_to_stream(
                    stream_name=event.stream_name,
                    events=[new_event],
                    expected_version=expected_state
                )
            )
            
            # Update stream metadata
            await self._update_stream_version(event.stream_name, event.version)
            
            logger.debug(f"Event appended: {event.id} to stream {event.stream_name}")
            metrics.event_repository_events_appended.inc()
            
            return event.id, event.version
            
        except WrongExpectedVersion as e:
            logger.error(f"Wrong expected version for stream {event.stream_name}: {e}")
            raise ValueError(f"Concurrency conflict: expected version {expected_version}")
        except Exception as e:
            logger.error(f"Error appending event: {e}")
            metrics.event_repository_errors.inc()
            raise
    
    @traced("event_repository_append_events")
    async def append_events(
        self, 
        events: List[Event], 
        expected_version: Optional[int] = None
    ) -> Tuple[List[str], int]:
        """Append multiple events to a stream atomically."""
        try:
            if not events:
                return [], 0
            
            stream_name = events[0].stream_name
            
            # Ensure all events are for the same stream
            for event in events:
                if event.stream_name != stream_name:
                    raise ValueError("All events must belong to the same stream")
            
            # Convert events to EventStore format
            new_events = []
            for event in events:
                new_event = await self._event_to_eventstore_event(event)
                new_events.append(new_event)
            
            # Determine expected stream state
            if expected_version is None:
                expected_state = StreamState.ANY
            elif expected_version == -1:
                expected_state = StreamState.NO_STREAM
            else:
                expected_state = expected_version
            
            # Append to EventStore
            commit_position = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.client.append_to_stream(
                    stream_name=stream_name,
                    events=new_events,
                    expected_version=expected_state
                )
            )
            
            # Update stream metadata
            final_version = expected_version + len(events) if expected_version is not None else len(events)
            await self._update_stream_version(stream_name, final_version)
            
            event_ids = [event.id for event in events]
            
            logger.debug(f"Batch of {len(events)} events appended to stream {stream_name}")
            metrics.event_repository_events_appended.inc(len(events))
            
            return event_ids, final_version
            
        except WrongExpectedVersion as e:
            logger.error(f"Wrong expected version for stream {stream_name}: {e}")
            raise ValueError(f"Concurrency conflict: expected version {expected_version}")
        except Exception as e:
            logger.error(f"Error appending events: {e}")
            metrics.event_repository_errors.inc()
            raise
    
    @traced("event_repository_get_stream_events")
    async def get_stream_events(
        self,
        stream_name: str,
        from_version: int = 0,
        to_version: Optional[int] = None,
        limit: int = 1000,
        forward: bool = True
    ) -> List[Event]:
        """Get events from a stream."""
        try:
            # Read events from EventStore
            recorded_events = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: list(self.client.read_stream(
                    stream_name=stream_name,
                    stream_position=from_version,
                    backwards=not forward,
                    limit=limit
                ))
            )
            
            events = []
            for recorded_event in recorded_events:
                if to_version is not None and recorded_event.stream_position > to_version:
                    break
                
                event = await self._eventstore_event_to_event(recorded_event, stream_name)
                events.append(event)
            
            logger.debug(f"Retrieved {len(events)} events from stream {stream_name}")
            metrics.event_repository_events_read.inc(len(events))
            
            return events
            
        except NotFound:
            logger.warning(f"Stream not found: {stream_name}")
            return []
        except Exception as e:
            logger.error(f"Error getting stream events: {e}")
            metrics.event_repository_errors.inc()
            raise
    
    @traced("event_repository_query_events")
    async def query_events(
        self,
        stream_names: Optional[List[str]] = None,
        event_types: Optional[List[EventType]] = None,
        aggregate_ids: Optional[List[str]] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        from_version: Optional[int] = None,
        to_version: Optional[int] = None,
        limit: int = 1000,
        forward: bool = True
    ) -> List[Event]:
        """Query events across multiple streams with filters."""
        try:
            events = []
            
            if stream_names:
                # Query specific streams
                for stream_name in stream_names:
                    stream_events = await self.get_stream_events(
                        stream_name=stream_name,
                        from_version=from_version or 0,
                        to_version=to_version,
                        limit=limit,
                        forward=forward
                    )
                    events.extend(stream_events)
            else:
                # Query all events (this would be more efficient with EventStore subscriptions)
                for stream_name in self.stream_metadata.keys():
                    stream_events = await self.get_stream_events(
                        stream_name=stream_name,
                        from_version=from_version or 0,
                        to_version=to_version,
                        limit=limit // len(self.stream_metadata) if self.stream_metadata else limit,
                        forward=forward
                    )
                    events.extend(stream_events)
            
            # Apply filters
            filtered_events = []
            for event in events:
                # Filter by event type
                if event_types and event.event_type not in event_types:
                    continue
                
                # Filter by aggregate ID
                if aggregate_ids and event.aggregate_id not in aggregate_ids:
                    continue
                
                # Filter by time range
                if start_time and event.timestamp < start_time:
                    continue
                if end_time and event.timestamp > end_time:
                    continue
                
                filtered_events.append(event)
            
            # Sort and limit results
            if forward:
                filtered_events.sort(key=lambda e: e.timestamp)
            else:
                filtered_events.sort(key=lambda e: e.timestamp, reverse=True)
            
            result_events = filtered_events[:limit]
            
            logger.debug(f"Query returned {len(result_events)} events")
            metrics.event_repository_queries_executed.inc()
            
            return result_events
            
        except Exception as e:
            logger.error(f"Error querying events: {e}")
            metrics.event_repository_errors.inc()
            raise
    
    @traced("event_repository_get_stream")
    async def get_stream(self, stream_name: str) -> Optional[EventStream]:
        """Get stream metadata."""
        try:
            stream_data = self.stream_metadata.get(stream_name)
            if not stream_data:
                return None
            
            return EventStream(
                id=stream_data["id"],
                stream_name=stream_data["stream_name"],
                aggregate_type=AggregateType(stream_data["aggregate_type"]),
                description=stream_data.get("description"),
                retention_days=stream_data.get("retention_days"),
                snapshot_frequency=stream_data.get("snapshot_frequency", 100),
                created_at=datetime.fromisoformat(stream_data["created_at"]),
                current_version=stream_data.get("current_version", 0),
                event_count=stream_data.get("event_count", 0),
                metadata=stream_data.get("metadata", {})
            )
            
        except Exception as e:
            logger.error(f"Error getting stream: {e}")
            metrics.event_repository_errors.inc()
            raise
    
    @traced("event_repository_list_streams")
    async def list_streams(
        self,
        limit: int = 100,
        offset: int = 0,
        aggregate_type: Optional[AggregateType] = None
    ) -> List[EventStream]:
        """List event streams."""
        try:
            streams = []
            stream_items = list(self.stream_metadata.items())[offset:offset + limit]
            
            for stream_name, stream_data in stream_items:
                if aggregate_type and stream_data["aggregate_type"] != aggregate_type:
                    continue
                
                stream = EventStream(
                    id=stream_data["id"],
                    stream_name=stream_data["stream_name"],
                    aggregate_type=AggregateType(stream_data["aggregate_type"]),
                    description=stream_data.get("description"),
                    retention_days=stream_data.get("retention_days"),
                    snapshot_frequency=stream_data.get("snapshot_frequency", 100),
                    created_at=datetime.fromisoformat(stream_data["created_at"]),
                    current_version=stream_data.get("current_version", 0),
                    event_count=stream_data.get("event_count", 0),
                    metadata=stream_data.get("metadata", {})
                )
                streams.append(stream)
            
            return streams
            
        except Exception as e:
            logger.error(f"Error listing streams: {e}")
            metrics.event_repository_errors.inc()
            raise
    
    @traced("event_repository_count_streams")
    async def count_streams(self, aggregate_type: Optional[AggregateType] = None) -> int:
        """Count event streams."""
        try:
            if aggregate_type:
                count = sum(
                    1 for stream_data in self.stream_metadata.values()
                    if stream_data["aggregate_type"] == aggregate_type
                )
            else:
                count = len(self.stream_metadata)
            
            return count
            
        except Exception as e:
            logger.error(f"Error counting streams: {e}")
            metrics.event_repository_errors.inc()
            raise
    
    @traced("event_repository_create_snapshot")
    async def create_snapshot(self, snapshot: Snapshot) -> str:
        """Create a snapshot."""
        try:
            # Store snapshot as a special event
            snapshot_stream = f"{self.snapshot_prefix}{snapshot.stream_name}-{snapshot.aggregate_id}"
            
            snapshot_event = Event(
                stream_name=snapshot_stream,
                event_type=EventType.SNAPSHOT_CREATED,
                event_data=snapshot.snapshot_data,
                metadata={
                    "snapshot_id": snapshot.id,
                    "original_stream": snapshot.stream_name,
                    "aggregate_id": snapshot.aggregate_id,
                    "version": snapshot.version,
                    **snapshot.metadata
                },
                aggregate_id=snapshot.aggregate_id,
                timestamp=snapshot.created_at,
                version=0  # Snapshots start at version 0
            )
            
            await self.append_event(snapshot_event)
            
            logger.debug(f"Snapshot created: {snapshot.id}")
            metrics.event_repository_snapshots_created.inc()
            
            return snapshot.id
            
        except Exception as e:
            logger.error(f"Error creating snapshot: {e}")
            metrics.event_repository_errors.inc()
            raise
    
    @traced("event_repository_get_snapshot")
    async def get_snapshot(
        self,
        stream_name: str,
        aggregate_id: str,
        version: Optional[int] = None
    ) -> Optional[Snapshot]:
        """Get the latest snapshot for an aggregate."""
        try:
            snapshot_stream = f"{self.snapshot_prefix}{stream_name}-{aggregate_id}"
            
            # Get latest snapshot event
            snapshot_events = await self.get_stream_events(
                stream_name=snapshot_stream,
                limit=1,
                forward=False  # Get latest
            )
            
            if not snapshot_events:
                return None
            
            snapshot_event = snapshot_events[0]
            
            snapshot = Snapshot(
                id=snapshot_event.metadata.get("snapshot_id", str(uuid.uuid4())),
                stream_name=stream_name,
                aggregate_id=aggregate_id,
                version=snapshot_event.metadata.get("version", 0),
                snapshot_data=snapshot_event.event_data,
                metadata=snapshot_event.metadata,
                created_at=snapshot_event.timestamp
            )
            
            return snapshot
            
        except Exception as e:
            logger.error(f"Error getting snapshot: {e}")
            metrics.event_repository_errors.inc()
            raise
    
    @traced("event_repository_delete_stream")
    async def delete_stream(self, stream_name: str, hard_delete: bool = False) -> bool:
        """Delete an event stream."""
        try:
            if hard_delete:
                # Hard delete - would require EventStore admin operations
                logger.warning(f"Hard delete not implemented for stream: {stream_name}")
            else:
                # Soft delete - mark stream as deleted
                if stream_name in self.stream_metadata:
                    self.stream_metadata[stream_name]["deleted"] = True
                    self.stream_metadata[stream_name]["deleted_at"] = datetime.now(timezone.utc).isoformat()
            
            # Remove from memory (in production, would mark as deleted in database)
            if stream_name in self.stream_metadata:
                del self.stream_metadata[stream_name]
                
                logger.debug(f"Stream deleted: {stream_name}")
                metrics.event_repository_streams_deleted.inc()
                
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error deleting stream: {e}")
            metrics.event_repository_errors.inc()
            raise
    
    async def _test_connection(self):
        """Test EventStore connection."""
        try:
            # Simple connection test
            if hasattr(self.client, 'get_server_version'):
                version = self.client.get_server_version()
                logger.info(f"EventStore connection test passed, version: {version}")
            else:
                logger.info("EventStore connection test passed (mock)")
        except Exception as e:
            logger.error(f"EventStore connection test failed: {e}")
            raise
    
    async def _event_to_eventstore_event(self, event: Event):
        """Convert Event to EventStore NewEvent."""
        try:
            if NewEvent is None:
                return MockNewEvent(event)
            
            return NewEvent(
                type=event.event_type,
                data=json.dumps(event.event_data).encode('utf-8'),
                metadata=json.dumps({
                    "event_id": event.id,
                    "aggregate_id": event.aggregate_id,
                    "aggregate_type": event.aggregate_type,
                    "correlation_id": event.correlation_id,
                    "causation_id": event.causation_id,
                    "timestamp": event.timestamp.isoformat(),
                    **event.metadata
                }).encode('utf-8'),
                content_type="application/json"
            )
        except Exception as e:
            logger.error(f"Error converting event to EventStore format: {e}")
            raise
    
    async def _eventstore_event_to_event(self, recorded_event, stream_name: str) -> Event:
        """Convert EventStore recorded event to Event."""
        try:
            # Parse event data and metadata
            event_data = json.loads(recorded_event.data.decode('utf-8'))
            metadata = json.loads(recorded_event.metadata.decode('utf-8')) if recorded_event.metadata else {}
            
            return Event(
                id=metadata.get("event_id", str(uuid.uuid4())),
                stream_name=stream_name,
                event_type=EventType(recorded_event.type),
                event_data=event_data,
                metadata=metadata,
                aggregate_id=metadata.get("aggregate_id"),
                aggregate_type=AggregateType(metadata["aggregate_type"]) if metadata.get("aggregate_type") else None,
                correlation_id=metadata.get("correlation_id"),
                causation_id=metadata.get("causation_id"),
                timestamp=datetime.fromisoformat(metadata["timestamp"]) if metadata.get("timestamp") else datetime.now(timezone.utc),
                version=recorded_event.stream_position
            )
        except Exception as e:
            logger.error(f"Error converting EventStore event to Event: {e}")
            raise
    
    async def _update_stream_version(self, stream_name: str, version: int):
        """Update stream version in metadata."""
        if stream_name in self.stream_metadata:
            self.stream_metadata[stream_name]["current_version"] = version
            self.stream_metadata[stream_name]["event_count"] = version + 1
    
    def get_stats(self) -> Dict[str, Any]:
        """Get repository statistics."""
        return {
            "connection_status": "connected" if self.client else "disconnected",
            "connection_string": self.connection_string,
            "total_streams": len(self.stream_metadata),
            "default_batch_size": self.default_batch_size,
            "operations": [
                "create_stream", "append_event", "append_events",
                "get_stream_events", "query_events", "get_stream",
                "list_streams", "count_streams", "create_snapshot",
                "get_snapshot", "delete_stream"
            ]
        }


# Mock classes for development without EventStore
class MockEventStoreClient:
    """Mock EventStore client for development."""
    
    def __init__(self):
        self.streams = {}
    
    def append_to_stream(self, stream_name: str, events: List, expected_version):
        """Mock append to stream."""
        if stream_name not in self.streams:
            self.streams[stream_name] = []
        
        for event in events:
            self.streams[stream_name].append(event)
        
        return len(self.streams[stream_name])
    
    def read_stream(self, stream_name: str, stream_position: int = 0, backwards: bool = False, limit: int = 1000):
        """Mock read stream."""
        if stream_name not in self.streams:
            raise NotFound(f"Stream {stream_name} not found")
        
        events = self.streams[stream_name][stream_position:]
        
        if backwards:
            events = events[::-1]
        
        return events[:limit]
    
    def get_server_version(self):
        """Mock get server version."""
        return "mock-version"


class MockNewEvent:
    """Mock NewEvent for development."""
    
    def __init__(self, event: Event):
        self.type = event.event_type
        self.data = json.dumps(event.event_data).encode('utf-8')
        self.metadata = json.dumps(event.metadata).encode('utf-8')
        self.stream_position = event.version