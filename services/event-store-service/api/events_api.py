"""
Events API - REST endpoints for event sourcing operations

This service provides comprehensive event sourcing capabilities using EventStore
for immutable event logging, replay, and temporal queries.
"""

import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from uuid import UUID
import json

from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel, Field
from fastapi.responses import JSONResponse, StreamingResponse

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced
from shared.security.sanitization import sanitize_input

from ..models.events import (
    Event, EventStream, EventMetadata, Snapshot, ProjectionState,
    EventType, AggregateType, create_event, create_event_stream
)
from ..services.event_repository import EventRepository
from ..services.event_processor import EventProcessor
from ..services.projection_manager import ProjectionManager

logger = get_logger(__name__)
metrics = get_metrics()

router = APIRouter()

# Global instances (would be injected in real implementation)
event_repository = None
event_processor = None
projection_manager = None


class AppendEventRequest(BaseModel):
    """Request model for appending events to a stream."""
    stream_name: str = Field(..., min_length=1, max_length=255)
    event_type: EventType = Field(...)
    event_data: Dict[str, Any] = Field(...)
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)
    aggregate_id: Optional[str] = Field(None, max_length=255)
    aggregate_type: Optional[AggregateType] = None
    expected_version: Optional[int] = Field(None, ge=-1)
    correlation_id: Optional[str] = Field(None, max_length=255)
    causation_id: Optional[str] = Field(None, max_length=255)


class AppendMultipleEventsRequest(BaseModel):
    """Request model for appending multiple events to a stream."""
    stream_name: str = Field(..., min_length=1, max_length=255)
    events: List[Dict[str, Any]] = Field(..., min_items=1, max_items=1000)
    expected_version: Optional[int] = Field(None, ge=-1)


class CreateStreamRequest(BaseModel):
    """Request model for creating event streams."""
    stream_name: str = Field(..., min_length=1, max_length=255)
    aggregate_type: AggregateType = Field(...)
    description: Optional[str] = Field(None, max_length=500)
    retention_days: Optional[int] = Field(None, ge=1, le=3650)
    snapshot_frequency: int = Field(default=100, ge=1, le=10000)
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)


class CreateSnapshotRequest(BaseModel):
    """Request model for creating snapshots."""
    stream_name: str = Field(..., min_length=1, max_length=255)
    aggregate_id: str = Field(..., min_length=1, max_length=255)
    snapshot_data: Dict[str, Any] = Field(...)
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)


class QueryEventsRequest(BaseModel):
    """Request model for querying events."""
    stream_names: Optional[List[str]] = Field(default_factory=list)
    event_types: Optional[List[EventType]] = Field(default_factory=list)
    aggregate_ids: Optional[List[str]] = Field(default_factory=list)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    from_version: Optional[int] = Field(None, ge=0)
    to_version: Optional[int] = Field(None, ge=0)
    limit: int = Field(1000, ge=1, le=10000)
    forward: bool = Field(default=True)


def get_event_repository() -> EventRepository:
    """Get event repository instance."""
    global event_repository
    if event_repository is None:
        raise RuntimeError("Event repository not initialized")
    return event_repository


def get_event_processor() -> EventProcessor:
    """Get event processor instance."""
    global event_processor
    if event_processor is None:
        raise RuntimeError("Event processor not initialized")
    return event_processor


def get_projection_manager() -> ProjectionManager:
    """Get projection manager instance."""
    global projection_manager
    if projection_manager is None:
        raise RuntimeError("Projection manager not initialized")
    return projection_manager


@router.post("/streams", response_model=Dict[str, Any])
@traced("events_api_create_stream")
async def create_stream(
    request: CreateStreamRequest,
    repository: EventRepository = Depends(get_event_repository)
):
    """Create a new event stream."""
    try:
        # Sanitize inputs
        stream_name = sanitize_input(request.stream_name, max_length=255)
        
        # Check if stream already exists
        existing_stream = await repository.get_stream(stream_name)
        if existing_stream:
            raise HTTPException(
                status_code=409, 
                detail="Event stream already exists"
            )
        
        # Create event stream
        stream = create_event_stream(
            stream_name=stream_name,
            aggregate_type=request.aggregate_type,
            description=request.description,
            retention_days=request.retention_days,
            snapshot_frequency=request.snapshot_frequency,
            metadata=request.metadata or {}
        )
        
        # Store stream
        stream_id = await repository.create_stream(stream)
        
        logger.info(f"Event stream created: {stream_id}")
        metrics.events_api_streams_created.inc()
        
        return {
            "message": "Event stream created successfully",
            "stream_id": stream_id,
            "stream_name": stream_name,
            "aggregate_type": request.aggregate_type,
            "timestamp": stream.created_at.isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating event stream: {e}")
        metrics.events_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/streams/{stream_name}/events", response_model=Dict[str, Any])
@traced("events_api_append_event")
async def append_event(
    stream_name: str,
    request: AppendEventRequest,
    background_tasks: BackgroundTasks,
    repository: EventRepository = Depends(get_event_repository),
    processor: EventProcessor = Depends(get_event_processor)
):
    """Append an event to a stream."""
    try:
        # Sanitize inputs
        stream_name = sanitize_input(stream_name, max_length=255)
        
        # Verify stream exists
        stream = await repository.get_stream(stream_name)
        if not stream:
            raise HTTPException(status_code=404, detail="Event stream not found")
        
        # Create event
        event = create_event(
            stream_name=stream_name,
            event_type=request.event_type,
            event_data=request.event_data,
            metadata=request.metadata or {},
            aggregate_id=request.aggregate_id,
            aggregate_type=request.aggregate_type,
            correlation_id=request.correlation_id,
            causation_id=request.causation_id
        )
        
        # Append event
        event_id, version = await repository.append_event(
            event, 
            expected_version=request.expected_version
        )
        
        # Process event asynchronously
        background_tasks.add_task(processor.process_event, event)
        
        logger.info(f"Event appended: {event_id} to stream {stream_name}")
        metrics.events_api_events_appended.inc()
        
        return {
            "message": "Event appended successfully",
            "event_id": event_id,
            "stream_name": stream_name,
            "event_type": request.event_type,
            "version": version,
            "timestamp": event.timestamp.isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error appending event: {e}")
        metrics.events_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/streams/{stream_name}/events/batch", response_model=Dict[str, Any])
@traced("events_api_append_multiple_events")
async def append_multiple_events(
    stream_name: str,
    request: AppendMultipleEventsRequest,
    background_tasks: BackgroundTasks,
    repository: EventRepository = Depends(get_event_repository),
    processor: EventProcessor = Depends(get_event_processor)
):
    """Append multiple events to a stream atomically."""
    try:
        # Sanitize inputs
        stream_name = sanitize_input(stream_name, max_length=255)
        
        # Verify stream exists
        stream = await repository.get_stream(stream_name)
        if not stream:
            raise HTTPException(status_code=404, detail="Event stream not found")
        
        # Create events
        events = []
        for event_data in request.events:
            event = create_event(
                stream_name=stream_name,
                event_type=EventType(event_data["event_type"]),
                event_data=event_data["event_data"],
                metadata=event_data.get("metadata", {}),
                aggregate_id=event_data.get("aggregate_id"),
                aggregate_type=AggregateType(event_data["aggregate_type"]) if event_data.get("aggregate_type") else None,
                correlation_id=event_data.get("correlation_id"),
                causation_id=event_data.get("causation_id")
            )
            events.append(event)
        
        # Append events atomically
        event_ids, final_version = await repository.append_events(
            events, 
            expected_version=request.expected_version
        )
        
        # Process events asynchronously
        for event in events:
            background_tasks.add_task(processor.process_event, event)
        
        logger.info(f"Batch of {len(events)} events appended to stream {stream_name}")
        metrics.events_api_events_appended.inc(len(events))
        
        return {
            "message": "Events appended successfully",
            "event_ids": event_ids,
            "stream_name": stream_name,
            "events_count": len(events),
            "final_version": final_version,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error appending multiple events: {e}")
        metrics.events_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/streams/{stream_name}/events", response_model=Dict[str, Any])
@traced("events_api_get_stream_events")
async def get_stream_events(
    stream_name: str,
    from_version: int = Query(0, ge=0),
    to_version: Optional[int] = Query(None, ge=0),
    limit: int = Query(1000, ge=1, le=10000),
    forward: bool = Query(True),
    repository: EventRepository = Depends(get_event_repository)
):
    """Get events from a stream."""
    try:
        # Sanitize inputs
        stream_name = sanitize_input(stream_name, max_length=255)
        
        # Get events
        events = await repository.get_stream_events(
            stream_name=stream_name,
            from_version=from_version,
            to_version=to_version,
            limit=limit,
            forward=forward
        )
        
        # Get stream info
        stream = await repository.get_stream(stream_name)
        if not stream:
            raise HTTPException(status_code=404, detail="Event stream not found")
        
        return {
            "stream_name": stream_name,
            "events": [event.dict() for event in events],
            "events_count": len(events),
            "from_version": from_version,
            "to_version": to_version,
            "limit": limit,
            "forward": forward,
            "stream_version": stream.current_version,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting stream events: {e}")
        metrics.events_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/events/query", response_model=Dict[str, Any])
@traced("events_api_query_events")
async def query_events(
    request: QueryEventsRequest,
    repository: EventRepository = Depends(get_event_repository)
):
    """Query events across multiple streams with filters."""
    try:
        events = await repository.query_events(
            stream_names=request.stream_names,
            event_types=request.event_types,
            aggregate_ids=request.aggregate_ids,
            start_time=request.start_time,
            end_time=request.end_time,
            from_version=request.from_version,
            to_version=request.to_version,
            limit=request.limit,
            forward=request.forward
        )
        
        return {
            "events": [event.dict() for event in events],
            "events_count": len(events),
            "query_parameters": request.dict(),
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error querying events: {e}")
        metrics.events_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/streams/{stream_name}/events/stream", response_class=StreamingResponse)
@traced("events_api_stream_events")
async def stream_events(
    stream_name: str,
    from_version: int = Query(0, ge=0),
    live: bool = Query(False, description="Continue streaming new events"),
    repository: EventRepository = Depends(get_event_repository)
):
    """Stream events from a stream in real-time."""
    try:
        # Sanitize inputs
        stream_name = sanitize_input(stream_name, max_length=255)
        
        async def event_generator():
            current_version = from_version
            
            while True:
                # Get next batch of events
                events = await repository.get_stream_events(
                    stream_name=stream_name,
                    from_version=current_version,
                    limit=100,
                    forward=True
                )
                
                for event in events:
                    yield f"data: {json.dumps(event.dict())}\n\n"
                    current_version = event.version + 1
                
                if not live or not events:
                    break
                
                # Wait for new events
                await asyncio.sleep(1)
        
        return StreamingResponse(
            event_generator(),
            media_type="text/plain",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive"
            }
        )
        
    except Exception as e:
        logger.error(f"Error streaming events: {e}")
        metrics.events_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/streams/{stream_name}/snapshots", response_model=Dict[str, Any])
@traced("events_api_create_snapshot")
async def create_snapshot(
    stream_name: str,
    request: CreateSnapshotRequest,
    repository: EventRepository = Depends(get_event_repository)
):
    """Create a snapshot for an aggregate."""
    try:
        # Sanitize inputs
        stream_name = sanitize_input(stream_name, max_length=255)
        aggregate_id = sanitize_input(request.aggregate_id, max_length=255)
        
        # Get stream
        stream = await repository.get_stream(stream_name)
        if not stream:
            raise HTTPException(status_code=404, detail="Event stream not found")
        
        # Create snapshot
        snapshot = Snapshot(
            stream_name=stream_name,
            aggregate_id=aggregate_id,
            version=stream.current_version,
            snapshot_data=request.snapshot_data,
            metadata=request.metadata or {}
        )
        
        # Store snapshot
        snapshot_id = await repository.create_snapshot(snapshot)
        
        logger.info(f"Snapshot created: {snapshot_id}")
        metrics.events_api_snapshots_created.inc()
        
        return {
            "message": "Snapshot created successfully",
            "snapshot_id": snapshot_id,
            "stream_name": stream_name,
            "aggregate_id": aggregate_id,
            "version": snapshot.version,
            "timestamp": snapshot.created_at.isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating snapshot: {e}")
        metrics.events_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/streams/{stream_name}/snapshots/{aggregate_id}", response_model=Dict[str, Any])
@traced("events_api_get_snapshot")
async def get_snapshot(
    stream_name: str,
    aggregate_id: str,
    version: Optional[int] = Query(None, description="Snapshot version, latest if not specified"),
    repository: EventRepository = Depends(get_event_repository)
):
    """Get the latest snapshot for an aggregate."""
    try:
        # Sanitize inputs
        stream_name = sanitize_input(stream_name, max_length=255)
        aggregate_id = sanitize_input(aggregate_id, max_length=255)
        
        # Get snapshot
        snapshot = await repository.get_snapshot(
            stream_name=stream_name,
            aggregate_id=aggregate_id,
            version=version
        )
        
        if not snapshot:
            raise HTTPException(status_code=404, detail="Snapshot not found")
        
        return snapshot.dict()
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting snapshot: {e}")
        metrics.events_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/streams", response_model=Dict[str, Any])
@traced("events_api_list_streams")
async def list_streams(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    aggregate_type: Optional[AggregateType] = Query(None),
    repository: EventRepository = Depends(get_event_repository)
):
    """List event streams."""
    try:
        streams = await repository.list_streams(
            limit=limit,
            offset=offset,
            aggregate_type=aggregate_type
        )
        
        total_count = await repository.count_streams(aggregate_type=aggregate_type)
        
        return {
            "streams": [stream.dict() for stream in streams],
            "total_count": total_count,
            "limit": limit,
            "offset": offset,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error listing streams: {e}")
        metrics.events_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/streams/{stream_name}", response_model=Dict[str, Any])
@traced("events_api_get_stream")
async def get_stream(
    stream_name: str,
    repository: EventRepository = Depends(get_event_repository)
):
    """Get stream information."""
    try:
        # Sanitize inputs
        stream_name = sanitize_input(stream_name, max_length=255)
        
        stream = await repository.get_stream(stream_name)
        if not stream:
            raise HTTPException(status_code=404, detail="Event stream not found")
        
        return stream.dict()
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting stream: {e}")
        metrics.events_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/projections", response_model=Dict[str, Any])
@traced("events_api_list_projections")
async def list_projections(
    projection_manager: ProjectionManager = Depends(get_projection_manager)
):
    """List all projections and their status."""
    try:
        projections = await projection_manager.list_projections()
        
        return {
            "projections": [proj.dict() for proj in projections],
            "total_count": len(projections),
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error listing projections: {e}")
        metrics.events_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/projections/{projection_name}/rebuild", response_model=Dict[str, Any])
@traced("events_api_rebuild_projection")
async def rebuild_projection(
    projection_name: str,
    background_tasks: BackgroundTasks,
    from_version: int = Query(0, ge=0),
    projection_manager: ProjectionManager = Depends(get_projection_manager)
):
    """Rebuild a projection from events."""
    try:
        # Sanitize inputs
        projection_name = sanitize_input(projection_name, max_length=255)
        
        # Start rebuild asynchronously
        background_tasks.add_task(
            projection_manager.rebuild_projection,
            projection_name,
            from_version
        )
        
        logger.info(f"Projection rebuild started: {projection_name}")
        
        return {
            "message": "Projection rebuild started",
            "projection_name": projection_name,
            "from_version": from_version,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error rebuilding projection: {e}")
        metrics.events_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/statistics", response_model=Dict[str, Any])
@traced("events_api_get_statistics")
async def get_statistics(
    repository: EventRepository = Depends(get_event_repository),
    processor: EventProcessor = Depends(get_event_processor),
    projection_manager: ProjectionManager = Depends(get_projection_manager)
):
    """Get comprehensive event store statistics."""
    try:
        repository_stats = repository.get_stats()
        processor_stats = processor.get_stats()
        projection_stats = projection_manager.get_stats()
        
        return {
            "service": "event-store-service",
            "repository": repository_stats,
            "processor": processor_stats,
            "projections": projection_stats,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        metrics.events_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.delete("/streams/{stream_name}", response_model=Dict[str, Any])
@traced("events_api_delete_stream")
async def delete_stream(
    stream_name: str,
    hard_delete: bool = Query(False, description="Permanently delete stream data"),
    repository: EventRepository = Depends(get_event_repository)
):
    """Delete an event stream."""
    try:
        # Sanitize inputs
        stream_name = sanitize_input(stream_name, max_length=255)
        
        success = await repository.delete_stream(stream_name, hard_delete=hard_delete)
        
        if not success:
            raise HTTPException(status_code=404, detail="Event stream not found")
        
        logger.info(f"Event stream deleted: {stream_name}")
        
        return {
            "message": "Event stream deleted successfully",
            "stream_name": stream_name,
            "hard_delete": hard_delete,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting stream: {e}")
        metrics.events_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")