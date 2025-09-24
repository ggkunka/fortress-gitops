"""Base classes for event bus infrastructure."""

import asyncio
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, Optional, List, Callable, Union
from uuid import UUID, uuid4
from dataclasses import dataclass, field

from pydantic import BaseModel, Field
import structlog

logger = structlog.get_logger()


class EventMessage(BaseModel):
    """Base event message model."""
    
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    event_type: str = Field(..., description="Type of the event")
    source_service: str = Field(..., description="Service that generated the event")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    correlation_id: Optional[str] = Field(None, description="Correlation ID for request tracing")
    data: Dict[str, Any] = Field(default_factory=dict, description="Event payload")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Event metadata")
    version: str = Field(default="1.0", description="Event schema version")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat(),
            UUID: str,
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event message to dictionary."""
        return self.model_dump()
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EventMessage":
        """Create event message from dictionary."""
        return cls(**data)


@dataclass
class EventHandler:
    """Event handler registration."""
    
    handler: Callable
    event_pattern: str
    service_name: str
    handler_id: str = field(default_factory=lambda: str(uuid4()))
    middleware: List[Any] = field(default_factory=list)
    options: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Post-initialization validation."""
        if not callable(self.handler):
            raise ValueError("Handler must be callable")
        if not self.event_pattern:
            raise ValueError("Event pattern is required")
        if not self.service_name:
            raise ValueError("Service name is required")


class EventBusBase(ABC):
    """Abstract base class for event bus implementations."""
    
    def __init__(self, service_name: str):
        self.service_name = service_name
        self.handlers: Dict[str, EventHandler] = {}
        self.middleware: List[Any] = []
        self.is_connected = False
        self.logger = logger.bind(service=service_name, component="event_bus")
    
    @abstractmethod
    async def connect(self) -> None:
        """Connect to the event bus."""
        pass
    
    @abstractmethod
    async def disconnect(self) -> None:
        """Disconnect from the event bus."""
        pass
    
    @abstractmethod
    async def publish(
        self,
        event_type: str,
        data: Dict[str, Any],
        correlation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Publish an event to the bus."""
        pass
    
    @abstractmethod
    async def subscribe(
        self,
        event_pattern: str,
        handler: Callable,
        options: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Subscribe to events matching a pattern."""
        pass
    
    @abstractmethod
    async def unsubscribe(self, handler_id: str) -> bool:
        """Unsubscribe from events."""
        pass
    
    @abstractmethod
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on the event bus."""
        pass
    
    def add_middleware(self, middleware: Any) -> None:
        """Add middleware to the event bus."""
        self.middleware.append(middleware)
        self.logger.info("Middleware added", middleware_type=type(middleware).__name__)
    
    def remove_middleware(self, middleware: Any) -> None:
        """Remove middleware from the event bus."""
        if middleware in self.middleware:
            self.middleware.remove(middleware)
            self.logger.info("Middleware removed", middleware_type=type(middleware).__name__)
    
    async def _apply_middleware(
        self,
        event: EventMessage,
        direction: str = "outbound"
    ) -> EventMessage:
        """Apply middleware to an event."""
        for middleware in self.middleware:
            if hasattr(middleware, f"process_{direction}"):
                method = getattr(middleware, f"process_{direction}")
                event = await method(event)
        return event
    
    async def _handle_event(
        self,
        handler: EventHandler,
        event: EventMessage,
    ) -> None:
        """Handle an incoming event."""
        try:
            # Apply inbound middleware
            processed_event = await self._apply_middleware(event, "inbound")
            
            # Call the handler
            if asyncio.iscoroutinefunction(handler.handler):
                await handler.handler(processed_event)
            else:
                handler.handler(processed_event)
            
            self.logger.info(
                "Event handled successfully",
                event_type=event.event_type,
                event_id=event.event_id,
                handler_id=handler.handler_id,
            )
        
        except Exception as e:
            self.logger.error(
                "Event handling failed",
                event_type=event.event_type,
                event_id=event.event_id,
                handler_id=handler.handler_id,
                error=str(e),
            )
            raise
    
    def _create_event_message(
        self,
        event_type: str,
        data: Dict[str, Any],
        correlation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> EventMessage:
        """Create an event message."""
        return EventMessage(
            event_type=event_type,
            source_service=self.service_name,
            data=data,
            correlation_id=correlation_id,
            metadata=metadata or {},
        )
    
    def get_handler(self, handler_id: str) -> Optional[EventHandler]:
        """Get a handler by ID."""
        return self.handlers.get(handler_id)
    
    def get_handlers_for_pattern(self, event_pattern: str) -> List[EventHandler]:
        """Get all handlers for a specific pattern."""
        return [
            handler for handler in self.handlers.values()
            if handler.event_pattern == event_pattern
        ]
    
    def list_handlers(self) -> List[EventHandler]:
        """List all registered handlers."""
        return list(self.handlers.values())
    
    def get_stats(self) -> Dict[str, Any]:
        """Get event bus statistics."""
        return {
            "service_name": self.service_name,
            "is_connected": self.is_connected,
            "handlers_count": len(self.handlers),
            "middleware_count": len(self.middleware),
            "timestamp": datetime.utcnow().isoformat(),
        }


class EventBusManager:
    """Manager for multiple event bus instances."""
    
    def __init__(self):
        self.buses: Dict[str, EventBusBase] = {}
        self.logger = logger.bind(component="event_bus_manager")
    
    def add_bus(self, name: str, bus: EventBusBase) -> None:
        """Add an event bus instance."""
        self.buses[name] = bus
        self.logger.info("Event bus added", name=name, bus_type=type(bus).__name__)
    
    def get_bus(self, name: str) -> Optional[EventBusBase]:
        """Get an event bus instance by name."""
        return self.buses.get(name)
    
    def remove_bus(self, name: str) -> bool:
        """Remove an event bus instance."""
        if name in self.buses:
            del self.buses[name]
            self.logger.info("Event bus removed", name=name)
            return True
        return False
    
    async def connect_all(self) -> None:
        """Connect all event buses."""
        for name, bus in self.buses.items():
            try:
                await bus.connect()
                self.logger.info("Event bus connected", name=name)
            except Exception as e:
                self.logger.error("Failed to connect event bus", name=name, error=str(e))
                raise
    
    async def disconnect_all(self) -> None:
        """Disconnect all event buses."""
        for name, bus in self.buses.items():
            try:
                await bus.disconnect()
                self.logger.info("Event bus disconnected", name=name)
            except Exception as e:
                self.logger.error("Failed to disconnect event bus", name=name, error=str(e))
    
    async def health_check_all(self) -> Dict[str, Any]:
        """Health check for all event buses."""
        results = {}
        for name, bus in self.buses.items():
            try:
                results[name] = await bus.health_check()
            except Exception as e:
                results[name] = {
                    "status": "unhealthy",
                    "error": str(e),
                    "timestamp": datetime.utcnow().isoformat(),
                }
        return results
    
    def get_stats(self) -> Dict[str, Any]:
        """Get statistics for all event buses."""
        return {
            "total_buses": len(self.buses),
            "buses": {name: bus.get_stats() for name, bus in self.buses.items()},
            "timestamp": datetime.utcnow().isoformat(),
        }