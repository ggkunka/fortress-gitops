"""Event bus exceptions."""


class EventBusError(Exception):
    """Base exception for event bus errors."""
    pass


class EventPublishError(EventBusError):
    """Exception raised when event publishing fails."""
    pass


class EventSubscribeError(EventBusError):
    """Exception raised when event subscription fails."""
    pass


class EventSerializationError(EventBusError):
    """Exception raised when event serialization fails."""
    pass


class EventDeserializationError(EventBusError):
    """Exception raised when event deserialization fails."""
    pass


class EventValidationError(EventBusError):
    """Exception raised when event validation fails."""
    pass


class EventHandlerError(EventBusError):
    """Exception raised when event handling fails."""
    pass


class EventMiddlewareError(EventBusError):
    """Exception raised when middleware processing fails."""
    pass