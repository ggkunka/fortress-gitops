"""Event serializers for different formats."""

import json
from abc import ABC, abstractmethod
from typing import Any, Dict, Union
from datetime import datetime

from pydantic import ValidationError

from .base import EventMessage
from .exceptions import EventSerializationError, EventDeserializationError


class EventSerializer(ABC):
    """Abstract base class for event serializers."""
    
    @abstractmethod
    def serialize(self, event: EventMessage) -> Union[str, bytes]:
        """Serialize an event message."""
        pass
    
    @abstractmethod
    def deserialize(self, data: Union[str, bytes]) -> EventMessage:
        """Deserialize an event message."""
        pass


class JSONEventSerializer(EventSerializer):
    """JSON event serializer."""
    
    def __init__(self, indent: int = None):
        self.indent = indent
    
    def serialize(self, event: EventMessage) -> str:
        """Serialize an event message to JSON."""
        try:
            # Convert event to dict
            event_dict = event.to_dict()
            
            # Handle datetime serialization
            event_dict = self._serialize_datetime(event_dict)
            
            # Serialize to JSON
            return json.dumps(event_dict, indent=self.indent, ensure_ascii=False)
        
        except Exception as e:
            raise EventSerializationError(f"Failed to serialize event: {str(e)}")
    
    def deserialize(self, data: Union[str, bytes]) -> EventMessage:
        """Deserialize an event message from JSON."""
        try:
            # Parse JSON
            if isinstance(data, bytes):
                data = data.decode('utf-8')
            
            event_dict = json.loads(data)
            
            # Handle datetime deserialization
            event_dict = self._deserialize_datetime(event_dict)
            
            # Create event message
            return EventMessage.from_dict(event_dict)
        
        except json.JSONDecodeError as e:
            raise EventDeserializationError(f"Invalid JSON format: {str(e)}")
        except ValidationError as e:
            raise EventDeserializationError(f"Event validation failed: {str(e)}")
        except Exception as e:
            raise EventDeserializationError(f"Failed to deserialize event: {str(e)}")
    
    def _serialize_datetime(self, obj: Any) -> Any:
        """Recursively serialize datetime objects."""
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, dict):
            return {key: self._serialize_datetime(value) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [self._serialize_datetime(item) for item in obj]
        else:
            return obj
    
    def _deserialize_datetime(self, obj: Any) -> Any:
        """Recursively deserialize datetime objects."""
        if isinstance(obj, str):
            # Try to parse as ISO datetime
            try:
                return datetime.fromisoformat(obj.replace('Z', '+00:00'))
            except ValueError:
                return obj
        elif isinstance(obj, dict):
            # Special handling for timestamp field
            if 'timestamp' in obj and isinstance(obj['timestamp'], str):
                try:
                    obj['timestamp'] = datetime.fromisoformat(obj['timestamp'].replace('Z', '+00:00'))
                except ValueError:
                    pass
            return {key: self._deserialize_datetime(value) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [self._deserialize_datetime(item) for item in obj]
        else:
            return obj


class CompactJSONEventSerializer(JSONEventSerializer):
    """Compact JSON event serializer without indentation."""
    
    def __init__(self):
        super().__init__(indent=None)


class PrettyJSONEventSerializer(JSONEventSerializer):
    """Pretty JSON event serializer with indentation."""
    
    def __init__(self, indent: int = 2):
        super().__init__(indent=indent)


class BinaryEventSerializer(EventSerializer):
    """Binary event serializer using JSON with UTF-8 encoding."""
    
    def __init__(self):
        self.json_serializer = JSONEventSerializer()
    
    def serialize(self, event: EventMessage) -> bytes:
        """Serialize an event message to binary."""
        try:
            json_str = self.json_serializer.serialize(event)
            return json_str.encode('utf-8')
        except Exception as e:
            raise EventSerializationError(f"Failed to serialize event to binary: {str(e)}")
    
    def deserialize(self, data: Union[str, bytes]) -> EventMessage:
        """Deserialize an event message from binary."""
        try:
            if isinstance(data, bytes):
                data = data.decode('utf-8')
            return self.json_serializer.deserialize(data)
        except Exception as e:
            raise EventDeserializationError(f"Failed to deserialize event from binary: {str(e)}")


class MessagePackEventSerializer(EventSerializer):
    """MessagePack event serializer for efficient binary serialization."""
    
    def __init__(self):
        try:
            import msgpack
            self.msgpack = msgpack
        except ImportError:
            raise ImportError("msgpack is required for MessagePackEventSerializer")
    
    def serialize(self, event: EventMessage) -> bytes:
        """Serialize an event message to MessagePack."""
        try:
            event_dict = event.to_dict()
            event_dict = self._serialize_datetime(event_dict)
            return self.msgpack.packb(event_dict, use_bin_type=True)
        except Exception as e:
            raise EventSerializationError(f"Failed to serialize event to MessagePack: {str(e)}")
    
    def deserialize(self, data: bytes) -> EventMessage:
        """Deserialize an event message from MessagePack."""
        try:
            event_dict = self.msgpack.unpackb(data, raw=False)
            event_dict = self._deserialize_datetime(event_dict)
            return EventMessage.from_dict(event_dict)
        except Exception as e:
            raise EventDeserializationError(f"Failed to deserialize event from MessagePack: {str(e)}")
    
    def _serialize_datetime(self, obj: Any) -> Any:
        """Recursively serialize datetime objects."""
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, dict):
            return {key: self._serialize_datetime(value) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [self._serialize_datetime(item) for item in obj]
        else:
            return obj
    
    def _deserialize_datetime(self, obj: Any) -> Any:
        """Recursively deserialize datetime objects."""
        if isinstance(obj, str):
            try:
                return datetime.fromisoformat(obj.replace('Z', '+00:00'))
            except ValueError:
                return obj
        elif isinstance(obj, dict):
            if 'timestamp' in obj and isinstance(obj['timestamp'], str):
                try:
                    obj['timestamp'] = datetime.fromisoformat(obj['timestamp'].replace('Z', '+00:00'))
                except ValueError:
                    pass
            return {key: self._deserialize_datetime(value) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [self._deserialize_datetime(item) for item in obj]
        else:
            return obj


class ProtobufEventSerializer(EventSerializer):
    """Protocol Buffers event serializer for efficient binary serialization."""
    
    def __init__(self):
        try:
            import google.protobuf
            self.protobuf = google.protobuf
        except ImportError:
            raise ImportError("protobuf is required for ProtobufEventSerializer")
    
    def serialize(self, event: EventMessage) -> bytes:
        """Serialize an event message to Protocol Buffers."""
        # This would require generating protobuf definitions
        # For now, fall back to JSON serialization
        raise NotImplementedError("ProtobufEventSerializer requires protobuf definitions")
    
    def deserialize(self, data: bytes) -> EventMessage:
        """Deserialize an event message from Protocol Buffers."""
        # This would require generating protobuf definitions
        # For now, fall back to JSON deserialization
        raise NotImplementedError("ProtobufEventSerializer requires protobuf definitions")


def get_serializer(serializer_type: str = "json") -> EventSerializer:
    """Get an event serializer by type."""
    serializers = {
        "json": JSONEventSerializer,
        "compact_json": CompactJSONEventSerializer,
        "pretty_json": PrettyJSONEventSerializer,
        "binary": BinaryEventSerializer,
        "messagepack": MessagePackEventSerializer,
        "protobuf": ProtobufEventSerializer,
    }
    
    serializer_class = serializers.get(serializer_type)
    if not serializer_class:
        raise ValueError(f"Unknown serializer type: {serializer_type}")
    
    return serializer_class()