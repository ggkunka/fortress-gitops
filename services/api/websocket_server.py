"""
WebSocket Real-Time Communication Server

This service provides real-time bidirectional communication for the MCP Security Platform
including live updates, notifications, and interactive features.
"""

import asyncio
import json
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Set, Callable, Union
from enum import Enum
import websockets
from websockets.server import WebSocketServerProtocol
from websockets.exceptions import ConnectionClosed, InvalidMessage
from dataclasses import dataclass, field
import jwt
from urllib.parse import parse_qs

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced
from shared.events.event_bus import EventBus

logger = get_logger(__name__)
metrics = get_metrics()


class MessageType(str, Enum):
    """WebSocket message types."""
    # Connection management
    CONNECTION_INIT = "connection_init"
    CONNECTION_ACK = "connection_ack"
    CONNECTION_ERROR = "connection_error"
    CONNECTION_TERMINATE = "connection_terminate"
    
    # Subscription management
    SUBSCRIBE = "subscribe"
    UNSUBSCRIBE = "unsubscribe"
    SUBSCRIPTION_DATA = "subscription_data"
    SUBSCRIPTION_ERROR = "subscription_error"
    SUBSCRIPTION_COMPLETE = "subscription_complete"
    
    # Real-time events
    SCAN_UPDATE = "scan_update"
    VULNERABILITY_ALERT = "vulnerability_alert"
    SECURITY_EVENT = "security_event"
    COMPLIANCE_UPDATE = "compliance_update"
    SYSTEM_STATUS = "system_status"
    
    # Interactive features
    COMMAND = "command"
    COMMAND_RESULT = "command_result"
    HEARTBEAT = "heartbeat"
    PONG = "pong"


class SubscriptionType(str, Enum):
    """Subscription types."""
    SCAN_UPDATES = "scan_updates"
    VULNERABILITY_ALERTS = "vulnerability_alerts"
    SECURITY_EVENTS = "security_events"
    COMPLIANCE_UPDATES = "compliance_updates"
    SYSTEM_STATUS = "system_status"
    ALL_EVENTS = "all_events"


@dataclass
class WebSocketMessage:
    """WebSocket message structure."""
    id: str
    type: MessageType
    payload: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "type": self.type.value,
            "payload": self.payload,
            "timestamp": self.timestamp.isoformat()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "WebSocketMessage":
        """Create from dictionary."""
        return cls(
            id=data["id"],
            type=MessageType(data["type"]),
            payload=data.get("payload", {}),
            timestamp=datetime.fromisoformat(data.get("timestamp", datetime.now(timezone.utc).isoformat()))
        )


@dataclass
class ClientConnection:
    """WebSocket client connection information."""
    connection_id: str
    websocket: WebSocketServerProtocol
    user_id: Optional[str] = None
    roles: List[str] = field(default_factory=list)
    subscriptions: Set[str] = field(default_factory=set)
    filters: Dict[str, Any] = field(default_factory=dict)
    last_heartbeat: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    connected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Subscription:
    """Client subscription information."""
    subscription_id: str
    connection_id: str
    subscription_type: SubscriptionType
    filters: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class WebSocketServer:
    """
    WebSocket real-time communication server.
    
    Features:
    - Real-time event streaming
    - Client subscription management
    - Authentication and authorization
    - Message filtering and routing
    - Connection pooling and management
    - Heartbeat and reconnection handling
    - Rate limiting and throttling
    - Broadcasting and multicasting
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        
        # Server configuration
        self.host = self.config.get("host", "localhost")
        self.port = self.config.get("port", 8765)
        self.max_connections = self.config.get("max_connections", 1000)
        self.heartbeat_interval = self.config.get("heartbeat_interval", 30)
        self.connection_timeout = self.config.get("connection_timeout", 300)
        
        # Connection management
        self.connections: Dict[str, ClientConnection] = {}
        self.subscriptions: Dict[str, Subscription] = {}
        self.subscription_handlers: Dict[SubscriptionType, Callable] = {}
        self.command_handlers: Dict[str, Callable] = {}
        
        # Event bus for external events
        self.event_bus: Optional[EventBus] = None
        
        # Rate limiting
        self.rate_limits: Dict[str, List[datetime]] = {}
        self.max_messages_per_minute = self.config.get("max_messages_per_minute", 100)
        
        # Authentication
        self.jwt_secret = self.config.get("jwt_secret", "default_secret")
        self.require_auth = self.config.get("require_auth", True)
        
        # Server instance
        self.server = None
        self._running = False
        
        # Initialize handlers
        self._initialize_handlers()
        
        logger.info("WebSocket Server initialized")
    
    async def initialize(self) -> bool:
        """Initialize the WebSocket server."""
        try:
            # Initialize event bus
            self.event_bus = EventBus()
            await self.event_bus.initialize()
            
            # Subscribe to external events
            await self._subscribe_to_external_events()
            
            # Start heartbeat task
            asyncio.create_task(self._heartbeat_task())
            
            # Start cleanup task
            asyncio.create_task(self._cleanup_task())
            
            logger.info("WebSocket Server initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize WebSocket Server: {e}")
            return False
    
    async def start(self) -> bool:
        """Start the WebSocket server."""
        try:
            self.server = await websockets.serve(
                self._handle_connection,
                self.host,
                self.port,
                max_size=1024 * 1024,  # 1MB max message size
                max_queue=100,
                ping_interval=self.heartbeat_interval,
                ping_timeout=10
            )
            
            self._running = True
            logger.info(f"WebSocket Server started on ws://{self.host}:{self.port}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start WebSocket Server: {e}")
            return False
    
    async def stop(self) -> bool:
        """Stop the WebSocket server."""
        try:
            self._running = False
            
            if self.server:
                self.server.close()
                await self.server.wait_closed()
            
            # Close all connections
            for connection in list(self.connections.values()):
                try:
                    await connection.websocket.close()
                except Exception:
                    pass
            
            self.connections.clear()
            self.subscriptions.clear()
            
            logger.info("WebSocket Server stopped")
            return True
            
        except Exception as e:
            logger.error(f"Failed to stop WebSocket Server: {e}")
            return False
    
    async def cleanup(self) -> bool:
        """Cleanup WebSocket server."""
        try:
            await self.stop()
            
            if self.event_bus:
                await self.event_bus.cleanup()
            
            logger.info("WebSocket Server cleaned up successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to cleanup WebSocket Server: {e}")
            return False
    
    @traced("websocket_handle_connection")
    async def _handle_connection(self, websocket: WebSocketServerProtocol, path: str):
        """Handle new WebSocket connection."""
        connection_id = str(uuid.uuid4())
        
        try:
            # Check connection limit
            if len(self.connections) >= self.max_connections:
                await websocket.close(code=1013, reason="Server overloaded")
                return
            
            # Parse query parameters for authentication
            query_params = parse_qs(websocket.query) if websocket.query else {}
            
            # Create connection
            connection = ClientConnection(
                connection_id=connection_id,
                websocket=websocket,
                metadata={"remote_address": websocket.remote_address}
            )
            
            # Authenticate connection if required
            if self.require_auth:
                auth_success = await self._authenticate_connection(connection, query_params)
                if not auth_success:
                    await websocket.close(code=1008, reason="Authentication failed")
                    return
            
            # Register connection
            self.connections[connection_id] = connection
            
            # Send connection acknowledgment
            await self._send_message(connection, WebSocketMessage(
                id=str(uuid.uuid4()),
                type=MessageType.CONNECTION_ACK,
                payload={"connection_id": connection_id}
            ))
            
            logger.info(f"WebSocket connection established: {connection_id}")
            metrics.websocket_connections_active.inc()
            
            # Handle messages
            async for raw_message in websocket:
                await self._handle_message(connection, raw_message)
                
        except ConnectionClosed:
            logger.debug(f"WebSocket connection closed: {connection_id}")
        except Exception as e:
            logger.error(f"WebSocket connection error: {e}")
        finally:
            # Cleanup connection
            await self._cleanup_connection(connection_id)
    
    async def _handle_message(self, connection: ClientConnection, raw_message: str):
        """Handle incoming WebSocket message."""
        try:
            # Parse message
            try:
                message_data = json.loads(raw_message)
                message = WebSocketMessage.from_dict(message_data)
            except (json.JSONDecodeError, KeyError, ValueError) as e:
                await self._send_error(connection, "Invalid message format", str(e))
                return
            
            # Rate limiting
            if not await self._check_rate_limit(connection.connection_id):
                await self._send_error(connection, "Rate limit exceeded")
                return
            
            # Update heartbeat
            connection.last_heartbeat = datetime.now(timezone.utc)
            
            # Route message based on type
            if message.type == MessageType.SUBSCRIBE:
                await self._handle_subscribe(connection, message)
            elif message.type == MessageType.UNSUBSCRIBE:
                await self._handle_unsubscribe(connection, message)
            elif message.type == MessageType.COMMAND:
                await self._handle_command(connection, message)
            elif message.type == MessageType.HEARTBEAT:
                await self._handle_heartbeat(connection, message)
            elif message.type == MessageType.CONNECTION_TERMINATE:
                await connection.websocket.close()
            else:
                await self._send_error(connection, "Unknown message type", message.type.value)
            
            metrics.websocket_messages_received.inc()
            
        except Exception as e:
            logger.error(f"Failed to handle WebSocket message: {e}")
            await self._send_error(connection, "Message processing failed", str(e))
    
    async def _handle_subscribe(self, connection: ClientConnection, message: WebSocketMessage):
        """Handle subscription request."""
        try:
            subscription_type = SubscriptionType(message.payload.get("type"))
            filters = message.payload.get("filters", {})
            
            # Create subscription
            subscription_id = str(uuid.uuid4())
            subscription = Subscription(
                subscription_id=subscription_id,
                connection_id=connection.connection_id,
                subscription_type=subscription_type,
                filters=filters
            )
            
            # Register subscription
            self.subscriptions[subscription_id] = subscription
            connection.subscriptions.add(subscription_id)
            
            # Send confirmation
            await self._send_message(connection, WebSocketMessage(
                id=str(uuid.uuid4()),
                type=MessageType.SUBSCRIPTION_DATA,
                payload={
                    "subscription_id": subscription_id,
                    "status": "subscribed",
                    "type": subscription_type.value
                }
            ))
            
            logger.debug(f"Client {connection.connection_id} subscribed to {subscription_type.value}")
            metrics.websocket_subscriptions.inc()
            
        except (ValueError, KeyError) as e:
            await self._send_error(connection, "Invalid subscription", str(e))
    
    async def _handle_unsubscribe(self, connection: ClientConnection, message: WebSocketMessage):
        """Handle unsubscription request."""
        try:
            subscription_id = message.payload.get("subscription_id")
            
            if subscription_id in self.subscriptions:
                # Remove subscription
                del self.subscriptions[subscription_id]
                connection.subscriptions.discard(subscription_id)
                
                # Send confirmation
                await self._send_message(connection, WebSocketMessage(
                    id=str(uuid.uuid4()),
                    type=MessageType.SUBSCRIPTION_COMPLETE,
                    payload={"subscription_id": subscription_id}
                ))
                
                logger.debug(f"Client {connection.connection_id} unsubscribed from {subscription_id}")
                metrics.websocket_subscriptions.dec()
            else:
                await self._send_error(connection, "Subscription not found", subscription_id)
                
        except KeyError as e:
            await self._send_error(connection, "Invalid unsubscription", str(e))
    
    async def _handle_command(self, connection: ClientConnection, message: WebSocketMessage):
        """Handle command execution request."""
        try:
            command = message.payload.get("command")
            args = message.payload.get("args", {})
            
            # Check authorization
            if not await self._authorize_command(connection, command):
                await self._send_error(connection, "Command not authorized", command)
                return
            
            # Execute command
            if command in self.command_handlers:
                result = await self.command_handlers[command](connection, args)
                
                # Send result
                await self._send_message(connection, WebSocketMessage(
                    id=str(uuid.uuid4()),
                    type=MessageType.COMMAND_RESULT,
                    payload={
                        "command": command,
                        "result": result,
                        "request_id": message.id
                    }
                ))
            else:
                await self._send_error(connection, "Unknown command", command)
            
        except Exception as e:
            await self._send_error(connection, "Command execution failed", str(e))
    
    async def _handle_heartbeat(self, connection: ClientConnection, message: WebSocketMessage):
        """Handle heartbeat message."""
        await self._send_message(connection, WebSocketMessage(
            id=str(uuid.uuid4()),
            type=MessageType.PONG,
            payload={"timestamp": datetime.now(timezone.utc).isoformat()}
        ))
    
    async def _send_message(self, connection: ClientConnection, message: WebSocketMessage):
        """Send message to client."""
        try:
            await connection.websocket.send(json.dumps(message.to_dict()))
            metrics.websocket_messages_sent.inc()
        except ConnectionClosed:
            logger.debug(f"Connection closed while sending message: {connection.connection_id}")
        except Exception as e:
            logger.error(f"Failed to send WebSocket message: {e}")
    
    async def _send_error(self, connection: ClientConnection, error: str, details: str = ""):
        """Send error message to client."""
        await self._send_message(connection, WebSocketMessage(
            id=str(uuid.uuid4()),
            type=MessageType.CONNECTION_ERROR,
            payload={"error": error, "details": details}
        ))
    
    async def _authenticate_connection(self, connection: ClientConnection, query_params: Dict[str, List[str]]) -> bool:
        """Authenticate WebSocket connection."""
        try:
            # Get token from query parameters
            tokens = query_params.get("token", [])
            if not tokens:
                return False
            
            token = tokens[0]
            
            # Verify JWT token
            payload = jwt.decode(token, self.jwt_secret, algorithms=["HS256"])
            
            # Set user information
            connection.user_id = payload.get("user_id")
            connection.roles = payload.get("roles", [])
            
            logger.debug(f"Authenticated user {connection.user_id} for connection {connection.connection_id}")
            return True
            
        except jwt.InvalidTokenError:
            logger.warning("Invalid JWT token for WebSocket connection")
            return False
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return False
    
    async def _authorize_command(self, connection: ClientConnection, command: str) -> bool:
        """Authorize command execution."""
        # Simple role-based authorization
        admin_commands = ["system_shutdown", "reset_database", "manage_users"]
        
        if command in admin_commands:
            return "admin" in connection.roles
        
        return True  # Allow other commands
    
    async def _check_rate_limit(self, connection_id: str) -> bool:
        """Check rate limiting for connection."""
        now = datetime.now(timezone.utc)
        
        # Initialize if not exists
        if connection_id not in self.rate_limits:
            self.rate_limits[connection_id] = []
        
        # Clean old entries
        cutoff = now.timestamp() - 60  # 1 minute
        self.rate_limits[connection_id] = [
            ts for ts in self.rate_limits[connection_id] 
            if ts.timestamp() > cutoff
        ]
        
        # Check limit
        if len(self.rate_limits[connection_id]) >= self.max_messages_per_minute:
            return False
        
        # Add current timestamp
        self.rate_limits[connection_id].append(now)
        return True
    
    async def _cleanup_connection(self, connection_id: str):
        """Cleanup connection and subscriptions."""
        if connection_id in self.connections:
            connection = self.connections[connection_id]
            
            # Remove subscriptions
            for subscription_id in list(connection.subscriptions):
                if subscription_id in self.subscriptions:
                    del self.subscriptions[subscription_id]
            
            # Remove connection
            del self.connections[connection_id]
            
            # Clean rate limits
            if connection_id in self.rate_limits:
                del self.rate_limits[connection_id]
            
            metrics.websocket_connections_active.dec()
            logger.debug(f"Cleaned up connection: {connection_id}")
    
    async def _heartbeat_task(self):
        """Background task for connection heartbeat monitoring."""
        while self._running:
            try:
                now = datetime.now(timezone.utc)
                timeout_threshold = now.timestamp() - self.connection_timeout
                
                # Find timed out connections
                timed_out = []
                for connection_id, connection in self.connections.items():
                    if connection.last_heartbeat.timestamp() < timeout_threshold:
                        timed_out.append(connection_id)
                
                # Close timed out connections
                for connection_id in timed_out:
                    try:
                        connection = self.connections[connection_id]
                        await connection.websocket.close(code=1001, reason="Connection timeout")
                    except Exception:
                        pass
                
                await asyncio.sleep(self.heartbeat_interval)
                
            except Exception as e:
                logger.error(f"Heartbeat task error: {e}")
                await asyncio.sleep(self.heartbeat_interval)
    
    async def _cleanup_task(self):
        """Background task for periodic cleanup."""
        while self._running:
            try:
                # Clean up old rate limit entries
                now = datetime.now(timezone.utc)
                cutoff = now.timestamp() - 3600  # 1 hour
                
                for connection_id in list(self.rate_limits.keys()):
                    if connection_id not in self.connections:
                        del self.rate_limits[connection_id]
                    else:
                        self.rate_limits[connection_id] = [
                            ts for ts in self.rate_limits[connection_id]
                            if ts.timestamp() > cutoff
                        ]
                
                await asyncio.sleep(300)  # 5 minutes
                
            except Exception as e:
                logger.error(f"Cleanup task error: {e}")
                await asyncio.sleep(300)
    
    async def _subscribe_to_external_events(self):
        """Subscribe to external events from event bus."""
        if self.event_bus:
            # Subscribe to scan events
            await self.event_bus.subscribe("scan.*", self._handle_scan_event)
            
            # Subscribe to vulnerability events
            await self.event_bus.subscribe("vulnerability.*", self._handle_vulnerability_event)
            
            # Subscribe to security events
            await self.event_bus.subscribe("security.*", self._handle_security_event)
            
            # Subscribe to compliance events
            await self.event_bus.subscribe("compliance.*", self._handle_compliance_event)
            
            # Subscribe to system events
            await self.event_bus.subscribe("system.*", self._handle_system_event)
    
    async def _handle_scan_event(self, event_data: Dict[str, Any]):
        """Handle scan-related events."""
        await self._broadcast_to_subscribers(
            SubscriptionType.SCAN_UPDATES,
            MessageType.SCAN_UPDATE,
            event_data
        )
    
    async def _handle_vulnerability_event(self, event_data: Dict[str, Any]):
        """Handle vulnerability-related events."""
        await self._broadcast_to_subscribers(
            SubscriptionType.VULNERABILITY_ALERTS,
            MessageType.VULNERABILITY_ALERT,
            event_data
        )
    
    async def _handle_security_event(self, event_data: Dict[str, Any]):
        """Handle security events."""
        await self._broadcast_to_subscribers(
            SubscriptionType.SECURITY_EVENTS,
            MessageType.SECURITY_EVENT,
            event_data
        )
    
    async def _handle_compliance_event(self, event_data: Dict[str, Any]):
        """Handle compliance-related events."""
        await self._broadcast_to_subscribers(
            SubscriptionType.COMPLIANCE_UPDATES,
            MessageType.COMPLIANCE_UPDATE,
            event_data
        )
    
    async def _handle_system_event(self, event_data: Dict[str, Any]):
        """Handle system status events."""
        await self._broadcast_to_subscribers(
            SubscriptionType.SYSTEM_STATUS,
            MessageType.SYSTEM_STATUS,
            event_data
        )
    
    async def _broadcast_to_subscribers(
        self,
        subscription_type: SubscriptionType,
        message_type: MessageType,
        payload: Dict[str, Any]
    ):
        """Broadcast message to all subscribers of a specific type."""
        message = WebSocketMessage(
            id=str(uuid.uuid4()),
            type=message_type,
            payload=payload
        )
        
        # Find matching subscriptions
        matching_subscriptions = [
            sub for sub in self.subscriptions.values()
            if sub.subscription_type in [subscription_type, SubscriptionType.ALL_EVENTS]
            and self._match_filters(payload, sub.filters)
        ]
        
        # Send to subscribers
        for subscription in matching_subscriptions:
            if subscription.connection_id in self.connections:
                connection = self.connections[subscription.connection_id]
                await self._send_message(connection, message)
    
    def _match_filters(self, payload: Dict[str, Any], filters: Dict[str, Any]) -> bool:
        """Check if payload matches subscription filters."""
        if not filters:
            return True
        
        for key, value in filters.items():
            if key not in payload:
                return False
            
            if isinstance(value, list):
                if payload[key] not in value:
                    return False
            else:
                if payload[key] != value:
                    return False
        
        return True
    
    def _initialize_handlers(self):
        """Initialize command handlers."""
        self.command_handlers = {
            "get_status": self._command_get_status,
            "get_connections": self._command_get_connections,
            "get_subscriptions": self._command_get_subscriptions,
            "trigger_scan": self._command_trigger_scan,
            "get_metrics": self._command_get_metrics
        }
    
    async def _command_get_status(self, connection: ClientConnection, args: Dict[str, Any]) -> Dict[str, Any]:
        """Get server status."""
        return {
            "server_status": "running",
            "active_connections": len(self.connections),
            "total_subscriptions": len(self.subscriptions),
            "uptime": (datetime.now(timezone.utc) - connection.connected_at).total_seconds()
        }
    
    async def _command_get_connections(self, connection: ClientConnection, args: Dict[str, Any]) -> Dict[str, Any]:
        """Get connection information (admin only)."""
        if "admin" not in connection.roles:
            raise PermissionError("Admin access required")
        
        return {
            "connections": [
                {
                    "id": conn.connection_id,
                    "user_id": conn.user_id,
                    "connected_at": conn.connected_at.isoformat(),
                    "subscriptions_count": len(conn.subscriptions)
                }
                for conn in self.connections.values()
            ]
        }
    
    async def _command_get_subscriptions(self, connection: ClientConnection, args: Dict[str, Any]) -> Dict[str, Any]:
        """Get user's subscriptions."""
        user_subscriptions = [
            {
                "id": sub.subscription_id,
                "type": sub.subscription_type.value,
                "filters": sub.filters,
                "created_at": sub.created_at.isoformat()
            }
            for sub in self.subscriptions.values()
            if sub.connection_id == connection.connection_id
        ]
        
        return {"subscriptions": user_subscriptions}
    
    async def _command_trigger_scan(self, connection: ClientConnection, args: Dict[str, Any]) -> Dict[str, Any]:
        """Trigger a security scan."""
        # This would integrate with the scan service
        return {"message": "Scan triggered", "scan_id": str(uuid.uuid4())}
    
    async def _command_get_metrics(self, connection: ClientConnection, args: Dict[str, Any]) -> Dict[str, Any]:
        """Get real-time metrics."""
        return {
            "active_connections": len(self.connections),
            "total_subscriptions": len(self.subscriptions),
            "messages_per_minute": sum(
                len([ts for ts in timestamps if (datetime.now(timezone.utc) - ts).total_seconds() < 60])
                for timestamps in self.rate_limits.values()
            )
        }
    
    async def broadcast_message(self, message_type: MessageType, payload: Dict[str, Any]):
        """Broadcast message to all connected clients."""
        message = WebSocketMessage(
            id=str(uuid.uuid4()),
            type=message_type,
            payload=payload
        )
        
        for connection in self.connections.values():
            await self._send_message(connection, message)
    
    def get_connection_stats(self) -> Dict[str, Any]:
        """Get connection statistics."""
        return {
            "total_connections": len(self.connections),
            "total_subscriptions": len(self.subscriptions),
            "subscription_breakdown": {
                sub_type.value: len([
                    sub for sub in self.subscriptions.values()
                    if sub.subscription_type == sub_type
                ])
                for sub_type in SubscriptionType
            }
        }