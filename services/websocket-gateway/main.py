#!/usr/bin/env python3
"""
WebSocket Gateway Service for MCP Security Platform
Provides real-time communication for live dashboards and notifications
"""

import asyncio
import json
import logging
from typing import Dict, Set, List, Any
from datetime import datetime

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import redis.asyncio as redis
import httpx
from prometheus_client import Counter, Histogram, Gauge, generate_latest
from prometheus_fastapi_instrumentator import Instrumentator

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Metrics
websocket_connections = Gauge('websocket_connections_active', 'Active WebSocket connections')
websocket_messages = Counter('websocket_messages_total', 'Total WebSocket messages', ['message_type'])
notification_events = Counter('notification_events_total', 'Total notification events', ['event_type'])

class ConnectionManager:
    """Manages WebSocket connections and message broadcasting"""
    
    def __init__(self):
        self.active_connections: Dict[str, Set[WebSocket]] = {
            "notifications": set(),
            "dashboard": set(),
            "scans": set(),
            "logs": set()
        }
        self.user_connections: Dict[WebSocket, str] = {}
    
    async def connect(self, websocket: WebSocket, channel: str, user_id: str = None):
        """Accept new WebSocket connection"""
        await websocket.accept()
        
        if channel not in self.active_connections:
            self.active_connections[channel] = set()
        
        self.active_connections[channel].add(websocket)
        self.user_connections[websocket] = user_id or "anonymous"
        
        websocket_connections.inc()
        logger.info(f"New connection to {channel} channel. Total: {len(self.active_connections[channel])}")
        
        # Send welcome message
        await self.send_personal_message({
            "type": "connection",
            "message": f"Connected to {channel} channel",
            "timestamp": datetime.now().isoformat(),
            "channel": channel
        }, websocket)
    
    def disconnect(self, websocket: WebSocket):
        """Remove WebSocket connection"""
        websocket_connections.dec()
        
        # Remove from all channels
        for channel, connections in self.active_connections.items():
            if websocket in connections:
                connections.remove(websocket)
                logger.info(f"Connection removed from {channel}. Remaining: {len(connections)}")
        
        # Remove from user connections
        if websocket in self.user_connections:
            del self.user_connections[websocket]
    
    async def send_personal_message(self, message: dict, websocket: WebSocket):
        """Send message to specific connection"""
        try:
            await websocket.send_text(json.dumps(message))
            websocket_messages.labels(message_type=message.get("type", "unknown")).inc()
        except Exception as e:
            logger.error(f"Error sending personal message: {e}")
    
    async def broadcast_to_channel(self, message: dict, channel: str):
        """Broadcast message to all connections in a channel"""
        if channel not in self.active_connections:
            return
        
        disconnected = set()
        
        for connection in self.active_connections[channel]:
            try:
                await connection.send_text(json.dumps(message))
                websocket_messages.labels(message_type=message.get("type", "unknown")).inc()
            except Exception as e:
                logger.error(f"Error broadcasting to connection: {e}")
                disconnected.add(connection)
        
        # Remove disconnected connections
        for connection in disconnected:
            self.active_connections[channel].discard(connection)
    
    async def broadcast_notification(self, notification: dict):
        """Broadcast security notification to all notification subscribers"""
        notification_events.labels(event_type=notification.get("severity", "unknown")).inc()
        
        message = {
            "type": "security_notification",
            "data": notification,
            "timestamp": datetime.now().isoformat()
        }
        
        await self.broadcast_to_channel(message, "notifications")
    
    async def broadcast_dashboard_update(self, metrics: dict):
        """Broadcast dashboard metrics update"""
        message = {
            "type": "dashboard_update",
            "data": metrics,
            "timestamp": datetime.now().isoformat()
        }
        
        await self.broadcast_to_channel(message, "dashboard")
    
    async def broadcast_scan_update(self, scan_data: dict):
        """Broadcast scan progress update"""
        message = {
            "type": "scan_update",
            "data": scan_data,
            "timestamp": datetime.now().isoformat()
        }
        
        await self.broadcast_to_channel(message, "scans")
    
    async def broadcast_log_entry(self, log_entry: dict):
        """Broadcast new log entry"""
        message = {
            "type": "log_entry",
            "data": log_entry,
            "timestamp": datetime.now().isoformat()
        }
        
        await self.broadcast_to_channel(message, "logs")

# Global connection manager
manager = ConnectionManager()

# FastAPI app
app = FastAPI(
    title="MCP Security Platform - WebSocket Gateway",
    description="Real-time communication gateway for live updates",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add Prometheus metrics
instrumentator = Instrumentator()
instrumentator.instrument(app).expose(app)

# Redis connection for pub/sub
redis_client = None

async def init_redis():
    """Initialize Redis connection for pub/sub"""
    global redis_client
    try:
        redis_client = redis.from_url("redis://redis-master:6379/0")
        await redis_client.ping()
        logger.info("Connected to Redis for pub/sub")
    except Exception as e:
        logger.error(f"Failed to connect to Redis: {e}")

async def redis_subscriber():
    """Subscribe to Redis channels for real-time events"""
    if not redis_client:
        return
    
    try:
        pubsub = redis_client.pubsub()
        await pubsub.subscribe("mcp:notifications", "mcp:scans", "mcp:metrics", "mcp:logs")
        
        logger.info("Subscribed to Redis channels")
        
        async for message in pubsub.listen():
            if message["type"] == "message":
                try:
                    data = json.loads(message["data"])
                    channel = message["channel"].decode()
                    
                    if channel == "mcp:notifications":
                        await manager.broadcast_notification(data)
                    elif channel == "mcp:scans":
                        await manager.broadcast_scan_update(data)
                    elif channel == "mcp:metrics":
                        await manager.broadcast_dashboard_update(data)
                    elif channel == "mcp:logs":
                        await manager.broadcast_log_entry(data)
                        
                except Exception as e:
                    logger.error(f"Error processing Redis message: {e}")
                    
    except Exception as e:
        logger.error(f"Redis subscriber error: {e}")

@app.on_event("startup")
async def startup_event():
    """Initialize connections on startup"""
    await init_redis()
    # Start Redis subscriber in background
    asyncio.create_task(redis_subscriber())

@app.websocket("/ws/notifications")
async def websocket_notifications(websocket: WebSocket, user_id: str = None):
    """WebSocket endpoint for security notifications"""
    await manager.connect(websocket, "notifications", user_id)
    try:
        while True:
            # Keep connection alive and handle incoming messages
            data = await websocket.receive_text()
            message = json.loads(data)
            
            # Handle client messages (e.g., subscription preferences)
            if message.get("type") == "subscribe":
                await manager.send_personal_message({
                    "type": "subscription_confirmed",
                    "filters": message.get("filters", {}),
                    "timestamp": datetime.now().isoformat()
                }, websocket)
                
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket)

@app.websocket("/ws/dashboard")
async def websocket_dashboard(websocket: WebSocket, user_id: str = None):
    """WebSocket endpoint for live dashboard updates"""
    await manager.connect(websocket, "dashboard", user_id)
    try:
        # Send initial dashboard data
        initial_metrics = await get_current_metrics()
        await manager.send_personal_message({
            "type": "initial_data",
            "data": initial_metrics,
            "timestamp": datetime.now().isoformat()
        }, websocket)
        
        while True:
            data = await websocket.receive_text()
            # Handle dashboard-specific messages
            
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"Dashboard WebSocket error: {e}")
        manager.disconnect(websocket)

@app.websocket("/ws/scans")
async def websocket_scans(websocket: WebSocket, user_id: str = None):
    """WebSocket endpoint for scan progress updates"""
    await manager.connect(websocket, "scans", user_id)
    try:
        # Send current active scans
        active_scans = await get_active_scans()
        await manager.send_personal_message({
            "type": "active_scans",
            "data": active_scans,
            "timestamp": datetime.now().isoformat()
        }, websocket)
        
        while True:
            data = await websocket.receive_text()
            # Handle scan-specific messages
            
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"Scans WebSocket error: {e}")
        manager.disconnect(websocket)

@app.websocket("/ws/logs")
async def websocket_logs(websocket: WebSocket, user_id: str = None):
    """WebSocket endpoint for real-time log streaming"""
    await manager.connect(websocket, "logs", user_id)
    try:
        while True:
            data = await websocket.receive_text()
            message = json.loads(data)
            
            # Handle log filtering requests
            if message.get("type") == "filter":
                await manager.send_personal_message({
                    "type": "filter_applied",
                    "filters": message.get("filters", {}),
                    "timestamp": datetime.now().isoformat()
                }, websocket)
                
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"Logs WebSocket error: {e}")
        manager.disconnect(websocket)

# HTTP endpoints for triggering broadcasts
@app.post("/api/v1/broadcast/notification")
async def broadcast_notification(notification: dict):
    """HTTP endpoint to broadcast security notification"""
    await manager.broadcast_notification(notification)
    return {"status": "broadcasted", "type": "notification"}

@app.post("/api/v1/broadcast/metrics")
async def broadcast_metrics(metrics: dict):
    """HTTP endpoint to broadcast dashboard metrics"""
    await manager.broadcast_dashboard_update(metrics)
    return {"status": "broadcasted", "type": "metrics"}

@app.get("/api/v1/connections")
async def get_connection_stats():
    """Get WebSocket connection statistics"""
    stats = {}
    for channel, connections in manager.active_connections.items():
        stats[channel] = len(connections)
    
    return {
        "total_connections": sum(stats.values()),
        "channels": stats,
        "timestamp": datetime.now().isoformat()
    }

async def get_current_metrics():
    """Fetch current security metrics"""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "http://vulnerability-analyzer:8083/api/v1/vulnerabilities/summary",
                timeout=10.0
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": "Failed to fetch metrics"}
    except Exception as e:
        logger.error(f"Error fetching metrics: {e}")
        return {"error": str(e)}

async def get_active_scans():
    """Fetch currently active scans"""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "http://scanner-manager:8082/api/v1/scans?status=running",
                timeout=10.0
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                return {"scans": []}
    except Exception as e:
        logger.error(f"Error fetching active scans: {e}")
        return {"scans": []}

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "websocket-gateway",
        "timestamp": datetime.now().isoformat(),
        "active_connections": sum(len(conns) for conns in manager.active_connections.values()),
        "version": "1.0.0"
    }

@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint"""
    return generate_latest()

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8088,
        log_level="info",
        reload=False
    )
