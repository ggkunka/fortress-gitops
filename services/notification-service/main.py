"""Main application for the notification service."""

import asyncio
import signal
import sys
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Dict, Any, List
import json

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr
import uvicorn
import structlog

logger = structlog.get_logger()

# In-memory storage for POC
notifications_db = []
notification_channels = {
    "email": {"enabled": True, "endpoint": "smtp://localhost:587"},
    "slack": {"enabled": True, "webhook": "https://hooks.slack.com/services/..."},
    "webhook": {"enabled": True, "endpoints": []},
    "sms": {"enabled": False, "provider": "twilio"}
}

class NotificationRequest(BaseModel):
    title: str
    message: str
    severity: str = "info"  # info, warning, error, critical
    channels: List[str] = ["email"]
    recipients: List[str] = []
    metadata: Dict[str, Any] = {}

class NotificationResponse(BaseModel):
    id: str
    title: str
    message: str
    severity: str
    status: str
    created_at: datetime
    sent_at: datetime = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    try:
        logger.info("Starting notification service")
        yield
    except Exception as e:
        logger.error("Failed to start notification service", error=str(e))
        raise
    finally:
        logger.info("Shutting down notification service")

app = FastAPI(
    title="MCP Security Platform - Notification Service",
    description="Multi-channel notification service for alerts and events",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

async def send_notification_async(notification_id: str, notification: NotificationRequest):
    """Send notification asynchronously."""
    try:
        # Simulate sending notification
        await asyncio.sleep(1)
        
        # Update notification status
        for notif in notifications_db:
            if notif["id"] == notification_id:
                notif["status"] = "sent"
                notif["sent_at"] = datetime.utcnow()
                break
        
        logger.info("Notification sent successfully", 
                   notification_id=notification_id,
                   channels=notification.channels,
                   severity=notification.severity)
                   
    except Exception as e:
        logger.error("Failed to send notification", 
                    notification_id=notification_id, 
                    error=str(e))
        
        for notif in notifications_db:
            if notif["id"] == notification_id:
                notif["status"] = "failed"
                notif["error"] = str(e)
                break

@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "service": "notification",
        "version": "1.0.0",
        "status": "running",
        "description": "Multi-channel notification service",
        "timestamp": datetime.utcnow().isoformat()
    }

@app.post("/api/v1/notifications", response_model=NotificationResponse)
async def send_notification(
    notification: NotificationRequest,
    background_tasks: BackgroundTasks
):
    """Send notification via specified channels."""
    try:
        notification_id = f"notif-{int(datetime.utcnow().timestamp())}"
        
        # Store notification
        notification_data = {
            "id": notification_id,
            "title": notification.title,
            "message": notification.message,
            "severity": notification.severity,
            "channels": notification.channels,
            "recipients": notification.recipients,
            "status": "pending",
            "created_at": datetime.utcnow(),
            "sent_at": None,
            "metadata": notification.metadata
        }
        
        notifications_db.append(notification_data)
        
        # Send notification asynchronously
        background_tasks.add_task(send_notification_async, notification_id, notification)
        
        return NotificationResponse(
            id=notification_id,
            title=notification.title,
            message=notification.message,
            severity=notification.severity,
            status="pending",
            created_at=notification_data["created_at"]
        )
        
    except Exception as e:
        logger.error("Failed to create notification", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/notifications")
async def list_notifications(limit: int = 50, offset: int = 0):
    """List notifications."""
    total = len(notifications_db)
    notifications = notifications_db[offset:offset + limit]
    
    return {
        "notifications": notifications,
        "total": total,
        "limit": limit,
        "offset": offset
    }

@app.get("/api/v1/notifications/{notification_id}")
async def get_notification(notification_id: str):
    """Get specific notification."""
    for notification in notifications_db:
        if notification["id"] == notification_id:
            return notification
    
    raise HTTPException(status_code=404, detail="Notification not found")

@app.get("/api/v1/channels")
async def get_notification_channels():
    """Get available notification channels."""
    return {"channels": notification_channels}

@app.post("/api/v1/channels/{channel_name}/test")
async def test_notification_channel(channel_name: str):
    """Test notification channel."""
    if channel_name not in notification_channels:
        raise HTTPException(status_code=404, detail="Channel not found")
    
    # Simulate channel test
    test_result = {
        "channel": channel_name,
        "status": "success" if notification_channels[channel_name]["enabled"] else "disabled",
        "message": f"Test notification sent via {channel_name}",
        "timestamp": datetime.utcnow().isoformat()
    }
    
    return test_result

@app.get("/api/v1/stats")
async def get_notification_stats():
    """Get notification statistics."""
    stats = {
        "total_notifications": len(notifications_db),
        "pending": len([n for n in notifications_db if n["status"] == "pending"]),
        "sent": len([n for n in notifications_db if n["status"] == "sent"]),
        "failed": len([n for n in notifications_db if n["status"] == "failed"]),
        "by_severity": {
            "critical": len([n for n in notifications_db if n["severity"] == "critical"]),
            "error": len([n for n in notifications_db if n["severity"] == "error"]),
            "warning": len([n for n in notifications_db if n["severity"] == "warning"]),
            "info": len([n for n in notifications_db if n["severity"] == "info"])
        }
    }
    
    return stats

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "notification",
        "version": "1.0.0",
        "channels": len(notification_channels),
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/health/live")
async def liveness_probe():
    return {"status": "alive"}

@app.get("/health/ready")
async def readiness_probe():
    return {"status": "ready"}

@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint."""
    return {
        "service": "notification",
        "notifications_total": len(notifications_db),
        "channels_enabled": len([c for c in notification_channels.values() if c["enabled"]]),
        "timestamp": datetime.utcnow().isoformat()
    }

def main():
    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}, shutting down gracefully...")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    logger.info("Starting notification service", port=8084)
    
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8084,
        workers=1,
        log_level="info",
        reload=False,
        access_log=True,
    )

if __name__ == "__main__":
    main()
