"""
Notifier plugin interface for alert notifications and incident response.
"""

from abc import abstractmethod
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from .base import BasePlugin, PluginMetadata, PluginType


class NotificationType(str, Enum):
    """Types of notifications."""
    ALERT = "alert"
    INCIDENT = "incident"
    REPORT = "report"
    STATUS_UPDATE = "status_update"
    ESCALATION = "escalation"
    RESOLUTION = "resolution"


class Priority(str, Enum):
    """Notification priority levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class NotificationChannel(str, Enum):
    """Notification delivery channels."""
    EMAIL = "email"
    SLACK = "slack"
    TEAMS = "teams"
    WEBHOOK = "webhook"
    SMS = "sms"
    PAGERDUTY = "pagerduty"
    JIRA = "jira"
    DISCORD = "discord"
    TELEGRAM = "telegram"


class NotificationResult(BaseModel):
    """Result of notification delivery."""
    
    # Identification
    notification_id: str = Field(..., description="Unique notification identifier")
    channel: NotificationChannel = Field(..., description="Delivery channel used")
    
    # Status
    success: bool = Field(..., description="Whether notification was delivered successfully")
    status_code: Optional[int] = Field(None, description="HTTP status code or equivalent")
    status_message: str = Field("", description="Status message")
    
    # Delivery information
    delivered_at: Optional[datetime] = Field(None, description="Delivery timestamp")
    delivery_duration: Optional[float] = Field(None, description="Delivery duration in seconds")
    
    # Recipients
    recipients: List[str] = Field(default_factory=list, description="List of recipients")
    failed_recipients: List[str] = Field(default_factory=list, description="Recipients that failed")
    
    # Response information
    response_data: Dict[str, Any] = Field(default_factory=dict, description="Response data from channel")
    external_id: Optional[str] = Field(None, description="External ID from notification system")
    
    # Retry information
    retry_count: int = Field(0, description="Number of retry attempts")
    will_retry: bool = Field(False, description="Whether delivery will be retried")
    next_retry_at: Optional[datetime] = Field(None, description="Next retry timestamp")
    
    class Config:
        use_enum_values = True


class NotificationRequest(BaseModel):
    """Request for notification delivery."""
    
    request_id: str = Field(..., description="Unique request identifier")
    notification_type: NotificationType = Field(..., description="Type of notification")
    priority: Priority = Field(Priority.MEDIUM, description="Notification priority")
    
    # Content
    title: str = Field(..., description="Notification title")
    message: str = Field(..., description="Notification message")
    details: Dict[str, Any] = Field(default_factory=dict, description="Additional details")
    
    # Delivery configuration
    channels: List[NotificationChannel] = Field(..., description="Delivery channels")
    recipients: Dict[str, List[str]] = Field(default_factory=dict, description="Recipients per channel")
    
    # Formatting and templating
    template: Optional[str] = Field(None, description="Message template to use")
    template_vars: Dict[str, Any] = Field(default_factory=dict, description="Template variables")
    
    # Scheduling
    send_at: Optional[datetime] = Field(None, description="Scheduled send time")
    timezone: str = Field("UTC", description="Timezone for scheduling")
    
    # Retry configuration
    max_retries: int = Field(3, description="Maximum retry attempts")
    retry_delay: int = Field(60, description="Retry delay in seconds")
    
    # Context and metadata
    source: str = Field("", description="Source of the notification")
    context: Dict[str, Any] = Field(default_factory=dict, description="Additional context")
    tags: List[str] = Field(default_factory=list, description="Notification tags")
    
    # Related objects
    incident_id: Optional[str] = Field(None, description="Related incident ID")
    alert_id: Optional[str] = Field(None, description="Related alert ID")
    
    # Metadata
    timestamp: datetime = Field(default_factory=datetime.now)


class NotificationResponse(BaseModel):
    """Response from notification delivery."""
    
    request_id: str = Field(..., description="Original request identifier")
    notification_id: str = Field(..., description="Unique notification identifier")
    
    # Overall status
    status: str = Field(..., description="Overall status: success, partial, failed, scheduled")
    
    # Results per channel
    results: List[NotificationResult] = Field(default_factory=list)
    
    # Summary
    total_channels: int = Field(0, description="Total channels attempted")
    successful_channels: int = Field(0, description="Channels delivered successfully")
    failed_channels: int = Field(0, description="Channels that failed")
    
    # Performance metrics
    total_duration: float = Field(0.0, description="Total delivery duration in seconds")
    
    # Error information
    error_message: Optional[str] = Field(None, description="Error message if delivery failed")
    warnings: List[str] = Field(default_factory=list, description="Delivery warnings")
    
    # Metadata
    notifier_version: str = Field("", description="Notifier version")
    completion_timestamp: datetime = Field(default_factory=datetime.now)


class NotifierPlugin(BasePlugin):
    """
    Base class for notifier plugins.
    
    Notifier plugins deliver security alerts and notifications through
    various channels including email, messaging platforms, and incident
    management systems.
    """
    
    def get_metadata(self) -> PluginMetadata:
        """Get notifier plugin metadata."""
        metadata = super().get_metadata() if hasattr(super(), 'get_metadata') else PluginMetadata(
            name=self.__class__.__name__,
            version="1.0.0",
            plugin_type=PluginType.NOTIFIER,
            entry_point=f"{self.__class__.__module__}:{self.__class__.__name__}"
        )
        metadata.plugin_type = PluginType.NOTIFIER
        return metadata
    
    @abstractmethod
    async def send_notification(self, request: NotificationRequest) -> NotificationResponse:
        """
        Send a notification.
        
        Args:
            request: Notification request with content and delivery parameters
            
        Returns:
            NotificationResponse: Delivery results
            
        Raises:
            PluginError: If notification delivery fails
        """
        pass
    
    @abstractmethod
    def get_supported_channels(self) -> List[NotificationChannel]:
        """
        Get list of supported notification channels.
        
        Returns:
            List of supported notification channels
        """
        pass
    
    @abstractmethod
    def get_channel_config_schema(self, channel: NotificationChannel) -> Dict[str, Any]:
        """
        Get configuration schema for a notification channel.
        
        Args:
            channel: Notification channel
            
        Returns:
            JSON schema for channel configuration
        """
        pass
    
    async def validate_request(self, request: NotificationRequest) -> bool:
        """
        Validate a notification request.
        
        Args:
            request: Notification request to validate
            
        Returns:
            True if request is valid, False otherwise
        """
        if not request.title and not request.message:
            return False
            
        if not request.channels:
            return False
            
        for channel in request.channels:
            if channel not in self.get_supported_channels():
                return False
                
        return True
    
    async def test_channel(self, channel: NotificationChannel, config: Dict[str, Any]) -> bool:
        """
        Test a notification channel configuration.
        
        Args:
            channel: Notification channel to test
            config: Channel configuration
            
        Returns:
            True if channel is working, False otherwise
        """
        try:
            test_request = NotificationRequest(
                request_id="test",
                notification_type=NotificationType.STATUS_UPDATE,
                priority=Priority.LOW,
                title="Test Notification",
                message="This is a test notification from MCP Security Platform",
                channels=[channel],
                recipients={channel.value: ["test@example.com"] if channel == NotificationChannel.EMAIL else ["test"]}
            )
            
            response = await self.send_notification(test_request)
            return response.status == "success"
        except Exception:
            return False
    
    async def get_notification_stats(self) -> Dict[str, Any]:
        """
        Get notification statistics.
        
        Returns:
            Dictionary with notification statistics
        """
        return {
            "total_notifications": 0,
            "successful_notifications": 0,
            "failed_notifications": 0,
            "average_delivery_time": 0.0,
            "supported_channels": [c.value for c in self.get_supported_channels()],
            "delivery_rate": 1.0,
        }