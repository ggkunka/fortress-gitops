"""
Slack Integration Plugin - Team communication and notification integration

This plugin integrates with Slack to provide real-time notifications,
incident response coordination, and team communication for security events.
"""

import asyncio
import json
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Union
import aiohttp
from urllib.parse import urljoin

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced
from shared.plugins.base import BaseIntegrationPlugin, IntegrationConfig, IntegrationResult

logger = get_logger(__name__)
metrics = get_metrics()


class SlackConfig(IntegrationConfig):
    """Slack integration configuration."""
    api_endpoint: str = "https://slack.com/api"
    bot_token: str  # Required: Bot User OAuth Token (starts with xoxb-)
    
    # Default settings
    default_channel: Optional[str] = None
    default_username: str = "MCP Security Bot"
    default_icon_emoji: str = ":shield:"
    
    # Rate limiting
    rate_limit_requests_per_minute: int = 50  # Slack allows ~1 per second
    
    # Message formatting
    message_format: str = "blocks"  # blocks, text, or attachments
    include_metadata: bool = True
    
    # Security settings
    signing_secret: Optional[str] = None
    encryption_key: Optional[str] = None
    
    # Notification channels mapping
    security_channels: Dict[str, str] = {
        "critical": "#security-critical",
        "high": "#security-high", 
        "medium": "#security-medium",
        "low": "#security-low",
        "incidents": "#security-incidents",
        "alerts": "#security-alerts"
    }
    
    # Thread management
    use_threads: bool = True
    thread_timeout_hours: int = 24
    
    # User groups for notifications
    user_groups: Dict[str, str] = {
        "security_team": "@security-team",
        "devops_team": "@devops-team",
        "oncall": "@oncall"
    }


class SlackPlugin(BaseIntegrationPlugin):
    """
    Slack integration plugin.
    
    Provides integration with Slack for:
    - Security alert notifications
    - Incident response coordination
    - Team communication
    - Interactive security workflows
    - File sharing and collaboration
    - Status updates and reporting
    """
    
    def __init__(self, config: SlackConfig):
        super().__init__(config)
        self.config = config
        self.name = "slack"
        self.version = "1.0.0"
        self.description = "Slack team communication and notification integration"
        
        # Supported operations
        self.supported_operations = [
            "send_message",
            "send_security_alert",
            "create_incident_channel",
            "post_to_thread",
            "upload_file",
            "update_message",
            "add_reaction",
            "get_channel_info",
            "list_channels",
            "create_channel",
            "invite_users",
            "send_direct_message"
        ]
        
        # API session
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Thread tracking
        self.active_threads: Dict[str, Dict[str, Any]] = {}
        
        logger.info("Slack plugin initialized")
    
    async def initialize(self) -> bool:
        """Initialize the Slack plugin."""
        try:
            # Create HTTP session with authentication
            headers = {
                "Authorization": f"Bearer {self.config.bot_token}",
                "Content-Type": "application/json; charset=utf-8",
                "User-Agent": "MCP-Security-Platform/1.0"
            }
            
            timeout = aiohttp.ClientTimeout(total=self.config.timeout_seconds)
            self.session = aiohttp.ClientSession(
                headers=headers,
                timeout=timeout,
                connector=aiohttp.TCPConnector(limit=50)
            )
            
            # Test API connection
            await self._test_connection()
            
            logger.info("Slack plugin initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize Slack plugin: {e}")
            return False
    
    async def cleanup(self) -> bool:
        """Cleanup Slack plugin resources."""
        try:
            if self.session:
                await self.session.close()
                self.session = None
            
            logger.info("Slack plugin cleaned up successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to cleanup Slack plugin: {e}")
            return False
    
    @traced("slack_plugin_send_message")
    async def send_message(
        self, 
        channel: str, 
        text: str,
        blocks: Optional[List[Dict[str, Any]]] = None,
        thread_ts: Optional[str] = None,
        username: Optional[str] = None,
        icon_emoji: Optional[str] = None
    ) -> IntegrationResult:
        """Send a message to Slack channel."""
        try:
            data = {
                "channel": channel,
                "text": text,
                "username": username or self.config.default_username,
                "icon_emoji": icon_emoji or self.config.default_icon_emoji
            }
            
            if blocks and self.config.message_format == "blocks":
                data["blocks"] = blocks
            
            if thread_ts:
                data["thread_ts"] = thread_ts
            
            response = await self._make_request("POST", "/chat.postMessage", json=data)
            
            result = IntegrationResult(
                plugin_name=self.name,
                plugin_version=self.version,
                operation_type="create",
                resource_type="message",
                resource_id=response.get("ts"),
                status="success",
                data=response
            )
            
            logger.info(f"Sent Slack message to {channel}")
            metrics.slack_messages_sent.inc()
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to send Slack message: {e}")
            metrics.slack_api_errors.inc()
            
            return IntegrationResult(
                plugin_name=self.name,
                plugin_version=self.version,
                operation_type="create",
                resource_type="message",
                status="failed",
                error_message=str(e)
            )
    
    @traced("slack_plugin_send_security_alert")
    async def send_security_alert(
        self, 
        severity: str,
        title: str,
        description: str,
        vulnerability_id: Optional[str] = None,
        affected_systems: Optional[List[str]] = None,
        remediation: Optional[str] = None,
        scan_result: Optional[Dict[str, Any]] = None
    ) -> IntegrationResult:
        """Send a formatted security alert."""
        try:
            # Determine channel based on severity
            severity_lower = severity.lower()
            channel = self.config.security_channels.get(severity_lower, self.config.default_channel)
            
            if not channel:
                raise ValueError("No channel configured for security alerts")
            
            # Build alert blocks
            blocks = self._build_security_alert_blocks(
                severity=severity,
                title=title,
                description=description,
                vulnerability_id=vulnerability_id,
                affected_systems=affected_systems,
                remediation=remediation,
                scan_result=scan_result
            )
            
            # Send alert
            result = await self.send_message(
                channel=channel,
                text=f"🚨 {severity.upper()} Security Alert: {title}",
                blocks=blocks
            )
            
            # Mention appropriate team for critical/high severity
            if severity_lower in ["critical", "high"]:
                team_mention = self.config.user_groups.get("security_team")
                if team_mention:
                    await self.send_message(
                        channel=channel,
                        text=f"{team_mention} - Urgent security alert requires attention",
                        thread_ts=result.resource_id
                    )
            
            logger.info(f"Sent {severity} security alert to {channel}")
            metrics.slack_security_alerts_sent.inc()
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to send security alert: {e}")
            return IntegrationResult(
                plugin_name=self.name,
                plugin_version=self.version,
                operation_type="create",
                resource_type="security_alert",
                status="failed",
                error_message=str(e)
            )
    
    @traced("slack_plugin_create_incident_channel")
    async def create_incident_channel(
        self, 
        incident_id: str,
        severity: str,
        title: str,
        initial_users: Optional[List[str]] = None
    ) -> IntegrationResult:
        """Create a dedicated incident response channel."""
        try:
            # Generate channel name
            channel_name = f"incident-{incident_id}-{severity.lower()}"
            
            # Create channel
            create_data = {
                "name": channel_name,
                "is_private": True
            }
            
            create_response = await self._make_request("POST", "/conversations.create", json=create_data)
            channel_id = create_response.get("channel", {}).get("id")
            
            if not channel_id:
                raise RuntimeError("Failed to create incident channel")
            
            # Set channel topic
            topic_data = {
                "channel": channel_id,
                "topic": f"Incident Response: {title} (Severity: {severity})"
            }
            await self._make_request("POST", "/conversations.setTopic", json=topic_data)
            
            # Invite users if specified
            if initial_users:
                invite_data = {
                    "channel": channel_id,
                    "users": ",".join(initial_users)
                }
                await self._make_request("POST", "/conversations.invite", json=invite_data)
            
            # Send initial incident summary
            summary_blocks = self._build_incident_summary_blocks(
                incident_id=incident_id,
                severity=severity,
                title=title
            )
            
            await self.send_message(
                channel=channel_id,
                text=f"🚨 Incident Response Channel Created for {incident_id}",
                blocks=summary_blocks
            )
            
            result = IntegrationResult(
                plugin_name=self.name,
                plugin_version=self.version,
                operation_type="create",
                resource_type="incident_channel",
                resource_id=channel_id,
                status="success",
                data={
                    "channel_id": channel_id,
                    "channel_name": channel_name,
                    "incident_id": incident_id
                }
            )
            
            logger.info(f"Created incident channel {channel_name} for {incident_id}")
            metrics.slack_incident_channels_created.inc()
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to create incident channel: {e}")
            return IntegrationResult(
                plugin_name=self.name,
                plugin_version=self.version,
                operation_type="create",
                resource_type="incident_channel",
                status="failed",
                error_message=str(e)
            )
    
    async def create_resource(
        self, 
        resource_type: str, 
        data: Dict[str, Any],
        options: Optional[Dict[str, Any]] = None
    ) -> IntegrationResult:
        """Create a Slack resource."""
        try:
            if resource_type == "message":
                return await self.send_message(
                    channel=data["channel"],
                    text=data["text"],
                    blocks=data.get("blocks"),
                    thread_ts=data.get("thread_ts"),
                    username=data.get("username"),
                    icon_emoji=data.get("icon_emoji")
                )
            elif resource_type == "security_alert":
                return await self.send_security_alert(
                    severity=data["severity"],
                    title=data["title"],
                    description=data["description"],
                    vulnerability_id=data.get("vulnerability_id"),
                    affected_systems=data.get("affected_systems"),
                    remediation=data.get("remediation"),
                    scan_result=data.get("scan_result")
                )
            elif resource_type == "incident_channel":
                return await self.create_incident_channel(
                    incident_id=data["incident_id"],
                    severity=data["severity"],
                    title=data["title"],
                    initial_users=data.get("initial_users")
                )
            elif resource_type == "channel":
                return await self.create_channel(
                    name=data["name"],
                    is_private=data.get("is_private", False),
                    purpose=data.get("purpose")
                )
            else:
                raise ValueError(f"Unsupported resource type: {resource_type}")
                
        except Exception as e:
            logger.error(f"Failed to create Slack resource: {e}")
            return IntegrationResult(
                plugin_name=self.name,
                plugin_version=self.version,
                operation_type="create",
                resource_type=resource_type,
                status="failed",
                error_message=str(e)
            )
    
    async def update_resource(
        self, 
        resource_id: str, 
        resource_type: str, 
        data: Dict[str, Any],
        options: Optional[Dict[str, Any]] = None
    ) -> IntegrationResult:
        """Update a Slack resource."""
        try:
            if resource_type == "message":
                channel = data.get("channel")
                if not channel:
                    raise ValueError("Channel is required for message updates")
                
                update_data = {
                    "channel": channel,
                    "ts": resource_id,
                    "text": data.get("text", ""),
                    "blocks": data.get("blocks")
                }
                
                response = await self._make_request("POST", "/chat.update", json=update_data)
                
                result = IntegrationResult(
                    plugin_name=self.name,
                    plugin_version=self.version,
                    operation_type="update",
                    resource_type=resource_type,
                    resource_id=resource_id,
                    status="success",
                    data=response
                )
                
                logger.info(f"Updated Slack message {resource_id}")
                return result
            else:
                raise ValueError(f"Cannot update resource type: {resource_type}")
                
        except Exception as e:
            logger.error(f"Failed to update Slack resource: {e}")
            return IntegrationResult(
                plugin_name=self.name,
                plugin_version=self.version,
                operation_type="update",
                resource_type=resource_type,
                resource_id=resource_id,
                status="failed",
                error_message=str(e)
            )
    
    async def delete_resource(
        self, 
        resource_id: str, 
        resource_type: str,
        options: Optional[Dict[str, Any]] = None
    ) -> IntegrationResult:
        """Delete a Slack resource."""
        try:
            if resource_type == "message":
                channel = options.get("channel") if options else None
                if not channel:
                    raise ValueError("Channel is required for message deletion")
                
                delete_data = {
                    "channel": channel,
                    "ts": resource_id
                }
                
                response = await self._make_request("POST", "/chat.delete", json=delete_data)
                
                result = IntegrationResult(
                    plugin_name=self.name,
                    plugin_version=self.version,
                    operation_type="delete",
                    resource_type=resource_type,
                    resource_id=resource_id,
                    status="success",
                    data=response
                )
                
                logger.info(f"Deleted Slack message {resource_id}")
                return result
            else:
                raise ValueError(f"Cannot delete resource type: {resource_type}")
                
        except Exception as e:
            logger.error(f"Failed to delete Slack resource: {e}")
            return IntegrationResult(
                plugin_name=self.name,
                plugin_version=self.version,
                operation_type="delete",
                resource_type=resource_type,
                resource_id=resource_id,
                status="failed",
                error_message=str(e)
            )
    
    async def query_resources(
        self, 
        resource_type: str, 
        filters: Optional[Dict[str, Any]] = None,
        options: Optional[Dict[str, Any]] = None
    ) -> IntegrationResult:
        """Query Slack resources."""
        try:
            filters = filters or {}
            options = options or {}
            
            if resource_type == "channels":
                response = await self.list_channels(
                    exclude_archived=filters.get("exclude_archived", True),
                    types=filters.get("types", "public_channel,private_channel")
                )
            elif resource_type == "users":
                response = await self.list_users()
            else:
                raise ValueError(f"Unsupported resource type: {resource_type}")
            
            result = IntegrationResult(
                plugin_name=self.name,
                plugin_version=self.version,
                operation_type="query",
                resource_type=resource_type,
                status="success",
                data=response
            )
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to query Slack resources: {e}")
            return IntegrationResult(
                plugin_name=self.name,
                plugin_version=self.version,
                operation_type="query",
                resource_type=resource_type,
                status="failed",
                error_message=str(e)
            )
    
    @traced("slack_plugin_create_channel")
    async def create_channel(
        self, 
        name: str, 
        is_private: bool = False,
        purpose: Optional[str] = None
    ) -> IntegrationResult:
        """Create a Slack channel."""
        try:
            data = {
                "name": name,
                "is_private": is_private
            }
            
            response = await self._make_request("POST", "/conversations.create", json=data)
            channel_id = response.get("channel", {}).get("id")
            
            # Set purpose if provided
            if purpose and channel_id:
                purpose_data = {
                    "channel": channel_id,
                    "purpose": purpose
                }
                await self._make_request("POST", "/conversations.setPurpose", json=purpose_data)
            
            result = IntegrationResult(
                plugin_name=self.name,
                plugin_version=self.version,
                operation_type="create",
                resource_type="channel",
                resource_id=channel_id,
                status="success",
                data=response
            )
            
            logger.info(f"Created Slack channel: {name}")
            metrics.slack_channels_created.inc()
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to create channel: {e}")
            return IntegrationResult(
                plugin_name=self.name,
                plugin_version=self.version,
                operation_type="create",
                resource_type="channel",
                status="failed",
                error_message=str(e)
            )
    
    @traced("slack_plugin_list_channels")
    async def list_channels(
        self, 
        exclude_archived: bool = True,
        types: str = "public_channel,private_channel"
    ) -> List[Dict[str, Any]]:
        """List Slack channels."""
        try:
            params = {
                "exclude_archived": exclude_archived,
                "types": types,
                "limit": 1000
            }
            
            response = await self._make_request("GET", "/conversations.list", params=params)
            channels = response.get("channels", [])
            
            logger.info(f"Retrieved {len(channels)} Slack channels")
            metrics.slack_channels_fetched.inc(len(channels))
            
            return channels
            
        except Exception as e:
            logger.error(f"Failed to list channels: {e}")
            raise
    
    async def list_users(self) -> List[Dict[str, Any]]:
        """List Slack users."""
        try:
            response = await self._make_request("GET", "/users.list")
            users = response.get("members", [])
            
            logger.info(f"Retrieved {len(users)} Slack users")
            
            return users
            
        except Exception as e:
            logger.error(f"Failed to list users: {e}")
            raise
    
    def _build_security_alert_blocks(
        self,
        severity: str,
        title: str, 
        description: str,
        vulnerability_id: Optional[str] = None,
        affected_systems: Optional[List[str]] = None,
        remediation: Optional[str] = None,
        scan_result: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """Build formatted blocks for security alerts."""
        
        # Severity color mapping
        severity_colors = {
            "critical": "#FF0000",
            "high": "#FF6600", 
            "medium": "#FFAA00",
            "low": "#00AA00",
            "unknown": "#666666"
        }
        
        color = severity_colors.get(severity.lower(), "#666666")
        
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🚨 {severity.upper()} Security Alert"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*{title}*\n{description}"
                }
            }
        ]
        
        # Add fields section
        fields = []
        
        if vulnerability_id:
            fields.append({
                "type": "mrkdwn",
                "text": f"*Vulnerability ID:*\n{vulnerability_id}"
            })
        
        fields.append({
            "type": "mrkdwn", 
            "text": f"*Severity:*\n{severity.upper()}"
        })
        
        fields.append({
            "type": "mrkdwn",
            "text": f"*Timestamp:*\n{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
        })
        
        if affected_systems:
            systems_text = "\n".join(f"• {system}" for system in affected_systems[:5])
            if len(affected_systems) > 5:
                systems_text += f"\n• ... and {len(affected_systems) - 5} more"
            
            fields.append({
                "type": "mrkdwn",
                "text": f"*Affected Systems:*\n{systems_text}"
            })
        
        if fields:
            blocks.append({
                "type": "section",
                "fields": fields
            })
        
        # Add remediation section
        if remediation:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Recommended Action:*\n{remediation}"
                }
            })
        
        # Add divider
        blocks.append({"type": "divider"})
        
        return blocks
    
    def _build_incident_summary_blocks(
        self,
        incident_id: str,
        severity: str,
        title: str
    ) -> List[Dict[str, Any]]:
        """Build formatted blocks for incident summary."""
        
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🚨 Incident Response: {incident_id}"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Incident Title:* {title}\n*Severity:* {severity.upper()}\n*Created:* {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "This channel has been created for coordinating the incident response. All relevant updates, actions, and communications should be posted here."
                }
            },
            {"type": "divider"}
        ]
        
        return blocks
    
    async def _test_connection(self):
        """Test Slack API connection."""
        try:
            response = await self._make_request("GET", "/auth.test")
            logger.info(f"Slack API connection successful (bot: {response.get('user')})")
        except Exception as e:
            logger.error(f"Slack API connection failed: {e}")
            raise
    
    async def _make_request(
        self, 
        method: str, 
        url: str, 
        json: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None
    ) -> Any:
        """Make Slack API request."""
        try:
            if not self.session:
                raise RuntimeError("Slack session not initialized")
            
            full_url = urljoin(self.config.api_endpoint, url)
            
            async with self.session.request(
                method, 
                full_url, 
                json=json, 
                params=params
            ) as response:
                
                response.raise_for_status()
                
                result = await response.json()
                
                # Check Slack API response
                if not result.get("ok"):
                    error = result.get("error", "Unknown error")
                    raise RuntimeError(f"Slack API error: {error}")
                
                return result
                    
        except Exception as e:
            logger.error(f"Slack API request failed: {method} {url} - {e}")
            raise
    
    def get_info(self) -> Dict[str, Any]:
        """Get plugin information."""
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "supported_operations": self.supported_operations,
            "api_endpoint": self.config.api_endpoint,
            "default_channel": self.config.default_channel,
            "security_channels": self.config.security_channels,
            "rate_limit": self.config.rate_limit_requests_per_minute
        }
    
    def get_health(self) -> Dict[str, Any]:
        """Get plugin health status."""
        try:
            return {
                "healthy": self.session is not None and not self.session.closed,
                "session_active": self.session is not None,
                "api_endpoint": self.config.api_endpoint,
                "last_error": self.last_error,
                "active_threads": len(self.active_threads)
            }
        except Exception as e:
            return {
                "healthy": False,
                "error": str(e)
            }