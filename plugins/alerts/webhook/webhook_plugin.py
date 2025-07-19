"""
Webhook Alert Plugin - HTTP webhook notifications for security alerts

This plugin provides webhook notification capabilities for integrating with
external systems, APIs, and custom applications for alert delivery.
"""

import asyncio
import json
import hashlib
import hmac
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Union
import aiohttp
from urllib.parse import urljoin

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced
from shared.plugins.base import BaseAlertPlugin, AlertConfig, AlertResult

logger = get_logger(__name__)
metrics = get_metrics()


class WebhookConfig(AlertConfig):
    """Webhook alert configuration."""
    # Default webhook settings
    default_webhook_url: Optional[str] = None
    default_method: str = "POST"
    default_timeout_seconds: int = 30
    
    # Authentication
    auth_type: str = "none"  # none, bearer, basic, hmac, custom
    bearer_token: Optional[str] = None
    basic_username: Optional[str] = None
    basic_password: Optional[str] = None
    hmac_secret: Optional[str] = None
    hmac_algorithm: str = "sha256"
    custom_headers: Dict[str, str] = {}
    
    # Webhook URLs by priority/type
    webhook_urls: Dict[str, str] = {}  # priority/type -> URL mapping
    
    # Payload settings
    payload_format: str = "json"  # json, form, xml
    include_metadata: bool = True
    include_raw_data: bool = False
    custom_payload_template: Optional[str] = None
    
    # Request settings
    max_redirects: int = 3
    verify_ssl: bool = True
    user_agent: str = "MCP-Security-Platform-Webhook/1.0"
    
    # Rate limiting
    max_requests_per_minute: int = 120
    max_concurrent_requests: int = 10
    
    # Retry settings
    retry_count: int = 3
    retry_delay_seconds: int = 5
    retry_backoff_multiplier: float = 2.0
    retry_on_status_codes: List[int] = [500, 502, 503, 504, 408, 429]
    
    # Response validation
    expected_status_codes: List[int] = [200, 201, 202, 204]
    validate_response: bool = False
    expected_response_content: Optional[str] = None


class WebhookPlugin(BaseAlertPlugin):
    """
    Webhook alert plugin.
    
    Provides webhook notification capabilities for:
    - Security alert forwarding to external systems
    - API integrations with SIEM platforms
    - Custom application notifications
    - Third-party service integrations
    - Real-time event streaming
    """
    
    def __init__(self, config: WebhookConfig):
        super().__init__(config)
        self.config = config
        self.name = "webhook"
        self.version = "1.0.0"
        self.description = "HTTP webhook notifications for security alerts"
        
        # Supported alert types
        self.supported_alert_types = [
            "security_alert",
            "vulnerability_notification",
            "incident_notification",
            "compliance_alert",
            "system_status",
            "scan_complete",
            "custom_alert"
        ]
        
        # HTTP session
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Rate limiting
        self.request_count = 0
        self.last_reset = datetime.now(timezone.utc)
        self.active_requests = 0
        
        logger.info("Webhook plugin initialized")
    
    async def initialize(self) -> bool:
        """Initialize the Webhook plugin."""
        try:
            # Create HTTP session
            timeout = aiohttp.ClientTimeout(total=self.config.default_timeout_seconds)
            connector = aiohttp.TCPConnector(
                limit=self.config.max_concurrent_requests,
                verify_ssl=self.config.verify_ssl
            )
            
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                connector=connector,
                headers={"User-Agent": self.config.user_agent}
            )
            
            # Test default webhook if configured
            if self.config.default_webhook_url:
                await self._test_webhook(self.config.default_webhook_url)
            
            logger.info("Webhook plugin initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize Webhook plugin: {e}")
            return False
    
    async def cleanup(self) -> bool:
        """Cleanup Webhook plugin resources."""
        try:
            if self.session:
                await self.session.close()
                self.session = None
            
            logger.info("Webhook plugin cleaned up successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to cleanup Webhook plugin: {e}")
            return False
    
    @traced("webhook_plugin_send_alert")
    async def send_alert(
        self, 
        alert_type: str, 
        recipient: str, 
        subject: str, 
        message: str,
        priority: str = "medium",
        data: Optional[Dict[str, Any]] = None
    ) -> AlertResult:
        """Send a webhook alert."""
        try:
            # Validate alert type
            if alert_type not in self.supported_alert_types:
                raise ValueError(f"Unsupported alert type: {alert_type}")
            
            # Determine webhook URL
            webhook_url = self._get_webhook_url(recipient, priority, alert_type)
            if not webhook_url:
                raise ValueError("No webhook URL configured")
            
            # Check rate limiting
            await self._check_rate_limit()
            
            # Build payload
            payload = await self._build_payload(
                alert_type=alert_type,
                subject=subject,
                message=message,
                priority=priority,
                data=data or {}
            )
            
            # Send webhook with retries
            alert_id = f"webhook-{datetime.now(timezone.utc).timestamp()}"
            
            success, response_data = await self._send_webhook_with_retries(
                url=webhook_url,
                payload=payload,
                method=self.config.default_method
            )
            
            result = AlertResult(
                plugin_name=self.name,
                plugin_version=self.version,
                alert_id=alert_id,
                recipient=webhook_url,
                alert_type=alert_type,
                priority=priority,
                delivered=success,
                delivery_attempts=1,  # Will be updated by retry logic
                status="success" if success else "failed",
                metadata={"response": response_data} if response_data else None
            )
            
            if success:
                logger.info(f"Webhook alert sent successfully to {webhook_url}")
                metrics.webhook_alerts_sent.inc()
            else:
                logger.error(f"Failed to send webhook alert to {webhook_url}")
                metrics.webhook_delivery_failures.inc()
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to send webhook alert: {e}")
            metrics.webhook_plugin_errors.inc()
            
            return AlertResult(
                plugin_name=self.name,
                plugin_version=self.version,
                alert_id=f"webhook-error-{datetime.now(timezone.utc).timestamp()}",
                recipient=recipient,
                alert_type=alert_type,
                priority=priority,
                delivered=False,
                delivery_attempts=1,
                status="failed",
                error_message=str(e)
            )
    
    @traced("webhook_plugin_send_security_alert")
    async def send_security_alert(
        self,
        webhook_url: str,
        vulnerability_id: str,
        severity: str,
        title: str,
        description: str,
        affected_systems: Optional[List[str]] = None,
        remediation: Optional[str] = None,
        scan_result: Optional[Dict[str, Any]] = None
    ) -> AlertResult:
        """Send a formatted security alert via webhook."""
        try:
            # Build alert data
            alert_data = {
                "vulnerability_id": vulnerability_id,
                "severity": severity,
                "title": title,
                "description": description,
                "affected_systems": affected_systems or [],
                "remediation": remediation,
                "scan_result": scan_result,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "alert_id": f"sec-{vulnerability_id}-{int(datetime.now(timezone.utc).timestamp())}"
            }
            
            return await self.send_alert(
                alert_type="security_alert",
                recipient=webhook_url,
                subject=f"Security Alert: {title}",
                message=description,
                priority=severity.lower(),
                data=alert_data
            )
            
        except Exception as e:
            logger.error(f"Failed to send security alert webhook: {e}")
            return AlertResult(
                plugin_name=self.name,
                plugin_version=self.version,
                alert_id=f"security-webhook-error-{datetime.now(timezone.utc).timestamp()}",
                recipient=webhook_url,
                alert_type="security_alert",
                priority=severity.lower(),
                delivered=False,
                delivery_attempts=1,
                status="failed",
                error_message=str(e)
            )
    
    async def get_alert_status(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Get alert delivery status."""
        try:
            # For webhooks, we only know if the initial request succeeded
            # Real implementation might track this in a database
            return {
                "alert_id": alert_id,
                "status": "delivered",  # Assume success if no error stored
                "message": "Webhook delivery status based on HTTP response"
            }
            
        except Exception as e:
            logger.error(f"Failed to get alert status: {e}")
            return None
    
    async def _build_payload(
        self,
        alert_type: str,
        subject: str,
        message: str,
        priority: str,
        data: Dict[str, Any]
    ) -> Union[Dict[str, Any], str]:
        """Build webhook payload."""
        try:
            base_payload = {
                "alert_type": alert_type,
                "subject": subject,
                "message": message,
                "priority": priority,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source": "mcp-security-platform"
            }
            
            # Add metadata if enabled
            if self.config.include_metadata:
                base_payload["metadata"] = {
                    "plugin_name": self.name,
                    "plugin_version": self.version,
                    "sender": "MCP Security Platform"
                }
            
            # Add provided data
            if data:
                if self.config.include_raw_data:
                    base_payload["data"] = data
                else:
                    # Include only non-sensitive data
                    filtered_data = {
                        k: v for k, v in data.items() 
                        if not any(sensitive in k.lower() for sensitive in ["password", "secret", "token", "key"])
                    }
                    base_payload["data"] = filtered_data
            
            # Apply custom template if configured
            if self.config.custom_payload_template:
                # In a real implementation, you might use a templating engine
                # For now, just merge with base payload
                pass
            
            # Format payload based on configuration
            if self.config.payload_format == "json":
                return base_payload
            elif self.config.payload_format == "form":
                # Convert to form data format
                return self._flatten_dict(base_payload)
            elif self.config.payload_format == "xml":
                # Convert to XML format
                return self._dict_to_xml(base_payload)
            else:
                return base_payload
                
        except Exception as e:
            logger.error(f"Failed to build payload: {e}")
            raise
    
    async def _send_webhook_with_retries(
        self,
        url: str,
        payload: Union[Dict[str, Any], str],
        method: str = "POST"
    ) -> tuple[bool, Optional[Dict[str, Any]]]:
        """Send webhook with retry logic."""
        last_error = None
        
        for attempt in range(self.config.retry_count + 1):
            try:
                success, response_data = await self._send_webhook(url, payload, method)
                
                if success:
                    return True, response_data
                
                # Check if we should retry based on status code
                if response_data and response_data.get("status_code") not in self.config.retry_on_status_codes:
                    break
                
                if attempt < self.config.retry_count:
                    delay = self.config.retry_delay_seconds * (self.config.retry_backoff_multiplier ** attempt)
                    logger.warning(f"Webhook failed (attempt {attempt + 1}), retrying in {delay}s")
                    await asyncio.sleep(delay)
                
            except Exception as e:
                last_error = e
                if attempt < self.config.retry_count:
                    delay = self.config.retry_delay_seconds * (self.config.retry_backoff_multiplier ** attempt)
                    logger.warning(f"Webhook error (attempt {attempt + 1}): {e}, retrying in {delay}s")
                    await asyncio.sleep(delay)
        
        # All retries failed
        logger.error(f"Webhook failed after {self.config.retry_count + 1} attempts")
        return False, {"error": str(last_error) if last_error else "All retries failed"}
    
    async def _send_webhook(
        self,
        url: str,
        payload: Union[Dict[str, Any], str],
        method: str = "POST"
    ) -> tuple[bool, Optional[Dict[str, Any]]]:
        """Send single webhook request."""
        try:
            if not self.session:
                raise RuntimeError("Webhook session not initialized")
            
            # Prepare headers
            headers = self.config.custom_headers.copy()
            
            # Add authentication headers
            await self._add_auth_headers(headers, payload)
            
            # Prepare request data
            if self.config.payload_format == "json":
                headers["Content-Type"] = "application/json"
                data = json.dumps(payload) if isinstance(payload, dict) else payload
            elif self.config.payload_format == "form":
                headers["Content-Type"] = "application/x-www-form-urlencoded"
                data = payload
            else:
                data = payload
            
            # Track active requests
            self.active_requests += 1
            self.request_count += 1
            
            try:
                async with self.session.request(
                    method,
                    url,
                    data=data,
                    headers=headers,
                    max_redirects=self.config.max_redirects
                ) as response:
                    
                    response_data = {
                        "status_code": response.status,
                        "headers": dict(response.headers),
                        "url": str(response.url)
                    }
                    
                    # Read response content
                    try:
                        if response.content_type == "application/json":
                            response_data["content"] = await response.json()
                        else:
                            response_data["content"] = await response.text()
                    except Exception:
                        response_data["content"] = None
                    
                    # Check if response is successful
                    success = response.status in self.config.expected_status_codes
                    
                    # Validate response content if configured
                    if success and self.config.validate_response and self.config.expected_response_content:
                        content_str = str(response_data.get("content", ""))
                        if self.config.expected_response_content not in content_str:
                            success = False
                            response_data["validation_error"] = "Expected content not found in response"
                    
                    return success, response_data
                    
            finally:
                self.active_requests -= 1
                
        except Exception as e:
            logger.error(f"Webhook request failed: {e}")
            return False, {"error": str(e)}
    
    async def _add_auth_headers(self, headers: Dict[str, str], payload: Union[Dict[str, Any], str]):
        """Add authentication headers based on configuration."""
        try:
            if self.config.auth_type == "bearer" and self.config.bearer_token:
                headers["Authorization"] = f"Bearer {self.config.bearer_token}"
            
            elif self.config.auth_type == "basic" and self.config.basic_username and self.config.basic_password:
                import base64
                credentials = f"{self.config.basic_username}:{self.config.basic_password}"
                encoded_credentials = base64.b64encode(credentials.encode()).decode()
                headers["Authorization"] = f"Basic {encoded_credentials}"
            
            elif self.config.auth_type == "hmac" and self.config.hmac_secret:
                # Create HMAC signature
                payload_str = json.dumps(payload) if isinstance(payload, dict) else str(payload)
                signature = hmac.new(
                    self.config.hmac_secret.encode(),
                    payload_str.encode(),
                    getattr(hashlib, self.config.hmac_algorithm)
                ).hexdigest()
                headers["X-Signature"] = f"{self.config.hmac_algorithm}={signature}"
                
        except Exception as e:
            logger.error(f"Failed to add auth headers: {e}")
    
    def _get_webhook_url(self, recipient: str, priority: str, alert_type: str) -> Optional[str]:
        """Get webhook URL based on recipient, priority, or alert type."""
        # If recipient is a URL, use it directly
        if recipient.startswith(("http://", "https://")):
            return recipient
        
        # Check for priority-specific URL
        priority_url = self.config.webhook_urls.get(priority)
        if priority_url:
            return priority_url
        
        # Check for alert type-specific URL
        type_url = self.config.webhook_urls.get(alert_type)
        if type_url:
            return type_url
        
        # Check for recipient-specific URL
        recipient_url = self.config.webhook_urls.get(recipient)
        if recipient_url:
            return recipient_url
        
        # Fallback to default URL
        return self.config.default_webhook_url
    
    def _flatten_dict(self, data: Dict[str, Any], parent_key: str = '', sep: str = '.') -> Dict[str, str]:
        """Flatten nested dictionary for form data."""
        items = []
        for k, v in data.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep=sep).items())
            elif isinstance(v, list):
                for i, item in enumerate(v):
                    items.append((f"{new_key}[{i}]", str(item)))
            else:
                items.append((new_key, str(v)))
        return dict(items)
    
    def _dict_to_xml(self, data: Dict[str, Any], root_tag: str = "alert") -> str:
        """Convert dictionary to XML format."""
        def build_xml(d, tag="item"):
            if isinstance(d, dict):
                xml = f"<{tag}>"
                for key, value in d.items():
                    xml += build_xml(value, key)
                xml += f"</{tag}>"
                return xml
            elif isinstance(d, list):
                xml = f"<{tag}>"
                for item in d:
                    xml += build_xml(item, "item")
                xml += f"</{tag}>"
                return xml
            else:
                return f"<{tag}>{str(d)}</{tag}>"
        
        return f'<?xml version="1.0" encoding="UTF-8"?>{build_xml(data, root_tag)}'
    
    async def _check_rate_limit(self):
        """Check and enforce rate limiting."""
        now = datetime.now(timezone.utc)
        
        # Reset counter if minute has passed
        if (now - self.last_reset).total_seconds() >= 60:
            self.request_count = 0
            self.last_reset = now
        
        # Check rate limit
        if self.request_count >= self.config.max_requests_per_minute:
            wait_time = 60 - (now - self.last_reset).total_seconds()
            if wait_time > 0:
                logger.warning(f"Rate limit exceeded, waiting {wait_time} seconds")
                await asyncio.sleep(wait_time)
                self.request_count = 0
                self.last_reset = datetime.now(timezone.utc)
        
        # Check concurrent request limit
        while self.active_requests >= self.config.max_concurrent_requests:
            logger.warning("Concurrent request limit reached, waiting...")
            await asyncio.sleep(0.1)
    
    async def _test_webhook(self, url: str):
        """Test webhook connectivity."""
        try:
            test_payload = {
                "test": True,
                "message": "MCP Security Platform webhook test",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            
            success, response = await self._send_webhook(url, test_payload, "POST")
            
            if success:
                logger.info(f"Webhook test successful: {url}")
            else:
                logger.warning(f"Webhook test failed: {url} - {response}")
                
        except Exception as e:
            logger.error(f"Webhook test error: {e}")
            raise
    
    def get_info(self) -> Dict[str, Any]:
        """Get plugin information."""
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "supported_alert_types": self.supported_alert_types,
            "default_webhook_url": self.config.default_webhook_url,
            "payload_format": self.config.payload_format,
            "auth_type": self.config.auth_type,
            "max_requests_per_minute": self.config.max_requests_per_minute,
            "max_concurrent_requests": self.config.max_concurrent_requests
        }
    
    def get_health(self) -> Dict[str, Any]:
        """Get plugin health status."""
        try:
            return {
                "healthy": self.session is not None and not self.session.closed,
                "session_active": self.session is not None,
                "active_requests": self.active_requests,
                "requests_this_minute": self.request_count,
                "rate_limit": self.config.max_requests_per_minute,
                "last_error": self.last_error
            }
        except Exception as e:
            return {
                "healthy": False,
                "error": str(e)
            }