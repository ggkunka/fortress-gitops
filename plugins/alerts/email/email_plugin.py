"""
Email Alert Plugin - Email notification system for security alerts

This plugin provides email notification capabilities for security alerts,
vulnerability notifications, and incident response communications.
"""

import asyncio
import smtplib
import ssl
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Union
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import aiosmtplib
import jinja2

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced
from shared.plugins.base import BaseAlertPlugin, AlertConfig, AlertResult

logger = get_logger(__name__)
metrics = get_metrics()


class EmailConfig(AlertConfig):
    """Email alert configuration."""
    # SMTP server settings
    smtp_server: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_username: str
    smtp_password: str
    use_tls: bool = True
    use_ssl: bool = False
    
    # Email settings
    from_email: str
    from_name: str = "MCP Security Platform"
    reply_to: Optional[str] = None
    
    # Default recipients
    default_recipients: List[str] = []
    security_team_emails: List[str] = []
    admin_emails: List[str] = []
    
    # Priority to recipient mapping
    priority_recipients: Dict[str, List[str]] = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": []
    }
    
    # Template settings
    template_format: str = "html"  # html, text, both
    template_directory: str = "/templates/email"
    include_attachments: bool = True
    
    # Rate limiting
    max_emails_per_minute: int = 60
    max_recipients_per_email: int = 50
    
    # Retry settings
    retry_count: int = 3
    retry_delay_seconds: int = 30
    
    # Content settings
    include_logo: bool = True
    logo_url: Optional[str] = None
    footer_text: Optional[str] = "This is an automated message from MCP Security Platform"
    
    # Security settings
    encrypt_attachments: bool = False
    pgp_key_id: Optional[str] = None


class EmailPlugin(BaseAlertPlugin):
    """
    Email alert plugin.
    
    Provides email notification capabilities for:
    - Security vulnerability alerts
    - Incident response notifications
    - System status updates
    - Compliance reports
    - Custom alert notifications
    """
    
    def __init__(self, config: EmailConfig):
        super().__init__(config)
        self.config = config
        self.name = "email"
        self.version = "1.0.0"
        self.description = "Email notification system for security alerts"
        
        # Supported alert types
        self.supported_alert_types = [
            "security_alert",
            "vulnerability_notification",
            "incident_notification", 
            "compliance_report",
            "system_status",
            "scan_report",
            "custom_alert"
        ]
        
        # Template engine
        self.template_env = None
        
        # Rate limiting
        self.email_count = 0
        self.last_reset = datetime.now(timezone.utc)
        
        logger.info("Email plugin initialized")
    
    async def initialize(self) -> bool:
        """Initialize the Email plugin."""
        try:
            # Initialize Jinja2 template environment
            self.template_env = jinja2.Environment(
                loader=jinja2.FileSystemLoader(self.config.template_directory),
                autoescape=jinja2.select_autoescape(['html', 'xml'])
            )
            
            # Test SMTP connection
            await self._test_connection()
            
            logger.info("Email plugin initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize Email plugin: {e}")
            return False
    
    async def cleanup(self) -> bool:
        """Cleanup Email plugin resources."""
        try:
            # No persistent connections to clean up for email
            logger.info("Email plugin cleaned up successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to cleanup Email plugin: {e}")
            return False
    
    @traced("email_plugin_send_alert")
    async def send_alert(
        self, 
        alert_type: str, 
        recipient: str, 
        subject: str, 
        message: str,
        priority: str = "medium",
        data: Optional[Dict[str, Any]] = None
    ) -> AlertResult:
        """Send an email alert."""
        try:
            # Validate alert type
            if alert_type not in self.supported_alert_types:
                raise ValueError(f"Unsupported alert type: {alert_type}")
            
            # Parse recipients
            recipients = self._parse_recipients(recipient)
            if not recipients:
                raise ValueError("No valid recipients found")
            
            # Check rate limiting
            await self._check_rate_limit()
            
            # Build email content
            email_content = await self._build_email_content(
                alert_type=alert_type,
                subject=subject,
                message=message,
                priority=priority,
                data=data or {}
            )
            
            # Send email
            alert_id = f"email-{datetime.now(timezone.utc).timestamp()}"
            
            success = await self._send_email(
                recipients=recipients,
                subject=email_content["subject"],
                html_body=email_content.get("html_body"),
                text_body=email_content.get("text_body"),
                attachments=email_content.get("attachments", [])
            )
            
            result = AlertResult(
                plugin_name=self.name,
                plugin_version=self.version,
                alert_id=alert_id,
                recipient=recipient,
                alert_type=alert_type,
                priority=priority,
                delivered=success,
                delivery_attempts=1,
                status="success" if success else "failed"
            )
            
            if success:
                logger.info(f"Email alert sent successfully to {len(recipients)} recipients")
                metrics.email_alerts_sent.inc()
            else:
                logger.error("Failed to send email alert")
                metrics.email_delivery_failures.inc()
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")
            metrics.email_plugin_errors.inc()
            
            return AlertResult(
                plugin_name=self.name,
                plugin_version=self.version,
                alert_id=f"email-error-{datetime.now(timezone.utc).timestamp()}",
                recipient=recipient,
                alert_type=alert_type,
                priority=priority,
                delivered=False,
                delivery_attempts=1,
                status="failed",
                error_message=str(e)
            )
    
    @traced("email_plugin_send_security_alert")
    async def send_security_alert(
        self,
        vulnerability_id: str,
        severity: str,
        title: str,
        description: str,
        affected_systems: Optional[List[str]] = None,
        remediation: Optional[str] = None,
        scan_result: Optional[Dict[str, Any]] = None,
        recipients: Optional[List[str]] = None
    ) -> AlertResult:
        """Send a formatted security alert email."""
        try:
            # Determine recipients based on severity
            if not recipients:
                recipients = self._get_recipients_for_priority(severity.lower())
            
            recipient_str = ",".join(recipients)
            
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
                "urgency": "URGENT" if severity.upper() in ["CRITICAL", "HIGH"] else "NORMAL"
            }
            
            # Create subject
            subject = f"🚨 {severity.upper()} Security Alert: {title} ({vulnerability_id})"
            
            # Create message
            message = f"Security vulnerability detected: {description}"
            
            return await self.send_alert(
                alert_type="security_alert",
                recipient=recipient_str,
                subject=subject,
                message=message,
                priority=severity.lower(),
                data=alert_data
            )
            
        except Exception as e:
            logger.error(f"Failed to send security alert: {e}")
            return AlertResult(
                plugin_name=self.name,
                plugin_version=self.version,
                alert_id=f"security-alert-error-{datetime.now(timezone.utc).timestamp()}",
                recipient=",".join(recipients) if recipients else "",
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
            # For email, we don't track detailed delivery status
            # In a real implementation, you might track this in a database
            return {
                "alert_id": alert_id,
                "status": "unknown",
                "message": "Email delivery status tracking not implemented"
            }
            
        except Exception as e:
            logger.error(f"Failed to get alert status: {e}")
            return None
    
    async def _build_email_content(
        self,
        alert_type: str,
        subject: str,
        message: str,
        priority: str,
        data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Build email content from templates."""
        try:
            content = {
                "subject": subject,
                "text_body": message,
                "html_body": None,
                "attachments": []
            }
            
            # Template context
            template_context = {
                "alert_type": alert_type,
                "subject": subject,
                "message": message,
                "priority": priority,
                "data": data,
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                "platform_name": "MCP Security Platform",
                "footer_text": self.config.footer_text
            }
            
            # Try to render HTML template
            if self.config.template_format in ["html", "both"]:
                try:
                    html_template = self.template_env.get_template(f"{alert_type}.html")
                    content["html_body"] = html_template.render(**template_context)
                except Exception as e:
                    logger.warning(f"Could not render HTML template for {alert_type}: {e}")
                    # Fallback to basic HTML
                    content["html_body"] = self._create_basic_html(subject, message, data)
            
            # Try to render text template
            if self.config.template_format in ["text", "both"]:
                try:
                    text_template = self.template_env.get_template(f"{alert_type}.txt")
                    content["text_body"] = text_template.render(**template_context)
                except Exception as e:
                    logger.warning(f"Could not render text template for {alert_type}: {e}")
                    # Use provided message as fallback
                    content["text_body"] = self._create_basic_text(subject, message, data)
            
            return content
            
        except Exception as e:
            logger.error(f"Failed to build email content: {e}")
            # Return basic content
            return {
                "subject": subject,
                "text_body": message,
                "html_body": self._create_basic_html(subject, message, data),
                "attachments": []
            }
    
    def _create_basic_html(self, subject: str, message: str, data: Dict[str, Any]) -> str:
        """Create basic HTML email content."""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>{subject}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #f44336; color: white; padding: 15px; }}
                .content {{ padding: 20px; }}
                .footer {{ background-color: #f5f5f5; padding: 10px; font-size: 12px; }}
                .priority-critical {{ border-left: 5px solid #f44336; }}
                .priority-high {{ border-left: 5px solid #ff9800; }}
                .priority-medium {{ border-left: 5px solid #2196f3; }}
                .priority-low {{ border-left: 5px solid #4caf50; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h2>🚨 MCP Security Platform Alert</h2>
            </div>
            <div class="content priority-{data.get('priority', 'medium')}">
                <h3>{subject}</h3>
                <p>{message}</p>
                <hr>
                <p><strong>Timestamp:</strong> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        """
        
        # Add additional data fields
        for key, value in data.items():
            if key not in ['priority'] and value is not None:
                html += f"<p><strong>{key.replace('_', ' ').title()}:</strong> {value}</p>\n"
        
        html += f"""
            </div>
            <div class="footer">
                <p>{self.config.footer_text}</p>
            </div>
        </body>
        </html>
        """
        
        return html
    
    def _create_basic_text(self, subject: str, message: str, data: Dict[str, Any]) -> str:
        """Create basic text email content."""
        text = f"""
MCP Security Platform Alert
===========================

{subject}

{message}

Details:
--------
Timestamp: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
"""
        
        # Add additional data fields
        for key, value in data.items():
            if value is not None:
                text += f"{key.replace('_', ' ').title()}: {value}\n"
        
        text += f"\n{self.config.footer_text}\n"
        
        return text
    
    async def _send_email(
        self,
        recipients: List[str],
        subject: str,
        html_body: Optional[str] = None,
        text_body: Optional[str] = None,
        attachments: Optional[List[Dict[str, Any]]] = None
    ) -> bool:
        """Send email using SMTP."""
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['From'] = f"{self.config.from_name} <{self.config.from_email}>"
            msg['To'] = ", ".join(recipients)
            msg['Subject'] = subject
            
            if self.config.reply_to:
                msg['Reply-To'] = self.config.reply_to
            
            # Add text part
            if text_body:
                text_part = MIMEText(text_body, 'plain', 'utf-8')
                msg.attach(text_part)
            
            # Add HTML part
            if html_body:
                html_part = MIMEText(html_body, 'html', 'utf-8')
                msg.attach(html_part)
            
            # Add attachments
            if attachments and self.config.include_attachments:
                for attachment in attachments:
                    await self._add_attachment(msg, attachment)
            
            # Send email
            if self.config.use_ssl:
                await self._send_via_ssl(msg, recipients)
            else:
                await self._send_via_tls(msg, recipients)
            
            # Update rate limiting counter
            self.email_count += 1
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            return False
    
    async def _send_via_tls(self, message: MIMEMultipart, recipients: List[str]):
        """Send email using TLS."""
        await aiosmtplib.send(
            message,
            hostname=self.config.smtp_server,
            port=self.config.smtp_port,
            start_tls=self.config.use_tls,
            username=self.config.smtp_username,
            password=self.config.smtp_password,
            recipients=recipients
        )
    
    async def _send_via_ssl(self, message: MIMEMultipart, recipients: List[str]):
        """Send email using SSL."""
        await aiosmtplib.send(
            message,
            hostname=self.config.smtp_server,
            port=self.config.smtp_port,
            use_tls=False,
            start_tls=False,
            username=self.config.smtp_username,
            password=self.config.smtp_password,
            recipients=recipients,
            tls_context=ssl.create_default_context()
        )
    
    async def _add_attachment(self, message: MIMEMultipart, attachment: Dict[str, Any]):
        """Add attachment to email message."""
        try:
            filename = attachment.get("filename", "attachment")
            content = attachment.get("content", b"")
            content_type = attachment.get("content_type", "application/octet-stream")
            
            part = MIMEBase(*content_type.split('/', 1))
            part.set_payload(content)
            encoders.encode_base64(part)
            part.add_header(
                'Content-Disposition',
                f'attachment; filename= {filename}'
            )
            message.attach(part)
            
        except Exception as e:
            logger.error(f"Failed to add attachment: {e}")
    
    def _parse_recipients(self, recipient: str) -> List[str]:
        """Parse recipient string into list of email addresses."""
        if not recipient:
            return []
        
        # Split by comma and clean up
        recipients = [email.strip() for email in recipient.split(',')]
        
        # Filter out empty strings and validate email format
        valid_recipients = []
        for email in recipients:
            if email and '@' in email:
                valid_recipients.append(email)
        
        return valid_recipients
    
    def _get_recipients_for_priority(self, priority: str) -> List[str]:
        """Get recipient list based on priority."""
        recipients = []
        
        # Add priority-specific recipients
        priority_recipients = self.config.priority_recipients.get(priority, [])
        recipients.extend(priority_recipients)
        
        # For critical/high, also include security team
        if priority in ["critical", "high"]:
            recipients.extend(self.config.security_team_emails)
        
        # For critical, also include admins
        if priority == "critical":
            recipients.extend(self.config.admin_emails)
        
        # Fallback to default recipients
        if not recipients:
            recipients = self.config.default_recipients
        
        # Remove duplicates and return
        return list(set(recipients))
    
    async def _check_rate_limit(self):
        """Check and enforce rate limiting."""
        now = datetime.now(timezone.utc)
        
        # Reset counter if minute has passed
        if (now - self.last_reset).total_seconds() >= 60:
            self.email_count = 0
            self.last_reset = now
        
        # Check if rate limit exceeded
        if self.email_count >= self.config.max_emails_per_minute:
            wait_time = 60 - (now - self.last_reset).total_seconds()
            if wait_time > 0:
                logger.warning(f"Rate limit exceeded, waiting {wait_time} seconds")
                await asyncio.sleep(wait_time)
                self.email_count = 0
                self.last_reset = datetime.now(timezone.utc)
    
    async def _test_connection(self):
        """Test SMTP connection."""
        try:
            if self.config.use_ssl:
                server = aiosmtplib.SMTP(
                    hostname=self.config.smtp_server,
                    port=self.config.smtp_port,
                    use_tls=False,
                    start_tls=False,
                    tls_context=ssl.create_default_context()
                )
            else:
                server = aiosmtplib.SMTP(
                    hostname=self.config.smtp_server,
                    port=self.config.smtp_port,
                    start_tls=self.config.use_tls
                )
            
            await server.connect()
            await server.login(self.config.smtp_username, self.config.smtp_password)
            await server.quit()
            
            logger.info("SMTP connection test successful")
            
        except Exception as e:
            logger.error(f"SMTP connection test failed: {e}")
            raise
    
    def get_info(self) -> Dict[str, Any]:
        """Get plugin information."""
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "supported_alert_types": self.supported_alert_types,
            "smtp_server": self.config.smtp_server,
            "smtp_port": self.config.smtp_port,
            "from_email": self.config.from_email,
            "template_format": self.config.template_format,
            "max_emails_per_minute": self.config.max_emails_per_minute
        }
    
    def get_health(self) -> Dict[str, Any]:
        """Get plugin health status."""
        try:
            return {
                "healthy": True,  # Email doesn't maintain persistent connections
                "smtp_server": self.config.smtp_server,
                "from_email": self.config.from_email,
                "emails_sent_this_minute": self.email_count,
                "rate_limit": self.config.max_emails_per_minute,
                "last_error": self.last_error
            }
        except Exception as e:
            return {
                "healthy": False,
                "error": str(e)
            }