"""
Alert Plugins Package

This package contains alert and notification plugins for delivering security alerts
through various channels and platforms. These plugins enable real-time communication
of security events to relevant stakeholders and systems.

Available Alert Plugins:
- Email: Email notification system for security alerts
- Webhook: HTTP webhook notifications for external system integration
- PagerDuty: Incident management and on-call notification integration

Usage:
    from plugins.alerts.email.email_plugin import EmailPlugin, EmailConfig
    from plugins.alerts.webhook.webhook_plugin import WebhookPlugin, WebhookConfig
    from plugins.alerts.pagerduty.pagerduty_plugin import PagerDutyPlugin, PagerDutyConfig
    
    # Initialize alert plugin
    email_config = EmailConfig(
        smtp_server="smtp.gmail.com",
        smtp_username="alerts@company.com",
        smtp_password="password",
        from_email="alerts@company.com"
    )
    email_plugin = EmailPlugin(email_config)
    await email_plugin.initialize()
    
    # Send security alert
    result = await email_plugin.send_security_alert(
        vulnerability_id="CVE-2023-1234",
        severity="high",
        title="Critical Vulnerability Detected",
        description="A critical vulnerability was found in the application",
        recipients=["security@company.com"]
    )
"""

from .email.email_plugin import EmailPlugin, EmailConfig
from .webhook.webhook_plugin import WebhookPlugin, WebhookConfig
from .pagerduty.pagerduty_plugin import PagerDutyPlugin, PagerDutyConfig

__all__ = [
    "EmailPlugin",
    "EmailConfig",
    "WebhookPlugin",
    "WebhookConfig", 
    "PagerDutyPlugin",
    "PagerDutyConfig"
]