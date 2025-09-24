"""
Cloud Connector - Integration with Cloud Security Services

This connector provides integration capabilities with major cloud security
platforms including AWS Security Hub, Azure Security Center, GCP Security
Command Center, and cloud-native security tools.
"""

import asyncio
import json
import boto3
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import httpx
from botocore.exceptions import ClientError, NoCredentialsError

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced

from ..models.integration import Integration

logger = get_logger(__name__)
metrics = get_metrics()


class CloudConnector:
    """
    Cloud security integration connector supporting multiple cloud platforms.
    
    Supported cloud platforms:
    - AWS Security Hub
    - AWS GuardDuty  
    - AWS Config
    - Azure Security Center
    - Azure Sentinel
    - Google Cloud Security Command Center
    - Google Cloud Asset Inventory
    - Multi-cloud security platforms
    """
    
    def __init__(self):
        self.http_client = httpx.AsyncClient(timeout=30.0)
        self.aws_clients = {}  # Cache AWS clients
        self.azure_clients = {}  # Cache Azure clients
        self.gcp_clients = {}  # Cache GCP clients
        
        self.supported_providers = {
            "aws_security_hub": self._handle_aws_security_hub,
            "aws_guardduty": self._handle_aws_guardduty,
            "aws_config": self._handle_aws_config,
            "azure_security_center": self._handle_azure_security_center,
            "azure_sentinel": self._handle_azure_sentinel,
            "gcp_security_command_center": self._handle_gcp_scc,
            "gcp_asset_inventory": self._handle_gcp_asset_inventory
        }
        
        logger.info("Cloud connector initialized")
    
    @traced("cloud_connector_connect")
    async def connect(self, integration: Integration) -> Dict[str, Any]:
        """Establish connection to cloud security platform."""
        try:
            provider = integration.provider.lower()
            if provider not in self.supported_providers:
                return {
                    "success": False,
                    "error": f"Unsupported cloud provider: {provider}",
                    "provider": provider
                }
            
            # Get provider-specific handler
            handler = self.supported_providers[provider]
            
            # Attempt connection
            start_time = datetime.now()
            result = await handler("connect", integration)
            response_time = (datetime.now() - start_time).total_seconds() * 1000
            
            result.update({
                "response_time": response_time,
                "provider": provider,
                "connected_at": datetime.now().isoformat()
            })
            
            if result.get("success"):
                logger.info(f"Successfully connected to {provider}: {integration.name}")
                metrics.cloud_connector_connections_successful.inc()
            else:
                logger.error(f"Failed to connect to {provider}: {integration.name}")
                metrics.cloud_connector_connections_failed.inc()
            
            return result
            
        except Exception as e:
            logger.error(f"Error connecting to cloud platform {integration.name}: {e}")
            metrics.cloud_connector_errors.inc()
            return {
                "success": False,
                "error": str(e),
                "error_type": type(e).__name__
            }
    
    @traced("cloud_connector_health_check")
    async def health_check(self, integration: Integration) -> Dict[str, Any]:
        """Perform health check on cloud platform connection."""
        try:
            provider = integration.provider.lower()
            handler = self.supported_providers.get(provider)
            
            if not handler:
                return {"healthy": False, "error": "Unsupported provider"}
            
            start_time = datetime.now()
            result = await handler("health_check", integration)
            response_time = (datetime.now() - start_time).total_seconds() * 1000
            
            result.update({
                "response_time": response_time,
                "checked_at": datetime.now().isoformat()
            })
            
            metrics.cloud_connector_health_checks.inc()
            return result
            
        except Exception as e:
            logger.error(f"Error checking cloud platform health {integration.name}: {e}")
            return {
                "healthy": False,
                "error": str(e),
                "error_type": type(e).__name__
            }
    
    @traced("cloud_connector_pull_data")
    async def pull_data(self, integration: Integration) -> Dict[str, Any]:
        """Pull security findings and alerts from cloud platform."""
        try:
            provider = integration.provider.lower()
            handler = self.supported_providers.get(provider)
            
            if not handler:
                return {"success": False, "error": "Unsupported provider"}
            
            result = await handler("pull_data", integration)
            
            if result.get("success"):
                logger.info(f"Successfully pulled data from {provider}: {integration.name}")
                metrics.cloud_connector_data_pulls_successful.inc()
            else:
                logger.error(f"Failed to pull data from {provider}: {integration.name}")
                metrics.cloud_connector_data_pulls_failed.inc()
            
            return result
            
        except Exception as e:
            logger.error(f"Error pulling data from cloud platform {integration.name}: {e}")
            return {
                "success": False,
                "error": str(e),
                "records_processed": 0
            }
    
    @traced("cloud_connector_push_data")
    async def push_data(self, integration: Integration, data: Dict[str, Any]) -> Dict[str, Any]:
        """Push security findings to cloud platform."""
        try:
            provider = integration.provider.lower()
            handler = self.supported_providers.get(provider)
            
            if not handler:
                return {"success": False, "error": "Unsupported provider"}
            
            result = await handler("push_data", integration, data)
            
            if result.get("success"):
                logger.info(f"Successfully pushed data to {provider}: {integration.name}")
                metrics.cloud_connector_data_pushes_successful.inc()
            else:
                logger.error(f"Failed to push data to {provider}: {integration.name}")
                metrics.cloud_connector_data_pushes_failed.inc()
            
            return result
            
        except Exception as e:
            logger.error(f"Error pushing data to cloud platform {integration.name}: {e}")
            return {
                "success": False,
                "error": str(e),
                "records_processed": 0
            }
    
    @traced("cloud_connector_send_event")
    async def send_event(self, integration: Integration, event_type: str, event_data: Dict[str, Any]):
        """Send security event to cloud platform."""
        try:
            provider = integration.provider.lower()
            handler = self.supported_providers.get(provider)
            
            if not handler:
                logger.warning(f"Cannot send event to unsupported cloud provider: {provider}")
                return
            
            # Format event for cloud platform
            formatted_event = self._format_event_for_cloud(provider, event_type, event_data)
            
            result = await handler("send_event", integration, formatted_event)
            
            if result.get("success"):
                logger.info(f"Successfully sent {event_type} event to {provider}")
                metrics.cloud_connector_events_sent.inc()
            else:
                logger.error(f"Failed to send {event_type} event to {provider}")
                metrics.cloud_connector_events_failed.inc()
            
        except Exception as e:
            logger.error(f"Error sending event to cloud platform {integration.name}: {e}")
            metrics.cloud_connector_errors.inc()
    
    async def test_connection(self, integration: Integration) -> Dict[str, Any]:
        """Test cloud platform connection."""
        return await self.health_check(integration)
    
    async def disconnect(self, integration: Integration):
        """Disconnect from cloud platform."""
        try:
            provider = integration.provider.lower()
            integration_id = str(integration.id)
            
            # Clean up cached clients
            if provider.startswith("aws"):
                self.aws_clients.pop(integration_id, None)
            elif provider.startswith("azure"):
                self.azure_clients.pop(integration_id, None)
            elif provider.startswith("gcp"):
                self.gcp_clients.pop(integration_id, None)
            
            logger.info(f"Disconnected from {provider}: {integration.name}")
            
        except Exception as e:
            logger.error(f"Error disconnecting from cloud platform {integration.name}: {e}")
    
    # AWS handlers
    
    async def _handle_aws_security_hub(self, action: str, integration: Integration, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Handle AWS Security Hub operations."""
        try:
            credentials = integration.credentials
            config = integration.config
            
            aws_access_key = credentials.get("aws_access_key_id")
            aws_secret_key = credentials.get("aws_secret_access_key")
            aws_session_token = credentials.get("aws_session_token")
            region = config.get("region", "us-east-1")
            
            if not aws_access_key or not aws_secret_key:
                return {"success": False, "error": "AWS credentials not configured"}
            
            # Get or create Security Hub client
            integration_id = str(integration.id)
            if integration_id not in self.aws_clients:
                session = boto3.Session(
                    aws_access_key_id=aws_access_key,
                    aws_secret_access_key=aws_secret_key,
                    aws_session_token=aws_session_token,
                    region_name=region
                )
                self.aws_clients[integration_id] = {
                    "securityhub": session.client("securityhub"),
                    "sts": session.client("sts")
                }
            
            securityhub_client = self.aws_clients[integration_id]["securityhub"]
            sts_client = self.aws_clients[integration_id]["sts"]
            
            if action == "connect":
                # Test connection by getting caller identity and Security Hub status
                try:
                    identity = sts_client.get_caller_identity()
                    hub_status = securityhub_client.get_enabled_standards()
                    
                    return {
                        "success": True,
                        "account_id": identity.get("Account"),
                        "region": region,
                        "capabilities": ["findings", "insights", "standards", "custom_actions"],
                        "supports_pull": True,
                        "supports_push": True,
                        "enabled_standards": len(hub_status.get("StandardsSubscriptions", []))
                    }
                except ClientError as e:
                    return {"success": False, "error": str(e)}
            
            elif action == "health_check":
                try:
                    # Check if Security Hub is enabled
                    hub_status = securityhub_client.describe_hub()
                    
                    return {
                        "healthy": True,
                        "health_data": {
                            "hub_arn": hub_status.get("HubArn"),
                            "subscribed_at": hub_status.get("SubscribedAt", "").isoformat() if hub_status.get("SubscribedAt") else None,
                            "auto_enable_controls": hub_status.get("AutoEnableControls", False)
                        }
                    }
                except ClientError as e:
                    return {"healthy": False, "error": str(e)}
            
            elif action == "pull_data":
                try:
                    # Pull recent findings from Security Hub
                    max_results = config.get("max_results", 100)
                    
                    # Get findings from last hour
                    end_time = datetime.now()
                    start_time = end_time - timedelta(hours=1)
                    
                    findings_response = securityhub_client.get_findings(
                        Filters={
                            "UpdatedAt": [
                                {
                                    "Start": start_time.isoformat(),
                                    "End": end_time.isoformat()
                                }
                            ]
                        },
                        MaxResults=max_results
                    )
                    
                    findings = findings_response.get("Findings", [])
                    
                    return {
                        "success": True,
                        "records_processed": len(findings),
                        "records_successful": len(findings),
                        "records_failed": 0,
                        "data": findings,
                        "metadata": {
                            "next_token": findings_response.get("NextToken"),
                            "time_range": {"start": start_time.isoformat(), "end": end_time.isoformat()}
                        }
                    }
                except ClientError as e:
                    return {"success": False, "error": str(e)}
            
            elif action == "push_data":
                try:
                    # Push findings to Security Hub
                    findings_data = data.get("findings", [])
                    
                    if not findings_data:
                        return {"success": True, "records_processed": 0, "records_successful": 0, "records_failed": 0}
                    
                    # Convert to Security Hub finding format
                    formatted_findings = []
                    for finding in findings_data:
                        formatted_finding = self._format_finding_for_security_hub(finding, integration)
                        formatted_findings.append(formatted_finding)
                    
                    # Batch import findings (max 100 per request)
                    successful_count = 0
                    failed_count = 0
                    
                    for i in range(0, len(formatted_findings), 100):
                        batch = formatted_findings[i:i+100]
                        
                        try:
                            response = securityhub_client.batch_import_findings(Findings=batch)
                            
                            successful_count += response.get("SuccessCount", 0)
                            failed_count += response.get("FailedCount", 0)
                            
                            # Log any failed findings
                            for failed_finding in response.get("FailedFindings", []):
                                logger.warning(f"Failed to import finding: {failed_finding}")
                        
                        except ClientError as e:
                            logger.error(f"Error importing findings batch: {e}")
                            failed_count += len(batch)
                    
                    return {
                        "success": failed_count == 0,
                        "records_processed": len(findings_data),
                        "records_successful": successful_count,
                        "records_failed": failed_count
                    }
                
                except Exception as e:
                    return {"success": False, "error": str(e)}
            
            elif action == "send_event":
                try:
                    # Convert event to Security Hub finding
                    finding = self._format_event_as_security_hub_finding(data, integration)
                    
                    response = securityhub_client.batch_import_findings(Findings=[finding])
                    
                    return {
                        "success": response.get("SuccessCount", 0) > 0,
                        "failed_count": response.get("FailedCount", 0)
                    }
                
                except ClientError as e:
                    return {"success": False, "error": str(e)}
            
            elif action == "disconnect":
                return {"success": True}
            
            else:
                return {"success": False, "error": f"Unknown action: {action}"}
                
        except Exception as e:
            logger.error(f"Error in AWS Security Hub handler: {e}")
            return {"success": False, "error": str(e)}
    
    async def _handle_aws_guardduty(self, action: str, integration: Integration, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Handle AWS GuardDuty operations."""
        try:
            credentials = integration.credentials
            config = integration.config
            
            aws_access_key = credentials.get("aws_access_key_id")
            aws_secret_key = credentials.get("aws_secret_access_key")
            aws_session_token = credentials.get("aws_session_token")
            region = config.get("region", "us-east-1")
            
            if not aws_access_key or not aws_secret_key:
                return {"success": False, "error": "AWS credentials not configured"}
            
            # Get or create GuardDuty client
            integration_id = str(integration.id)
            if integration_id not in self.aws_clients:
                session = boto3.Session(
                    aws_access_key_id=aws_access_key,
                    aws_secret_access_key=aws_secret_key,
                    aws_session_token=aws_session_token,
                    region_name=region
                )
                self.aws_clients[integration_id] = {
                    "guardduty": session.client("guardduty")
                }
            
            guardduty_client = self.aws_clients[integration_id]["guardduty"]
            
            if action == "connect":
                try:
                    # List detectors to verify access
                    detectors_response = guardduty_client.list_detectors()
                    detector_ids = detectors_response.get("DetectorIds", [])
                    
                    if not detector_ids:
                        return {"success": False, "error": "No GuardDuty detectors found"}
                    
                    # Get detector details
                    detector_id = detector_ids[0]  # Use first detector
                    detector_details = guardduty_client.get_detector(DetectorId=detector_id)
                    
                    return {
                        "success": True,
                        "detector_id": detector_id,
                        "region": region,
                        "capabilities": ["findings", "threat_intelligence", "malware_protection"],
                        "supports_pull": True,
                        "supports_push": False,  # GuardDuty is read-only
                        "status": detector_details.get("Status"),
                        "service_role": detector_details.get("ServiceRole")
                    }
                
                except ClientError as e:
                    return {"success": False, "error": str(e)}
            
            elif action == "health_check":
                try:
                    # Check detector status
                    detectors_response = guardduty_client.list_detectors()
                    detector_ids = detectors_response.get("DetectorIds", [])
                    
                    if not detector_ids:
                        return {"healthy": False, "error": "No GuardDuty detectors found"}
                    
                    detector_details = guardduty_client.get_detector(DetectorId=detector_ids[0])
                    
                    return {
                        "healthy": detector_details.get("Status") == "ENABLED",
                        "health_data": {
                            "detector_status": detector_details.get("Status"),
                            "finding_publishing_frequency": detector_details.get("FindingPublishingFrequency")
                        }
                    }
                
                except ClientError as e:
                    return {"healthy": False, "error": str(e)}
            
            elif action == "pull_data":
                try:
                    # Pull recent findings from GuardDuty
                    detectors_response = guardduty_client.list_detectors()
                    detector_ids = detectors_response.get("DetectorIds", [])
                    
                    if not detector_ids:
                        return {"success": False, "error": "No GuardDuty detectors found"}
                    
                    detector_id = detector_ids[0]
                    max_results = config.get("max_results", 50)
                    
                    # Get finding IDs first
                    findings_response = guardduty_client.list_findings(
                        DetectorId=detector_id,
                        MaxResults=max_results,
                        FindingCriteria={
                            "Criterion": {
                                "updatedAt": {
                                    "gte": int((datetime.now() - timedelta(hours=1)).timestamp() * 1000)
                                }
                            }
                        }
                    )
                    
                    finding_ids = findings_response.get("FindingIds", [])
                    
                    if not finding_ids:
                        return {
                            "success": True,
                            "records_processed": 0,
                            "records_successful": 0,
                            "records_failed": 0,
                            "data": []
                        }
                    
                    # Get detailed findings
                    detailed_findings = guardduty_client.get_findings(
                        DetectorId=detector_id,
                        FindingIds=finding_ids
                    )
                    
                    findings = detailed_findings.get("Findings", [])
                    
                    return {
                        "success": True,
                        "records_processed": len(findings),
                        "records_successful": len(findings),
                        "records_failed": 0,
                        "data": findings,
                        "metadata": {"detector_id": detector_id}
                    }
                
                except ClientError as e:
                    return {"success": False, "error": str(e)}
            
            elif action == "disconnect":
                return {"success": True}
            
            else:
                return {"success": False, "error": f"Action {action} not supported for GuardDuty"}
                
        except Exception as e:
            logger.error(f"Error in AWS GuardDuty handler: {e}")
            return {"success": False, "error": str(e)}
    
    async def _handle_aws_config(self, action: str, integration: Integration, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Handle AWS Config operations."""
        # Placeholder implementation - would implement AWS Config API calls
        return {"success": False, "error": "AWS Config integration not yet implemented"}
    
    # Azure handlers
    
    async def _handle_azure_security_center(self, action: str, integration: Integration, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Handle Azure Security Center operations."""
        # Placeholder implementation - would implement Azure Security Center API calls
        return {"success": False, "error": "Azure Security Center integration not yet implemented"}
    
    async def _handle_azure_sentinel(self, action: str, integration: Integration, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Handle Azure Sentinel operations."""
        # Placeholder implementation - would implement Azure Sentinel API calls
        return {"success": False, "error": "Azure Sentinel integration not yet implemented"}
    
    # GCP handlers
    
    async def _handle_gcp_scc(self, action: str, integration: Integration, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Handle Google Cloud Security Command Center operations."""
        # Placeholder implementation - would implement GCP Security Command Center API calls
        return {"success": False, "error": "GCP Security Command Center integration not yet implemented"}
    
    async def _handle_gcp_asset_inventory(self, action: str, integration: Integration, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Handle Google Cloud Asset Inventory operations."""
        # Placeholder implementation - would implement GCP Asset Inventory API calls
        return {"success": False, "error": "GCP Asset Inventory integration not yet implemented"}
    
    # Helper methods
    
    def _format_finding_for_security_hub(self, finding: Dict[str, Any], integration: Integration) -> Dict[str, Any]:
        """Format a finding for AWS Security Hub."""
        # Generate unique finding ID
        finding_id = finding.get("id", f"mcp-{datetime.now().timestamp()}")
        
        # Map severity
        severity_mapping = {
            "low": {"Label": "LOW", "Normalized": 25},
            "medium": {"Label": "MEDIUM", "Normalized": 50},
            "high": {"Label": "HIGH", "Normalized": 75},
            "critical": {"Label": "CRITICAL", "Normalized": 90}
        }
        
        severity = finding.get("severity", "medium").lower()
        severity_data = severity_mapping.get(severity, severity_mapping["medium"])
        
        return {
            "SchemaVersion": "2018-10-08",
            "Id": finding_id,
            "ProductArn": f"arn:aws:securityhub:{integration.config.get('region', 'us-east-1')}::product/mcp-security-platform/mcp-security-platform",
            "GeneratorId": "mcp-security-platform",
            "AwsAccountId": integration.config.get("account_id", "123456789012"),
            "Types": [finding.get("type", "Sensitive Data Identifications/Personally Identifiable Information")],
            "FirstObservedAt": finding.get("first_observed", datetime.now().isoformat()),
            "LastObservedAt": finding.get("last_observed", datetime.now().isoformat()),
            "CreatedAt": finding.get("created_at", datetime.now().isoformat()),
            "UpdatedAt": datetime.now().isoformat(),
            "Severity": severity_data,
            "Title": finding.get("title", "Security Finding"),
            "Description": finding.get("description", "Security finding detected by MCP Security Platform"),
            "SourceUrl": finding.get("source_url", ""),
            "ProductFields": {
                "mcp/finding_type": finding.get("finding_type", "security"),
                "mcp/source": finding.get("source", "mcp-security-platform")
            },
            "UserDefinedFields": finding.get("custom_fields", {}),
            "Remediation": {
                "Recommendation": {
                    "Text": finding.get("remediation", "Review and investigate this security finding")
                }
            },
            "RecordState": "ACTIVE",
            "WorkflowState": "NEW"
        }
    
    def _format_event_as_security_hub_finding(self, event_data: Dict[str, Any], integration: Integration) -> Dict[str, Any]:
        """Format an event as AWS Security Hub finding."""
        return self._format_finding_for_security_hub({
            "id": event_data.get("id", f"event-{datetime.now().timestamp()}"),
            "title": f"Security Event: {event_data.get('event_type', 'Unknown')}",
            "description": event_data.get("description", "Security event detected"),
            "severity": event_data.get("severity", "medium"),
            "type": event_data.get("type", "Unusual Behaviors"),
            "source": "mcp-security-platform",
            "finding_type": "event",
            "custom_fields": event_data.get("metadata", {})
        }, integration)
    
    def _format_event_for_cloud(self, provider: str, event_type: str, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Format event data for specific cloud platform."""
        base_event = {
            "timestamp": datetime.now().isoformat(),
            "source": "mcp-security-platform",
            "event_type": event_type,
            "data": event_data
        }
        
        if provider.startswith("aws"):
            # Format for AWS services
            return {
                "source": "mcp-security-platform",
                "detail-type": f"MCP Security Event - {event_type}",
                "detail": base_event,
                "time": datetime.now().isoformat()
            }
        elif provider.startswith("azure"):
            # Format for Azure services
            return {
                "eventType": f"MCP.Security.{event_type}",
                "subject": "mcp-security-platform",
                "eventTime": datetime.now().isoformat(),
                "data": base_event
            }
        elif provider.startswith("gcp"):
            # Format for GCP services
            return {
                "eventType": f"providers/mcp-security-platform/eventTypes/{event_type}",
                "eventTime": datetime.now().isoformat(),
                "data": base_event
            }
        else:
            return base_event
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.http_client.aclose()