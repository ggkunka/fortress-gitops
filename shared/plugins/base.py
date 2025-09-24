"""
Base Plugin Classes

This module defines the base classes and interfaces for all MCP Security Platform plugins.
It provides standardized interfaces for scanners, integrations, alerts, and compliance plugins.
"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Union
from enum import Enum
from pydantic import BaseModel, Field
import uuid

from shared.observability.logging import get_logger

logger = get_logger(__name__)


class PluginType(str, Enum):
    """Types of plugins."""
    SCANNER = "scanner"
    INTEGRATION = "integration"
    ALERT = "alert"
    COMPLIANCE = "compliance"
    CUSTOM = "custom"


class PluginStatus(str, Enum):
    """Plugin status."""
    INITIALIZING = "initializing"
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    DISABLED = "disabled"


class BaseConfig(BaseModel):
    """Base configuration for all plugins."""
    enabled: bool = Field(default=True)
    name: str = Field(...)
    description: Optional[str] = None
    timeout_seconds: int = Field(default=300, ge=1, le=3600)
    retry_count: int = Field(default=3, ge=0, le=10)
    retry_delay_seconds: int = Field(default=5, ge=1, le=60)
    tags: Dict[str, str] = Field(default_factory=dict)
    
    class Config:
        use_enum_values = True


class ScannerConfig(BaseConfig):
    """Base configuration for scanner plugins."""
    pass


class IntegrationConfig(BaseConfig):
    """Base configuration for integration plugins."""
    api_endpoint: str = Field(...)
    api_key: Optional[str] = None
    api_token: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    rate_limit_requests_per_minute: int = Field(default=60, ge=1, le=10000)


class AlertConfig(BaseConfig):
    """Base configuration for alert plugins."""
    priority_levels: List[str] = Field(default=["low", "medium", "high", "critical"])
    template_format: str = Field(default="json")


class ComplianceConfig(BaseConfig):
    """Base configuration for compliance plugins."""
    framework_version: str = Field(...)
    control_mappings: Dict[str, str] = Field(default_factory=dict)


class BaseResult(BaseModel):
    """Base result for plugin operations."""
    plugin_name: str = Field(...)
    plugin_version: str = Field(...)
    operation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = Field(...)  # success, failed, partial
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    class Config:
        use_enum_values = True


class ScanResult(BaseResult):
    """Result from scanner plugin operations."""
    target: str = Field(...)
    scan_type: str = Field(...)
    started_at: datetime = Field(...)
    completed_at: datetime = Field(...)
    
    # Vulnerability information
    vulnerability_count: int = Field(default=0, ge=0)
    vulnerabilities: List[Dict[str, Any]] = Field(default_factory=list)
    
    # Package information
    package_count: int = Field(default=0, ge=0)
    packages: List[Dict[str, Any]] = Field(default_factory=list)
    
    # Additional findings
    secrets: List[Dict[str, Any]] = Field(default_factory=list)
    misconfigurations: List[Dict[str, Any]] = Field(default_factory=list)
    files: List[Dict[str, Any]] = Field(default_factory=list)
    
    # Raw output and SBOM data
    raw_output: Optional[Dict[str, Any]] = None
    sbom_data: Optional[Dict[str, Any]] = None


class IntegrationResult(BaseResult):
    """Result from integration plugin operations."""
    operation_type: str = Field(...)  # create, update, delete, query
    resource_id: Optional[str] = None
    resource_type: Optional[str] = None
    data: Optional[Dict[str, Any]] = None


class AlertResult(BaseResult):
    """Result from alert plugin operations."""
    alert_id: str = Field(...)
    recipient: str = Field(...)
    alert_type: str = Field(...)
    priority: str = Field(...)
    delivered: bool = Field(default=False)
    delivery_attempts: int = Field(default=0, ge=0)


class ComplianceResult(BaseResult):
    """Result from compliance plugin operations."""
    framework: str = Field(...)
    assessment_type: str = Field(...)
    controls_evaluated: int = Field(default=0, ge=0)
    controls_passed: int = Field(default=0, ge=0)
    controls_failed: int = Field(default=0, ge=0)
    compliance_score: float = Field(default=0.0, ge=0.0, le=1.0)
    findings: List[Dict[str, Any]] = Field(default_factory=list)


class BasePlugin(ABC):
    """Base class for all plugins."""
    
    def __init__(self, config: BaseConfig):
        self.config = config
        self.name = config.name
        self.version = "1.0.0"
        self.description = config.description or "Base plugin"
        self.plugin_type = PluginType.CUSTOM
        self.status = PluginStatus.INITIALIZING
        self.last_error: Optional[str] = None
        
        logger.info(f"Base plugin initialized: {self.name}")
    
    @abstractmethod
    async def initialize(self) -> bool:
        """Initialize the plugin."""
        pass
    
    @abstractmethod
    async def cleanup(self) -> bool:
        """Cleanup plugin resources."""
        pass
    
    @abstractmethod
    def get_info(self) -> Dict[str, Any]:
        """Get plugin information."""
        pass
    
    @abstractmethod
    def get_health(self) -> Dict[str, Any]:
        """Get plugin health status."""
        pass
    
    def set_status(self, status: PluginStatus, error_message: Optional[str] = None):
        """Set plugin status."""
        self.status = status
        if error_message:
            self.last_error = error_message
            logger.error(f"Plugin {self.name} error: {error_message}")
        else:
            self.last_error = None
        
        logger.info(f"Plugin {self.name} status changed to: {status}")


class BaseScannerPlugin(BasePlugin):
    """Base class for scanner plugins."""
    
    def __init__(self, config: ScannerConfig):
        super().__init__(config)
        self.plugin_type = PluginType.SCANNER
        self.supported_targets = []
        
    @abstractmethod
    async def scan(
        self, 
        target: str, 
        scan_type: str = "default",
        options: Optional[Dict[str, Any]] = None
    ) -> ScanResult:
        """Perform a scan."""
        pass


class BaseIntegrationPlugin(BasePlugin):
    """Base class for integration plugins."""
    
    def __init__(self, config: IntegrationConfig):
        super().__init__(config)
        self.plugin_type = PluginType.INTEGRATION
        self.config = config
        self.supported_operations = []
        
    @abstractmethod
    async def create_resource(
        self, 
        resource_type: str, 
        data: Dict[str, Any],
        options: Optional[Dict[str, Any]] = None
    ) -> IntegrationResult:
        """Create a resource."""
        pass
    
    @abstractmethod
    async def update_resource(
        self, 
        resource_id: str, 
        resource_type: str, 
        data: Dict[str, Any],
        options: Optional[Dict[str, Any]] = None
    ) -> IntegrationResult:
        """Update a resource."""
        pass
    
    @abstractmethod
    async def delete_resource(
        self, 
        resource_id: str, 
        resource_type: str,
        options: Optional[Dict[str, Any]] = None
    ) -> IntegrationResult:
        """Delete a resource."""
        pass
    
    @abstractmethod
    async def query_resources(
        self, 
        resource_type: str, 
        filters: Optional[Dict[str, Any]] = None,
        options: Optional[Dict[str, Any]] = None
    ) -> IntegrationResult:
        """Query resources."""
        pass


class BaseAlertPlugin(BasePlugin):
    """Base class for alert plugins."""
    
    def __init__(self, config: AlertConfig):
        super().__init__(config)
        self.plugin_type = PluginType.ALERT
        self.config = config
        self.supported_alert_types = []
        
    @abstractmethod
    async def send_alert(
        self, 
        alert_type: str, 
        recipient: str, 
        subject: str, 
        message: str,
        priority: str = "medium",
        data: Optional[Dict[str, Any]] = None
    ) -> AlertResult:
        """Send an alert."""
        pass
    
    @abstractmethod
    async def get_alert_status(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Get alert delivery status."""
        pass


class BaseCompliancePlugin(BasePlugin):
    """Base class for compliance plugins."""
    
    def __init__(self, config: ComplianceConfig):
        super().__init__(config)
        self.plugin_type = PluginType.COMPLIANCE
        self.config = config
        self.supported_assessments = []
        
    @abstractmethod
    async def assess_compliance(
        self, 
        assessment_type: str, 
        target: str,
        controls: Optional[List[str]] = None,
        options: Optional[Dict[str, Any]] = None
    ) -> ComplianceResult:
        """Assess compliance."""
        pass
    
    @abstractmethod
    async def get_control_details(self, control_id: str) -> Optional[Dict[str, Any]]:
        """Get control details."""
        pass
    
    @abstractmethod
    async def list_controls(self) -> List[Dict[str, Any]]:
        """List available controls."""
        pass