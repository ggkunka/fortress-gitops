"""Runtime behavior schema definitions."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, validator


class RuntimeEvent(BaseModel):
    """Runtime event model."""
    
    event_id: str = Field(..., description="Event unique identifier")
    event_type: str = Field(..., description="Event type")
    timestamp: datetime = Field(..., description="Event timestamp")
    severity: str = Field(..., description="Event severity")
    message: str = Field(..., description="Event message")
    
    # Source information
    source_host: Optional[str] = Field(None, description="Source host")
    source_process: Optional[str] = Field(None, description="Source process")
    source_pid: Optional[int] = Field(None, description="Source process ID")
    source_user: Optional[str] = Field(None, description="Source user")
    source_container: Optional[str] = Field(None, description="Source container")
    
    # Event details
    details: Optional[Dict[str, Any]] = Field(None, description="Event details")
    tags: Optional[List[str]] = Field(None, description="Event tags")
    
    @validator('event_type')
    def validate_event_type(cls, v):
        """Validate event type."""
        valid_types = [
            'security_violation', 'anomaly_detected', 'policy_violation',
            'access_denied', 'privilege_escalation', 'suspicious_activity',
            'malware_detected', 'network_intrusion', 'data_exfiltration',
            'system_compromise', 'configuration_change', 'audit_failure'
        ]
        if v not in valid_types:
            raise ValueError(f'Invalid event type: {v}. Valid types: {valid_types}')
        return v
    
    @validator('severity')
    def validate_severity(cls, v):
        """Validate event severity."""
        valid_severities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        if v not in valid_severities:
            raise ValueError(f'Invalid severity: {v}. Valid severities: {valid_severities}')
        return v
    
    @validator('source_pid')
    def validate_source_pid(cls, v):
        """Validate process ID."""
        if v is not None and v <= 0:
            raise ValueError('Process ID must be positive')
        return v


class RuntimeMetrics(BaseModel):
    """Runtime metrics model."""
    
    metric_name: str = Field(..., description="Metric name")
    metric_type: str = Field(..., description="Metric type")
    timestamp: datetime = Field(..., description="Metric timestamp")
    value: float = Field(..., description="Metric value")
    unit: Optional[str] = Field(None, description="Metric unit")
    
    # Metric metadata
    labels: Optional[Dict[str, str]] = Field(None, description="Metric labels")
    dimensions: Optional[Dict[str, str]] = Field(None, description="Metric dimensions")
    
    @validator('metric_type')
    def validate_metric_type(cls, v):
        """Validate metric type."""
        valid_types = [
            'counter', 'gauge', 'histogram', 'summary',
            'cpu_usage', 'memory_usage', 'network_traffic',
            'disk_io', 'file_access', 'system_calls'
        ]
        if v not in valid_types:
            raise ValueError(f'Invalid metric type: {v}. Valid types: {valid_types}')
        return v


class RuntimeProcess(BaseModel):
    """Runtime process model."""
    
    pid: int = Field(..., description="Process ID")
    name: str = Field(..., description="Process name")
    executable: str = Field(..., description="Process executable path")
    command_line: Optional[str] = Field(None, description="Process command line")
    start_time: datetime = Field(..., description="Process start time")
    end_time: Optional[datetime] = Field(None, description="Process end time")
    
    # Process metadata
    user: Optional[str] = Field(None, description="Process user")
    group: Optional[str] = Field(None, description="Process group")
    parent_pid: Optional[int] = Field(None, description="Parent process ID")
    session_id: Optional[int] = Field(None, description="Session ID")
    
    # Process behavior
    file_accesses: Optional[List[str]] = Field(None, description="Files accessed")
    network_connections: Optional[List[Dict[str, Any]]] = Field(None, description="Network connections")
    system_calls: Optional[List[str]] = Field(None, description="System calls made")
    
    @validator('pid')
    def validate_pid(cls, v):
        """Validate process ID."""
        if v <= 0:
            raise ValueError('Process ID must be positive')
        return v
    
    @validator('parent_pid')
    def validate_parent_pid(cls, v):
        """Validate parent process ID."""
        if v is not None and v <= 0:
            raise ValueError('Parent process ID must be positive')
        return v


class RuntimeContainer(BaseModel):
    """Runtime container model."""
    
    container_id: str = Field(..., description="Container ID")
    name: str = Field(..., description="Container name")
    image: str = Field(..., description="Container image")
    image_tag: Optional[str] = Field(None, description="Container image tag")
    created: datetime = Field(..., description="Container creation time")
    started: Optional[datetime] = Field(None, description="Container start time")
    stopped: Optional[datetime] = Field(None, description="Container stop time")
    
    # Container metadata
    labels: Optional[Dict[str, str]] = Field(None, description="Container labels")
    environment: Optional[Dict[str, str]] = Field(None, description="Environment variables")
    volumes: Optional[List[str]] = Field(None, description="Mounted volumes")
    ports: Optional[List[Dict[str, Any]]] = Field(None, description="Exposed ports")
    
    # Runtime behavior
    processes: Optional[List[RuntimeProcess]] = Field(None, description="Container processes")
    network_activity: Optional[List[Dict[str, Any]]] = Field(None, description="Network activity")
    file_system_changes: Optional[List[Dict[str, Any]]] = Field(None, description="File system changes")


class RuntimeNetworkConnection(BaseModel):
    """Runtime network connection model."""
    
    connection_id: str = Field(..., description="Connection ID")
    protocol: str = Field(..., description="Network protocol")
    source_ip: str = Field(..., description="Source IP address")
    source_port: int = Field(..., description="Source port")
    destination_ip: str = Field(..., description="Destination IP address")
    destination_port: int = Field(..., description="Destination port")
    timestamp: datetime = Field(..., description="Connection timestamp")
    
    # Connection metadata
    state: Optional[str] = Field(None, description="Connection state")
    bytes_sent: Optional[int] = Field(None, description="Bytes sent")
    bytes_received: Optional[int] = Field(None, description="Bytes received")
    duration: Optional[float] = Field(None, description="Connection duration in seconds")
    
    @validator('protocol')
    def validate_protocol(cls, v):
        """Validate network protocol."""
        valid_protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS', 'FTP', 'SSH']
        if v not in valid_protocols:
            raise ValueError(f'Invalid protocol: {v}. Valid protocols: {valid_protocols}')
        return v
    
    @validator('source_port', 'destination_port')
    def validate_port(cls, v):
        """Validate port number."""
        if not (1 <= v <= 65535):
            raise ValueError('Port must be between 1 and 65535')
        return v


class RuntimeFileAccess(BaseModel):
    """Runtime file access model."""
    
    file_path: str = Field(..., description="File path")
    operation: str = Field(..., description="File operation")
    timestamp: datetime = Field(..., description="Access timestamp")
    
    # Access metadata
    process_id: Optional[int] = Field(None, description="Process ID")
    user: Optional[str] = Field(None, description="User")
    result: Optional[str] = Field(None, description="Operation result")
    
    @validator('operation')
    def validate_operation(cls, v):
        """Validate file operation."""
        valid_operations = ['read', 'write', 'execute', 'create', 'delete', 'modify', 'access']
        if v not in valid_operations:
            raise ValueError(f'Invalid operation: {v}. Valid operations: {valid_operations}')
        return v


class RuntimeBehaviorSchema(BaseModel):
    """Main runtime behavior schema."""
    
    # Required fields
    session_id: str = Field(..., description="Runtime session ID")
    start_time: datetime = Field(..., description="Session start time")
    end_time: Optional[datetime] = Field(None, description="Session end time")
    
    # Environment information
    host_name: str = Field(..., description="Host name")
    host_ip: Optional[str] = Field(None, description="Host IP address")
    operating_system: Optional[str] = Field(None, description="Operating system")
    kernel_version: Optional[str] = Field(None, description="Kernel version")
    
    # Runtime data
    events: List[RuntimeEvent] = Field(..., description="Runtime events")
    metrics: Optional[List[RuntimeMetrics]] = Field(None, description="Runtime metrics")
    processes: Optional[List[RuntimeProcess]] = Field(None, description="Runtime processes")
    containers: Optional[List[RuntimeContainer]] = Field(None, description="Runtime containers")
    network_connections: Optional[List[RuntimeNetworkConnection]] = Field(None, description="Network connections")
    file_accesses: Optional[List[RuntimeFileAccess]] = Field(None, description="File accesses")
    
    # Behavioral analysis
    anomalies: Optional[List[Dict[str, Any]]] = Field(None, description="Detected anomalies")
    threats: Optional[List[Dict[str, Any]]] = Field(None, description="Identified threats")
    
    # Additional properties
    properties: Optional[Dict[str, Any]] = Field(None, description="Additional properties")
    
    # Ingestion metadata
    ingestion_id: UUID = Field(default_factory=uuid4, description="Ingestion unique identifier")
    ingestion_timestamp: datetime = Field(default_factory=datetime.utcnow, description="Ingestion timestamp")
    source_system: Optional[str] = Field(None, description="Source system identifier")
    source_environment: Optional[str] = Field(None, description="Source environment")
    
    @validator('events')
    def validate_events_not_empty(cls, v):
        """Ensure events list is not empty."""
        if not v:
            raise ValueError('Runtime behavior must contain at least one event')
        return v
    
    @validator('host_ip')
    def validate_host_ip(cls, v):
        """Validate host IP address format."""
        if v:
            import ipaddress
            try:
                ipaddress.ip_address(v)
            except ValueError:
                raise ValueError('Invalid IP address format')
        return v
    
    class Config:
        """Pydantic configuration."""
        
        json_encoders = {
            datetime: lambda v: v.isoformat(),
            UUID: lambda v: str(v),
        }
        
        schema_extra = {
            "example": {
                "session_id": "session-123e4567-e89b-12d3-a456-426614174000",
                "start_time": "2023-01-01T00:00:00Z",
                "host_name": "web-server-01",
                "host_ip": "192.168.1.100",
                "operating_system": "Linux",
                "kernel_version": "5.15.0-60-generic",
                "events": [
                    {
                        "event_id": "event-001",
                        "event_type": "security_violation",
                        "timestamp": "2023-01-01T00:01:00Z",
                        "severity": "HIGH",
                        "message": "Unauthorized access attempt detected",
                        "source_host": "web-server-01",
                        "source_process": "nginx",
                        "source_pid": 1234,
                        "details": {
                            "source_ip": "192.168.1.200",
                            "target_resource": "/admin",
                            "method": "POST"
                        }
                    }
                ],
                "metrics": [
                    {
                        "metric_name": "cpu_usage",
                        "metric_type": "gauge",
                        "timestamp": "2023-01-01T00:00:00Z",
                        "value": 75.5,
                        "unit": "percent",
                        "labels": {
                            "host": "web-server-01",
                            "process": "nginx"
                        }
                    }
                ],
                "processes": [
                    {
                        "pid": 1234,
                        "name": "nginx",
                        "executable": "/usr/sbin/nginx",
                        "start_time": "2023-01-01T00:00:00Z",
                        "user": "www-data",
                        "parent_pid": 1
                    }
                ],
                "network_connections": [
                    {
                        "connection_id": "conn-001",
                        "protocol": "TCP",
                        "source_ip": "192.168.1.100",
                        "source_port": 80,
                        "destination_ip": "192.168.1.200",
                        "destination_port": 45678,
                        "timestamp": "2023-01-01T00:00:00Z",
                        "state": "ESTABLISHED"
                    }
                ]
            }
        }