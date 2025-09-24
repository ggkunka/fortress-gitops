"""
gRPC Service Server - High-performance RPC interface for the MCP Security Platform

This module provides comprehensive gRPC services for efficient communication
between microservices and external integrations.
"""

import asyncio
import json
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, AsyncIterator
import grpc
from grpc import aio
from grpc_reflection.v1alpha import reflection
from grpc_health.v1 import health, health_pb2, health_pb2_grpc
import logging
from concurrent.futures import ThreadPoolExecutor

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced

logger = get_logger(__name__)
metrics = get_metrics()


# Generated protobuf classes would be imported here
# For demonstration, we'll define simplified message structures

class ScanRequest:
    """Scan request message."""
    def __init__(self, target_id: str, scanner_types: List[str], options: Dict[str, Any] = None):
        self.target_id = target_id
        self.scanner_types = scanner_types
        self.options = options or {}


class ScanResponse:
    """Scan response message."""
    def __init__(self, scan_id: str, status: str, message: str = ""):
        self.scan_id = scan_id
        self.status = status
        self.message = message


class ScanStatusRequest:
    """Scan status request message."""
    def __init__(self, scan_id: str):
        self.scan_id = scan_id


class ScanStatusResponse:
    """Scan status response message."""
    def __init__(self, scan_id: str, status: str, progress: int, results: Dict[str, Any] = None):
        self.scan_id = scan_id
        self.status = status
        self.progress = progress
        self.results = results or {}


class VulnerabilityRequest:
    """Vulnerability query request."""
    def __init__(self, cve_id: str = "", severity: str = "", limit: int = 100):
        self.cve_id = cve_id
        self.severity = severity
        self.limit = limit


class Vulnerability:
    """Vulnerability message."""
    def __init__(self, cve_id: str, title: str, description: str, severity: str, cvss_score: float):
        self.cve_id = cve_id
        self.title = title
        self.description = description
        self.severity = severity
        self.cvss_score = cvss_score


class VulnerabilityResponse:
    """Vulnerability response message."""
    def __init__(self, vulnerabilities: List[Vulnerability]):
        self.vulnerabilities = vulnerabilities


class ComplianceAssessmentRequest:
    """Compliance assessment request."""
    def __init__(self, framework_id: str, target: str, assessment_type: str):
        self.framework_id = framework_id
        self.target = target
        self.assessment_type = assessment_type


class ComplianceAssessmentResponse:
    """Compliance assessment response."""
    def __init__(self, assessment_id: str, status: str, score: float):
        self.assessment_id = assessment_id
        self.status = status
        self.score = score


class EventStreamRequest:
    """Event stream request."""
    def __init__(self, event_types: List[str], filters: Dict[str, str] = None):
        self.event_types = event_types
        self.filters = filters or {}


class SecurityEvent:
    """Security event message."""
    def __init__(self, event_id: str, event_type: str, severity: str, timestamp: str, payload: Dict[str, Any]):
        self.event_id = event_id
        self.event_type = event_type
        self.severity = severity
        self.timestamp = timestamp
        self.payload = payload


# gRPC Service Implementations

class ScanServicer:
    """gRPC service for security scanning operations."""
    
    def __init__(self, scan_service=None):
        self.scan_service = scan_service
    
    @traced("grpc_start_scan")
    async def StartScan(self, request: ScanRequest, context: grpc.aio.ServicerContext) -> ScanResponse:
        """Start a security scan."""
        try:
            # Validate request
            if not request.target_id:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Target ID is required")
            
            if not request.scanner_types:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Scanner types are required")
            
            # Start scan using scan service
            # scan_result = await self.scan_service.start_scan(
            #     target_id=request.target_id,
            #     scanner_types=request.scanner_types,
            #     options=request.options
            # )
            
            # Simulate scan start
            scan_id = f"scan_{int(datetime.now().timestamp())}"
            
            logger.info(f"Started scan {scan_id} for target {request.target_id}")
            metrics.grpc_scans_started.inc()
            
            return ScanResponse(
                scan_id=scan_id,
                status="started",
                message="Scan initiated successfully"
            )
            
        except Exception as e:
            logger.error(f"Failed to start scan: {e}")
            context.abort(grpc.StatusCode.INTERNAL, f"Scan failed: {str(e)}")
    
    @traced("grpc_get_scan_status")
    async def GetScanStatus(self, request: ScanStatusRequest, context: grpc.aio.ServicerContext) -> ScanStatusResponse:
        """Get scan status."""
        try:
            if not request.scan_id:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Scan ID is required")
            
            # Get scan status from scan service
            # scan_status = await self.scan_service.get_scan_status(request.scan_id)
            
            # Simulate scan status
            return ScanStatusResponse(
                scan_id=request.scan_id,
                status="running",
                progress=75,
                results={"vulnerabilities_found": 5}
            )
            
        except Exception as e:
            logger.error(f"Failed to get scan status: {e}")
            context.abort(grpc.StatusCode.INTERNAL, f"Status check failed: {str(e)}")
    
    @traced("grpc_stream_scan_updates")
    async def StreamScanUpdates(
        self, 
        request: ScanStatusRequest, 
        context: grpc.aio.ServicerContext
    ) -> AsyncIterator[ScanStatusResponse]:
        """Stream scan status updates."""
        try:
            scan_id = request.scan_id
            
            # Simulate streaming scan updates
            statuses = ["running", "running", "running", "completed"]
            progress_values = [25, 50, 75, 100]
            
            for i, (status, progress) in enumerate(zip(statuses, progress_values)):
                yield ScanStatusResponse(
                    scan_id=scan_id,
                    status=status,
                    progress=progress,
                    results={"vulnerabilities_found": i + 1}
                )
                
                if status == "completed":
                    break
                    
                await asyncio.sleep(2)  # Simulate scan progress
            
        except Exception as e:
            logger.error(f"Failed to stream scan updates: {e}")
            context.abort(grpc.StatusCode.INTERNAL, f"Stream failed: {str(e)}")


class VulnerabilityServicer:
    """gRPC service for vulnerability management operations."""
    
    def __init__(self, vulnerability_service=None):
        self.vulnerability_service = vulnerability_service
    
    @traced("grpc_get_vulnerabilities")
    async def GetVulnerabilities(self, request: VulnerabilityRequest, context: grpc.aio.ServicerContext) -> VulnerabilityResponse:
        """Get vulnerabilities with filtering."""
        try:
            # Query vulnerabilities from vulnerability service
            # vulnerabilities = await self.vulnerability_service.get_vulnerabilities(
            #     cve_id=request.cve_id,
            #     severity=request.severity,
            #     limit=request.limit
            # )
            
            # Simulate vulnerability data
            vulnerabilities = [
                Vulnerability(
                    cve_id="CVE-2023-1234",
                    title="Critical RCE Vulnerability",
                    description="Remote code execution vulnerability in web framework",
                    severity="critical",
                    cvss_score=9.8
                ),
                Vulnerability(
                    cve_id="CVE-2023-5678",
                    title="SQL Injection Vulnerability",
                    description="SQL injection in user authentication module",
                    severity="high",
                    cvss_score=7.5
                )
            ]
            
            logger.info(f"Retrieved {len(vulnerabilities)} vulnerabilities")
            metrics.grpc_vulnerabilities_queried.inc()
            
            return VulnerabilityResponse(vulnerabilities=vulnerabilities)
            
        except Exception as e:
            logger.error(f"Failed to get vulnerabilities: {e}")
            context.abort(grpc.StatusCode.INTERNAL, f"Query failed: {str(e)}")
    
    @traced("grpc_get_vulnerability_by_cve")
    async def GetVulnerabilityByCVE(self, request: VulnerabilityRequest, context: grpc.aio.ServicerContext) -> Vulnerability:
        """Get specific vulnerability by CVE ID."""
        try:
            if not request.cve_id:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "CVE ID is required")
            
            # Get vulnerability by CVE ID
            # vulnerability = await self.vulnerability_service.get_by_cve(request.cve_id)
            
            # Simulate vulnerability lookup
            return Vulnerability(
                cve_id=request.cve_id,
                title="Sample Vulnerability",
                description=f"Vulnerability details for {request.cve_id}",
                severity="medium",
                cvss_score=6.5
            )
            
        except Exception as e:
            logger.error(f"Failed to get vulnerability by CVE: {e}")
            context.abort(grpc.StatusCode.INTERNAL, f"Lookup failed: {str(e)}")


class ComplianceServicer:
    """gRPC service for compliance assessment operations."""
    
    def __init__(self, compliance_service=None):
        self.compliance_service = compliance_service
    
    @traced("grpc_start_compliance_assessment")
    async def StartComplianceAssessment(
        self, 
        request: ComplianceAssessmentRequest, 
        context: grpc.aio.ServicerContext
    ) -> ComplianceAssessmentResponse:
        """Start a compliance assessment."""
        try:
            # Validate request
            if not request.framework_id:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Framework ID is required")
            
            if not request.target:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Target is required")
            
            # Start assessment using compliance service
            # assessment = await self.compliance_service.start_assessment(
            #     framework_id=request.framework_id,
            #     target=request.target,
            #     assessment_type=request.assessment_type
            # )
            
            # Simulate assessment start
            assessment_id = f"assessment_{int(datetime.now().timestamp())}"
            
            logger.info(f"Started compliance assessment {assessment_id}")
            metrics.grpc_assessments_started.inc()
            
            return ComplianceAssessmentResponse(
                assessment_id=assessment_id,
                status="started",
                score=0.0
            )
            
        except Exception as e:
            logger.error(f"Failed to start compliance assessment: {e}")
            context.abort(grpc.StatusCode.INTERNAL, f"Assessment failed: {str(e)}")


class EventServicer:
    """gRPC service for real-time event streaming."""
    
    def __init__(self, event_service=None):
        self.event_service = event_service
    
    @traced("grpc_stream_security_events")
    async def StreamSecurityEvents(
        self, 
        request: EventStreamRequest, 
        context: grpc.aio.ServicerContext
    ) -> AsyncIterator[SecurityEvent]:
        """Stream security events in real-time."""
        try:
            logger.info(f"Starting event stream for types: {request.event_types}")
            
            # Simulate streaming security events
            event_counter = 0
            while not context.cancelled():
                event_counter += 1
                
                event = SecurityEvent(
                    event_id=f"event_{event_counter}",
                    event_type="vulnerability_detected",
                    severity="medium",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    payload={"description": f"Security event #{event_counter}"}
                )
                
                yield event
                
                await asyncio.sleep(5)  # Send event every 5 seconds
            
        except Exception as e:
            logger.error(f"Failed to stream security events: {e}")
            context.abort(grpc.StatusCode.INTERNAL, f"Stream failed: {str(e)}")


class HealthServicer(health_pb2_grpc.HealthServicer):
    """gRPC health check service."""
    
    def __init__(self):
        self.service_status = {
            "": health_pb2.HealthCheckResponse.SERVING,
            "mcp.scan.ScanService": health_pb2.HealthCheckResponse.SERVING,
            "mcp.vulnerability.VulnerabilityService": health_pb2.HealthCheckResponse.SERVING,
            "mcp.compliance.ComplianceService": health_pb2.HealthCheckResponse.SERVING,
            "mcp.event.EventService": health_pb2.HealthCheckResponse.SERVING,
        }
    
    async def Check(self, request, context):
        """Health check for specific service."""
        service = request.service
        status = self.service_status.get(service, health_pb2.HealthCheckResponse.SERVICE_UNKNOWN)
        
        return health_pb2.HealthCheckResponse(status=status)
    
    async def Watch(self, request, context):
        """Watch health status changes."""
        service = request.service
        
        while not context.cancelled():
            status = self.service_status.get(service, health_pb2.HealthCheckResponse.SERVICE_UNKNOWN)
            yield health_pb2.HealthCheckResponse(status=status)
            await asyncio.sleep(5)


class GRPCServer:
    """
    gRPC Server for the MCP Security Platform.
    
    Features:
    - High-performance RPC communication
    - Streaming support for real-time data
    - Health checking and reflection
    - Authentication and authorization
    - Load balancing support
    - Metrics and monitoring
    - Error handling and recovery
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        
        # Server configuration
        self.host = self.config.get("host", "localhost")
        self.port = self.config.get("port", 50051)
        self.max_workers = self.config.get("max_workers", 100)
        self.max_message_length = self.config.get("max_message_length", 4 * 1024 * 1024)  # 4MB
        
        # gRPC server
        self.server: Optional[aio.Server] = None
        
        # Service dependencies
        self.scan_service = None
        self.vulnerability_service = None
        self.compliance_service = None
        self.event_service = None
        
        # Authentication
        self.auth_enabled = self.config.get("auth_enabled", True)
        self.jwt_secret = self.config.get("jwt_secret", "default_secret")
        
        logger.info("gRPC Server initialized")
    
    async def initialize(self) -> bool:
        """Initialize the gRPC server."""
        try:
            # Create server
            self.server = aio.server(
                ThreadPoolExecutor(max_workers=self.max_workers),
                options=[
                    ("grpc.max_send_message_length", self.max_message_length),
                    ("grpc.max_receive_message_length", self.max_message_length),
                    ("grpc.keepalive_time_ms", 30000),
                    ("grpc.keepalive_timeout_ms", 5000),
                    ("grpc.keepalive_permit_without_calls", True),
                    ("grpc.http2.max_pings_without_data", 0),
                    ("grpc.http2.min_time_between_pings_ms", 10000),
                    ("grpc.http2.min_ping_interval_without_data_ms", 300000),
                ]
            )
            
            # Add servicers
            await self._add_servicers()
            
            # Add reflection for development
            if self.config.get("enable_reflection", True):
                SERVICE_NAMES = (
                    "mcp.scan.ScanService",
                    "mcp.vulnerability.VulnerabilityService", 
                    "mcp.compliance.ComplianceService",
                    "mcp.event.EventService",
                    health.SERVICE_NAME,
                    reflection.SERVICE_NAME,
                )
                reflection.enable_server_reflection(SERVICE_NAMES, self.server)
            
            # Add interceptors
            if self.auth_enabled:
                # Add authentication interceptor
                pass  # Would implement JWT authentication interceptor
            
            # Configure listen address
            listen_addr = f"{self.host}:{self.port}"
            self.server.add_insecure_port(listen_addr)
            
            logger.info("gRPC Server initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize gRPC Server: {e}")
            return False
    
    async def start(self) -> bool:
        """Start the gRPC server."""
        try:
            if not self.server:
                raise RuntimeError("gRPC server not initialized")
            
            await self.server.start()
            logger.info(f"gRPC Server started on {self.host}:{self.port}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start gRPC Server: {e}")
            return False
    
    async def stop(self) -> bool:
        """Stop the gRPC server."""
        try:
            if self.server:
                await self.server.stop(grace=30)
                logger.info("gRPC Server stopped")
            return True
            
        except Exception as e:
            logger.error(f"Failed to stop gRPC Server: {e}")
            return False
    
    async def wait_for_termination(self):
        """Wait for server termination."""
        if self.server:
            await self.server.wait_for_termination()
    
    async def cleanup(self) -> bool:
        """Cleanup gRPC server."""
        try:
            await self.stop()
            logger.info("gRPC Server cleaned up successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to cleanup gRPC Server: {e}")
            return False
    
    async def _add_servicers(self):
        """Add gRPC servicers to the server."""
        # Add scan service
        scan_servicer = ScanServicer(self.scan_service)
        # scan_pb2_grpc.add_ScanServiceServicer_to_server(scan_servicer, self.server)
        
        # Add vulnerability service
        vulnerability_servicer = VulnerabilityServicer(self.vulnerability_service)
        # vulnerability_pb2_grpc.add_VulnerabilityServiceServicer_to_server(vulnerability_servicer, self.server)
        
        # Add compliance service
        compliance_servicer = ComplianceServicer(self.compliance_service)
        # compliance_pb2_grpc.add_ComplianceServiceServicer_to_server(compliance_servicer, self.server)
        
        # Add event service
        event_servicer = EventServicer(self.event_service)
        # event_pb2_grpc.add_EventServiceServicer_to_server(event_servicer, self.server)
        
        # Add health service
        health_servicer = HealthServicer()
        health_pb2_grpc.add_HealthServicer_to_server(health_servicer, self.server)
        
        logger.debug("Added all gRPC servicers")
    
    def set_scan_service(self, scan_service):
        """Set scan service dependency."""
        self.scan_service = scan_service
    
    def set_vulnerability_service(self, vulnerability_service):
        """Set vulnerability service dependency."""
        self.vulnerability_service = vulnerability_service
    
    def set_compliance_service(self, compliance_service):
        """Set compliance service dependency."""
        self.compliance_service = compliance_service
    
    def set_event_service(self, event_service):
        """Set event service dependency."""
        self.event_service = event_service
    
    def get_server_info(self) -> Dict[str, Any]:
        """Get server information."""
        return {
            "host": self.host,
            "port": self.port,
            "max_workers": self.max_workers,
            "max_message_length": self.max_message_length,
            "auth_enabled": self.auth_enabled,
            "reflection_enabled": self.config.get("enable_reflection", True),
            "status": "running" if self.server else "stopped"
        }


# gRPC Client Helper
class GRPCClient:
    """gRPC client helper for connecting to MCP services."""
    
    def __init__(self, host: str = "localhost", port: int = 50051):
        self.host = host
        self.port = port
        self.channel: Optional[aio.Channel] = None
        
        # Stub clients
        self.scan_stub = None
        self.vulnerability_stub = None
        self.compliance_stub = None
        self.event_stub = None
        self.health_stub = None
    
    async def connect(self):
        """Connect to gRPC server."""
        try:
            self.channel = aio.insecure_channel(
                f"{self.host}:{self.port}",
                options=[
                    ("grpc.keepalive_time_ms", 30000),
                    ("grpc.keepalive_timeout_ms", 5000),
                ]
            )
            
            # Create stubs
            # self.scan_stub = scan_pb2_grpc.ScanServiceStub(self.channel)
            # self.vulnerability_stub = vulnerability_pb2_grpc.VulnerabilityServiceStub(self.channel)
            # self.compliance_stub = compliance_pb2_grpc.ComplianceServiceStub(self.channel)
            # self.event_stub = event_pb2_grpc.EventServiceStub(self.channel)
            self.health_stub = health_pb2_grpc.HealthStub(self.channel)
            
            logger.info(f"Connected to gRPC server at {self.host}:{self.port}")
            
        except Exception as e:
            logger.error(f"Failed to connect to gRPC server: {e}")
            raise
    
    async def disconnect(self):
        """Disconnect from gRPC server."""
        if self.channel:
            await self.channel.close()
            self.channel = None
            logger.info("Disconnected from gRPC server")
    
    async def health_check(self, service: str = "") -> bool:
        """Perform health check."""
        try:
            if not self.health_stub:
                return False
            
            request = health_pb2.HealthCheckRequest(service=service)
            response = await self.health_stub.Check(request)
            
            return response.status == health_pb2.HealthCheckResponse.SERVING
            
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return False


# Example protobuf schema (would be in separate .proto files)
PROTO_SCHEMA = """
syntax = "proto3";

package mcp.scan;

service ScanService {
    rpc StartScan(ScanRequest) returns (ScanResponse);
    rpc GetScanStatus(ScanStatusRequest) returns (ScanStatusResponse);
    rpc StreamScanUpdates(ScanStatusRequest) returns (stream ScanStatusResponse);
}

message ScanRequest {
    string target_id = 1;
    repeated string scanner_types = 2;
    map<string, string> options = 3;
}

message ScanResponse {
    string scan_id = 1;
    string status = 2;
    string message = 3;
}

message ScanStatusRequest {
    string scan_id = 1;
}

message ScanStatusResponse {
    string scan_id = 1;
    string status = 2;
    int32 progress = 3;
    map<string, string> results = 4;
}
"""