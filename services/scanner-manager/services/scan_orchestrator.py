"""
Scan Orchestrator Service

Orchestrates security scanning operations across multiple scanner plugins.
"""

import asyncio
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import structlog
from shared.event_bus import EventBus

from ..models.scan_models import (
    ScanRequest, ScanResult, ScannerResult, ScanStatus, 
    ScanStatistics, VulnerabilityFinding, SeverityLevel,
    ScanFilter, BulkScanRequest, BulkScanResponse
)

logger = structlog.get_logger(__name__)


class ScanOrchestrator:
    """
    Orchestrates scanning operations across multiple scanner plugins.
    
    Manages scan lifecycle, resource allocation, and result aggregation.
    """
    
    def __init__(self, plugin_manager, resource_manager, event_bus: EventBus):
        """Initialize the scan orchestrator."""
        self.plugin_manager = plugin_manager
        self.resource_manager = resource_manager
        self.event_bus = event_bus
        
        # In-memory storage (in production, use database)
        self.scans: Dict[str, ScanResult] = {}
        self.running_scans: Dict[str, asyncio.Task] = {}
        self.scan_queue: List[str] = []
        
        # Configuration
        self.max_concurrent_scans = 10
        self.default_timeout = 300
        self.scan_retention_days = 30
        
        # Statistics
        self.scan_count = 0
        self.total_duration = 0.0
        
        # Health status
        self.healthy = False
    
    async def initialize(self):
        """Initialize the orchestrator."""
        try:
            # Start background tasks
            asyncio.create_task(self._process_scan_queue())
            asyncio.create_task(self._cleanup_old_scans())
            
            self.healthy = True
            logger.info("Scan orchestrator initialized")
            
        except Exception as e:
            logger.error("Failed to initialize scan orchestrator", error=str(e))
            raise
    
    async def cleanup(self):
        """Cleanup orchestrator resources."""
        try:
            # Cancel all running scans
            for scan_id, task in self.running_scans.items():
                task.cancel()
                logger.info("Cancelled running scan", scan_id=scan_id)
            
            # Wait for tasks to complete
            if self.running_scans:
                await asyncio.gather(*self.running_scans.values(), return_exceptions=True)
            
            self.healthy = False
            logger.info("Scan orchestrator cleaned up")
            
        except Exception as e:
            logger.error("Error during orchestrator cleanup", error=str(e))
    
    def is_healthy(self) -> bool:
        """Check if orchestrator is healthy."""
        return self.healthy
    
    async def create_scan(self, request: ScanRequest) -> str:
        """Create a new scan."""
        scan_id = str(uuid.uuid4())
        
        # Create scan result record
        scan_result = ScanResult(
            scan_id=scan_id,
            target=request.target,
            target_type=request.target_type,
            status=ScanStatus.QUEUED,
            priority=request.priority,
            created_at=datetime.utcnow(),
            tags=request.tags,
            metadata=request.metadata
        )
        
        self.scans[scan_id] = scan_result
        self.scan_queue.append(scan_id)
        
        # Emit scan created event
        await self.event_bus.publish(
            "scan.created",
            {
                "scan_id": scan_id,
                "target": request.target,
                "scanners": [s.value for s in request.scanners],
                "priority": request.priority.value,
                "created_at": scan_result.created_at.isoformat()
            }
        )
        
        logger.info("Scan created", scan_id=scan_id, target=request.target)
        return scan_id
    
    async def execute_scan(self, scan_id: str):
        """Execute a scan with all configured scanners."""
        if scan_id not in self.scans:
            logger.error("Scan not found", scan_id=scan_id)
            return
        
        scan_result = self.scans[scan_id]
        
        try:
            # Update scan status
            scan_result.status = ScanStatus.RUNNING
            scan_result.started_at = datetime.utcnow()
            
            logger.info("Starting scan execution", scan_id=scan_id, target=scan_result.target)
            
            # Emit scan started event
            await self.event_bus.publish(
                "scan.started",
                {
                    "scan_id": scan_id,
                    "target": scan_result.target,
                    "started_at": scan_result.started_at.isoformat()
                }
            )
            
            # Get available scanners from the scan request
            # For now, we'll simulate scanner execution
            scanners = ["grype", "trivy", "syft"]  # This would come from the original request
            
            # Execute scanners in parallel
            scanner_tasks = []
            for scanner in scanners:
                task = asyncio.create_task(self._execute_scanner(scan_id, scanner, scan_result.target))
                scanner_tasks.append(task)
            
            # Wait for all scanners to complete
            scanner_results = await asyncio.gather(*scanner_tasks, return_exceptions=True)
            
            # Process scanner results
            for i, result in enumerate(scanner_results):
                if isinstance(result, Exception):
                    logger.error("Scanner failed", scanner=scanners[i], error=str(result))
                    # Create failed scanner result
                    failed_result = ScannerResult(
                        scanner=scanners[i],
                        status=ScanStatus.FAILED,
                        started_at=scan_result.started_at,
                        completed_at=datetime.utcnow(),
                        error_message=str(result)
                    )
                    scan_result.scanner_results.append(failed_result)
                else:
                    scan_result.scanner_results.append(result)
            
            # Aggregate results
            await self._aggregate_scan_results(scan_result)
            
            # Update final status
            scan_result.status = ScanStatus.COMPLETED
            scan_result.completed_at = datetime.utcnow()
            scan_result.duration = (scan_result.completed_at - scan_result.started_at).total_seconds()
            
            # Update statistics
            self.scan_count += 1
            self.total_duration += scan_result.duration
            
            # Emit scan completed event
            await self.event_bus.publish(
                "scan.completed",
                {
                    "scan_id": scan_id,
                    "target": scan_result.target,
                    "status": scan_result.status.value,
                    "duration": scan_result.duration,
                    "vulnerabilities": scan_result.total_vulnerabilities,
                    "completed_at": scan_result.completed_at.isoformat()
                }
            )
            
            logger.info("Scan completed", 
                       scan_id=scan_id, 
                       duration=scan_result.duration,
                       vulnerabilities=scan_result.total_vulnerabilities)
            
        except asyncio.CancelledError:
            scan_result.status = ScanStatus.CANCELLED
            scan_result.completed_at = datetime.utcnow()
            logger.info("Scan cancelled", scan_id=scan_id)
            
        except Exception as e:
            scan_result.status = ScanStatus.FAILED
            scan_result.completed_at = datetime.utcnow()
            scan_result.error_message = str(e)
            
            # Emit scan failed event
            await self.event_bus.publish(
                "scan.failed",
                {
                    "scan_id": scan_id,
                    "target": scan_result.target,
                    "error": str(e),
                    "completed_at": scan_result.completed_at.isoformat()
                }
            )
            
            logger.error("Scan failed", scan_id=scan_id, error=str(e))
        
        finally:
            # Remove from running scans
            if scan_id in self.running_scans:
                del self.running_scans[scan_id]
    
    async def _execute_scanner(self, scan_id: str, scanner: str, target: str) -> ScannerResult:
        """Execute a single scanner."""
        started_at = datetime.utcnow()
        
        try:
            logger.info("Executing scanner", scan_id=scan_id, scanner=scanner, target=target)
            
            # Simulate scanner execution (in production, use actual scanner plugins)
            await asyncio.sleep(2)  # Simulate scan time
            
            # Generate sample vulnerabilities
            vulnerabilities = self._generate_sample_vulnerabilities(scanner, target)
            
            completed_at = datetime.utcnow()
            duration = (completed_at - started_at).total_seconds()
            
            return ScannerResult(
                scanner=scanner,
                status=ScanStatus.COMPLETED,
                started_at=started_at,
                completed_at=completed_at,
                duration=duration,
                vulnerabilities=vulnerabilities,
                summary={
                    "total_vulnerabilities": len(vulnerabilities),
                    "critical_count": len([v for v in vulnerabilities if v.severity == SeverityLevel.CRITICAL]),
                    "high_count": len([v for v in vulnerabilities if v.severity == SeverityLevel.HIGH]),
                },
                metadata={"scanner_version": "1.0.0", "target": target}
            )
            
        except Exception as e:
            completed_at = datetime.utcnow()
            duration = (completed_at - started_at).total_seconds()
            
            return ScannerResult(
                scanner=scanner,
                status=ScanStatus.FAILED,
                started_at=started_at,
                completed_at=completed_at,
                duration=duration,
                error_message=str(e)
            )
    
    def _generate_sample_vulnerabilities(self, scanner: str, target: str) -> List[VulnerabilityFinding]:
        """Generate sample vulnerabilities for demonstration."""
        sample_vulns = [
            VulnerabilityFinding(
                id="CVE-2023-1234",
                severity=SeverityLevel.CRITICAL,
                title="Buffer overflow in authentication module",
                description="A buffer overflow vulnerability in the authentication module allows remote code execution",
                package_name="openssl",
                package_version="1.1.1k",
                fixed_version="1.1.1l",
                cvss_score=9.1,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                references=["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-1234"],
                scanner=scanner,
                confidence=0.95
            ),
            VulnerabilityFinding(
                id="CVE-2023-5678",
                severity=SeverityLevel.HIGH,
                title="SQL injection vulnerability",
                description="SQL injection vulnerability in user input validation",
                package_name="libpq",
                package_version="13.5",
                fixed_version="13.6",
                cvss_score=7.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                references=["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-5678"],
                scanner=scanner,
                confidence=0.88
            )
        ]
        
        # Return a subset based on scanner type
        if scanner == "grype":
            return sample_vulns
        elif scanner == "trivy":
            return sample_vulns[:1]  # Return fewer for variety
        else:
            return []
    
    async def _aggregate_scan_results(self, scan_result: ScanResult):
        """Aggregate results from all scanners."""
        all_vulnerabilities = []
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "negligible": 0,
            "unknown": 0
        }
        
        # Collect all vulnerabilities
        for scanner_result in scan_result.scanner_results:
            all_vulnerabilities.extend(scanner_result.vulnerabilities)
        
        # Deduplicate vulnerabilities by ID
        unique_vulns = {}
        for vuln in all_vulnerabilities:
            if vuln.id not in unique_vulns:
                unique_vulns[vuln.id] = vuln
            # Could merge scanner results here for same CVE
        
        scan_result.unique_vulnerabilities = list(unique_vulns.values())
        scan_result.total_vulnerabilities = len(scan_result.unique_vulnerabilities)
        
        # Count by severity
        for vuln in scan_result.unique_vulnerabilities:
            severity_counts[vuln.severity.value] += 1
        
        scan_result.severity_counts = severity_counts
    
    async def get_scan_result(self, scan_id: str) -> Optional[ScanResult]:
        """Get scan result by ID."""
        return self.scans.get(scan_id)
    
    async def list_scans(
        self, 
        status_filter: Optional[ScanStatus] = None, 
        limit: int = 50, 
        offset: int = 0
    ) -> List[ScanResult]:
        """List scans with optional filtering."""
        scans = list(self.scans.values())
        
        # Apply status filter
        if status_filter:
            scans = [s for s in scans if s.status == status_filter]
        
        # Sort by creation date (newest first)
        scans.sort(key=lambda x: x.created_at, reverse=True)
        
        # Apply pagination
        return scans[offset:offset + limit]
    
    async def cancel_scan(self, scan_id: str) -> bool:
        """Cancel a running scan."""
        if scan_id not in self.scans:
            return False
        
        scan_result = self.scans[scan_id]
        
        # Can only cancel queued or running scans
        if scan_result.status not in [ScanStatus.QUEUED, ScanStatus.RUNNING]:
            return False
        
        # If running, cancel the task
        if scan_id in self.running_scans:
            task = self.running_scans[scan_id]
            task.cancel()
        
        # If queued, remove from queue
        if scan_id in self.scan_queue:
            self.scan_queue.remove(scan_id)
        
        # Update status
        scan_result.status = ScanStatus.CANCELLED
        scan_result.completed_at = datetime.utcnow()
        
        logger.info("Scan cancelled", scan_id=scan_id)
        
        # Emit event
        await self.event_bus.publish(
            "scan.cancelled",
            {
                "scan_id": scan_id,
                "target": scan_result.target,
                "cancelled_at": scan_result.completed_at.isoformat()
            }
        )
        
        return True
    
    def get_running_scans(self) -> List[str]:
        """Get list of currently running scan IDs."""
        return list(self.running_scans.keys())
    
    def get_queued_scans(self) -> List[str]:
        """Get list of queued scan IDs."""
        return self.scan_queue.copy()
    
    def get_scan_count(self) -> int:
        """Get total scan count."""
        return self.scan_count
    
    async def get_statistics(self) -> ScanStatistics:
        """Get scanning statistics."""
        now = datetime.utcnow()
        
        # Count scans by status
        total_scans = len(self.scans)
        completed_scans = len([s for s in self.scans.values() if s.status == ScanStatus.COMPLETED])
        failed_scans = len([s for s in self.scans.values() if s.status == ScanStatus.FAILED])
        running_scans = len(self.running_scans)
        queued_scans = len(self.scan_queue)
        
        # Calculate time-based metrics
        last_24h = now - timedelta(hours=24)
        last_week = now - timedelta(weeks=1)
        last_month = now - timedelta(days=30)
        
        scans_last_24h = len([s for s in self.scans.values() if s.created_at >= last_24h])
        scans_last_week = len([s for s in self.scans.values() if s.created_at >= last_week])
        scans_last_month = len([s for s in self.scans.values() if s.created_at >= last_month])
        
        # Calculate performance metrics
        completed_scan_durations = [s.duration for s in self.scans.values() 
                                  if s.status == ScanStatus.COMPLETED and s.duration]
        average_duration = sum(completed_scan_durations) / len(completed_scan_durations) if completed_scan_durations else 0
        
        # Calculate vulnerability metrics
        total_vulnerabilities = sum(s.total_vulnerabilities for s in self.scans.values())
        critical_vulnerabilities = sum(s.severity_counts.get("critical", 0) for s in self.scans.values())
        high_vulnerabilities = sum(s.severity_counts.get("high", 0) for s in self.scans.values())
        
        vulnerability_rate = total_vulnerabilities / total_scans if total_scans > 0 else 0
        
        # Calculate rates
        error_rate = (failed_scans / total_scans * 100) if total_scans > 0 else 0
        timeout_rate = 0  # Would calculate from actual timeout events
        
        # Throughput (scans per hour)
        if scans_last_24h > 0:
            throughput = scans_last_24h / 24
        else:
            throughput = 0
        
        return ScanStatistics(
            total_scans=total_scans,
            completed_scans=completed_scans,
            failed_scans=failed_scans,
            running_scans=running_scans,
            queued_scans=queued_scans,
            average_duration=average_duration,
            total_duration=self.total_duration,
            throughput=throughput,
            total_vulnerabilities=total_vulnerabilities,
            critical_vulnerabilities=critical_vulnerabilities,
            high_vulnerabilities=high_vulnerabilities,
            vulnerability_rate=vulnerability_rate,
            scanner_usage={},  # Would calculate from actual usage
            scanner_performance={},  # Would calculate from scanner timings
            scans_last_24h=scans_last_24h,
            scans_last_week=scans_last_week,
            scans_last_month=scans_last_month,
            cpu_usage=0,  # Would get from resource manager
            memory_usage=0,  # Would get from resource manager
            storage_usage=0,  # Would get from resource manager
            error_rate=error_rate,
            timeout_rate=timeout_rate,
            generated_at=now
        )
    
    async def _process_scan_queue(self):
        """Background task to process the scan queue."""
        while True:
            try:
                # Check if we can start more scans
                if (len(self.running_scans) < self.max_concurrent_scans and self.scan_queue):
                    scan_id = self.scan_queue.pop(0)
                    
                    # Start scan execution
                    task = asyncio.create_task(self.execute_scan(scan_id))
                    self.running_scans[scan_id] = task
                    
                    logger.info("Started scan from queue", scan_id=scan_id)
                
                # Wait before next check
                await asyncio.sleep(1)
                
            except Exception as e:
                logger.error("Error processing scan queue", error=str(e))
                await asyncio.sleep(5)
    
    async def _cleanup_old_scans(self):
        """Background task to cleanup old scan results."""
        while True:
            try:
                cutoff = datetime.utcnow() - timedelta(days=self.scan_retention_days)
                
                # Find old scans to remove
                old_scan_ids = [
                    scan_id for scan_id, scan in self.scans.items()
                    if scan.created_at < cutoff and scan.status in [
                        ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED
                    ]
                ]
                
                # Remove old scans
                for scan_id in old_scan_ids:
                    del self.scans[scan_id]
                    logger.info("Cleaned up old scan", scan_id=scan_id)
                
                if old_scan_ids:
                    logger.info("Cleaned up old scans", count=len(old_scan_ids))
                
                # Wait 1 hour before next cleanup
                await asyncio.sleep(3600)
                
            except Exception as e:
                logger.error("Error during scan cleanup", error=str(e))
                await asyncio.sleep(3600)