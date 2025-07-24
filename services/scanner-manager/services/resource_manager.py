"""
Resource Manager Service

Manages system resources for scanning operations including CPU, memory, and concurrency limits.
"""

import asyncio
import psutil
from datetime import datetime, timedelta
from typing import Dict, Optional

import structlog

from ..models.scan_models import ResourceUsage

logger = structlog.get_logger(__name__)


class ResourceManager:
    """
    Manages system resources for optimal scanning performance.
    
    Monitors CPU, memory, disk usage and enforces resource limits.
    """
    
    def __init__(self):
        """Initialize the resource manager."""
        # Resource limits
        self.max_cpu_percent = 80.0
        self.max_memory_percent = 85.0
        self.max_disk_usage_gb = 50.0
        self.max_concurrent_scans = 5
        
        # Current resource tracking
        self.current_cpu = 0.0
        self.current_memory = 0.0
        self.current_disk = 0.0
        self.concurrent_scans = 0
        
        # Resource history for trending
        self.resource_history: List[ResourceUsage] = []
        self.max_history_size = 1440  # 24 hours of minute-by-minute data
        
        # Health status
        self.healthy = True
        
        # Background monitoring
        self.monitor_task: Optional[asyncio.Task] = None
    
    async def initialize(self):
        """Initialize the resource manager."""
        try:
            # Start resource monitoring
            self.monitor_task = asyncio.create_task(self._monitor_resources())
            
            # Initial resource check
            await self._update_resource_usage()
            
            logger.info("Resource manager initialized",
                       max_cpu=self.max_cpu_percent,
                       max_memory=self.max_memory_percent,
                       max_concurrent=self.max_concurrent_scans)
            
        except Exception as e:
            logger.error("Failed to initialize resource manager", error=str(e))
            self.healthy = False
            raise
    
    async def cleanup(self):
        """Cleanup resource manager."""
        try:
            # Cancel monitoring task
            if self.monitor_task:
                self.monitor_task.cancel()
            
            logger.info("Resource manager cleaned up")
            
        except Exception as e:
            logger.error("Error during resource manager cleanup", error=str(e))
    
    def is_healthy(self) -> bool:
        """Check if resource manager is healthy."""
        return self.healthy
    
    async def can_start_scan(self) -> bool:
        """Check if resources are available to start a new scan."""
        # Check concurrent scan limit
        if self.concurrent_scans >= self.max_concurrent_scans:
            logger.debug("Concurrent scan limit reached", 
                        current=self.concurrent_scans,
                        max=self.max_concurrent_scans)
            return False
        
        # Check CPU usage
        if self.current_cpu > self.max_cpu_percent:
            logger.debug("CPU usage too high", 
                        current=self.current_cpu,
                        max=self.max_cpu_percent)
            return False
        
        # Check memory usage
        if self.current_memory > self.max_memory_percent:
            logger.debug("Memory usage too high", 
                        current=self.current_memory,
                        max=self.max_memory_percent)
            return False
        
        # Check disk usage
        if self.current_disk > self.max_disk_usage_gb:
            logger.debug("Disk usage too high", 
                        current=self.current_disk,
                        max=self.max_disk_usage_gb)
            return False
        
        return True
    
    async def reserve_resources(self, estimated_cpu: float = 10.0, estimated_memory: float = 512.0):
        """Reserve resources for a scan."""
        # For now, just increment concurrent scan counter
        # In production, would implement proper resource reservation
        self.concurrent_scans += 1
        
        logger.debug("Resources reserved", 
                    concurrent_scans=self.concurrent_scans,
                    estimated_cpu=estimated_cpu,
                    estimated_memory=estimated_memory)
    
    async def release_resources(self):
        """Release resources after scan completion."""
        if self.concurrent_scans > 0:
            self.concurrent_scans -= 1
        
        logger.debug("Resources released", concurrent_scans=self.concurrent_scans)
    
    def get_current_usage(self) -> ResourceUsage:
        """Get current resource usage."""
        return ResourceUsage(
            cpu_percent=self.current_cpu,
            memory_percent=self.current_memory,
            disk_usage=self.current_disk,
            network_io=self._get_network_stats(),
            active_connections=self.concurrent_scans,
            timestamp=datetime.utcnow()
        )
    
    def get_usage_stats(self) -> Dict[str, float]:
        """Get usage statistics."""
        return {
            "cpu_percent": self.current_cpu,
            "memory_percent": self.current_memory,
            "disk_usage_gb": self.current_disk,
            "concurrent_scans": self.concurrent_scans,
            "max_concurrent_scans": self.max_concurrent_scans,
            "cpu_limit": self.max_cpu_percent,
            "memory_limit": self.max_memory_percent,
            "disk_limit": self.max_disk_usage_gb
        }
    
    def get_resource_trends(self, hours: int = 1) -> List[ResourceUsage]:
        """Get resource usage trends."""
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        return [
            usage for usage in self.resource_history
            if usage.timestamp >= cutoff
        ]
    
    async def _monitor_resources(self):
        """Background task to monitor system resources."""
        while True:
            try:
                await self._update_resource_usage()
                
                # Check if system is under stress
                if (self.current_cpu > self.max_cpu_percent or 
                    self.current_memory > self.max_memory_percent):
                    logger.warning("System under resource stress",
                                 cpu=self.current_cpu,
                                 memory=self.current_memory)
                    self.healthy = False
                else:
                    self.healthy = True
                
                # Wait 30 seconds before next check
                await asyncio.sleep(30)
                
            except Exception as e:
                logger.error("Error monitoring resources", error=str(e))
                self.healthy = False
                await asyncio.sleep(60)
    
    async def _update_resource_usage(self):
        """Update current resource usage metrics."""
        try:
            # Get CPU usage (average over 1 second)
            self.current_cpu = psutil.cpu_percent(interval=1)
            
            # Get memory usage
            memory = psutil.virtual_memory()
            self.current_memory = memory.percent
            
            # Get disk usage for current directory
            disk = psutil.disk_usage('/')
            self.current_disk = (disk.used / (1024**3))  # Convert to GB
            
            # Create resource usage record
            usage = ResourceUsage(
                cpu_percent=self.current_cpu,
                memory_percent=self.current_memory,
                disk_usage=self.current_disk,
                network_io=self._get_network_stats(),
                active_connections=self.concurrent_scans,
                timestamp=datetime.utcnow()
            )
            
            # Add to history
            self.resource_history.append(usage)
            
            # Trim history if too large
            if len(self.resource_history) > self.max_history_size:
                self.resource_history = self.resource_history[-self.max_history_size:]
            
            logger.debug("Resource usage updated",
                        cpu=self.current_cpu,
                        memory=self.current_memory,
                        disk=self.current_disk)
            
        except Exception as e:
            logger.error("Failed to update resource usage", error=str(e))
            # Use safe defaults
            self.current_cpu = 50.0
            self.current_memory = 50.0
            self.current_disk = 10.0
    
    def _get_network_stats(self) -> Dict[str, float]:
        """Get network I/O statistics."""
        try:
            net_io = psutil.net_io_counters()
            return {
                "bytes_sent": float(net_io.bytes_sent),
                "bytes_recv": float(net_io.bytes_recv),
                "packets_sent": float(net_io.packets_sent),
                "packets_recv": float(net_io.packets_recv)
            }
        except Exception:
            return {
                "bytes_sent": 0.0,
                "bytes_recv": 0.0,
                "packets_sent": 0.0,
                "packets_recv": 0.0
            }
    
    def set_limits(self, 
                   max_cpu: Optional[float] = None,
                   max_memory: Optional[float] = None,
                   max_disk: Optional[float] = None,
                   max_concurrent: Optional[int] = None):
        """Update resource limits."""
        if max_cpu is not None:
            self.max_cpu_percent = max_cpu
        if max_memory is not None:
            self.max_memory_percent = max_memory
        if max_disk is not None:
            self.max_disk_usage_gb = max_disk
        if max_concurrent is not None:
            self.max_concurrent_scans = max_concurrent
        
        logger.info("Resource limits updated",
                   max_cpu=self.max_cpu_percent,
                   max_memory=self.max_memory_percent,
                   max_disk=self.max_disk_usage_gb,
                   max_concurrent=self.max_concurrent_scans)