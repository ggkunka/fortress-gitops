"""
Scan Scheduler Service

Manages scheduled scanning operations with cron-like functionality.
"""

import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import uuid

import structlog
from shared.event_bus import EventBus

from ..models.scan_models import ScheduledScan, ScanRequest, Priority

logger = structlog.get_logger(__name__)


class ScanScheduler:
    """
    Manages scheduled scanning operations.
    
    Provides cron-like scheduling for automated security scans.
    """
    
    def __init__(self, orchestrator, event_bus: EventBus):
        """Initialize the scan scheduler."""
        self.orchestrator = orchestrator
        self.event_bus = event_bus
        
        # Schedule storage
        self.schedules: Dict[str, ScheduledScan] = {}
        
        # Scheduler state
        self.running = False
        self.healthy = True
        
        # Background task
        self.scheduler_task: Optional[asyncio.Task] = None
    
    async def initialize(self):
        """Initialize the scheduler."""
        try:
            # Load existing schedules (in production, from database)
            await self._load_schedules()
            
            logger.info("Scan scheduler initialized", schedule_count=len(self.schedules))
            
        except Exception as e:
            logger.error("Failed to initialize scan scheduler", error=str(e))
            self.healthy = False
            raise
    
    async def start(self):
        """Start the scheduler."""
        if self.running:
            logger.warning("Scheduler already running")
            return
        
        self.running = True
        logger.info("Starting scan scheduler")
        
        try:
            while self.running:
                await self._process_schedules()
                await asyncio.sleep(60)  # Check every minute
                
        except asyncio.CancelledError:
            logger.info("Scheduler cancelled")
        except Exception as e:
            logger.error("Scheduler error", error=str(e))
            self.healthy = False
        finally:
            self.running = False
    
    async def stop(self):
        """Stop the scheduler."""
        self.running = False
        if self.scheduler_task:
            self.scheduler_task.cancel()
        logger.info("Scan scheduler stopped")
    
    def is_healthy(self) -> bool:
        """Check if scheduler is healthy."""
        return self.healthy
    
    async def create_schedule(self, schedule_request: dict) -> ScheduledScan:
        """Create a new scheduled scan."""
        schedule_id = str(uuid.uuid4())
        
        # Parse schedule request
        scan_request = ScanRequest(**schedule_request.get("scan_request", {}))
        
        # Create scheduled scan
        schedule = ScheduledScan(
            schedule_id=schedule_id,
            name=schedule_request.get("name", f"Scheduled scan for {scan_request.target}"),
            description=schedule_request.get("description"),
            enabled=schedule_request.get("enabled", True),
            scan_request=scan_request,
            cron_expression=schedule_request.get("cron_expression", "0 0 * * *"),  # Daily at midnight
            timezone=schedule_request.get("timezone", "UTC"),
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            max_results=schedule_request.get("max_results", 10),
            retention_days=schedule_request.get("retention_days", 30)
        )
        
        # Calculate next run time
        schedule.next_run = self._calculate_next_run(schedule.cron_expression)
        
        # Store schedule
        self.schedules[schedule_id] = schedule
        
        # Emit event
        await self.event_bus.publish(
            "schedule.created",
            {
                "schedule_id": schedule_id,
                "name": schedule.name,
                "target": scan_request.target,
                "cron_expression": schedule.cron_expression,
                "enabled": schedule.enabled,
                "next_run": schedule.next_run.isoformat() if schedule.next_run else None
            }
        )
        
        logger.info("Schedule created", 
                   schedule_id=schedule_id, 
                   name=schedule.name,
                   next_run=schedule.next_run)
        
        return schedule
    
    async def update_schedule(self, schedule_id: str, updates: dict) -> Optional[ScheduledScan]:
        """Update an existing schedule."""
        if schedule_id not in self.schedules:
            return None
        
        schedule = self.schedules[schedule_id]
        
        # Update fields
        if "name" in updates:
            schedule.name = updates["name"]
        if "description" in updates:
            schedule.description = updates["description"]
        if "enabled" in updates:
            schedule.enabled = updates["enabled"]
        if "cron_expression" in updates:
            schedule.cron_expression = updates["cron_expression"]
            schedule.next_run = self._calculate_next_run(schedule.cron_expression)
        if "scan_request" in updates:
            schedule.scan_request = ScanRequest(**updates["scan_request"])
        
        schedule.updated_at = datetime.utcnow()
        
        # Emit event
        await self.event_bus.publish(
            "schedule.updated",
            {
                "schedule_id": schedule_id,
                "name": schedule.name,
                "enabled": schedule.enabled,
                "next_run": schedule.next_run.isoformat() if schedule.next_run else None
            }
        )
        
        logger.info("Schedule updated", schedule_id=schedule_id)
        return schedule
    
    async def delete_schedule(self, schedule_id: str) -> bool:
        """Delete a schedule."""
        if schedule_id not in self.schedules:
            return False
        
        schedule = self.schedules[schedule_id]
        del self.schedules[schedule_id]
        
        # Emit event
        await self.event_bus.publish(
            "schedule.deleted",
            {
                "schedule_id": schedule_id,
                "name": schedule.name
            }
        )
        
        logger.info("Schedule deleted", schedule_id=schedule_id)
        return True
    
    def get_schedule(self, schedule_id: str) -> Optional[ScheduledScan]:
        """Get a schedule by ID."""
        return self.schedules.get(schedule_id)
    
    def list_schedules(self, enabled_only: bool = False) -> List[ScheduledScan]:
        """List all schedules."""
        schedules = list(self.schedules.values())
        
        if enabled_only:
            schedules = [s for s in schedules if s.enabled]
        
        # Sort by next run time
        schedules.sort(key=lambda x: x.next_run or datetime.max)
        return schedules
    
    async def _process_schedules(self):
        """Process due schedules."""
        now = datetime.utcnow()
        
        for schedule in self.schedules.values():
            if not schedule.enabled:
                continue
            
            if schedule.next_run and schedule.next_run <= now:
                await self._execute_scheduled_scan(schedule)
    
    async def _execute_scheduled_scan(self, schedule: ScheduledScan):
        """Execute a scheduled scan."""
        try:
            logger.info("Executing scheduled scan", 
                       schedule_id=schedule.schedule_id,
                       name=schedule.name)
            
            # Create scan
            scan_id = await self.orchestrator.create_scan(schedule.scan_request)
            
            # Update schedule
            schedule.last_run = datetime.utcnow()
            schedule.run_count += 1
            schedule.next_run = self._calculate_next_run(schedule.cron_expression)
            
            # Emit event
            await self.event_bus.publish(
                "schedule.executed",
                {
                    "schedule_id": schedule.schedule_id,
                    "name": schedule.name,
                    "scan_id": scan_id,
                    "run_count": schedule.run_count,
                    "last_run": schedule.last_run.isoformat(),
                    "next_run": schedule.next_run.isoformat() if schedule.next_run else None
                }
            )
            
            logger.info("Scheduled scan executed", 
                       schedule_id=schedule.schedule_id,
                       scan_id=scan_id,
                       next_run=schedule.next_run)
            
        except Exception as e:
            logger.error("Failed to execute scheduled scan", 
                        schedule_id=schedule.schedule_id,
                        error=str(e))
            
            # Calculate next run even on failure
            schedule.next_run = self._calculate_next_run(schedule.cron_expression)
    
    def _calculate_next_run(self, cron_expression: str) -> Optional[datetime]:
        """Calculate next run time from cron expression."""
        # Simplified cron parsing - in production, use croniter library
        try:
            if cron_expression == "0 0 * * *":  # Daily at midnight
                now = datetime.utcnow()
                next_run = now.replace(hour=0, minute=0, second=0, microsecond=0)
                if next_run <= now:
                    next_run += timedelta(days=1)
                return next_run
            
            elif cron_expression == "0 */6 * * *":  # Every 6 hours
                now = datetime.utcnow()
                next_hour = (now.hour // 6 + 1) * 6
                if next_hour >= 24:
                    next_run = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
                else:
                    next_run = now.replace(hour=next_hour, minute=0, second=0, microsecond=0)
                return next_run
            
            elif cron_expression == "0 0 * * 0":  # Weekly on Sunday
                now = datetime.utcnow()
                days_until_sunday = (6 - now.weekday()) % 7
                if days_until_sunday == 0 and now.hour >= 0:
                    days_until_sunday = 7
                next_run = (now + timedelta(days=days_until_sunday)).replace(
                    hour=0, minute=0, second=0, microsecond=0)
                return next_run
            
            else:
                # Default: run in 1 hour
                return datetime.utcnow() + timedelta(hours=1)
                
        except Exception as e:
            logger.error("Failed to parse cron expression", 
                        cron_expression=cron_expression, error=str(e))
            return None
    
    async def _load_schedules(self):
        """Load existing schedules from storage."""
        # In production, load from database
        # For now, create some sample schedules
        
        sample_schedules = [
            {
                "name": "Daily Redis Scan",
                "description": "Daily vulnerability scan of Redis container",
                "scan_request": {
                    "target": "redis:latest",
                    "scanners": ["grype", "trivy"],
                    "priority": "normal"
                },
                "cron_expression": "0 0 * * *",  # Daily at midnight
                "enabled": True
            },
            {
                "name": "Weekly Infrastructure Scan",
                "description": "Weekly comprehensive scan of infrastructure",
                "scan_request": {
                    "target": "nginx:latest",
                    "scanners": ["grype", "trivy", "syft"],
                    "priority": "high"
                },
                "cron_expression": "0 0 * * 0",  # Weekly on Sunday
                "enabled": True
            }
        ]
        
        for schedule_data in sample_schedules:
            await self.create_schedule(schedule_data)