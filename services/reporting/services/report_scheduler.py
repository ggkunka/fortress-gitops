"""
Report Scheduler - Automated Report Generation Scheduler

This service handles scheduled report generation and delivery.
"""

import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set
from uuid import UUID
import croniter

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced
from shared.events.event_bus import EventBus

from ..models.reporting import ReportSchedule, ScheduleFrequency, get_db
from .report_generator import ReportGenerator

logger = get_logger(__name__)
metrics = get_metrics()


class ReportScheduler:
    """
    Report scheduler for automated report generation and delivery.
    
    This scheduler:
    1. Monitors scheduled reports
    2. Triggers report generation at specified times
    3. Handles delivery to recipients
    4. Manages schedule lifecycle
    """
    
    def __init__(self, report_generator: ReportGenerator, event_bus: EventBus):
        self.report_generator = report_generator
        self.event_bus = event_bus
        
        # Scheduler state
        self.running = False
        self.scheduler_task = None
        self.active_schedules: Dict[UUID, ReportSchedule] = {}
        
        # Check interval (in seconds)
        self.check_interval = 60  # Check every minute
        
        logger.info("Report scheduler initialized")
    
    async def start(self):
        """Start the report scheduler."""
        if self.running:
            return
        
        self.running = True
        
        # Load active schedules
        await self._load_active_schedules()
        
        # Start scheduler task
        self.scheduler_task = asyncio.create_task(self._run_scheduler())
        
        logger.info("Report scheduler started")
    
    async def stop(self):
        """Stop the report scheduler."""
        if not self.running:
            return
        
        self.running = False
        
        # Cancel scheduler task
        if self.scheduler_task:
            self.scheduler_task.cancel()
            try:
                await self.scheduler_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Report scheduler stopped")
    
    @traced("report_scheduler_run")
    async def _run_scheduler(self):
        """Main scheduler loop."""
        while self.running:
            try:
                # Check for due schedules
                await self._check_due_schedules()
                
                # Reload schedules periodically
                await self._load_active_schedules()
                
                # Wait before next check
                await asyncio.sleep(self.check_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in scheduler loop: {e}")
                await asyncio.sleep(5)  # Wait before retrying
    
    async def _load_active_schedules(self):
        """Load active schedules from database."""
        try:
            with get_db() as db:
                schedules = db.query(ReportSchedule).filter(
                    ReportSchedule.is_active == True
                ).all()
                
                # Update active schedules
                self.active_schedules = {schedule.id: schedule for schedule in schedules}
                
                # Calculate next run times for new schedules
                for schedule in schedules:
                    if schedule.next_run is None:
                        next_run = self._calculate_next_run(schedule)
                        schedule.next_run = next_run
                        db.commit()
                
                logger.debug(f"Loaded {len(schedules)} active schedules")
                
        except Exception as e:
            logger.error(f"Error loading active schedules: {e}")
    
    async def _check_due_schedules(self):
        """Check for schedules that are due to run."""
        now = datetime.now()
        
        for schedule_id, schedule in self.active_schedules.items():
            try:
                if schedule.next_run and schedule.next_run <= now:
                    if not schedule.is_running:
                        await self._execute_schedule(schedule)
                    
            except Exception as e:
                logger.error(f"Error checking schedule {schedule_id}: {e}")
    
    @traced("report_scheduler_execute_schedule")
    async def _execute_schedule(self, schedule: ReportSchedule):
        """Execute a scheduled report."""
        try:
            logger.info(f"Executing scheduled report: {schedule.name}")
            
            # Mark schedule as running
            with get_db() as db:
                db_schedule = db.query(ReportSchedule).filter(
                    ReportSchedule.id == schedule.id
                ).first()
                
                if db_schedule:
                    db_schedule.is_running = True
                    db_schedule.last_run = datetime.now()
                    db.commit()
            
            # Create report copy for this execution
            report_copy = await self._create_report_copy(schedule)
            
            # Generate report
            success = await self.report_generator.generate_report(report_copy.id)
            
            if success:
                # Deliver report to recipients
                await self._deliver_report(schedule, report_copy)
                
                # Update schedule metrics
                await self._update_schedule_success(schedule)
                
                logger.info(f"Scheduled report executed successfully: {schedule.name}")
                metrics.report_scheduler_executions_success.inc()
                
            else:
                await self._update_schedule_failure(schedule, "Report generation failed")
                logger.error(f"Scheduled report execution failed: {schedule.name}")
                metrics.report_scheduler_executions_failed.inc()
            
        except Exception as e:
            logger.error(f"Error executing schedule {schedule.id}: {e}")
            await self._update_schedule_failure(schedule, str(e))
            metrics.report_scheduler_executions_failed.inc()
        
        finally:
            # Mark schedule as not running and calculate next run
            with get_db() as db:
                db_schedule = db.query(ReportSchedule).filter(
                    ReportSchedule.id == schedule.id
                ).first()
                
                if db_schedule:
                    db_schedule.is_running = False
                    db_schedule.next_run = self._calculate_next_run(db_schedule)
                    db.commit()
    
    async def _create_report_copy(self, schedule: ReportSchedule):
        """Create a copy of the report for scheduled execution."""
        try:
            with get_db() as db:
                # Get the original report
                original_report = db.query(Report).filter(
                    Report.id == schedule.report_id
                ).first()
                
                if not original_report:
                    raise ValueError(f"Original report not found: {schedule.report_id}")
                
                # Create a copy with updated dates
                from ..models.reporting import Report, ReportStatus
                
                report_copy = Report(
                    title=f"{original_report.title} - {datetime.now().strftime('%Y-%m-%d %H:%M')}",
                    description=original_report.description,
                    report_type=original_report.report_type,
                    format=original_report.format,
                    template_id=original_report.template_id,
                    data_sources=original_report.data_sources,
                    filters=original_report.filters,
                    parameters=original_report.parameters,
                    start_date=self._calculate_report_start_date(schedule),
                    end_date=self._calculate_report_end_date(schedule),
                    timezone=original_report.timezone,
                    status=ReportStatus.DRAFT,
                    created_by=f"scheduler_{schedule.id}",
                    visibility="private"
                )
                
                db.add(report_copy)
                db.commit()
                db.refresh(report_copy)
                
                return report_copy
                
        except Exception as e:
            logger.error(f"Error creating report copy: {e}")
            raise
    
    async def _deliver_report(self, schedule: ReportSchedule, report):
        """Deliver report to recipients."""
        try:
            delivery_method = schedule.delivery_method
            
            if delivery_method == "email":
                await self._deliver_via_email(schedule, report)
            elif delivery_method == "slack":
                await self._deliver_via_slack(schedule, report)
            elif delivery_method == "webhook":
                await self._deliver_via_webhook(schedule, report)
            else:
                logger.warning(f"Unknown delivery method: {delivery_method}")
            
        except Exception as e:
            logger.error(f"Error delivering report: {e}")
            raise
    
    async def _deliver_via_email(self, schedule: ReportSchedule, report):
        """Deliver report via email."""
        try:
            # This would integrate with an email service
            # For now, just log the delivery
            logger.info(f"Email delivery: {schedule.name} to {schedule.recipients}")
            
            # Publish event for email delivery
            await self.event_bus.publish("report.email_delivery", {
                "schedule_id": str(schedule.id),
                "report_id": str(report.id),
                "recipients": schedule.recipients,
                "report_title": report.title,
                "report_path": report.file_path
            })
            
        except Exception as e:
            logger.error(f"Error delivering via email: {e}")
            raise
    
    async def _deliver_via_slack(self, schedule: ReportSchedule, report):
        """Deliver report via Slack."""
        try:
            # This would integrate with Slack API
            # For now, just log the delivery
            logger.info(f"Slack delivery: {schedule.name} to {schedule.recipients}")
            
            # Publish event for Slack delivery
            await self.event_bus.publish("report.slack_delivery", {
                "schedule_id": str(schedule.id),
                "report_id": str(report.id),
                "channels": schedule.recipients,
                "report_title": report.title,
                "report_path": report.file_path
            })
            
        except Exception as e:
            logger.error(f"Error delivering via Slack: {e}")
            raise
    
    async def _deliver_via_webhook(self, schedule: ReportSchedule, report):
        """Deliver report via webhook."""
        try:
            # This would make HTTP POST to webhook URLs
            # For now, just log the delivery
            logger.info(f"Webhook delivery: {schedule.name} to {schedule.recipients}")
            
            # Publish event for webhook delivery
            await self.event_bus.publish("report.webhook_delivery", {
                "schedule_id": str(schedule.id),
                "report_id": str(report.id),
                "webhooks": schedule.recipients,
                "report_title": report.title,
                "report_path": report.file_path
            })
            
        except Exception as e:
            logger.error(f"Error delivering via webhook: {e}")
            raise
    
    def _calculate_next_run(self, schedule: ReportSchedule) -> datetime:
        """Calculate next run time for a schedule."""
        try:
            now = datetime.now()
            
            if schedule.cron_expression:
                # Use cron expression
                cron = croniter.croniter(schedule.cron_expression, now)
                return cron.get_next(datetime)
            
            else:
                # Use frequency
                if schedule.frequency == ScheduleFrequency.HOURLY:
                    return now + timedelta(hours=1)
                elif schedule.frequency == ScheduleFrequency.DAILY:
                    return now + timedelta(days=1)
                elif schedule.frequency == ScheduleFrequency.WEEKLY:
                    return now + timedelta(weeks=1)
                elif schedule.frequency == ScheduleFrequency.MONTHLY:
                    return now + timedelta(days=30)
                elif schedule.frequency == ScheduleFrequency.QUARTERLY:
                    return now + timedelta(days=90)
                elif schedule.frequency == ScheduleFrequency.ANNUALLY:
                    return now + timedelta(days=365)
                else:
                    return now + timedelta(days=1)  # Default to daily
                    
        except Exception as e:
            logger.error(f"Error calculating next run: {e}")
            return datetime.now() + timedelta(days=1)  # Default to tomorrow
    
    def _calculate_report_start_date(self, schedule: ReportSchedule) -> datetime:
        """Calculate start date for report based on schedule frequency."""
        now = datetime.now()
        
        if schedule.frequency == ScheduleFrequency.HOURLY:
            return now - timedelta(hours=1)
        elif schedule.frequency == ScheduleFrequency.DAILY:
            return now - timedelta(days=1)
        elif schedule.frequency == ScheduleFrequency.WEEKLY:
            return now - timedelta(weeks=1)
        elif schedule.frequency == ScheduleFrequency.MONTHLY:
            return now - timedelta(days=30)
        elif schedule.frequency == ScheduleFrequency.QUARTERLY:
            return now - timedelta(days=90)
        elif schedule.frequency == ScheduleFrequency.ANNUALLY:
            return now - timedelta(days=365)
        else:
            return now - timedelta(days=1)  # Default to last day
    
    def _calculate_report_end_date(self, schedule: ReportSchedule) -> datetime:
        """Calculate end date for report."""
        return datetime.now()
    
    async def _update_schedule_success(self, schedule: ReportSchedule):
        """Update schedule after successful execution."""
        try:
            with get_db() as db:
                db_schedule = db.query(ReportSchedule).filter(
                    ReportSchedule.id == schedule.id
                ).first()
                
                if db_schedule:
                    db_schedule.execution_count += 1
                    db_schedule.success_count += 1
                    db_schedule.last_error = None
                    db.commit()
                    
        except Exception as e:
            logger.error(f"Error updating schedule success: {e}")
    
    async def _update_schedule_failure(self, schedule: ReportSchedule, error_message: str):
        """Update schedule after failed execution."""
        try:
            with get_db() as db:
                db_schedule = db.query(ReportSchedule).filter(
                    ReportSchedule.id == schedule.id
                ).first()
                
                if db_schedule:
                    db_schedule.execution_count += 1
                    db_schedule.failure_count += 1
                    db_schedule.last_error = error_message
                    db.commit()
                    
        except Exception as e:
            logger.error(f"Error updating schedule failure: {e}")
    
    async def create_schedule(
        self,
        report_id: UUID,
        name: str,
        frequency: ScheduleFrequency,
        recipients: List[str],
        delivery_method: str = "email",
        cron_expression: Optional[str] = None,
        delivery_config: Optional[Dict[str, Any]] = None
    ) -> ReportSchedule:
        """Create a new report schedule."""
        try:
            with get_db() as db:
                schedule = ReportSchedule(
                    report_id=report_id,
                    name=name,
                    frequency=frequency,
                    cron_expression=cron_expression,
                    recipients=recipients,
                    delivery_method=delivery_method,
                    delivery_config=delivery_config or {},
                    is_active=True,
                    created_by="api_user"
                )
                
                # Calculate next run
                schedule.next_run = self._calculate_next_run(schedule)
                
                db.add(schedule)
                db.commit()
                db.refresh(schedule)
                
                # Add to active schedules
                self.active_schedules[schedule.id] = schedule
                
                logger.info(f"Created schedule: {schedule.name}")
                
                return schedule
                
        except Exception as e:
            logger.error(f"Error creating schedule: {e}")
            raise
    
    async def update_schedule(
        self,
        schedule_id: UUID,
        updates: Dict[str, Any]
    ) -> Optional[ReportSchedule]:
        """Update an existing schedule."""
        try:
            with get_db() as db:
                schedule = db.query(ReportSchedule).filter(
                    ReportSchedule.id == schedule_id
                ).first()
                
                if not schedule:
                    return None
                
                # Update fields
                for field, value in updates.items():
                    if hasattr(schedule, field):
                        setattr(schedule, field, value)
                
                # Recalculate next run if frequency changed
                if "frequency" in updates or "cron_expression" in updates:
                    schedule.next_run = self._calculate_next_run(schedule)
                
                db.commit()
                db.refresh(schedule)
                
                # Update active schedules
                self.active_schedules[schedule_id] = schedule
                
                logger.info(f"Updated schedule: {schedule.name}")
                
                return schedule
                
        except Exception as e:
            logger.error(f"Error updating schedule: {e}")
            raise
    
    async def delete_schedule(self, schedule_id: UUID) -> bool:
        """Delete a schedule."""
        try:
            with get_db() as db:
                schedule = db.query(ReportSchedule).filter(
                    ReportSchedule.id == schedule_id
                ).first()
                
                if not schedule:
                    return False
                
                db.delete(schedule)
                db.commit()
                
                # Remove from active schedules
                if schedule_id in self.active_schedules:
                    del self.active_schedules[schedule_id]
                
                logger.info(f"Deleted schedule: {schedule.name}")
                
                return True
                
        except Exception as e:
            logger.error(f"Error deleting schedule: {e}")
            return False
    
    def get_stats(self) -> Dict[str, Any]:
        """Get scheduler statistics."""
        return {
            "running": self.running,
            "active_schedules": len(self.active_schedules),
            "check_interval": self.check_interval,
            "next_executions": [
                {
                    "schedule_id": str(schedule.id),
                    "name": schedule.name,
                    "next_run": schedule.next_run.isoformat() if schedule.next_run else None
                }
                for schedule in list(self.active_schedules.values())[:10]  # Show next 10
            ]
        }