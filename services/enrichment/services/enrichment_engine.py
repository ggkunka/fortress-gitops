"""Core enrichment engine for orchestrating data enrichment."""

import asyncio
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from uuid import uuid4

import structlog
from shared.event_bus import RedisEventBus

from ..schemas.enrichment import (
    EnrichmentRequest, EnrichmentResponse, EnrichmentResult,
    EnrichmentTask, EnrichmentStatus, EnrichmentType
)
from ..schemas.events import (
    EnrichmentStartedEvent, EnrichmentCompletedEvent, EnrichmentFailedEvent,
    EnrichmentProgressEvent, EnrichmentTimeoutEvent
)
from .threat_intelligence import ThreatIntelligenceService
from .mitre_attack import MitreAttackService
from .enrichment_processor import EnrichmentProcessor
from .caching import CachingService

logger = structlog.get_logger()


class EnrichmentEngine:
    """Core enrichment engine that orchestrates data enrichment."""
    
    def __init__(self):
        self.event_bus = RedisEventBus(service_name="enrichment")
        self.threat_intelligence_service = ThreatIntelligenceService()
        self.mitre_attack_service = MitreAttackService()
        self.enrichment_processor = EnrichmentProcessor()
        self.caching_service = CachingService()
        
        self.logger = logger.bind(service="enrichment", component="enrichment_engine")
        self.is_running = False
        self.active_tasks: Dict[str, EnrichmentTask] = {}
        self.task_queue: asyncio.Queue = asyncio.Queue()
        self.worker_tasks: List[asyncio.Task] = []
        self.max_concurrent_tasks = 10
        
        # Enrichment type to service mapping
        self.enrichment_services = {
            EnrichmentType.THREAT_INTELLIGENCE: self.threat_intelligence_service,
            EnrichmentType.MITRE_ATTACK: self.mitre_attack_service,
            EnrichmentType.VULNERABILITY_ANALYSIS: self.enrichment_processor,
            EnrichmentType.BEHAVIORAL_ANALYSIS: self.enrichment_processor,
            EnrichmentType.CONTEXTUAL_ANALYSIS: self.enrichment_processor,
            EnrichmentType.RISK_ASSESSMENT: self.enrichment_processor,
        }
    
    async def start(self) -> None:
        """Start the enrichment engine."""
        try:
            # Connect to event bus
            await self.event_bus.connect()
            
            # Start services
            await self.threat_intelligence_service.start()
            await self.mitre_attack_service.start()
            await self.enrichment_processor.start()
            await self.caching_service.start()
            
            # Start worker tasks
            self.worker_tasks = [
                asyncio.create_task(self._worker(f"worker_{i}"))
                for i in range(self.max_concurrent_tasks)
            ]
            
            # Start cleanup task
            asyncio.create_task(self._cleanup_expired_tasks())
            
            self.is_running = True
            self.logger.info("Enrichment engine started successfully")
            
        except Exception as e:
            self.logger.error("Failed to start enrichment engine", error=str(e))
            raise
    
    async def stop(self) -> None:
        """Stop the enrichment engine."""
        try:
            self.is_running = False
            
            # Cancel worker tasks
            for task in self.worker_tasks:
                task.cancel()
            
            # Wait for workers to finish
            if self.worker_tasks:
                await asyncio.gather(*self.worker_tasks, return_exceptions=True)
            
            # Stop services
            await self.threat_intelligence_service.stop()
            await self.mitre_attack_service.stop()
            await self.enrichment_processor.stop()
            await self.caching_service.stop()
            
            # Disconnect from event bus
            await self.event_bus.disconnect()
            
            self.logger.info("Enrichment engine stopped successfully")
            
        except Exception as e:
            self.logger.error("Error stopping enrichment engine", error=str(e))
            raise
    
    async def enrich_data(self, request: EnrichmentRequest) -> str:
        """Submit data for enrichment."""
        try:
            # Create enrichment task
            task = EnrichmentTask(
                task_id=str(uuid4()),
                request=request,
                created_at=datetime.utcnow(),
                expires_at=datetime.utcnow() + timedelta(seconds=request.timeout_seconds),
            )
            
            # Add to active tasks
            self.active_tasks[task.task_id] = task
            
            # Add to queue
            await self.task_queue.put(task)
            
            self.logger.info(
                "Enrichment task queued",
                task_id=task.task_id,
                request_id=request.request_id,
                data_type=request.data_type,
                enrichment_types=request.enrichment_types
            )
            
            return task.task_id
            
        except Exception as e:
            self.logger.error(
                "Error queuing enrichment task",
                request_id=request.request_id,
                error=str(e)
            )
            raise
    
    async def get_enrichment_status(self, task_id: str) -> Optional[EnrichmentTask]:
        """Get the status of an enrichment task."""
        return self.active_tasks.get(task_id)
    
    async def cancel_enrichment(self, task_id: str) -> bool:
        """Cancel an enrichment task."""
        if task_id in self.active_tasks:
            task = self.active_tasks[task_id]
            task.status = EnrichmentStatus.CANCELLED
            
            self.logger.info(
                "Enrichment task cancelled",
                task_id=task_id,
                request_id=task.request.request_id
            )
            
            return True
        
        return False
    
    async def _worker(self, worker_id: str) -> None:
        """Worker task for processing enrichment requests."""
        worker_logger = self.logger.bind(worker_id=worker_id)
        
        while self.is_running:
            try:
                # Get task from queue
                task = await asyncio.wait_for(self.task_queue.get(), timeout=1.0)
                
                # Check if task is expired or cancelled
                if task.is_expired() or task.status == EnrichmentStatus.CANCELLED:
                    self.task_queue.task_done()
                    continue
                
                # Process the task
                await self._process_enrichment_task(task, worker_id)
                
                # Mark task as done
                self.task_queue.task_done()
                
            except asyncio.TimeoutError:
                # No task available, continue
                continue
            except Exception as e:
                worker_logger.error("Error in worker", error=str(e))
                await asyncio.sleep(1)
    
    async def _process_enrichment_task(self, task: EnrichmentTask, worker_id: str) -> None:
        """Process a single enrichment task."""
        try:
            # Update task status
            task.status = EnrichmentStatus.PROCESSING
            task.assigned_worker = worker_id
            task.started_at = datetime.utcnow()
            
            # Publish started event
            await self._publish_started_event(task)
            
            # Process enrichment
            response = await self._perform_enrichment(task)
            
            # Update task with result
            task.result = response
            task.status = EnrichmentStatus.COMPLETED
            task.completed_at = datetime.utcnow()
            
            # Publish completed event
            await self._publish_completed_event(task)
            
            self.logger.info(
                "Enrichment task completed",
                task_id=task.task_id,
                request_id=task.request.request_id,
                processing_time=response.total_processing_time
            )
            
        except Exception as e:
            # Handle task failure
            task.status = EnrichmentStatus.FAILED
            task.error = str(e)
            task.completed_at = datetime.utcnow()
            
            # Publish failed event
            await self._publish_failed_event(task, str(e))
            
            self.logger.error(
                "Enrichment task failed",
                task_id=task.task_id,
                request_id=task.request.request_id,
                error=str(e)
            )
            
            # Retry if possible
            if task.can_retry():
                await self._retry_task(task)
        
        finally:
            # Remove from active tasks if completed or failed
            if task.status in [EnrichmentStatus.COMPLETED, EnrichmentStatus.FAILED]:
                self.active_tasks.pop(task.task_id, None)
    
    async def _perform_enrichment(self, task: EnrichmentTask) -> EnrichmentResponse:
        """Perform the actual enrichment process."""
        request = task.request
        start_time = datetime.utcnow()
        
        # Initialize response
        response = EnrichmentResponse(
            request_id=request.request_id,
            status=EnrichmentStatus.PROCESSING,
            data_type=request.data_type,
            original_data=request.data,
            enriched_data=request.data.copy(),
            started_at=start_time,
            correlation_id=request.correlation_id,
        )
        
        # Check cache first
        cached_result = await self.caching_service.get_enrichment_result(
            data_type=request.data_type,
            data=request.data,
            enrichment_types=request.enrichment_types
        )
        
        if cached_result:
            self.logger.info(
                "Using cached enrichment result",
                request_id=request.request_id,
                cache_hit=True
            )
            return cached_result
        
        # Perform enrichment for each type
        total_steps = len(request.enrichment_types)
        completed_steps = 0
        
        for enrichment_type in request.enrichment_types:
            try:
                # Publish progress event
                await self._publish_progress_event(
                    task, enrichment_type.value, total_steps, completed_steps
                )
                
                # Get enrichment service
                service = self.enrichment_services.get(enrichment_type)
                if not service:
                    raise ValueError(f"Unknown enrichment type: {enrichment_type}")
                
                # Perform enrichment
                step_start_time = datetime.utcnow()
                result = await service.enrich(request.data, request.data_type)
                step_duration = (datetime.utcnow() - step_start_time).total_seconds()
                
                # Create enrichment result
                enrichment_result = EnrichmentResult(
                    enrichment_type=enrichment_type,
                    status=EnrichmentStatus.COMPLETED,
                    data=result.get("data", {}),
                    confidence=result.get("confidence", 0.0),
                    sources=result.get("sources", []),
                    processing_time=step_duration,
                    metadata=result.get("metadata", {}),
                )
                
                # Add to response
                response.results.append(enrichment_result)
                
                # Merge enriched data
                if "enriched_data" in result:
                    self._merge_enriched_data(
                        response.enriched_data,
                        result["enriched_data"]
                    )
                
                completed_steps += 1
                
            except Exception as e:
                # Handle enrichment failure
                enrichment_result = EnrichmentResult(
                    enrichment_type=enrichment_type,
                    status=EnrichmentStatus.FAILED,
                    confidence=0.0,
                    processing_time=0.0,
                    errors=[str(e)],
                )
                
                response.results.append(enrichment_result)
                response.errors.append(f"{enrichment_type.value}: {str(e)}")
                
                self.logger.error(
                    "Enrichment step failed",
                    request_id=request.request_id,
                    enrichment_type=enrichment_type,
                    error=str(e)
                )
        
        # Finalize response
        response.status = EnrichmentStatus.COMPLETED
        response.completed_at = datetime.utcnow()
        response.total_processing_time = (
            response.completed_at - response.started_at
        ).total_seconds()
        
        # Cache result if successful
        if not response.errors:
            await self.caching_service.cache_enrichment_result(
                data_type=request.data_type,
                data=request.data,
                enrichment_types=request.enrichment_types,
                result=response
            )
        
        return response
    
    def _merge_enriched_data(self, target: Dict[str, Any], source: Dict[str, Any]) -> None:
        """Merge enriched data from different sources."""
        for key, value in source.items():
            if key in target:
                # Merge lists
                if isinstance(target[key], list) and isinstance(value, list):
                    target[key].extend(value)
                # Merge dictionaries
                elif isinstance(target[key], dict) and isinstance(value, dict):
                    target[key].update(value)
                # Override other values
                else:
                    target[key] = value
            else:
                target[key] = value
    
    async def _retry_task(self, task: EnrichmentTask) -> None:
        """Retry a failed enrichment task."""
        task.retry_count += 1
        task.status = EnrichmentStatus.PENDING
        task.assigned_worker = None
        task.started_at = None
        task.completed_at = None
        task.error = None
        
        # Add back to queue with delay
        await asyncio.sleep(2 ** task.retry_count)  # Exponential backoff
        await self.task_queue.put(task)
        
        self.logger.info(
            "Enrichment task retried",
            task_id=task.task_id,
            retry_count=task.retry_count,
            max_retries=task.max_retries
        )
    
    async def _cleanup_expired_tasks(self) -> None:
        """Clean up expired and completed tasks."""
        while self.is_running:
            try:
                current_time = datetime.utcnow()
                expired_tasks = []
                
                for task_id, task in self.active_tasks.items():
                    if task.is_expired():
                        expired_tasks.append(task_id)
                        
                        # Publish timeout event
                        await self._publish_timeout_event(task)
                
                # Remove expired tasks
                for task_id in expired_tasks:
                    self.active_tasks.pop(task_id, None)
                
                # Sleep for 60 seconds before next cleanup
                await asyncio.sleep(60)
                
            except Exception as e:
                self.logger.error("Error in cleanup task", error=str(e))
                await asyncio.sleep(60)
    
    async def _publish_started_event(self, task: EnrichmentTask) -> None:
        """Publish enrichment started event."""
        try:
            event = EnrichmentStartedEvent(
                event_id=str(uuid4()),
                request_id=task.request.request_id,
                data_type=task.request.data_type,
                enrichment_types=[t.value for t in task.request.enrichment_types],
                priority=task.request.priority,
                timeout_seconds=task.request.timeout_seconds,
                correlation_id=task.request.correlation_id,
            )
            
            await self.event_bus.publish(
                event_type=event.event_type,
                data=event.model_dump(),
                correlation_id=event.correlation_id,
            )
            
        except Exception as e:
            self.logger.error("Failed to publish started event", error=str(e))
    
    async def _publish_completed_event(self, task: EnrichmentTask) -> None:
        """Publish enrichment completed event."""
        try:
            event = EnrichmentCompletedEvent(
                event_id=str(uuid4()),
                request_id=task.request.request_id,
                data_type=task.request.data_type,
                processing_time=task.result.total_processing_time,
                enrichment_response=task.result,
                correlation_id=task.request.correlation_id,
            )
            
            await self.event_bus.publish(
                event_type=event.event_type,
                data=event.model_dump(),
                correlation_id=event.correlation_id,
            )
            
        except Exception as e:
            self.logger.error("Failed to publish completed event", error=str(e))
    
    async def _publish_failed_event(self, task: EnrichmentTask, error: str) -> None:
        """Publish enrichment failed event."""
        try:
            processing_time = 0.0
            if task.started_at:
                processing_time = (
                    datetime.utcnow() - task.started_at
                ).total_seconds()
            
            event = EnrichmentFailedEvent(
                event_id=str(uuid4()),
                request_id=task.request.request_id,
                data_type=task.request.data_type,
                error_type="processing_error",
                error_message=error,
                processing_time=processing_time,
                retry_count=task.retry_count,
                is_retryable=task.can_retry(),
                correlation_id=task.request.correlation_id,
            )
            
            await self.event_bus.publish(
                event_type=event.event_type,
                data=event.model_dump(),
                correlation_id=event.correlation_id,
            )
            
        except Exception as e:
            self.logger.error("Failed to publish failed event", error=str(e))
    
    async def _publish_progress_event(
        self,
        task: EnrichmentTask,
        current_step: str,
        total_steps: int,
        completed_steps: int
    ) -> None:
        """Publish enrichment progress event."""
        try:
            progress_percentage = (completed_steps / total_steps) * 100
            
            event = EnrichmentProgressEvent(
                event_id=str(uuid4()),
                request_id=task.request.request_id,
                data_type=task.request.data_type,
                current_step=current_step,
                total_steps=total_steps,
                completed_steps=completed_steps,
                progress_percentage=progress_percentage,
                correlation_id=task.request.correlation_id,
            )
            
            await self.event_bus.publish(
                event_type=event.event_type,
                data=event.model_dump(),
                correlation_id=event.correlation_id,
            )
            
        except Exception as e:
            self.logger.error("Failed to publish progress event", error=str(e))
    
    async def _publish_timeout_event(self, task: EnrichmentTask) -> None:
        """Publish enrichment timeout event."""
        try:
            processing_time = 0.0
            if task.started_at:
                processing_time = (
                    datetime.utcnow() - task.started_at
                ).total_seconds()
            
            event = EnrichmentTimeoutEvent(
                event_id=str(uuid4()),
                request_id=task.request.request_id,
                data_type=task.request.data_type,
                timeout_seconds=task.request.timeout_seconds,
                processing_time=processing_time,
                correlation_id=task.request.correlation_id,
            )
            
            await self.event_bus.publish(
                event_type=event.event_type,
                data=event.model_dump(),
                correlation_id=event.correlation_id,
            )
            
        except Exception as e:
            self.logger.error("Failed to publish timeout event", error=str(e))
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on the enrichment engine."""
        health_status = {
            "service": "enrichment_engine",
            "status": "healthy" if self.is_running else "stopped",
            "active_tasks": len(self.active_tasks),
            "queue_size": self.task_queue.qsize(),
            "worker_count": len(self.worker_tasks),
            "timestamp": datetime.utcnow().isoformat(),
        }
        
        # Check services health
        try:
            services_health = {
                "threat_intelligence": await self.threat_intelligence_service.health_check(),
                "mitre_attack": await self.mitre_attack_service.health_check(),
                "enrichment_processor": await self.enrichment_processor.health_check(),
                "caching": await self.caching_service.health_check(),
            }
            health_status["services"] = services_health
        except Exception as e:
            health_status["services_error"] = str(e)
        
        return health_status
    
    def get_stats(self) -> Dict[str, Any]:
        """Get enrichment engine statistics."""
        return {
            "service": "enrichment_engine",
            "is_running": self.is_running,
            "active_tasks": len(self.active_tasks),
            "queue_size": self.task_queue.qsize(),
            "worker_count": len(self.worker_tasks),
            "max_concurrent_tasks": self.max_concurrent_tasks,
            "timestamp": datetime.utcnow().isoformat(),
        }