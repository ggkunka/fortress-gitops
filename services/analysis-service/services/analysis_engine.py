"""
Analysis Engine - Core Analysis Orchestrator

This service orchestrates various types of security analysis including
anomaly detection, behavioral analysis, pattern analysis, and threat analysis.
"""

import asyncio
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set
from uuid import UUID
from dataclasses import dataclass

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced
from shared.events.event_bus import EventBus

from ..models.analysis import (
    AnalysisJob, AnalysisResult, AnalysisType, AnalysisStatus, SeverityLevel,
    create_analysis_job, create_analysis_result, get_db
)
from .anomaly_detector import AnomalyDetector
from .behavioral_analyzer import BehavioralAnalyzer
from .pattern_analyzer import PatternAnalyzer
from .threat_analyzer import ThreatAnalyzer
from .baseline_manager import BaselineManager

logger = get_logger(__name__)
metrics = get_metrics()


@dataclass
class AnalysisRequest:
    """Analysis request model."""
    analysis_type: AnalysisType
    input_source: str
    input_data: Dict[str, Any]
    parameters: Dict[str, Any]
    priority: int = 5
    requested_by: str = "system"


class AnalysisEngine:
    """
    Core analysis engine that orchestrates various types of security analysis.
    
    This engine:
    1. Manages analysis job queue and execution
    2. Coordinates different analysis services
    3. Aggregates and correlates results
    4. Publishes analysis results to downstream services
    """
    
    def __init__(self, event_bus: EventBus):
        self.event_bus = event_bus
        
        # Initialize analysis services
        self.anomaly_detector = AnomalyDetector()
        self.behavioral_analyzer = BehavioralAnalyzer()
        self.pattern_analyzer = PatternAnalyzer()
        self.threat_analyzer = ThreatAnalyzer()
        self.baseline_manager = BaselineManager()
        
        # Job management
        self.job_queue = asyncio.Queue()
        self.active_jobs: Dict[UUID, AnalysisJob] = {}
        self.processing_tasks: Set[asyncio.Task] = set()
        
        # Runtime state
        self.is_running = False
        self.max_concurrent_jobs = 10
        
        # Performance tracking
        self.stats = {
            'jobs_processed': 0,
            'jobs_completed': 0,
            'jobs_failed': 0,
            'active_jobs': 0,
            'avg_processing_time': 0.0
        }
        
        logger.info("Analysis engine initialized")
    
    async def start(self):
        """Start the analysis engine."""
        if self.is_running:
            logger.warning("Analysis engine is already running")
            return
        
        logger.info("Starting analysis engine...")
        
        try:
            # Subscribe to correlation results for analysis
            await self.event_bus.subscribe(
                "correlation.results.*",
                self._handle_correlation_result
            )
            
            # Subscribe to enriched events for behavioral analysis
            await self.event_bus.subscribe(
                "enrichment.events.*",
                self._handle_enriched_event
            )
            
            # Start job processor
            processor_task = asyncio.create_task(self._process_jobs())
            self.processing_tasks.add(processor_task)
            
            # Start baseline updater
            baseline_task = asyncio.create_task(self._update_baselines())
            self.processing_tasks.add(baseline_task)
            
            self.is_running = True
            logger.info("Analysis engine started successfully")
            metrics.analysis_engine_status.set(1)
            
        except Exception as e:
            logger.error(f"Failed to start analysis engine: {e}")
            metrics.analysis_engine_errors.inc()
            raise
    
    async def stop(self):
        """Stop the analysis engine."""
        if not self.is_running:
            return
        
        logger.info("Stopping analysis engine...")
        
        self.is_running = False
        
        # Cancel all processing tasks
        for task in self.processing_tasks:
            task.cancel()
        
        if self.processing_tasks:
            await asyncio.gather(*self.processing_tasks, return_exceptions=True)
        
        # Unsubscribe from events
        await self.event_bus.unsubscribe("correlation.results.*")
        await self.event_bus.unsubscribe("enrichment.events.*")
        
        logger.info("Analysis engine stopped")
        metrics.analysis_engine_status.set(0)
    
    @traced("analysis_engine_analyze")
    async def analyze(self, request: AnalysisRequest) -> UUID:
        """Submit analysis request and return job ID."""
        try:
            # Create analysis job
            job = create_analysis_job(
                name=f"{request.analysis_type.value}_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                analysis_type=request.analysis_type,
                input_source=request.input_source,
                input_config=request.input_data,
                parameters=request.parameters,
                created_by=request.requested_by
            )
            
            job.priority = request.priority
            
            # Save job to database
            with get_db() as db:
                db.add(job)
                db.commit()
                db.refresh(job)
            
            # Queue job for processing
            await self.job_queue.put(job)
            
            logger.info(f"Analysis job queued: {job.id}")
            metrics.analysis_engine_jobs_queued.inc()
            
            return job.id
            
        except Exception as e:
            logger.error(f"Error submitting analysis request: {e}")
            metrics.analysis_engine_errors.inc()
            raise
    
    async def _handle_correlation_result(self, event_data: Dict[str, Any]):
        """Handle correlation result events for analysis."""
        try:
            correlation_id = event_data.get("id")
            if not correlation_id:
                return
            
            # Create analysis request for threat analysis
            request = AnalysisRequest(
                analysis_type=AnalysisType.THREAT_ANALYSIS,
                input_source="correlation_result",
                input_data=event_data,
                parameters={
                    "correlation_id": correlation_id,
                    "analysis_depth": "deep"
                },
                priority=8,
                requested_by="correlation_engine"
            )
            
            await self.analyze(request)
            
        except Exception as e:
            logger.error(f"Error handling correlation result: {e}")
    
    async def _handle_enriched_event(self, event_data: Dict[str, Any]):
        """Handle enriched events for behavioral analysis."""
        try:
            # Create analysis request for behavioral analysis
            request = AnalysisRequest(
                analysis_type=AnalysisType.BEHAVIORAL_ANALYSIS,
                input_source="enriched_event",
                input_data=event_data,
                parameters={
                    "window_size": 3600,  # 1 hour
                    "entity_tracking": True
                },
                priority=5,
                requested_by="enrichment_service"
            )
            
            await self.analyze(request)
            
        except Exception as e:
            logger.error(f"Error handling enriched event: {e}")
    
    async def _process_jobs(self):
        """Process analysis job queue."""
        while self.is_running:
            try:
                # Get job from queue
                job = await self.job_queue.get()
                
                # Check concurrent job limit
                if len(self.active_jobs) >= self.max_concurrent_jobs:
                    # Put job back and wait
                    await self.job_queue.put(job)
                    await asyncio.sleep(1)
                    continue
                
                # Process job
                task = asyncio.create_task(self._execute_job(job))
                self.processing_tasks.add(task)
                task.add_done_callback(self.processing_tasks.discard)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error processing jobs: {e}")
                await asyncio.sleep(1)
    
    @traced("analysis_engine_execute_job")
    async def _execute_job(self, job: AnalysisJob):
        """Execute a single analysis job."""
        start_time = time.time()
        
        try:
            self.active_jobs[job.id] = job
            self.stats['active_jobs'] = len(self.active_jobs)
            
            # Update job status
            with get_db() as db:
                db_job = db.query(AnalysisJob).filter(AnalysisJob.id == job.id).first()
                if db_job:
                    db_job.status = AnalysisStatus.RUNNING
                    db_job.started_at = datetime.now()
                    db.commit()
            
            logger.info(f"Starting analysis job: {job.id} ({job.analysis_type})")
            
            # Execute analysis based on type
            results = []
            
            if job.analysis_type == AnalysisType.ANOMALY_DETECTION.value:
                results = await self._execute_anomaly_detection(job)
            elif job.analysis_type == AnalysisType.BEHAVIORAL_ANALYSIS.value:
                results = await self._execute_behavioral_analysis(job)
            elif job.analysis_type == AnalysisType.PATTERN_ANALYSIS.value:
                results = await self._execute_pattern_analysis(job)
            elif job.analysis_type == AnalysisType.THREAT_ANALYSIS.value:
                results = await self._execute_threat_analysis(job)
            elif job.analysis_type == AnalysisType.BASELINE_ANALYSIS.value:
                results = await self._execute_baseline_analysis(job)
            else:
                raise ValueError(f"Unsupported analysis type: {job.analysis_type}")
            
            # Save results and update job
            with get_db() as db:
                db_job = db.query(AnalysisJob).filter(AnalysisJob.id == job.id).first()
                if db_job:
                    db_job.status = AnalysisStatus.COMPLETED
                    db_job.completed_at = datetime.now()
                    db_job.execution_time = time.time() - start_time
                    db_job.results_count = len(results)
                    db_job.findings_count = sum(len(r.findings) for r in results if hasattr(r, 'findings'))
                    
                    # Save results
                    for result in results:
                        result.job_id = job.id
                        db.add(result)
                    
                    db.commit()
            
            # Publish results
            await self._publish_analysis_results(job, results)
            
            # Update statistics
            execution_time = time.time() - start_time
            self.stats['jobs_processed'] += 1
            self.stats['jobs_completed'] += 1
            self.stats['avg_processing_time'] = (
                (self.stats['avg_processing_time'] * (self.stats['jobs_processed'] - 1) + 
                 execution_time) / self.stats['jobs_processed']
            )
            
            metrics.analysis_engine_jobs_completed.inc()
            metrics.analysis_engine_processing_time.observe(execution_time)
            
            logger.info(f"Analysis job completed: {job.id} ({len(results)} results)")
            
        except Exception as e:
            logger.error(f"Error executing analysis job {job.id}: {e}")
            
            # Update job status to failed
            with get_db() as db:
                db_job = db.query(AnalysisJob).filter(AnalysisJob.id == job.id).first()
                if db_job:
                    db_job.status = AnalysisStatus.FAILED
                    db_job.completed_at = datetime.now()
                    db_job.execution_time = time.time() - start_time
                    db_job.error_message = str(e)
                    db.commit()
            
            self.stats['jobs_failed'] += 1
            metrics.analysis_engine_jobs_failed.inc()
            
        finally:
            # Remove from active jobs
            if job.id in self.active_jobs:
                del self.active_jobs[job.id]
            self.stats['active_jobs'] = len(self.active_jobs)
    
    async def _execute_anomaly_detection(self, job: AnalysisJob) -> List[AnalysisResult]:
        """Execute anomaly detection analysis."""
        results = []
        
        # Get input data
        input_data = job.input_config
        parameters = job.parameters
        
        # Run anomaly detection
        anomalies = await self.anomaly_detector.detect_anomalies(
            data=input_data,
            config=parameters
        )
        
        # Convert anomalies to analysis results
        for anomaly in anomalies:
            result = create_analysis_result(
                job_id=job.id,
                title=f"Anomaly Detected: {anomaly.get('type', 'Unknown')}",
                analysis_type=AnalysisType.ANOMALY_DETECTION,
                severity=SeverityLevel(anomaly.get('severity', 'medium')),
                confidence_score=anomaly.get('confidence', 0.5),
                risk_score=anomaly.get('risk_score', 50),
                finding_type="anomaly",
                description=anomaly.get('description', ''),
                affected_entities=anomaly.get('affected_entities', []),
                evidence=anomaly.get('evidence', {}),
                recommendations=anomaly.get('recommendations', [])
            )
            
            # Add anomaly-specific metadata
            result.baseline_deviation = anomaly.get('deviation')
            result.z_score = anomaly.get('z_score')
            result.p_value = anomaly.get('p_value')
            
            results.append(result)
        
        return results
    
    async def _execute_behavioral_analysis(self, job: AnalysisJob) -> List[AnalysisResult]:
        """Execute behavioral analysis."""
        results = []
        
        # Get input data
        input_data = job.input_config
        parameters = job.parameters
        
        # Run behavioral analysis
        behaviors = await self.behavioral_analyzer.analyze_behavior(
            data=input_data,
            config=parameters
        )
        
        # Convert behaviors to analysis results
        for behavior in behaviors:
            result = create_analysis_result(
                job_id=job.id,
                title=f"Behavioral Pattern: {behavior.get('pattern_name', 'Unknown')}",
                analysis_type=AnalysisType.BEHAVIORAL_ANALYSIS,
                severity=SeverityLevel(behavior.get('severity', 'medium')),
                confidence_score=behavior.get('confidence', 0.5),
                risk_score=behavior.get('risk_score', 50),
                finding_type="behavioral_pattern",
                description=behavior.get('description', ''),
                affected_entities=behavior.get('affected_entities', []),
                evidence=behavior.get('evidence', {}),
                recommendations=behavior.get('recommendations', [])
            )
            
            # Add behavioral-specific metadata
            result.observation_window = behavior.get('observation_window')
            result.first_observed = behavior.get('first_observed')
            result.last_observed = behavior.get('last_observed')
            
            results.append(result)
        
        return results
    
    async def _execute_pattern_analysis(self, job: AnalysisJob) -> List[AnalysisResult]:
        """Execute pattern analysis."""
        results = []
        
        # Get input data
        input_data = job.input_config
        parameters = job.parameters
        
        # Run pattern analysis
        patterns = await self.pattern_analyzer.analyze_patterns(
            data=input_data,
            config=parameters
        )
        
        # Convert patterns to analysis results
        for pattern in patterns:
            result = create_analysis_result(
                job_id=job.id,
                title=f"Pattern Match: {pattern.get('pattern_name', 'Unknown')}",
                analysis_type=AnalysisType.PATTERN_ANALYSIS,
                severity=SeverityLevel(pattern.get('severity', 'medium')),
                confidence_score=pattern.get('confidence', 0.5),
                risk_score=pattern.get('risk_score', 50),
                finding_type="pattern_match",
                description=pattern.get('description', ''),
                affected_entities=pattern.get('affected_entities', []),
                evidence=pattern.get('evidence', {}),
                recommendations=pattern.get('recommendations', [])
            )
            
            results.append(result)
        
        return results
    
    async def _execute_threat_analysis(self, job: AnalysisJob) -> List[AnalysisResult]:
        """Execute threat analysis."""
        results = []
        
        # Get input data
        input_data = job.input_config
        parameters = job.parameters
        
        # Run threat analysis
        threats = await self.threat_analyzer.analyze_threats(
            data=input_data,
            config=parameters
        )
        
        # Convert threats to analysis results
        for threat in threats:
            result = create_analysis_result(
                job_id=job.id,
                title=f"Threat Identified: {threat.get('threat_type', 'Unknown')}",
                analysis_type=AnalysisType.THREAT_ANALYSIS,
                severity=SeverityLevel(threat.get('severity', 'medium')),
                confidence_score=threat.get('confidence', 0.5),
                risk_score=threat.get('risk_score', 50),
                finding_type="threat",
                description=threat.get('description', ''),
                affected_entities=threat.get('affected_entities', []),
                evidence=threat.get('evidence', {}),
                recommendations=threat.get('recommendations', [])
            )
            
            results.append(result)
        
        return results
    
    async def _execute_baseline_analysis(self, job: AnalysisJob) -> List[AnalysisResult]:
        """Execute baseline analysis."""
        results = []
        
        # Get input data
        input_data = job.input_config
        parameters = job.parameters
        
        # Run baseline analysis
        baselines = await self.baseline_manager.analyze_baselines(
            data=input_data,
            config=parameters
        )
        
        # Convert baseline analysis to results
        for baseline in baselines:
            result = create_analysis_result(
                job_id=job.id,
                title=f"Baseline Analysis: {baseline.get('entity_type', 'Unknown')}",
                analysis_type=AnalysisType.BASELINE_ANALYSIS,
                severity=SeverityLevel(baseline.get('severity', 'informational')),
                confidence_score=baseline.get('confidence', 0.8),
                risk_score=baseline.get('risk_score', 20),
                finding_type="baseline_update",
                description=baseline.get('description', ''),
                affected_entities=baseline.get('affected_entities', []),
                evidence=baseline.get('evidence', {}),
                recommendations=baseline.get('recommendations', [])
            )
            
            results.append(result)
        
        return results
    
    async def _publish_analysis_results(self, job: AnalysisJob, results: List[AnalysisResult]):
        """Publish analysis results to event bus."""
        try:
            event_data = {
                "job_id": str(job.id),
                "analysis_type": job.analysis_type,
                "results_count": len(results),
                "completed_at": datetime.now().isoformat(),
                "results": [
                    {
                        "id": str(result.id),
                        "title": result.title,
                        "severity": result.severity,
                        "confidence_score": result.confidence_score,
                        "risk_score": result.risk_score,
                        "finding_type": result.finding_type
                    }
                    for result in results
                ]
            }
            
            await self.event_bus.publish("analysis.results.completed", event_data)
            logger.info(f"Published analysis results for job {job.id}")
            
        except Exception as e:
            logger.error(f"Error publishing analysis results: {e}")
    
    async def _update_baselines(self):
        """Periodically update baseline profiles."""
        while self.is_running:
            try:
                await asyncio.sleep(3600)  # Update hourly
                
                logger.info("Updating baseline profiles")
                await self.baseline_manager.update_all_baselines()
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error updating baselines: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get analysis engine statistics."""
        return {
            **self.stats,
            'is_running': self.is_running,
            'queue_size': self.job_queue.qsize(),
            'max_concurrent_jobs': self.max_concurrent_jobs
        }