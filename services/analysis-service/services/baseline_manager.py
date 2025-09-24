"""
Baseline Manager - Baseline Profile Management and Analysis

This service manages baseline profiles for entities, updates statistical baselines,
and performs baseline deviation analysis to identify anomalous behaviors.
"""

import statistics
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from enum import Enum

import numpy as np
from scipy import stats

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced

from ..models.analysis import BaselineProfile, create_baseline_profile, get_db

logger = get_logger(__name__)
metrics = get_metrics()


class BaselineType(str, Enum):
    """Types of baseline profiles."""
    STATISTICAL = "statistical"
    BEHAVIORAL = "behavioral"
    TEMPORAL = "temporal"
    VOLUMETRIC = "volumetric"
    PATTERN_BASED = "pattern_based"


class LearningMethod(str, Enum):
    """Learning methods for baseline updates."""
    EXPONENTIAL_MOVING_AVERAGE = "exponential_moving_average"
    SLIDING_WINDOW = "sliding_window"
    ADAPTIVE_THRESHOLD = "adaptive_threshold"
    SEASONAL_DECOMPOSITION = "seasonal_decomposition"


@dataclass
class BaselineMetric:
    """Individual baseline metric."""
    name: str
    value: float
    variance: float
    confidence_interval: Tuple[float, float]
    sample_count: int
    last_updated: datetime
    learning_rate: float = 0.1


@dataclass
class BaselineUpdate:
    """Baseline update result."""
    entity_type: str
    entity_id: str
    updated_metrics: List[str]
    baseline_drift: float
    update_confidence: float
    recommendations: List[str]


class BaselineManager:
    """
    Baseline manager for creating, updating, and analyzing baseline profiles.
    
    Manages:
    - Statistical baselines for numeric metrics
    - Behavioral baselines for user/system patterns
    - Temporal baselines for time-based patterns
    - Volumetric baselines for data volumes
    - Pattern-based baselines for recurring patterns
    """
    
    def __init__(self):
        # Baseline configuration
        self.learning_methods = {
            BaselineType.STATISTICAL: LearningMethod.EXPONENTIAL_MOVING_AVERAGE,
            BaselineType.BEHAVIORAL: LearningMethod.SLIDING_WINDOW,
            BaselineType.TEMPORAL: LearningMethod.SEASONAL_DECOMPOSITION,
            BaselineType.VOLUMETRIC: LearningMethod.ADAPTIVE_THRESHOLD,
            BaselineType.PATTERN_BASED: LearningMethod.SLIDING_WINDOW
        }
        
        # Learning parameters
        self.learning_rates = {
            BaselineType.STATISTICAL: 0.1,
            BaselineType.BEHAVIORAL: 0.05,
            BaselineType.TEMPORAL: 0.02,
            BaselineType.VOLUMETRIC: 0.15,
            BaselineType.PATTERN_BASED: 0.08
        }
        
        # Baseline caches
        self.baseline_cache = {}
        self.cache_ttl = 1800  # 30 minutes
        
        # Update tracking
        self.update_history = defaultdict(deque)
        self.max_history_size = 1000
        
        # Minimum requirements for baseline creation
        self.min_samples_required = 50
        self.min_learning_period_days = 7
        self.confidence_threshold = 0.8
        
        logger.info("Baseline manager initialized")
    
    @traced("baseline_manager_analyze_baselines")
    async def analyze_baselines(
        self,
        data: Dict[str, Any],
        config: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Analyze data against baseline profiles."""
        try:
            analyses = []
            
            entity_id = data.get('entity_id', 'unknown')
            entity_type = data.get('entity_type', 'generic')
            
            # Get baseline types to analyze
            baseline_types = config.get('baseline_types', [
                BaselineType.STATISTICAL, BaselineType.BEHAVIORAL,
                BaselineType.TEMPORAL, BaselineType.VOLUMETRIC
            ])
            
            # Extract metrics from data
            metrics_data = self._extract_metrics_for_baseline(data)
            
            # Analyze each baseline type
            for baseline_type in baseline_types:
                baseline_analysis = await self._analyze_baseline_type(
                    baseline_type, entity_type, entity_id, metrics_data, config
                )
                if baseline_analysis:
                    analyses.extend(baseline_analysis)
            
            # Update baselines with new data
            if config.get('update_baselines', True):
                await self._update_entity_baselines(
                    entity_type, entity_id, metrics_data
                )
            
            logger.info(f"Baseline analysis completed for {entity_type}:{entity_id}")
            metrics.baseline_manager_analyses_completed.inc()
            
            return analyses
            
        except Exception as e:
            logger.error(f"Error analyzing baselines: {e}")
            metrics.baseline_manager_errors.inc()
            raise
    
    async def _analyze_baseline_type(
        self,
        baseline_type: BaselineType,
        entity_type: str,
        entity_id: str,
        metrics_data: Dict[str, Any],
        config: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Analyze specific baseline type."""
        analyses = []
        
        # Get baseline profile
        baseline = await self._get_baseline_profile(
            baseline_type, entity_type, entity_id
        )
        
        if not baseline:
            # Create initial baseline if none exists
            if config.get('create_missing_baselines', True):
                baseline = await self._create_baseline_profile(
                    baseline_type, entity_type, entity_id, metrics_data
                )
                if baseline:
                    analyses.append({
                        'type': 'baseline_created',
                        'baseline_type': baseline_type.value,
                        'confidence': 0.5,
                        'severity': 'informational',
                        'risk_score': 10,
                        'description': f"New {baseline_type.value} baseline created for {entity_type}:{entity_id}",
                        'affected_entities': [f"{entity_type}:{entity_id}"],
                        'evidence': {
                            'baseline_type': baseline_type.value,
                            'metrics_count': len(metrics_data),
                            'creation_time': datetime.now().isoformat()
                        },
                        'recommendations': [
                            "Allow baseline to learn for minimum period",
                            "Monitor baseline accuracy over time",
                            "Adjust learning parameters if needed"
                        ]
                    })
            return analyses
        
        # Perform baseline deviation analysis
        if baseline_type == BaselineType.STATISTICAL:
            deviation_analyses = await self._analyze_statistical_deviations(
                baseline, metrics_data, config
            )
            analyses.extend(deviation_analyses)
        
        elif baseline_type == BaselineType.BEHAVIORAL:
            behavior_analyses = await self._analyze_behavioral_deviations(
                baseline, metrics_data, config
            )
            analyses.extend(behavior_analyses)
        
        elif baseline_type == BaselineType.TEMPORAL:
            temporal_analyses = await self._analyze_temporal_deviations(
                baseline, metrics_data, config
            )
            analyses.extend(temporal_analyses)
        
        elif baseline_type == BaselineType.VOLUMETRIC:
            volume_analyses = await self._analyze_volumetric_deviations(
                baseline, metrics_data, config
            )
            analyses.extend(volume_analyses)
        
        return analyses
    
    async def _get_baseline_profile(
        self,
        baseline_type: BaselineType,
        entity_type: str,
        entity_id: str
    ) -> Optional[BaselineProfile]:
        """Get baseline profile from cache or database."""
        cache_key = f"{baseline_type.value}:{entity_type}:{entity_id}"
        
        # Check cache
        if cache_key in self.baseline_cache:
            cached_entry = self.baseline_cache[cache_key]
            if cached_entry['expires_at'] > datetime.now():
                return cached_entry['baseline']
        
        # Query database
        with get_db() as db:
            baseline = db.query(BaselineProfile).filter(
                BaselineProfile.entity_type == entity_type,
                BaselineProfile.entity_id == entity_id,
                BaselineProfile.baseline_type == baseline_type.value,
                BaselineProfile.is_active == True
            ).first()
            
            if baseline:
                # Cache baseline
                self.baseline_cache[cache_key] = {
                    'baseline': baseline,
                    'expires_at': datetime.now() + timedelta(seconds=self.cache_ttl)
                }
            
            return baseline
    
    async def _create_baseline_profile(
        self,
        baseline_type: BaselineType,
        entity_type: str,
        entity_id: str,
        metrics_data: Dict[str, Any]
    ) -> Optional[BaselineProfile]:
        """Create new baseline profile."""
        try:
            # Check if we have enough data
            if not self._has_sufficient_data(metrics_data):
                logger.info(f"Insufficient data to create baseline for {entity_type}:{entity_id}")
                return None
            
            # Calculate initial baseline metrics
            baseline_metrics = self._calculate_initial_metrics(
                baseline_type, metrics_data
            )
            
            # Create baseline profile
            baseline = create_baseline_profile(
                entity_type=entity_type,
                entity_id=entity_id,
                baseline_type=baseline_type.value,
                baseline_name=f"{baseline_type.value}_{entity_type}_{entity_id}",
                statistical_metrics=baseline_metrics,
                learning_parameters={
                    'learning_method': self.learning_methods[baseline_type].value,
                    'learning_rate': self.learning_rates[baseline_type],
                    'confidence_threshold': self.confidence_threshold
                },
                samples_count=len(metrics_data),
                confidence_score=0.5  # Initial confidence
            )
            
            # Save to database
            with get_db() as db:
                db.add(baseline)
                db.commit()
                db.refresh(baseline)
            
            logger.info(f"Created baseline profile: {baseline_type.value} for {entity_type}:{entity_id}")
            metrics.baseline_manager_baselines_created.inc()
            
            return baseline
            
        except Exception as e:
            logger.error(f"Error creating baseline profile: {e}")
            return None
    
    def _extract_metrics_for_baseline(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract metrics suitable for baseline analysis."""
        metrics = {}
        
        # Extract numeric metrics
        for key, value in data.items():
            if isinstance(value, (int, float)):
                metrics[key] = value
            elif isinstance(value, list) and value and isinstance(value[0], (int, float)):
                metrics[f"{key}_mean"] = statistics.mean(value)
                metrics[f"{key}_std"] = statistics.stdev(value) if len(value) > 1 else 0
                metrics[f"{key}_count"] = len(value)
        
        # Extract event-based metrics
        if 'events' in data and isinstance(data['events'], list):
            events = data['events']
            
            # Event count metrics
            metrics['event_count'] = len(events)
            
            # Time-based metrics
            if events:
                timestamps = []
                for event in events:
                    if 'timestamp' in event:
                        try:
                            ts = datetime.fromisoformat(event['timestamp'])
                            timestamps.append(ts)
                        except:
                            continue
                
                if timestamps:
                    # Time distribution metrics
                    hours = [ts.hour for ts in timestamps]
                    days = [ts.weekday() for ts in timestamps]
                    
                    metrics['hour_variance'] = statistics.variance(hours) if len(hours) > 1 else 0
                    metrics['day_variance'] = statistics.variance(days) if len(days) > 1 else 0
                    metrics['time_span_seconds'] = (max(timestamps) - min(timestamps)).total_seconds()
            
            # Event type distribution
            event_types = [event.get('type', 'unknown') for event in events]
            unique_types = len(set(event_types))
            metrics['event_type_diversity'] = unique_types
            
            # Source distribution
            sources = [event.get('source', 'unknown') for event in events]
            unique_sources = len(set(sources))
            metrics['source_diversity'] = unique_sources
        
        return metrics
    
    def _has_sufficient_data(self, metrics_data: Dict[str, Any]) -> bool:
        """Check if there's sufficient data to create baseline."""
        # Check minimum number of metrics
        if len(metrics_data) < 5:
            return False
        
        # Check for numeric data
        numeric_metrics = sum(
            1 for value in metrics_data.values()
            if isinstance(value, (int, float))
        )
        
        return numeric_metrics >= 3
    
    def _calculate_initial_metrics(
        self,
        baseline_type: BaselineType,
        metrics_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Calculate initial baseline metrics."""
        baseline_metrics = {}
        
        for metric_name, value in metrics_data.items():
            if isinstance(value, (int, float)):
                baseline_metrics[metric_name] = {
                    'mean': float(value),
                    'variance': 0.0,  # Will be updated with more data
                    'std_dev': 0.0,
                    'min_value': float(value),
                    'max_value': float(value),
                    'sample_count': 1,
                    'confidence_interval': [float(value), float(value)],
                    'last_updated': datetime.now().isoformat()
                }
        
        return baseline_metrics
    
    async def _analyze_statistical_deviations(
        self,
        baseline: BaselineProfile,
        metrics_data: Dict[str, Any],
        config: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Analyze statistical deviations from baseline."""
        analyses = []
        
        deviation_threshold = config.get('deviation_threshold', 2.0)  # Z-score
        
        for metric_name, current_value in metrics_data.items():
            if not isinstance(current_value, (int, float)):
                continue
            
            if metric_name not in baseline.statistical_metrics:
                continue
            
            baseline_stats = baseline.statistical_metrics[metric_name]
            baseline_mean = baseline_stats.get('mean', current_value)
            baseline_std = baseline_stats.get('std_dev', 1.0)
            
            if baseline_std == 0:
                continue
            
            # Calculate Z-score
            z_score = abs(current_value - baseline_mean) / baseline_std
            
            if z_score > deviation_threshold:
                # Calculate additional metrics
                deviation_percentage = abs(current_value - baseline_mean) / abs(baseline_mean) * 100 if baseline_mean != 0 else 0
                confidence = min(1.0, z_score / (deviation_threshold * 2))
                
                # Determine severity
                if z_score > 4:
                    severity = 'critical'
                    risk_score = 85
                elif z_score > 3:
                    severity = 'high'
                    risk_score = 70
                else:
                    severity = 'medium'
                    risk_score = 55
                
                analysis = {
                    'type': 'statistical_deviation',
                    'baseline_type': 'statistical',
                    'metric_name': metric_name,
                    'confidence': confidence,
                    'severity': severity,
                    'risk_score': risk_score,
                    'description': f"Statistical deviation in {metric_name}: {deviation_percentage:.1f}% from baseline",
                    'current_value': current_value,
                    'baseline_mean': baseline_mean,
                    'z_score': z_score,
                    'deviation_percentage': deviation_percentage,
                    'affected_entities': [f"{baseline.entity_type}:{baseline.entity_id}"],
                    'evidence': {
                        'metric_name': metric_name,
                        'current_value': current_value,
                        'baseline_mean': baseline_mean,
                        'baseline_std': baseline_std,
                        'z_score': z_score,
                        'sample_count': baseline_stats.get('sample_count', 0)
                    },
                    'recommendations': [
                        f"Investigate cause of {metric_name} deviation",
                        "Verify data collection accuracy",
                        "Check for system changes or anomalies",
                        "Consider updating baseline if legitimate change"
                    ]
                }
                
                analyses.append(analysis)
        
        return analyses
    
    async def _analyze_behavioral_deviations(
        self,
        baseline: BaselineProfile,
        metrics_data: Dict[str, Any],
        config: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Analyze behavioral deviations from baseline."""
        analyses = []
        
        # Analyze diversity metrics
        diversity_metrics = ['event_type_diversity', 'source_diversity']
        
        for metric_name in diversity_metrics:
            if metric_name not in metrics_data or metric_name not in baseline.statistical_metrics:
                continue
            
            current_diversity = metrics_data[metric_name]
            baseline_stats = baseline.statistical_metrics[metric_name]
            baseline_mean = baseline_stats.get('mean', current_diversity)
            
            # Check for significant diversity changes
            if baseline_mean > 0:
                diversity_ratio = current_diversity / baseline_mean
                
                if diversity_ratio > 2.0 or diversity_ratio < 0.5:
                    confidence = min(1.0, abs(diversity_ratio - 1.0))
                    severity = 'medium' if diversity_ratio > 2.0 else 'low'
                    risk_score = min(70, int(abs(diversity_ratio - 1.0) * 50))
                    
                    analysis = {
                        'type': 'behavioral_deviation',
                        'baseline_type': 'behavioral',
                        'metric_name': metric_name,
                        'confidence': confidence,
                        'severity': severity,
                        'risk_score': risk_score,
                        'description': f"Behavioral change in {metric_name}: {diversity_ratio:.1f}x normal diversity",
                        'current_value': current_diversity,
                        'baseline_mean': baseline_mean,
                        'diversity_ratio': diversity_ratio,
                        'affected_entities': [f"{baseline.entity_type}:{baseline.entity_id}"],
                        'evidence': {
                            'metric_name': metric_name,
                            'current_diversity': current_diversity,
                            'baseline_diversity': baseline_mean,
                            'diversity_ratio': diversity_ratio
                        },
                        'recommendations': [
                            f"Investigate change in {metric_name}",
                            "Check for new data sources or types",
                            "Verify operational changes",
                            "Update behavioral baseline if appropriate"
                        ]
                    }
                    
                    analyses.append(analysis)
        
        return analyses
    
    async def _analyze_temporal_deviations(
        self,
        baseline: BaselineProfile,
        metrics_data: Dict[str, Any],
        config: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Analyze temporal deviations from baseline."""
        analyses = []
        
        # Analyze time-based variance
        temporal_metrics = ['hour_variance', 'day_variance']
        
        for metric_name in temporal_metrics:
            if metric_name not in metrics_data or metric_name not in baseline.statistical_metrics:
                continue
            
            current_variance = metrics_data[metric_name]
            baseline_stats = baseline.statistical_metrics[metric_name]
            baseline_variance = baseline_stats.get('mean', current_variance)
            
            if baseline_variance > 0:
                variance_ratio = current_variance / baseline_variance
                
                if variance_ratio > 1.5 or variance_ratio < 0.5:
                    confidence = min(1.0, abs(variance_ratio - 1.0) / 2.0)
                    severity = 'medium' if variance_ratio > 1.5 else 'low'
                    risk_score = min(60, int(abs(variance_ratio - 1.0) * 40))
                    
                    analysis = {
                        'type': 'temporal_deviation',
                        'baseline_type': 'temporal',
                        'metric_name': metric_name,
                        'confidence': confidence,
                        'severity': severity,
                        'risk_score': risk_score,
                        'description': f"Temporal pattern change in {metric_name}: {variance_ratio:.1f}x normal variance",
                        'current_variance': current_variance,
                        'baseline_variance': baseline_variance,
                        'variance_ratio': variance_ratio,
                        'affected_entities': [f"{baseline.entity_type}:{baseline.entity_id}"],
                        'evidence': {
                            'metric_name': metric_name,
                            'current_variance': current_variance,
                            'baseline_variance': baseline_variance,
                            'variance_ratio': variance_ratio
                        },
                        'recommendations': [
                            f"Investigate temporal pattern change in {metric_name}",
                            "Check for schedule changes",
                            "Verify time zone configurations",
                            "Consider seasonal adjustments"
                        ]
                    }
                    
                    analyses.append(analysis)
        
        return analyses
    
    async def _analyze_volumetric_deviations(
        self,
        baseline: BaselineProfile,
        metrics_data: Dict[str, Any],
        config: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Analyze volumetric deviations from baseline."""
        analyses = []
        
        # Analyze volume-based metrics
        volume_metrics = ['event_count', 'time_span_seconds']
        
        for metric_name in volume_metrics:
            if metric_name not in metrics_data or metric_name not in baseline.statistical_metrics:
                continue
            
            current_volume = metrics_data[metric_name]
            baseline_stats = baseline.statistical_metrics[metric_name]
            baseline_mean = baseline_stats.get('mean', current_volume)
            
            if baseline_mean > 0:
                volume_ratio = current_volume / baseline_mean
                
                if volume_ratio > 2.0 or volume_ratio < 0.3:
                    confidence = min(1.0, abs(volume_ratio - 1.0) / 3.0)
                    
                    if volume_ratio > 3.0:
                        severity = 'high'
                        risk_score = 75
                    elif volume_ratio > 2.0 or volume_ratio < 0.3:
                        severity = 'medium'
                        risk_score = 60
                    else:
                        severity = 'low'
                        risk_score = 40
                    
                    analysis = {
                        'type': 'volumetric_deviation',
                        'baseline_type': 'volumetric',
                        'metric_name': metric_name,
                        'confidence': confidence,
                        'severity': severity,
                        'risk_score': risk_score,
                        'description': f"Volume change in {metric_name}: {volume_ratio:.1f}x normal volume",
                        'current_volume': current_volume,
                        'baseline_volume': baseline_mean,
                        'volume_ratio': volume_ratio,
                        'affected_entities': [f"{baseline.entity_type}:{baseline.entity_id}"],
                        'evidence': {
                            'metric_name': metric_name,
                            'current_volume': current_volume,
                            'baseline_volume': baseline_mean,
                            'volume_ratio': volume_ratio
                        },
                        'recommendations': [
                            f"Investigate volume change in {metric_name}",
                            "Check for system load changes",
                            "Verify data collection completeness",
                            "Consider capacity planning implications"
                        ]
                    }
                    
                    analyses.append(analysis)
        
        return analyses
    
    async def _update_entity_baselines(
        self,
        entity_type: str,
        entity_id: str,
        metrics_data: Dict[str, Any]
    ):
        """Update baselines for an entity with new metrics data."""
        try:
            # Update baselines for each type
            for baseline_type in BaselineType:
                baseline = await self._get_baseline_profile(
                    baseline_type, entity_type, entity_id
                )
                
                if baseline:
                    updated = await self._update_baseline_with_data(
                        baseline, metrics_data
                    )
                    
                    if updated:
                        # Save updated baseline
                        with get_db() as db:
                            db.merge(baseline)
                            db.commit()
                        
                        # Invalidate cache
                        cache_key = f"{baseline_type.value}:{entity_type}:{entity_id}"
                        if cache_key in self.baseline_cache:
                            del self.baseline_cache[cache_key]
            
            metrics.baseline_manager_baselines_updated.inc()
            
        except Exception as e:
            logger.error(f"Error updating baselines: {e}")
    
    async def _update_baseline_with_data(
        self,
        baseline: BaselineProfile,
        metrics_data: Dict[str, Any]
    ) -> bool:
        """Update a baseline profile with new data."""
        try:
            baseline_type = BaselineType(baseline.baseline_type)
            learning_rate = self.learning_rates[baseline_type]
            updated = False
            
            for metric_name, current_value in metrics_data.items():
                if not isinstance(current_value, (int, float)):
                    continue
                
                if metric_name not in baseline.statistical_metrics:
                    # Add new metric
                    baseline.statistical_metrics[metric_name] = {
                        'mean': float(current_value),
                        'variance': 0.0,
                        'std_dev': 0.0,
                        'min_value': float(current_value),
                        'max_value': float(current_value),
                        'sample_count': 1,
                        'confidence_interval': [float(current_value), float(current_value)],
                        'last_updated': datetime.now().isoformat()
                    }
                    updated = True
                else:
                    # Update existing metric using exponential moving average
                    stats = baseline.statistical_metrics[metric_name]
                    old_mean = stats['mean']
                    sample_count = stats['sample_count']
                    
                    # Update mean
                    new_mean = (1 - learning_rate) * old_mean + learning_rate * current_value
                    
                    # Update variance (simplified)
                    old_variance = stats['variance']
                    new_variance = (1 - learning_rate) * old_variance + learning_rate * (current_value - new_mean) ** 2
                    
                    # Update statistics
                    stats['mean'] = new_mean
                    stats['variance'] = new_variance
                    stats['std_dev'] = np.sqrt(new_variance)
                    stats['min_value'] = min(stats['min_value'], current_value)
                    stats['max_value'] = max(stats['max_value'], current_value)
                    stats['sample_count'] = sample_count + 1
                    stats['last_updated'] = datetime.now().isoformat()
                    
                    # Update confidence interval (simplified)
                    std_dev = stats['std_dev']
                    stats['confidence_interval'] = [
                        new_mean - 2 * std_dev,
                        new_mean + 2 * std_dev
                    ]
                    
                    updated = True
            
            if updated:
                baseline.samples_count += 1
                baseline.last_updated = datetime.now()
                
                # Update confidence score based on sample count
                if baseline.samples_count >= self.min_samples_required:
                    baseline.confidence_score = min(1.0, baseline.samples_count / (self.min_samples_required * 2))
            
            return updated
            
        except Exception as e:
            logger.error(f"Error updating baseline: {e}")
            return False
    
    async def update_all_baselines(self):
        """Update all active baselines (called periodically)."""
        try:
            with get_db() as db:
                active_baselines = db.query(BaselineProfile).filter(
                    BaselineProfile.is_active == True
                ).all()
                
                logger.info(f"Updating {len(active_baselines)} active baselines")
                
                for baseline in active_baselines:
                    # Check if baseline needs maintenance
                    if self._needs_maintenance(baseline):
                        await self._perform_baseline_maintenance(baseline)
                
                logger.info("Baseline update cycle completed")
                metrics.baseline_manager_update_cycles_completed.inc()
                
        except Exception as e:
            logger.error(f"Error in baseline update cycle: {e}")
    
    def _needs_maintenance(self, baseline: BaselineProfile) -> bool:
        """Check if baseline needs maintenance."""
        # Check age
        age_days = (datetime.now() - baseline.last_updated).days
        if age_days > 30:  # Baseline not updated in 30 days
            return True
        
        # Check sample count
        if baseline.samples_count < self.min_samples_required:
            return True
        
        # Check confidence score
        if baseline.confidence_score < self.confidence_threshold:
            return True
        
        return False
    
    async def _perform_baseline_maintenance(self, baseline: BaselineProfile):
        """Perform maintenance on a baseline profile."""
        try:
            # Check if baseline should be disabled
            age_days = (datetime.now() - baseline.last_updated).days
            
            if age_days > 90:  # No updates for 90 days
                baseline.is_active = False
                logger.info(f"Disabled stale baseline: {baseline.id}")
            
            # Recalculate confidence intervals if needed
            if baseline.samples_count >= self.min_samples_required:
                for metric_name, stats in baseline.statistical_metrics.items():
                    if 'std_dev' in stats and stats['std_dev'] > 0:
                        mean = stats['mean']
                        std_dev = stats['std_dev']
                        stats['confidence_interval'] = [
                            mean - 2 * std_dev,
                            mean + 2 * std_dev
                        ]
            
            # Save updates
            with get_db() as db:
                db.merge(baseline)
                db.commit()
            
        except Exception as e:
            logger.error(f"Error performing baseline maintenance: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get baseline manager statistics."""
        return {
            'baseline_cache_size': len(self.baseline_cache),
            'learning_methods': {bt.value: lm.value for bt, lm in self.learning_methods.items()},
            'learning_rates': {bt.value: lr for bt, lr in self.learning_rates.items()},
            'min_samples_required': self.min_samples_required,
            'confidence_threshold': self.confidence_threshold,
            'cache_ttl': self.cache_ttl
        }