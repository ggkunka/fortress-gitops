"""
Anomaly Detector - Statistical Anomaly Detection Service

This service implements various anomaly detection algorithms including
statistical methods, machine learning approaches, and time series analysis.
"""

import math
import statistics
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from collections import defaultdict, deque

import numpy as np
from scipy import stats

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced

from ..models.analysis import BaselineProfile, AnomalyDetection, get_db

logger = get_logger(__name__)
metrics = get_metrics()


class AnomalyDetector:
    """
    Anomaly detector using statistical and machine learning methods.
    
    Implements:
    - Z-score based detection
    - Interquartile range (IQR) method
    - Time series anomaly detection  
    - Behavioral anomaly detection
    - Ensemble methods
    """
    
    def __init__(self):
        # Detection thresholds
        self.z_score_threshold = 2.5
        self.iqr_multiplier = 1.5
        self.confidence_threshold = 0.7
        
        # Time series parameters
        self.seasonal_periods = [24, 168, 720]  # hourly, weekly, monthly patterns
        self.trend_window = 168  # 1 week for trend analysis
        
        # Cache for performance
        self.baseline_cache = {}
        self.cache_ttl = 3600  # 1 hour
        
        logger.info("Anomaly detector initialized")
    
    @traced("anomaly_detector_detect_anomalies")
    async def detect_anomalies(
        self,
        data: Dict[str, Any],
        config: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Detect anomalies in input data."""
        try:
            anomalies = []
            
            detection_methods = config.get('methods', ['z_score', 'iqr', 'time_series'])
            entity_id = data.get('entity_id', 'unknown')
            entity_type = data.get('entity_type', 'generic')
            
            # Get or create baseline profile
            baseline = await self._get_baseline_profile(entity_type, entity_id)
            
            # Extract metrics from data
            metrics_data = self._extract_metrics(data)
            
            # Apply each detection method
            for method in detection_methods:
                if method == 'z_score':
                    method_anomalies = await self._detect_z_score_anomalies(
                        metrics_data, baseline, config
                    )
                    anomalies.extend(method_anomalies)
                
                elif method == 'iqr':
                    method_anomalies = await self._detect_iqr_anomalies(
                        metrics_data, baseline, config
                    )
                    anomalies.extend(method_anomalies)
                
                elif method == 'time_series':
                    method_anomalies = await self._detect_time_series_anomalies(
                        metrics_data, baseline, config
                    )
                    anomalies.extend(method_anomalies)
                
                elif method == 'behavioral':
                    method_anomalies = await self._detect_behavioral_anomalies(
                        metrics_data, baseline, config
                    )
                    anomalies.extend(method_anomalies)
            
            # Apply ensemble voting if multiple methods used
            if len(detection_methods) > 1:
                anomalies = self._apply_ensemble_voting(anomalies, config)
            
            # Filter by confidence threshold
            filtered_anomalies = [
                anomaly for anomaly in anomalies
                if anomaly.get('confidence', 0) >= self.confidence_threshold
            ]
            
            # Save anomalies to database
            await self._save_anomalies(filtered_anomalies, entity_type, entity_id)
            
            logger.info(f"Detected {len(filtered_anomalies)} anomalies for {entity_type}:{entity_id}")
            metrics.anomaly_detector_anomalies_detected.inc(len(filtered_anomalies))
            
            return filtered_anomalies
            
        except Exception as e:
            logger.error(f"Error detecting anomalies: {e}")
            metrics.anomaly_detector_errors.inc()
            raise
    
    async def _get_baseline_profile(
        self,
        entity_type: str,
        entity_id: str
    ) -> Optional[BaselineProfile]:
        """Get baseline profile for entity."""
        cache_key = f"{entity_type}:{entity_id}"
        
        # Check cache first
        if cache_key in self.baseline_cache:
            cached_entry = self.baseline_cache[cache_key]
            if cached_entry['expires_at'] > datetime.now():
                return cached_entry['baseline']
        
        # Query database
        with get_db() as db:
            baseline = db.query(BaselineProfile).filter(
                BaselineProfile.entity_type == entity_type,
                BaselineProfile.entity_id == entity_id,
                BaselineProfile.is_active == True
            ).first()
            
            if baseline:
                # Cache baseline
                self.baseline_cache[cache_key] = {
                    'baseline': baseline,
                    'expires_at': datetime.now() + timedelta(seconds=self.cache_ttl)
                }
            
            return baseline
    
    def _extract_metrics(self, data: Dict[str, Any]) -> Dict[str, List[float]]:
        """Extract numeric metrics from data."""
        metrics_data = defaultdict(list)
        
        # Extract different types of metrics
        if 'events' in data:
            # Event-based metrics
            events = data['events']
            if isinstance(events, list):
                # Event count over time
                event_times = [
                    datetime.fromisoformat(event.get('timestamp', datetime.now().isoformat()))
                    for event in events
                ]
                
                # Group events by hour
                hourly_counts = defaultdict(int)
                for event_time in event_times:
                    hour_key = event_time.replace(minute=0, second=0, microsecond=0)
                    hourly_counts[hour_key] += 1
                
                metrics_data['event_count_hourly'] = list(hourly_counts.values())
                
                # Extract numeric fields from events
                for event in events:
                    for key, value in event.items():
                        if isinstance(value, (int, float)):
                            metrics_data[f"event_{key}"].append(float(value))
        
        # Direct numeric metrics
        for key, value in data.items():
            if isinstance(value, (int, float)):
                metrics_data[key].append(float(value))
            elif isinstance(value, list) and value and isinstance(value[0], (int, float)):
                metrics_data[key] = [float(v) for v in value]
        
        return dict(metrics_data)
    
    async def _detect_z_score_anomalies(
        self,
        metrics_data: Dict[str, List[float]],
        baseline: Optional[BaselineProfile],
        config: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Detect anomalies using Z-score method."""
        anomalies = []
        
        threshold = config.get('z_score_threshold', self.z_score_threshold)
        
        for metric_name, values in metrics_data.items():
            if not values or len(values) < 2:
                continue
            
            # Get baseline statistics
            if baseline and metric_name in baseline.statistical_metrics:
                baseline_stats = baseline.statistical_metrics[metric_name]
                mean = baseline_stats.get('mean', statistics.mean(values))
                std_dev = baseline_stats.get('std_dev', statistics.stdev(values))
            else:
                mean = statistics.mean(values)
                std_dev = statistics.stdev(values) if len(values) > 1 else 0
            
            if std_dev == 0:
                continue
            
            # Calculate Z-scores
            for i, value in enumerate(values):
                z_score = abs(value - mean) / std_dev
                
                if z_score > threshold:
                    # Calculate additional metrics
                    p_value = 2 * (1 - stats.norm.cdf(abs(z_score)))
                    confidence = min(1.0, z_score / (threshold * 2))
                    
                    # Determine severity based on Z-score
                    if z_score > 4:
                        severity = 'critical'
                        risk_score = 90
                    elif z_score > 3:
                        severity = 'high'
                        risk_score = 75
                    elif z_score > 2.5:
                        severity = 'medium'
                        risk_score = 60
                    else:
                        severity = 'low'
                        risk_score = 40
                    
                    anomaly = {
                        'type': 'statistical_outlier',
                        'method': 'z_score',
                        'metric_name': metric_name,
                        'observed_value': value,
                        'baseline_mean': mean,
                        'baseline_std_dev': std_dev,
                        'z_score': z_score,
                        'p_value': p_value,
                        'deviation': abs(value - mean),
                        'confidence': confidence,
                        'severity': severity,
                        'risk_score': risk_score,
                        'description': f"Value {value:.2f} deviates {z_score:.2f} standard deviations from baseline mean {mean:.2f}",
                        'recommendations': [
                            f"Investigate cause of {metric_name} deviation",
                            "Check for system changes or external factors",
                            "Verify data collection accuracy"
                        ],
                        'evidence': {
                            'metric_name': metric_name,
                            'sample_index': i,
                            'total_samples': len(values),
                            'baseline_samples': baseline.samples_count if baseline else len(values)
                        }
                    }
                    
                    anomalies.append(anomaly)
        
        return anomalies
    
    async def _detect_iqr_anomalies(
        self,
        metrics_data: Dict[str, List[float]],
        baseline: Optional[BaselineProfile],
        config: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Detect anomalies using Interquartile Range method."""
        anomalies = []
        
        multiplier = config.get('iqr_multiplier', self.iqr_multiplier)
        
        for metric_name, values in metrics_data.items():
            if not values or len(values) < 4:
                continue
            
            # Calculate quartiles
            q1 = np.percentile(values, 25)
            q3 = np.percentile(values, 75)
            iqr = q3 - q1
            
            if iqr == 0:
                continue
            
            # Calculate bounds
            lower_bound = q1 - (multiplier * iqr)
            upper_bound = q3 + (multiplier * iqr)
            
            # Find outliers
            for i, value in enumerate(values):
                if value < lower_bound or value > upper_bound:
                    # Calculate confidence based on distance from bounds
                    if value < lower_bound:
                        distance = lower_bound - value
                        bound_type = 'lower'
                    else:
                        distance = value - upper_bound
                        bound_type = 'upper'
                    
                    confidence = min(1.0, distance / (iqr * multiplier))
                    
                    # Determine severity
                    if distance > iqr * 3:
                        severity = 'high'
                        risk_score = 80
                    elif distance > iqr * 2:
                        severity = 'medium'
                        risk_score = 60
                    else:
                        severity = 'low'
                        risk_score = 40
                    
                    anomaly = {
                        'type': 'iqr_outlier',
                        'method': 'iqr',
                        'metric_name': metric_name,
                        'observed_value': value,
                        'q1': q1,
                        'q3': q3,
                        'iqr': iqr,
                        'lower_bound': lower_bound,
                        'upper_bound': upper_bound,
                        'bound_violated': bound_type,
                        'distance_from_bound': distance,
                        'confidence': confidence,
                        'severity': severity,
                        'risk_score': risk_score,
                        'description': f"Value {value:.2f} is outside IQR bounds [{lower_bound:.2f}, {upper_bound:.2f}]",
                        'recommendations': [
                            f"Review {metric_name} measurement methodology",
                            "Check for data collection errors",
                            "Investigate environmental factors"
                        ],
                        'evidence': {
                            'metric_name': metric_name,
                            'sample_index': i,
                            'percentile_25': q1,
                            'percentile_75': q3
                        }
                    }
                    
                    anomalies.append(anomaly)
        
        return anomalies
    
    async def _detect_time_series_anomalies(
        self,
        metrics_data: Dict[str, List[float]],
        baseline: Optional[BaselineProfile],
        config: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Detect time series anomalies using trend and seasonal analysis."""
        anomalies = []
        
        for metric_name, values in metrics_data.items():
            if not values or len(values) < 10:
                continue
            
            # Simple trend detection using linear regression
            x = np.arange(len(values))
            y = np.array(values)
            
            # Calculate trend
            slope, intercept, r_value, p_value, std_err = stats.linregress(x, y)
            
            # Detect significant trend changes
            if abs(r_value) > 0.7 and p_value < 0.05:
                trend_type = 'increasing' if slope > 0 else 'decreasing'
                
                # Calculate confidence based on correlation strength
                confidence = abs(r_value)
                
                # Determine severity based on trend strength and significance
                if abs(r_value) > 0.9 and p_value < 0.01:
                    severity = 'high'
                    risk_score = 75
                elif abs(r_value) > 0.8 and p_value < 0.05:
                    severity = 'medium'
                    risk_score = 60
                else:
                    severity = 'low'
                    risk_score = 40
                
                anomaly = {
                    'type': 'trend_anomaly',
                    'method': 'time_series',
                    'metric_name': metric_name,
                    'trend_type': trend_type,
                    'slope': slope,
                    'correlation': r_value,
                    'p_value': p_value,
                    'confidence': confidence,
                    'severity': severity,
                    'risk_score': risk_score,
                    'description': f"Significant {trend_type} trend detected in {metric_name}",
                    'recommendations': [
                        f"Monitor {trend_type} trend in {metric_name}",
                        "Investigate root cause of trend",
                        "Consider capacity planning implications"
                    ],
                    'evidence': {
                        'metric_name': metric_name,
                        'sample_count': len(values),
                        'trend_strength': abs(r_value),
                        'statistical_significance': p_value
                    }
                }
                
                anomalies.append(anomaly)
            
            # Detect sudden changes (change points)
            if len(values) >= 20:
                change_points = self._detect_change_points(values)
                
                for change_point in change_points:
                    idx, magnitude, confidence = change_point
                    
                    if magnitude > np.std(values) * 2:  # Significant change
                        severity = 'medium'
                        risk_score = 65
                        
                        anomaly = {
                            'type': 'change_point',
                            'method': 'time_series',
                            'metric_name': metric_name,
                            'change_point_index': idx,
                            'change_magnitude': magnitude,
                            'confidence': confidence,
                            'severity': severity,
                            'risk_score': risk_score,
                            'description': f"Sudden change detected in {metric_name} at position {idx}",
                            'recommendations': [
                                f"Investigate change in {metric_name} at timestamp {idx}",
                                "Check for system events or configuration changes",
                                "Verify data integrity"
                            ],
                            'evidence': {
                                'metric_name': metric_name,
                                'change_position': idx,
                                'before_value': values[max(0, idx-1)],
                                'after_value': values[min(len(values)-1, idx+1)]
                            }
                        }
                        
                        anomalies.append(anomaly)
        
        return anomalies
    
    async def _detect_behavioral_anomalies(
        self,
        metrics_data: Dict[str, List[float]],
        baseline: Optional[BaselineProfile],
        config: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Detect behavioral anomalies based on patterns."""
        anomalies = []
        
        # Check for unusual patterns in the data
        for metric_name, values in metrics_data.items():
            if not values or len(values) < 5:
                continue
            
            # Detect constant values (potential sensor failure)  
            if len(set(values)) == 1:
                anomaly = {
                    'type': 'constant_behavior',
                    'method': 'behavioral',
                    'metric_name': metric_name,
                    'constant_value': values[0],
                    'sample_count': len(values),
                    'confidence': 0.9,
                    'severity': 'medium',
                    'risk_score': 70,
                    'description': f"{metric_name} shows constant value {values[0]} across all samples",
                    'recommendations': [
                        f"Check {metric_name} sensor or measurement system",
                        "Verify data collection is functioning",
                        "Investigate potential system freeze"
                    ],
                    'evidence': {
                        'metric_name': metric_name,
                        'unique_values': 1,
                        'total_samples': len(values)
                    }
                }
                anomalies.append(anomaly)
            
            # Detect spike patterns
            spikes = self._detect_spikes(values)
            for spike in spikes:
                idx, value, spike_ratio = spike
                
                anomaly = {
                    'type': 'spike_behavior',
                    'method': 'behavioral',
                    'metric_name': metric_name,
                    'spike_index': idx,
                    'spike_value': value,
                    'spike_ratio': spike_ratio,
                    'confidence': min(1.0, spike_ratio / 5.0),
                    'severity': 'high' if spike_ratio > 10 else 'medium',
                    'risk_score': min(90, int(spike_ratio * 10)),
                    'description': f"Spike detected in {metric_name}: {spike_ratio:.1f}x normal level",
                    'recommendations': [
                        f"Investigate cause of spike in {metric_name}",
                        "Check for system overload or attack",
                        "Review resource utilization"
                    ],
                    'evidence': {
                        'metric_name': metric_name,
                        'spike_position': idx,
                        'spike_magnitude': spike_ratio
                    }
                }
                anomalies.append(anomaly)
        
        return anomalies
    
    def _detect_change_points(self, values: List[float]) -> List[Tuple[int, float, float]]:
        """Detect change points in time series data."""
        change_points = []
        
        # Simple change point detection using moving averages
        window_size = min(5, len(values) // 4)
        if window_size < 2:
            return change_points
        
        for i in range(window_size, len(values) - window_size):
            before_window = values[i-window_size:i]
            after_window = values[i:i+window_size]
            
            before_mean = statistics.mean(before_window)
            after_mean = statistics.mean(after_window)
            
            # Calculate change magnitude
            magnitude = abs(after_mean - before_mean)
            
            # Calculate confidence based on variance
            before_var = statistics.variance(before_window) if len(before_window) > 1 else 0
            after_var = statistics.variance(after_window) if len(after_window) > 1 else 0
            
            pooled_std = math.sqrt((before_var + after_var) / 2) if (before_var + after_var) > 0 else 1
            confidence = magnitude / pooled_std if pooled_std > 0 else 0
            
            # Threshold for significant change
            if confidence > 2.0:  # 2 standard deviations
                change_points.append((i, magnitude, min(1.0, confidence / 4.0)))
        
        return change_points
    
    def _detect_spikes(self, values: List[float]) -> List[Tuple[int, float, float]]:
        """Detect spikes in data."""
        spikes = []
        
        if len(values) < 3:
            return spikes
        
        # Calculate baseline (median of values)
        baseline = statistics.median(values)
        
        for i, value in enumerate(values):
            if baseline > 0:
                spike_ratio = value / baseline
                
                # Consider it a spike if it's > 3x baseline
                if spike_ratio > 3.0:
                    spikes.append((i, value, spike_ratio))
        
        return spikes
    
    def _apply_ensemble_voting(
        self,
        anomalies: List[Dict[str, Any]],
        config: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Apply ensemble voting to combine results from multiple methods."""
        # Group anomalies by metric and approximate location
        anomaly_groups = defaultdict(list)
        
        for anomaly in anomalies:
            metric_name = anomaly.get('metric_name', 'unknown')
            # Use a simple grouping key
            group_key = f"{metric_name}_{anomaly.get('type', 'unknown')}"
            anomaly_groups[group_key].append(anomaly)
        
        # Apply voting
        ensemble_anomalies = []
        min_votes = config.get('min_ensemble_votes', 2)
        
        for group_key, group_anomalies in anomaly_groups.items():
            if len(group_anomalies) >= min_votes:
                # Create ensemble anomaly
                confidences = [a.get('confidence', 0) for a in group_anomalies]
                risk_scores = [a.get('risk_score', 0) for a in group_anomalies]
                
                ensemble_anomaly = {
                    'type': 'ensemble_anomaly',
                    'method': 'ensemble',
                    'constituent_methods': [a.get('method', 'unknown') for a in group_anomalies],
                    'votes': len(group_anomalies),
                    'confidence': statistics.mean(confidences),
                    'risk_score': int(statistics.mean(risk_scores)),
                    'severity': group_anomalies[0].get('severity', 'medium'),
                    'metric_name': group_anomalies[0].get('metric_name', 'unknown'),
                    'description': f"Ensemble detection: {len(group_anomalies)} methods agree",
                    'evidence': {
                        'constituent_anomalies': len(group_anomalies),
                        'methods_agreement': [a.get('method') for a in group_anomalies]
                    }
                }
                
                ensemble_anomalies.append(ensemble_anomaly)
            else:
                # Keep individual anomalies that don't have enough votes
                ensemble_anomalies.extend(group_anomalies)
        
        return ensemble_anomalies
    
    async def _save_anomalies(
        self,
        anomalies: List[Dict[str, Any]],
        entity_type: str,
        entity_id: str
    ):
        """Save detected anomalies to database."""
        try:
            with get_db() as db:
                for anomaly in anomalies:
                    detection = AnomalyDetection(
                        detection_name=f"{anomaly.get('type', 'unknown')}_{entity_type}_{entity_id}",
                        anomaly_type=anomaly.get('type', 'unknown'),
                        source_entity=f"{entity_type}:{entity_id}",
                        source_data=anomaly.get('evidence', {}),
                        baseline_value=anomaly.get('baseline_mean'),
                        observed_value=anomaly.get('observed_value'),
                        deviation=anomaly.get('deviation'),
                        z_score=anomaly.get('z_score'),
                        p_value=anomaly.get('p_value'),
                        confidence=anomaly.get('confidence', 0.5),
                        severity=anomaly.get('severity', 'medium'),
                        anomaly_score=anomaly.get('risk_score', 50),
                        detection_window=3600,  # 1 hour default
                        context_data=anomaly,
                        detected_at=datetime.now(),
                        window_start=datetime.now() - timedelta(hours=1),
                        window_end=datetime.now()
                    )
                    
                    db.add(detection)
                
                db.commit()
                
        except Exception as e:
            logger.error(f"Error saving anomalies: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get anomaly detector statistics."""
        return {
            'z_score_threshold': self.z_score_threshold,
            'iqr_multiplier': self.iqr_multiplier,
            'confidence_threshold': self.confidence_threshold,
            'baseline_cache_size': len(self.baseline_cache),
            'seasonal_periods': self.seasonal_periods
        }