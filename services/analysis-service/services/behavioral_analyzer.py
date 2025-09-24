"""
Behavioral Analyzer - Advanced Behavioral Pattern Analysis

This service analyzes user and system behaviors to detect anomalous patterns,
privilege escalations, insider threats, and other behavioral security issues.
"""

import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple
from collections import defaultdict, Counter
from dataclasses import dataclass
from enum import Enum

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced

from ..models.analysis import BehaviorPattern, get_db

logger = get_logger(__name__)
metrics = get_metrics()


class BehaviorType(str, Enum):
    """Types of behavioral patterns."""
    USER_ACTIVITY = "user_activity"
    SYSTEM_ACCESS = "system_access"
    NETWORK_BEHAVIOR = "network_behavior"
    RESOURCE_USAGE = "resource_usage"
    PRIVILEGE_USAGE = "privilege_usage"
    TIME_BASED = "time_based"


@dataclass
class BehaviorProfile:
    """Individual behavior profile."""
    entity_id: str
    entity_type: str
    normal_patterns: Dict[str, Any]
    anomaly_thresholds: Dict[str, float]
    learning_period: int
    last_updated: datetime


class BehavioralAnalyzer:
    """
    Behavioral analyzer for detecting anomalous user and system behaviors.
    
    Analyzes:
    - User access patterns
    - Privilege escalation attempts
    - Unusual working hours
    - Resource access anomalies
    - Network behavior changes
    - Command/query patterns
    """
    
    def __init__(self):
        # Behavior profiles cache
        self.behavior_profiles: Dict[str, BehaviorProfile] = {}
        self.cache_ttl = 3600  # 1 hour
        
        # Analysis parameters
        self.learning_period_days = 30
        self.min_samples_required = 100
        self.anomaly_threshold = 2.5  # Standard deviations
        
        # Pattern detection rules
        self.builtin_patterns = self._initialize_builtin_patterns()
        
        logger.info("Behavioral analyzer initialized")
    
    def _initialize_builtin_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Initialize built-in behavioral patterns."""
        return {
            'after_hours_access': {
                'type': BehaviorType.TIME_BASED,
                'description': 'Access outside normal business hours',
                'rules': {
                    'business_hours_start': 8,
                    'business_hours_end': 18,
                    'business_days': [0, 1, 2, 3, 4],  # Monday-Friday
                    'threshold_violations': 5
                }
            },
            
            'privilege_escalation': {
                'type': BehaviorType.PRIVILEGE_USAGE,
                'description': 'Unusual privilege escalation patterns',
                'rules': {
                    'sudo_frequency_threshold': 10,
                    'admin_commands_threshold': 5,
                    'sensitive_files_threshold': 3
                }
            },
            
            'unusual_locations': {
                'type': BehaviorType.NETWORK_BEHAVIOR,
                'description': 'Access from unusual geographic locations',
                'rules': {
                    'max_locations_per_day': 3,
                    'impossible_travel_speed': 1000  # km/h
                }
            },
            
            'bulk_data_access': {
                'type': BehaviorType.RESOURCE_USAGE,
                'description': 'Unusual bulk data access patterns',
                'rules': {
                    'files_accessed_threshold': 100,
                    'data_volume_threshold': 1024 * 1024 * 1024,  # 1GB
                    'time_window_minutes': 60
                }
            },
            
            'failed_authentication': {
                'type': BehaviorType.USER_ACTIVITY,
                'description': 'Excessive failed authentication attempts',
                'rules': {
                    'failed_attempts_threshold': 10,
                    'time_window_minutes': 15,
                    'lockout_pattern_threshold': 3
                }
            }
        }
    
    @traced("behavioral_analyzer_analyze_behavior")
    async def analyze_behavior(
        self,
        data: Dict[str, Any],
        config: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Analyze behavioral patterns in data."""
        try:
            behaviors = []
            
            entity_id = data.get('entity_id', 'unknown')
            entity_type = data.get('entity_type', 'user')
            analysis_window = config.get('window_hours', 24)
            
            # Get or create behavior profile
            profile = await self._get_behavior_profile(entity_type, entity_id)
            
            # Extract behavioral features
            features = self._extract_behavioral_features(data, analysis_window)
            
            # Run different behavioral analyses
            analyses = config.get('analyses', [
                'time_based', 'access_patterns', 'privilege_usage',
                'resource_access', 'network_behavior'
            ])
            
            for analysis_type in analyses:
                if analysis_type == 'time_based':
                    time_behaviors = await self._analyze_time_based_behavior(
                        features, profile, config
                    )
                    behaviors.extend(time_behaviors)
                
                elif analysis_type == 'access_patterns':
                    access_behaviors = await self._analyze_access_patterns(
                        features, profile, config
                    )
                    behaviors.extend(access_behaviors)
                
                elif analysis_type == 'privilege_usage':
                    privilege_behaviors = await self._analyze_privilege_usage(
                        features, profile, config
                    )
                    behaviors.extend(privilege_behaviors)
                
                elif analysis_type == 'resource_access':
                    resource_behaviors = await self._analyze_resource_access(
                        features, profile, config
                    )
                    behaviors.extend(resource_behaviors)
                
                elif analysis_type == 'network_behavior':
                    network_behaviors = await self._analyze_network_behavior(
                        features, profile, config
                    )
                    behaviors.extend(network_behaviors)
            
            # Update behavior profile
            if profile:
                await self._update_behavior_profile(profile, features)
            
            logger.info(f"Analyzed behavior for {entity_type}:{entity_id}, found {len(behaviors)} patterns")
            metrics.behavioral_analyzer_patterns_detected.inc(len(behaviors))
            
            return behaviors
            
        except Exception as e:
            logger.error(f"Error analyzing behavior: {e}")
            metrics.behavioral_analyzer_errors.inc()
            raise
    
    async def _get_behavior_profile(
        self,
        entity_type: str,
        entity_id: str
    ) -> Optional[BehaviorProfile]:
        """Get or create behavior profile for entity."""
        profile_key = f"{entity_type}:{entity_id}"
        
        # Check cache
        if profile_key in self.behavior_profiles:
            profile = self.behavior_profiles[profile_key]
            if (datetime.now() - profile.last_updated).seconds < self.cache_ttl:
                return profile
        
        # Load from database or create new
        with get_db() as db:
            db_patterns = db.query(BehaviorPattern).filter(
                BehaviorPattern.category == f"{entity_type}_profile",
                BehaviorPattern.pattern_name == entity_id,
                BehaviorPattern.is_enabled == True
            ).all()
            
            if db_patterns:
                # Build profile from database patterns
                normal_patterns = {}
                anomaly_thresholds = {}
                
                for pattern in db_patterns:
                    normal_patterns.update(pattern.pattern_rules)
                    if 'thresholds' in pattern.detection_logic:
                        anomaly_thresholds.update(pattern.detection_logic['thresholds'])
                
                profile = BehaviorProfile(
                    entity_id=entity_id,
                    entity_type=entity_type,
                    normal_patterns=normal_patterns,
                    anomaly_thresholds=anomaly_thresholds,
                    learning_period=self.learning_period_days,
                    last_updated=datetime.now()
                )
                
                # Cache profile
                self.behavior_profiles[profile_key] = profile
                return profile
            
            # Create new profile (learning mode)
            profile = BehaviorProfile(
                entity_id=entity_id,
                entity_type=entity_type,
                normal_patterns={},
                anomaly_thresholds={},
                learning_period=self.learning_period_days,
                last_updated=datetime.now()
            )
            
            self.behavior_profiles[profile_key] = profile
            return profile
    
    def _extract_behavioral_features(
        self,
        data: Dict[str, Any],
        window_hours: int
    ) -> Dict[str, Any]:
        """Extract behavioral features from data."""
        features = {
            'timestamp_features': {},
            'access_features': {},
            'privilege_features': {},
            'resource_features': {},
            'network_features': {},
            'command_features': {}
        }
        
        # Extract timestamp-based features
        if 'events' in data:
            events = data['events']
            if isinstance(events, list):
                timestamps = []
                hours_of_day = []
                days_of_week = []
                
                for event in events:
                    if 'timestamp' in event:
                        try:
                            ts = datetime.fromisoformat(event['timestamp'])
                            timestamps.append(ts)
                            hours_of_day.append(ts.hour)
                            days_of_week.append(ts.weekday())
                        except:
                            continue
                
                features['timestamp_features'] = {
                    'total_events': len(timestamps),
                    'unique_hours': len(set(hours_of_day)),
                    'unique_days': len(set(days_of_week)),
                    'hour_distribution': Counter(hours_of_day),
                    'day_distribution': Counter(days_of_week),
                    'after_hours_count': sum(1 for h in hours_of_day if h < 8 or h > 18),
                    'weekend_count': sum(1 for d in days_of_week if d >= 5)
                }
                
                # Extract access-related features
                resources_accessed = set()
                commands_used = []
                failed_attempts = 0
                successful_logins = 0
                
                for event in events:
                    event_type = event.get('type', '')
                    
                    if 'file_access' in event_type or 'resource_access' in event_type:
                        resource = event.get('resource', event.get('file_path', ''))
                        if resource:
                            resources_accessed.add(resource)
                    
                    if 'command' in event_type or 'exec' in event_type:
                        command = event.get('command', event.get('process_name', ''))
                        if command:
                            commands_used.append(command)
                    
                    if 'login_failed' in event_type or 'auth_failed' in event_type:
                        failed_attempts += 1
                    elif 'login_success' in event_type or 'auth_success' in event_type:
                        successful_logins += 1
                
                features['access_features'] = {
                    'unique_resources': len(resources_accessed),
                    'resources_accessed': list(resources_accessed),
                    'failed_auth_attempts': failed_attempts,
                    'successful_logins': successful_logins,
                    'auth_failure_rate': failed_attempts / max(1, failed_attempts + successful_logins)
                }
                
                features['command_features'] = {
                    'total_commands': len(commands_used),
                    'unique_commands': len(set(commands_used)),
                    'command_distribution': Counter(commands_used),
                    'admin_commands': sum(1 for cmd in commands_used 
                                        if any(admin_cmd in cmd.lower() 
                                             for admin_cmd in ['sudo', 'su', 'admin', 'root']))
                }
                
                # Extract network features
                source_ips = set()
                destinations = set()
                data_volumes = []
                
                for event in events:
                    if 'source_ip' in event:
                        source_ips.add(event['source_ip'])
                    if 'destination' in event:
                        destinations.add(event['destination'])
                    if 'bytes_transferred' in event:
                        try:
                            data_volumes.append(int(event['bytes_transferred']))
                        except:
                            pass
                
                features['network_features'] = {
                    'unique_source_ips': len(source_ips),
                    'source_ips': list(source_ips),
                    'unique_destinations': len(destinations),
                    'destinations': list(destinations),
                    'total_data_volume': sum(data_volumes),
                    'max_data_transfer': max(data_volumes) if data_volumes else 0
                }
        
        return features
    
    async def _analyze_time_based_behavior(
        self,
        features: Dict[str, Any],
        profile: BehaviorProfile,
        config: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Analyze time-based behavioral patterns."""
        behaviors = []
        
        timestamp_features = features.get('timestamp_features', {})
        if not timestamp_features:
            return behaviors
        
        # Check after-hours access pattern
        after_hours_count = timestamp_features.get('after_hours_count', 0)
        total_events = timestamp_features.get('total_events', 1)
        after_hours_ratio = after_hours_count / total_events
        
        # Compare with profile baseline
        normal_after_hours_ratio = profile.normal_patterns.get('after_hours_ratio', 0.1)
        threshold = profile.anomaly_thresholds.get('after_hours_threshold', 0.3)
        
        if after_hours_ratio > threshold and after_hours_ratio > normal_after_hours_ratio * 2:
            confidence = min(1.0, after_hours_ratio / threshold)
            
            behavior = {
                'pattern_name': 'excessive_after_hours_access',
                'pattern_type': BehaviorType.TIME_BASED.value,
                'confidence': confidence,
                'severity': 'high' if after_hours_ratio > 0.5 else 'medium',
                'risk_score': min(90, int(after_hours_ratio * 100)),
                'description': f"Unusual after-hours access pattern: {after_hours_ratio:.1%} of activity",
                'affected_entities': [profile.entity_id],
                'evidence': {
                    'after_hours_events': after_hours_count,
                    'total_events': total_events,
                    'after_hours_ratio': after_hours_ratio,
                    'normal_ratio': normal_after_hours_ratio,
                    'hour_distribution': timestamp_features.get('hour_distribution', {})
                },
                'recommendations': [
                    "Review business justification for after-hours access",
                    "Verify user identity and authorization",
                    "Monitor for data exfiltration activities"
                ],
                'first_observed': datetime.now() - timedelta(hours=24),
                'last_observed': datetime.now(),
                'observation_window': 24 * 3600  # 24 hours in seconds
            }
            
            behaviors.append(behavior)
        
        # Check weekend access pattern
        weekend_count = timestamp_features.get('weekend_count', 0)
        weekend_ratio = weekend_count / total_events
        
        normal_weekend_ratio = profile.normal_patterns.get('weekend_ratio', 0.05)
        weekend_threshold = profile.anomaly_thresholds.get('weekend_threshold', 0.2)
        
        if weekend_ratio > weekend_threshold and weekend_ratio > normal_weekend_ratio * 3:
            confidence = min(1.0, weekend_ratio / weekend_threshold)
            
            behavior = {
                'pattern_name': 'unusual_weekend_activity',
                'pattern_type': BehaviorType.TIME_BASED.value,
                'confidence': confidence,
                'severity': 'medium',
                'risk_score': min(70, int(weekend_ratio * 100)),
                'description': f"Unusual weekend activity: {weekend_ratio:.1%} of total activity",
                'affected_entities': [profile.entity_id],
                'evidence': {
                    'weekend_events': weekend_count,
                    'weekend_ratio': weekend_ratio,
                    'normal_weekend_ratio': normal_weekend_ratio,
                    'day_distribution': timestamp_features.get('day_distribution', {})
                },
                'recommendations': [
                    "Verify business need for weekend access",
                    "Check for automated processes or scheduled tasks",
                    "Monitor for suspicious activities"
                ]
            }
            
            behaviors.append(behavior)
        
        return behaviors
    
    async def _analyze_access_patterns(
        self,
        features: Dict[str, Any],
        profile: BehaviorProfile,
        config: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Analyze access pattern behaviors."""
        behaviors = []
        
        access_features = features.get('access_features', {})
        if not access_features:
            return behaviors
        
        # Check for unusual resource access volume
        unique_resources = access_features.get('unique_resources', 0)
        normal_resource_count = profile.normal_patterns.get('avg_resources_accessed', 10)
        resource_threshold = profile.anomaly_thresholds.get('resource_access_threshold', 50)
        
        if unique_resources > resource_threshold and unique_resources > normal_resource_count * 3:
            confidence = min(1.0, unique_resources / resource_threshold)
            
            behavior = {
                'pattern_name': 'bulk_resource_access',
                'pattern_type': BehaviorType.RESOURCE_USAGE.value,
                'confidence': confidence,
                'severity': 'high',
                'risk_score': min(95, int((unique_resources / resource_threshold) * 70)),
                'description': f"Unusual bulk resource access: {unique_resources} unique resources",
                'affected_entities': [profile.entity_id],
                'evidence': {
                    'unique_resources_accessed': unique_resources,
                    'normal_resource_count': normal_resource_count,
                    'sample_resources': access_features.get('resources_accessed', [])[:10]
                },
                'recommendations': [
                    "Investigate business justification for bulk access",
                    "Check for data exfiltration attempts",
                    "Review access permissions and need-to-know principle"
                ]
            }
            
            behaviors.append(behavior)
        
        # Check authentication failure patterns
        failure_rate = access_features.get('auth_failure_rate', 0)
        normal_failure_rate = profile.normal_patterns.get('normal_failure_rate', 0.05)
        failure_threshold = profile.anomaly_thresholds.get('failure_rate_threshold', 0.3)
        
        if failure_rate > failure_threshold and failure_rate > normal_failure_rate * 5:
            confidence = min(1.0, failure_rate / failure_threshold)
            
            behavior = {
                'pattern_name': 'excessive_auth_failures',
                'pattern_type': BehaviorType.USER_ACTIVITY.value,
                'confidence': confidence,
                'severity': 'high',
                'risk_score': min(90, int(failure_rate * 100)),
                'description': f"High authentication failure rate: {failure_rate:.1%}",
                'affected_entities': [profile.entity_id],
                'evidence': {
                    'failure_rate': failure_rate,
                    'failed_attempts': access_features.get('failed_auth_attempts', 0),
                    'successful_logins': access_features.get('successful_logins', 0),
                    'normal_failure_rate': normal_failure_rate
                },
                'recommendations': [
                    "Check for brute force attack attempts",
                    "Verify user account status",
                    "Consider temporary account lockout"
                ]
            }
            
            behaviors.append(behavior)
        
        return behaviors
    
    async def _analyze_privilege_usage(
        self,
        features: Dict[str, Any],
        profile: BehaviorProfile,
        config: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Analyze privilege usage patterns."""
        behaviors = []
        
        command_features = features.get('command_features', {})
        if not command_features:
            return behaviors
        
        # Check for unusual admin command usage
        admin_commands = command_features.get('admin_commands', 0)
        total_commands = command_features.get('total_commands', 1)
        admin_ratio = admin_commands / total_commands
        
        normal_admin_ratio = profile.normal_patterns.get('admin_command_ratio', 0.1)
        admin_threshold = profile.anomaly_thresholds.get('admin_command_threshold', 0.4)
        
        if admin_ratio > admin_threshold and admin_ratio > normal_admin_ratio * 3:
            confidence = min(1.0, admin_ratio / admin_threshold)
            
            behavior = {
                'pattern_name': 'privilege_escalation_attempt',
                'pattern_type': BehaviorType.PRIVILEGE_USAGE.value,
                'confidence': confidence,
                'severity': 'critical',
                'risk_score': min(95, int(admin_ratio * 100)),
                'description': f"Unusual privilege escalation pattern: {admin_ratio:.1%} admin commands",
                'affected_entities': [profile.entity_id],
                'evidence': {
                    'admin_commands': admin_commands,
                    'total_commands': total_commands,
                    'admin_ratio': admin_ratio,
                    'normal_admin_ratio': normal_admin_ratio,
                    'command_distribution': dict(list(command_features.get('command_distribution', {}).items())[:10])
                },
                'recommendations': [
                    "Investigate necessity of privilege escalation",
                    "Verify user authorization for admin commands",
                    "Monitor for insider threat indicators"
                ]
            }
            
            behaviors.append(behavior)
        
        return behaviors
    
    async def _analyze_resource_access(
        self,
        features: Dict[str, Any],
        profile: BehaviorProfile,
        config: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Analyze resource access patterns."""
        behaviors = []
        
        # This method would analyze patterns in resource access
        # Implementation similar to other analysis methods
        
        return behaviors
    
    async def _analyze_network_behavior(
        self,
        features: Dict[str, Any],
        profile: BehaviorProfile,
        config: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Analyze network behavior patterns."""
        behaviors = []
        
        network_features = features.get('network_features', {})
        if not network_features:
            return behaviors
        
        # Check for unusual source IP diversity
        unique_ips = network_features.get('unique_source_ips', 0)
        normal_ip_count = profile.normal_patterns.get('avg_source_ips', 2)
        ip_threshold = profile.anomaly_thresholds.get('source_ip_threshold', 10)
        
        if unique_ips > ip_threshold and unique_ips > normal_ip_count * 3:
            confidence = min(1.0, unique_ips / ip_threshold)
            
            behavior = {
                'pattern_name': 'unusual_location_access',
                'pattern_type': BehaviorType.NETWORK_BEHAVIOR.value,
                'confidence': confidence,
                'severity': 'high',
                'risk_score': min(85, int((unique_ips / ip_threshold) * 70)),
                'description': f"Access from {unique_ips} different IP addresses",
                'affected_entities': [profile.entity_id],
                'evidence': {
                    'unique_source_ips': unique_ips,
                    'normal_ip_count': normal_ip_count,
                    'source_ips': network_features.get('source_ips', [])
                },
                'recommendations': [
                    "Verify legitimate business travel or remote access",
                    "Check for compromised credentials",
                    "Review VPN and remote access logs"
                ]
            }
            
            behaviors.append(behavior)
        
        return behaviors
    
    async def _update_behavior_profile(
        self,
        profile: BehaviorProfile,
        features: Dict[str, Any]
    ):
        """Update behavior profile with new observations."""
        try:
            # Update normal patterns with exponential moving average
            alpha = 0.1  # Learning rate
            
            timestamp_features = features.get('timestamp_features', {})
            if timestamp_features:
                total_events = timestamp_features.get('total_events', 0)
                
                if total_events > 0:
                    # Update after-hours ratio
                    after_hours_ratio = timestamp_features.get('after_hours_count', 0) / total_events
                    current_ratio = profile.normal_patterns.get('after_hours_ratio', 0.1)
                    profile.normal_patterns['after_hours_ratio'] = (
                        (1 - alpha) * current_ratio + alpha * after_hours_ratio
                    )
                    
                    # Update weekend ratio
                    weekend_ratio = timestamp_features.get('weekend_count', 0) / total_events
                    current_weekend = profile.normal_patterns.get('weekend_ratio', 0.05)
                    profile.normal_patterns['weekend_ratio'] = (
                        (1 - alpha) * current_weekend + alpha * weekend_ratio
                    )
            
            # Update access patterns
            access_features = features.get('access_features', {})
            if access_features:
                unique_resources = access_features.get('unique_resources', 0)
                current_resources = profile.normal_patterns.get('avg_resources_accessed', 10)
                profile.normal_patterns['avg_resources_accessed'] = (
                    (1 - alpha) * current_resources + alpha * unique_resources
                )
                
                failure_rate = access_features.get('auth_failure_rate', 0)
                current_failure = profile.normal_patterns.get('normal_failure_rate', 0.05)
                profile.normal_patterns['normal_failure_rate'] = (
                    (1 - alpha) * current_failure + alpha * failure_rate
                )
            
            # Update command patterns
            command_features = features.get('command_features', {})
            if command_features:
                total_commands = command_features.get('total_commands', 1)
                admin_ratio = command_features.get('admin_commands', 0) / total_commands
                current_admin = profile.normal_patterns.get('admin_command_ratio', 0.1)
                profile.normal_patterns['admin_command_ratio'] = (
                    (1 - alpha) * current_admin + alpha * admin_ratio
                )
            
            # Update network patterns
            network_features = features.get('network_features', {})
            if network_features:
                unique_ips = network_features.get('unique_source_ips', 0)
                current_ips = profile.normal_patterns.get('avg_source_ips', 2)
                profile.normal_patterns['avg_source_ips'] = (
                    (1 - alpha) * current_ips + alpha * unique_ips
                )
            
            profile.last_updated = datetime.now()
            
            # Save updated profile to database
            await self._save_behavior_profile(profile)
            
        except Exception as e:
            logger.error(f"Error updating behavior profile: {e}")
    
    async def _save_behavior_profile(self, profile: BehaviorProfile):
        """Save behavior profile to database."""
        try:
            with get_db() as db:
                # Create or update behavior pattern record
                pattern = db.query(BehaviorPattern).filter(
                    BehaviorPattern.category == f"{profile.entity_type}_profile",
                    BehaviorPattern.pattern_name == profile.entity_id
                ).first()
                
                if not pattern:
                    pattern = BehaviorPattern(
                        pattern_name=profile.entity_id,
                        pattern_type='behavioral_profile',
                        pattern_signature=f"{profile.entity_type}:{profile.entity_id}",
                        pattern_rules=profile.normal_patterns,
                        detection_logic={'thresholds': profile.anomaly_thresholds},
                        description=f"Behavioral profile for {profile.entity_type} {profile.entity_id}",
                        category=f"{profile.entity_type}_profile"
                    )
                    db.add(pattern)
                else:
                    pattern.pattern_rules = profile.normal_patterns
                    pattern.detection_logic = {'thresholds': profile.anomaly_thresholds}
                    pattern.updated_at = datetime.now()
                
                db.commit()
                
        except Exception as e:
            logger.error(f"Error saving behavior profile: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get behavioral analyzer statistics."""
        return {
            'cached_profiles': len(self.behavior_profiles),
            'learning_period_days': self.learning_period_days,
            'min_samples_required': self.min_samples_required,
            'anomaly_threshold': self.anomaly_threshold,
            'builtin_patterns': len(self.builtin_patterns)
        }