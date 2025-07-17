"""
Sample Analyzer Plugin

Demonstrates custom vulnerability scanning with pattern matching,
AI-powered analysis, and integration with the MCP event bus.
"""

import asyncio
import hashlib
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
import json

import aiofiles
import yaml

from mcp_plugin_sdk import (
    AnalyzerPlugin, AnalysisRequest, AnalysisResponse, VulnerabilityResult,
    PluginMetadata, PluginContext, SecurityEvent, EventType,
    Severity, VulnerabilityType, MitreAttackTactic
)
from mcp_plugin_sdk.utils.exceptions import PluginError


class VulnerabilityRule:
    """Represents a vulnerability detection rule."""
    
    def __init__(
        self,
        name: str,
        pattern: str,
        severity: Severity,
        vulnerability_type: VulnerabilityType,
        description: str,
        remediation: str = "",
        cwe_ids: List[str] = None,
        mitre_tactics: List[MitreAttackTactic] = None
    ):
        self.name = name
        self.pattern = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        self.severity = severity
        self.vulnerability_type = vulnerability_type
        self.description = description
        self.remediation = remediation
        self.cwe_ids = cwe_ids or []
        self.mitre_tactics = mitre_tactics or []


class SampleAnalyzerPlugin(AnalyzerPlugin):
    """
    Sample vulnerability analyzer plugin.
    
    This plugin demonstrates:
    - Pattern-based vulnerability detection
    - Custom rule engine
    - Event bus integration
    - Configuration management
    - AI-powered analysis (simulated)
    """
    
    def __init__(self, context: PluginContext):
        super().__init__(context)
        
        # Plugin state
        self.rules: List[VulnerabilityRule] = []
        self.supported_extensions = {'.py', '.js', '.php', '.java', '.cpp', '.c', '.cs', '.rb', '.go', '.rs'}
        self.analysis_stats = {
            'total_analyses': 0,
            'vulnerabilities_found': 0,
            'files_analyzed': 0,
            'average_analysis_time': 0.0
        }
        
        # AI simulation state
        self.ai_model_loaded = False
        
    async def initialize(self) -> None:
        """Initialize the analyzer plugin."""
        try:
            self.logger.info("Initializing Sample Analyzer Plugin")
            
            # Load vulnerability rules
            await self._load_rules()
            
            # Initialize AI model (simulated)
            if self.config.get('enable_ai_analysis', False):
                await self._initialize_ai_model()
            
            # Subscribe to analysis events
            if self.event_bus:
                await self.event_bus.subscribe(
                    subscriber_id=self.plugin_id,
                    callback=self._handle_analysis_event,
                    filters={'event_types': ['analysis.requested']}
                )
            
            self.logger.info(f"Loaded {len(self.rules)} vulnerability rules")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize plugin: {e}")
            raise PluginError(f"Initialization failed: {e}")
    
    async def shutdown(self) -> None:
        """Shutdown the analyzer plugin."""
        self.logger.info("Shutting down Sample Analyzer Plugin")
        
        # Save analysis statistics
        await self._save_stats()
        
        # Cleanup AI model
        if self.ai_model_loaded:
            await self._cleanup_ai_model()
    
    def get_metadata(self) -> PluginMetadata:
        """Get plugin metadata."""
        return PluginMetadata(
            name="sample-analyzer",
            version="1.0.0",
            description="Sample vulnerability analyzer plugin",
            plugin_type="analyzer",
            entry_point="src.analyzer:SampleAnalyzerPlugin"
        )
    
    async def analyze(self, request: AnalysisRequest) -> AnalysisResponse:
        """
        Perform vulnerability analysis.
        
        Args:
            request: Analysis request
            
        Returns:
            Analysis response with findings
        """
        start_time = time.time()
        
        try:
            self.logger.info(f"Starting analysis for request {request.request_id}")
            
            # Validate request
            if not await self.validate_request(request):
                return AnalysisResponse(
                    request_id=request.request_id,
                    status="error",
                    error_message="Invalid analysis request",
                    analysis_duration=time.time() - start_time
                )
            
            # Perform analysis based on target type
            vulnerabilities = []
            files_analyzed = 0
            
            if request.target_type == "source_code":
                vulnerabilities, files_analyzed = await self._analyze_source_code(request)
            elif request.target_type == "config_file":
                vulnerabilities, files_analyzed = await self._analyze_config_file(request)
            elif request.target_type == "log_file":
                vulnerabilities, files_analyzed = await self._analyze_log_file(request)
            else:
                return AnalysisResponse(
                    request_id=request.request_id,
                    status="error",
                    error_message=f"Unsupported target type: {request.target_type}",
                    analysis_duration=time.time() - start_time
                )
            
            # Generate summary
            summary = await self._generate_summary(vulnerabilities)
            
            # Update statistics
            duration = time.time() - start_time
            await self._update_stats(len(vulnerabilities), files_analyzed, duration)
            
            # Publish findings to event bus
            if vulnerabilities and self.event_bus:
                await self._publish_findings(request, vulnerabilities)
            
            response = AnalysisResponse(
                request_id=request.request_id,
                status="success",
                vulnerabilities=vulnerabilities,
                summary=summary,
                analysis_duration=duration,
                files_analyzed=files_analyzed,
                rules_executed=len(self.rules),
                analyzer_version="1.0.0"
            )
            
            self.logger.info(
                f"Analysis completed: {len(vulnerabilities)} vulnerabilities found "
                f"in {files_analyzed} files ({duration:.2f}s)"
            )
            
            return response
            
        except asyncio.TimeoutError:
            return AnalysisResponse(
                request_id=request.request_id,
                status="timeout",
                error_message="Analysis timed out",
                analysis_duration=time.time() - start_time
            )
        except Exception as e:
            self.logger.error(f"Analysis failed: {e}")
            return AnalysisResponse(
                request_id=request.request_id,
                status="error",
                error_message=str(e),
                analysis_duration=time.time() - start_time
            )
    
    def get_supported_types(self) -> List[str]:
        """Get supported target types."""
        return ["source_code", "config_file", "log_file"]
    
    def get_rules_info(self) -> Dict[str, Any]:
        """Get information about analysis rules."""
        rule_categories = {}
        for rule in self.rules:
            category = rule.vulnerability_type.value
            rule_categories[category] = rule_categories.get(category, 0) + 1
        
        return {
            "total_rules": len(self.rules),
            "categories": rule_categories,
            "supported_extensions": list(self.supported_extensions),
            "ai_enabled": self.config.get('enable_ai_analysis', False)
        }
    
    async def get_analysis_stats(self) -> Dict[str, Any]:
        """Get analysis statistics."""
        return {
            **self.analysis_stats,
            "rules_loaded": len(self.rules),
            "ai_model_loaded": self.ai_model_loaded,
            "supported_types": self.get_supported_types(),
            "rules_info": self.get_rules_info()
        }
    
    # Private methods
    
    async def _load_rules(self) -> None:
        """Load vulnerability detection rules from configuration."""
        patterns = self.config.get('scan_patterns', [])
        severity_mapping = self.config.get('severity_mapping', {})
        
        # Define built-in rules
        rule_definitions = [
            {
                'name': 'hardcoded_password',
                'pattern': r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'][^"\']{1,50}["\']',
                'severity': 'high',
                'type': 'authentication_bypass',
                'description': 'Hardcoded password detected',
                'remediation': 'Use environment variables or secure configuration management',
                'cwe_ids': ['CWE-798'],
                'mitre_tactics': ['credential_access']
            },
            {
                'name': 'api_key_exposure',
                'pattern': r'(?i)(api_key|apikey|api-key)\s*[=:]\s*["\'][^"\']{10,}["\']',
                'severity': 'high',
                'type': 'information_disclosure',
                'description': 'API key exposure detected',
                'remediation': 'Store API keys securely and rotate exposed keys',
                'cwe_ids': ['CWE-200'],
                'mitre_tactics': ['credential_access']
            },
            {
                'name': 'code_injection',
                'pattern': r'(?i)(eval|exec|system|shell_exec|passthru)\s*\(',
                'severity': 'critical',
                'type': 'code_injection',
                'description': 'Potential code injection vulnerability',
                'remediation': 'Avoid dynamic code execution and validate all inputs',
                'cwe_ids': ['CWE-94'],
                'mitre_tactics': ['execution']
            },
            {
                'name': 'sql_injection',
                'pattern': r'(?i)(union\s+select|drop\s+table|delete\s+from)',
                'severity': 'high',
                'type': 'sql_injection',
                'description': 'Potential SQL injection vulnerability',
                'remediation': 'Use parameterized queries and input validation',
                'cwe_ids': ['CWE-89'],
                'mitre_tactics': ['execution']
            },
            {
                'name': 'xss_vulnerability',
                'pattern': r'(?i)<script[^>]*>.*?</script>',
                'severity': 'medium',
                'type': 'xss',
                'description': 'Potential XSS vulnerability',
                'remediation': 'Sanitize user inputs and use Content Security Policy',
                'cwe_ids': ['CWE-79'],
                'mitre_tactics': ['execution']
            }
        ]
        
        # Create rule objects
        for rule_def in rule_definitions:
            try:
                severity = Severity(severity_mapping.get(rule_def['name'], rule_def['severity']))
                vuln_type = VulnerabilityType(rule_def['type'])
                tactics = [MitreAttackTactic(t) for t in rule_def.get('mitre_tactics', [])]
                
                rule = VulnerabilityRule(
                    name=rule_def['name'],
                    pattern=rule_def['pattern'],
                    severity=severity,
                    vulnerability_type=vuln_type,
                    description=rule_def['description'],
                    remediation=rule_def['remediation'],
                    cwe_ids=rule_def.get('cwe_ids', []),
                    mitre_tactics=tactics
                )
                
                self.rules.append(rule)
                
            except Exception as e:
                self.logger.warning(f"Failed to load rule {rule_def['name']}: {e}")
        
        # Load custom patterns from config
        for i, pattern in enumerate(patterns):
            try:
                rule = VulnerabilityRule(
                    name=f"custom_rule_{i}",
                    pattern=pattern,
                    severity=Severity.MEDIUM,
                    vulnerability_type=VulnerabilityType.OTHER,
                    description=f"Custom pattern match: {pattern[:50]}...",
                    remediation="Review and validate the detected pattern"
                )
                self.rules.append(rule)
                
            except Exception as e:
                self.logger.warning(f"Failed to compile pattern {pattern}: {e}")
    
    async def _analyze_source_code(self, request: AnalysisRequest) -> tuple[List[VulnerabilityResult], int]:
        """Analyze source code for vulnerabilities."""
        vulnerabilities = []
        files_analyzed = 0
        
        target_data = request.target_data
        
        if 'file_path' in target_data:
            # Single file analysis
            file_path = Path(target_data['file_path'])
            if file_path.exists() and file_path.suffix in self.supported_extensions:
                vulns = await self._analyze_file(file_path, request)
                vulnerabilities.extend(vulns)
                files_analyzed = 1
                
        elif 'directory' in target_data:
            # Directory analysis
            directory = Path(target_data['directory'])
            if directory.exists() and directory.is_dir():
                for file_path in directory.rglob('*'):
                    if file_path.is_file() and file_path.suffix in self.supported_extensions:
                        # Check file size limit
                        max_size = self.config.get('max_file_size_mb', 10) * 1024 * 1024
                        if file_path.stat().st_size > max_size:
                            continue
                        
                        vulns = await self._analyze_file(file_path, request)
                        vulnerabilities.extend(vulns)
                        files_analyzed += 1
                        
        elif 'content' in target_data:
            # Direct content analysis
            content = target_data['content']
            filename = target_data.get('filename', 'unknown')
            vulns = await self._analyze_content(content, filename, request)
            vulnerabilities.extend(vulns)
            files_analyzed = 1
        
        return vulnerabilities, files_analyzed
    
    async def _analyze_file(self, file_path: Path, request: AnalysisRequest) -> List[VulnerabilityResult]:
        """Analyze a single file."""
        try:
            async with aiofiles.open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = await f.read()
            
            return await self._analyze_content(content, str(file_path), request)
            
        except Exception as e:
            self.logger.warning(f"Failed to analyze file {file_path}: {e}")
            return []
    
    async def _analyze_content(self, content: str, filename: str, request: AnalysisRequest) -> List[VulnerabilityResult]:
        """Analyze content for vulnerabilities."""
        vulnerabilities = []
        
        # Apply all rules
        for rule in self.rules:
            matches = rule.pattern.finditer(content)
            
            for match in matches:
                # Calculate location information
                line_start = content.rfind('\n', 0, match.start()) + 1
                line_end = content.find('\n', match.end())
                if line_end == -1:
                    line_end = len(content)
                
                line_number = content[:match.start()].count('\n') + 1
                column = match.start() - line_start + 1
                
                # Extract evidence
                evidence_line = content[line_start:line_end].strip()
                
                # Generate vulnerability ID
                vuln_id = hashlib.md5(
                    f"{filename}:{line_number}:{rule.name}:{match.group()}".encode()
                ).hexdigest()[:16]
                
                vulnerability = VulnerabilityResult(
                    vulnerability_id=vuln_id,
                    title=f"{rule.description} in {Path(filename).name}",
                    description=f"Pattern '{rule.name}' detected at line {line_number}",
                    vulnerability_type=rule.vulnerability_type,
                    severity=rule.severity,
                    affected_component=filename,
                    location={
                        'file': filename,
                        'line': line_number,
                        'column': column,
                        'start_pos': match.start(),
                        'end_pos': match.end()
                    },
                    evidence=[evidence_line],
                    cwe_ids=rule.cwe_ids,
                    mitre_tactics=rule.mitre_tactics,
                    remediation=rule.remediation,
                    confidence=0.8,
                    analyzer_name="sample-analyzer"
                )
                
                vulnerabilities.append(vulnerability)
        
        # AI-powered analysis (simulated)
        if self.config.get('enable_ai_analysis', False) and self.ai_model_loaded:
            ai_vulns = await self._ai_analyze_content(content, filename)
            vulnerabilities.extend(ai_vulns)
        
        return vulnerabilities
    
    async def _analyze_config_file(self, request: AnalysisRequest) -> tuple[List[VulnerabilityResult], int]:
        """Analyze configuration files."""
        # Simplified config analysis
        return await self._analyze_source_code(request)
    
    async def _analyze_log_file(self, request: AnalysisRequest) -> tuple[List[VulnerabilityResult], int]:
        """Analyze log files for security events."""
        # Simplified log analysis
        return await self._analyze_source_code(request)
    
    async def _ai_analyze_content(self, content: str, filename: str) -> List[VulnerabilityResult]:
        """Simulate AI-powered vulnerability analysis."""
        # This is a simulation - in a real implementation, this would call
        # an AI model for advanced vulnerability detection
        
        await asyncio.sleep(0.1)  # Simulate AI processing time
        
        vulnerabilities = []
        
        # Simulate AI finding additional vulnerabilities
        if 'subprocess' in content and 'shell=True' in content:
            vuln_id = hashlib.md5(f"{filename}:ai:subprocess_shell".encode()).hexdigest()[:16]
            
            vulnerability = VulnerabilityResult(
                vulnerability_id=vuln_id,
                title=f"AI: Unsafe subprocess usage in {Path(filename).name}",
                description="AI detected potentially unsafe subprocess call with shell=True",
                vulnerability_type=VulnerabilityType.CODE_INJECTION,
                severity=Severity.HIGH,
                affected_component=filename,
                location={'file': filename, 'ai_detected': True},
                evidence=['subprocess.call(..., shell=True)'],
                cwe_ids=['CWE-78'],
                remediation="Use subprocess without shell=True and validate all arguments",
                confidence=0.7,
                analyzer_name="sample-analyzer-ai"
            )
            
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    async def _initialize_ai_model(self) -> None:
        """Initialize AI model (simulated)."""
        self.logger.info("Initializing AI model...")
        await asyncio.sleep(1)  # Simulate model loading
        self.ai_model_loaded = True
        self.logger.info("AI model loaded successfully")
    
    async def _cleanup_ai_model(self) -> None:
        """Cleanup AI model."""
        self.logger.info("Cleaning up AI model...")
        self.ai_model_loaded = False
    
    async def _generate_summary(self, vulnerabilities: List[VulnerabilityResult]) -> Dict[str, Any]:
        """Generate analysis summary."""
        if not vulnerabilities:
            return {
                'total_vulnerabilities': 0,
                'risk_score': 0.0,
                'risk_level': 'none'
            }
        
        # Count by severity
        severity_counts = {}
        for vuln in vulnerabilities:
            severity_counts[vuln.severity.value] = severity_counts.get(vuln.severity.value, 0) + 1
        
        # Calculate risk score
        severity_weights = {
            'critical': 10,
            'high': 7,
            'medium': 4,
            'low': 1,
            'info': 0.5
        }
        
        risk_score = sum(
            severity_weights.get(severity, 0) * count
            for severity, count in severity_counts.items()
        ) / len(vulnerabilities)
        
        # Determine risk level
        if risk_score >= 8:
            risk_level = 'critical'
        elif risk_score >= 6:
            risk_level = 'high'
        elif risk_score >= 3:
            risk_level = 'medium'
        elif risk_score > 0:
            risk_level = 'low'
        else:
            risk_level = 'none'
        
        return {
            'total_vulnerabilities': len(vulnerabilities),
            'severity_counts': severity_counts,
            'risk_score': round(risk_score, 2),
            'risk_level': risk_level,
            'most_common_types': self._get_most_common_types(vulnerabilities)
        }
    
    def _get_most_common_types(self, vulnerabilities: List[VulnerabilityResult]) -> List[Dict[str, Any]]:
        """Get most common vulnerability types."""
        type_counts = {}
        for vuln in vulnerabilities:
            type_counts[vuln.vulnerability_type.value] = type_counts.get(vuln.vulnerability_type.value, 0) + 1
        
        sorted_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)
        return [{'type': t, 'count': c} for t, c in sorted_types[:5]]
    
    async def _update_stats(self, vulnerabilities_found: int, files_analyzed: int, duration: float) -> None:
        """Update analysis statistics."""
        self.analysis_stats['total_analyses'] += 1
        self.analysis_stats['vulnerabilities_found'] += vulnerabilities_found
        self.analysis_stats['files_analyzed'] += files_analyzed
        
        # Update rolling average
        total = self.analysis_stats['total_analyses']
        current_avg = self.analysis_stats['average_analysis_time']
        self.analysis_stats['average_analysis_time'] = (
            (current_avg * (total - 1) + duration) / total
        )
    
    async def _save_stats(self) -> None:
        """Save analysis statistics."""
        try:
            stats_file = Path(self.context.working_directory) / "analysis_stats.json"
            async with aiofiles.open(stats_file, 'w') as f:
                await f.write(json.dumps(self.analysis_stats, indent=2))
        except Exception as e:
            self.logger.warning(f"Failed to save statistics: {e}")
    
    async def _publish_findings(self, request: AnalysisRequest, vulnerabilities: List[VulnerabilityResult]) -> None:
        """Publish vulnerability findings to event bus."""
        for vuln in vulnerabilities:
            event = SecurityEvent(
                event_type=EventType.VULNERABILITY_DETECTED,
                source=self.plugin_id,
                data={
                    'vulnerability_id': vuln.vulnerability_id,
                    'title': vuln.title,
                    'severity': vuln.severity.value,
                    'type': vuln.vulnerability_type.value,
                    'component': vuln.affected_component,
                    'location': vuln.location,
                    'analyzer': vuln.analyzer_name
                },
                priority=vuln.severity.value,
                correlation_id=request.request_id,
                tags=['vulnerability', 'static-analysis']
            )
            
            await self.event_bus.publish(event)
    
    async def _handle_analysis_event(self, event: SecurityEvent) -> None:
        """Handle incoming analysis events."""
        if event.event_type == 'analysis.requested':
            self.logger.info(f"Received analysis request event: {event.event_id}")
            
            # Extract analysis request from event data
            try:
                request_data = event.data
                request = AnalysisRequest(**request_data)
                
                # Perform analysis
                response = await self.analyze(request)
                
                # Publish response event
                response_event = SecurityEvent(
                    event_type='analysis.completed',
                    source=self.plugin_id,
                    data=response.dict(),
                    correlation_id=event.correlation_id
                )
                
                await self.event_bus.publish(response_event)
                
            except Exception as e:
                self.logger.error(f"Failed to handle analysis event: {e}")
                
                # Publish error event
                error_event = SecurityEvent(
                    event_type='analysis.failed',
                    source=self.plugin_id,
                    data={'error': str(e), 'original_event_id': event.event_id},
                    correlation_id=event.correlation_id
                )
                
                await self.event_bus.publish(error_event)