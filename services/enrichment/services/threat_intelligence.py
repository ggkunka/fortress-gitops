"""Threat intelligence service for enriching data with threat intelligence."""

import asyncio
import hashlib
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta

import httpx
import structlog
from shared.config import get_settings

from ..schemas.threat_intelligence import (
    ThreatIntelligence, IoC, ThreatActor, Malware, Campaign,
    ThreatLevel, IndicatorType, MalwareFamily, ThreatActorType
)
from ..schemas.enrichment import DataType
from .caching import CachingService

settings = get_settings()
logger = structlog.get_logger()


class ThreatIntelligenceService:
    """Service for enriching data with threat intelligence."""
    
    def __init__(self):
        self.logger = logger.bind(service="enrichment", component="threat_intelligence")
        self.caching_service = CachingService()
        self.is_running = False
        
        # Threat intelligence sources configuration
        self.sources = {
            "misp": {
                "url": settings.misp_url if hasattr(settings, 'misp_url') else None,
                "api_key": settings.misp_api_key if hasattr(settings, 'misp_api_key') else None,
                "enabled": True,
            },
            "virustotal": {
                "url": "https://www.virustotal.com/vtapi/v2",
                "api_key": settings.virustotal_api_key if hasattr(settings, 'virustotal_api_key') else None,
                "enabled": True,
            },
            "otx": {
                "url": "https://otx.alienvault.com/api/v1",
                "api_key": settings.otx_api_key if hasattr(settings, 'otx_api_key') else None,
                "enabled": True,
            },
            "threatminer": {
                "url": "https://www.threatminer.org/api.php",
                "api_key": None,  # No API key required
                "enabled": True,
            },
            "urlvoid": {
                "url": "http://api.urlvoid.com/1000",
                "api_key": settings.urlvoid_api_key if hasattr(settings, 'urlvoid_api_key') else None,
                "enabled": True,
            },
        }
        
        # HTTP client for API calls
        self.http_client = httpx.AsyncClient(timeout=30.0)
    
    async def start(self) -> None:
        """Start the threat intelligence service."""
        try:
            await self.caching_service.start()
            self.is_running = True
            self.logger.info("Threat intelligence service started")
        except Exception as e:
            self.logger.error("Failed to start threat intelligence service", error=str(e))
            raise
    
    async def stop(self) -> None:
        """Stop the threat intelligence service."""
        try:
            await self.http_client.aclose()
            await self.caching_service.stop()
            self.is_running = False
            self.logger.info("Threat intelligence service stopped")
        except Exception as e:
            self.logger.error("Error stopping threat intelligence service", error=str(e))
            raise
    
    async def enrich(self, data: Dict[str, Any], data_type: DataType) -> Dict[str, Any]:
        """Enrich data with threat intelligence."""
        try:
            self.logger.info(
                "Starting threat intelligence enrichment",
                data_type=data_type
            )
            
            start_time = datetime.utcnow()
            
            # Extract indicators based on data type
            indicators = await self._extract_indicators(data, data_type)
            
            if not indicators:
                self.logger.info("No indicators found for enrichment")
                return {
                    "data": {},
                    "enriched_data": data,
                    "confidence": 0.0,
                    "sources": [],
                    "metadata": {
                        "indicators_found": 0,
                        "processing_time": 0.0,
                    }
                }
            
            # Enrich indicators with threat intelligence
            threat_intelligence = await self._enrich_indicators(indicators)
            
            # Calculate processing time
            processing_time = (datetime.utcnow() - start_time).total_seconds()
            
            # Apply enrichment to original data
            enriched_data = await self._apply_enrichment(data, threat_intelligence)
            
            # Determine overall confidence and sources
            confidence = self._calculate_confidence(threat_intelligence)
            sources = self._get_sources_used(threat_intelligence)
            
            return {
                "data": threat_intelligence.model_dump(),
                "enriched_data": enriched_data,
                "confidence": confidence,
                "sources": sources,
                "metadata": {
                    "indicators_found": len(indicators),
                    "processing_time": processing_time,
                    "threat_level": threat_intelligence.threat_level.value,
                    "risk_score": threat_intelligence.risk_score,
                }
            }
            
        except Exception as e:
            self.logger.error("Error in threat intelligence enrichment", error=str(e))
            raise
    
    async def _extract_indicators(self, data: Dict[str, Any], data_type: DataType) -> List[Dict[str, Any]]:
        """Extract indicators from data based on data type."""
        indicators = []
        
        try:
            if data_type == DataType.SBOM:
                indicators.extend(await self._extract_sbom_indicators(data))
            elif data_type == DataType.CVE:
                indicators.extend(await self._extract_cve_indicators(data))
            elif data_type == DataType.RUNTIME:
                indicators.extend(await self._extract_runtime_indicators(data))
            
            self.logger.info(
                "Extracted indicators",
                data_type=data_type,
                indicator_count=len(indicators)
            )
            
        except Exception as e:
            self.logger.error("Error extracting indicators", error=str(e))
        
        return indicators
    
    async def _extract_sbom_indicators(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract indicators from SBOM data."""
        indicators = []
        
        # Extract from components
        for component in data.get("components", []):
            # Component names and versions
            if component.get("name"):
                indicators.append({
                    "type": "component_name",
                    "value": component["name"],
                    "context": {
                        "component_type": component.get("type"),
                        "version": component.get("version"),
                        "purl": component.get("purl"),
                    }
                })
            
            # Download locations (URLs)
            if component.get("download_location"):
                indicators.append({
                    "type": IndicatorType.URL,
                    "value": component["download_location"],
                    "context": {
                        "component_name": component.get("name"),
                        "component_version": component.get("version"),
                    }
                })
            
            # File hashes
            for hash_info in component.get("hashes", []):
                if hash_info.get("value"):
                    indicators.append({
                        "type": IndicatorType.FILE_HASH,
                        "value": hash_info["value"],
                        "context": {
                            "algorithm": hash_info.get("algorithm"),
                            "component_name": component.get("name"),
                            "component_version": component.get("version"),
                        }
                    })
        
        # Extract from vulnerabilities
        for vulnerability in data.get("vulnerabilities", []):
            if vulnerability.get("id"):
                indicators.append({
                    "type": "vulnerability_id",
                    "value": vulnerability["id"],
                    "context": {
                        "description": vulnerability.get("description"),
                        "severity": vulnerability.get("severity"),
                        "cvss_score": vulnerability.get("cvss_score"),
                    }
                })
        
        return indicators
    
    async def _extract_cve_indicators(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract indicators from CVE data."""
        indicators = []
        
        # CVE ID
        if data.get("cve_id"):
            indicators.append({
                "type": "cve_id",
                "value": data["cve_id"],
                "context": {
                    "description": data.get("description"),
                    "severity": self._extract_cve_severity(data),
                    "published_date": data.get("published_date"),
                }
            })
        
        # References (URLs)
        for reference in data.get("references", []):
            if reference.get("url"):
                indicators.append({
                    "type": IndicatorType.URL,
                    "value": reference["url"],
                    "context": {
                        "cve_id": data.get("cve_id"),
                        "source": reference.get("source"),
                    }
                })
        
        # CPE configurations
        for config in data.get("configurations", []):
            for cpe_match in config.get("cpe_match", []):
                if cpe_match.get("cpe23Uri"):
                    indicators.append({
                        "type": "cpe",
                        "value": cpe_match["cpe23Uri"],
                        "context": {
                            "cve_id": data.get("cve_id"),
                            "vulnerable": cpe_match.get("vulnerable", False),
                        }
                    })
        
        return indicators
    
    async def _extract_runtime_indicators(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract indicators from runtime behavior data."""
        indicators = []
        
        # Process events
        for event in data.get("events", []):
            event_type = event.get("event_type")
            event_data = event.get("data", {})
            
            # Network connections
            if event_type == "network_connection":
                if event_data.get("destination_ip"):
                    indicators.append({
                        "type": IndicatorType.IP_ADDRESS,
                        "value": event_data["destination_ip"],
                        "context": {
                            "source": "network_connection",
                            "destination_port": event_data.get("destination_port"),
                            "protocol": event_data.get("protocol"),
                            "timestamp": event.get("timestamp"),
                        }
                    })
            
            # Process execution
            elif event_type == "process_start":
                if event_data.get("process_name"):
                    indicators.append({
                        "type": IndicatorType.PROCESS,
                        "value": event_data["process_name"],
                        "context": {
                            "command_line": event_data.get("command_line"),
                            "user": event_data.get("user"),
                            "parent_process": event_data.get("parent_process_id"),
                            "timestamp": event.get("timestamp"),
                        }
                    })
                
                if event_data.get("command_line"):
                    indicators.append({
                        "type": IndicatorType.COMMAND_LINE,
                        "value": event_data["command_line"],
                        "context": {
                            "process_name": event_data.get("process_name"),
                            "user": event_data.get("user"),
                            "timestamp": event.get("timestamp"),
                        }
                    })
            
            # File operations
            elif event_type == "file_access":
                if event_data.get("file_path"):
                    indicators.append({
                        "type": "file_path",
                        "value": event_data["file_path"],
                        "context": {
                            "operation": event_data.get("operation"),
                            "process_name": event_data.get("process_name"),
                            "timestamp": event.get("timestamp"),
                        }
                    })
        
        # Anomalies
        for anomaly in data.get("anomalies", []):
            if anomaly.get("type") == "suspicious_process":
                metadata = anomaly.get("metadata", {})
                if metadata.get("process_name"):
                    indicators.append({
                        "type": IndicatorType.PROCESS,
                        "value": metadata["process_name"],
                        "context": {
                            "anomaly_type": anomaly.get("type"),
                            "severity": anomaly.get("severity"),
                            "confidence": anomaly.get("confidence"),
                            "timestamp": anomaly.get("timestamp"),
                        }
                    })
        
        return indicators
    
    async def _enrich_indicators(self, indicators: List[Dict[str, Any]]) -> ThreatIntelligence:
        """Enrich indicators with threat intelligence from various sources."""
        # Initialize threat intelligence object
        threat_intelligence = ThreatIntelligence(
            intelligence_id=f"ti_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
            data_type="mixed",
            threat_level=ThreatLevel.UNKNOWN,
            confidence=0.0,
            risk_score=0.0,
        )
        
        # Process each indicator
        for indicator in indicators:
            try:
                # Check cache first
                cached_result = await self.caching_service.get_threat_intelligence(
                    indicator["value"], indicator["type"]
                )
                
                if cached_result:
                    self._merge_threat_intelligence(threat_intelligence, cached_result)
                    continue
                
                # Enrich with multiple sources
                enrichment_tasks = []
                
                # Create tasks for each enabled source
                for source_name, source_config in self.sources.items():
                    if source_config["enabled"]:
                        task = asyncio.create_task(
                            self._enrich_with_source(indicator, source_name, source_config)
                        )
                        enrichment_tasks.append(task)
                
                # Wait for all enrichment tasks to complete
                if enrichment_tasks:
                    results = await asyncio.gather(*enrichment_tasks, return_exceptions=True)
                    
                    # Process results
                    for result in results:
                        if isinstance(result, Exception):
                            self.logger.warning(
                                "Enrichment source failed",
                                indicator=indicator["value"],
                                error=str(result)
                            )
                        elif result:
                            self._merge_threat_intelligence(threat_intelligence, result)
                
                # Cache the enriched result
                await self.caching_service.cache_threat_intelligence(
                    indicator["value"], indicator["type"], threat_intelligence
                )
                
            except Exception as e:
                self.logger.error(
                    "Error enriching indicator",
                    indicator=indicator["value"],
                    error=str(e)
                )
        
        # Calculate final threat level and confidence
        threat_intelligence.threat_level = self._calculate_threat_level(threat_intelligence)
        threat_intelligence.confidence = self._calculate_confidence(threat_intelligence)
        threat_intelligence.risk_score = self._calculate_risk_score(threat_intelligence)
        
        return threat_intelligence
    
    async def _enrich_with_source(
        self,
        indicator: Dict[str, Any],
        source_name: str,
        source_config: Dict[str, Any]
    ) -> Optional[ThreatIntelligence]:
        """Enrich an indicator with a specific threat intelligence source."""
        try:
            if source_name == "virustotal":
                return await self._enrich_with_virustotal(indicator, source_config)
            elif source_name == "otx":
                return await self._enrich_with_otx(indicator, source_config)
            elif source_name == "threatminer":
                return await self._enrich_with_threatminer(indicator, source_config)
            elif source_name == "urlvoid":
                return await self._enrich_with_urlvoid(indicator, source_config)
            elif source_name == "misp":
                return await self._enrich_with_misp(indicator, source_config)
            else:
                self.logger.warning("Unknown threat intelligence source", source=source_name)
                return None
                
        except Exception as e:
            self.logger.error(
                "Error enriching with source",
                source=source_name,
                indicator=indicator["value"],
                error=str(e)
            )
            return None
    
    async def _enrich_with_virustotal(
        self,
        indicator: Dict[str, Any],
        source_config: Dict[str, Any]
    ) -> Optional[ThreatIntelligence]:
        """Enrich with VirusTotal API."""
        if not source_config.get("api_key"):
            return None
        
        try:
            # Mock implementation - in real scenario, make API call to VirusTotal
            # This is a placeholder for demonstration
            threat_intelligence = ThreatIntelligence(
                intelligence_id=f"vt_{hashlib.md5(indicator['value'].encode()).hexdigest()}",
                data_type=indicator.get("type", "unknown"),
                threat_level=ThreatLevel.MEDIUM,
                confidence=0.8,
                sources=["virustotal"],
                risk_score=5.0,
            )
            
            # Add mock IoC
            if indicator["type"] in [IndicatorType.DOMAIN, IndicatorType.IP_ADDRESS, IndicatorType.URL]:
                ioc = IoC(
                    indicator_id=f"vt_ioc_{hashlib.md5(indicator['value'].encode()).hexdigest()}",
                    indicator_type=indicator["type"],
                    value=indicator["value"],
                    threat_level=ThreatLevel.MEDIUM,
                    confidence=0.8,
                    first_seen=datetime.utcnow() - timedelta(days=30),
                    last_seen=datetime.utcnow(),
                    sources=["virustotal"],
                    tags=["malicious", "virustotal"],
                )
                threat_intelligence.indicators.append(ioc)
            
            return threat_intelligence
            
        except Exception as e:
            self.logger.error("VirusTotal enrichment failed", error=str(e))
            return None
    
    async def _enrich_with_otx(
        self,
        indicator: Dict[str, Any],
        source_config: Dict[str, Any]
    ) -> Optional[ThreatIntelligence]:
        """Enrich with AlienVault OTX API."""
        try:
            # Mock implementation
            threat_intelligence = ThreatIntelligence(
                intelligence_id=f"otx_{hashlib.md5(indicator['value'].encode()).hexdigest()}",
                data_type=indicator.get("type", "unknown"),
                threat_level=ThreatLevel.LOW,
                confidence=0.6,
                sources=["otx"],
                risk_score=3.0,
            )
            
            return threat_intelligence
            
        except Exception as e:
            self.logger.error("OTX enrichment failed", error=str(e))
            return None
    
    async def _enrich_with_threatminer(
        self,
        indicator: Dict[str, Any],
        source_config: Dict[str, Any]
    ) -> Optional[ThreatIntelligence]:
        """Enrich with ThreatMiner API."""
        try:
            # Mock implementation
            threat_intelligence = ThreatIntelligence(
                intelligence_id=f"tm_{hashlib.md5(indicator['value'].encode()).hexdigest()}",
                data_type=indicator.get("type", "unknown"),
                threat_level=ThreatLevel.LOW,
                confidence=0.5,
                sources=["threatminer"],
                risk_score=2.0,
            )
            
            return threat_intelligence
            
        except Exception as e:
            self.logger.error("ThreatMiner enrichment failed", error=str(e))
            return None
    
    async def _enrich_with_urlvoid(
        self,
        indicator: Dict[str, Any],
        source_config: Dict[str, Any]
    ) -> Optional[ThreatIntelligence]:
        """Enrich with URLVoid API."""
        if not source_config.get("api_key") or indicator["type"] != IndicatorType.URL:
            return None
        
        try:
            # Mock implementation
            threat_intelligence = ThreatIntelligence(
                intelligence_id=f"uv_{hashlib.md5(indicator['value'].encode()).hexdigest()}",
                data_type=indicator.get("type", "unknown"),
                threat_level=ThreatLevel.LOW,
                confidence=0.4,
                sources=["urlvoid"],
                risk_score=1.0,
            )
            
            return threat_intelligence
            
        except Exception as e:
            self.logger.error("URLVoid enrichment failed", error=str(e))
            return None
    
    async def _enrich_with_misp(
        self,
        indicator: Dict[str, Any],
        source_config: Dict[str, Any]
    ) -> Optional[ThreatIntelligence]:
        """Enrich with MISP API."""
        if not source_config.get("url") or not source_config.get("api_key"):
            return None
        
        try:
            # Mock implementation
            threat_intelligence = ThreatIntelligence(
                intelligence_id=f"misp_{hashlib.md5(indicator['value'].encode()).hexdigest()}",
                data_type=indicator.get("type", "unknown"),
                threat_level=ThreatLevel.HIGH,
                confidence=0.9,
                sources=["misp"],
                risk_score=7.0,
            )
            
            return threat_intelligence
            
        except Exception as e:
            self.logger.error("MISP enrichment failed", error=str(e))
            return None
    
    def _merge_threat_intelligence(
        self,
        target: ThreatIntelligence,
        source: ThreatIntelligence
    ) -> None:
        """Merge threat intelligence from multiple sources."""
        # Merge sources
        target.sources.extend(source.sources)
        target.sources = list(set(target.sources))  # Remove duplicates
        
        # Merge indicators
        target.indicators.extend(source.indicators)
        
        # Merge threat actors
        target.threat_actors.extend(source.threat_actors)
        
        # Merge malware
        target.malware.extend(source.malware)
        
        # Merge campaigns
        target.campaigns.extend(source.campaigns)
        
        # Merge TTPs
        target.ttps.extend(source.ttps)
        target.ttps = list(set(target.ttps))  # Remove duplicates
        
        # Merge kill chain phases
        target.kill_chain_phases.extend(source.kill_chain_phases)
        target.kill_chain_phases = list(set(target.kill_chain_phases))
        
        # Merge recommendations
        target.recommendations.extend(source.recommendations)
        
        # Update confidence and risk score (use highest values)
        target.confidence = max(target.confidence, source.confidence)
        target.risk_score = max(target.risk_score, source.risk_score)
    
    def _calculate_threat_level(self, threat_intelligence: ThreatIntelligence) -> ThreatLevel:
        """Calculate overall threat level based on indicators."""
        max_level = ThreatLevel.UNKNOWN
        
        for indicator in threat_intelligence.indicators:
            if indicator.threat_level == ThreatLevel.CRITICAL:
                return ThreatLevel.CRITICAL
            elif indicator.threat_level == ThreatLevel.HIGH:
                max_level = ThreatLevel.HIGH
            elif indicator.threat_level == ThreatLevel.MEDIUM and max_level not in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
                max_level = ThreatLevel.MEDIUM
            elif indicator.threat_level == ThreatLevel.LOW and max_level == ThreatLevel.UNKNOWN:
                max_level = ThreatLevel.LOW
        
        return max_level
    
    def _calculate_confidence(self, threat_intelligence: ThreatIntelligence) -> float:
        """Calculate overall confidence score."""
        if not threat_intelligence.indicators:
            return 0.0
        
        # Use weighted average based on sources
        source_weights = {
            "misp": 0.9,
            "virustotal": 0.8,
            "otx": 0.7,
            "threatminer": 0.6,
            "urlvoid": 0.5,
        }
        
        total_weight = 0.0
        weighted_confidence = 0.0
        
        for indicator in threat_intelligence.indicators:
            for source in indicator.sources:
                weight = source_weights.get(source, 0.5)
                total_weight += weight
                weighted_confidence += indicator.confidence * weight
        
        if total_weight > 0:
            return min(weighted_confidence / total_weight, 1.0)
        else:
            return 0.0
    
    def _calculate_risk_score(self, threat_intelligence: ThreatIntelligence) -> float:
        """Calculate risk score based on threat level and confidence."""
        threat_level_scores = {
            ThreatLevel.UNKNOWN: 0.0,
            ThreatLevel.LOW: 2.0,
            ThreatLevel.MEDIUM: 5.0,
            ThreatLevel.HIGH: 8.0,
            ThreatLevel.CRITICAL: 10.0,
        }
        
        base_score = threat_level_scores.get(threat_intelligence.threat_level, 0.0)
        confidence_multiplier = threat_intelligence.confidence
        
        # Factor in number of sources
        source_bonus = min(len(threat_intelligence.sources) * 0.5, 2.0)
        
        risk_score = (base_score * confidence_multiplier) + source_bonus
        
        return min(risk_score, 10.0)
    
    def _get_sources_used(self, threat_intelligence: ThreatIntelligence) -> List[str]:
        """Get list of sources used in enrichment."""
        return list(set(threat_intelligence.sources))
    
    def _extract_cve_severity(self, cve_data: Dict[str, Any]) -> str:
        """Extract CVE severity from metrics."""
        metrics = cve_data.get("metrics", {})
        
        # Try CVSS v3 first
        cvss_v3 = metrics.get("cvss_v3", {})
        if cvss_v3.get("baseSeverity"):
            return cvss_v3["baseSeverity"].lower()
        
        # Fall back to CVSS v2
        cvss_v2 = metrics.get("cvss_v2", {})
        if cvss_v2.get("baseScore"):
            score = cvss_v2["baseScore"]
            if score >= 7.0:
                return "high"
            elif score >= 4.0:
                return "medium"
            else:
                return "low"
        
        return "unknown"
    
    async def _apply_enrichment(
        self,
        original_data: Dict[str, Any],
        threat_intelligence: ThreatIntelligence
    ) -> Dict[str, Any]:
        """Apply threat intelligence enrichment to original data."""
        enriched_data = original_data.copy()
        
        # Add threat intelligence summary
        enriched_data["threat_intelligence"] = {
            "threat_level": threat_intelligence.threat_level.value,
            "confidence": threat_intelligence.confidence,
            "risk_score": threat_intelligence.risk_score,
            "sources": threat_intelligence.sources,
            "indicators_count": len(threat_intelligence.indicators),
            "threat_actors_count": len(threat_intelligence.threat_actors),
            "malware_count": len(threat_intelligence.malware),
            "campaigns_count": len(threat_intelligence.campaigns),
            "recommendations": threat_intelligence.recommendations,
        }
        
        # Add indicators summary
        if threat_intelligence.indicators:
            enriched_data["indicators"] = [
                {
                    "type": indicator.indicator_type.value,
                    "value": indicator.value,
                    "threat_level": indicator.threat_level.value,
                    "confidence": indicator.confidence,
                    "sources": indicator.sources,
                    "tags": indicator.tags,
                }
                for indicator in threat_intelligence.indicators
            ]
        
        # Add threat actors summary
        if threat_intelligence.threat_actors:
            enriched_data["threat_actors"] = [
                {
                    "name": actor.name,
                    "type": actor.actor_type.value,
                    "sophistication": actor.sophistication,
                    "motivation": actor.motivation,
                    "active": actor.active,
                }
                for actor in threat_intelligence.threat_actors
            ]
        
        # Add malware summary
        if threat_intelligence.malware:
            enriched_data["malware"] = [
                {
                    "name": malware.name,
                    "family": malware.family.value,
                    "capabilities": malware.capabilities,
                    "active": malware.active,
                }
                for malware in threat_intelligence.malware
            ]
        
        return enriched_data
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on the threat intelligence service."""
        health_status = {
            "service": "threat_intelligence",
            "status": "healthy" if self.is_running else "stopped",
            "sources": {},
            "timestamp": datetime.utcnow().isoformat(),
        }
        
        # Check each source
        for source_name, source_config in self.sources.items():
            health_status["sources"][source_name] = {
                "enabled": source_config["enabled"],
                "has_api_key": source_config.get("api_key") is not None,
                "url": source_config.get("url"),
            }
        
        # Check caching service
        try:
            cache_health = await self.caching_service.health_check()
            health_status["caching"] = cache_health
        except Exception as e:
            health_status["caching"] = {"status": "unhealthy", "error": str(e)}
        
        return health_status
    
    def get_stats(self) -> Dict[str, Any]:
        """Get threat intelligence service statistics."""
        return {
            "service": "threat_intelligence",
            "is_running": self.is_running,
            "enabled_sources": [
                name for name, config in self.sources.items()
                if config["enabled"]
            ],
            "total_sources": len(self.sources),
            "timestamp": datetime.utcnow().isoformat(),
        }