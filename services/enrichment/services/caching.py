"""Caching service for enrichment data."""

import asyncio
import json
import hashlib
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta

import redis.asyncio as redis
import structlog
from shared.config import get_settings

from ..schemas.enrichment import EnrichmentResponse, EnrichmentType, DataType
from ..schemas.threat_intelligence import ThreatIntelligence

settings = get_settings()
logger = structlog.get_logger()


class CachingService:
    """Service for caching enrichment results and threat intelligence."""
    
    def __init__(self):
        self.logger = logger.bind(service="enrichment", component="caching")
        self.redis_client: Optional[redis.Redis] = None
        self.is_running = False
        
        # Cache configuration
        self.cache_config = {
            "enrichment_results": {
                "ttl": 3600,  # 1 hour
                "prefix": "enrich:result:",
            },
            "threat_intelligence": {
                "ttl": 1800,  # 30 minutes
                "prefix": "enrich:ti:",
            },
            "mitre_attack": {
                "ttl": 86400,  # 24 hours
                "prefix": "enrich:mitre:",
            },
            "vulnerability_data": {
                "ttl": 7200,  # 2 hours
                "prefix": "enrich:vuln:",
            },
        }
        
        # Redis connection settings
        self.redis_url = getattr(settings, 'redis_url', 'redis://localhost:6379/0')
        self.redis_password = getattr(settings, 'redis_password', None)
        self.max_connections = getattr(settings, 'redis_max_connections', 10)
    
    async def start(self) -> None:
        """Start the caching service."""
        try:
            # Create Redis connection pool
            self.redis_client = redis.from_url(
                self.redis_url,
                password=self.redis_password,
                max_connections=self.max_connections,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
                retry_on_timeout=True,
            )
            
            # Test connection
            await self.redis_client.ping()
            
            self.is_running = True
            self.logger.info("Caching service started successfully")
            
        except Exception as e:
            self.logger.error("Failed to start caching service", error=str(e))
            raise
    
    async def stop(self) -> None:
        """Stop the caching service."""
        try:
            if self.redis_client:
                await self.redis_client.close()
                self.redis_client = None
            
            self.is_running = False
            self.logger.info("Caching service stopped successfully")
            
        except Exception as e:
            self.logger.error("Error stopping caching service", error=str(e))
            raise
    
    def _generate_cache_key(self, prefix: str, *args) -> str:
        """Generate a cache key from prefix and arguments."""
        # Create a hash of the arguments for consistent key generation
        key_data = ":".join(str(arg) for arg in args)
        key_hash = hashlib.md5(key_data.encode()).hexdigest()
        return f"{prefix}{key_hash}"
    
    def _serialize_data(self, data: Any) -> str:
        """Serialize data for caching."""
        if hasattr(data, 'model_dump'):
            # Pydantic model
            return json.dumps(data.model_dump(), default=str, ensure_ascii=False)
        elif isinstance(data, dict):
            return json.dumps(data, default=str, ensure_ascii=False)
        else:
            return json.dumps(data, default=str, ensure_ascii=False)
    
    def _deserialize_data(self, data: str) -> Dict[str, Any]:
        """Deserialize data from cache."""
        return json.loads(data)
    
    async def cache_enrichment_result(
        self,
        data_type: DataType,
        data: Dict[str, Any],
        enrichment_types: List[EnrichmentType],
        result: EnrichmentResponse
    ) -> None:
        """Cache an enrichment result."""
        try:
            if not self.redis_client:
                return
            
            config = self.cache_config["enrichment_results"]
            
            # Generate cache key
            enrichment_types_str = ":".join(sorted([et.value for et in enrichment_types]))
            data_hash = hashlib.md5(json.dumps(data, sort_keys=True).encode()).hexdigest()
            cache_key = self._generate_cache_key(
                config["prefix"],
                data_type.value,
                enrichment_types_str,
                data_hash
            )
            
            # Serialize result
            cached_data = {
                "result": result.model_dump(),
                "cached_at": datetime.utcnow().isoformat(),
                "data_type": data_type.value,
                "enrichment_types": enrichment_types_str,
            }
            
            serialized_data = self._serialize_data(cached_data)
            
            # Store in cache with TTL
            await self.redis_client.setex(
                cache_key,
                config["ttl"],
                serialized_data
            )
            
            self.logger.debug(
                "Cached enrichment result",
                cache_key=cache_key,
                data_type=data_type.value,
                ttl=config["ttl"]
            )
            
        except Exception as e:
            self.logger.error("Error caching enrichment result", error=str(e))
    
    async def get_enrichment_result(
        self,
        data_type: DataType,
        data: Dict[str, Any],
        enrichment_types: List[EnrichmentType]
    ) -> Optional[EnrichmentResponse]:
        """Get cached enrichment result."""
        try:
            if not self.redis_client:
                return None
            
            config = self.cache_config["enrichment_results"]
            
            # Generate cache key
            enrichment_types_str = ":".join(sorted([et.value for et in enrichment_types]))
            data_hash = hashlib.md5(json.dumps(data, sort_keys=True).encode()).hexdigest()
            cache_key = self._generate_cache_key(
                config["prefix"],
                data_type.value,
                enrichment_types_str,
                data_hash
            )
            
            # Get from cache
            cached_data = await self.redis_client.get(cache_key)
            if not cached_data:
                return None
            
            # Deserialize and reconstruct response
            data_dict = self._deserialize_data(cached_data)
            result_data = data_dict["result"]
            
            # Reconstruct EnrichmentResponse
            response = EnrichmentResponse(**result_data)
            
            self.logger.debug(
                "Retrieved cached enrichment result",
                cache_key=cache_key,
                data_type=data_type.value
            )
            
            return response
            
        except Exception as e:
            self.logger.error("Error getting cached enrichment result", error=str(e))
            return None
    
    async def cache_threat_intelligence(
        self,
        indicator_value: str,
        indicator_type: str,
        threat_intelligence: ThreatIntelligence
    ) -> None:
        """Cache threat intelligence data."""
        try:
            if not self.redis_client:
                return
            
            config = self.cache_config["threat_intelligence"]
            
            # Generate cache key
            cache_key = self._generate_cache_key(
                config["prefix"],
                indicator_type,
                indicator_value
            )
            
            # Serialize threat intelligence
            cached_data = {
                "threat_intelligence": threat_intelligence.model_dump(),
                "cached_at": datetime.utcnow().isoformat(),
                "indicator_value": indicator_value,
                "indicator_type": indicator_type,
            }
            
            serialized_data = self._serialize_data(cached_data)
            
            # Store in cache with TTL
            await self.redis_client.setex(
                cache_key,
                config["ttl"],
                serialized_data
            )
            
            self.logger.debug(
                "Cached threat intelligence",
                cache_key=cache_key,
                indicator_type=indicator_type,
                indicator_value=indicator_value[:50] + "..." if len(indicator_value) > 50 else indicator_value
            )
            
        except Exception as e:
            self.logger.error("Error caching threat intelligence", error=str(e))
    
    async def get_threat_intelligence(
        self,
        indicator_value: str,
        indicator_type: str
    ) -> Optional[ThreatIntelligence]:
        """Get cached threat intelligence data."""
        try:
            if not self.redis_client:
                return None
            
            config = self.cache_config["threat_intelligence"]
            
            # Generate cache key
            cache_key = self._generate_cache_key(
                config["prefix"],
                indicator_type,
                indicator_value
            )
            
            # Get from cache
            cached_data = await self.redis_client.get(cache_key)
            if not cached_data:
                return None
            
            # Deserialize and reconstruct threat intelligence
            data_dict = self._deserialize_data(cached_data)
            ti_data = data_dict["threat_intelligence"]
            
            # Reconstruct ThreatIntelligence
            threat_intelligence = ThreatIntelligence(**ti_data)
            
            self.logger.debug(
                "Retrieved cached threat intelligence",
                cache_key=cache_key,
                indicator_type=indicator_type
            )
            
            return threat_intelligence
            
        except Exception as e:
            self.logger.error("Error getting cached threat intelligence", error=str(e))
            return None
    
    async def cache_mitre_attack_data(
        self,
        technique_id: str,
        technique_data: Dict[str, Any]
    ) -> None:
        """Cache MITRE ATT&CK technique data."""
        try:
            if not self.redis_client:
                return
            
            config = self.cache_config["mitre_attack"]
            
            # Generate cache key
            cache_key = self._generate_cache_key(
                config["prefix"],
                "technique",
                technique_id
            )
            
            # Serialize technique data
            cached_data = {
                "technique_data": technique_data,
                "cached_at": datetime.utcnow().isoformat(),
                "technique_id": technique_id,
            }
            
            serialized_data = self._serialize_data(cached_data)
            
            # Store in cache with TTL
            await self.redis_client.setex(
                cache_key,
                config["ttl"],
                serialized_data
            )
            
            self.logger.debug(
                "Cached MITRE ATT&CK technique data",
                cache_key=cache_key,
                technique_id=technique_id
            )
            
        except Exception as e:
            self.logger.error("Error caching MITRE ATT&CK data", error=str(e))
    
    async def get_mitre_attack_data(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """Get cached MITRE ATT&CK technique data."""
        try:
            if not self.redis_client:
                return None
            
            config = self.cache_config["mitre_attack"]
            
            # Generate cache key
            cache_key = self._generate_cache_key(
                config["prefix"],
                "technique",
                technique_id
            )
            
            # Get from cache
            cached_data = await self.redis_client.get(cache_key)
            if not cached_data:
                return None
            
            # Deserialize technique data
            data_dict = self._deserialize_data(cached_data)
            technique_data = data_dict["technique_data"]
            
            self.logger.debug(
                "Retrieved cached MITRE ATT&CK data",
                cache_key=cache_key,
                technique_id=technique_id
            )
            
            return technique_data
            
        except Exception as e:
            self.logger.error("Error getting cached MITRE ATT&CK data", error=str(e))
            return None
    
    async def cache_vulnerability_data(
        self,
        cve_id: str,
        vulnerability_data: Dict[str, Any]
    ) -> None:
        """Cache vulnerability data."""
        try:
            if not self.redis_client:
                return
            
            config = self.cache_config["vulnerability_data"]
            
            # Generate cache key
            cache_key = self._generate_cache_key(
                config["prefix"],
                cve_id
            )
            
            # Serialize vulnerability data
            cached_data = {
                "vulnerability_data": vulnerability_data,
                "cached_at": datetime.utcnow().isoformat(),
                "cve_id": cve_id,
            }
            
            serialized_data = self._serialize_data(cached_data)
            
            # Store in cache with TTL
            await self.redis_client.setex(
                cache_key,
                config["ttl"],
                serialized_data
            )
            
            self.logger.debug(
                "Cached vulnerability data",
                cache_key=cache_key,
                cve_id=cve_id
            )
            
        except Exception as e:
            self.logger.error("Error caching vulnerability data", error=str(e))
    
    async def get_vulnerability_data(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get cached vulnerability data."""
        try:
            if not self.redis_client:
                return None
            
            config = self.cache_config["vulnerability_data"]
            
            # Generate cache key
            cache_key = self._generate_cache_key(
                config["prefix"],
                cve_id
            )
            
            # Get from cache
            cached_data = await self.redis_client.get(cache_key)
            if not cached_data:
                return None
            
            # Deserialize vulnerability data
            data_dict = self._deserialize_data(cached_data)
            vulnerability_data = data_dict["vulnerability_data"]
            
            self.logger.debug(
                "Retrieved cached vulnerability data",
                cache_key=cache_key,
                cve_id=cve_id
            )
            
            return vulnerability_data
            
        except Exception as e:
            self.logger.error("Error getting cached vulnerability data", error=str(e))
            return None
    
    async def invalidate_cache(self, pattern: str) -> int:
        """Invalidate cache entries matching a pattern."""
        try:
            if not self.redis_client:
                return 0
            
            # Find keys matching pattern
            keys = await self.redis_client.keys(pattern)
            
            if keys:
                # Delete matching keys
                deleted_count = await self.redis_client.delete(*keys)
                
                self.logger.info(
                    "Invalidated cache entries",
                    pattern=pattern,
                    deleted_count=deleted_count
                )
                
                return deleted_count
            
            return 0
            
        except Exception as e:
            self.logger.error("Error invalidating cache", pattern=pattern, error=str(e))
            return 0
    
    async def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        try:
            if not self.redis_client:
                return {"status": "disconnected"}
            
            # Get Redis info
            info = await self.redis_client.info()
            
            # Get key counts for each cache type
            cache_stats = {}
            for cache_type, config in self.cache_config.items():
                pattern = f"{config['prefix']}*"
                keys = await self.redis_client.keys(pattern)
                cache_stats[cache_type] = {
                    "key_count": len(keys),
                    "ttl": config["ttl"],
                    "prefix": config["prefix"],
                }
            
            return {
                "status": "connected",
                "redis_info": {
                    "used_memory": info.get("used_memory_human"),
                    "connected_clients": info.get("connected_clients"),
                    "total_commands_processed": info.get("total_commands_processed"),
                    "keyspace_hits": info.get("keyspace_hits"),
                    "keyspace_misses": info.get("keyspace_misses"),
                    "uptime_in_seconds": info.get("uptime_in_seconds"),
                },
                "cache_types": cache_stats,
                "timestamp": datetime.utcnow().isoformat(),
            }
            
        except Exception as e:
            self.logger.error("Error getting cache stats", error=str(e))
            return {"status": "error", "error": str(e)}
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on the caching service."""
        health_status = {
            "service": "caching",
            "status": "healthy" if self.is_running else "stopped",
            "timestamp": datetime.utcnow().isoformat(),
        }
        
        if self.redis_client:
            try:
                # Test Redis connection
                latency_start = datetime.utcnow()
                await self.redis_client.ping()
                latency = (datetime.utcnow() - latency_start).total_seconds() * 1000
                
                health_status["redis"] = {
                    "status": "connected",
                    "latency_ms": latency,
                }
                
                # Get basic stats
                stats = await self.get_cache_stats()
                health_status["cache_stats"] = stats
                
            except Exception as e:
                health_status["redis"] = {
                    "status": "unhealthy",
                    "error": str(e),
                }
                health_status["status"] = "unhealthy"
        else:
            health_status["redis"] = {"status": "disconnected"}
            health_status["status"] = "unhealthy"
        
        return health_status
    
    def get_stats(self) -> Dict[str, Any]:
        """Get caching service statistics."""
        return {
            "service": "caching",
            "is_running": self.is_running,
            "redis_url": self.redis_url.split('@')[-1] if '@' in self.redis_url else self.redis_url,  # Hide credentials
            "max_connections": self.max_connections,
            "cache_types": list(self.cache_config.keys()),
            "timestamp": datetime.utcnow().isoformat(),
        }