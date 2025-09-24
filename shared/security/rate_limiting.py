"""
Advanced rate limiting implementation for MCP Security Platform.
"""

import time
import json
import hashlib
from typing import Dict, Any, Optional, List, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
import asyncio
from abc import ABC, abstractmethod

import redis.asyncio as redis
from ..observability.logging import get_logger


class RateLimitAlgorithm(Enum):
    """Rate limiting algorithms."""
    TOKEN_BUCKET = "token_bucket"
    SLIDING_WINDOW = "sliding_window"
    FIXED_WINDOW = "fixed_window"
    LEAKY_BUCKET = "leaky_bucket"


@dataclass
class RateLimitRule:
    """Rate limit rule configuration."""
    name: str
    limit: int  # Number of requests
    window: int  # Time window in seconds
    algorithm: RateLimitAlgorithm = RateLimitAlgorithm.SLIDING_WINDOW
    burst_limit: Optional[int] = None  # Burst allowance
    key_pattern: str = "{ip}"  # Pattern for generating keys
    scope: str = "global"  # Scope of the rule
    enabled: bool = True


@dataclass
class RateLimitConfig:
    """Rate limiting configuration."""
    redis_url: str
    redis_prefix: str = "ratelimit:"
    default_rules: List[RateLimitRule] = field(default_factory=list)
    global_rules: List[RateLimitRule] = field(default_factory=list)
    endpoint_rules: Dict[str, List[RateLimitRule]] = field(default_factory=dict)
    user_rules: Dict[str, List[RateLimitRule]] = field(default_factory=dict)
    
    # Default limits
    default_per_ip_limit: int = 1000
    default_per_ip_window: int = 3600
    default_per_user_limit: int = 5000
    default_per_user_window: int = 3600
    
    # Enforcement
    enabled: bool = True
    fail_open: bool = True  # Allow requests if rate limiting fails
    log_violations: bool = True
    
    def __post_init__(self):
        """Initialize default rules if none provided."""
        if not self.default_rules:
            self.default_rules = [
                RateLimitRule(
                    name="per_ip_default",
                    limit=self.default_per_ip_limit,
                    window=self.default_per_ip_window,
                    key_pattern="{ip}",
                    scope="ip"
                ),
                RateLimitRule(
                    name="per_user_default", 
                    limit=self.default_per_user_limit,
                    window=self.default_per_user_window,
                    key_pattern="{user_id}",
                    scope="user"
                ),
                RateLimitRule(
                    name="auth_endpoints",
                    limit=10,
                    window=600,  # 10 requests per 10 minutes
                    key_pattern="{ip}:auth",
                    scope="auth"
                )
            ]


class RateLimitBackend(ABC):
    """Abstract backend for rate limiting storage."""
    
    @abstractmethod
    async def check_limit(self, key: str, rule: RateLimitRule) -> Tuple[bool, Dict[str, Any]]:
        """Check if request is within rate limit."""
        pass
    
    @abstractmethod
    async def reset_limit(self, key: str, rule: RateLimitRule) -> bool:
        """Reset rate limit for a key."""
        pass
    
    @abstractmethod
    async def get_limit_info(self, key: str, rule: RateLimitRule) -> Dict[str, Any]:
        """Get current limit information."""
        pass


class RedisRateLimitBackend(RateLimitBackend):
    """Redis-based rate limiting backend."""
    
    def __init__(self, redis_client: redis.Redis, prefix: str = "ratelimit:"):
        self.redis = redis_client
        self.prefix = prefix
        self.logger = get_logger("rate_limit.redis")
    
    async def check_limit(self, key: str, rule: RateLimitRule) -> Tuple[bool, Dict[str, Any]]:
        """Check rate limit using specified algorithm."""
        full_key = f"{self.prefix}{rule.name}:{key}"
        
        try:
            if rule.algorithm == RateLimitAlgorithm.SLIDING_WINDOW:
                return await self._sliding_window_check(full_key, rule)
            elif rule.algorithm == RateLimitAlgorithm.FIXED_WINDOW:
                return await self._fixed_window_check(full_key, rule)
            elif rule.algorithm == RateLimitAlgorithm.TOKEN_BUCKET:
                return await self._token_bucket_check(full_key, rule)
            elif rule.algorithm == RateLimitAlgorithm.LEAKY_BUCKET:
                return await self._leaky_bucket_check(full_key, rule)
            else:
                return await self._sliding_window_check(full_key, rule)
        
        except Exception as e:
            self.logger.error(f"Rate limit check failed for {key}: {e}")
            return True, {"error": str(e)}  # Fail open
    
    async def _sliding_window_check(self, key: str, rule: RateLimitRule) -> Tuple[bool, Dict[str, Any]]:
        """Sliding window rate limiting."""
        now = time.time()
        window_start = now - rule.window
        
        # Lua script for atomic sliding window check
        lua_script = """
        local key = KEYS[1]
        local window_start = tonumber(ARGV[1])
        local now = tonumber(ARGV[2])
        local limit = tonumber(ARGV[3])
        local window = tonumber(ARGV[4])
        
        -- Remove old entries
        redis.call('zremrangebyscore', key, '-inf', window_start)
        
        -- Count current entries
        local current = redis.call('zcard', key)
        
        if current < limit then
            -- Add new entry
            redis.call('zadd', key, now, now)
            redis.call('expire', key, window)
            return {1, current + 1, limit - current - 1}
        else
            return {0, current, 0}
        end
        """
        
        result = await self.redis.eval(
            lua_script, 1, key, window_start, now, rule.limit, rule.window
        )
        
        allowed = bool(result[0])
        current_count = result[1]
        remaining = result[2]
        
        info = {
            "allowed": allowed,
            "current": current_count,
            "limit": rule.limit,
            "remaining": remaining,
            "reset_time": now + rule.window,
            "algorithm": rule.algorithm.value
        }
        
        return allowed, info
    
    async def _fixed_window_check(self, key: str, rule: RateLimitRule) -> Tuple[bool, Dict[str, Any]]:
        """Fixed window rate limiting."""
        now = time.time()
        window_start = int(now // rule.window) * rule.window
        window_key = f"{key}:{window_start}"
        
        # Lua script for atomic fixed window check
        lua_script = """
        local key = KEYS[1]
        local limit = tonumber(ARGV[1])
        local window = tonumber(ARGV[2])
        
        local current = redis.call('get', key)
        if current == false then
            current = 0
        else
            current = tonumber(current)
        end
        
        if current < limit then
            local new_count = redis.call('incr', key)
            if new_count == 1 then
                redis.call('expire', key, window)
            end
            return {1, new_count, limit - new_count}
        else
            return {0, current, 0}
        end
        """
        
        result = await self.redis.eval(
            lua_script, 1, window_key, rule.limit, rule.window
        )
        
        allowed = bool(result[0])
        current_count = result[1]
        remaining = result[2]
        
        info = {
            "allowed": allowed,
            "current": current_count,
            "limit": rule.limit,
            "remaining": remaining,
            "reset_time": window_start + rule.window,
            "algorithm": rule.algorithm.value
        }
        
        return allowed, info
    
    async def _token_bucket_check(self, key: str, rule: RateLimitRule) -> Tuple[bool, Dict[str, Any]]:
        """Token bucket rate limiting."""
        now = time.time()
        bucket_key = f"{key}:bucket"
        
        # Lua script for atomic token bucket check
        lua_script = """
        local key = KEYS[1]
        local now = tonumber(ARGV[1])
        local limit = tonumber(ARGV[2])
        local window = tonumber(ARGV[3])
        local burst = tonumber(ARGV[4])
        
        local bucket = redis.call('hmget', key, 'tokens', 'last_refill')
        local tokens = tonumber(bucket[1]) or limit
        local last_refill = tonumber(bucket[2]) or now
        
        -- Calculate tokens to add
        local elapsed = now - last_refill
        local tokens_to_add = math.floor(elapsed * limit / window)
        tokens = math.min(burst, tokens + tokens_to_add)
        
        if tokens >= 1 then
            tokens = tokens - 1
            redis.call('hmset', key, 'tokens', tokens, 'last_refill', now)
            redis.call('expire', key, window * 2)
            return {1, tokens, burst - tokens}
        else
            redis.call('hmset', key, 'last_refill', now)
            redis.call('expire', key, window * 2)
            return {0, tokens, 0}
        end
        """
        
        burst_limit = rule.burst_limit or rule.limit
        
        result = await self.redis.eval(
            lua_script, 1, bucket_key, now, rule.limit, rule.window, burst_limit
        )
        
        allowed = bool(result[0])
        current_tokens = result[1]
        remaining = result[2]
        
        info = {
            "allowed": allowed,
            "current_tokens": current_tokens,
            "burst_limit": burst_limit,
            "remaining": remaining,
            "algorithm": rule.algorithm.value
        }
        
        return allowed, info
    
    async def _leaky_bucket_check(self, key: str, rule: RateLimitRule) -> Tuple[bool, Dict[str, Any]]:
        """Leaky bucket rate limiting."""
        now = time.time()
        bucket_key = f"{key}:leaky"
        
        # Lua script for atomic leaky bucket check
        lua_script = """
        local key = KEYS[1]
        local now = tonumber(ARGV[1])
        local capacity = tonumber(ARGV[2])
        local leak_rate = tonumber(ARGV[3])
        local window = tonumber(ARGV[4])
        
        local bucket = redis.call('hmget', key, 'volume', 'last_leak')
        local volume = tonumber(bucket[1]) or 0
        local last_leak = tonumber(bucket[2]) or now
        
        -- Calculate leaked volume
        local elapsed = now - last_leak
        local leaked = elapsed * leak_rate / window
        volume = math.max(0, volume - leaked)
        
        if volume < capacity then
            volume = volume + 1
            redis.call('hmset', key, 'volume', volume, 'last_leak', now)
            redis.call('expire', key, window * 2)
            return {1, volume, capacity - volume}
        else
            redis.call('hmset', key, 'last_leak', now)
            redis.call('expire', key, window * 2)
            return {0, volume, 0}
        end
        """
        
        result = await self.redis.eval(
            lua_script, 1, bucket_key, now, rule.limit, rule.limit, rule.window
        )
        
        allowed = bool(result[0])
        current_volume = result[1]
        remaining = result[2]
        
        info = {
            "allowed": allowed,
            "current_volume": current_volume,
            "capacity": rule.limit,
            "remaining": remaining,
            "algorithm": rule.algorithm.value
        }
        
        return allowed, info
    
    async def reset_limit(self, key: str, rule: RateLimitRule) -> bool:
        """Reset rate limit for a key."""
        try:
            pattern = f"{self.prefix}{rule.name}:{key}*"
            keys = await self.redis.keys(pattern)
            
            if keys:
                await self.redis.delete(*keys)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to reset limit for {key}: {e}")
            return False
    
    async def get_limit_info(self, key: str, rule: RateLimitRule) -> Dict[str, Any]:
        """Get current limit information without incrementing."""
        full_key = f"{self.prefix}{rule.name}:{key}"
        
        try:
            if rule.algorithm == RateLimitAlgorithm.SLIDING_WINDOW:
                now = time.time()
                window_start = now - rule.window
                await self.redis.zremrangebyscore(full_key, '-inf', window_start)
                current = await self.redis.zcard(full_key)
                
                return {
                    "current": current,
                    "limit": rule.limit,
                    "remaining": max(0, rule.limit - current),
                    "reset_time": now + rule.window,
                    "algorithm": rule.algorithm.value
                }
            
            elif rule.algorithm == RateLimitAlgorithm.FIXED_WINDOW:
                now = time.time()
                window_start = int(now // rule.window) * rule.window
                window_key = f"{full_key}:{window_start}"
                current = await self.redis.get(window_key) or 0
                current = int(current)
                
                return {
                    "current": current,
                    "limit": rule.limit,
                    "remaining": max(0, rule.limit - current),
                    "reset_time": window_start + rule.window,
                    "algorithm": rule.algorithm.value
                }
            
            else:
                # For bucket algorithms, return basic info
                return {
                    "limit": rule.limit,
                    "algorithm": rule.algorithm.value
                }
                
        except Exception as e:
            self.logger.error(f"Failed to get limit info for {key}: {e}")
            return {"error": str(e)}


class RateLimiter:
    """Main rate limiter class."""
    
    def __init__(self, config: RateLimitConfig):
        self.config = config
        self.logger = get_logger("rate_limiter")
        self.backend: Optional[RateLimitBackend] = None
        self._redis_client: Optional[redis.Redis] = None
    
    async def initialize(self):
        """Initialize rate limiter with Redis backend."""
        if not self.config.enabled:
            self.logger.info("Rate limiting disabled")
            return
        
        try:
            self._redis_client = redis.from_url(
                self.config.redis_url,
                decode_responses=True,
                retry_on_timeout=True,
                socket_keepalive=True,
                socket_keepalive_options={}
            )
            
            # Test connection
            await self._redis_client.ping()
            
            self.backend = RedisRateLimitBackend(
                self._redis_client, 
                self.config.redis_prefix
            )
            
            self.logger.info("Rate limiter initialized with Redis backend")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize rate limiter: {e}")
            if not self.config.fail_open:
                raise
    
    async def check_rate_limit(self, 
                             request_info: Dict[str, Any],
                             endpoint: str = None) -> Tuple[bool, Dict[str, Any]]:
        """
        Check if request should be rate limited.
        
        Args:
            request_info: Dictionary containing request information (ip, user_id, etc.)
            endpoint: Specific endpoint being accessed
            
        Returns:
            Tuple of (allowed, rate_limit_info)
        """
        if not self.config.enabled or not self.backend:
            return True, {"status": "disabled"}
        
        # Get applicable rules
        rules = self._get_applicable_rules(request_info, endpoint)
        
        # Check each rule
        violations = []
        all_info = {}
        
        for rule in rules:
            try:
                key = self._generate_key(rule, request_info)
                allowed, info = await self.backend.check_limit(key, rule)
                
                all_info[rule.name] = info
                
                if not allowed:
                    violations.append({
                        "rule": rule.name,
                        "key": key,
                        "info": info
                    })
                    
                    if self.config.log_violations:
                        self.logger.warning(
                            f"Rate limit exceeded",
                            rule=rule.name,
                            key=key,
                            limit=rule.limit,
                            window=rule.window,
                            **info
                        )
            
            except Exception as e:
                self.logger.error(f"Rate limit check failed for rule {rule.name}: {e}")
                if not self.config.fail_open:
                    return False, {"error": str(e)}
        
        # Determine final result
        allowed = len(violations) == 0
        
        result_info = {
            "allowed": allowed,
            "violations": violations,
            "rules_checked": len(rules),
            "details": all_info
        }
        
        # Add retry-after header info if blocked
        if not allowed and violations:
            # Find the rule with the shortest reset time
            min_reset = min(
                v["info"].get("reset_time", time.time() + 3600) 
                for v in violations 
                if "reset_time" in v["info"]
            )
            result_info["retry_after"] = max(1, int(min_reset - time.time()))
        
        return allowed, result_info
    
    async def reset_user_limits(self, user_id: str) -> bool:
        """Reset all rate limits for a user."""
        if not self.backend:
            return False
        
        success = True
        for rule in self.config.default_rules + self.config.global_rules:
            if "{user_id}" in rule.key_pattern:
                key = rule.key_pattern.format(user_id=user_id)
                if not await self.backend.reset_limit(key, rule):
                    success = False
        
        return success
    
    async def get_user_limits(self, user_id: str) -> Dict[str, Any]:
        """Get current rate limit status for a user."""
        if not self.backend:
            return {}
        
        user_limits = {}
        for rule in self.config.default_rules + self.config.global_rules:
            if "{user_id}" in rule.key_pattern:
                key = rule.key_pattern.format(user_id=user_id)
                info = await self.backend.get_limit_info(key, rule)
                user_limits[rule.name] = info
        
        return user_limits
    
    def _get_applicable_rules(self, request_info: Dict[str, Any], endpoint: str = None) -> List[RateLimitRule]:
        """Get list of applicable rate limiting rules."""
        rules = []
        
        # Add global rules
        rules.extend([r for r in self.config.global_rules if r.enabled])
        
        # Add default rules
        rules.extend([r for r in self.config.default_rules if r.enabled])
        
        # Add endpoint-specific rules
        if endpoint and endpoint in self.config.endpoint_rules:
            rules.extend([r for r in self.config.endpoint_rules[endpoint] if r.enabled])
        
        # Add user-specific rules
        user_id = request_info.get("user_id")
        if user_id and user_id in self.config.user_rules:
            rules.extend([r for r in self.config.user_rules[user_id] if r.enabled])
        
        # Filter rules based on scope
        filtered_rules = []
        for rule in rules:
            if self._rule_applies(rule, request_info, endpoint):
                filtered_rules.append(rule)
        
        return filtered_rules
    
    def _rule_applies(self, rule: RateLimitRule, request_info: Dict[str, Any], endpoint: str = None) -> bool:
        """Check if a rule applies to the request."""
        # Check scope-based filtering
        if rule.scope == "auth" and endpoint and "/auth/" not in endpoint:
            return False
        
        # Check if required variables are available in request_info
        required_vars = self._extract_variables(rule.key_pattern)
        for var in required_vars:
            if var not in request_info:
                return False
        
        return True
    
    def _generate_key(self, rule: RateLimitRule, request_info: Dict[str, Any]) -> str:
        """Generate rate limiting key from rule pattern and request info."""
        try:
            return rule.key_pattern.format(**request_info)
        except KeyError as e:
            self.logger.error(f"Missing variable for key pattern {rule.key_pattern}: {e}")
            # Fallback to IP-based key
            return request_info.get("ip", "unknown")
    
    def _extract_variables(self, pattern: str) -> List[str]:
        """Extract variable names from key pattern."""
        import re
        return re.findall(r'\{(\w+)\}', pattern)
    
    async def cleanup(self):
        """Cleanup resources."""
        if self._redis_client:
            await self._redis_client.close()


# Convenience functions for common rate limiting patterns
def create_ip_rate_limiter(redis_url: str, requests_per_hour: int = 1000) -> RateLimiter:
    """Create a simple IP-based rate limiter."""
    config = RateLimitConfig(
        redis_url=redis_url,
        default_rules=[
            RateLimitRule(
                name="per_ip",
                limit=requests_per_hour,
                window=3600,
                key_pattern="{ip}"
            )
        ]
    )
    return RateLimiter(config)


def create_user_rate_limiter(redis_url: str, requests_per_hour: int = 5000) -> RateLimiter:
    """Create a simple user-based rate limiter."""
    config = RateLimitConfig(
        redis_url=redis_url,
        default_rules=[
            RateLimitRule(
                name="per_user",
                limit=requests_per_hour,
                window=3600,
                key_pattern="{user_id}"
            )
        ]
    )
    return RateLimiter(config)


def create_endpoint_rate_limiter(redis_url: str, 
                                endpoint_limits: Dict[str, Tuple[int, int]]) -> RateLimiter:
    """Create endpoint-specific rate limiter."""
    endpoint_rules = {}
    
    for endpoint, (limit, window) in endpoint_limits.items():
        endpoint_rules[endpoint] = [
            RateLimitRule(
                name=f"endpoint_{endpoint.replace('/', '_')}",
                limit=limit,
                window=window,
                key_pattern=f"{{ip}}:{endpoint}"
            )
        ]
    
    config = RateLimitConfig(
        redis_url=redis_url,
        endpoint_rules=endpoint_rules
    )
    return RateLimiter(config)