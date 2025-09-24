#!/usr/bin/env python3
"""
Fortress Security Database - Core Models
"""

import asyncio
import asyncpg
import redis.asyncio as redis
from elasticsearch import AsyncElasticsearch
import json
import os

class FortressDB:
    def __init__(self):
        self.pg_pool = None
        self.redis = None
        self.es = None
    
    async def connect(self):
        """Initialize database connections"""
        # PostgreSQL
        self.pg_pool = await asyncpg.create_pool(
            host="fortress-postgresql", port=5432,
            user="fortress_user", password="fortress_secure_password",
            database="fortress_security", min_size=5, max_size=20
        )
        
        # Redis
        self.redis = redis.Redis(host="fortress-redis", port=6379, decode_responses=True)
        
        # Elasticsearch
        self.es = AsyncElasticsearch([{"host": "fortress-elasticsearch", "port": 9200}])
        
        print("✅ Database connections established")
    
    async def register_cluster(self, name: str, endpoint: str) -> str:
        """Register new cluster"""
        async with self.pg_pool.acquire() as conn:
            cluster_id = await conn.fetchval(
                "INSERT INTO clusters (cluster_name, api_endpoint) VALUES ($1, $2) RETURNING cluster_id",
                name, endpoint
            )
            return str(cluster_id)
    
    async def queue_scan(self, priority: str, task: dict):
        """Queue scan task"""
        await self.redis.lpush(f"scan:queue:{priority}", json.dumps(task))
    
    async def log_vulnerability(self, vuln_data: dict):
        """Log vulnerability to Elasticsearch"""
        await self.es.index(index="fortress_vulnerability_events", body=vuln_data)
    
    async def get_cluster_performance(self, cluster_id: str) -> dict:
        """Get cluster performance from Redis"""
        key = f"performance:metrics:{cluster_id}"
        data = await self.redis.hgetall(key)
        return {k: float(v) if v else 0.0 for k, v in data.items()}

# Global database instance
db = FortressDB()
