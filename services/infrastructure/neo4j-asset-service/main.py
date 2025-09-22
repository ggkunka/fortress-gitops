#!/usr/bin/env python3
"""
Fortress Asset Relationship Service - Neo4j Integration
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import os
import uvicorn
from neo4j import GraphDatabase

app = FastAPI(title="Fortress Asset Relationship Service", version="1.0.0")

# Neo4j Configuration
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://fortress-neo4j.fortress-system.svc.cluster.local:7687")
NEO4J_USERNAME = os.getenv("NEO4J_USERNAME", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "fortress_secure_password")

class Asset(BaseModel):
    asset_id: str
    asset_type: str  # pod, service, deployment, node, cluster
    name: str
    namespace: Optional[str] = None
    cluster: Optional[str] = None
    risk_score: float = 0.0

class AssetGraphService:
    def __init__(self):
        self.driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USERNAME, NEO4J_PASSWORD))
    
    def create_asset(self, asset: Asset):
        with self.driver.session() as session:
            query = """
            MERGE (a:Asset {asset_id: $asset_id})
            SET a.asset_type = $asset_type,
                a.name = $name,
                a.namespace = $namespace,
                a.cluster = $cluster,
                a.risk_score = $risk_score
            RETURN a
            """
            return session.run(query, **asset.dict()).single()
    
    def find_attack_paths(self, source: str, target: str):
        with self.driver.session() as session:
            query = """
            MATCH path = shortestPath((s:Asset {asset_id: $source})-[:CONNECTS_TO*1..5]->(t:Asset {asset_id: $target}))
            RETURN path
            """
            return list(session.run(query, source=source, target=target))

graph_service = AssetGraphService()

@app.post("/assets")
async def create_asset(asset: Asset):
    """Create asset in graph"""
    result = graph_service.create_asset(asset)
    return {"status": "created", "asset": dict(result['a']) if result else {}}

@app.get("/attack-paths/{source_id}/{target_id}")
async def get_attack_paths(source_id: str, target_id: str):
    """Find attack paths between assets"""
    paths = graph_service.find_attack_paths(source_id, target_id)
    return {"paths": len(paths), "details": [str(p) for p in paths]}

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "asset_relationships", "database": "neo4j"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8095)
