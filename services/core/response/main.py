#!/usr/bin/env python3
"""
MCP Security Platform Service
"""
import os
import uvicorn
from fastapi import FastAPI

app = FastAPI(
    title="MCP Security Platform Service",
    description="A component of the MCP Security Platform",
    version="1.0.0"
)

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "mcp-service"}

@app.get("/")
async def root():
    return {"message": "MCP Security Platform Service"}

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)
