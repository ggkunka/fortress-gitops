#!/usr/bin/env python3
"""
GraphQL Gateway Service - Main Server
Phase 4.1: Complete GraphQL Implementation
"""
from fastapi import FastAPI
from starlette_graphene3 import GraphQLApp
from graphene import Schema
from schema import Query, Mutation
import uvicorn

app = FastAPI(title="Fortress GraphQL Gateway", version="1.0.0")

# Create GraphQL Schema
schema = Schema(query=Query, mutation=Mutation)

# Mount GraphQL endpoint
app.mount("/graphql", GraphQLApp(schema=schema))

# GraphQL Playground endpoint
@app.get("/playground")
async def graphql_playground():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Fortress GraphQL Playground</title>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/graphql-playground-react/build/static/css/index.css" />
    </head>
    <body>
        <div id="root">
            <style>
                body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif; }
                #root { height: 100vh; }
            </style>
            <script src="https://cdn.jsdelivr.net/npm/graphql-playground-react/build/static/js/middleware.js"></script>
        </div>
        <script>window.GraphQLPlayground.init(document.getElementById('root'), { endpoint: '/graphql' })</script>
    </body>
    </html>
    """

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "graphql-gateway"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8087)
