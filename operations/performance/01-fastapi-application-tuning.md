# FastAPI Application Performance Tuning

**Guide Version**: 1.0  
**Last Updated**: 2024-01-01  
**Target Audience**: Backend Developers, DevOps Engineers  

## Overview

This guide covers comprehensive performance optimization techniques for FastAPI applications in the MCP Security Platform, focusing on request handling, response times, and resource utilization.

## FastAPI Configuration Optimization

### 1. ASGI Server Configuration

#### Uvicorn Production Settings
```python
# main.py
import uvicorn
from fastapi import FastAPI
from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await initialize_connections()
    yield
    # Shutdown
    await cleanup_connections()

app = FastAPI(
    title="MCP Security Platform API",
    lifespan=lifespan,
    # Performance optimizations
    docs_url=None,  # Disable in production
    redoc_url=None,  # Disable in production
    openapi_url=None,  # Disable in production
)

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        workers=4,  # Number of worker processes
        worker_class="uvicorn.workers.UvicornWorker",
        worker_connections=1000,  # Max concurrent connections per worker
        max_requests=1000,  # Restart worker after N requests
        max_requests_jitter=100,  # Add randomness to prevent thundering herd
        preload_app=True,  # Load app before forking workers
        keepalive=2,  # Keep connections alive for 2 seconds
        access_log=False,  # Disable access logs in production
        use_colors=False,  # Disable colors in production
        loop="uvloop",  # Use uvloop for better performance
        http="httptools",  # Use httptools for better HTTP parsing
    )
```

#### Gunicorn with Uvicorn Workers
```python
# gunicorn_config.py
import multiprocessing

# Server socket
bind = "0.0.0.0:8000"
backlog = 2048

# Worker processes
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "uvicorn.workers.UvicornWorker"
worker_connections = 1000
max_requests = 1000
max_requests_jitter = 100
preload_app = True

# Restart workers gracefully
max_worker_lifetime = 3600  # 1 hour
max_worker_lifetime_jitter = 300  # 5 minutes

# Logging
accesslog = "-"
errorlog = "-"
loglevel = "info"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Process naming
proc_name = "mcp-api-server"

# Worker timeout
timeout = 30
keepalive = 2

# SSL (if terminating SSL at application level)
# keyfile = "/path/to/private.key"
# certfile = "/path/to/certificate.crt"
```

### 2. Application Structure Optimization

#### Dependency Injection Optimization
```python
from functools import lru_cache
from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

# Cache expensive dependency creation
@lru_cache()
def get_settings():
    return Settings()

# Optimize database sessions
async def get_db_session() -> AsyncSession:
    """Optimized database session with connection pooling."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

# Cache authentication dependencies
@lru_cache(maxsize=1000)
def parse_jwt_token(token: str) -> dict:
    """Cache JWT token parsing for repeated requests."""
    return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])

async def get_current_user(
    token: str = Depends(oauth2_scheme),
    session: AsyncSession = Depends(get_db_session)
) -> User:
    """Optimized user authentication with caching."""
    try:
        # Use cached token parsing
        payload = parse_jwt_token(token)
        user_id = payload.get("sub")
        
        # Cache user lookups
        user = await get_user_from_cache(user_id, session)
        return user
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")
```

#### Route Optimization
```python
from fastapi import FastAPI, Response, Request
from fastapi.responses import ORJSONResponse
import orjson

app = FastAPI(default_response_class=ORJSONResponse)

@app.middleware("http")
async def performance_middleware(request: Request, call_next):
    """Add performance optimizations."""
    # Add response compression headers
    response = await call_next(request)
    
    # Enable compression for large responses
    if int(response.headers.get("content-length", 0)) > 1024:
        response.headers["Content-Encoding"] = "gzip"
    
    # Add caching headers for static content
    if request.url.path.startswith("/static/"):
        response.headers["Cache-Control"] = "public, max-age=31536000"
    
    return response

@app.get("/health", response_class=Response)
async def health_check():
    """Ultra-fast health check endpoint."""
    return Response(content="OK", media_type="text/plain")

@app.get("/users/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: int,
    session: AsyncSession = Depends(get_db_session),
    response: Response = None
):
    """Optimized user retrieval with caching."""
    # Try cache first
    cached_user = await redis_client.get(f"user:{user_id}")
    if cached_user:
        response.headers["X-Cache"] = "HIT"
        return orjson.loads(cached_user)
    
    # Fetch from database
    user = await session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Cache for future requests
    user_data = UserResponse.from_orm(user)
    await redis_client.setex(
        f"user:{user_id}", 
        300,  # 5 minutes
        orjson.dumps(user_data.dict())
    )
    
    response.headers["X-Cache"] = "MISS"
    return user_data
```

## Database Integration Optimization

### 3. SQLAlchemy Async Optimization

#### Connection Pool Configuration
```python
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import QueuePool

# Optimized database engine
engine = create_async_engine(
    DATABASE_URL,
    # Connection pool settings
    poolclass=QueuePool,
    pool_size=20,  # Number of persistent connections
    max_overflow=30,  # Additional connections during peak
    pool_pre_ping=True,  # Validate connections
    pool_recycle=3600,  # Recycle connections every hour
    
    # Query optimization
    echo=False,  # Disable SQL logging in production
    future=True,  # Use SQLAlchemy 2.0 style
    
    # Connection arguments
    connect_args={
        "server_settings": {
            "application_name": "mcp-api-server",
            "jit": "off",  # Disable JIT for better predictability
        },
        "command_timeout": 30,
        "connect_timeout": 10,
    }
)

AsyncSessionLocal = sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,  # Keep objects accessible after commit
)
```

#### Query Optimization
```python
from sqlalchemy import select, func
from sqlalchemy.orm import selectinload, joinedload

class UserService:
    """Optimized user service with efficient queries."""
    
    @staticmethod
    async def get_users_with_events(
        session: AsyncSession,
        limit: int = 10,
        offset: int = 0
    ) -> List[User]:
        """Efficiently fetch users with their security events."""
        
        # Use joinedload for one-to-many relationships
        query = (
            select(User)
            .options(
                # Eager load related data to avoid N+1 queries
                selectinload(User.api_keys),
                joinedload(User.security_events)
            )
            .limit(limit)
            .offset(offset)
        )
        
        result = await session.execute(query)
        return result.unique().scalars().all()
    
    @staticmethod
    async def get_user_event_counts(session: AsyncSession) -> List[dict]:
        """Efficiently count events per user."""
        
        query = (
            select(
                User.id,
                User.username,
                func.count(SecurityEvent.id).label("event_count")
            )
            .outerjoin(SecurityEvent)
            .group_by(User.id, User.username)
            .order_by(func.count(SecurityEvent.id).desc())
        )
        
        result = await session.execute(query)
        return [
            {"user_id": row.id, "username": row.username, "event_count": row.event_count}
            for row in result
        ]
    
    @staticmethod
    async def bulk_update_users(
        session: AsyncSession,
        user_updates: List[dict]
    ) -> int:
        """Efficiently update multiple users."""
        
        # Use bulk operations for better performance
        stmt = update(User)
        result = await session.execute(stmt, user_updates)
        await session.commit()
        
        return result.rowcount
```

### 4. Caching Strategy

#### Redis Integration
```python
import redis.asyncio as redis
import orjson
from typing import Optional, Any

class CacheService:
    """High-performance caching service."""
    
    def __init__(self, redis_url: str):
        self.redis = redis.from_url(
            redis_url,
            encoding="utf-8",
            decode_responses=False,  # Handle bytes for better performance
            socket_keepalive=True,
            socket_keepalive_options={},
            health_check_interval=30,
            retry_on_timeout=True,
            connection_pool_max_connections=20,
        )
    
    async def get(self, key: str) -> Optional[Any]:
        """Get cached value with automatic deserialization."""
        try:
            data = await self.redis.get(key)
            if data:
                return orjson.loads(data)
            return None
        except Exception as e:
            logger.error(f"Cache get error: {e}")
            return None
    
    async def set(
        self, 
        key: str, 
        value: Any, 
        expire: int = 300
    ) -> bool:
        """Set cached value with automatic serialization."""
        try:
            serialized = orjson.dumps(value)
            await self.redis.setex(key, expire, serialized)
            return True
        except Exception as e:
            logger.error(f"Cache set error: {e}")
            return False
    
    async def get_or_set(
        self,
        key: str,
        fetch_func: callable,
        expire: int = 300
    ) -> Any:
        """Get from cache or fetch and cache."""
        # Try cache first
        cached = await self.get(key)
        if cached is not None:
            return cached
        
        # Fetch and cache
        value = await fetch_func()
        await self.set(key, value, expire)
        return value

# Application-level caching
cache_service = CacheService(REDIS_URL)

@app.get("/vulnerabilities")
async def get_vulnerabilities(
    page: int = 1,
    limit: int = 20,
    session: AsyncSession = Depends(get_db_session)
):
    """Cached vulnerability listing."""
    cache_key = f"vulnerabilities:page:{page}:limit:{limit}"
    
    async def fetch_vulnerabilities():
        query = (
            select(Vulnerability)
            .order_by(Vulnerability.created_at.desc())
            .limit(limit)
            .offset((page - 1) * limit)
        )
        result = await session.execute(query)
        vulns = result.scalars().all()
        return [VulnerabilityResponse.from_orm(v).dict() for v in vulns]
    
    return await cache_service.get_or_set(
        cache_key, 
        fetch_vulnerabilities,
        expire=300  # 5 minutes
    )
```

## Response Optimization

### 5. Response Serialization

#### ORJson Integration
```python
from fastapi.responses import ORJSONResponse
import orjson

def orjson_dumps(v, *, default):
    """Custom orjson serializer with optimizations."""
    return orjson.dumps(v, default=default, option=orjson.OPT_FAST_ENCODE)

app = FastAPI(
    default_response_class=ORJSONResponse,
    # Use faster JSON serialization
    json_dumps=orjson_dumps
)

class OptimizedResponse(ORJSONResponse):
    """Response class with additional optimizations."""
    
    def render(self, content: Any) -> bytes:
        """Optimized rendering with compression."""
        return orjson.dumps(
            content,
            option=orjson.OPT_FAST_ENCODE | orjson.OPT_PASSTHROUGH_SUBCLASS
        )

@app.get("/api/large-dataset", response_class=OptimizedResponse)
async def get_large_dataset():
    """Endpoint optimized for large responses."""
    # Use streaming for large datasets
    data = await fetch_large_dataset()
    return data
```

#### Response Compression
```python
from fastapi.middleware.gzip import GZipMiddleware
from starlette.middleware.compression import CompressionMiddleware

# Add compression middleware
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Custom compression middleware for better control
class OptimizedCompressionMiddleware:
    """Custom compression with dynamic thresholds."""
    
    def __init__(self, app, minimum_size: int = 500):
        self.app = app
        self.minimum_size = minimum_size
    
    async def __call__(self, scope, receive, send):
        """Apply compression based on response size and type."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        
        # Check if client accepts compression
        headers = dict(scope["headers"])
        accept_encoding = headers.get(b"accept-encoding", b"").decode()
        
        if "gzip" not in accept_encoding:
            await self.app(scope, receive, send)
            return
        
        # Apply compression for appropriate responses
        response = await self.app(scope, receive, send)
        # Compression logic here
        
app.add_middleware(OptimizedCompressionMiddleware)
```

### 6. Streaming Responses

#### Large Dataset Streaming
```python
from fastapi.responses import StreamingResponse
import csv
from io import StringIO

@app.get("/export/vulnerabilities")
async def export_vulnerabilities(
    format: str = "csv",
    session: AsyncSession = Depends(get_db_session)
):
    """Stream large datasets efficiently."""
    
    if format == "csv":
        return StreamingResponse(
            stream_vulnerabilities_csv(session),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=vulnerabilities.csv"}
        )
    
async def stream_vulnerabilities_csv(session: AsyncSession):
    """Stream CSV data in chunks."""
    output = StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(["id", "title", "severity", "created_at"])
    yield output.getvalue()
    output.seek(0)
    output.truncate(0)
    
    # Stream data in chunks
    query = select(Vulnerability).order_by(Vulnerability.id)
    
    async for row in session.stream(query):
        vulnerability = row[0]
        writer.writerow([
            vulnerability.id,
            vulnerability.title,
            vulnerability.severity,
            vulnerability.created_at
        ])
        
        # Yield chunk when buffer is full
        if output.tell() > 8192:  # 8KB chunks
            yield output.getvalue()
            output.seek(0)
            output.truncate(0)
    
    # Yield remaining data
    if output.tell() > 0:
        yield output.getvalue()
```

## Error Handling Optimization

### 7. Exception Handling

#### Optimized Error Responses
```python
from fastapi import HTTPException
from fastapi.exception_handlers import http_exception_handler
from starlette.exceptions import HTTPException as StarletteHTTPException

class OptimizedHTTPException(HTTPException):
    """HTTP exception with performance optimizations."""
    
    def __init__(
        self,
        status_code: int,
        detail: str = None,
        headers: dict = None,
        error_code: str = None
    ):
        super().__init__(status_code, detail, headers)
        self.error_code = error_code

@app.exception_handler(OptimizedHTTPException)
async def optimized_exception_handler(request, exc):
    """Fast exception handling with minimal overhead."""
    return ORJSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "error_code": getattr(exc, "error_code", None),
            "timestamp": int(time.time())
        },
        headers=exc.headers
    )

# Global error handler with caching
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler with error tracking."""
    error_id = str(uuid.uuid4())
    
    # Log error asynchronously
    asyncio.create_task(log_error_async(error_id, exc, request))
    
    return ORJSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "error_id": error_id
        }
    )
```

## Background Tasks Optimization

### 8. Async Task Processing

#### Optimized Background Tasks
```python
from fastapi import BackgroundTasks
import asyncio
from concurrent.futures import ThreadPoolExecutor

# Thread pool for CPU-intensive tasks
executor = ThreadPoolExecutor(max_workers=4)

@app.post("/scan/vulnerability")
async def trigger_vulnerability_scan(
    target: str,
    background_tasks: BackgroundTasks,
    session: AsyncSession = Depends(get_db_session)
):
    """Trigger vulnerability scan with optimized background processing."""
    
    # Create scan record
    scan = VulnerabilityScan(target=target, status="pending")
    session.add(scan)
    await session.commit()
    
    # Add optimized background task
    background_tasks.add_task(
        process_vulnerability_scan_optimized,
        scan.id,
        target
    )
    
    return {"scan_id": scan.id, "status": "started"}

async def process_vulnerability_scan_optimized(scan_id: int, target: str):
    """Optimized vulnerability scan processing."""
    try:
        # Update status
        await update_scan_status(scan_id, "running")
        
        # Run CPU-intensive scan in thread pool
        loop = asyncio.get_event_loop()
        results = await loop.run_in_executor(
            executor,
            run_vulnerability_scan,
            target
        )
        
        # Process results asynchronously
        await store_scan_results(scan_id, results)
        await update_scan_status(scan_id, "completed")
        
    except Exception as e:
        await update_scan_status(scan_id, "failed", str(e))
        logger.error(f"Scan {scan_id} failed: {e}")

# Celery integration for heavy tasks
from celery import Celery

celery_app = Celery(
    "mcp_tasks",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=["tasks.vulnerability_scanning"]
)

@app.post("/scan/heavy")
async def trigger_heavy_scan(target: str):
    """Trigger heavy scan using Celery."""
    task = celery_app.send_task(
        "tasks.vulnerability_scanning.heavy_scan",
        args=[target]
    )
    
    return {"task_id": task.id, "status": "queued"}
```

## Monitoring and Profiling

### 9. Performance Monitoring

#### Built-in Metrics
```python
import time
from prometheus_client import Counter, Histogram, Gauge, generate_latest

# Metrics
REQUEST_COUNT = Counter('http_requests_total', 'Total HTTP requests', ['method', 'endpoint', 'status'])
REQUEST_DURATION = Histogram('http_request_duration_seconds', 'HTTP request duration')
ACTIVE_CONNECTIONS = Gauge('active_connections', 'Active database connections')

@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    """Collect performance metrics."""
    start_time = time.time()
    
    response = await call_next(request)
    
    # Record metrics
    duration = time.time() - start_time
    REQUEST_DURATION.observe(duration)
    REQUEST_COUNT.labels(
        method=request.method,
        endpoint=request.url.path,
        status=response.status_code
    ).inc()
    
    # Add performance headers
    response.headers["X-Process-Time"] = str(duration)
    
    return response

@app.get("/metrics")
async def get_metrics():
    """Expose Prometheus metrics."""
    return Response(
        generate_latest(),
        media_type="text/plain"
    )
```

## Performance Testing

### 10. Load Testing Setup

#### Artillery Configuration
```yaml
# load-test.yml
config:
  target: 'http://localhost:8000'
  phases:
    - duration: 60
      arrivalRate: 10
      name: "Warm up"
    - duration: 120
      arrivalRate: 50
      name: "Sustained load"
    - duration: 60
      arrivalRate: 100
      name: "Peak load"
  processor: "./test-functions.js"

scenarios:
  - name: "API Performance Test"
    weight: 70
    flow:
      - get:
          url: "/health"
      - think: 1
      - post:
          url: "/auth/login"
          json:
            username: "testuser"
            password: "testpass"
      - think: 2
      - get:
          url: "/vulnerabilities"
          headers:
            Authorization: "Bearer {{ token }}"
      - think: 1
      - get:
          url: "/users/{{ userId }}"
          headers:
            Authorization: "Bearer {{ token }}"
```

#### Performance Benchmarks
```python
import asyncio
import aiohttp
import time
from statistics import mean, median

async def benchmark_endpoint(url: str, concurrent: int = 10, requests: int = 100):
    """Benchmark API endpoint performance."""
    
    async def single_request(session):
        start = time.time()
        async with session.get(url) as response:
            await response.read()
            return time.time() - start, response.status
    
    async with aiohttp.ClientSession() as session:
        tasks = []
        for _ in range(requests):
            if len(tasks) >= concurrent:
                # Wait for some tasks to complete
                done, pending = await asyncio.wait(
                    tasks, 
                    return_when=asyncio.FIRST_COMPLETED
                )
                tasks = list(pending)
            
            tasks.append(single_request(session))
        
        # Wait for remaining tasks
        if tasks:
            await asyncio.wait(tasks)
    
    return durations, status_codes

# Run benchmark
if __name__ == "__main__":
    durations, statuses = asyncio.run(
        benchmark_endpoint("http://localhost:8000/health")
    )
    
    print(f"Mean response time: {mean(durations):.3f}s")
    print(f"Median response time: {median(durations):.3f}s")
    print(f"Success rate: {statuses.count(200)/len(statuses)*100:.1f}%")
```

---

**Next Steps**:
1. Implement monitoring for all endpoints
2. Set up automated performance testing
3. Create alerting for performance degradation
4. Regular performance reviews and optimizations

**Related Guides**:
- [Database Performance Tuning](./04-postgresql-performance-tuning.md)
- [Kubernetes Resource Optimization](./07-kubernetes-resource-optimization.md)
- [Load Testing Guide](./15-load-testing-guide.md)