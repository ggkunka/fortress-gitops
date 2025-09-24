"""
Benchmark tests for MCP Security Platform components.
"""

import asyncio
import time
import statistics
import json
import uuid
from typing import Dict, List, Any, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import httpx
import redis
import psycopg2
from psycopg2.extras import RealDictCursor


class PerformanceBenchmark:
    """Base class for performance benchmarks."""
    
    def __init__(self, name: str):
        self.name = name
        self.results = []
    
    def add_result(self, operation: str, duration: float, success: bool = True, **metadata):
        """Add a benchmark result."""
        self.results.append({
            "operation": operation,
            "duration": duration,
            "success": success,
            "timestamp": time.time(),
            **metadata
        })
    
    def get_statistics(self, operation: str = None) -> Dict[str, Any]:
        """Get performance statistics."""
        if operation:
            durations = [r["duration"] for r in self.results if r["operation"] == operation and r["success"]]
        else:
            durations = [r["duration"] for r in self.results if r["success"]]
        
        if not durations:
            return {"count": 0}
        
        return {
            "count": len(durations),
            "min": min(durations),
            "max": max(durations),
            "mean": statistics.mean(durations),
            "median": statistics.median(durations),
            "p95": statistics.quantiles(durations, n=20)[18] if len(durations) > 1 else durations[0],
            "p99": statistics.quantiles(durations, n=100)[98] if len(durations) > 1 else durations[0],
            "stdev": statistics.stdev(durations) if len(durations) > 1 else 0
        }
    
    def print_report(self):
        """Print benchmark report."""
        print(f"\n{'='*60}")
        print(f"BENCHMARK REPORT: {self.name}")
        print(f"{'='*60}")
        
        # Overall statistics
        overall_stats = self.get_statistics()
        if overall_stats["count"] > 0:
            print(f"Total Operations: {overall_stats['count']}")
            print(f"Mean Duration: {overall_stats['mean']:.3f}s")
            print(f"Median Duration: {overall_stats['median']:.3f}s")
            print(f"P95 Duration: {overall_stats['p95']:.3f}s")
            print(f"P99 Duration: {overall_stats['p99']:.3f}s")
            print(f"Min Duration: {overall_stats['min']:.3f}s")
            print(f"Max Duration: {overall_stats['max']:.3f}s")
        
        # Per-operation statistics
        operations = set(r["operation"] for r in self.results)
        for operation in operations:
            stats = self.get_statistics(operation)
            if stats["count"] > 0:
                print(f"\n{operation}:")
                print(f"  Count: {stats['count']}")
                print(f"  Mean: {stats['mean']:.3f}s")
                print(f"  P95: {stats['p95']:.3f}s")
                print(f"  P99: {stats['p99']:.3f}s")


class DatabaseBenchmark(PerformanceBenchmark):
    """Benchmark database operations."""
    
    def __init__(self, database_url: str):
        super().__init__("Database Operations")
        self.database_url = database_url
    
    def run_benchmarks(self, iterations: int = 1000):
        """Run database benchmarks."""
        print(f"Running database benchmarks ({iterations} iterations)...")
        
        # Connection pooling test
        self.benchmark_connections(iterations // 10)
        
        # CRUD operations
        self.benchmark_crud_operations(iterations)
        
        # Query performance
        self.benchmark_query_performance(iterations)
        
        # Concurrent operations
        self.benchmark_concurrent_operations(iterations // 4)
    
    def benchmark_connections(self, iterations: int):
        """Benchmark database connection performance."""
        for i in range(iterations):
            start_time = time.time()
            try:
                conn = psycopg2.connect(self.database_url)
                conn.close()
                duration = time.time() - start_time
                self.add_result("connection", duration)
            except Exception as e:
                duration = time.time() - start_time
                self.add_result("connection", duration, success=False, error=str(e))
    
    def benchmark_crud_operations(self, iterations: int):
        """Benchmark CRUD operations."""
        conn = psycopg2.connect(self.database_url)
        cursor = conn.cursor()
        
        try:
            # Create test table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS benchmark_test (
                    id SERIAL PRIMARY KEY,
                    data JSONB,
                    created_at TIMESTAMP DEFAULT NOW()
                )
            """)
            conn.commit()
            
            # Insert benchmark
            for i in range(iterations // 4):
                data = {"test_id": i, "data": f"test_data_{i}"}
                
                start_time = time.time()
                try:
                    cursor.execute(
                        "INSERT INTO benchmark_test (data) VALUES (%s) RETURNING id",
                        (json.dumps(data),)
                    )
                    conn.commit()
                    duration = time.time() - start_time
                    self.add_result("insert", duration)
                except Exception as e:
                    conn.rollback()
                    duration = time.time() - start_time
                    self.add_result("insert", duration, success=False, error=str(e))
            
            # Select benchmark
            for i in range(iterations // 4):
                start_time = time.time()
                try:
                    cursor.execute("SELECT * FROM benchmark_test WHERE id = %s", (i + 1,))
                    cursor.fetchone()
                    duration = time.time() - start_time
                    self.add_result("select", duration)
                except Exception as e:
                    duration = time.time() - start_time
                    self.add_result("select", duration, success=False, error=str(e))
            
            # Update benchmark
            for i in range(iterations // 4):
                new_data = {"test_id": i, "updated": True}
                
                start_time = time.time()
                try:
                    cursor.execute(
                        "UPDATE benchmark_test SET data = %s WHERE id = %s",
                        (json.dumps(new_data), i + 1)
                    )
                    conn.commit()
                    duration = time.time() - start_time
                    self.add_result("update", duration)
                except Exception as e:
                    conn.rollback()
                    duration = time.time() - start_time
                    self.add_result("update", duration, success=False, error=str(e))
            
            # Delete benchmark
            for i in range(iterations // 4):
                start_time = time.time()
                try:
                    cursor.execute("DELETE FROM benchmark_test WHERE id = %s", (i + 1,))
                    conn.commit()
                    duration = time.time() - start_time
                    self.add_result("delete", duration)
                except Exception as e:
                    conn.rollback()
                    duration = time.time() - start_time
                    self.add_result("delete", duration, success=False, error=str(e))
            
        finally:
            cursor.execute("DROP TABLE IF EXISTS benchmark_test")
            conn.commit()
            cursor.close()
            conn.close()
    
    def benchmark_query_performance(self, iterations: int):
        """Benchmark complex query performance."""
        conn = psycopg2.connect(self.database_url)
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        try:
            # Create test data
            cursor.execute("""
                CREATE TEMP TABLE query_test (
                    id SERIAL PRIMARY KEY,
                    category VARCHAR(50),
                    value INTEGER,
                    metadata JSONB,
                    created_at TIMESTAMP DEFAULT NOW()
                )
            """)
            
            # Insert test data
            for i in range(1000):
                cursor.execute("""
                    INSERT INTO query_test (category, value, metadata) 
                    VALUES (%s, %s, %s)
                """, (
                    f"category_{i % 10}",
                    i % 100,
                    json.dumps({"index": i, "group": i // 10})
                ))
            conn.commit()
            
            # Query benchmarks
            queries = [
                ("simple_select", "SELECT * FROM query_test WHERE id = %s"),
                ("filtered_select", "SELECT * FROM query_test WHERE category = %s AND value > %s"),
                ("json_query", "SELECT * FROM query_test WHERE metadata->>'group' = %s"),
                ("aggregate_query", "SELECT category, COUNT(*), AVG(value) FROM query_test GROUP BY category"),
                ("complex_join", """
                    SELECT t1.*, t2.category as related_category 
                    FROM query_test t1 
                    JOIN query_test t2 ON t1.value = t2.id 
                    WHERE t1.category = %s
                """)
            ]
            
            for query_name, query_sql in queries:
                for i in range(iterations // len(queries)):
                    start_time = time.time()
                    try:
                        if query_name == "simple_select":
                            cursor.execute(query_sql, (i % 1000 + 1,))
                        elif query_name == "filtered_select":
                            cursor.execute(query_sql, (f"category_{i % 10}", i % 50))
                        elif query_name == "json_query":
                            cursor.execute(query_sql, (str(i % 100),))
                        elif query_name == "aggregate_query":
                            cursor.execute(query_sql)
                        elif query_name == "complex_join":
                            cursor.execute(query_sql, (f"category_{i % 10}",))
                        
                        cursor.fetchall()
                        duration = time.time() - start_time
                        self.add_result(query_name, duration)
                    except Exception as e:
                        duration = time.time() - start_time
                        self.add_result(query_name, duration, success=False, error=str(e))
            
        finally:
            cursor.close()
            conn.close()
    
    def benchmark_concurrent_operations(self, iterations: int):
        """Benchmark concurrent database operations."""
        def worker_operation(worker_id: int, ops_per_worker: int):
            conn = psycopg2.connect(self.database_url)
            cursor = conn.cursor()
            
            try:
                for i in range(ops_per_worker):
                    start_time = time.time()
                    try:
                        cursor.execute("SELECT NOW(), %s", (f"worker_{worker_id}_op_{i}",))
                        cursor.fetchone()
                        duration = time.time() - start_time
                        self.add_result("concurrent_select", duration, worker_id=worker_id)
                    except Exception as e:
                        duration = time.time() - start_time
                        self.add_result("concurrent_select", duration, success=False, 
                                      error=str(e), worker_id=worker_id)
            finally:
                cursor.close()
                conn.close()
        
        # Run concurrent operations
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            ops_per_worker = iterations // 10
            
            for worker_id in range(10):
                future = executor.submit(worker_operation, worker_id, ops_per_worker)
                futures.append(future)
            
            # Wait for completion
            for future in as_completed(futures):
                future.result()


class RedisBenchmark(PerformanceBenchmark):
    """Benchmark Redis operations."""
    
    def __init__(self, redis_url: str):
        super().__init__("Redis Operations")
        self.redis_url = redis_url
    
    def run_benchmarks(self, iterations: int = 1000):
        """Run Redis benchmarks."""
        print(f"Running Redis benchmarks ({iterations} iterations)...")
        
        client = redis.Redis.from_url(self.redis_url, decode_responses=True)
        
        # Basic operations
        self.benchmark_basic_operations(client, iterations)
        
        # Pub/Sub operations
        self.benchmark_pubsub_operations(client, iterations // 10)
        
        # Complex data structures
        self.benchmark_complex_structures(client, iterations // 2)
    
    def benchmark_basic_operations(self, client: redis.Redis, iterations: int):
        """Benchmark basic Redis operations."""
        # SET operations
        for i in range(iterations // 4):
            key = f"test:key:{i}"
            value = f"test_value_{i}"
            
            start_time = time.time()
            try:
                client.set(key, value)
                duration = time.time() - start_time
                self.add_result("set", duration)
            except Exception as e:
                duration = time.time() - start_time
                self.add_result("set", duration, success=False, error=str(e))
        
        # GET operations
        for i in range(iterations // 4):
            key = f"test:key:{i}"
            
            start_time = time.time()
            try:
                client.get(key)
                duration = time.time() - start_time
                self.add_result("get", duration)
            except Exception as e:
                duration = time.time() - start_time
                self.add_result("get", duration, success=False, error=str(e))
        
        # DELETE operations
        for i in range(iterations // 4):
            key = f"test:key:{i}"
            
            start_time = time.time()
            try:
                client.delete(key)
                duration = time.time() - start_time
                self.add_result("delete", duration)
            except Exception as e:
                duration = time.time() - start_time
                self.add_result("delete", duration, success=False, error=str(e))
        
        # Pipeline operations
        pipe = client.pipeline()
        start_time = time.time()
        try:
            for i in range(iterations // 4):
                pipe.set(f"pipe:key:{i}", f"pipe_value_{i}")
            pipe.execute()
            duration = time.time() - start_time
            self.add_result("pipeline", duration, operations=iterations // 4)
        except Exception as e:
            duration = time.time() - start_time
            self.add_result("pipeline", duration, success=False, error=str(e))
    
    def benchmark_pubsub_operations(self, client: redis.Redis, iterations: int):
        """Benchmark Pub/Sub operations."""
        pubsub = client.pubsub()
        
        try:
            # Subscribe benchmark
            start_time = time.time()
            try:
                pubsub.subscribe("test:channel")
                duration = time.time() - start_time
                self.add_result("subscribe", duration)
            except Exception as e:
                duration = time.time() - start_time
                self.add_result("subscribe", duration, success=False, error=str(e))
            
            # Publish benchmark
            for i in range(iterations):
                start_time = time.time()
                try:
                    client.publish("test:channel", f"message_{i}")
                    duration = time.time() - start_time
                    self.add_result("publish", duration)
                except Exception as e:
                    duration = time.time() - start_time
                    self.add_result("publish", duration, success=False, error=str(e))
            
        finally:
            pubsub.close()
    
    def benchmark_complex_structures(self, client: redis.Redis, iterations: int):
        """Benchmark complex Redis data structures."""
        # Hash operations
        for i in range(iterations // 4):
            hash_key = f"test:hash:{i}"
            
            start_time = time.time()
            try:
                client.hset(hash_key, "field1", f"value1_{i}")
                client.hset(hash_key, "field2", f"value2_{i}")
                duration = time.time() - start_time
                self.add_result("hash_set", duration)
            except Exception as e:
                duration = time.time() - start_time
                self.add_result("hash_set", duration, success=False, error=str(e))
        
        # List operations
        for i in range(iterations // 4):
            list_key = f"test:list:{i}"
            
            start_time = time.time()
            try:
                client.lpush(list_key, f"item_{i}")
                client.rpop(list_key)
                duration = time.time() - start_time
                self.add_result("list_ops", duration)
            except Exception as e:
                duration = time.time() - start_time
                self.add_result("list_ops", duration, success=False, error=str(e))
        
        # Set operations
        for i in range(iterations // 4):
            set_key = f"test:set:{i}"
            
            start_time = time.time()
            try:
                client.sadd(set_key, f"member_{i}")
                client.sismember(set_key, f"member_{i}")
                duration = time.time() - start_time
                self.add_result("set_ops", duration)
            except Exception as e:
                duration = time.time() - start_time
                self.add_result("set_ops", duration, success=False, error=str(e))


class HTTPBenchmark(PerformanceBenchmark):
    """Benchmark HTTP API operations."""
    
    def __init__(self, base_url: str):
        super().__init__("HTTP API Operations")
        self.base_url = base_url
    
    async def run_benchmarks(self, iterations: int = 1000):
        """Run HTTP API benchmarks."""
        print(f"Running HTTP API benchmarks ({iterations} iterations)...")
        
        # Get auth token
        auth_token = await self.get_auth_token()
        headers = {"Authorization": f"Bearer {auth_token}"}
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Health check benchmarks
            await self.benchmark_health_checks(client, iterations // 10)
            
            # Authentication benchmarks
            await self.benchmark_authentication(client, iterations // 10)
            
            # Data ingestion benchmarks
            await self.benchmark_data_ingestion(client, headers, iterations // 2)
            
            # Query benchmarks
            await self.benchmark_queries(client, headers, iterations // 4)
    
    async def get_auth_token(self) -> str:
        """Get authentication token for benchmarks."""
        async with httpx.AsyncClient() as client:
            user_data = {
                "username": f"benchmark_user_{uuid.uuid4().hex[:8]}",
                "email": f"benchmark_{uuid.uuid4().hex[:8]}@example.com",
                "password": "BenchmarkTest123!",
                "organization_id": "benchmark-org"
            }
            
            try:
                response = await client.post(
                    f"{self.base_url}/api/v1/auth/register",
                    json=user_data,
                    timeout=10.0
                )
                
                if response.status_code in [200, 201]:
                    return response.json()["access_token"]
            except:
                pass
            
            # Try login
            try:
                login_data = {
                    "username": user_data["username"],
                    "password": user_data["password"]
                }
                
                response = await client.post(
                    f"{self.base_url}/api/v1/auth/login",
                    json=login_data,
                    timeout=10.0
                )
                
                if response.status_code == 200:
                    return response.json()["access_token"]
            except:
                pass
            
            return "benchmark-token"
    
    async def benchmark_health_checks(self, client: httpx.AsyncClient, iterations: int):
        """Benchmark health check endpoints."""
        services = ["gateway", "auth", "ingestion", "enrichment", "analysis", "notification"]
        
        for service in services:
            for i in range(iterations // len(services)):
                start_time = time.time()
                try:
                    response = await client.get(f"{self.base_url}/api/v1/{service}/health")
                    duration = time.time() - start_time
                    success = response.status_code == 200
                    self.add_result("health_check", duration, success=success, service=service)
                except Exception as e:
                    duration = time.time() - start_time
                    self.add_result("health_check", duration, success=False, 
                                  error=str(e), service=service)
    
    async def benchmark_authentication(self, client: httpx.AsyncClient, iterations: int):
        """Benchmark authentication operations."""
        for i in range(iterations):
            user_data = {
                "username": f"bench_user_{i}",
                "email": f"bench_{i}@example.com",
                "password": "BenchTest123!",
                "organization_id": "bench-org"
            }
            
            # Register benchmark
            start_time = time.time()
            try:
                response = await client.post(
                    f"{self.base_url}/api/v1/auth/register",
                    json=user_data
                )
                duration = time.time() - start_time
                success = response.status_code in [200, 201]
                self.add_result("register", duration, success=success)
            except Exception as e:
                duration = time.time() - start_time
                self.add_result("register", duration, success=False, error=str(e))
            
            # Login benchmark
            start_time = time.time()
            try:
                login_data = {
                    "username": user_data["username"],
                    "password": user_data["password"]
                }
                response = await client.post(
                    f"{self.base_url}/api/v1/auth/login",
                    json=login_data
                )
                duration = time.time() - start_time
                success = response.status_code == 200
                self.add_result("login", duration, success=success)
            except Exception as e:
                duration = time.time() - start_time
                self.add_result("login", duration, success=False, error=str(e))
    
    async def benchmark_data_ingestion(self, client: httpx.AsyncClient, headers: Dict, iterations: int):
        """Benchmark data ingestion endpoints."""
        # Generate test data
        test_sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": f"test-lib-{i}",
                    "version": "1.0.0"
                } for i in range(10)
            ]
        }
        
        test_cve = {
            "cve_id": "CVE-2023-99999",
            "description": "Test CVE for benchmarking",
            "severity": "HIGH",
            "cvss_score": 8.5
        }
        
        # SBOM ingestion
        for i in range(iterations // 2):
            data = {
                "data_type": "sbom",
                "source": "benchmark",
                "correlation_id": str(uuid.uuid4()),
                "data": test_sbom
            }
            
            start_time = time.time()
            try:
                response = await client.post(
                    f"{self.base_url}/api/v1/ingestion/sbom",
                    json=data,
                    headers=headers
                )
                duration = time.time() - start_time
                success = response.status_code in [200, 202]
                self.add_result("ingest_sbom", duration, success=success)
            except Exception as e:
                duration = time.time() - start_time
                self.add_result("ingest_sbom", duration, success=False, error=str(e))
        
        # CVE ingestion
        for i in range(iterations // 2):
            data = {
                "data_type": "cve",
                "source": "benchmark",
                "correlation_id": str(uuid.uuid4()),
                "data": test_cve
            }
            
            start_time = time.time()
            try:
                response = await client.post(
                    f"{self.base_url}/api/v1/ingestion/cve",
                    json=data,
                    headers=headers
                )
                duration = time.time() - start_time
                success = response.status_code in [200, 202]
                self.add_result("ingest_cve", duration, success=success)
            except Exception as e:
                duration = time.time() - start_time
                self.add_result("ingest_cve", duration, success=False, error=str(e))
    
    async def benchmark_queries(self, client: httpx.AsyncClient, headers: Dict, iterations: int):
        """Benchmark query endpoints."""
        correlation_id = str(uuid.uuid4())
        
        query_endpoints = [
            f"/api/v1/analysis/results/{correlation_id}",
            f"/api/v1/analysis/risk/{correlation_id}",
            f"/api/v1/notifications/{correlation_id}",
            "/api/v1/plugins",
            "/api/v1/plugins/health"
        ]
        
        for endpoint in query_endpoints:
            for i in range(iterations // len(query_endpoints)):
                start_time = time.time()
                try:
                    response = await client.get(f"{self.base_url}{endpoint}", headers=headers)
                    duration = time.time() - start_time
                    success = response.status_code in [200, 404]  # 404 is acceptable for non-existent data
                    operation = endpoint.split("/")[-1] or endpoint.split("/")[-2]
                    self.add_result(f"query_{operation}", duration, success=success)
                except Exception as e:
                    duration = time.time() - start_time
                    operation = endpoint.split("/")[-1] or endpoint.split("/")[-2]
                    self.add_result(f"query_{operation}", duration, success=False, error=str(e))


async def run_all_benchmarks():
    """Run all performance benchmarks."""
    # Configuration
    DATABASE_URL = "postgresql://mcp_user:mcp_test_password@postgresql:5432/mcp_test"
    REDIS_URL = "redis://redis:6379"
    API_URL = "http://gateway-service:8081"
    
    # Run database benchmarks
    db_benchmark = DatabaseBenchmark(DATABASE_URL)
    db_benchmark.run_benchmarks(1000)
    db_benchmark.print_report()
    
    # Run Redis benchmarks
    redis_benchmark = RedisBenchmark(REDIS_URL)
    redis_benchmark.run_benchmarks(1000)
    redis_benchmark.print_report()
    
    # Run HTTP API benchmarks
    http_benchmark = HTTPBenchmark(API_URL)
    await http_benchmark.run_benchmarks(500)
    http_benchmark.print_report()
    
    return {
        "database": db_benchmark.get_statistics(),
        "redis": redis_benchmark.get_statistics(),
        "http_api": http_benchmark.get_statistics()
    }


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Run MCP Security Platform benchmarks")
    parser.add_argument("--iterations", type=int, default=1000, help="Number of iterations per benchmark")
    parser.add_argument("--output", help="Output file for results")
    
    args = parser.parse_args()
    
    # Run benchmarks
    results = asyncio.run(run_all_benchmarks())
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to {args.output}")