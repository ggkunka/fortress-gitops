"""
Performance and load testing for MCP Security Platform using Locust.
"""

import argparse
import json
import random
import uuid
from datetime import datetime
from typing import Dict, Any, List

from locust import HttpUser, TaskSet, task, between, events
from locust.env import Environment
from locust.stats import stats_printer, stats_history
from locust.log import setup_logging


class SecurityDataGenerator:
    """Generate realistic security test data."""
    
    @staticmethod
    def generate_sbom() -> Dict[str, Any]:
        """Generate realistic SBOM data."""
        components = []
        
        # Generate random components
        libraries = [
            "express", "lodash", "react", "vue", "angular", "jquery",
            "bootstrap", "axios", "moment", "underscore", "chalk", "debug"
        ]
        
        for i in range(random.randint(10, 50)):
            lib = random.choice(libraries)
            version = f"{random.randint(1, 5)}.{random.randint(0, 20)}.{random.randint(0, 10)}"
            
            components.append({
                "type": "library",
                "name": f"{lib}-{random.randint(1, 100)}",
                "version": version,
                "purl": f"pkg:npm/{lib}@{version}",
                "hashes": [{"alg": "SHA-256", "content": uuid.uuid4().hex}]
            })
        
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "tools": [{"name": "test-generator", "version": "1.0.0"}]
            },
            "components": components
        }
    
    @staticmethod
    def generate_cve_data() -> Dict[str, Any]:
        """Generate realistic CVE data."""
        severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        cvss_ranges = {
            "LOW": (0.1, 3.9),
            "MEDIUM": (4.0, 6.9), 
            "HIGH": (7.0, 8.9),
            "CRITICAL": (9.0, 10.0)
        }
        
        severity = random.choice(severities)
        cvss_min, cvss_max = cvss_ranges[severity]
        
        return {
            "cve_id": f"CVE-{random.randint(2020, 2024)}-{random.randint(10000, 99999)}",
            "description": f"Test vulnerability in component-{random.randint(1, 1000)}",
            "severity": severity,
            "cvss_score": round(random.uniform(cvss_min, cvss_max), 1),
            "affected_components": [f"component-{random.randint(1, 100)}@{random.randint(1, 5)}.0.0"],
            "references": [f"https://nvd.nist.gov/vuln/detail/CVE-{random.randint(2020, 2024)}-{random.randint(10000, 99999)}"]
        }
    
    @staticmethod
    def generate_runtime_data() -> Dict[str, Any]:
        """Generate realistic runtime data."""
        processes = []
        for i in range(random.randint(5, 20)):
            processes.append({
                "pid": random.randint(1000, 9999),
                "name": random.choice(["node", "python", "java", "nginx", "redis"]),
                "cmdline": f"process-{i} --port {random.randint(3000, 9000)}"
            })
        
        connections = []
        for i in range(random.randint(1, 10)):
            connections.append({
                "local_port": random.randint(3000, 9000),
                "remote_host": f"api-{random.randint(1, 100)}.external.com",
                "remote_port": random.choice([80, 443, 8080, 8443])
            })
        
        file_accesses = []
        for i in range(random.randint(1, 15)):
            file_accesses.append({
                "path": f"/tmp/file-{random.randint(1, 1000)}.dat",
                "operation": random.choice(["read", "write", "execute"])
            })
        
        return {
            "container_id": f"container-{uuid.uuid4().hex[:12]}",
            "image": f"app:v{random.randint(1, 10)}.{random.randint(0, 20)}",
            "processes": processes,
            "network_connections": connections,
            "file_access": file_accesses
        }


class AuthenticationMixin:
    """Mixin for handling authentication in load tests."""
    
    def on_start(self):
        """Authenticate user on start."""
        self.auth_token = self.get_auth_token()
    
    def get_auth_token(self) -> str:
        """Get authentication token."""
        user_data = {
            "username": f"load_test_user_{uuid.uuid4().hex[:8]}",
            "email": f"loadtest_{uuid.uuid4().hex[:8]}@example.com", 
            "password": "LoadTest123!",
            "organization_id": "load-test-org"
        }
        
        # Register user
        response = self.client.post(
            "/api/v1/auth/register",
            json=user_data,
            timeout=30
        )
        
        if response.status_code not in [200, 201]:
            # Try to login in case user already exists
            login_data = {
                "username": user_data["username"],
                "password": user_data["password"]
            }
            
            response = self.client.post(
                "/api/v1/auth/login",
                json=login_data,
                timeout=30
            )
        
        if response.status_code == 200:
            return response.json()["access_token"]
        else:
            # Use a default token for load testing
            return "load-test-token"
    
    @property
    def auth_headers(self) -> Dict[str, str]:
        """Get authentication headers."""
        return {"Authorization": f"Bearer {self.auth_token}"}


class IngestionLoadTest(TaskSet):
    """Load test for data ingestion endpoints."""
    
    @task(3)
    def ingest_sbom(self):
        """Load test SBOM ingestion."""
        correlation_id = str(uuid.uuid4())
        
        data = {
            "data_type": "sbom",
            "source": "load-test-scanner",
            "correlation_id": correlation_id,
            "data": SecurityDataGenerator.generate_sbom()
        }
        
        response = self.client.post(
            "/api/v1/ingestion/sbom",
            json=data,
            headers=self.parent.auth_headers,
            name="ingest_sbom"
        )
    
    @task(2)
    def ingest_cve(self):
        """Load test CVE ingestion."""
        correlation_id = str(uuid.uuid4())
        
        data = {
            "data_type": "cve",
            "source": "load-test-feed",
            "correlation_id": correlation_id,
            "data": SecurityDataGenerator.generate_cve_data()
        }
        
        response = self.client.post(
            "/api/v1/ingestion/cve",
            json=data,
            headers=self.parent.auth_headers,
            name="ingest_cve"
        )
    
    @task(1)
    def ingest_runtime(self):
        """Load test runtime data ingestion."""
        correlation_id = str(uuid.uuid4())
        
        data = {
            "data_type": "runtime",
            "source": "load-test-monitor",
            "correlation_id": correlation_id,
            "data": SecurityDataGenerator.generate_runtime_data()
        }
        
        response = self.client.post(
            "/api/v1/ingestion/runtime",
            json=data,
            headers=self.parent.auth_headers,
            name="ingest_runtime"
        )


class AnalysisLoadTest(TaskSet):
    """Load test for analysis endpoints."""
    
    @task(2)
    def get_analysis_results(self):
        """Load test analysis results retrieval."""
        correlation_id = str(uuid.uuid4())
        
        response = self.client.get(
            f"/api/v1/analysis/results/{correlation_id}",
            headers=self.parent.auth_headers,
            name="get_analysis_results"
        )
    
    @task(1)
    def get_risk_assessment(self):
        """Load test risk assessment retrieval."""
        correlation_id = str(uuid.uuid4())
        
        response = self.client.get(
            f"/api/v1/analysis/risk/{correlation_id}",
            headers=self.parent.auth_headers,
            name="get_risk_assessment"
        )
    
    @task(1)
    def get_behavioral_analysis(self):
        """Load test behavioral analysis retrieval."""
        correlation_id = str(uuid.uuid4())
        
        response = self.client.get(
            f"/api/v1/analysis/behavioral/{correlation_id}",
            headers=self.parent.auth_headers,
            name="get_behavioral_analysis"
        )


class EnrichmentLoadTest(TaskSet):
    """Load test for enrichment endpoints."""
    
    @task(2)
    def enrich_threat_intel(self):
        """Load test threat intelligence enrichment."""
        data = {
            "data_type": "ip",
            "data_value": f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}",
            "enrichment_types": ["reputation", "geolocation", "threat_intel"]
        }
        
        response = self.client.post(
            "/api/v1/enrichment/threat-intel",
            json=data,
            headers=self.parent.auth_headers,
            name="enrich_threat_intel"
        )
    
    @task(1)
    def enrich_mitre_attack(self):
        """Load test MITRE ATT&CK enrichment."""
        data = {
            "technique_id": f"T{random.randint(1000, 1600)}",
            "include_subtechniques": True
        }
        
        response = self.client.post(
            "/api/v1/enrichment/mitre-attack",
            json=data,
            headers=self.parent.auth_headers,
            name="enrich_mitre_attack"
        )


class PluginLoadTest(TaskSet):
    """Load test for plugin registry endpoints."""
    
    @task(2)
    def list_plugins(self):
        """Load test plugin listing."""
        response = self.client.get(
            "/api/v1/plugins",
            headers=self.parent.auth_headers,
            name="list_plugins"
        )
    
    @task(1)
    def get_plugin_health(self):
        """Load test plugin health checks."""
        response = self.client.get(
            "/api/v1/plugins/health",
            headers=self.parent.auth_headers,
            name="get_plugin_health"
        )


class SecurityPlatformUser(HttpUser, AuthenticationMixin):
    """Main user class for load testing."""
    
    wait_time = between(1, 3)  # Wait 1-3 seconds between tasks
    
    tasks = [
        IngestionLoadTest,
        AnalysisLoadTest,
        EnrichmentLoadTest,
        PluginLoadTest
    ]
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.auth_token = None


class HighThroughputUser(HttpUser, AuthenticationMixin):
    """High-throughput user for stress testing."""
    
    wait_time = between(0.1, 0.5)  # Very short wait times
    
    @task(5)
    def rapid_ingestion(self):
        """Rapid-fire ingestion for stress testing."""
        correlation_id = str(uuid.uuid4())
        
        data = {
            "data_type": "cve",
            "source": "stress-test",
            "correlation_id": correlation_id,
            "data": SecurityDataGenerator.generate_cve_data()
        }
        
        self.client.post(
            "/api/v1/ingestion/cve",
            json=data,
            headers=self.auth_headers,
            name="rapid_ingestion"
        )
    
    @task(3)
    def rapid_analysis(self):
        """Rapid analysis requests."""
        correlation_id = str(uuid.uuid4())
        
        self.client.get(
            f"/api/v1/analysis/results/{correlation_id}",
            headers=self.auth_headers,
            name="rapid_analysis"
        )


# Performance test configurations
LOAD_TEST_SCENARIOS = {
    "normal_load": {
        "user_class": SecurityPlatformUser,
        "users": 50,
        "spawn_rate": 5,
        "run_time": "5m"
    },
    "stress_test": {
        "user_class": HighThroughputUser,
        "users": 200,
        "spawn_rate": 20,
        "run_time": "10m"
    },
    "spike_test": {
        "user_class": SecurityPlatformUser,
        "users": 500,
        "spawn_rate": 50,
        "run_time": "3m"
    },
    "endurance_test": {
        "user_class": SecurityPlatformUser,
        "users": 100,
        "spawn_rate": 10,
        "run_time": "30m"
    }
}


def run_performance_test(
    host: str,
    scenario: str = "normal_load",
    users: int = None,
    spawn_rate: int = None,
    run_time: str = None,
    html_report: str = None,
    csv_prefix: str = None
):
    """Run performance test with specified parameters."""
    
    # Get scenario configuration
    scenario_config = LOAD_TEST_SCENARIOS.get(scenario, LOAD_TEST_SCENARIOS["normal_load"])
    
    # Override with command line parameters
    final_users = users or scenario_config["users"]
    final_spawn_rate = spawn_rate or scenario_config["spawn_rate"]
    final_run_time = run_time or scenario_config["run_time"]
    
    print(f"Running performance test: {scenario}")
    print(f"Target: {host}")
    print(f"Users: {final_users}")
    print(f"Spawn Rate: {final_spawn_rate}")
    print(f"Duration: {final_run_time}")
    
    # Setup logging
    setup_logging("INFO")
    
    # Create environment
    env = Environment(
        user_classes=[scenario_config["user_class"]],
        host=host
    )
    
    # Add event listeners for reporting
    if html_report or csv_prefix:
        @events.request.add_listener
        def on_request(request_type, name, response_time, response_length, response, context, exception, **kwargs):
            pass
    
    # Start load test
    env.create_local_runner()
    
    # Start test
    env.runner.start(final_users, spawn_rate=final_spawn_rate)
    
    # Convert run_time to seconds
    if final_run_time.endswith('s'):
        duration = int(final_run_time[:-1])
    elif final_run_time.endswith('m'):
        duration = int(final_run_time[:-1]) * 60
    elif final_run_time.endswith('h'):
        duration = int(final_run_time[:-1]) * 3600
    else:
        duration = int(final_run_time)
    
    # Run for specified duration
    import time
    time.sleep(duration)
    
    # Stop test
    env.runner.stop()
    
    # Generate reports
    stats = env.runner.stats
    
    if html_report:
        from locust.stats import StatsCSV
        stats_csv = StatsCSV(env, csv_prefix or "performance")
        stats_csv.stats_csv()
        
        # Generate HTML report
        with open(html_report, 'w') as f:
            f.write(generate_html_report(stats))
    
    if csv_prefix:
        from locust.stats import StatsCSV
        stats_csv = StatsCSV(env, csv_prefix)
        stats_csv.stats_csv()
    
    # Print summary
    print("\n" + "="*50)
    print("PERFORMANCE TEST SUMMARY")
    print("="*50)
    print(f"Total Requests: {stats.total.num_requests}")
    print(f"Failed Requests: {stats.total.num_failures}")
    print(f"Average Response Time: {stats.total.avg_response_time:.2f}ms")
    print(f"Max Response Time: {stats.total.max_response_time}ms")
    print(f"RPS: {stats.total.current_rps:.2f}")
    print(f"Failure Rate: {stats.total.fail_ratio*100:.2f}%")
    
    return stats.total.fail_ratio == 0  # Return True if no failures


def generate_html_report(stats) -> str:
    """Generate HTML performance report."""
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>MCP Security Platform - Performance Test Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            .header {{ background: #2c3e50; color: white; padding: 20px; text-align: center; }}
            .summary {{ background: #ecf0f1; padding: 15px; margin: 20px 0; }}
            .stats-table {{ width: 100%; border-collapse: collapse; }}
            .stats-table th, .stats-table td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            .stats-table th {{ background-color: #34495e; color: white; }}
            .success {{ color: #27ae60; }}
            .warning {{ color: #f39c12; }}
            .error {{ color: #e74c3c; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>MCP Security Platform</h1>
            <h2>Performance Test Report</h2>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="summary">
            <h3>Test Summary</h3>
            <p><strong>Total Requests:</strong> {stats.total.num_requests}</p>
            <p><strong>Failed Requests:</strong> {stats.total.num_failures}</p>
            <p><strong>Average Response Time:</strong> {stats.total.avg_response_time:.2f}ms</p>
            <p><strong>Max Response Time:</strong> {stats.total.max_response_time}ms</p>
            <p><strong>Requests per Second:</strong> {stats.total.current_rps:.2f}</p>
            <p><strong>Failure Rate:</strong> {stats.total.fail_ratio*100:.2f}%</p>
        </div>
        
        <h3>Detailed Statistics</h3>
        <table class="stats-table">
            <tr>
                <th>Endpoint</th>
                <th>Requests</th>
                <th>Failures</th>
                <th>Avg (ms)</th>
                <th>Max (ms)</th>
                <th>RPS</th>
            </tr>
    """
    
    for endpoint, entry in stats.entries.items():
        if endpoint[0] != "Aggregated":
            html += f"""
            <tr>
                <td>{endpoint[1]}</td>
                <td>{entry.num_requests}</td>
                <td class="{'error' if entry.num_failures > 0 else 'success'}">{entry.num_failures}</td>
                <td>{entry.avg_response_time:.2f}</td>
                <td>{entry.max_response_time}</td>
                <td>{entry.current_rps:.2f}</td>
            </tr>
            """
    
    html += """
        </table>
    </body>
    </html>
    """
    
    return html


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run MCP Security Platform performance tests")
    parser.add_argument("--host", required=True, help="Target host URL")
    parser.add_argument("--scenario", default="normal_load", choices=LOAD_TEST_SCENARIOS.keys(),
                       help="Test scenario to run")
    parser.add_argument("--users", type=int, help="Number of users")
    parser.add_argument("--spawn-rate", type=int, help="User spawn rate")
    parser.add_argument("--time", help="Test duration (e.g., 5m, 300s)")
    parser.add_argument("--html", help="HTML report output file")
    parser.add_argument("--csv", help="CSV report prefix")
    
    args = parser.parse_args()
    
    success = run_performance_test(
        host=args.host,
        scenario=args.scenario,
        users=args.users,
        spawn_rate=args.spawn_rate,
        run_time=args.time,
        html_report=args.html,
        csv_prefix=args.csv
    )
    
    exit(0 if success else 1)