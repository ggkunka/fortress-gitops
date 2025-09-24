"""
Chaos Engineering tests for MCP Security Platform.

Tests system resilience by introducing controlled failures and observing
system behavior and recovery capabilities.
"""

import asyncio
import json
import random
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import httpx
import kubernetes
from kubernetes import client, config
import argparse
import logging


class ChaosExperiment:
    """Base class for chaos experiments."""
    
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.start_time = None
        self.end_time = None
        self.results = []
        self.logger = logging.getLogger(f"chaos.{name}")
    
    async def run(self) -> Dict[str, Any]:
        """Run the chaos experiment."""
        self.logger.info(f"Starting chaos experiment: {self.name}")
        self.start_time = datetime.now()
        
        try:
            # Pre-experiment validation
            await self.pre_experiment_check()
            
            # Execute experiment
            await self.execute_experiment()
            
            # Wait for system stabilization
            await self.wait_for_stabilization()
            
            # Post-experiment validation
            await self.post_experiment_check()
            
            self.end_time = datetime.now()
            duration = (self.end_time - self.start_time).total_seconds()
            
            return {
                "name": self.name,
                "description": self.description,
                "duration": duration,
                "success": True,
                "results": self.results,
                "start_time": self.start_time.isoformat(),
                "end_time": self.end_time.isoformat()
            }
            
        except Exception as e:
            self.end_time = datetime.now()
            self.logger.error(f"Chaos experiment failed: {e}")
            
            return {
                "name": self.name,
                "description": self.description,
                "success": False,
                "error": str(e),
                "results": self.results,
                "start_time": self.start_time.isoformat() if self.start_time else None,
                "end_time": self.end_time.isoformat()
            }
    
    async def pre_experiment_check(self):
        """Validate system state before experiment."""
        pass
    
    async def execute_experiment(self):
        """Execute the chaos experiment."""
        raise NotImplementedError
    
    async def wait_for_stabilization(self, timeout: int = 120):
        """Wait for system to stabilize after chaos injection."""
        await asyncio.sleep(timeout)
    
    async def post_experiment_check(self):
        """Validate system recovery after experiment."""
        pass
    
    def add_result(self, operation: str, success: bool, **metadata):
        """Add result to experiment."""
        self.results.append({
            "operation": operation,
            "success": success,
            "timestamp": datetime.now().isoformat(),
            **metadata
        })


class PodKillExperiment(ChaosExperiment):
    """Experiment that kills random pods to test resilience."""
    
    def __init__(self, namespace: str = "default", target_services: List[str] = None):
        super().__init__(
            "pod_kill",
            "Kill random pods to test pod recovery and service resilience"
        )
        self.namespace = namespace
        self.target_services = target_services or [
            "gateway-service", "auth-service", "ingestion-service",
            "enrichment-service", "analysis-service", "notification-service"
        ]
        self.killed_pods = []
    
    async def execute_experiment(self):
        """Kill random pods and monitor recovery."""
        try:
            # Load Kubernetes config
            config.load_incluster_config()
        except:
            config.load_kube_config()
        
        v1 = client.CoreV1Api()
        
        # Kill pods for each target service
        for service in self.target_services:
            try:
                # Get pods for service
                pods = v1.list_namespaced_pod(
                    namespace=self.namespace,
                    label_selector=f"app={service}"
                )
                
                if pods.items:
                    # Kill random pod
                    target_pod = random.choice(pods.items)
                    pod_name = target_pod.metadata.name
                    
                    self.logger.info(f"Killing pod: {pod_name}")
                    v1.delete_namespaced_pod(
                        name=pod_name,
                        namespace=self.namespace,
                        grace_period_seconds=0
                    )
                    
                    self.killed_pods.append({
                        "service": service,
                        "pod_name": pod_name,
                        "kill_time": datetime.now().isoformat()
                    })
                    
                    self.add_result("pod_kill", True, service=service, pod=pod_name)
                    
                    # Wait between kills
                    await asyncio.sleep(5)
                else:
                    self.add_result("pod_kill", False, service=service, error="No pods found")
                    
            except Exception as e:
                self.logger.error(f"Failed to kill pod for {service}: {e}")
                self.add_result("pod_kill", False, service=service, error=str(e))
    
    async def post_experiment_check(self):
        """Check that new pods were created and are healthy."""
        try:
            config.load_incluster_config()
        except:
            config.load_kube_config()
        
        v1 = client.CoreV1Api()
        
        for service in self.target_services:
            try:
                # Check that pods are running
                pods = v1.list_namespaced_pod(
                    namespace=self.namespace,
                    label_selector=f"app={service}"
                )
                
                running_pods = [p for p in pods.items if p.status.phase == "Running"]
                
                if running_pods:
                    self.add_result("recovery_check", True, service=service, 
                                  running_pods=len(running_pods))
                else:
                    self.add_result("recovery_check", False, service=service,
                                  error="No running pods found")
                    
            except Exception as e:
                self.add_result("recovery_check", False, service=service, error=str(e))


class NetworkPartitionExperiment(ChaosExperiment):
    """Experiment that creates network partitions between services."""
    
    def __init__(self, namespace: str = "default"):
        super().__init__(
            "network_partition", 
            "Create network partitions to test service communication resilience"
        )
        self.namespace = namespace
        self.network_policies = []
    
    async def execute_experiment(self):
        """Create network policies to partition services."""
        try:
            config.load_incluster_config()
        except:
            config.load_kube_config()
        
        networking_v1 = client.NetworkingV1Api()
        
        # Create network policy to isolate ingestion service
        policy_manifest = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": "chaos-partition-ingestion",
                "namespace": self.namespace
            },
            "spec": {
                "podSelector": {
                    "matchLabels": {
                        "app": "ingestion-service"
                    }
                },
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [
                    {
                        "from": [
                            {
                                "podSelector": {
                                    "matchLabels": {
                                        "app": "gateway-service"
                                    }
                                }
                            }
                        ]
                    }
                ],
                "egress": [
                    {
                        "to": [
                            {
                                "podSelector": {
                                    "matchLabels": {
                                        "app": "postgresql"
                                    }
                                }
                            }
                        ]
                    }
                ]
            }
        }
        
        try:
            networking_v1.create_namespaced_network_policy(
                namespace=self.namespace,
                body=policy_manifest
            )
            self.network_policies.append("chaos-partition-ingestion")
            self.add_result("network_partition", True, policy="chaos-partition-ingestion")
            
        except Exception as e:
            self.add_result("network_partition", False, error=str(e))
    
    async def wait_for_stabilization(self, timeout: int = 60):
        """Wait shorter time for network experiments."""
        await asyncio.sleep(timeout)
    
    async def post_experiment_check(self):
        """Remove network policies and verify connectivity restoration."""
        try:
            config.load_incluster_config()
        except:
            config.load_kube_config()
        
        networking_v1 = client.NetworkingV1Api()
        
        # Remove network policies
        for policy_name in self.network_policies:
            try:
                networking_v1.delete_namespaced_network_policy(
                    name=policy_name,
                    namespace=self.namespace
                )
                self.add_result("cleanup", True, policy=policy_name)
            except Exception as e:
                self.add_result("cleanup", False, policy=policy_name, error=str(e))
        
        # Wait for connectivity to restore
        await asyncio.sleep(30)


class ResourceExhaustionExperiment(ChaosExperiment):
    """Experiment that exhausts system resources."""
    
    def __init__(self, namespace: str = "default"):
        super().__init__(
            "resource_exhaustion",
            "Exhaust CPU/memory resources to test resource management"
        )
        self.namespace = namespace
        self.stress_pods = []
    
    async def execute_experiment(self):
        """Create pods that consume excessive resources."""
        try:
            config.load_incluster_config()
        except:
            config.load_kube_config()
        
        v1 = client.CoreV1Api()
        
        # Create CPU stress pod
        cpu_stress_manifest = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "chaos-cpu-stress",
                "namespace": self.namespace,
                "labels": {"chaos-experiment": "resource-exhaustion"}
            },
            "spec": {
                "containers": [
                    {
                        "name": "stress",
                        "image": "progrium/stress",
                        "args": ["--cpu", "4", "--timeout", "300s"],
                        "resources": {
                            "requests": {"cpu": "1000m", "memory": "1Gi"},
                            "limits": {"cpu": "4000m", "memory": "4Gi"}
                        }
                    }
                ],
                "restartPolicy": "Never"
            }
        }
        
        # Create memory stress pod
        memory_stress_manifest = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "chaos-memory-stress",
                "namespace": self.namespace,
                "labels": {"chaos-experiment": "resource-exhaustion"}
            },
            "spec": {
                "containers": [
                    {
                        "name": "stress",
                        "image": "progrium/stress",
                        "args": ["--vm", "2", "--vm-bytes", "2G", "--timeout", "300s"],
                        "resources": {
                            "requests": {"memory": "2Gi"},
                            "limits": {"memory": "4Gi"}
                        }
                    }
                ],
                "restartPolicy": "Never"
            }
        }
        
        # Create stress pods
        for manifest in [cpu_stress_manifest, memory_stress_manifest]:
            try:
                v1.create_namespaced_pod(
                    namespace=self.namespace,
                    body=manifest
                )
                self.stress_pods.append(manifest["metadata"]["name"])
                self.add_result("stress_pod_creation", True, 
                              pod=manifest["metadata"]["name"])
            except Exception as e:
                self.add_result("stress_pod_creation", False,
                              pod=manifest["metadata"]["name"], error=str(e))
    
    async def post_experiment_check(self):
        """Clean up stress pods and verify system recovery."""
        try:
            config.load_incluster_config()
        except:
            config.load_kube_config()
        
        v1 = client.CoreV1Api()
        
        # Delete stress pods
        for pod_name in self.stress_pods:
            try:
                v1.delete_namespaced_pod(
                    name=pod_name,
                    namespace=self.namespace,
                    grace_period_seconds=0
                )
                self.add_result("cleanup", True, pod=pod_name)
            except Exception as e:
                self.add_result("cleanup", False, pod=pod_name, error=str(e))


class ServiceLatencyExperiment(ChaosExperiment):
    """Experiment that introduces latency to service communications."""
    
    def __init__(self, gateway_url: str):
        super().__init__(
            "service_latency",
            "Introduce artificial latency to test timeout handling"
        )
        self.gateway_url = gateway_url
        self.auth_token = None
    
    async def pre_experiment_check(self):
        """Get auth token and verify services are responsive."""
        self.auth_token = await self.get_auth_token()
        
        # Verify baseline performance
        start_time = time.time()
        async with httpx.AsyncClient(timeout=30.0) as client:
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            
            response = await client.get(f"{self.gateway_url}/api/v1/ingestion/health", 
                                      headers=headers)
            
            baseline_latency = time.time() - start_time
            
            if response.status_code == 200:
                self.add_result("baseline_check", True, latency=baseline_latency)
            else:
                self.add_result("baseline_check", False, 
                              status_code=response.status_code)
    
    async def execute_experiment(self):
        """Simulate high latency conditions by overwhelming the system."""
        async with httpx.AsyncClient(timeout=5.0) as client:
            headers = {"Authorization": f"Bearer {self.auth_token}"}
            
            # Create many concurrent requests to simulate latency
            tasks = []
            
            for i in range(100):
                # Create large payload to slow down processing
                large_sbom = {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.4",
                    "version": 1,
                    "components": [
                        {
                            "type": "library",
                            "name": f"large-component-{j}",
                            "version": "1.0.0",
                            "description": "x" * 1000  # Large description
                        } for j in range(50)  # Many components
                    ]
                }
                
                data = {
                    "data_type": "sbom",
                    "source": "chaos-latency",
                    "correlation_id": str(uuid.uuid4()),
                    "data": large_sbom
                }
                
                task = self.send_request_with_timing(client, data, headers)
                tasks.append(task)
            
            # Execute requests concurrently
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Analyze results
            successful_requests = [r for r in results if isinstance(r, dict) and r.get("success")]
            failed_requests = [r for r in results if isinstance(r, dict) and not r.get("success")]
            exceptions = [r for r in results if isinstance(r, Exception)]
            
            self.add_result("latency_test", True,
                          total_requests=len(tasks),
                          successful=len(successful_requests),
                          failed=len(failed_requests),
                          exceptions=len(exceptions))
    
    async def send_request_with_timing(self, client: httpx.AsyncClient, data: Dict, headers: Dict):
        """Send request and measure timing."""
        start_time = time.time()
        
        try:
            response = await client.post(
                f"{self.gateway_url}/api/v1/ingestion/sbom",
                json=data,
                headers=headers
            )
            
            duration = time.time() - start_time
            
            return {
                "success": response.status_code in [200, 202],
                "duration": duration,
                "status_code": response.status_code
            }
            
        except Exception as e:
            duration = time.time() - start_time
            return {
                "success": False,
                "duration": duration,
                "error": str(e)
            }
    
    async def get_auth_token(self) -> str:
        """Get authentication token."""
        async with httpx.AsyncClient() as client:
            user_data = {
                "username": f"chaos_user_{uuid.uuid4().hex[:8]}",
                "email": f"chaos_{uuid.uuid4().hex[:8]}@example.com",
                "password": "ChaosTest123!",
                "organization_id": "chaos-org"
            }
            
            try:
                response = await client.post(
                    f"{self.gateway_url}/api/v1/auth/register",
                    json=user_data,
                    timeout=10.0
                )
                
                if response.status_code in [200, 201]:
                    return response.json()["access_token"]
            except:
                pass
            
            return "chaos-token"


class DatabaseConnectionExperiment(ChaosExperiment):
    """Experiment that tests database connection resilience."""
    
    def __init__(self, namespace: str = "default"):
        super().__init__(
            "database_connection",
            "Test database connection pool exhaustion and recovery"
        )
        self.namespace = namespace
    
    async def execute_experiment(self):
        """Scale down database to test connection handling."""
        try:
            config.load_incluster_config()
        except:
            config.load_kube_config()
        
        apps_v1 = client.AppsV1Api()
        
        try:
            # Scale down PostgreSQL to 0 replicas
            apps_v1.patch_namespaced_deployment(
                name="postgresql",
                namespace=self.namespace,
                body={"spec": {"replicas": 0}}
            )
            
            self.add_result("scale_down", True, service="postgresql")
            
            # Wait for pods to terminate
            await asyncio.sleep(30)
            
            # Scale back up
            apps_v1.patch_namespaced_deployment(
                name="postgresql",
                namespace=self.namespace,
                body={"spec": {"replicas": 1}}
            )
            
            self.add_result("scale_up", True, service="postgresql")
            
        except Exception as e:
            self.add_result("database_scaling", False, error=str(e))


class ChaosTestRunner:
    """Main chaos test runner."""
    
    def __init__(self, namespace: str = "default", gateway_url: str = "http://gateway-service:8081"):
        self.namespace = namespace
        self.gateway_url = gateway_url
        self.experiments = []
        self.results = []
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger("chaos_runner")
    
    def add_experiment(self, experiment: ChaosExperiment):
        """Add chaos experiment to runner."""
        self.experiments.append(experiment)
    
    async def run_all_experiments(self) -> Dict[str, Any]:
        """Run all registered chaos experiments."""
        self.logger.info(f"Starting {len(self.experiments)} chaos experiments")
        
        start_time = datetime.now()
        
        for experiment in self.experiments:
            try:
                result = await experiment.run()
                self.results.append(result)
                
                if result["success"]:
                    self.logger.info(f"✅ {experiment.name} completed successfully")
                else:
                    self.logger.error(f"❌ {experiment.name} failed: {result.get('error')}")
                
                # Wait between experiments
                await asyncio.sleep(30)
                
            except Exception as e:
                self.logger.error(f"Failed to run experiment {experiment.name}: {e}")
                self.results.append({
                    "name": experiment.name,
                    "success": False,
                    "error": str(e)
                })
        
        end_time = datetime.now()
        
        # Generate summary
        total_experiments = len(self.results)
        successful_experiments = len([r for r in self.results if r.get("success")])
        failed_experiments = total_experiments - successful_experiments
        
        summary = {
            "chaos_test_summary": {
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
                "duration": (end_time - start_time).total_seconds(),
                "total_experiments": total_experiments,
                "successful_experiments": successful_experiments,
                "failed_experiments": failed_experiments,
                "success_rate": successful_experiments / total_experiments if total_experiments > 0 else 0
            },
            "experiment_results": self.results
        }
        
        return summary
    
    def print_summary(self, results: Dict[str, Any]):
        """Print chaos test summary."""
        summary = results["chaos_test_summary"]
        
        print("\n" + "="*60)
        print("CHAOS ENGINEERING TEST SUMMARY")
        print("="*60)
        print(f"Duration: {summary['duration']:.2f}s")
        print(f"Total Experiments: {summary['total_experiments']}")
        print(f"Successful: {summary['successful_experiments']}")
        print(f"Failed: {summary['failed_experiments']}")
        print(f"Success Rate: {summary['success_rate']*100:.1f}%")
        
        print("\nExperiment Details:")
        print("-" * 40)
        
        for result in results["experiment_results"]:
            status = "✅" if result.get("success") else "❌"
            print(f"{status} {result['name']}")
            if not result.get("success"):
                print(f"   Error: {result.get('error', 'Unknown error')}")


async def run_chaos_tests(namespace: str = "default", 
                         gateway_url: str = "http://gateway-service:8081",
                         output_dir: str = "/app/results/chaos"):
    """Run comprehensive chaos engineering tests."""
    
    runner = ChaosTestRunner(namespace, gateway_url)
    
    # Add experiments
    runner.add_experiment(PodKillExperiment(namespace))
    runner.add_experiment(NetworkPartitionExperiment(namespace))
    runner.add_experiment(ResourceExhaustionExperiment(namespace))
    runner.add_experiment(ServiceLatencyExperiment(gateway_url))
    runner.add_experiment(DatabaseConnectionExperiment(namespace))
    
    # Run experiments
    results = await runner.run_all_experiments()
    
    # Print summary
    runner.print_summary(results)
    
    # Save results
    import os
    os.makedirs(output_dir, exist_ok=True)
    
    with open(f"{output_dir}/chaos_results.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to {output_dir}/chaos_results.json")
    
    # Return success if all experiments passed
    return results["chaos_test_summary"]["failed_experiments"] == 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run MCP Security Platform chaos tests")
    parser.add_argument("--namespace", default="default", help="Kubernetes namespace")
    parser.add_argument("--gateway-url", default="http://gateway-service:8081", help="Gateway URL")
    parser.add_argument("--output-dir", default="/app/results/chaos", help="Output directory")
    
    args = parser.parse_args()
    
    success = asyncio.run(run_chaos_tests(
        namespace=args.namespace,
        gateway_url=args.gateway_url,
        output_dir=args.output_dir
    ))
    
    exit(0 if success else 1)