# Security Configuration Validator for MCP Security Platform
# This kpt function validates security configurations across all resources

def main(ctx):
    """Main validation function"""
    
    # Get configuration parameters
    config = get_config(ctx)
    errors = []
    warnings = []
    
    # Validate all resources
    for resource in ctx.resource_list.items:
        resource_errors, resource_warnings = validate_resource(resource, config)
        errors.extend(resource_errors)
        warnings.extend(resource_warnings)
    
    # Report results
    if errors:
        fail("Security validation failed:\n" + "\n".join(errors))
    
    if warnings:
        print("Security validation warnings:\n" + "\n".join(warnings))
    
    print(f"Security validation passed for {len(ctx.resource_list.items)} resources")

def get_config(ctx):
    """Extract configuration parameters"""
    config = {
        "strict_mode": ctx.config.get("strict_mode", "false") == "true",
        "require_mtls": ctx.config.get("require_mtls", "false") == "true",
        "require_non_root": ctx.config.get("require_non_root", "true") == "true",
        "require_read_only_fs": ctx.config.get("require_read_only_fs", "false") == "true",
        "require_resource_limits": ctx.config.get("require_resource_limits", "true") == "true",
        "require_network_policies": ctx.config.get("require_network_policies", "false") == "true",
        "require_pod_security_context": ctx.config.get("require_pod_security_context", "true") == "true",
        "scan_for_vulnerabilities": ctx.config.get("scan_for_vulnerabilities", "false") == "true",
    }
    return config

def validate_resource(resource, config):
    """Validate a single resource"""
    errors = []
    warnings = []
    
    kind = resource.get("kind", "")
    name = resource.get("metadata", {}).get("name", "unknown")
    namespace = resource.get("metadata", {}).get("namespace", "default")
    
    # Validate based on resource type
    if kind == "Deployment":
        e, w = validate_deployment(resource, config, name, namespace)
        errors.extend(e)
        warnings.extend(w)
    elif kind == "StatefulSet":
        e, w = validate_statefulset(resource, config, name, namespace)
        errors.extend(e)
        warnings.extend(w)
    elif kind == "Service":
        e, w = validate_service(resource, config, name, namespace)
        errors.extend(e)
        warnings.extend(w)
    elif kind == "PeerAuthentication":
        e, w = validate_peer_authentication(resource, config, name, namespace)
        errors.extend(e)
        warnings.extend(w)
    elif kind == "AuthorizationPolicy":
        e, w = validate_authorization_policy(resource, config, name, namespace)
        errors.extend(e)
        warnings.extend(w)
    elif kind == "NetworkPolicy":
        e, w = validate_network_policy(resource, config, name, namespace)
        errors.extend(e)
        warnings.extend(w)
    
    return errors, warnings

def validate_deployment(resource, config, name, namespace):
    """Validate Deployment security configuration"""
    errors = []
    warnings = []
    
    spec = resource.get("spec", {})
    template = spec.get("template", {})
    pod_spec = template.get("spec", {})
    
    # Validate security context
    if config["require_pod_security_context"]:
        security_context = pod_spec.get("securityContext", {})
        if not security_context.get("runAsNonRoot"):
            errors.append(f"Deployment {namespace}/{name}: Must set runAsNonRoot=true")
        if not security_context.get("fsGroup"):
            warnings.append(f"Deployment {namespace}/{name}: Consider setting fsGroup")
    
    # Validate containers
    containers = pod_spec.get("containers", [])
    for i, container in enumerate(containers):
        container_name = container.get("name", f"container-{i}")
        
        # Resource limits validation
        if config["require_resource_limits"]:
            resources = container.get("resources", {})
            if not resources.get("limits"):
                errors.append(f"Deployment {namespace}/{name}, container {container_name}: Must have resource limits")
            if not resources.get("requests"):
                warnings.append(f"Deployment {namespace}/{name}, container {container_name}: Should have resource requests")
        
        # Security context validation
        container_security = container.get("securityContext", {})
        if config["require_non_root"]:
            if not container_security.get("runAsNonRoot"):
                errors.append(f"Deployment {namespace}/{name}, container {container_name}: Must set runAsNonRoot=true")
        
        if config["require_read_only_fs"]:
            if not container_security.get("readOnlyRootFilesystem"):
                errors.append(f"Deployment {namespace}/{name}, container {container_name}: Must set readOnlyRootFilesystem=true")
        
        # Capabilities validation
        capabilities = container_security.get("capabilities", {})
        if not capabilities.get("drop") or "ALL" not in capabilities.get("drop", []):
            warnings.append(f"Deployment {namespace}/{name}, container {container_name}: Should drop ALL capabilities")
        
        # Privilege escalation
        if container_security.get("allowPrivilegeEscalation") != False:
            errors.append(f"Deployment {namespace}/{name}, container {container_name}: Must set allowPrivilegeEscalation=false")
    
    # Istio sidecar validation
    annotations = template.get("metadata", {}).get("annotations", {})
    if not annotations.get("sidecar.istio.io/inject") == "true":
        warnings.append(f"Deployment {namespace}/{name}: Consider enabling Istio sidecar injection")
    
    return errors, warnings

def validate_statefulset(resource, config, name, namespace):
    """Validate StatefulSet security configuration"""
    # Similar validation to Deployment
    return validate_deployment(resource, config, name, namespace)

def validate_service(resource, config, name, namespace):
    """Validate Service security configuration"""
    errors = []
    warnings = []
    
    spec = resource.get("spec", {})
    
    # Service type validation
    service_type = spec.get("type", "ClusterIP")
    if service_type == "NodePort" and config["strict_mode"]:
        warnings.append(f"Service {namespace}/{name}: NodePort services may expose unnecessary attack surface")
    
    if service_type == "LoadBalancer" and config["strict_mode"]:
        warnings.append(f"Service {namespace}/{name}: LoadBalancer services should have proper security groups")
    
    # Port validation
    ports = spec.get("ports", [])
    for port in ports:
        port_number = port.get("port")
        if port_number in [22, 23, 25, 53, 135, 139, 445, 1433, 1521, 3306, 3389, 5432]:
            warnings.append(f"Service {namespace}/{name}: Port {port_number} is commonly targeted by attackers")
    
    return errors, warnings

def validate_peer_authentication(resource, config, name, namespace):
    """Validate Istio PeerAuthentication"""
    errors = []
    warnings = []
    
    spec = resource.get("spec", {})
    mtls = spec.get("mtls", {})
    
    if config["require_mtls"]:
        mode = mtls.get("mode", "")
        if mode != "STRICT":
            errors.append(f"PeerAuthentication {namespace}/{name}: Must use STRICT mTLS mode")
    
    return errors, warnings

def validate_authorization_policy(resource, config, name, namespace):
    """Validate Istio AuthorizationPolicy"""
    errors = []
    warnings = []
    
    spec = resource.get("spec", {})
    rules = spec.get("rules", [])
    
    if not rules:
        errors.append(f"AuthorizationPolicy {namespace}/{name}: Must have at least one rule")
    
    # Check for overly permissive rules
    for i, rule in enumerate(rules):
        from_sources = rule.get("from", [])
        to_operations = rule.get("to", [])
        
        # Check for wildcard sources
        for source in from_sources:
            if source.get("source", {}).get("principals") == ["*"]:
                warnings.append(f"AuthorizationPolicy {namespace}/{name}, rule {i}: Wildcard principals may be too permissive")
        
        # Check for wildcard operations
        for operation in to_operations:
            paths = operation.get("operation", {}).get("paths", [])
            if "/*" in paths or "*" in paths:
                warnings.append(f"AuthorizationPolicy {namespace}/{name}, rule {i}: Wildcard paths may be too permissive")
    
    return errors, warnings

def validate_network_policy(resource, config, name, namespace):
    """Validate NetworkPolicy"""
    errors = []
    warnings = []
    
    spec = resource.get("spec", {})
    
    # Check if policy has proper selectors
    pod_selector = spec.get("podSelector", {})
    if not pod_selector.get("matchLabels") and not pod_selector.get("matchExpressions"):
        warnings.append(f"NetworkPolicy {namespace}/{name}: Empty podSelector affects all pods")
    
    # Check policy types
    policy_types = spec.get("policyTypes", [])
    if "Ingress" not in policy_types and "Egress" not in policy_types:
        warnings.append(f"NetworkPolicy {namespace}/{name}: Should specify policyTypes")
    
    return errors, warnings

# Entry point for kpt function
main(ctx)