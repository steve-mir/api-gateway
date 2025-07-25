# Troubleshooting Guide

This guide helps you diagnose and resolve common issues with the Rust API Gateway.

## Table of Contents

- [Gateway Won't Start](#gateway-wont-start)
- [Service Discovery Issues](#service-discovery-issues)
- [Authentication Problems](#authentication-problems)
- [Performance Issues](#performance-issues)
- [Network and Connectivity](#network-and-connectivity)
- [Configuration Problems](#configuration-problems)
- [Logging and Debugging](#logging-and-debugging)
- [Common Error Messages](#common-error-messages)
- [Monitoring and Diagnostics](#monitoring-and-diagnostics)

## Gateway Won't Start

### Symptom: Gateway fails to start with configuration errors

**Possible Causes:**
- Invalid YAML syntax in configuration file
- Missing required configuration fields
- Invalid port numbers or addresses
- File permission issues

**Solutions:**

1. **Validate YAML syntax:**
```bash
# Use a YAML validator
yamllint config/gateway.yaml

# Or use Python
python -c "import yaml; yaml.safe_load(open('config/gateway.yaml'))"
```

2. **Check configuration with verbose logging:**
```bash
RUST_LOG=debug cargo run
```

3. **Verify file permissions:**
```bash
ls -la config/gateway.yaml
chmod 644 config/gateway.yaml
```

4. **Check port availability:**
```bash
# Check if ports are already in use
netstat -tulpn | grep :8080
netstat -tulpn | grep :8081
```

### Symptom: Gateway starts but immediately crashes

**Possible Causes:**
- Memory allocation issues
- Dependency service unavailable
- Invalid TLS certificates

**Solutions:**

1. **Check system resources:**
```bash
free -h
df -h
ulimit -a
```

2. **Validate TLS certificates:**
```bash
openssl x509 -in /path/to/cert.pem -text -noout
openssl rsa -in /path/to/key.pem -check
```

3. **Start with minimal configuration:**
```yaml
server:
  bind_address: "127.0.0.1"
  http_port: 8080

routes:
  - path: "/health"
    upstream: "health-service"

upstreams:
  health-service:
    discovery:
      type: "static"
      endpoints:
        - "http://httpbin.org"
```

## Service Discovery Issues

### Symptom: Services not being discovered

**Kubernetes Service Discovery:**

1. **Check RBAC permissions:**
```bash
kubectl auth can-i get services --as=system:serviceaccount:default:gateway
kubectl auth can-i list endpoints --as=system:serviceaccount:default:gateway
```

2. **Verify service labels:**
```bash
kubectl get services -l app.kubernetes.io/managed-by=gateway
```

3. **Check namespace configuration:**
```yaml
service_discovery:
  kubernetes:
    namespace: "default"  # Make sure this matches your services
```

**Consul Service Discovery:**

1. **Test Consul connectivity:**
```bash
curl http://consul.service.consul:8500/v1/agent/self
```

2. **Check service registration:**
```bash
curl http://consul.service.consul:8500/v1/catalog/services
```

3. **Verify health checks:**
```bash
curl http://consul.service.consul:8500/v1/health/checks/your-service
```

### Symptom: Services discovered but marked as unhealthy

**Solutions:**

1. **Check health check configuration:**
```yaml
upstreams:
  your-service:
    health_check:
      enabled: true
      path: "/health"
      method: "GET"
      interval: 30
      timeout: 5
      healthy_threshold: 2
      unhealthy_threshold: 3
```

2. **Test health endpoint manually:**
```bash
curl -v http://your-service:8080/health
```

3. **Check service logs:**
```bash
kubectl logs -f deployment/your-service
```

## Authentication Problems

### Symptom: JWT authentication failing

**Solutions:**

1. **Verify JWT token:**
```bash
# Decode JWT token (without verification)
echo "your.jwt.token" | cut -d. -f2 | base64 -d | jq .
```

2. **Check JWT configuration:**
```yaml
authentication:
  jwt:
    secret: "correct-secret-key"
    algorithms: ["HS256"]
    issuer: "https://your-auth-server.com"
    audience: "api-gateway"
```

3. **Test with curl:**
```bash
curl -H "Authorization: Bearer your.jwt.token" \
     http://localhost:8080/api/protected
```

### Symptom: API key authentication not working

**Solutions:**

1. **Verify API key storage:**
```bash
# For Redis storage
redis-cli GET "api_keys:your-api-key"
```

2. **Check header name:**
```yaml
authentication:
  api_key:
    header_name: "X-API-Key"  # Make sure this matches your requests
```

3. **Test API key:**
```bash
curl -H "X-API-Key: your-api-key" \
     http://localhost:8080/api/protected
```

## Performance Issues

### Symptom: High latency

**Diagnostic Steps:**

1. **Check gateway metrics:**
```bash
curl http://localhost:9090/metrics | grep gateway_request_duration
```

2. **Enable request tracing:**
```yaml
observability:
  tracing:
    enabled: true
    sampling:
      rate: 1.0  # 100% sampling for debugging
```

3. **Check upstream health:**
```bash
curl http://localhost:8081/admin/services
```

**Solutions:**

1. **Optimize connection pooling:**
```yaml
upstreams:
  your-service:
    connection_pool:
      max_connections: 100
      max_idle_connections: 20
      idle_timeout: 300
```

2. **Adjust timeouts:**
```yaml
server:
  request_timeout: 30
  keep_alive_timeout: 60

routes:
  - path: "/api/slow-endpoint"
    timeout: 60  # Increase for slow endpoints
```

3. **Enable caching:**
```yaml
caching:
  enabled: true
  policies:
    - path: "/api/cacheable"
      methods: ["GET"]
      ttl: 300
```

### Symptom: High memory usage

**Diagnostic Steps:**

1. **Check memory metrics:**
```bash
curl http://localhost:9090/metrics | grep process_resident_memory
```

2. **Profile memory usage:**
```bash
RUST_LOG=debug cargo run --features profiling
```

**Solutions:**

1. **Adjust connection limits:**
```yaml
server:
  max_connections: 5000  # Reduce if memory constrained
```

2. **Configure caching limits:**
```yaml
caching:
  storage:
    memory:
      max_size: 100000000  # 100MB
      max_entries: 10000
```

## Network and Connectivity

### Symptom: Connection refused errors

**Solutions:**

1. **Check network connectivity:**
```bash
telnet your-service 8080
nc -zv your-service 8080
```

2. **Verify DNS resolution:**
```bash
nslookup your-service
dig your-service
```

3. **Check firewall rules:**
```bash
iptables -L
ufw status
```

### Symptom: SSL/TLS errors

**Solutions:**

1. **Test TLS connection:**
```bash
openssl s_client -connect your-service:8443 -servername your-service
```

2. **Verify certificate chain:**
```bash
openssl verify -CAfile ca.pem your-cert.pem
```

3. **Check TLS configuration:**
```yaml
server:
  tls:
    enabled: true
    cert_file: "/etc/ssl/certs/gateway.crt"
    key_file: "/etc/ssl/private/gateway.key"
    min_version: "1.2"
```

## Configuration Problems

### Symptom: Routes not matching

**Solutions:**

1. **Test route matching:**
```bash
curl -v http://localhost:8080/your/path
```

2. **Check route order (routes are matched in order):**
```yaml
routes:
  # More specific routes first
  - path: "/api/users/{id}/posts"
    upstream: "user-posts-service"
  
  # Less specific routes later
  - path: "/api/users/{id}"
    upstream: "user-service"
```

3. **Enable route debugging:**
```bash
RUST_LOG=api_gateway::routing=debug cargo run
```

### Symptom: Middleware not working

**Solutions:**

1. **Check middleware order:**
```yaml
middleware:
  global:
    - "request_id"    # Should be first
    - "cors"
    - "auth"          # Before rate limiting
    - "rate_limit"
    - "circuit_breaker"
```

2. **Verify middleware configuration:**
```yaml
middleware:
  definitions:
    auth:
      type: "auth"
      providers: ["jwt"]  # Make sure providers are configured
```

## Logging and Debugging

### Enable Debug Logging

```bash
# Enable debug logging for all modules
RUST_LOG=debug cargo run

# Enable debug logging for specific modules
RUST_LOG=api_gateway::routing=debug,api_gateway::auth=debug cargo run

# Enable trace logging (very verbose)
RUST_LOG=trace cargo run
```

### Structured Logging

```yaml
observability:
  logging:
    level: "debug"
    format: "json"
    fields:
      service: "api-gateway"
      version: "0.1.0"
```

### Request Tracing

```yaml
observability:
  tracing:
    enabled: true
    jaeger:
      endpoint: "http://jaeger:14268/api/traces"
    sampling:
      rate: 1.0  # 100% for debugging
```

## Common Error Messages

### "Configuration validation failed"

**Cause:** Invalid configuration file syntax or missing required fields.

**Solution:**
```bash
# Validate YAML syntax
yamllint config/gateway.yaml

# Check for required fields
RUST_LOG=debug cargo run 2>&1 | grep -i "missing"
```

### "Service discovery failed"

**Cause:** Cannot connect to service discovery backend.

**Solution:**
```bash
# For Kubernetes
kubectl cluster-info

# For Consul
curl http://consul:8500/v1/status/leader

# Check network connectivity
ping consul.service.consul
```

### "Upstream service unavailable"

**Cause:** All upstream instances are unhealthy or unreachable.

**Solution:**
```bash
# Check service health
curl http://localhost:8081/admin/services

# Check upstream logs
kubectl logs -f deployment/your-service

# Test direct connection
curl http://your-service:8080/health
```

### "Rate limit exceeded"

**Cause:** Client has exceeded configured rate limits.

**Solution:**
```bash
# Check rate limit configuration
curl http://localhost:8081/admin/config | jq .rate_limiting

# Check current rate limit status
redis-cli GET "rate_limit:client_ip"

# Adjust rate limits if needed
```

### "Circuit breaker open"

**Cause:** Circuit breaker has opened due to upstream failures.

**Solution:**
```bash
# Check circuit breaker status
curl http://localhost:8081/admin/circuit-breakers

# Check upstream health
curl http://your-service:8080/health

# Reset circuit breaker (if needed)
curl -X POST http://localhost:8081/admin/circuit-breakers/your-service/reset
```

## Monitoring and Diagnostics

### Health Check Endpoints

```bash
# Gateway health
curl http://localhost:8080/health

# Detailed health
curl http://localhost:8080/health/detailed

# Readiness check
curl http://localhost:8080/ready
```

### Metrics Endpoints

```bash
# Prometheus metrics
curl http://localhost:9090/metrics

# JSON metrics
curl http://localhost:9090/metrics/json

# Admin metrics
curl http://localhost:8081/admin/metrics
```

### Admin Endpoints

```bash
# Service status
curl http://localhost:8081/admin/services

# Configuration
curl http://localhost:8081/admin/config

# Circuit breaker status
curl http://localhost:8081/admin/circuit-breakers

# Rate limit status
curl http://localhost:8081/admin/rate-limits
```

### Performance Profiling

```bash
# Enable profiling
cargo run --features profiling

# Generate flame graph
cargo flamegraph --bin api-gateway

# Memory profiling
valgrind --tool=massif cargo run
```

### Log Analysis

```bash
# Filter logs by level
journalctl -u api-gateway | grep ERROR

# Filter logs by component
journalctl -u api-gateway | grep "auth"

# Real-time log monitoring
tail -f /var/log/api-gateway.log | jq .
```

## Getting Help

If you're still experiencing issues:

1. **Check the documentation:** Review the configuration reference and API documentation
2. **Search existing issues:** Look through GitHub issues for similar problems
3. **Enable debug logging:** Collect detailed logs with `RUST_LOG=debug`
4. **Gather system information:** Include OS, Rust version, and configuration details
5. **Create a minimal reproduction:** Provide the smallest configuration that reproduces the issue

### Useful Commands for Bug Reports

```bash
# System information
uname -a
cargo --version
rustc --version

# Gateway version
cargo run -- --version

# Configuration validation
cargo run -- --validate-config

# Network diagnostics
ss -tulpn | grep -E ':(8080|8081|9090)'
```

This troubleshooting guide covers the most common issues. For specific problems not covered here, please refer to the GitHub issues or create a new issue with detailed information about your setup and the problem you're experiencing.