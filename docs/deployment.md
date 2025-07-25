# API Gateway Deployment Guide

This guide provides comprehensive instructions for deploying the Rust API Gateway in production and staging environments.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Configuration Management](#configuration-management)
3. [Container Deployment](#container-deployment)
4. [Kubernetes Deployment](#kubernetes-deployment)
5. [Production Best Practices](#production-best-practices)
6. [Monitoring and Observability](#monitoring-and-observability)
7. [Disaster Recovery](#disaster-recovery)
8. [Troubleshooting](#troubleshooting)

## Prerequisites

### System Requirements

**Minimum Requirements:**
- CPU: 2 cores
- Memory: 2GB RAM
- Storage: 10GB available space
- Network: 1Gbps network interface

**Recommended for Production:**
- CPU: 4+ cores
- Memory: 8GB+ RAM
- Storage: 50GB+ SSD
- Network: 10Gbps network interface

### Dependencies

- **Kubernetes**: v1.24+ (for Kubernetes deployment)
- **Docker**: v20.10+ (for container deployment)
- **Redis**: v6.0+ (for distributed caching and rate limiting)
- **PostgreSQL**: v13+ (for persistent storage, if needed)
- **Prometheus**: v2.30+ (for metrics collection)
- **Jaeger**: v1.35+ (for distributed tracing)

## Configuration Management

### Environment-Specific Configurations

The gateway supports multiple configuration files for different environments:

```bash
config/
├── gateway.yaml          # Development configuration
├── staging.yaml          # Staging configuration
├── production.yaml       # Production configuration
└── microservices-example.yaml  # Example microservices setup
```

### Configuration Loading Priority

1. Command line arguments: `--config /path/to/config.yaml`
2. Environment variable: `GATEWAY_CONFIG_PATH`
3. Default: `config/gateway.yaml`

### Environment Variables

Critical environment variables for production:

```bash
# Configuration
export GATEWAY_CONFIG_PATH="/etc/gateway/production.yaml"

# Security
export JWT_SECRET="your-production-jwt-secret"
export OAUTH2_CLIENT_ID="your-oauth2-client-id"
export OAUTH2_CLIENT_SECRET="your-oauth2-client-secret"
export TRACING_TOKEN="your-tracing-auth-token"

# Database connections
export REDIS_URL="redis://redis-cluster:6379"
export DATABASE_URL="postgresql://user:pass@db:5432/gateway"

# TLS certificates
export TLS_CERT_PATH="/etc/ssl/certs/gateway.crt"
export TLS_KEY_PATH="/etc/ssl/private/gateway.key"
export TLS_CA_PATH="/etc/ssl/certs/ca.crt"
```

## Container Deployment

### Building the Container

```bash
# Build the production image
docker build -t api-gateway:latest .

# Build with specific version tag
docker build -t api-gateway:v1.0.0 .

# Multi-architecture build
docker buildx build --platform linux/amd64,linux/arm64 -t api-gateway:v1.0.0 .
```

### Running with Docker

```bash
# Basic run
docker run -d \
  --name api-gateway \
  -p 8080:8080 \
  -p 8443:8443 \
  -p 9090:9090 \
  -v $(pwd)/config:/etc/gateway/config \
  api-gateway:latest

# Production run with environment variables
docker run -d \
  --name api-gateway \
  --restart unless-stopped \
  -p 8080:8080 \
  -p 8443:8443 \
  -p 9090:9090 \
  -e GATEWAY_CONFIG_PATH="/etc/gateway/config/production.yaml" \
  -e JWT_SECRET="${JWT_SECRET}" \
  -e REDIS_URL="${REDIS_URL}" \
  -v $(pwd)/config:/etc/gateway/config:ro \
  -v $(pwd)/certs:/etc/ssl/certs:ro \
  -v $(pwd)/logs:/var/log/gateway \
  --memory=2g \
  --cpus=2 \
  api-gateway:latest
```

### Docker Compose

```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  api-gateway:
    image: api-gateway:latest
    ports:
      - "8080:8080"
      - "8443:8443"
      - "9090:9090"
    environment:
      - GATEWAY_CONFIG_PATH=/etc/gateway/config/production.yaml
      - JWT_SECRET=${JWT_SECRET}
      - REDIS_URL=redis://redis:6379
    volumes:
      - ./config:/etc/gateway/config:ro
      - ./certs:/etc/ssl/certs:ro
      - ./logs:/var/log/gateway
    depends_on:
      - redis
      - prometheus
    restart: unless-stopped
    deploy:
      resources:
        limits:
          memory: 2G
          cpus: '2'
        reservations:
          memory: 1G
          cpus: '1'

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    restart: unless-stopped

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9091:9090"
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus_data:/prometheus
    restart: unless-stopped

volumes:
  redis_data:
  prometheus_data:
```

## Kubernetes Deployment

### Namespace Setup

```bash
# Create namespace
kubectl create namespace api-gateway-prod

# Set as default namespace
kubectl config set-context --current --namespace=api-gateway-prod
```

### ConfigMap and Secrets

```bash
# Create ConfigMap from production config
kubectl create configmap gateway-config \
  --from-file=config/production.yaml \
  --namespace=api-gateway-prod

# Create secrets
kubectl create secret generic gateway-secrets \
  --from-literal=jwt-secret="${JWT_SECRET}" \
  --from-literal=oauth2-client-id="${OAUTH2_CLIENT_ID}" \
  --from-literal=oauth2-client-secret="${OAUTH2_CLIENT_SECRET}" \
  --namespace=api-gateway-prod

# Create TLS secret
kubectl create secret tls gateway-tls \
  --cert=certs/gateway.crt \
  --key=certs/gateway.key \
  --namespace=api-gateway-prod
```

### Deployment

```bash
# Apply all Kubernetes manifests
kubectl apply -f k8s/ --namespace=api-gateway-prod

# Or apply individually
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/secret.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/ingress.yaml
kubectl apply -f k8s/hpa.yaml
kubectl apply -f k8s/pdb.yaml
```

### Verification

```bash
# Check deployment status
kubectl get deployments -n api-gateway-prod
kubectl get pods -n api-gateway-prod
kubectl get services -n api-gateway-prod

# Check logs
kubectl logs -f deployment/api-gateway -n api-gateway-prod

# Check health
kubectl port-forward service/api-gateway 8080:8080 -n api-gateway-prod
curl http://localhost:8080/health
```

## Production Best Practices

### Security

1. **TLS Configuration**
   ```yaml
   tls:
     enabled: true
     cert_file: "/etc/ssl/certs/gateway.crt"
     key_file: "/etc/ssl/private/gateway.key"
     min_version: "1.2"
     cipher_suites:
       - "TLS_AES_256_GCM_SHA384"
       - "TLS_CHACHA20_POLY1305_SHA256"
   ```

2. **Network Security**
   - Use network policies to restrict traffic
   - Enable pod security policies
   - Use service mesh for mTLS

3. **Secrets Management**
   - Use Kubernetes secrets or external secret managers
   - Rotate secrets regularly
   - Never store secrets in configuration files

### Performance Optimization

1. **Resource Limits**
   ```yaml
   resources:
     requests:
       memory: "1Gi"
       cpu: "500m"
     limits:
       memory: "2Gi"
       cpu: "1000m"
   ```

2. **Horizontal Pod Autoscaling**
   ```yaml
   apiVersion: autoscaling/v2
   kind: HorizontalPodAutoscaler
   metadata:
     name: api-gateway-hpa
   spec:
     scaleTargetRef:
       apiVersion: apps/v1
       kind: Deployment
       name: api-gateway
     minReplicas: 3
     maxReplicas: 20
     metrics:
     - type: Resource
       resource:
         name: cpu
         target:
           type: Utilization
           averageUtilization: 70
   ```

3. **Pod Disruption Budget**
   ```yaml
   apiVersion: policy/v1
   kind: PodDisruptionBudget
   metadata:
     name: api-gateway-pdb
   spec:
     minAvailable: 2
     selector:
       matchLabels:
         app: api-gateway
   ```

### High Availability

1. **Multi-Zone Deployment**
   ```yaml
   affinity:
     podAntiAffinity:
       preferredDuringSchedulingIgnoredDuringExecution:
       - weight: 100
         podAffinityTerm:
           labelSelector:
             matchExpressions:
             - key: app
               operator: In
               values:
               - api-gateway
           topologyKey: kubernetes.io/zone
   ```

2. **Health Checks**
   ```yaml
   livenessProbe:
     httpGet:
       path: /health
       port: 8080
     initialDelaySeconds: 30
     periodSeconds: 10
     timeoutSeconds: 5
     failureThreshold: 3

   readinessProbe:
     httpGet:
       path: /ready
       port: 8080
     initialDelaySeconds: 5
     periodSeconds: 5
     timeoutSeconds: 3
     failureThreshold: 3
   ```

## Monitoring and Observability

### Metrics Collection

1. **Prometheus Configuration**
   ```yaml
   # prometheus.yml
   global:
     scrape_interval: 15s

   scrape_configs:
   - job_name: 'api-gateway'
     static_configs:
     - targets: ['api-gateway:9090']
     metrics_path: /metrics
     scrape_interval: 15s
   ```

2. **Key Metrics to Monitor**
   - Request rate (RPS)
   - Response latency (P50, P95, P99)
   - Error rate (4xx, 5xx)
   - Upstream service health
   - Circuit breaker state
   - Rate limiting hits
   - Memory and CPU usage

### Alerting Rules

```yaml
# alerts.yml
groups:
- name: api-gateway
  rules:
  - alert: HighErrorRate
    expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.1
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: "High error rate detected"

  - alert: HighLatency
    expr: histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m])) > 1
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High latency detected"

  - alert: ServiceDown
    expr: up{job="api-gateway"} == 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "API Gateway is down"
```

### Log Management

1. **Structured Logging**
   ```yaml
   observability:
     logging:
       level: "info"
       format: "json"
       structured_logging: true
       correlation_id_header: "X-Correlation-ID"
   ```

2. **Log Aggregation**
   - Use Fluentd or Fluent Bit for log collection
   - Send logs to Elasticsearch or similar
   - Set up log retention policies

## Disaster Recovery

### Backup Procedures

1. **Configuration Backup**
   ```bash
   #!/bin/bash
   # backup-config.sh
   
   DATE=$(date +%Y%m%d_%H%M%S)
   BACKUP_DIR="/backups/gateway-config-${DATE}"
   
   mkdir -p "${BACKUP_DIR}"
   
   # Backup Kubernetes resources
   kubectl get configmap gateway-config -o yaml > "${BACKUP_DIR}/configmap.yaml"
   kubectl get secret gateway-secrets -o yaml > "${BACKUP_DIR}/secrets.yaml"
   kubectl get deployment api-gateway -o yaml > "${BACKUP_DIR}/deployment.yaml"
   
   # Backup configuration files
   cp -r config/ "${BACKUP_DIR}/"
   
   # Create archive
   tar -czf "/backups/gateway-backup-${DATE}.tar.gz" -C /backups "gateway-config-${DATE}"
   
   echo "Backup completed: gateway-backup-${DATE}.tar.gz"
   ```

2. **Database Backup** (if using persistent storage)
   ```bash
   # Backup Redis data
   kubectl exec redis-0 -- redis-cli BGSAVE
   kubectl cp redis-0:/data/dump.rdb ./backups/redis-backup-$(date +%Y%m%d).rdb
   ```

### Recovery Procedures

1. **Configuration Recovery**
   ```bash
   #!/bin/bash
   # restore-config.sh
   
   BACKUP_FILE="$1"
   
   if [ -z "$BACKUP_FILE" ]; then
     echo "Usage: $0 <backup-file.tar.gz>"
     exit 1
   fi
   
   # Extract backup
   tar -xzf "$BACKUP_FILE" -C /tmp/
   
   # Restore Kubernetes resources
   kubectl apply -f /tmp/gateway-config-*/configmap.yaml
   kubectl apply -f /tmp/gateway-config-*/secrets.yaml
   kubectl apply -f /tmp/gateway-config-*/deployment.yaml
   
   echo "Configuration restored from $BACKUP_FILE"
   ```

2. **Rolling Back Deployment**
   ```bash
   # Rollback to previous version
   kubectl rollout undo deployment/api-gateway
   
   # Rollback to specific revision
   kubectl rollout undo deployment/api-gateway --to-revision=2
   
   # Check rollout status
   kubectl rollout status deployment/api-gateway
   ```

## Troubleshooting

### Common Issues

1. **Gateway Won't Start**
   ```bash
   # Check logs
   kubectl logs deployment/api-gateway
   
   # Check configuration
   kubectl describe configmap gateway-config
   
   # Validate configuration
   kubectl exec deployment/api-gateway -- /usr/local/bin/api-gateway --validate-config
   ```

2. **High Memory Usage**
   ```bash
   # Check memory metrics
   kubectl top pods
   
   # Check for memory leaks
   kubectl exec deployment/api-gateway -- ps aux
   
   # Restart pod if necessary
   kubectl delete pod -l app=api-gateway
   ```

3. **Service Discovery Issues**
   ```bash
   # Check service discovery logs
   kubectl logs deployment/api-gateway | grep "service_discovery"
   
   # Verify RBAC permissions
   kubectl auth can-i get services --as=system:serviceaccount:api-gateway-prod:api-gateway
   
   # Check service endpoints
   kubectl get endpoints
   ```

### Performance Troubleshooting

1. **High Latency**
   - Check upstream service health
   - Review circuit breaker status
   - Analyze request patterns
   - Check resource utilization

2. **High Error Rate**
   - Review error logs
   - Check upstream connectivity
   - Verify authentication configuration
   - Analyze rate limiting settings

### Debug Mode

Enable debug mode for troubleshooting:

```yaml
observability:
  logging:
    level: "debug"
    
middleware:
  pipeline:
    settings:
      log_execution: true
```

### Health Check Endpoints

- `/health` - Basic health check
- `/ready` - Readiness check
- `/metrics` - Prometheus metrics
- `/debug/pprof` - Performance profiling (debug builds only)

## Maintenance

### Regular Maintenance Tasks

1. **Weekly**
   - Review metrics and alerts
   - Check log aggregation
   - Verify backup integrity

2. **Monthly**
   - Update dependencies
   - Review security patches
   - Performance optimization review

3. **Quarterly**
   - Disaster recovery testing
   - Security audit
   - Capacity planning review

### Upgrade Procedures

1. **Rolling Update**
   ```bash
   # Update image
   kubectl set image deployment/api-gateway api-gateway=api-gateway:v1.1.0
   
   # Monitor rollout
   kubectl rollout status deployment/api-gateway
   ```

2. **Blue-Green Deployment**
   ```bash
   # Deploy new version alongside current
   kubectl apply -f k8s/deployment-v2.yaml
   
   # Switch traffic
   kubectl patch service api-gateway -p '{"spec":{"selector":{"version":"v2"}}}'
   
   # Remove old version
   kubectl delete deployment api-gateway-v1
   ```

This deployment guide provides comprehensive instructions for deploying and maintaining the API Gateway in production environments. Follow these best practices to ensure reliable, secure, and performant operation.