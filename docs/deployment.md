# Deployment Guide

This guide covers various deployment strategies for the Rust API Gateway, from local development to production Kubernetes clusters.

## Table of Contents

- [Local Development](#local-development)
- [Docker Deployment](#docker-deployment)
- [Kubernetes Deployment](#kubernetes-deployment)
- [Production Considerations](#production-considerations)
- [Monitoring and Observability](#monitoring-and-observability)
- [Security Configuration](#security-configuration)
- [Performance Tuning](#performance-tuning)
- [Backup and Recovery](#backup-and-recovery)

## Local Development

### Prerequisites

- Rust 1.75 or later
- Docker (optional)
- kubectl (for Kubernetes development)

### Building from Source

```bash
# Clone the repository
git clone https://github.com/your-org/rust-api-gateway.git
cd rust-api-gateway

# Build in debug mode for development
cargo build

# Build optimized release version
cargo build --release

# Run tests
cargo test

# Run with custom configuration
cargo run -- --config config/development.yaml
```

### Development Configuration

Create a `config/development.yaml` file:

```yaml
server:
  bind_address: "127.0.0.1"
  http_port: 8080
  admin_port: 8081
  request_timeout: 30

routes:
  - path: "/api/users"
    upstream: "user-service"
    methods: ["GET", "POST", "PUT", "DELETE"]

upstreams:
  user-service:
    discovery:
      type: "static"
      endpoints:
        - "http://localhost:3001"
    health_check:
      enabled: true
      path: "/health"

observability:
  logging:
    level: "debug"
    format: "text"
  metrics:
    enabled: true
    prometheus:
      enabled: true
      port: 9090
```

### Hot Reloading

The gateway supports hot configuration reloading:

```bash
# Start with file watching enabled
RUST_LOG=info cargo run

# In another terminal, modify the configuration
vim config/gateway.yaml

# The gateway will automatically reload the configuration
```

## Docker Deployment

### Building Docker Image

```dockerfile
# Multi-stage build for optimal image size
FROM rust:1.75-slim as builder

WORKDIR /app

# Copy dependency files first for better caching
COPY Cargo.toml Cargo.lock ./
COPY src ./src

# Build the application
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -r -s /bin/false -m gateway

# Copy binary and configuration
COPY --from=builder /app/target/release/api-gateway /usr/local/bin/
COPY config/ /etc/gateway/
COPY k8s/configmap.yaml /etc/gateway/

# Set ownership
RUN chown -R gateway:gateway /etc/gateway

USER gateway

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

EXPOSE 8080 8081 9090

ENTRYPOINT ["/usr/local/bin/api-gateway"]
CMD ["--config", "/etc/gateway/gateway.yaml"]
```

### Building and Running

```bash
# Build the Docker image
docker build -t rust-api-gateway:latest .

# Run with basic configuration
docker run -d \
  --name api-gateway \
  -p 8080:8080 \
  -p 8081:8081 \
  -p 9090:9090 \
  rust-api-gateway:latest

# Run with custom configuration
docker run -d \
  --name api-gateway \
  -p 8080:8080 \
  -p 8081:8081 \
  -p 9090:9090 \
  -v $(pwd)/config:/etc/gateway \
  rust-api-gateway:latest

# Check logs
docker logs -f api-gateway

# Check health
curl http://localhost:8080/health
```

### Docker Compose

Create a `docker-compose.yml` file:

```yaml
version: '3.8'

services:
  api-gateway:
    build: .
    ports:
      - "8080:8080"
      - "8081:8081"
      - "9090:9090"
    volumes:
      - ./config:/etc/gateway
      - ./logs:/var/log/gateway
    environment:
      - RUST_LOG=info
      - GATEWAY_REDIS_URL=redis://redis:6379
    depends_on:
      - redis
      - user-service
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    restart: unless-stopped

  user-service:
    image: your-org/user-service:latest
    ports:
      - "3001:3001"
    environment:
      - DATABASE_URL=postgresql://user:pass@postgres:5432/users
    depends_on:
      - postgres
    restart: unless-stopped

  postgres:
    image: postgres:15-alpine
    environment:
      - POSTGRES_DB=users
      - POSTGRES_USER=user
      - POSTGRES_PASSWORD=pass
    volumes:
      - postgres_data:/var/lib/postgresql/data
    restart: unless-stopped

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9091:9090"
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
    restart: unless-stopped

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    volumes:
      - grafana_data:/var/lib/grafana
      - ./monitoring/grafana/dashboards:/etc/grafana/provisioning/dashboards
      - ./monitoring/grafana/datasources:/etc/grafana/provisioning/datasources
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    restart: unless-stopped

volumes:
  redis_data:
  postgres_data:
  prometheus_data:
  grafana_data:
```

Start the stack:

```bash
docker-compose up -d
```

## Kubernetes Deployment

### Namespace

```yaml
# k8s/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: api-gateway
  labels:
    name: api-gateway
```

### ConfigMap

```yaml
# k8s/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: gateway-config
  namespace: api-gateway
data:
  gateway.yaml: |
    server:
      bind_address: "0.0.0.0"
      http_port: 8080
      admin_port: 8081
      max_connections: 10000
      request_timeout: 30

    routes:
      - path: "/api/users"
        upstream: "user-service"
        methods: ["GET", "POST", "PUT", "DELETE"]
        middleware: ["auth", "rate_limit"]

    upstreams:
      user-service:
        discovery:
          type: "kubernetes"
          namespace: "default"
          service_name: "user-service"
        load_balancer:
          algorithm: "round_robin"
        health_check:
          enabled: true
          path: "/health"
          interval: 30

    authentication:
      jwt:
        secret: "${JWT_SECRET}"
        algorithms: ["HS256"]

    rate_limiting:
      enabled: true
      storage:
        type: "redis"
        redis:
          url: "${REDIS_URL}"

    observability:
      metrics:
        enabled: true
        prometheus:
          enabled: true
          port: 9090
      logging:
        level: "info"
        format: "json"
      tracing:
        enabled: true
        jaeger:
          endpoint: "${JAEGER_ENDPOINT}"
```

### Secret

```yaml
# k8s/secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: gateway-secrets
  namespace: api-gateway
type: Opaque
data:
  jwt-secret: <base64-encoded-jwt-secret>
  redis-url: <base64-encoded-redis-url>
  jaeger-endpoint: <base64-encoded-jaeger-endpoint>
```

### Service Account and RBAC

```yaml
# k8s/rbac.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: gateway-service-account
  namespace: api-gateway

---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: gateway-cluster-role
rules:
- apiGroups: [""]
  resources: ["services", "endpoints"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["get", "list", "watch"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: gateway-cluster-role-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: gateway-cluster-role
subjects:
- kind: ServiceAccount
  name: gateway-service-account
  namespace: api-gateway
```

### Deployment

```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-gateway
  namespace: api-gateway
  labels:
    app: api-gateway
spec:
  replicas: 3
  selector:
    matchLabels:
      app: api-gateway
  template:
    metadata:
      labels:
        app: api-gateway
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "9090"
        prometheus.io/path: "/metrics"
    spec:
      serviceAccountName: gateway-service-account
      containers:
      - name: gateway
        image: rust-api-gateway:latest
        ports:
        - containerPort: 8080
          name: http
          protocol: TCP
        - containerPort: 8081
          name: admin
          protocol: TCP
        - containerPort: 9090
          name: metrics
          protocol: TCP
        env:
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: gateway-secrets
              key: jwt-secret
        - name: REDIS_URL
          valueFrom:
            secretKeyRef:
              name: gateway-secrets
              key: redis-url
        - name: JAEGER_ENDPOINT
          valueFrom:
            secretKeyRef:
              name: gateway-secrets
              key: jaeger-endpoint
        - name: RUST_LOG
          value: "info"
        volumeMounts:
        - name: config
          mountPath: /etc/gateway
          readOnly: true
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
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
        securityContext:
          allowPrivilegeEscalation: false
          runAsNonRoot: true
          runAsUser: 1000
          capabilities:
            drop:
            - ALL
      volumes:
      - name: config
        configMap:
          name: gateway-config
      securityContext:
        fsGroup: 1000
      terminationGracePeriodSeconds: 30
```

### Service

```yaml
# k8s/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: api-gateway
  namespace: api-gateway
  labels:
    app: api-gateway
spec:
  type: ClusterIP
  ports:
  - port: 8080
    targetPort: 8080
    protocol: TCP
    name: http
  - port: 8081
    targetPort: 8081
    protocol: TCP
    name: admin
  - port: 9090
    targetPort: 9090
    protocol: TCP
    name: metrics
  selector:
    app: api-gateway

---
apiVersion: v1
kind: Service
metadata:
  name: api-gateway-admin
  namespace: api-gateway
  labels:
    app: api-gateway
    component: admin
spec:
  type: ClusterIP
  ports:
  - port: 8081
    targetPort: 8081
    protocol: TCP
    name: admin
  selector:
    app: api-gateway
```

### Ingress

```yaml
# k8s/ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: api-gateway-ingress
  namespace: api-gateway
  annotations:
    kubernetes.io/ingress.class: "nginx"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/proxy-body-size: "10m"
    nginx.ingress.kubernetes.io/proxy-read-timeout: "300"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "300"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  tls:
  - hosts:
    - api.example.com
    secretName: api-gateway-tls
  rules:
  - host: api.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: api-gateway
            port:
              number: 8080

---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: api-gateway-admin-ingress
  namespace: api-gateway
  annotations:
    kubernetes.io/ingress.class: "nginx"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/auth-type: basic
    nginx.ingress.kubernetes.io/auth-secret: admin-auth
    nginx.ingress.kubernetes.io/auth-realm: "Admin Access Required"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  tls:
  - hosts:
    - admin.example.com
    secretName: api-gateway-admin-tls
  rules:
  - host: admin.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: api-gateway-admin
            port:
              number: 8081
```

### Horizontal Pod Autoscaler

```yaml
# k8s/hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: api-gateway-hpa
  namespace: api-gateway
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
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 10
        periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
      - type: Percent
        value: 50
        periodSeconds: 60
```

### Pod Disruption Budget

```yaml
# k8s/pdb.yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: api-gateway-pdb
  namespace: api-gateway
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app: api-gateway
```

### Network Policy

```yaml
# k8s/networkpolicy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: api-gateway-network-policy
  namespace: api-gateway
spec:
  podSelector:
    matchLabels:
      app: api-gateway
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    ports:
    - protocol: TCP
      port: 8080
  - from:
    - namespaceSelector:
        matchLabels:
          name: monitoring
    ports:
    - protocol: TCP
      port: 9090
  egress:
  - to: []
    ports:
    - protocol: TCP
      port: 53
    - protocol: UDP
      port: 53
  - to:
    - namespaceSelector: {}
    ports:
    - protocol: TCP
      port: 8080
  - to: []
    ports:
    - protocol: TCP
      port: 6379  # Redis
    - protocol: TCP
      port: 443   # HTTPS
```

### Deployment Commands

```bash
# Apply all Kubernetes manifests
kubectl apply -f k8s/

# Check deployment status
kubectl get pods -n api-gateway
kubectl get services -n api-gateway
kubectl get ingress -n api-gateway

# Check logs
kubectl logs -f deployment/api-gateway -n api-gateway

# Scale deployment
kubectl scale deployment api-gateway --replicas=5 -n api-gateway

# Rolling update
kubectl set image deployment/api-gateway gateway=rust-api-gateway:v1.1.0 -n api-gateway

# Check rollout status
kubectl rollout status deployment/api-gateway -n api-gateway

# Rollback if needed
kubectl rollout undo deployment/api-gateway -n api-gateway
```

## Production Considerations

### Resource Planning

```yaml
# Production resource configuration
resources:
  requests:
    memory: "512Mi"
    cpu: "500m"
  limits:
    memory: "1Gi"
    cpu: "1000m"
```

### High Availability

1. **Multiple Replicas**: Run at least 3 replicas across different nodes
2. **Pod Anti-Affinity**: Spread pods across availability zones
3. **Health Checks**: Configure proper liveness and readiness probes
4. **Graceful Shutdown**: Handle SIGTERM signals properly

```yaml
# Pod anti-affinity configuration
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
        topologyKey: kubernetes.io/hostname
```

### Load Balancing

```yaml
# Service configuration for load balancing
spec:
  type: LoadBalancer
  sessionAffinity: None
  externalTrafficPolicy: Local
```

### SSL/TLS Configuration

```yaml
# TLS configuration in gateway config
server:
  tls:
    enabled: true
    cert_file: "/etc/ssl/certs/gateway.crt"
    key_file: "/etc/ssl/private/gateway.key"
    min_version: "1.2"
    cipher_suites:
      - "TLS_AES_256_GCM_SHA384"
      - "TLS_CHACHA20_POLY1305_SHA256"
```

## Monitoring and Observability

### Prometheus Configuration

```yaml
# monitoring/prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'api-gateway'
    static_configs:
      - targets: ['api-gateway:9090']
    metrics_path: /metrics
    scrape_interval: 15s

  - job_name: 'kubernetes-pods'
    kubernetes_sd_configs:
      - role: pod
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
        action: keep
        regex: true
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_path]
        action: replace
        target_label: __metrics_path__
        regex: (.+)
```

### Grafana Dashboard

Create dashboards for:
- Request rate and latency
- Error rates by service
- Circuit breaker status
- Resource utilization
- Service topology

### Alerting Rules

```yaml
# monitoring/alerts.yml
groups:
  - name: api-gateway
    rules:
      - alert: HighErrorRate
        expr: rate(gateway_requests_total{status=~"5.."}[5m]) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High error rate detected"
          description: "Error rate is {{ $value }} errors per second"

      - alert: HighLatency
        expr: histogram_quantile(0.95, rate(gateway_request_duration_seconds_bucket[5m])) > 1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High latency detected"
          description: "95th percentile latency is {{ $value }} seconds"
```

## Security Configuration

### Network Security

1. **Network Policies**: Restrict pod-to-pod communication
2. **Service Mesh**: Use Istio or Linkerd for mTLS
3. **Ingress Security**: Configure proper ingress rules

### Pod Security

```yaml
# Security context
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  fsGroup: 1000
  capabilities:
    drop:
    - ALL
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
```

### Secrets Management

Use external secret management:

```yaml
# External secrets operator
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: vault-backend
spec:
  provider:
    vault:
      server: "https://vault.example.com"
      path: "secret"
      version: "v2"
      auth:
        kubernetes:
          mountPath: "kubernetes"
          role: "api-gateway"
```

## Performance Tuning

### JVM-like Tuning for Rust

```bash
# Environment variables for performance
RUST_LOG=info
TOKIO_WORKER_THREADS=8
GATEWAY_MAX_CONNECTIONS=10000
GATEWAY_CONNECTION_POOL_SIZE=100
```

### Kernel Parameters

```bash
# /etc/sysctl.conf
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 60
net.ipv4.tcp_keepalive_probes = 3
```

### Resource Limits

```yaml
# Optimized resource limits
resources:
  requests:
    memory: "1Gi"
    cpu: "1000m"
  limits:
    memory: "2Gi"
    cpu: "2000m"
```

## Backup and Recovery

### Configuration Backup

```bash
#!/bin/bash
# backup-config.sh

DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backups/gateway-config"

# Create backup directory
mkdir -p $BACKUP_DIR

# Backup Kubernetes resources
kubectl get configmap gateway-config -n api-gateway -o yaml > $BACKUP_DIR/configmap-$DATE.yaml
kubectl get secret gateway-secrets -n api-gateway -o yaml > $BACKUP_DIR/secrets-$DATE.yaml

# Backup configuration files
tar -czf $BACKUP_DIR/config-$DATE.tar.gz config/

echo "Backup completed: $BACKUP_DIR"
```

### Disaster Recovery

1. **Multi-Region Deployment**: Deploy across multiple regions
2. **Database Replication**: Replicate configuration data
3. **Automated Failover**: Use DNS-based failover
4. **Recovery Testing**: Regularly test recovery procedures

This deployment guide provides comprehensive coverage of deploying the Rust API Gateway in various environments. Choose the deployment strategy that best fits your infrastructure and requirements.