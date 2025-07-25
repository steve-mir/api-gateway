# Configuration Reference

This document provides a comprehensive reference for all configuration options available in the Rust API Gateway.

## Table of Contents

- [Configuration File Format](#configuration-file-format)
- [Server Configuration](#server-configuration)
- [Routes Configuration](#routes-configuration)
- [Upstream Services](#upstream-services)
- [Service Discovery](#service-discovery)
- [Load Balancing](#load-balancing)
- [Authentication](#authentication)
- [Rate Limiting](#rate-limiting)
- [Circuit Breaker](#circuit-breaker)
- [Middleware](#middleware)
- [Caching](#caching)
- [Observability](#observability)
- [Admin Configuration](#admin-configuration)
- [Environment Variables](#environment-variables)
- [Configuration Examples](#configuration-examples)

## Configuration File Format

The gateway uses YAML configuration files. The default configuration file is `config/gateway.yaml`.

```yaml
# Basic structure
server:
  # Server settings
routes:
  # Route definitions
upstreams:
  # Upstream service definitions
middleware:
  # Middleware configuration
observability:
  # Monitoring and logging settings
```

## Server Configuration

### Basic Server Settings

```yaml
server:
  # Bind address for the main gateway server
  bind_address: "0.0.0.0"
  
  # HTTP port for gateway traffic
  http_port: 8080
  
  # HTTPS port (requires TLS configuration)
  https_port: 8443
  
  # Admin interface port
  admin_port: 8081
  
  # Maximum number of concurrent connections
  max_connections: 10000
  
  # Request timeout in seconds
  request_timeout: 30
  
  # Keep-alive timeout in seconds
  keep_alive_timeout: 60
  
  # Maximum request body size in bytes
  max_request_size: 10485760  # 10MB
  
  # Enable HTTP/2 support
  http2_enabled: true
  
  # Enable compression
  compression:
    enabled: true
    algorithms: ["gzip", "brotli"]
    min_size: 1024
```

### TLS Configuration

```yaml
server:
  tls:
    # Enable TLS
    enabled: true
    
    # Certificate file path
    cert_file: "/etc/ssl/certs/gateway.crt"
    
    # Private key file path
    key_file: "/etc/ssl/private/gateway.key"
    
    # CA certificate file (for client certificate validation)
    ca_file: "/etc/ssl/certs/ca.crt"
    
    # Require client certificates
    client_cert_required: false
    
    # TLS version (1.2 or 1.3)
    min_version: "1.2"
    
    # Cipher suites
    cipher_suites:
      - "TLS_AES_256_GCM_SHA384"
      - "TLS_CHACHA20_POLY1305_SHA256"
```

## Routes Configuration

### Basic Route Definition

```yaml
routes:
  - path: "/api/users"
    methods: ["GET", "POST"]
    upstream: "user-service"
    
  - path: "/api/users/{id}"
    methods: ["GET", "PUT", "DELETE"]
    upstream: "user-service"
    
  - path: "/api/posts"
    methods: ["GET", "POST", "PUT", "DELETE"]
    upstream: "post-service"
```

### Advanced Route Configuration

```yaml
routes:
  - path: "/api/users"
    methods: ["GET", "POST"]
    upstream: "user-service"
    
    # Route-specific timeout
    timeout: 15
    
    # Route-specific middleware
    middleware:
      - "auth"
      - "rate_limit"
      - "cors"
    
    # Request transformation
    request_transform:
      headers:
        add:
          X-Service: "user-service"
        remove:
          - "X-Internal-Token"
      
      # Path rewriting
      path_rewrite:
        from: "/api/users"
        to: "/v1/users"
    
    # Response transformation
    response_transform:
      headers:
        add:
          X-Gateway: "rust-api-gateway"
    
    # Route-specific rate limiting
    rate_limit:
      requests_per_minute: 100
      burst: 20
    
    # Circuit breaker settings
    circuit_breaker:
      failure_threshold: 5
      timeout: 30
      success_threshold: 3
```

### Route Matching

```yaml
routes:
  # Exact path matching
  - path: "/api/health"
    exact: true
    
  # Path parameters
  - path: "/api/users/{id}"
    
  # Wildcard matching
  - path: "/api/files/*"
    
  # Regular expression matching
  - path: "/api/v{version:\\d+}/users"
    
  # Host-based routing
  - path: "/api/users"
    host: "api.example.com"
    
  # Header-based routing
  - path: "/api/users"
    headers:
      X-API-Version: "v2"
```

## Upstream Services

### Basic Upstream Configuration

```yaml
upstreams:
  user-service:
    # Service discovery configuration
    discovery:
      type: "kubernetes"
      namespace: "default"
      service_name: "user-service"
    
    # Load balancing algorithm
    load_balancer:
      algorithm: "round_robin"
    
    # Health check configuration
    health_check:
      enabled: true
      path: "/health"
      interval: 30
      timeout: 5
      healthy_threshold: 2
      unhealthy_threshold: 3
```

### Advanced Upstream Configuration

```yaml
upstreams:
  user-service:
    discovery:
      type: "kubernetes"
      namespace: "default"
      service_name: "user-service"
      port: 8080
    
    load_balancer:
      algorithm: "weighted"
      weights:
        "10.0.1.1:8080": 100
        "10.0.1.2:8080": 200
    
    # Connection pooling
    connection_pool:
      max_connections: 100
      max_idle_connections: 10
      idle_timeout: 300
    
    # Retry policy
    retry:
      max_attempts: 3
      backoff: "exponential"
      base_delay: 100  # milliseconds
      max_delay: 5000  # milliseconds
    
    # Circuit breaker
    circuit_breaker:
      enabled: true
      failure_threshold: 10
      timeout: 60
      success_threshold: 5
    
    # Health check
    health_check:
      enabled: true
      path: "/health"
      method: "GET"
      interval: 30
      timeout: 5
      healthy_threshold: 2
      unhealthy_threshold: 3
      headers:
        User-Agent: "gateway-health-check"
```

## Service Discovery

### Kubernetes Service Discovery

```yaml
service_discovery:
  kubernetes:
    # Kubernetes API server URL (optional, uses in-cluster config by default)
    api_server: "https://kubernetes.default.svc"
    
    # Namespace to watch (empty for all namespaces)
    namespace: "default"
    
    # Service account token path
    token_path: "/var/run/secrets/kubernetes.io/serviceaccount/token"
    
    # CA certificate path
    ca_cert_path: "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
    
    # Label selector for services
    label_selector: "app.kubernetes.io/managed-by=gateway"
    
    # Annotation prefix for gateway configuration
    annotation_prefix: "gateway.io"
```

### Consul Service Discovery

```yaml
service_discovery:
  consul:
    # Consul agent address
    address: "http://consul.service.consul:8500"
    
    # Datacenter
    datacenter: "dc1"
    
    # Service prefix
    service_prefix: "gateway"
    
    # Health check interval
    health_check_interval: 30
    
    # Tags to filter services
    tags:
      - "gateway"
      - "api"
```

### NATS Service Discovery

```yaml
service_discovery:
  nats:
    # NATS server URLs
    servers:
      - "nats://nats1.example.com:4222"
      - "nats://nats2.example.com:4222"
    
    # Subject for service announcements
    subject: "gateway.services"
    
    # Credentials
    username: "gateway"
    password: "secret"
    
    # TLS configuration
    tls:
      enabled: true
      cert_file: "/etc/ssl/nats-client.crt"
      key_file: "/etc/ssl/nats-client.key"
```

## Load Balancing

### Load Balancing Algorithms

```yaml
load_balancing:
  # Round-robin (default)
  round_robin:
    # No additional configuration needed
  
  # Least connections
  least_connections:
    # Connection tracking timeout
    connection_timeout: 300
  
  # Weighted round-robin
  weighted:
    # Weights are defined per upstream
  
  # Consistent hashing
  consistent_hash:
    # Hash key source
    hash_key: "source_ip"  # or "header:X-User-ID"
    
    # Number of virtual nodes
    virtual_nodes: 150
  
  # Random
  random:
    # No additional configuration needed
```

## Authentication

### JWT Authentication

```yaml
authentication:
  jwt:
    # JWT secret key (for HMAC algorithms)
    secret: "your-secret-key"
    
    # JWT public key (for RSA/ECDSA algorithms)
    public_key_file: "/etc/ssl/jwt-public.pem"
    
    # Allowed algorithms
    algorithms: ["HS256", "RS256"]
    
    # Token location
    token_location: "header"  # or "query" or "cookie"
    
    # Header name (if token_location is "header")
    header_name: "Authorization"
    
    # Token prefix (e.g., "Bearer ")
    token_prefix: "Bearer "
    
    # Issuer validation
    issuer: "https://auth.example.com"
    
    # Audience validation
    audience: "api-gateway"
    
    # Clock skew tolerance (seconds)
    clock_skew: 60
```

### API Key Authentication

```yaml
authentication:
  api_key:
    # Header name for API key
    header_name: "X-API-Key"
    
    # API key storage
    storage:
      type: "redis"
      redis:
        url: "redis://localhost:6379"
        key_prefix: "api_keys:"
    
    # Rate limiting per API key
    rate_limit:
      requests_per_minute: 1000
      burst: 100
```

### OAuth2 Authentication

```yaml
authentication:
  oauth2:
    # Authorization server URL
    auth_server: "https://auth.example.com"
    
    # Client ID
    client_id: "gateway-client"
    
    # Client secret
    client_secret: "client-secret"
    
    # Scopes
    scopes: ["read", "write"]
    
    # Token introspection endpoint
    introspection_endpoint: "https://auth.example.com/oauth/introspect"
    
    # JWKS endpoint for token validation
    jwks_endpoint: "https://auth.example.com/.well-known/jwks.json"
```

## Rate Limiting

### Global Rate Limiting

```yaml
rate_limiting:
  # Enable rate limiting
  enabled: true
  
  # Default limits
  default:
    requests_per_minute: 1000
    burst: 100
  
  # Storage backend
  storage:
    type: "redis"
    redis:
      url: "redis://localhost:6379"
      key_prefix: "rate_limit:"
  
  # Rate limiting algorithm
  algorithm: "token_bucket"  # or "sliding_window"
  
  # Key generation strategy
  key_strategy: "source_ip"  # or "user_id" or "api_key"
```

### Per-Route Rate Limiting

```yaml
routes:
  - path: "/api/users"
    rate_limit:
      requests_per_minute: 100
      burst: 20
      
  - path: "/api/admin"
    rate_limit:
      requests_per_minute: 10
      burst: 5
```

## Circuit Breaker

### Global Circuit Breaker

```yaml
circuit_breaker:
  # Enable circuit breaker
  enabled: true
  
  # Default settings
  default:
    failure_threshold: 10
    timeout: 60
    success_threshold: 5
    
  # Failure detection
  failure_detection:
    # HTTP status codes considered as failures
    failure_status_codes: [500, 502, 503, 504]
    
    # Timeout considered as failure
    timeout_as_failure: true
```

## Middleware

### Middleware Pipeline

```yaml
middleware:
  # Global middleware (applied to all routes)
  global:
    - "request_id"
    - "cors"
    - "compression"
    - "rate_limit"
    - "auth"
    - "circuit_breaker"
  
  # Middleware definitions
  definitions:
    request_id:
      type: "request_id"
      header_name: "X-Request-ID"
    
    cors:
      type: "cors"
      allowed_origins: ["*"]
      allowed_methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
      allowed_headers: ["Content-Type", "Authorization"]
      max_age: 86400
    
    compression:
      type: "compression"
      algorithms: ["gzip", "brotli"]
      min_size: 1024
    
    auth:
      type: "auth"
      providers: ["jwt", "api_key"]
    
    rate_limit:
      type: "rate_limit"
      requests_per_minute: 1000
      burst: 100
```

## Caching

### Response Caching

```yaml
caching:
  # Enable caching
  enabled: true
  
  # Cache storage
  storage:
    # In-memory cache
    memory:
      max_size: 1000000  # bytes
      max_entries: 10000
    
    # Redis cache
    redis:
      url: "redis://localhost:6379"
      key_prefix: "cache:"
      default_ttl: 300  # seconds
  
  # Cache policies
  policies:
    - path: "/api/users"
      methods: ["GET"]
      ttl: 300
      vary_headers: ["Authorization"]
    
    - path: "/api/posts"
      methods: ["GET"]
      ttl: 600
      cache_key: "path+query"
```

## Observability

### Metrics Configuration

```yaml
observability:
  metrics:
    # Enable metrics collection
    enabled: true
    
    # Prometheus exporter
    prometheus:
      enabled: true
      path: "/metrics"
      port: 9090
    
    # Custom metrics
    custom:
      - name: "business_metric"
        type: "counter"
        description: "Business-specific metric"
        labels: ["service", "operation"]
```

### Logging Configuration

```yaml
observability:
  logging:
    # Log level
    level: "info"
    
    # Log format
    format: "json"  # or "text"
    
    # Log output
    output: "stdout"  # or file path
    
    # Structured logging fields
    fields:
      service: "api-gateway"
      version: "0.1.0"
    
    # Request logging
    request_logging:
      enabled: true
      include_headers: false
      include_body: false
      sanitize_headers:
        - "Authorization"
        - "X-API-Key"
```

### Tracing Configuration

```yaml
observability:
  tracing:
    # Enable distributed tracing
    enabled: true
    
    # Jaeger exporter
    jaeger:
      endpoint: "http://jaeger:14268/api/traces"
      service_name: "api-gateway"
    
    # Sampling configuration
    sampling:
      type: "probabilistic"
      rate: 0.1  # 10% sampling rate
```

## Admin Configuration

### Admin Interface

```yaml
admin:
  # Enable admin interface
  enabled: true
  
  # Admin server configuration
  server:
    bind_address: "127.0.0.1"
    port: 8081
  
  # Authentication for admin interface
  auth:
    type: "basic"  # or "jwt" or "oauth2"
    username: "admin"
    password: "secret"
  
  # Admin API endpoints
  endpoints:
    # Configuration management
    config:
      enabled: true
      read_only: false
    
    # Metrics and monitoring
    metrics:
      enabled: true
    
    # Service management
    services:
      enabled: true
    
    # User management
    users:
      enabled: true
```

## Environment Variables

Configuration values can be overridden using environment variables:

```bash
# Server configuration
GATEWAY_SERVER_BIND_ADDRESS=0.0.0.0
GATEWAY_SERVER_HTTP_PORT=8080
GATEWAY_SERVER_ADMIN_PORT=8081

# Database configuration
GATEWAY_DATABASE_URL=postgresql://user:pass@localhost/gateway

# Redis configuration
GATEWAY_REDIS_URL=redis://localhost:6379

# JWT configuration
GATEWAY_JWT_SECRET=your-secret-key

# Log level
GATEWAY_LOG_LEVEL=info
```

## Configuration Examples

### Minimal Configuration

```yaml
server:
  bind_address: "0.0.0.0"
  http_port: 8080

routes:
  - path: "/api/users"
    upstream: "user-service"

upstreams:
  user-service:
    discovery:
      type: "static"
      endpoints:
        - "http://user-service:8080"
```

### Production Configuration

```yaml
server:
  bind_address: "0.0.0.0"
  http_port: 8080
  https_port: 8443
  admin_port: 8081
  max_connections: 10000
  request_timeout: 30
  
  tls:
    enabled: true
    cert_file: "/etc/ssl/certs/gateway.crt"
    key_file: "/etc/ssl/private/gateway.key"

routes:
  - path: "/api/users"
    methods: ["GET", "POST", "PUT", "DELETE"]
    upstream: "user-service"
    middleware: ["auth", "rate_limit"]
    timeout: 15

upstreams:
  user-service:
    discovery:
      type: "kubernetes"
      namespace: "default"
      service_name: "user-service"
    
    load_balancer:
      algorithm: "least_connections"
    
    health_check:
      enabled: true
      path: "/health"
      interval: 30
    
    circuit_breaker:
      enabled: true
      failure_threshold: 10
      timeout: 60

authentication:
  jwt:
    secret: "${JWT_SECRET}"
    algorithms: ["HS256"]
    issuer: "https://auth.example.com"

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
      path: "/metrics"
  
  logging:
    level: "info"
    format: "json"
  
  tracing:
    enabled: true
    jaeger:
      endpoint: "${JAEGER_ENDPOINT}"

admin:
  enabled: true
  server:
    bind_address: "127.0.0.1"
    port: 8081
  auth:
    type: "jwt"
    secret: "${ADMIN_JWT_SECRET}"
```

This configuration reference covers all available options for the Rust API Gateway. For specific use cases and deployment scenarios, refer to the deployment documentation.