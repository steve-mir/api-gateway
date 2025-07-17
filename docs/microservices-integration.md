# Microservices Integration Guide

This guide shows how to integrate the API Gateway into a microservices architecture with external authentication service and other services like user service, metrics service, etc.

## Architecture Overview

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Load Balancer │    │     Client      │    │   Mobile App    │
│   (nginx/ALB)   │    │   Application   │    │                 │
└─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │                         │
                    │    API Gateway          │
                    │  (Stateless Auth +      │
                    │   Request Routing)      │
                    │                         │
                    └────────────┬────────────┘
                                 │
        ┌────────────────────────┼────────────────────────┐
        │                       │                        │
┌───────▼───────┐    ┌──────────▼──────────┐    ┌───────▼───────┐
│               │    │                     │    │               │
│ Auth Service  │    │   User Service      │    │ Other Services│
│ (Login/Signup)│    │ (User Management)   │    │ (Metrics, etc)│
│               │    │                     │    │               │
└───────────────┘    └─────────────────────┘    └───────────────┘
```

## Key Integration Points

### 1. Stateless Authentication Flow

The gateway handles authentication verification while the auth service handles user management:

**Auth Service Responsibilities:**
- User registration/signup
- User login (username/password)
- Password reset
- JWT token issuance
- User profile management
- Account verification

**Gateway Responsibilities:**
- JWT token validation
- Request authorization (RBAC)
- Token extraction from headers
- Stateless authentication checks
- Route protection

### 2. Service Communication Patterns

#### External Client → Gateway → Services
```
1. Client sends request with JWT token
2. Gateway validates JWT (stateless)
3. Gateway extracts user context
4. Gateway routes to appropriate service
5. Service receives request with user context
```

#### Service-to-Service Communication
```
1. Service A needs to call Service B
2. Service A uses service account JWT
3. Gateway validates service token
4. Gateway routes with service context
```

## Configuration Examples

### Docker Compose Setup

```yaml
# docker-compose.yml
version: '3.8'

services:
  # API Gateway
  api-gateway:
    build: .
    ports:
      - "8080:8080"  # Main API port
      - "8081:8081"  # Admin port
      - "9090:9090"  # Metrics port
    environment:
      - GATEWAY_SERVER_HTTP_PORT=8080
      - GATEWAY_LOG_LEVEL=info
      - GATEWAY_METRICS_ENABLED=true
    volumes:
      - ./config/gateway.yaml:/app/config/gateway.yaml
    depends_on:
      - auth-service
      - user-service
      - redis
    networks:
      - microservices

  # Authentication Service
  auth-service:
    image: your-auth-service:latest
    ports:
      - "3001:3001"
    environment:
      - JWT_SECRET=your-shared-jwt-secret
      - DATABASE_URL=postgresql://user:pass@postgres:5432/auth
    depends_on:
      - postgres
    networks:
      - microservices

  # User Service
  user-service:
    image: your-user-service:latest
    ports:
      - "3002:3002"
    environment:
      - DATABASE_URL=postgresql://user:pass@postgres:5432/users
    depends_on:
      - postgres
    networks:
      - microservices

  # Metrics Service
  metrics-service:
    image: your-metrics-service:latest
    ports:
      - "3003:3003"
    networks:
      - microservices

  # Redis for rate limiting and caching
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    networks:
      - microservices

  # PostgreSQL for services
  postgres:
    image: postgres:15
    environment:
      - POSTGRES_DB=microservices
      - POSTGRES_USER=user
      - POSTGRES_PASSWORD=pass
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - microservices

networks:
  microservices:
    driver: bridge

volumes:
  postgres_data:
```

### Kubernetes Deployment

```yaml
# k8s/gateway-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-gateway
  namespace: microservices
spec:
  replicas: 3
  selector:
    matchLabels:
      app: api-gateway
  template:
    metadata:
      labels:
        app: api-gateway
    spec:
      containers:
      - name: api-gateway
        image: your-registry/api-gateway:latest
        ports:
        - containerPort: 8080
          name: http
        - containerPort: 8081
          name: admin
        - containerPort: 9090
          name: metrics
        env:
        - name: GATEWAY_SERVER_HTTP_PORT
          value: "8080"
        - name: GATEWAY_LOG_LEVEL
          value: "info"
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: jwt-secret
              key: secret
        volumeMounts:
        - name: config
          mountPath: /app/config
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
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: config
        configMap:
          name: gateway-config

---
apiVersion: v1
kind: Service
metadata:
  name: api-gateway
  namespace: microservices
spec:
  selector:
    app: api-gateway
  ports:
  - name: http
    port: 80
    targetPort: 8080
  - name: admin
    port: 8081
    targetPort: 8081
  - name: metrics
    port: 9090
    targetPort: 9090
  type: LoadBalancer
```

### Gateway Configuration for Microservices

```yaml
# config/gateway-microservices.yaml
server:
  http_port: 8080
  https_port: 8443
  metrics_port: 9090
  bind_address: "0.0.0.0"
  timeouts:
    request_timeout: "30s"
    keepalive_timeout: "60s"
    upstream_timeout: "10s"

# Route definitions for microservices
routes:
  # Auth service routes (public)
  - path: "/auth/login"
    methods: ["POST"]
    upstream: "auth-service"
    auth_required: false
    timeout: "10s"

  - path: "/auth/register"
    methods: ["POST"]
    upstream: "auth-service"
    auth_required: false
    timeout: "10s"

  - path: "/auth/refresh"
    methods: ["POST"]
    upstream: "auth-service"
    auth_required: false
    timeout: "10s"

  - path: "/auth/forgot-password"
    methods: ["POST"]
    upstream: "auth-service"
    auth_required: false
    timeout: "10s"

  # User service routes (protected)
  - path: "/api/v1/users"
    methods: ["GET", "POST"]
    upstream: "user-service"
    auth_required: true
    required_roles: ["user"]
    timeout: "30s"

  - path: "/api/v1/users/{id}"
    methods: ["GET", "PUT", "DELETE"]
    upstream: "user-service"
    auth_required: true
    required_roles: ["user"]
    timeout: "30s"

  - path: "/api/v1/users/{id}/profile"
    methods: ["GET", "PUT"]
    upstream: "user-service"
    auth_required: true
    required_roles: ["user"]
    timeout: "30s"

  # Admin routes (admin only)
  - path: "/api/v1/admin/users"
    methods: ["GET", "POST", "PUT", "DELETE"]
    upstream: "user-service"
    auth_required: true
    required_roles: ["admin"]
    timeout: "30s"

  # Metrics service routes
  - path: "/api/v1/metrics"
    methods: ["GET"]
    upstream: "metrics-service"
    auth_required: true
    required_roles: ["user", "admin"]
    timeout: "15s"

  # Health checks (public)
  - path: "/health"
    methods: ["GET"]
    upstream: "health-service"
    auth_required: false
    timeout: "5s"

# Upstream service definitions
upstreams:
  auth-service:
    discovery:
      type: "Static"
      endpoints: ["http://auth-service:3001"]
    load_balancer:
      type: "RoundRobin"
    health_check:
      path: "/health"
      interval: "30s"
      timeout: "5s"
      healthy_threshold: 2
      unhealthy_threshold: 3

  user-service:
    discovery:
      type: "Static"
      endpoints: ["http://user-service:3002"]
    load_balancer:
      type: "RoundRobin"
    health_check:
      path: "/health"
      interval: "30s"
      timeout: "5s"
      healthy_threshold: 2
      unhealthy_threshold: 3
    circuit_breaker:
      failure_threshold: 5
      timeout: "60s"
      success_threshold: 3

  metrics-service:
    discovery:
      type: "Static"
      endpoints: ["http://metrics-service:3003"]
    load_balancer:
      type: "RoundRobin"
    health_check:
      path: "/health"
      interval: "30s"
      timeout: "5s"
      healthy_threshold: 2
      unhealthy_threshold: 3

# Authentication configuration
auth:
  jwt:
    secret: "${JWT_SECRET}"  # Shared with auth service
    algorithm: "HS256"
    issuer: "auth-service"
    audience: "api-gateway"

# Rate limiting with Redis
middleware:
  rate_limiting:
    default_limit: 1000
    route_limits:
      "/auth/login": 10      # Stricter limit for login
      "/auth/register": 5    # Stricter limit for registration
    storage:
      type: "Redis"
      url: "redis://redis:6379"

  cors:
    allowed_origins: ["*"]
    allowed_methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    allowed_headers: ["Content-Type", "Authorization"]
    max_age: 3600

# Observability
observability:
  metrics:
    prometheus_enabled: true
    endpoint_path: "/metrics"
  
  logging:
    level: "info"
    format: "json"
  
  tracing:
    enabled: true
    backend:
      type: "Jaeger"
      endpoint: "http://jaeger:14268/api/traces"
    sampling_rate: 0.1
```

## Implementation Examples

### 1. JWT Token Validation Integration

The gateway validates JWT tokens issued by your auth service:

```rust
// In your auth service integration
use crate::auth::providers::{JwtAuthProvider, JwtConfig};

// Configure JWT provider to match your auth service
let jwt_config = JwtConfig {
    secret: env::var("JWT_SECRET").expect("JWT_SECRET must be set"),
    algorithm: Algorithm::HS256,
    issuer: "auth-service".to_string(),
    audience: "api-gateway".to_string(),
    leeway: 60, // 1 minute clock skew tolerance
};

let rbac = Arc::new(RbacManager::new());
let jwt_provider = Arc::new(JwtAuthProvider::new(jwt_config, rbac)?);
```

### 2. Service-to-Service Authentication

For service-to-service communication, use service account tokens:

```rust
// Service account JWT claims
let service_claims = JwtClaims {
    sub: "user-service".to_string(),
    exp: (Utc::now() + Duration::hours(1)).timestamp(),
    iat: Utc::now().timestamp(),
    iss: "auth-service".to_string(),
    aud: "api-gateway".to_string(),
    roles: vec!["service".to_string()],
    permissions: vec!["users:read".to_string(), "users:write".to_string()],
    custom_claims: HashMap::new(),
};
```

### 3. User Context Forwarding

The gateway forwards user context to downstream services:

```rust
// Add user context headers for downstream services
pub async fn add_user_context_headers(
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if let Some(auth_context) = request.extensions().get::<Arc<AuthContext>>() {
        let headers = request.headers_mut();
        
        // Add user ID header
        headers.insert(
            "X-User-ID",
            HeaderValue::from_str(&auth_context.user_id).unwrap(),
        );
        
        // Add user roles header
        let roles = auth_context.roles.join(",");
        headers.insert(
            "X-User-Roles",
            HeaderValue::from_str(&roles).unwrap(),
        );
        
        // Add user permissions header
        let permissions = auth_context.permissions.join(",");
        headers.insert(
            "X-User-Permissions",
            HeaderValue::from_str(&permissions).unwrap(),
        );
    }
    
    Ok(next.run(request).await)
}
```

## Security Considerations

### 1. JWT Secret Management

- Use the same JWT secret across auth service and gateway
- Store secrets in environment variables or secret management systems
- Rotate secrets regularly
- Use different secrets for different environments

### 2. Network Security

```yaml
# Network policies for Kubernetes
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: gateway-network-policy
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
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: auth-service
    ports:
    - protocol: TCP
      port: 3001
  - to:
    - podSelector:
        matchLabels:
          app: user-service
    ports:
    - protocol: TCP
      port: 3002
```

### 3. Rate Limiting Strategy

```yaml
# Different rate limits for different endpoints
middleware:
  rate_limiting:
    default_limit: 1000
    route_limits:
      "/auth/login": 10          # Prevent brute force
      "/auth/register": 5        # Prevent spam registration
      "/api/v1/users": 100       # Normal API usage
      "/api/v1/admin/*": 50      # Admin endpoints
```

## Monitoring and Observability

### 1. Metrics Collection

The gateway exposes metrics for monitoring:

```yaml
# Prometheus scrape config
scrape_configs:
  - job_name: 'api-gateway'
    static_configs:
      - targets: ['api-gateway:9090']
    metrics_path: '/metrics'
    scrape_interval: 15s
```

### 2. Distributed Tracing

Configure tracing to track requests across services:

```yaml
observability:
  tracing:
    enabled: true
    backend:
      type: "Jaeger"
      endpoint: "http://jaeger-collector:14268/api/traces"
    sampling_rate: 0.1
```

### 3. Logging Strategy

```yaml
observability:
  logging:
    level: "info"
    format: "json"
    output:
      type: "Stdout"  # For container environments
```

## Deployment Strategies

### 1. Blue-Green Deployment

```bash
# Deploy new version
kubectl apply -f k8s/gateway-deployment-v2.yaml

# Switch traffic
kubectl patch service api-gateway -p '{"spec":{"selector":{"version":"v2"}}}'

# Rollback if needed
kubectl patch service api-gateway -p '{"spec":{"selector":{"version":"v1"}}}'
```

### 2. Canary Deployment

```yaml
# Istio VirtualService for canary
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: api-gateway
spec:
  http:
  - match:
    - headers:
        canary:
          exact: "true"
    route:
    - destination:
        host: api-gateway
        subset: v2
  - route:
    - destination:
        host: api-gateway
        subset: v1
      weight: 90
    - destination:
        host: api-gateway
        subset: v2
      weight: 10
```

## Testing Integration

### 1. Integration Tests

```rust
#[tokio::test]
async fn test_auth_flow_integration() {
    // 1. Register user with auth service
    let register_response = test_client
        .post("/auth/register")
        .json(&json!({
            "username": "testuser",
            "password": "password123",
            "email": "test@example.com"
        }))
        .send()
        .await?;
    
    assert_eq!(register_response.status(), 201);
    
    // 2. Login to get JWT token
    let login_response = test_client
        .post("/auth/login")
        .json(&json!({
            "username": "testuser",
            "password": "password123"
        }))
        .send()
        .await?;
    
    let token = login_response.json::<LoginResponse>().await?.token;
    
    // 3. Use token to access protected endpoint
    let user_response = test_client
        .get("/api/v1/users/me")
        .bearer_auth(&token)
        .send()
        .await?;
    
    assert_eq!(user_response.status(), 200);
}
```

### 2. Load Testing

```yaml
# k6 load test script
import http from 'k6/http';
import { check } from 'k6';

export let options = {
  stages: [
    { duration: '2m', target: 100 },
    { duration: '5m', target: 100 },
    { duration: '2m', target: 200 },
    { duration: '5m', target: 200 },
    { duration: '2m', target: 0 },
  ],
};

export default function () {
  // Login to get token
  let loginRes = http.post('http://api-gateway/auth/login', {
    username: 'testuser',
    password: 'password123',
  });
  
  check(loginRes, {
    'login successful': (r) => r.status === 200,
  });
  
  let token = loginRes.json('token');
  
  // Use token for API calls
  let apiRes = http.get('http://api-gateway/api/v1/users', {
    headers: { Authorization: `Bearer ${token}` },
  });
  
  check(apiRes, {
    'API call successful': (r) => r.status === 200,
  });
}
```

This integration approach gives you:

1. **Stateless Authentication**: Gateway validates tokens without storing session state
2. **Service Separation**: Auth service handles user management, gateway handles request routing
3. **Scalability**: Each service can scale independently
4. **Security**: Centralized authentication with distributed authorization
5. **Observability**: Comprehensive monitoring across all services
6. **Flexibility**: Easy to add new services or modify existing ones

The key is that your gateway acts as a smart proxy that validates authentication tokens and routes requests, while your auth service handles the actual user lifecycle management.