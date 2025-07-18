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

## WebSocket Integration

The API Gateway provides comprehensive WebSocket support for real-time communication in microservices architectures. This enables features like live notifications, real-time updates, chat systems, and event streaming.

### WebSocket Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Web Client    │    │   Mobile App    │    │  Dashboard App  │
│   (WebSocket)   │    │   (WebSocket)   │    │   (WebSocket)   │
└─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │                         │
                    │    API Gateway          │
                    │  (WebSocket Handler +   │
                    │   Connection Manager)   │
                    │                         │
                    └────────────┬────────────┘
                                 │
        ┌────────────────────────┼────────────────────────┐
        │                       │                        │
┌───────▼───────┐    ┌──────────▼──────────┐    ┌───────▼───────┐
│               │    │                     │    │               │
│ Notification  │    │   User Service      │    │ Event Service │
│ Service       │    │ (User Events)       │    │ (Real-time    │
│ (Push Events) │    │                     │    │  Updates)     │
└───────────────┘    └─────────────────────┘    └───────────────┘
```

### WebSocket Features

#### 1. Connection Management
- **Connection Pooling**: Efficient management of thousands of concurrent connections
- **Authentication Integration**: JWT token-based WebSocket authentication
- **Connection Lifecycle**: Automatic cleanup of idle and disconnected connections
- **Connection Metadata**: Store custom data per connection for routing decisions

#### 2. Channel-Based Messaging
- **Pub/Sub System**: Subscribe to channels for targeted message delivery
- **Broadcast Messaging**: Send messages to all subscribers of a channel
- **Direct Messaging**: Send messages to specific connections
- **Channel Management**: Dynamic subscription and unsubscription

#### 3. Real-time Event Streaming
- **Service Integration**: Forward events from backend services to WebSocket clients
- **Event Filtering**: Route events based on user permissions and subscriptions
- **Event Transformation**: Transform backend events for client consumption

#### 4. Administrative Controls
- **Connection Monitoring**: View active connections and their status
- **Message Broadcasting**: Admin interface for sending messages
- **Connection Management**: Force disconnect problematic connections
- **Statistics and Metrics**: Real-time WebSocket usage statistics

### WebSocket Configuration

Add WebSocket configuration to your gateway config:

```yaml
# WebSocket Configuration
websocket:
  # Enable WebSocket support
  enabled: true
  
  # WebSocket server settings
  server:
    # Path for WebSocket upgrades
    path: "/ws"
    
    # Maximum concurrent connections
    max_connections: 10000
    
    # Connection idle timeout
    idle_timeout: "300s"  # 5 minutes
    
    # Maximum message size
    max_message_size: 1048576  # 1MB
    
    # Ping interval for keepalive
    ping_interval: "30s"
    
    # Pong timeout
    pong_timeout: "10s"
    
    # Require authentication for WebSocket connections
    require_auth: true
    
    # Allow anonymous connections (for public channels)
    allow_anonymous: false

  # Channel configuration
  channels:
    # Default channel settings
    default:
      max_subscribers: 1000
      message_history: 100
      require_auth: true
    
    # Specific channel configurations
    public:
      max_subscribers: 10000
      message_history: 50
      require_auth: false
      allowed_origins: ["*"]
    
    notifications:
      max_subscribers: 5000
      message_history: 200
      require_auth: true
      user_specific: true  # Only send to authenticated user
    
    admin:
      max_subscribers: 10
      message_history: 500
      require_auth: true
      required_roles: ["admin"]

  # Message routing
  routing:
    # Route messages from backend services
    service_events:
      enabled: true
      # Map service events to WebSocket channels
      mappings:
        "user.created": "notifications"
        "user.updated": "notifications"
        "system.alert": "admin"
        "public.announcement": "public"
    
    # Enable message persistence
    persistence:
      enabled: true
      storage: "redis"
      ttl: "24h"

  # Integration with backend services
  integration:
    # HTTP webhook for receiving events from services
    webhook:
      enabled: true
      path: "/webhook/websocket"
      auth_token: "${WEBHOOK_AUTH_TOKEN}"
    
    # Redis pub/sub integration
    redis_pubsub:
      enabled: true
      url: "redis://redis:6379/1"
      channels: ["events", "notifications", "alerts"]
    
    # Message queue integration
    message_queue:
      enabled: false
      type: "rabbitmq"
      url: "amqp://rabbitmq:5672"
      exchange: "websocket_events"

# Add WebSocket routes to your routing configuration
routes:
  # WebSocket upgrade endpoint
  - path: "/ws"
    methods: ["GET"]
    handler: "websocket"
    auth_required: false  # Auth handled during upgrade
    timeout: "0s"  # No timeout for WebSocket connections
```

### Docker Compose Integration

Update your docker-compose.yml to include WebSocket support:

```yaml
version: '3.8'

services:
  # API Gateway with WebSocket support
  api-gateway:
    build: .
    ports:
      - "8080:8080"  # HTTP API
      - "8081:8081"  # Admin API
      - "9090:9090"  # Metrics
    environment:
      - GATEWAY_SERVER_HTTP_PORT=8080
      - GATEWAY_WEBSOCKET_ENABLED=true
      - GATEWAY_WEBSOCKET_MAX_CONNECTIONS=10000
      - WEBHOOK_AUTH_TOKEN=your-webhook-secret
    volumes:
      - ./config/gateway-websocket.yaml:/app/config/gateway.yaml
    depends_on:
      - redis
      - notification-service
    networks:
      - microservices

  # Redis for WebSocket message persistence and pub/sub
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    command: redis-server --appendonly yes
    volumes:
      - redis_data:/data
    networks:
      - microservices

  # Notification service that sends WebSocket events
  notification-service:
    image: your-notification-service:latest
    ports:
      - "3004:3004"
    environment:
      - WEBSOCKET_WEBHOOK_URL=http://api-gateway:8080/webhook/websocket
      - WEBSOCKET_AUTH_TOKEN=your-webhook-secret
    depends_on:
      - api-gateway
    networks:
      - microservices

volumes:
  redis_data:

networks:
  microservices:
    driver: bridge
```

### Client Integration Examples

#### JavaScript/TypeScript Client

```javascript
// WebSocket client with authentication
class GatewayWebSocketClient {
  constructor(gatewayUrl, authToken) {
    this.gatewayUrl = gatewayUrl;
    this.authToken = authToken;
    this.ws = null;
    this.subscriptions = new Set();
    this.messageHandlers = new Map();
  }

  connect() {
    const wsUrl = `${this.gatewayUrl}/ws?token=${this.authToken}`;
    this.ws = new WebSocket(wsUrl);
    
    this.ws.onopen = () => {
      console.log('Connected to API Gateway WebSocket');
      this.authenticate();
    };
    
    this.ws.onmessage = (event) => {
      const message = JSON.parse(event.data);
      this.handleMessage(message);
    };
    
    this.ws.onclose = () => {
      console.log('WebSocket connection closed');
      // Implement reconnection logic
      setTimeout(() => this.connect(), 5000);
    };
    
    this.ws.onerror = (error) => {
      console.error('WebSocket error:', error);
    };
  }

  authenticate() {
    this.send({
      type: 'Auth',
      data: {
        token: this.authToken
      }
    });
  }

  subscribe(channel) {
    this.subscriptions.add(channel);
    this.send({
      type: 'Subscribe',
      data: {
        channel: channel
      }
    });
  }

  unsubscribe(channel) {
    this.subscriptions.delete(channel);
    this.send({
      type: 'Unsubscribe',
      data: {
        channel: channel
      }
    });
  }

  broadcast(channel, message) {
    this.send({
      type: 'Broadcast',
      data: {
        channel: channel,
        message: message
      }
    });
  }

  onMessage(action, handler) {
    this.messageHandlers.set(action, handler);
  }

  send(message) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(message));
    }
  }

  handleMessage(message) {
    const handler = this.messageHandlers.get(message.type);
    if (handler) {
      handler(message.data);
    }
    
    // Handle specific message types
    switch (message.type) {
      case 'Custom':
        if (message.data.action === 'broadcast') {
          this.handleBroadcast(message.data.payload);
        }
        break;
      case 'Error':
        console.error('WebSocket error:', message.data);
        break;
    }
  }

  handleBroadcast(payload) {
    console.log('Received broadcast:', payload);
    // Handle broadcast messages from other clients
  }
}

// Usage example
const client = new GatewayWebSocketClient('ws://localhost:8080', 'your-jwt-token');

client.onMessage('auth_success', (data) => {
  console.log('Authenticated:', data);
  
  // Subscribe to channels after authentication
  client.subscribe('notifications');
  client.subscribe('user_updates');
});

client.onMessage('broadcast', (data) => {
  console.log('Received message on channel:', data.channel, data.message);
});

client.connect();
```

#### React Hook for WebSocket

```javascript
// useWebSocket.js
import { useState, useEffect, useRef } from 'react';

export function useWebSocket(url, token) {
  const [isConnected, setIsConnected] = useState(false);
  const [messages, setMessages] = useState([]);
  const [error, setError] = useState(null);
  const ws = useRef(null);

  useEffect(() => {
    const wsUrl = `${url}/ws?token=${token}`;
    ws.current = new WebSocket(wsUrl);

    ws.current.onopen = () => {
      setIsConnected(true);
      setError(null);
      
      // Authenticate
      ws.current.send(JSON.stringify({
        type: 'Auth',
        data: { token }
      }));
    };

    ws.current.onmessage = (event) => {
      const message = JSON.parse(event.data);
      setMessages(prev => [...prev, message]);
    };

    ws.current.onclose = () => {
      setIsConnected(false);
    };

    ws.current.onerror = (error) => {
      setError(error);
    };

    return () => {
      ws.current?.close();
    };
  }, [url, token]);

  const sendMessage = (message) => {
    if (ws.current?.readyState === WebSocket.OPEN) {
      ws.current.send(JSON.stringify(message));
    }
  };

  const subscribe = (channel) => {
    sendMessage({
      type: 'Subscribe',
      data: { channel }
    });
  };

  const broadcast = (channel, message) => {
    sendMessage({
      type: 'Broadcast',
      data: { channel, message }
    });
  };

  return {
    isConnected,
    messages,
    error,
    sendMessage,
    subscribe,
    broadcast
  };
}

// Usage in React component
function NotificationComponent() {
  const { isConnected, messages, subscribe, broadcast } = useWebSocket(
    'ws://localhost:8080',
    localStorage.getItem('authToken')
  );

  useEffect(() => {
    if (isConnected) {
      subscribe('notifications');
    }
  }, [isConnected, subscribe]);

  const notifications = messages.filter(msg => 
    msg.type === 'Custom' && 
    msg.data.action === 'broadcast' && 
    msg.data.payload.channel === 'notifications'
  );

  return (
    <div>
      <div>Status: {isConnected ? 'Connected' : 'Disconnected'}</div>
      <div>
        {notifications.map((notification, index) => (
          <div key={index}>
            {notification.data.payload.message.text}
          </div>
        ))}
      </div>
    </div>
  );
}
```

### Backend Service Integration

#### Sending Events to WebSocket Clients

```javascript
// notification-service.js
const axios = require('axios');

class WebSocketNotifier {
  constructor(gatewayUrl, authToken) {
    this.gatewayUrl = gatewayUrl;
    this.authToken = authToken;
  }

  async sendNotification(userId, message) {
    try {
      await axios.post(`${this.gatewayUrl}/webhook/websocket`, {
        type: 'user_notification',
        target_user: userId,
        channel: 'notifications',
        message: {
          type: 'notification',
          title: message.title,
          body: message.body,
          timestamp: new Date().toISOString()
        }
      }, {
        headers: {
          'Authorization': `Bearer ${this.authToken}`,
          'Content-Type': 'application/json'
        }
      });
    } catch (error) {
      console.error('Failed to send WebSocket notification:', error);
    }
  }

  async broadcastToChannel(channel, message) {
    try {
      await axios.post(`${this.gatewayUrl}/webhook/websocket`, {
        type: 'channel_broadcast',
        channel: channel,
        message: message
      }, {
        headers: {
          'Authorization': `Bearer ${this.authToken}`,
          'Content-Type': 'application/json'
        }
      });
    } catch (error) {
      console.error('Failed to broadcast to WebSocket channel:', error);
    }
  }
}

// Usage in your service
const notifier = new WebSocketNotifier(
  'http://api-gateway:8080',
  process.env.WEBHOOK_AUTH_TOKEN
);

// Send notification when user is created
async function createUser(userData) {
  const user = await User.create(userData);
  
  // Send WebSocket notification
  await notifier.sendNotification(user.id, {
    title: 'Welcome!',
    body: 'Your account has been created successfully.'
  });
  
  // Broadcast to admin channel
  await notifier.broadcastToChannel('admin', {
    type: 'user_created',
    user_id: user.id,
    timestamp: new Date().toISOString()
  });
  
  return user;
}
```

### WebSocket Admin Management

The gateway provides admin endpoints for WebSocket management:

```bash
# List all active WebSocket connections
curl -X GET http://localhost:8081/admin/websocket/connections \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# Get specific connection details
curl -X GET http://localhost:8081/admin/websocket/connections/{connection_id} \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# Disconnect a connection
curl -X DELETE http://localhost:8081/admin/websocket/connections/{connection_id} \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# List all channels
curl -X GET http://localhost:8081/admin/websocket/channels \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# Broadcast message to channel
curl -X POST http://localhost:8081/admin/websocket/channels/notifications/broadcast \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "message": {
      "type": "system_announcement",
      "title": "Maintenance Notice",
      "body": "System maintenance scheduled for tonight at 2 AM UTC"
    }
  }'

# Send message to specific connection
curl -X POST http://localhost:8081/admin/websocket/connections/{connection_id}/send \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "message": {
      "type": "direct_message",
      "text": "Hello from admin!"
    }
  }'

# Get WebSocket statistics
curl -X GET http://localhost:8081/admin/websocket/statistics \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

### Monitoring and Metrics

WebSocket-specific metrics are exposed via Prometheus:

```yaml
# Prometheus metrics for WebSocket
- websocket_connections_total: Total number of active WebSocket connections
- websocket_connections_by_state: Connections grouped by state (connected, closing, closed)
- websocket_messages_sent_total: Total messages sent to clients
- websocket_messages_received_total: Total messages received from clients
- websocket_channel_subscribers: Number of subscribers per channel
- websocket_connection_duration_seconds: Connection duration histogram
- websocket_message_size_bytes: Message size histogram
```

### Security Considerations

#### 1. Authentication and Authorization
```yaml
websocket:
  security:
    # Require JWT authentication
    require_auth: true
    
    # Validate token on each message (optional, impacts performance)
    validate_token_per_message: false
    
    # Token refresh handling
    token_refresh:
      enabled: true
      grace_period: "300s"  # Allow 5 minutes after token expiry
    
    # Rate limiting per connection
    rate_limiting:
      messages_per_minute: 60
      burst_limit: 10
```

#### 2. Channel Access Control
```yaml
websocket:
  channels:
    user_notifications:
      require_auth: true
      access_control: "user_specific"  # Only send to message owner
      
    admin_alerts:
      require_auth: true
      required_roles: ["admin"]
      
    public_announcements:
      require_auth: false
      rate_limiting:
        messages_per_minute: 10
```

### Testing WebSocket Integration

```javascript
// websocket-integration.test.js
const WebSocket = require('ws');
const jwt = require('jsonwebtoken');

describe('WebSocket Integration', () => {
  let ws;
  let authToken;

  beforeAll(() => {
    // Create test JWT token
    authToken = jwt.sign(
      { user_id: 'test-user', roles: ['user'] },
      'your-secret-key',
      { expiresIn: '1h' }
    );
  });

  beforeEach((done) => {
    ws = new WebSocket(`ws://localhost:8080/ws?token=${authToken}`);
    ws.on('open', done);
  });

  afterEach(() => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.close();
    }
  });

  test('should authenticate successfully', (done) => {
    ws.on('message', (data) => {
      const message = JSON.parse(data);
      if (message.type === 'Custom' && message.data.action === 'auth_success') {
        expect(message.data.authenticated).toBe(true);
        done();
      }
    });

    ws.send(JSON.stringify({
      type: 'Auth',
      data: { token: authToken }
    }));
  });

  test('should subscribe to channel', (done) => {
    ws.on('message', (data) => {
      const message = JSON.parse(data);
      if (message.type === 'Custom' && message.data.action === 'subscribed') {
        expect(message.data.channel).toBe('test-channel');
        done();
      }
    });

    ws.send(JSON.stringify({
      type: 'Subscribe',
      data: { channel: 'test-channel' }
    }));
  });

  test('should receive broadcast messages', (done) => {
    // First subscribe to channel
    ws.send(JSON.stringify({
      type: 'Subscribe',
      data: { channel: 'test-broadcast' }
    }));

    // Then send broadcast
    setTimeout(() => {
      ws.send(JSON.stringify({
        type: 'Broadcast',
        data: {
          channel: 'test-broadcast',
          message: { text: 'Hello World!' }
        }
      }));
    }, 100);

    ws.on('message', (data) => {
      const message = JSON.parse(data);
      if (message.type === 'Custom' && message.data.action === 'broadcast') {
        expect(message.data.payload.message.text).toBe('Hello World!');
        done();
      }
    });
  });
});
```

This integration approach gives you:

1. **Stateless Authentication**: Gateway validates tokens without storing session state
2. **Service Separation**: Auth service handles user management, gateway handles request routing
3. **Scalability**: Each service can scale independently
4. **Security**: Centralized authentication with distributed authorization
5. **Observability**: Comprehensive monitoring across all services
6. **Flexibility**: Easy to add new services or modify existing ones
7. **Real-time Communication**: WebSocket support for live updates and notifications
8. **Event-Driven Architecture**: Integration with backend services for real-time event streaming

The key is that your gateway acts as a smart proxy that validates authentication tokens and routes requests, while your auth service handles the actual user lifecycle management. The WebSocket integration adds real-time capabilities while maintaining the same security and architectural principles.