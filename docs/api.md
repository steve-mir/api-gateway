# API Documentation

This document provides comprehensive documentation for the Rust API Gateway's REST API endpoints, including examples and usage patterns.

## Table of Contents

- [Authentication](#authentication)
- [Gateway Endpoints](#gateway-endpoints)
- [Health Check Endpoints](#health-check-endpoints)
- [Metrics Endpoints](#metrics-endpoints)
- [Error Responses](#error-responses)
- [Request/Response Examples](#requestresponse-examples)

## Authentication

The API Gateway supports multiple authentication methods:

### JWT Authentication

Include the JWT token in the Authorization header:

```http
Authorization: Bearer <jwt-token>
```

### API Key Authentication

Include the API key in the header:

```http
X-API-Key: <api-key>
```

### OAuth2 Authentication

Follow the OAuth2 flow to obtain an access token:

```http
Authorization: Bearer <oauth2-access-token>
```

## Gateway Endpoints

### Proxy Requests

All requests to configured routes are automatically proxied to upstream services.

#### HTTP/REST Requests

```http
GET /api/users
POST /api/users
PUT /api/users/{id}
DELETE /api/users/{id}
```

**Example Request:**
```bash
curl -X GET "http://localhost:8080/api/users" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**Example Response:**
```json
{
  "users": [
    {
      "id": "123",
      "name": "John Doe",
      "email": "john@example.com"
    }
  ],
  "total": 1
}
```

#### gRPC Requests

gRPC requests are automatically detected and routed to appropriate services:

```bash
grpcurl -plaintext \
  -H "authorization: Bearer <token>" \
  localhost:8080 \
  user.UserService/GetUser
```

#### WebSocket Connections

WebSocket connections are upgraded automatically:

```javascript
const ws = new WebSocket('ws://localhost:8080/api/websocket');
ws.onopen = function() {
  ws.send(JSON.stringify({
    type: 'subscribe',
    channel: 'user-updates'
  }));
};
```

## Health Check Endpoints

### Gateway Health

Check the overall health of the gateway:

```http
GET /health
```

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00Z",
  "version": "0.1.0",
  "uptime": "2h 15m 30s"
}
```

### Readiness Check

Check if the gateway is ready to serve traffic:

```http
GET /ready
```

**Response:**
```json
{
  "status": "ready",
  "services": {
    "user-service": "healthy",
    "post-service": "healthy"
  }
}
```

### Detailed Health Check

Get detailed health information:

```http
GET /health/detailed
```

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00Z",
  "components": {
    "database": {
      "status": "healthy",
      "response_time": "5ms"
    },
    "redis": {
      "status": "healthy",
      "response_time": "2ms"
    },
    "service_discovery": {
      "status": "healthy",
      "services_count": 5
    }
  }
}
```

## Metrics Endpoints

### Prometheus Metrics

Get Prometheus-formatted metrics:

```http
GET /metrics
```

**Response:**
```
# HELP gateway_requests_total Total number of requests
# TYPE gateway_requests_total counter
gateway_requests_total{method="GET",status="200"} 1234

# HELP gateway_request_duration_seconds Request duration in seconds
# TYPE gateway_request_duration_seconds histogram
gateway_request_duration_seconds_bucket{le="0.1"} 100
gateway_request_duration_seconds_bucket{le="0.5"} 200
gateway_request_duration_seconds_bucket{le="1.0"} 250
```

### JSON Metrics

Get metrics in JSON format:

```http
GET /metrics/json
```

**Response:**
```json
{
  "requests": {
    "total": 1234,
    "rate": 45.2,
    "by_status": {
      "200": 1100,
      "404": 100,
      "500": 34
    }
  },
  "latency": {
    "p50": 120,
    "p95": 450,
    "p99": 800
  },
  "upstreams": {
    "user-service": {
      "healthy_instances": 3,
      "total_instances": 3,
      "requests": 567
    }
  }
}
```

## Error Responses

The gateway returns standardized error responses:

### 400 Bad Request

```json
{
  "error": {
    "code": "BAD_REQUEST",
    "message": "Invalid request format",
    "details": "Missing required header: Content-Type"
  },
  "request_id": "req_123456789"
}
```

### 401 Unauthorized

```json
{
  "error": {
    "code": "UNAUTHORIZED",
    "message": "Authentication required",
    "details": "JWT token is missing or invalid"
  },
  "request_id": "req_123456789"
}
```

### 403 Forbidden

```json
{
  "error": {
    "code": "FORBIDDEN",
    "message": "Access denied",
    "details": "Insufficient permissions for this resource"
  },
  "request_id": "req_123456789"
}
```

### 429 Too Many Requests

```json
{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Rate limit exceeded",
    "details": "Maximum 100 requests per minute allowed"
  },
  "request_id": "req_123456789",
  "retry_after": 60
}
```

### 502 Bad Gateway

```json
{
  "error": {
    "code": "BAD_GATEWAY",
    "message": "Upstream service error",
    "details": "Service 'user-service' is temporarily unavailable"
  },
  "request_id": "req_123456789"
}
```

### 503 Service Unavailable

```json
{
  "error": {
    "code": "SERVICE_UNAVAILABLE",
    "message": "Service temporarily unavailable",
    "details": "Circuit breaker is open for service 'user-service'"
  },
  "request_id": "req_123456789"
}
```

## Request/Response Examples

### Creating a User

**Request:**
```bash
curl -X POST "http://localhost:8080/api/users" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "name": "Jane Doe",
    "email": "jane@example.com",
    "role": "user"
  }'
```

**Response:**
```json
{
  "id": "456",
  "name": "Jane Doe",
  "email": "jane@example.com",
  "role": "user",
  "created_at": "2024-01-15T10:30:00Z"
}
```

### Updating a User

**Request:**
```bash
curl -X PUT "http://localhost:8080/api/users/456" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "name": "Jane Smith",
    "email": "jane.smith@example.com"
  }'
```

**Response:**
```json
{
  "id": "456",
  "name": "Jane Smith",
  "email": "jane.smith@example.com",
  "role": "user",
  "updated_at": "2024-01-15T11:00:00Z"
}
```

### Batch Operations

**Request:**
```bash
curl -X POST "http://localhost:8080/api/users/batch" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "operation": "create",
    "users": [
      {"name": "User 1", "email": "user1@example.com"},
      {"name": "User 2", "email": "user2@example.com"}
    ]
  }'
```

**Response:**
```json
{
  "results": [
    {
      "id": "789",
      "name": "User 1",
      "email": "user1@example.com",
      "status": "created"
    },
    {
      "id": "790",
      "name": "User 2",
      "email": "user2@example.com",
      "status": "created"
    }
  ],
  "summary": {
    "total": 2,
    "successful": 2,
    "failed": 0
  }
}
```

### File Upload

**Request:**
```bash
curl -X POST "http://localhost:8080/api/files" \
  -H "Authorization: Bearer <token>" \
  -F "file=@document.pdf" \
  -F "metadata={\"description\":\"Important document\"}"
```

**Response:**
```json
{
  "id": "file_123",
  "filename": "document.pdf",
  "size": 1024000,
  "content_type": "application/pdf",
  "url": "/api/files/file_123",
  "uploaded_at": "2024-01-15T10:30:00Z"
}
```

### Streaming Response

**Request:**
```bash
curl -X GET "http://localhost:8080/api/events/stream" \
  -H "Accept: text/event-stream" \
  -H "Authorization: Bearer <token>"
```

**Response:**
```
data: {"type":"user_created","user_id":"123","timestamp":"2024-01-15T10:30:00Z"}

data: {"type":"user_updated","user_id":"456","timestamp":"2024-01-15T10:31:00Z"}

data: {"type":"user_deleted","user_id":"789","timestamp":"2024-01-15T10:32:00Z"}
```

## Rate Limiting Headers

The gateway includes rate limiting information in response headers:

```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1642248600
X-RateLimit-Window: 60
```

## Request Tracing

Each request includes tracing headers for debugging:

```http
X-Request-ID: req_123456789
X-Trace-ID: trace_abcdef123456
X-Span-ID: span_789012345678
```

## CORS Support

The gateway automatically handles CORS preflight requests:

**Preflight Request:**
```http
OPTIONS /api/users
Origin: https://example.com
Access-Control-Request-Method: POST
Access-Control-Request-Headers: Content-Type, Authorization
```

**Preflight Response:**
```http
Access-Control-Allow-Origin: https://example.com
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Access-Control-Allow-Headers: Content-Type, Authorization, X-API-Key
Access-Control-Max-Age: 86400
```

## WebSocket API

### Connection

```javascript
const ws = new WebSocket('ws://localhost:8080/api/websocket');
```

### Authentication

```javascript
ws.send(JSON.stringify({
  type: 'auth',
  token: 'your-jwt-token'
}));
```

### Subscribing to Events

```javascript
ws.send(JSON.stringify({
  type: 'subscribe',
  channels: ['user-updates', 'system-alerts']
}));
```

### Sending Messages

```javascript
ws.send(JSON.stringify({
  type: 'message',
  channel: 'chat',
  data: {
    text: 'Hello, world!',
    user_id: '123'
  }
}));
```

### Receiving Messages

```javascript
ws.onmessage = function(event) {
  const message = JSON.parse(event.data);
  console.log('Received:', message);
};
```

This API documentation provides comprehensive coverage of all gateway endpoints and usage patterns. For more specific implementation details, refer to the source code and inline documentation.