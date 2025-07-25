# Admin API Reference

The Rust API Gateway provides a comprehensive admin API for monitoring, configuration, and management. The admin API runs on a separate port (default: 8081) and includes authentication and authorization.

## Table of Contents

- [Authentication](#authentication)
- [Service Management](#service-management)
- [Configuration Management](#configuration-management)
- [Health and Status](#health-and-status)
- [Metrics and Monitoring](#metrics-and-monitoring)
- [User Management](#user-management)
- [Circuit Breaker Management](#circuit-breaker-management)
- [Rate Limiting Management](#rate-limiting-management)
- [Log Management](#log-management)
- [System Operations](#system-operations)

## Authentication

The admin API supports multiple authentication methods:

### JWT Authentication

```http
POST /admin/auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "secure-password"
}
```

**Response:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 3600,
  "token_type": "Bearer"
}
```

Use the token in subsequent requests:
```http
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### API Key Authentication

```http
X-Admin-API-Key: your-admin-api-key
```

## Service Management

### List Services

Get all registered services and their status:

```http
GET /admin/services
```

**Response:**
```json
{
  "services": [
    {
      "name": "user-service",
      "instances": [
        {
          "id": "user-service-1",
          "address": "10.0.1.10:8080",
          "status": "healthy",
          "last_health_check": "2024-01-15T10:30:00Z",
          "metadata": {
            "version": "1.2.0",
            "zone": "us-west-2a"
          }
        }
      ],
      "load_balancer": {
        "algorithm": "round_robin",
        "health_check_enabled": true
      }
    }
  ],
  "total_services": 1,
  "healthy_services": 1
}
```

### Get Service Details

Get detailed information about a specific service:

```http
GET /admin/services/{service_name}
```

**Response:**
```json
{
  "name": "user-service",
  "discovery": {
    "type": "kubernetes",
    "namespace": "default",
    "service_name": "user-service"
  },
  "instances": [
    {
      "id": "user-service-1",
      "address": "10.0.1.10:8080",
      "status": "healthy",
      "last_health_check": "2024-01-15T10:30:00Z",
      "response_time": 45,
      "error_count": 0,
      "metadata": {
        "version": "1.2.0",
        "zone": "us-west-2a"
      }
    }
  ],
  "load_balancer": {
    "algorithm": "round_robin",
    "weights": {}
  },
  "health_check": {
    "enabled": true,
    "path": "/health",
    "interval": 30,
    "timeout": 5,
    "healthy_threshold": 2,
    "unhealthy_threshold": 3
  },
  "circuit_breaker": {
    "enabled": true,
    "state": "closed",
    "failure_count": 0,
    "failure_threshold": 10,
    "timeout": 60
  }
}
```

### Register Service

Manually register a service instance:

```http
POST /admin/services
Content-Type: application/json

{
  "name": "new-service",
  "instances": [
    {
      "address": "10.0.1.20:8080",
      "metadata": {
        "version": "1.0.0",
        "zone": "us-west-2b"
      }
    }
  ],
  "load_balancer": {
    "algorithm": "least_connections"
  },
  "health_check": {
    "enabled": true,
    "path": "/health",
    "interval": 30
  }
}
```

### Update Service

Update service configuration:

```http
PUT /admin/services/{service_name}
Content-Type: application/json

{
  "load_balancer": {
    "algorithm": "weighted",
    "weights": {
      "10.0.1.10:8080": 100,
      "10.0.1.11:8080": 200
    }
  }
}
```

### Deregister Service

Remove a service:

```http
DELETE /admin/services/{service_name}
```

### Force Health Check

Trigger immediate health check for a service:

```http
POST /admin/services/{service_name}/health-check
```

## Configuration Management

### Get Current Configuration

```http
GET /admin/config
```

**Response:**
```json
{
  "server": {
    "bind_address": "0.0.0.0",
    "http_port": 8080,
    "admin_port": 8081
  },
  "routes": [
    {
      "path": "/api/users",
      "upstream": "user-service",
      "methods": ["GET", "POST", "PUT", "DELETE"]
    }
  ],
  "upstreams": {
    "user-service": {
      "discovery": {
        "type": "kubernetes",
        "namespace": "default"
      }
    }
  }
}
```

### Update Configuration

```http
PUT /admin/config
Content-Type: application/json

{
  "routes": [
    {
      "path": "/api/users",
      "upstream": "user-service",
      "methods": ["GET", "POST", "PUT", "DELETE"],
      "middleware": ["auth", "rate_limit"]
    }
  ]
}
```

### Validate Configuration

Validate configuration without applying:

```http
POST /admin/config/validate
Content-Type: application/json

{
  "routes": [
    {
      "path": "/api/invalid",
      "upstream": "nonexistent-service"
    }
  ]
}
```

**Response:**
```json
{
  "valid": false,
  "errors": [
    {
      "field": "routes[0].upstream",
      "message": "Upstream 'nonexistent-service' is not defined"
    }
  ]
}
```

### Configuration History

Get configuration change history:

```http
GET /admin/config/history
```

**Response:**
```json
{
  "changes": [
    {
      "id": "change_123",
      "timestamp": "2024-01-15T10:30:00Z",
      "user": "admin",
      "action": "update",
      "description": "Added rate limiting to user service",
      "diff": {
        "added": ["routes[0].middleware"],
        "modified": [],
        "removed": []
      }
    }
  ]
}
```

### Rollback Configuration

Rollback to a previous configuration:

```http
POST /admin/config/rollback
Content-Type: application/json

{
  "change_id": "change_123"
}
```

## Health and Status

### Gateway Health

```http
GET /admin/health
```

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00Z",
  "version": "0.1.0",
  "uptime": "2h 15m 30s",
  "components": {
    "database": {
      "status": "healthy",
      "response_time": 5
    },
    "redis": {
      "status": "healthy",
      "response_time": 2
    },
    "service_discovery": {
      "status": "healthy",
      "services_discovered": 5
    }
  }
}
```

### System Status

```http
GET /admin/status
```

**Response:**
```json
{
  "gateway": {
    "status": "running",
    "start_time": "2024-01-15T08:00:00Z",
    "uptime": "2h 30m 15s",
    "version": "0.1.0"
  },
  "resources": {
    "memory": {
      "used": 256000000,
      "total": 1073741824,
      "usage_percent": 23.8
    },
    "cpu": {
      "usage_percent": 15.2
    },
    "connections": {
      "active": 150,
      "total": 1500
    }
  },
  "services": {
    "total": 5,
    "healthy": 4,
    "unhealthy": 1
  }
}
```

## Metrics and Monitoring

### Get Metrics

```http
GET /admin/metrics
```

**Response:**
```json
{
  "requests": {
    "total": 10000,
    "rate": 45.2,
    "by_status": {
      "200": 8500,
      "404": 1000,
      "500": 500
    },
    "by_method": {
      "GET": 7000,
      "POST": 2000,
      "PUT": 800,
      "DELETE": 200
    }
  },
  "latency": {
    "p50": 120,
    "p95": 450,
    "p99": 800,
    "max": 2000
  },
  "upstreams": {
    "user-service": {
      "requests": 5000,
      "errors": 50,
      "latency_p95": 200
    }
  },
  "circuit_breakers": {
    "user-service": {
      "state": "closed",
      "failure_count": 2
    }
  }
}
```

### Real-time Metrics Stream

```http
GET /admin/metrics/stream
Accept: text/event-stream
```

**Response:**
```
data: {"timestamp":"2024-01-15T10:30:00Z","requests_per_second":45.2,"error_rate":0.05}

data: {"timestamp":"2024-01-15T10:30:01Z","requests_per_second":46.1,"error_rate":0.04}
```

### Custom Metrics

Add custom business metrics:

```http
POST /admin/metrics/custom
Content-Type: application/json

{
  "name": "user_registrations",
  "type": "counter",
  "value": 1,
  "labels": {
    "source": "web",
    "plan": "premium"
  }
}
```

## User Management

### List Admin Users

```http
GET /admin/users
```

**Response:**
```json
{
  "users": [
    {
      "id": "user_123",
      "username": "admin",
      "email": "admin@example.com",
      "roles": ["admin"],
      "created_at": "2024-01-01T00:00:00Z",
      "last_login": "2024-01-15T10:00:00Z",
      "active": true
    }
  ]
}
```

### Create Admin User

```http
POST /admin/users
Content-Type: application/json

{
  "username": "operator",
  "email": "operator@example.com",
  "password": "secure-password",
  "roles": ["operator"]
}
```

### Update User

```http
PUT /admin/users/{user_id}
Content-Type: application/json

{
  "roles": ["admin", "operator"],
  "active": true
}
```

### API Key Management

List API keys:

```http
GET /admin/api-keys
```

Create API key:

```http
POST /admin/api-keys
Content-Type: application/json

{
  "name": "monitoring-key",
  "permissions": ["read:metrics", "read:services"],
  "expires_at": "2024-12-31T23:59:59Z"
}
```

## Circuit Breaker Management

### List Circuit Breakers

```http
GET /admin/circuit-breakers
```

**Response:**
```json
{
  "circuit_breakers": [
    {
      "service": "user-service",
      "state": "closed",
      "failure_count": 2,
      "failure_threshold": 10,
      "timeout": 60,
      "success_count": 0,
      "success_threshold": 5,
      "last_failure": "2024-01-15T10:25:00Z"
    }
  ]
}
```

### Reset Circuit Breaker

```http
POST /admin/circuit-breakers/{service_name}/reset
```

### Update Circuit Breaker Configuration

```http
PUT /admin/circuit-breakers/{service_name}
Content-Type: application/json

{
  "failure_threshold": 15,
  "timeout": 90,
  "success_threshold": 3
}
```

## Rate Limiting Management

### Get Rate Limit Status

```http
GET /admin/rate-limits
```

**Response:**
```json
{
  "global": {
    "requests_per_minute": 1000,
    "current_usage": 450,
    "remaining": 550
  },
  "by_client": [
    {
      "client_id": "192.168.1.100",
      "requests_per_minute": 100,
      "current_usage": 75,
      "remaining": 25
    }
  ]
}
```

### Update Rate Limits

```http
PUT /admin/rate-limits
Content-Type: application/json

{
  "global": {
    "requests_per_minute": 2000,
    "burst": 200
  },
  "per_client": {
    "requests_per_minute": 200,
    "burst": 50
  }
}
```

### Reset Rate Limit

```http
POST /admin/rate-limits/reset
Content-Type: application/json

{
  "client_id": "192.168.1.100"
}
```

## Log Management

### Query Logs

```http
GET /admin/logs?level=error&since=2024-01-15T10:00:00Z&limit=100
```

**Response:**
```json
{
  "logs": [
    {
      "timestamp": "2024-01-15T10:30:00Z",
      "level": "error",
      "message": "Upstream service timeout",
      "service": "user-service",
      "request_id": "req_123456",
      "trace_id": "trace_abcdef"
    }
  ],
  "total": 1,
  "has_more": false
}
```

### Update Log Level

```http
PUT /admin/logs/level
Content-Type: application/json

{
  "level": "debug"
}
```

### Log Streaming

```http
GET /admin/logs/stream?level=info
Accept: text/event-stream
```

## System Operations

### Graceful Shutdown

```http
POST /admin/system/shutdown
Content-Type: application/json

{
  "grace_period": 30
}
```

### Reload Configuration

```http
POST /admin/system/reload
```

### Clear Caches

```http
POST /admin/system/cache/clear
Content-Type: application/json

{
  "cache_types": ["response", "auth", "service_discovery"]
}
```

### Export Configuration

```http
GET /admin/system/export
Accept: application/yaml
```

### Import Configuration

```http
POST /admin/system/import
Content-Type: application/yaml

server:
  bind_address: "0.0.0.0"
  http_port: 8080
routes:
  - path: "/api/users"
    upstream: "user-service"
```

### System Diagnostics

```http
GET /admin/system/diagnostics
```

**Response:**
```json
{
  "connectivity": {
    "service_discovery": "ok",
    "redis": "ok",
    "database": "ok"
  },
  "performance": {
    "memory_usage": "23.8%",
    "cpu_usage": "15.2%",
    "connection_pool": "healthy"
  },
  "configuration": {
    "valid": true,
    "last_reload": "2024-01-15T10:00:00Z"
  }
}
```

## Error Responses

All admin API endpoints return structured error responses:

### 400 Bad Request

```json
{
  "error": {
    "code": "INVALID_REQUEST",
    "message": "Invalid request format",
    "details": "Missing required field: 'name'"
  },
  "request_id": "req_admin_123"
}
```

### 401 Unauthorized

```json
{
  "error": {
    "code": "UNAUTHORIZED",
    "message": "Authentication required",
    "details": "Invalid or expired admin token"
  },
  "request_id": "req_admin_123"
}
```

### 403 Forbidden

```json
{
  "error": {
    "code": "FORBIDDEN",
    "message": "Insufficient permissions",
    "details": "Admin role required for this operation"
  },
  "request_id": "req_admin_123"
}
```

### 404 Not Found

```json
{
  "error": {
    "code": "NOT_FOUND",
    "message": "Resource not found",
    "details": "Service 'unknown-service' not found"
  },
  "request_id": "req_admin_123"
}
```

### 500 Internal Server Error

```json
{
  "error": {
    "code": "INTERNAL_ERROR",
    "message": "Internal server error",
    "details": "Database connection failed"
  },
  "request_id": "req_admin_123"
}
```

## Rate Limiting

The admin API has its own rate limiting:

```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 995
X-RateLimit-Reset: 1642248600
```

## Webhooks

Configure webhooks for admin events:

```http
POST /admin/webhooks
Content-Type: application/json

{
  "url": "https://your-system.com/webhook",
  "events": ["service.health_changed", "config.updated"],
  "secret": "webhook-secret"
}
```

This admin API provides comprehensive management capabilities for the Rust API Gateway. All endpoints support JSON responses and include proper error handling and authentication.