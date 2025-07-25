# Plugin Development Guide

This guide explains how to create custom plugins and middleware for the Rust API Gateway. The gateway provides a flexible plugin system that allows you to extend functionality while maintaining performance and safety.

## Table of Contents

- [Plugin Architecture](#plugin-architecture)
- [Middleware Development](#middleware-development)
- [Authentication Providers](#authentication-providers)
- [Load Balancing Strategies](#load-balancing-strategies)
- [Service Discovery Plugins](#service-discovery-plugins)
- [Custom Protocol Handlers](#custom-protocol-handlers)
- [Configuration Extensions](#configuration-extensions)
- [Testing Plugins](#testing-plugins)
- [Plugin Examples](#plugin-examples)
- [Best Practices](#best-practices)

## Plugin Architecture

The gateway uses Rust's trait system to provide pluggable interfaces. This approach ensures type safety and zero-cost abstractions while allowing for dynamic behavior.

### Core Plugin Traits

```rust
// All plugins must implement this base trait
pub trait Plugin: Send + Sync {
    fn name(&self) -> &'static str;
    fn version(&self) -> &'static str;
    fn description(&self) -> &'static str;
}

// Lifecycle management for plugins
#[async_trait]
pub trait PluginLifecycle: Plugin {
    async fn initialize(&mut self, config: &PluginConfig) -> Result<(), PluginError>;
    async fn shutdown(&mut self) -> Result<(), PluginError>;
}
```

### Plugin Registration

```rust
// Plugin registry for managing plugins
pub struct PluginRegistry {
    middleware: HashMap<String, Box<dyn Middleware>>,
    auth_providers: HashMap<String, Box<dyn AuthProvider>>,
    load_balancers: HashMap<String, Box<dyn LoadBalancer>>,
    // ... other plugin types
}

impl PluginRegistry {
    pub fn register_middleware<T>(&mut self, name: &str, middleware: T) 
    where 
        T: Middleware + 'static 
    {
        self.middleware.insert(name.to_string(), Box::new(middleware));
    }
}
```

## Middleware Development

Middleware plugins process requests and responses in a pipeline. They can modify headers, validate requests, implement caching, or perform any custom logic.

### Basic Middleware Interface

```rust
use async_trait::async_trait;
use crate::core::types::{Request, Response, RequestContext};
use crate::core::error::GatewayResult;

#[async_trait]
pub trait Middleware: Send + Sync + Plugin {
    /// Process the request before it's sent to upstream
    async fn process_request(
        &self, 
        request: &mut Request, 
        context: &mut RequestContext
    ) -> GatewayResult<()>;
    
    /// Process the response before it's sent to client
    async fn process_response(
        &self, 
        response: &mut Response, 
        context: &RequestContext
    ) -> GatewayResult<()>;
    
    /// Called when an error occurs in the pipeline
    async fn on_error(
        &self, 
        error: &GatewayError, 
        context: &RequestContext
    ) -> GatewayResult<Option<Response>>;
}
```

### Example: Custom Header Middleware

```rust
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CustomHeaderConfig {
    pub headers_to_add: HashMap<String, String>,
    pub headers_to_remove: Vec<String>,
    pub conditional_headers: Vec<ConditionalHeader>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConditionalHeader {
    pub condition: String,  // e.g., "path_starts_with:/api/v2"
    pub header_name: String,
    pub header_value: String,
}

pub struct CustomHeaderMiddleware {
    config: CustomHeaderConfig,
}

impl Plugin for CustomHeaderMiddleware {
    fn name(&self) -> &'static str { "custom_header" }
    fn version(&self) -> &'static str { "1.0.0" }
    fn description(&self) -> &'static str { "Adds and removes custom headers" }
}

#[async_trait]
impl Middleware for CustomHeaderMiddleware {
    async fn process_request(
        &self, 
        request: &mut Request, 
        context: &mut RequestContext
    ) -> GatewayResult<()> {
        // Add configured headers
        for (name, value) in &self.config.headers_to_add {
            request.headers.insert(name.clone(), value.clone());
        }
        
        // Remove configured headers
        for header_name in &self.config.headers_to_remove {
            request.headers.remove(header_name);
        }
        
        // Add conditional headers
        for conditional in &self.config.conditional_headers {
            if self.evaluate_condition(&conditional.condition, request, context) {
                request.headers.insert(
                    conditional.header_name.clone(), 
                    conditional.header_value.clone()
                );
            }
        }
        
        Ok(())
    }
    
    async fn process_response(
        &self, 
        response: &mut Response, 
        _context: &RequestContext
    ) -> GatewayResult<()> {
        // Add response headers
        response.headers.insert("X-Gateway".to_string(), "rust-api-gateway".to_string());
        Ok(())
    }
    
    async fn on_error(
        &self, 
        _error: &GatewayError, 
        _context: &RequestContext
    ) -> GatewayResult<Option<Response>> {
        // Don't handle errors in this middleware
        Ok(None)
    }
}

impl CustomHeaderMiddleware {
    pub fn new(config: CustomHeaderConfig) -> Self {
        Self { config }
    }
    
    fn evaluate_condition(
        &self, 
        condition: &str, 
        request: &Request, 
        _context: &RequestContext
    ) -> bool {
        // Simple condition evaluation
        if let Some(path_prefix) = condition.strip_prefix("path_starts_with:") {
            return request.path.starts_with(path_prefix);
        }
        
        if let Some(method) = condition.strip_prefix("method_equals:") {
            return request.method.eq_ignore_ascii_case(method);
        }
        
        // Add more condition types as needed
        false
    }
}
```

### Advanced Middleware: Request Validation

```rust
use jsonschema::{JSONSchema, ValidationError};
use serde_json::Value;

pub struct RequestValidationMiddleware {
    schemas: HashMap<String, JSONSchema>,
}

impl Plugin for RequestValidationMiddleware {
    fn name(&self) -> &'static str { "request_validation" }
    fn version(&self) -> &'static str { "1.0.0" }
    fn description(&self) -> &'static str { "Validates request payloads against JSON schemas" }
}

#[async_trait]
impl Middleware for RequestValidationMiddleware {
    async fn process_request(
        &self, 
        request: &mut Request, 
        context: &mut RequestContext
    ) -> GatewayResult<()> {
        // Only validate POST/PUT requests with JSON content
        if !matches!(request.method.as_str(), "POST" | "PUT") {
            return Ok(());
        }
        
        let content_type = request.headers.get("content-type")
            .unwrap_or(&"".to_string());
            
        if !content_type.contains("application/json") {
            return Ok(());
        }
        
        // Get schema for this route
        let route_key = format!("{}:{}", request.method, request.path);
        if let Some(schema) = self.schemas.get(&route_key) {
            // Parse request body as JSON
            let body_json: Value = serde_json::from_slice(&request.body)
                .map_err(|e| GatewayError::BadRequest(format!("Invalid JSON: {}", e)))?;
            
            // Validate against schema
            if let Err(errors) = schema.validate(&body_json) {
                let error_messages: Vec<String> = errors
                    .map(|e| format!("{}: {}", e.instance_path, e))
                    .collect();
                
                return Err(GatewayError::BadRequest(
                    format!("Validation failed: {}", error_messages.join(", "))
                ));
            }
        }
        
        Ok(())
    }
    
    async fn process_response(
        &self, 
        _response: &mut Response, 
        _context: &RequestContext
    ) -> GatewayResult<()> {
        Ok(())
    }
    
    async fn on_error(
        &self, 
        _error: &GatewayError, 
        _context: &RequestContext
    ) -> GatewayResult<Option<Response>> {
        Ok(None)
    }
}
```

## Authentication Providers

Custom authentication providers allow you to integrate with any authentication system.

### Authentication Provider Interface

```rust
#[async_trait]
pub trait AuthProvider: Send + Sync + Plugin {
    /// Authenticate a request and return user context
    async fn authenticate(&self, request: &Request) -> GatewayResult<Option<AuthContext>>;
    
    /// Check if user has permission for a specific action
    async fn authorize(
        &self, 
        context: &AuthContext, 
        resource: &str, 
        action: &str
    ) -> GatewayResult<bool>;
}

#[derive(Debug, Clone)]
pub struct AuthContext {
    pub user_id: String,
    pub username: String,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
    pub metadata: HashMap<String, String>,
}
```

### Example: Custom Database Auth Provider

```rust
use sqlx::{PgPool, Row};
use sha2::{Sha256, Digest};

pub struct DatabaseAuthProvider {
    pool: PgPool,
    hash_secret: String,
}

impl Plugin for DatabaseAuthProvider {
    fn name(&self) -> &'static str { "database_auth" }
    fn version(&self) -> &'static str { "1.0.0" }
    fn description(&self) -> &'static str { "Database-backed authentication" }
}

#[async_trait]
impl AuthProvider for DatabaseAuthProvider {
    async fn authenticate(&self, request: &Request) -> GatewayResult<Option<AuthContext>> {
        // Extract API key from header
        let api_key = request.headers.get("X-API-Key")
            .ok_or_else(|| GatewayError::Unauthorized("Missing API key".to_string()))?;
        
        // Hash the API key
        let mut hasher = Sha256::new();
        hasher.update(api_key.as_bytes());
        hasher.update(self.hash_secret.as_bytes());
        let hashed_key = format!("{:x}", hasher.finalize());
        
        // Query database for user
        let row = sqlx::query(
            "SELECT user_id, username, roles, permissions FROM api_keys WHERE key_hash = $1 AND active = true"
        )
        .bind(&hashed_key)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| GatewayError::Internal(format!("Database error: {}", e)))?;
        
        if let Some(row) = row {
            let roles: Vec<String> = row.get::<Vec<String>, _>("roles");
            let permissions: Vec<String> = row.get::<Vec<String>, _>("permissions");
            
            Ok(Some(AuthContext {
                user_id: row.get("user_id"),
                username: row.get("username"),
                roles,
                permissions,
                metadata: HashMap::new(),
            }))
        } else {
            Err(GatewayError::Unauthorized("Invalid API key".to_string()))
        }
    }
    
    async fn authorize(
        &self, 
        context: &AuthContext, 
        resource: &str, 
        action: &str
    ) -> GatewayResult<bool> {
        // Check if user has specific permission
        let required_permission = format!("{}:{}", resource, action);
        
        if context.permissions.contains(&required_permission) {
            return Ok(true);
        }
        
        // Check role-based permissions
        for role in &context.roles {
            if self.role_has_permission(role, &required_permission).await? {
                return Ok(true);
            }
        }
        
        Ok(false)
    }
}

impl DatabaseAuthProvider {
    pub fn new(pool: PgPool, hash_secret: String) -> Self {
        Self { pool, hash_secret }
    }
    
    async fn role_has_permission(&self, role: &str, permission: &str) -> GatewayResult<bool> {
        let row = sqlx::query(
            "SELECT COUNT(*) as count FROM role_permissions WHERE role = $1 AND permission = $2"
        )
        .bind(role)
        .bind(permission)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| GatewayError::Internal(format!("Database error: {}", e)))?;
        
        Ok(row.get::<i64, _>("count") > 0)
    }
}
```

## Load Balancing Strategies

Custom load balancing strategies allow you to implement domain-specific routing logic.

### Load Balancer Interface

```rust
#[async_trait]
pub trait LoadBalancer: Send + Sync + Plugin {
    /// Select an instance from available instances
    async fn select_instance(
        &self, 
        instances: &[ServiceInstance], 
        request: &Request
    ) -> Option<&ServiceInstance>;
    
    /// Update instance weights or state
    async fn update_instance(&self, instance: &ServiceInstance, metrics: &InstanceMetrics);
}
```

### Example: Geographic Load Balancer

```rust
use std::collections::HashMap;
use geoip2::Reader;

pub struct GeographicLoadBalancer {
    geoip_reader: Reader<Vec<u8>>,
    region_preferences: HashMap<String, Vec<String>>, // region -> preferred zones
}

impl Plugin for GeographicLoadBalancer {
    fn name(&self) -> &'static str { "geographic_lb" }
    fn version(&self) -> &'static str { "1.0.0" }
    fn description(&self) -> &'static str { "Routes requests based on client geography" }
}

#[async_trait]
impl LoadBalancer for GeographicLoadBalancer {
    async fn select_instance(
        &self, 
        instances: &[ServiceInstance], 
        request: &Request
    ) -> Option<&ServiceInstance> {
        // Get client IP from request
        let client_ip = self.extract_client_ip(request)?;
        
        // Look up geographic location
        let country = self.geoip_reader.lookup::<geoip2::Country>(client_ip)
            .ok()?
            .country?
            .iso_code?;
        
        // Find preferred zones for this country
        let preferred_zones = self.region_preferences.get(country)?;
        
        // Filter instances by preferred zones
        let preferred_instances: Vec<&ServiceInstance> = instances
            .iter()
            .filter(|instance| {
                if let Some(zone) = instance.metadata.get("zone") {
                    preferred_zones.contains(zone)
                } else {
                    false
                }
            })
            .collect();
        
        if !preferred_instances.is_empty() {
            // Use round-robin among preferred instances
            let index = fastrand::usize(..preferred_instances.len());
            Some(preferred_instances[index])
        } else {
            // Fallback to any available instance
            let index = fastrand::usize(..instances.len());
            instances.get(index)
        }
    }
    
    async fn update_instance(&self, _instance: &ServiceInstance, _metrics: &InstanceMetrics) {
        // Geographic load balancer doesn't need to track metrics
    }
}

impl GeographicLoadBalancer {
    fn extract_client_ip(&self, request: &Request) -> Option<std::net::IpAddr> {
        // Check X-Forwarded-For header first
        if let Some(forwarded) = request.headers.get("X-Forwarded-For") {
            if let Some(ip_str) = forwarded.split(',').next() {
                if let Ok(ip) = ip_str.trim().parse() {
                    return Some(ip);
                }
            }
        }
        
        // Check X-Real-IP header
        if let Some(real_ip) = request.headers.get("X-Real-IP") {
            if let Ok(ip) = real_ip.parse() {
                return Some(ip);
            }
        }
        
        // Use remote address as fallback
        request.remote_addr.map(|addr| addr.ip())
    }
}
```

## Service Discovery Plugins

Custom service discovery plugins allow integration with any service registry.

### Service Discovery Interface

```rust
#[async_trait]
pub trait ServiceDiscovery: Send + Sync + Plugin {
    /// Discover available services
    async fn discover_services(&self) -> GatewayResult<Vec<ServiceInstance>>;
    
    /// Register a service instance
    async fn register_service(&self, service: ServiceInstance) -> GatewayResult<()>;
    
    /// Deregister a service instance
    async fn deregister_service(&self, service_id: &str) -> GatewayResult<()>;
    
    /// Watch for service changes
    async fn watch_changes(&self) -> GatewayResult<ServiceChangeStream>;
}
```

### Example: Etcd Service Discovery

```rust
use etcd_rs::{Client, GetOptions, WatchOptions};
use tokio_stream::StreamExt;

pub struct EtcdServiceDiscovery {
    client: Client,
    key_prefix: String,
}

impl Plugin for EtcdServiceDiscovery {
    fn name(&self) -> &'static str { "etcd_discovery" }
    fn version(&self) -> &'static str { "1.0.0" }
    fn description(&self) -> &'static str { "Etcd-based service discovery" }
}

#[async_trait]
impl ServiceDiscovery for EtcdServiceDiscovery {
    async fn discover_services(&self) -> GatewayResult<Vec<ServiceInstance>> {
        let mut services = Vec::new();
        
        let resp = self.client
            .get(&self.key_prefix, Some(GetOptions::new().with_prefix()))
            .await
            .map_err(|e| GatewayError::ServiceDiscovery(format!("Etcd error: {}", e)))?;
        
        for kv in resp.kvs() {
            if let Ok(service_json) = std::str::from_utf8(kv.value()) {
                if let Ok(service) = serde_json::from_str::<ServiceInstance>(service_json) {
                    services.push(service);
                }
            }
        }
        
        Ok(services)
    }
    
    async fn register_service(&self, service: ServiceInstance) -> GatewayResult<()> {
        let key = format!("{}/{}", self.key_prefix, service.id);
        let value = serde_json::to_string(&service)
            .map_err(|e| GatewayError::Internal(format!("Serialization error: {}", e)))?;
        
        self.client
            .put(&key, value, None)
            .await
            .map_err(|e| GatewayError::ServiceDiscovery(format!("Etcd error: {}", e)))?;
        
        Ok(())
    }
    
    async fn deregister_service(&self, service_id: &str) -> GatewayResult<()> {
        let key = format!("{}/{}", self.key_prefix, service_id);
        
        self.client
            .delete(&key, None)
            .await
            .map_err(|e| GatewayError::ServiceDiscovery(format!("Etcd error: {}", e)))?;
        
        Ok(())
    }
    
    async fn watch_changes(&self) -> GatewayResult<ServiceChangeStream> {
        let watch_stream = self.client
            .watch(&self.key_prefix, Some(WatchOptions::new().with_prefix()))
            .await
            .map_err(|e| GatewayError::ServiceDiscovery(format!("Etcd error: {}", e)))?;
        
        let change_stream = watch_stream.map(|watch_resp| {
            let mut changes = Vec::new();
            
            for event in watch_resp.events() {
                match event.event_type() {
                    etcd_rs::EventType::Put => {
                        if let Ok(service_json) = std::str::from_utf8(event.kv().value()) {
                            if let Ok(service) = serde_json::from_str::<ServiceInstance>(service_json) {
                                changes.push(ServiceChange::Added(service));
                            }
                        }
                    }
                    etcd_rs::EventType::Delete => {
                        let key = std::str::from_utf8(event.kv().key()).unwrap_or("");
                        if let Some(service_id) = key.strip_prefix(&format!("{}/", self.key_prefix)) {
                            changes.push(ServiceChange::Removed(service_id.to_string()));
                        }
                    }
                }
            }
            
            changes
        });
        
        Ok(Box::pin(change_stream))
    }
}
```

## Testing Plugins

### Unit Testing

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::{Request, RequestContext};
    
    #[tokio::test]
    async fn test_custom_header_middleware() {
        let config = CustomHeaderConfig {
            headers_to_add: [("X-Custom".to_string(), "test-value".to_string())]
                .iter().cloned().collect(),
            headers_to_remove: vec!["X-Remove-Me".to_string()],
            conditional_headers: vec![],
        };
        
        let middleware = CustomHeaderMiddleware::new(config);
        let mut request = Request {
            method: "GET".to_string(),
            path: "/test".to_string(),
            headers: [("X-Remove-Me".to_string(), "should-be-removed".to_string())]
                .iter().cloned().collect(),
            body: vec![],
            remote_addr: None,
        };
        let mut context = RequestContext::new();
        
        middleware.process_request(&mut request, &mut context).await.unwrap();
        
        assert_eq!(request.headers.get("X-Custom"), Some(&"test-value".to_string()));
        assert!(!request.headers.contains_key("X-Remove-Me"));
    }
}
```

### Integration Testing

```rust
#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::gateway::server::GatewayServer;
    use axum_test::TestServer;
    
    #[tokio::test]
    async fn test_plugin_integration() {
        // Create test server with plugin
        let mut registry = PluginRegistry::new();
        registry.register_middleware("custom_header", CustomHeaderMiddleware::new(test_config()));
        
        let server = GatewayServer::new_with_plugins(test_router(), registry).await.unwrap();
        let test_server = TestServer::new(server.into_make_service()).unwrap();
        
        // Test request with plugin
        let response = test_server
            .get("/test")
            .await;
        
        assert_eq!(response.status_code(), 200);
        assert_eq!(response.header("X-Custom"), Some("test-value"));
    }
}
```

## Plugin Examples

### Rate Limiting Plugin

```rust
use std::time::{Duration, Instant};
use dashmap::DashMap;

pub struct CustomRateLimiter {
    buckets: DashMap<String, TokenBucket>,
    requests_per_minute: u32,
    burst_size: u32,
}

struct TokenBucket {
    tokens: u32,
    last_refill: Instant,
}

impl Plugin for CustomRateLimiter {
    fn name(&self) -> &'static str { "custom_rate_limiter" }
    fn version(&self) -> &'static str { "1.0.0" }
    fn description(&self) -> &'static str { "Token bucket rate limiter" }
}

#[async_trait]
impl Middleware for CustomRateLimiter {
    async fn process_request(
        &self, 
        request: &mut Request, 
        context: &mut RequestContext
    ) -> GatewayResult<()> {
        let key = self.generate_key(request, context);
        
        let mut bucket = self.buckets.entry(key).or_insert_with(|| TokenBucket {
            tokens: self.burst_size,
            last_refill: Instant::now(),
        });
        
        // Refill tokens based on time elapsed
        let now = Instant::now();
        let elapsed = now.duration_since(bucket.last_refill);
        let tokens_to_add = (elapsed.as_secs() * self.requests_per_minute as u64 / 60) as u32;
        
        if tokens_to_add > 0 {
            bucket.tokens = (bucket.tokens + tokens_to_add).min(self.burst_size);
            bucket.last_refill = now;
        }
        
        // Check if request is allowed
        if bucket.tokens > 0 {
            bucket.tokens -= 1;
            Ok(())
        } else {
            Err(GatewayError::RateLimitExceeded)
        }
    }
    
    async fn process_response(
        &self, 
        _response: &mut Response, 
        _context: &RequestContext
    ) -> GatewayResult<()> {
        Ok(())
    }
    
    async fn on_error(
        &self, 
        _error: &GatewayError, 
        _context: &RequestContext
    ) -> GatewayResult<Option<Response>> {
        Ok(None)
    }
}

impl CustomRateLimiter {
    fn generate_key(&self, request: &Request, context: &RequestContext) -> String {
        // Use client IP as key
        if let Some(addr) = request.remote_addr {
            addr.ip().to_string()
        } else if let Some(forwarded) = request.headers.get("X-Forwarded-For") {
            forwarded.split(',').next().unwrap_or("unknown").trim().to_string()
        } else {
            "unknown".to_string()
        }
    }
}
```

## Best Practices

### Performance Considerations

1. **Avoid Blocking Operations**: Use async/await for all I/O operations
2. **Minimize Allocations**: Reuse buffers and avoid unnecessary cloning
3. **Use Efficient Data Structures**: Choose appropriate collections (DashMap for concurrent access)
4. **Profile Your Plugins**: Use cargo flamegraph to identify bottlenecks

### Error Handling

1. **Use Structured Errors**: Implement proper error types with context
2. **Fail Fast**: Validate configuration early during plugin initialization
3. **Graceful Degradation**: Handle errors without crashing the gateway
4. **Logging**: Use structured logging for debugging

### Configuration

1. **Validate Configuration**: Implement comprehensive validation
2. **Use Serde**: Leverage serde for configuration serialization/deserialization
3. **Environment Variables**: Support environment variable overrides
4. **Documentation**: Document all configuration options

### Testing

1. **Unit Tests**: Test individual plugin functions
2. **Integration Tests**: Test plugins within the gateway context
3. **Property-Based Testing**: Use proptest for comprehensive testing
4. **Benchmarks**: Include performance benchmarks

### Security

1. **Input Validation**: Validate all inputs thoroughly
2. **Sanitization**: Sanitize data before logging or storing
3. **Least Privilege**: Request minimal permissions
4. **Audit Logging**: Log security-relevant events

This plugin development guide provides the foundation for extending the Rust API Gateway. The trait-based architecture ensures type safety while allowing for flexible customization of gateway behavior.