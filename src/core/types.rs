//! # Core Types Module
//!
//! This module defines the foundational data structures and traits used throughout the API Gateway.
//! It includes request/response types, context objects, and core abstractions that enable
//! the gateway's pluggable architecture.
//!
//! ## Rust Ownership Concepts in This Module
//!
//! - `Arc<T>` (Atomically Reference Counted) allows multiple owners of the same data
//! - `Clone` trait enables creating copies of data structures
//! - `Send + Sync` traits ensure types can be safely shared between threads
//! - Lifetime parameters (`'a`) specify how long references are valid
//! - `Box<dyn Trait>` enables dynamic dispatch for trait objects

use axum::http::{HeaderMap, Method, StatusCode, Uri, Version};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use uuid::Uuid;

/// Supported communication protocols
///
/// The gateway can handle multiple protocols, each with different characteristics.
/// This enum allows us to dispatch requests to the appropriate protocol handler.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Protocol {
    /// HTTP/1.1 and HTTP/2 REST APIs
    Http,
    /// gRPC over HTTP/2
    Grpc,
    /// WebSocket connections for real-time communication
    WebSocket,
    /// Raw TCP connections (for future extensibility)
    Tcp,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Http => write!(f, "HTTP"),
            Protocol::Grpc => write!(f, "gRPC"),
            Protocol::WebSocket => write!(f, "WebSocket"),
            Protocol::Tcp => write!(f, "TCP"),
        }
    }
}

/// Represents an incoming request before protocol-specific processing
///
/// This is the unified request type that all protocol handlers work with.
/// It abstracts away protocol-specific details while preserving essential information.
#[derive(Debug, Clone)]
pub struct IncomingRequest {
    /// Unique identifier for this request (for tracing and logging)
    pub id: String,
    
    /// Detected or specified protocol
    pub protocol: Protocol,
    
    /// HTTP method (GET, POST, etc.) - may be empty for non-HTTP protocols
    pub method: Method,
    
    /// Request URI including path and query parameters
    pub uri: Uri,
    
    /// HTTP version (1.0, 1.1, 2.0)
    pub version: Version,
    
    /// Request headers
    pub headers: HeaderMap,
    
    /// Request body as bytes
    /// Using Arc to avoid copying large payloads when cloning the request
    pub body: Arc<Vec<u8>>,
    
    /// Client's remote address
    pub remote_addr: SocketAddr,
    
    /// Timestamp when the request was received
    pub received_at: Instant,
    
    /// Additional metadata that can be set by middleware
    pub metadata: HashMap<String, serde_json::Value>,
}

impl IncomingRequest {
    /// Create a new incoming request with a generated ID
    pub fn new(
        protocol: Protocol,
        method: Method,
        uri: Uri,
        version: Version,
        headers: HeaderMap,
        body: Vec<u8>,
        remote_addr: SocketAddr,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            protocol,
            method,
            uri,
            version,
            headers,
            body: Arc::new(body),
            remote_addr,
            received_at: Instant::now(),
            metadata: HashMap::new(),
        }
    }

    /// Get the request path without query parameters
    pub fn path(&self) -> &str {
        self.uri.path()
    }

    /// Get query parameters as a string
    pub fn query(&self) -> Option<&str> {
        self.uri.query()
    }

    /// Get a header value by name
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(name)
            .and_then(|value| value.to_str().ok())
    }

    /// Check if this is a WebSocket upgrade request
    pub fn is_websocket_upgrade(&self) -> bool {
        self.header("upgrade").map(|v| v.to_lowercase()) == Some("websocket".to_string())
            && self.header("connection").map(|v| v.to_lowercase().contains("upgrade")) == Some(true)
    }

    /// Detect protocol from request characteristics
    pub fn detect_protocol(&self) -> Protocol {
        // Check for WebSocket upgrade
        if self.is_websocket_upgrade() {
            return Protocol::WebSocket;
        }

        // Check for gRPC (Content-Type: application/grpc)
        if let Some(content_type) = self.header("content-type") {
            if content_type.starts_with("application/grpc") {
                return Protocol::Grpc;
            }
        }

        // Default to HTTP
        Protocol::Http
    }
}

/// Request context that flows through the middleware pipeline
///
/// This context object carries information about the request as it flows through
/// various middleware components. It's designed to be cheaply cloneable using Arc.
#[derive(Debug, Clone)]
pub struct RequestContext {
    /// Reference to the original request
    pub request: Arc<IncomingRequest>,
    
    /// Unique trace ID for distributed tracing
    pub trace_id: String,
    
    /// Authentication context (if authenticated)
    pub auth_context: Option<Arc<AuthContext>>,
    
    /// Matched route information
    pub route: Option<Arc<RouteMatch>>,
    
    /// Available upstream service instances
    pub upstream_instances: Vec<Arc<ServiceInstance>>,
    
    /// Selected upstream instance for this request
    pub selected_instance: Option<Arc<ServiceInstance>>,
    
    /// Request start time for latency measurement
    pub start_time: Instant,
    
    /// Additional context data that middleware can set
    pub data: HashMap<String, serde_json::Value>,
}

impl RequestContext {
    /// Create a new request context
    pub fn new(request: Arc<IncomingRequest>) -> Self {
        Self {
            trace_id: Uuid::new_v4().to_string(),
            request,
            auth_context: None,
            route: None,
            upstream_instances: Vec::new(),
            selected_instance: None,
            start_time: Instant::now(),
            data: HashMap::new(),
        }
    }

    /// Get elapsed time since request started
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Set authentication context
    pub fn set_auth_context(&mut self, auth: AuthContext) {
        self.auth_context = Some(Arc::new(auth));
    }

    /// Set matched route
    pub fn set_route(&mut self, route: RouteMatch) {
        self.route = Some(Arc::new(route));
    }

    /// Set available upstream instances
    pub fn set_upstream_instances(&mut self, instances: Vec<ServiceInstance>) {
        self.upstream_instances = instances.into_iter().map(Arc::new).collect();
    }

    /// Set the selected upstream instance
    pub fn set_selected_instance(&mut self, instance: ServiceInstance) {
        self.selected_instance = Some(Arc::new(instance));
    }
}

/// Authentication context containing user information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthContext {
    /// Unique user identifier
    pub user_id: String,
    
    /// User roles for authorization
    pub roles: Vec<String>,
    
    /// Specific permissions granted to the user
    pub permissions: Vec<String>,
    
    /// Additional claims from JWT or other auth providers
    pub claims: HashMap<String, serde_json::Value>,
    
    /// Authentication method used
    pub auth_method: String,
    
    /// Token expiration time (if applicable)
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl AuthContext {
    /// Check if user has a specific role
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.contains(&role.to_string())
    }

    /// Check if user has a specific permission
    pub fn has_permission(&self, permission: &str) -> bool {
        self.permissions.contains(&permission.to_string())
    }

    /// Check if authentication is expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            chrono::Utc::now() > expires_at
        } else {
            false
        }
    }
}

/// Route matching result with extracted parameters
#[derive(Debug, Clone)]
pub struct RouteMatch {
    /// The matched route pattern
    pub pattern: String,
    
    /// Extracted path parameters (e.g., /users/{id} -> {"id": "123"})
    pub params: HashMap<String, String>,
    
    /// Query parameters
    pub query_params: HashMap<String, String>,
    
    /// Target upstream service name
    pub upstream: String,
    
    /// Route-specific configuration
    pub config: RouteConfig,
}

/// Route configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteConfig {
    /// Request timeout for this route
    pub timeout: Option<Duration>,
    
    /// Retry policy
    pub retry_policy: Option<RetryPolicy>,
    
    /// Rate limiting configuration
    pub rate_limit: Option<RateLimitConfig>,
    
    /// Required authentication
    pub auth_required: bool,
    
    /// Required roles/permissions
    pub required_roles: Vec<String>,
    pub required_permissions: Vec<String>,
    
    /// Middleware to apply to this route
    pub middleware: Vec<String>,
}

impl Default for RouteConfig {
    fn default() -> Self {
        Self {
            timeout: Some(Duration::from_secs(30)),
            retry_policy: None,
            rate_limit: None,
            auth_required: false,
            required_roles: Vec::new(),
            required_permissions: Vec::new(),
            middleware: Vec::new(),
        }
    }
}

/// Retry policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryPolicy {
    /// Maximum number of retry attempts
    pub max_attempts: u32,
    
    /// Base delay between retries
    pub base_delay: Duration,
    
    /// Maximum delay between retries
    pub max_delay: Duration,
    
    /// Backoff multiplier (exponential backoff)
    pub backoff_multiplier: f64,
    
    /// HTTP status codes that should trigger retries
    pub retryable_status_codes: Vec<u16>,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(5),
            backoff_multiplier: 2.0,
            retryable_status_codes: vec![502, 503, 504],
        }
    }
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum requests per window
    pub limit: u32,
    
    /// Time window for rate limiting
    pub window: Duration,
    
    /// Rate limiting key (e.g., "ip", "user", "api_key")
    pub key: String,
}

/// Service instance information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInstance {
    /// Unique instance identifier
    pub id: String,
    
    /// Service name
    pub name: String,
    
    /// Instance address
    pub address: SocketAddr,
    
    /// Instance metadata
    pub metadata: HashMap<String, String>,
    
    /// Health status
    pub health_status: HealthStatus,
    
    /// Protocol supported by this instance
    pub protocol: Protocol,
    
    /// Instance weight for load balancing
    pub weight: u32,
    
    /// Last health check timestamp (skip serialization for Instant)
    #[serde(skip)]
    pub last_health_check: Option<Instant>,
}

impl ServiceInstance {
    /// Create a new service instance
    pub fn new(
        id: String,
        name: String,
        address: SocketAddr,
        protocol: Protocol,
    ) -> Self {
        Self {
            id,
            name,
            address,
            metadata: HashMap::new(),
            health_status: HealthStatus::Unknown,
            protocol,
            weight: 1,
            last_health_check: None,
        }
    }

    /// Check if instance is healthy
    pub fn is_healthy(&self) -> bool {
        matches!(self.health_status, HealthStatus::Healthy)
    }

    /// Get instance URL
    pub fn url(&self) -> String {
        match self.protocol {
            Protocol::Http => format!("http://{}", self.address),
            Protocol::Grpc => format!("http://{}", self.address), // gRPC over HTTP/2
            Protocol::WebSocket => format!("ws://{}", self.address),
            Protocol::Tcp => self.address.to_string(),
        }
    }
}

/// Health status of a service instance
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    /// Instance is healthy and ready to receive traffic
    Healthy,
    /// Instance is unhealthy and should not receive traffic
    Unhealthy,
    /// Health status is unknown (e.g., not yet checked)
    Unknown,
    /// Instance is starting up
    Starting,
    /// Instance is shutting down
    Stopping,
}

impl fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HealthStatus::Healthy => write!(f, "healthy"),
            HealthStatus::Unhealthy => write!(f, "unhealthy"),
            HealthStatus::Unknown => write!(f, "unknown"),
            HealthStatus::Starting => write!(f, "starting"),
            HealthStatus::Stopping => write!(f, "stopping"),
        }
    }
}

/// Response from the gateway
#[derive(Debug, Clone)]
pub struct GatewayResponse {
    /// HTTP status code
    pub status: StatusCode,
    
    /// Response headers
    pub headers: HeaderMap,
    
    /// Response body
    pub body: Arc<Vec<u8>>,
    
    /// Processing time
    pub processing_time: Duration,
    
    /// Upstream instance that handled the request
    pub upstream_instance: Option<Arc<ServiceInstance>>,
}

impl GatewayResponse {
    /// Create a new response
    pub fn new(status: StatusCode, headers: HeaderMap, body: Vec<u8>) -> Self {
        Self {
            status,
            headers,
            body: Arc::new(body),
            processing_time: Duration::from_millis(0),
            upstream_instance: None,
        }
    }

    /// Create a simple text response
    pub fn text(status: StatusCode, text: String) -> Self {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "text/plain".parse().unwrap());
        Self::new(status, headers, text.into_bytes())
    }

    /// Create a JSON response
    pub fn json<T: Serialize>(status: StatusCode, data: &T) -> Result<Self, serde_json::Error> {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "application/json".parse().unwrap());
        let body = serde_json::to_vec(data)?;
        Ok(Self::new(status, headers, body))
    }

    /// Create an error response
    pub fn error(status: StatusCode, message: String) -> Self {
        let error_body = serde_json::json!({
            "error": {
                "code": status.as_u16(),
                "message": message
            }
        });
        Self::json(status, &error_body).unwrap_or_else(|_| {
            Self::text(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string())
        })
    }
}

/// Event types for the gateway event system
///
/// This enum represents different events that can occur during request processing.
/// Components can subscribe to these events for monitoring, logging, or custom logic.
#[derive(Debug, Clone)]
pub enum GatewayEvent {
    /// Request received
    RequestReceived {
        request_id: String,
        protocol: Protocol,
        path: String,
        method: String,
    },
    
    /// Request routed to upstream
    RequestRouted {
        request_id: String,
        upstream: String,
        instance: String,
    },
    
    /// Response received from upstream
    ResponseReceived {
        request_id: String,
        status: u16,
        processing_time: Duration,
    },
    
    /// Request completed
    RequestCompleted {
        request_id: String,
        status: u16,
        total_time: Duration,
    },
    
    /// Service instance health changed
    ServiceHealthChanged {
        service: String,
        instance: String,
        old_status: HealthStatus,
        new_status: HealthStatus,
    },
    
    /// Circuit breaker state changed
    CircuitBreakerStateChanged {
        service: String,
        old_state: String,
        new_state: String,
    },
    
    /// Rate limit exceeded
    RateLimitExceeded {
        key: String,
        limit: u32,
        window: String,
    },
}

/// Event publisher for the gateway event system
///
/// This type allows components to publish events that other components can subscribe to.
/// It uses Tokio's broadcast channel for efficient multi-subscriber event distribution.
pub type EventPublisher = tokio::sync::broadcast::Sender<GatewayEvent>;

/// Event subscriber for receiving gateway events
pub type EventSubscriber = tokio::sync::broadcast::Receiver<GatewayEvent>;

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Method;

    #[test]
    fn test_incoming_request_creation() {
        let request = IncomingRequest::new(
            Protocol::Http,
            Method::GET,
            "/api/users".parse().unwrap(),
            Version::HTTP_11,
            HeaderMap::new(),
            b"test body".to_vec(),
            "127.0.0.1:8080".parse().unwrap(),
        );

        assert_eq!(request.protocol, Protocol::Http);
        assert_eq!(request.method, Method::GET);
        assert_eq!(request.path(), "/api/users");
        assert!(!request.id.is_empty());
    }

    #[test]
    fn test_protocol_detection() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "application/grpc".parse().unwrap());
        
        let request = IncomingRequest::new(
            Protocol::Http,
            Method::POST,
            "/service.Method".parse().unwrap(),
            Version::HTTP_2,
            headers,
            Vec::new(),
            "127.0.0.1:8080".parse().unwrap(),
        );

        assert_eq!(request.detect_protocol(), Protocol::Grpc);
    }

    #[test]
    fn test_websocket_detection() {
        let mut headers = HeaderMap::new();
        headers.insert("upgrade", "websocket".parse().unwrap());
        headers.insert("connection", "upgrade".parse().unwrap());
        
        let request = IncomingRequest::new(
            Protocol::Http,
            Method::GET,
            "/ws".parse().unwrap(),
            Version::HTTP_11,
            headers,
            Vec::new(),
            "127.0.0.1:8080".parse().unwrap(),
        );

        assert!(request.is_websocket_upgrade());
        assert_eq!(request.detect_protocol(), Protocol::WebSocket);
    }

    #[test]
    fn test_auth_context() {
        let auth = AuthContext {
            user_id: "user123".to_string(),
            roles: vec!["admin".to_string(), "user".to_string()],
            permissions: vec!["read".to_string(), "write".to_string()],
            claims: HashMap::new(),
            auth_method: "jwt".to_string(),
            expires_at: None,
        };

        assert!(auth.has_role("admin"));
        assert!(auth.has_permission("read"));
        assert!(!auth.has_role("guest"));
        assert!(!auth.is_expired());
    }

    #[test]
    fn test_service_instance() {
        let instance = ServiceInstance::new(
            "instance-1".to_string(),
            "api-service".to_string(),
            "127.0.0.1:8080".parse().unwrap(),
            Protocol::Http,
        );

        assert_eq!(instance.url(), "http://127.0.0.1:8080");
        assert!(!instance.is_healthy()); // Default is Unknown
    }

    #[test]
    fn test_gateway_response() {
        let response = GatewayResponse::text(StatusCode::OK, "Hello, World!".to_string());
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body.as_ref(), b"Hello, World!");
    }
}