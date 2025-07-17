//! # HTTP Server Module
//!
//! This module implements the basic HTTP server using the Axum framework.
//! It handles incoming requests, performs protocol detection, creates request contexts,
//! and routes requests through the middleware pipeline.
//!
//! ## Rust Concepts Used
//!
//! - `Arc<T>` for sharing server state across async tasks
//! - `async/await` for non-blocking I/O operations
//! - `tokio::net::TcpListener` for accepting incoming connections
//! - Axum's handler system for request processing
//! - Tower middleware for request/response processing

use crate::core::error::{GatewayError, GatewayResult};
use crate::routing::router::Router;
use crate::core::types::{IncomingRequest, RequestContext, Protocol};
use crate::admin::{AdminRouter, AdminState};
use crate::admin::config_manager::RuntimeConfigManager;
use crate::admin::audit::ConfigAudit;
use crate::admin::circuit_breaker::{CircuitBreakerAdminRouter, CircuitBreakerAdminState};

use crate::observability::health::{HealthChecker, HealthCheckConfig};
use crate::middleware::circuit_breaker::{CircuitBreakerLayer, CircuitBreakerMiddlewareConfig};
use crate::middleware::transformation::TransformationLayer;
use crate::core::config::TransformationConfig;
use axum::{
    body::Body,
    extract::{Request, State},
    http::{StatusCode},
    response::{IntoResponse, Response},
    routing::any,
    Router as AxumRouter,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::{
    cors::CorsLayer,
    trace::TraceLayer,
    compression::CompressionLayer,
};
use tracing::{info, warn, debug, instrument};

/// HTTP Server configuration
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Server bind address for gateway routes
    pub bind_addr: SocketAddr,
    
    /// Admin server bind address (separate from gateway)
    pub admin_bind_addr: SocketAddr,
    
    /// Maximum request body size in bytes
    pub max_body_size: usize,
    
    /// Request timeout duration
    pub request_timeout: std::time::Duration,
    
    /// Enable request compression
    pub enable_compression: bool,
    
    /// Enable CORS
    pub enable_cors: bool,
    
    /// Circuit breaker configuration
    pub circuit_breaker: CircuitBreakerMiddlewareConfig,
    
    /// Request/response transformation configuration
    pub transformation: Option<TransformationConfig>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:8080".parse().unwrap(),
            admin_bind_addr: "0.0.0.0:8081".parse().unwrap(),
            max_body_size: 16 * 1024 * 1024, // 16MB
            request_timeout: std::time::Duration::from_secs(30),
            enable_compression: true,
            enable_cors: true,
            circuit_breaker: CircuitBreakerMiddlewareConfig::default(),
            transformation: None,
        }
    }
}

/// Shared server state
#[derive(Clone)]
pub struct ServerState {
    /// Request router
    pub router: Arc<Router>,
    
    /// Server configuration
    pub config: ServerConfig,
    
    /// Circuit breaker layer for upstream service protection
    pub circuit_breaker_layer: CircuitBreakerLayer,
}

impl ServerState {
    /// Create new server state
    pub fn new(router: Router, config: ServerConfig, circuit_breaker_layer: CircuitBreakerLayer) -> Self {
        Self {
            router: Arc::new(router),
            config,
            circuit_breaker_layer,
        }
    }
}

/// HTTP Server implementation
pub struct GatewayServer {
    /// Server state shared across handlers
    state: ServerState,
    
    /// Axum application router for gateway routes
    gateway_app: AxumRouter,
    
    /// Axum application router for admin routes
    admin_app: AxumRouter,
    
    /// Health checker for monitoring service health
    health_checker: Arc<HealthChecker>,
    
    /// Circuit breaker layer for middleware integration
    circuit_breaker_layer: CircuitBreakerLayer,
}

impl GatewayServer {
    /// Create a new HTTP server with separated admin and gateway routes
    pub fn new(router: Router, config: ServerConfig) -> Self {
        // Create circuit breaker layer first
        let circuit_breaker_layer = CircuitBreakerLayer::new(config.circuit_breaker.clone());
        
        // Create server state with circuit breaker layer
        let state = ServerState::new(router, config.clone(), circuit_breaker_layer.clone());
        
        // Create health checker
        let health_checker = Arc::new(HealthChecker::new(None));
        
        // Add default gateway health checks
        Self::setup_default_health_checks(&health_checker, &config);
        
        // Build the gateway application for handling API requests
        let mut gateway_app = AxumRouter::new()
            .route("/*path", any(handle_request))
            .route("/health", axum::routing::get(gateway_health_check))
            .route("/ready", axum::routing::get(gateway_readiness_check))
            .with_state(state.clone());

        // Add middleware layers to gateway app
        // Note: Order matters - compression should be applied last (outermost)
        let service_builder = ServiceBuilder::new()
            .layer(TraceLayer::new_for_http())
            .layer(CompressionLayer::new());

        // Add transformation layer if configured
        if let Some(ref transformation_config) = config.transformation {
            match TransformationLayer::new(transformation_config) {
                Ok(transformation_layer) => {
                    info!("Adding transformation middleware to gateway pipeline");
                    gateway_app = gateway_app.layer(transformation_layer);
                }
                Err(e) => {
                    warn!("Failed to create transformation layer: {}", e);
                }
            }
        }

        gateway_app = gateway_app.layer(service_builder);

        if config.enable_cors {
            gateway_app = gateway_app.layer(CorsLayer::permissive());
        }

        // Create admin application for configuration management
        let admin_app = Self::create_admin_app(state.clone(), circuit_breaker_layer.clone());

        Self { 
            state, 
            gateway_app,
            admin_app,
            health_checker,
            circuit_breaker_layer,
        }
    }

    /// Setup default health checks for the gateway
    fn setup_default_health_checks(health_checker: &Arc<HealthChecker>, config: &ServerConfig) {
        // Add self-health check for the gateway
        let gateway_health_config = HealthCheckConfig {
            name: "gateway-self".to_string(),
            url: format!("http://{}/health", config.bind_addr),
            method: "GET".to_string(),
            headers: std::collections::HashMap::new(),
            body: None,
            interval: std::time::Duration::from_secs(30),
            timeout: std::time::Duration::from_secs(5),
            healthy_threshold: 1,
            unhealthy_threshold: 3,
            expected_status_codes: vec![200],
            expected_body_content: None,
            critical: true,
            enabled: true,
        };
        
        health_checker.add_gateway_health_check("self".to_string(), gateway_health_config);
        
        // Add admin interface health check
        let admin_health_config = HealthCheckConfig {
            name: "admin-interface".to_string(),
            url: format!("http://{}/health", config.admin_bind_addr),
            method: "GET".to_string(),
            headers: std::collections::HashMap::new(),
            body: None,
            interval: std::time::Duration::from_secs(60),
            timeout: std::time::Duration::from_secs(5),
            healthy_threshold: 1,
            unhealthy_threshold: 3,
            expected_status_codes: vec![200],
            expected_body_content: None,
            critical: false,
            enabled: true,
        };
        
        health_checker.add_gateway_health_check("admin".to_string(), admin_health_config);
    }

    /// Create the admin application with configuration management endpoints
    fn create_admin_app(_state: ServerState, circuit_breaker_layer: CircuitBreakerLayer) -> AxumRouter {
        // Create audit trail for configuration changes
        let audit = Arc::new(ConfigAudit::new(Some("audit.log".into())));
        
        // Create runtime configuration manager
        // For now, use a default config - in future tasks this will be loaded from the actual config
        let initial_config = crate::core::config::GatewayConfig::default();
        let config_manager = Arc::new(RuntimeConfigManager::new(initial_config, audit.clone()));
        
        // Create admin state
        let admin_state = AdminState {
            config_manager,
            audit,
            service_management: None, // Service management will be added in future tasks
            load_balancer: None, // Load balancer management will be added when needed
        };

        // Create circuit breaker admin state
        let circuit_breaker_admin_state = CircuitBreakerAdminState::with_layer(
            circuit_breaker_layer.registry(),
            circuit_breaker_layer
        );

        // Create admin router with all endpoints
        let mut admin_app = AdminRouter::create_router(admin_state);

        // Add circuit breaker admin routes
        let circuit_breaker_routes = CircuitBreakerAdminRouter::create_router(circuit_breaker_admin_state);
        admin_app = admin_app.nest("/api/v1/admin", circuit_breaker_routes);

        // Add health check endpoints for admin interface
        admin_app = admin_app
            .route("/health", axum::routing::get(health_check))
            .route("/ready", axum::routing::get(readiness_check));

        // Add middleware layers to admin app
        admin_app = admin_app.layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CompressionLayer::new())
        );

        admin_app
    }

    /// Start both the gateway and admin HTTP servers
    #[instrument(skip(self))]
    pub async fn start(self) -> GatewayResult<()> {
        let gateway_bind_addr = self.state.config.bind_addr;
        let admin_bind_addr = self.state.config.admin_bind_addr;
        
        info!("Starting Gateway HTTP server on {}", gateway_bind_addr);
        info!("Starting Admin HTTP server on {}", admin_bind_addr);
        
        // Create TCP listeners for both servers
        let gateway_listener = TcpListener::bind(gateway_bind_addr)
            .await
            .map_err(|e| GatewayError::internal(format!("Failed to bind gateway server to {}: {}", gateway_bind_addr, e)))?;

        let admin_listener = TcpListener::bind(admin_bind_addr)
            .await
            .map_err(|e| GatewayError::internal(format!("Failed to bind admin server to {}: {}", admin_bind_addr, e)))?;

        info!("Gateway HTTP server listening on {}", gateway_bind_addr);
        info!("Admin HTTP server listening on {}", admin_bind_addr);

        // Start both servers concurrently
        let gateway_server = axum::serve(gateway_listener, self.gateway_app);
        let admin_server = axum::serve(admin_listener, self.admin_app);

        // Use tokio::select to run both servers concurrently
        tokio::select! {
            result = gateway_server => {
                result.map_err(|e| GatewayError::internal(format!("Gateway server error: {}", e)))?;
            }
            result = admin_server => {
                result.map_err(|e| GatewayError::internal(format!("Admin server error: {}", e)))?;
            }
        }

        Ok(())
    }

    /// Get gateway server bind address
    pub fn bind_addr(&self) -> SocketAddr {
        self.state.config.bind_addr
    }

    /// Get admin server bind address
    pub fn admin_bind_addr(&self) -> SocketAddr {
        self.state.config.admin_bind_addr
    }
}

/// Main request handler that processes all incoming requests
#[instrument(skip(state, request), fields(request_id, method, path))]
async fn handle_request(
    State(state): State<ServerState>,
    request: Request,
) -> Result<Response, GatewayError> {
    let start_time = std::time::Instant::now();
    
    // Extract request components
    let (parts, body) = request.into_parts();
    let method = parts.method;
    let uri = parts.uri;
    let version = parts.version;
    let headers = parts.headers;
    
    // Get remote address from extensions (set by proxy/load balancer)
    let remote_addr = parts
        .extensions
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|info| info.0)
        .unwrap_or_else(|| "127.0.0.1:0".parse().unwrap());

    // Read request body
    let body_bytes = match axum::body::to_bytes(body, state.config.max_body_size).await {
        Ok(bytes) => bytes.to_vec(),
        Err(e) => {
            warn!("Failed to read request body: {}", e);
            return Ok(create_error_response(
                StatusCode::BAD_REQUEST,
                "Failed to read request body".to_string(),
            ));
        }
    };

    // Create incoming request
    let incoming_request = IncomingRequest::new(
        Protocol::Http, // Will be updated by protocol detection
        method.clone(),
        uri.clone(),
        version,
        headers.clone(),
        body_bytes,
        remote_addr,
    );

    // Update protocol based on request characteristics
    let mut incoming_request = incoming_request;
    incoming_request.protocol = incoming_request.detect_protocol();

    // Add tracing fields
    tracing::Span::current()
        .record("request_id", &incoming_request.id)
        .record("method", method.as_str())
        .record("path", uri.path());

    debug!(
        request_id = %incoming_request.id,
        protocol = %incoming_request.protocol,
        method = %method,
        path = %uri.path(),
        remote_addr = %remote_addr,
        "Processing incoming request"
    );

    // Create request context
    let mut context = RequestContext::new(Arc::new(incoming_request));

    // Route the request
    if let Some(route_match) = state.router.match_route(&context.request) {
        debug!(
            request_id = %context.request.id,
            pattern = %route_match.pattern,
            upstream = %route_match.upstream,
            params = ?route_match.params,
            "Request matched route"
        );
        
        context.set_route(route_match);
        
        // Get the upstream service name for circuit breaker
        let upstream_service = &context.route.as_ref().unwrap().upstream;
        
        // Get or create circuit breaker for this upstream service
        let circuit_breaker_config = state.config.circuit_breaker.service_configs
            .get(upstream_service)
            .cloned()
            .unwrap_or(state.config.circuit_breaker.default_config.clone());
        
        let circuit_breaker = state.circuit_breaker_layer
            .registry()
            .get_or_create(upstream_service, circuit_breaker_config);
        
        // Check if request can proceed through circuit breaker
        match circuit_breaker.can_proceed() {
            Ok(()) => {
                // Circuit breaker allows request to proceed
                debug!(
                    request_id = %context.request.id,
                    upstream = %upstream_service,
                    "Circuit breaker allows request to proceed"
                );
                
                // Simulate upstream service call (in future tasks, this will be actual HTTP client call)
                let upstream_call_result = simulate_upstream_call(upstream_service, &context).await;
                
                match upstream_call_result {
                    Ok(response_data) => {
                        // Record success with circuit breaker
                        circuit_breaker.record_success();
                        
                        let response_body = serde_json::json!({
                            "message": "Request processed successfully",
                            "route": {
                                "pattern": context.route.as_ref().unwrap().pattern,
                                "upstream": context.route.as_ref().unwrap().upstream,
                                "params": context.route.as_ref().unwrap().params,
                                "query_params": context.route.as_ref().unwrap().query_params,
                            },
                            "upstream_response": response_data,
                            "request_id": context.request.id,
                            "processing_time_ms": start_time.elapsed().as_millis(),
                            "circuit_breaker_state": format!("{:?}", circuit_breaker.state()),
                        });
                        
                        Ok(create_json_response(StatusCode::OK, response_body))
                    }
                    Err(error) => {
                        // Record failure with circuit breaker
                        circuit_breaker.record_failure();
                        
                        warn!(
                            request_id = %context.request.id,
                            upstream = %upstream_service,
                            error = %error,
                            "Upstream service call failed"
                        );
                        
                        Ok(create_error_response(
                            StatusCode::BAD_GATEWAY,
                            format!("Upstream service '{}' failed: {}", upstream_service, error),
                        ))
                    }
                }
            }
            Err(crate::core::circuit_breaker::CircuitBreakerError::CircuitOpen) => {
                // Circuit breaker is open, reject request immediately
                warn!(
                    request_id = %context.request.id,
                    upstream = %upstream_service,
                    "Circuit breaker is open, rejecting request"
                );
                
                let error_body = serde_json::json!({
                    "error": {
                        "code": 503,
                        "message": format!("Service '{}' is currently unavailable", upstream_service),
                        "type": "CIRCUIT_BREAKER_OPEN",
                        "upstream": upstream_service,
                        "circuit_breaker_state": format!("{:?}", circuit_breaker.state()),
                        "retry_after": "60s"
                    },
                    "request_id": context.request.id,
                });
                
                let mut response = create_json_response(StatusCode::SERVICE_UNAVAILABLE, error_body);
                response.headers_mut().insert("retry-after", "60".parse().unwrap());
                response.headers_mut().insert("x-circuit-breaker", "open".parse().unwrap());
                
                Ok(response)
            }
            Err(error) => {
                // Other circuit breaker error
                warn!(
                    request_id = %context.request.id,
                    upstream = %upstream_service,
                    error = %error,
                    "Circuit breaker error"
                );
                
                Ok(create_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Circuit breaker error: {}", error),
                ))
            }
        }
    } else {
        warn!(
            request_id = %context.request.id,
            method = %method,
            path = %uri.path(),
            "No route matched for request"
        );
        
        Ok(create_error_response(
            StatusCode::NOT_FOUND,
            format!("No route found for {} {}", method, uri.path()),
        ))
    }
}

/// Create a JSON response
fn create_json_response(status: StatusCode, body: serde_json::Value) -> Response {
    let body_bytes = serde_json::to_vec(&body).unwrap_or_else(|_| {
        b"Internal server error".to_vec()
    });

    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("content-length", body_bytes.len())
        .body(Body::from(body_bytes))
        .unwrap()
}

/// Create an error response
fn create_error_response(status: StatusCode, message: String) -> Response {
    let error_body = serde_json::json!({
        "error": {
            "code": status.as_u16(),
            "message": message
        }
    });

    create_json_response(status, error_body)
}

/// Simulate upstream service call
/// 
/// This is a placeholder function that simulates calling an upstream service.
/// In future tasks, this will be replaced with actual HTTP client calls through
/// the load balancer and service discovery components.
async fn simulate_upstream_call(
    upstream_service: &str,
    context: &RequestContext,
) -> Result<serde_json::Value, String> {
    // Simulate network delay
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    
    // Simulate different response patterns based on service name
    match upstream_service {
        "user-service" => {
            // Simulate occasional failures for testing circuit breaker
            if context.request.uri.path().contains("fail") {
                return Err("User service temporarily unavailable".to_string());
            }
            
            Ok(serde_json::json!({
                "service": "user-service",
                "data": {
                    "users": [
                        {"id": 1, "name": "Alice"},
                        {"id": 2, "name": "Bob"}
                    ]
                },
                "timestamp": chrono::Utc::now().to_rfc3339(),
            }))
        }
        "post-service" => {
            // Simulate higher failure rate for post service
            if context.request.uri.path().contains("error") || 
               std::time::SystemTime::now()
                   .duration_since(std::time::UNIX_EPOCH)
                   .unwrap()
                   .as_secs() % 5 == 0 {
                return Err("Post service error".to_string());
            }
            
            Ok(serde_json::json!({
                "service": "post-service",
                "data": {
                    "posts": [
                        {"id": 1, "title": "Hello World", "author": "Alice"},
                        {"id": 2, "title": "Rust is Great", "author": "Bob"}
                    ]
                },
                "timestamp": chrono::Utc::now().to_rfc3339(),
            }))
        }
        "default-service" => {
            Ok(serde_json::json!({
                "service": "default-service",
                "message": "Default service response",
                "timestamp": chrono::Utc::now().to_rfc3339(),
            }))
        }
        _ => {
            // Unknown service
            Ok(serde_json::json!({
                "service": upstream_service,
                "message": "Generic upstream response",
                "timestamp": chrono::Utc::now().to_rfc3339(),
            }))
        }
    }
}

/// Health check handler
pub async fn health_check() -> impl IntoResponse {
    let health_info = serde_json::json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "version": env!("CARGO_PKG_VERSION"),
    });

    (StatusCode::OK, axum::Json(health_info))
}

/// Readiness check handler
pub async fn readiness_check() -> impl IntoResponse {
    // TODO: In future tasks, check if all dependencies are ready
    // (database connections, upstream services, etc.)
    
    let readiness_info = serde_json::json!({
        "status": "ready",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "checks": {
            "router": "ok",
            // Future: "database": "ok", "upstream_services": "ok", etc.
        }
    });

    (StatusCode::OK, axum::Json(readiness_info))
}

/// Gateway health check handler
pub async fn gateway_health_check() -> impl IntoResponse {
    let health_info = serde_json::json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "version": env!("CARGO_PKG_VERSION"),
        "service": "gateway"
    });

    (StatusCode::OK, axum::Json(health_info))
}

/// Gateway readiness check handler
pub async fn gateway_readiness_check() -> impl IntoResponse {
    let readiness_info = serde_json::json!({
        "status": "ready",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "service": "gateway",
        "checks": {
            "router": "ok",
            // Future: "load_balancer": "ok", "upstream_services": "ok", etc.
        }
    });

    (StatusCode::OK, axum::Json(readiness_info))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::router::{Route, RouterBuilder};
    use axum::http::Method;
    use tokio::time::{timeout, Duration};

    async fn create_test_server() -> GatewayServer {
        let router = RouterBuilder::new()
            .get("/api/users", "user-service")
            .get("/api/users/{id}", "user-service")
            .post("/api/users", "user-service")
            .get("/api/posts/{id}", "post-service")
            .default_route("default-service")
            .build();

        let config = ServerConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(), // Use random port for tests
            ..Default::default()
        };

        GatewayServer::new(router, config)
    }

    #[tokio::test]
    async fn test_server_creation() {
        let server = create_test_server().await;
        assert_eq!(server.bind_addr().ip().to_string(), "127.0.0.1");
    }

    #[tokio::test]
    async fn test_protocol_detection() {
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

    #[tokio::test]
    async fn test_websocket_detection() {
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

        assert_eq!(request.detect_protocol(), Protocol::WebSocket);
    }

    #[tokio::test]
    async fn test_request_context_creation() {
        let request = IncomingRequest::new(
            Protocol::Http,
            Method::GET,
            "/api/users/123".parse().unwrap(),
            Version::HTTP_11,
            HeaderMap::new(),
            Vec::new(),
            "127.0.0.1:8080".parse().unwrap(),
        );

        let context = RequestContext::new(Arc::new(request));
        
        assert!(!context.trace_id.is_empty());
        assert!(context.auth_context.is_none());
        assert!(context.route.is_none());
        assert!(context.upstream_instances.is_empty());
    }
}