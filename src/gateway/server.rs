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
}

impl ServerState {
    /// Create new server state
    pub fn new(router: Router, config: ServerConfig) -> Self {
        Self {
            router: Arc::new(router),
            config,
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
}

impl GatewayServer {
    /// Create a new HTTP server with separated admin and gateway routes
    pub fn new(router: Router, config: ServerConfig) -> Self {
        let state = ServerState::new(router, config.clone());
        
        // Build the gateway application for handling API requests
        let mut gateway_app = AxumRouter::new()
            .route("/*path", any(handle_request))
            .with_state(state.clone());

        // Add middleware layers to gateway app
        gateway_app = gateway_app.layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CompressionLayer::new())
        );

        if config.enable_cors {
            gateway_app = gateway_app.layer(CorsLayer::permissive());
        }

        // Create admin application for configuration management
        let admin_app = Self::create_admin_app(state.clone());

        Self { 
            state, 
            gateway_app,
            admin_app,
        }
    }

    /// Create the admin application with configuration management endpoints
    fn create_admin_app(_state: ServerState) -> AxumRouter {
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

        // Create admin router with all endpoints
        let mut admin_app = AdminRouter::create_router(admin_state);

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
        
        // TODO: In subsequent tasks, this is where we would:
        // 1. Apply middleware pipeline
        // 2. Perform authentication/authorization
        // 3. Apply rate limiting
        // 4. Load balance to upstream service
        // 5. Forward request and get response
        
        // For now, return a simple success response indicating the route was matched
        let response_body = serde_json::json!({
            "message": "Request routed successfully",
            "route": {
                "pattern": context.route.as_ref().unwrap().pattern,
                "upstream": context.route.as_ref().unwrap().upstream,
                "params": context.route.as_ref().unwrap().params,
                "query_params": context.route.as_ref().unwrap().query_params,
            },
            "request_id": context.request.id,
            "processing_time_ms": start_time.elapsed().as_millis(),
        });

        Ok(create_json_response(StatusCode::OK, response_body))
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