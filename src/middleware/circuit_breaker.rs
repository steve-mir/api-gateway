//! Circuit Breaker Middleware
//! 
//! This middleware integrates circuit breaker functionality into the request processing pipeline.
//! It wraps upstream service calls with circuit breaker protection to prevent cascade failures.
//! 
//! ## Key Features:
//! - Automatic failure detection and circuit opening
//! - Configurable per-service circuit breakers
//! - Integration with service discovery for upstream calls
//! - Metrics collection for monitoring
//! 
//! ## Rust Concepts:
//! - Uses `Arc` for sharing circuit breaker registry across middleware instances
//! - Leverages async/await for non-blocking circuit breaker operations
//! - Employs `Result` types for proper error propagation

use std::sync::Arc;
use axum::{
    extract::Request,
    response::{Response, IntoResponse},
    http::StatusCode,
};
use tower::{Layer, Service};
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};

use crate::core::circuit_breaker::{
    CircuitBreaker, CircuitBreakerConfig, CircuitBreakerRegistry, CircuitBreakerError
};
use crate::core::error::GatewayError;

/// Configuration for circuit breaker middleware
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CircuitBreakerMiddlewareConfig {
    /// Default circuit breaker configuration for services
    pub default_config: CircuitBreakerConfig,
    
    /// Per-service circuit breaker configurations
    pub service_configs: std::collections::HashMap<String, CircuitBreakerConfig>,
    
    /// Whether to enable circuit breaker middleware
    pub enabled: bool,
}

impl Default for CircuitBreakerMiddlewareConfig {
    fn default() -> Self {
        Self {
            default_config: CircuitBreakerConfig::default(),
            service_configs: std::collections::HashMap::new(),
            enabled: true,
        }
    }
}

/// Circuit breaker middleware layer
/// 
/// This layer creates circuit breaker middleware instances for each service.
/// It uses the Tower layer pattern for composable middleware.
#[derive(Clone)]
pub struct CircuitBreakerLayer {
    registry: Arc<CircuitBreakerRegistry>,
    config: CircuitBreakerMiddlewareConfig,
}

impl CircuitBreakerLayer {
    /// Create a new circuit breaker layer
    pub fn new(config: CircuitBreakerMiddlewareConfig) -> Self {
        Self {
            registry: Arc::new(CircuitBreakerRegistry::new()),
            config,
        }
    }
    
    /// Get the circuit breaker registry (for admin access)
    pub fn registry(&self) -> Arc<CircuitBreakerRegistry> {
        Arc::clone(&self.registry)
    }
}

impl<S> Layer<S> for CircuitBreakerLayer {
    type Service = CircuitBreakerMiddleware<S>;
    
    fn layer(&self, inner: S) -> Self::Service {
        CircuitBreakerMiddleware {
            inner,
            registry: Arc::clone(&self.registry),
            config: self.config.clone(),
        }
    }
}

/// Circuit breaker middleware service
/// 
/// This middleware wraps each request with circuit breaker protection.
/// It determines the target service and applies the appropriate circuit breaker.
#[derive(Clone)]
pub struct CircuitBreakerMiddleware<S> {
    inner: S,
    registry: Arc<CircuitBreakerRegistry>,
    config: CircuitBreakerMiddlewareConfig,
}

impl<S> Service<Request> for CircuitBreakerMiddleware<S>
where
    S: Service<Request> + Clone + Send + 'static,
    S::Response: IntoResponse + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<GatewayError> + Send,
{
    type Response = Response;
    type Error = GatewayError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;
    
    fn poll_ready(&mut self, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }
    
    fn call(&mut self, request: Request) -> Self::Future {
        if !self.config.enabled {
            // Circuit breaker disabled, pass through
            let future = self.inner.call(request);
            return Box::pin(async move {
                let response = future.await.map_err(Into::into)?;
                Ok(response.into_response())
            });
        }
        
        let mut inner = self.inner.clone();
        let registry = Arc::clone(&self.registry);
        let config = self.config.clone();
        
        Box::pin(async move {
            // Extract service name from request (this would typically come from routing)
            let service_name = extract_service_name(&request);
            
            // Get or create circuit breaker for this service
            let cb_config = config.service_configs
                .get(&service_name)
                .cloned()
                .unwrap_or(config.default_config);
            
            let circuit_breaker = registry.get_or_create(&service_name, cb_config);
            
            // Check if request can proceed
            match circuit_breaker.can_proceed() {
                Ok(()) => {
                    // Circuit is closed or half-open, proceed with request
                    let _start_time = std::time::Instant::now();
                    
                    match inner.call(request).await {
                        Ok(response) => {
                            // Convert response to standard Response type
                            let response = response.into_response();
                            // Check if response indicates success or failure
                            if is_success_response(&response) {
                                circuit_breaker.record_success();
                            } else {
                                circuit_breaker.record_failure();
                            }
                            Ok(response)
                        }
                        Err(error) => {
                            // Request failed, record failure
                            circuit_breaker.record_failure();
                            Err(error.into())
                        }
                    }
                }
                Err(CircuitBreakerError::CircuitOpen) => {
                    // Circuit is open, return service unavailable
                    Ok(create_circuit_open_response(&service_name))
                }
                Err(error) => {
                    // Other circuit breaker error
                    Err(GatewayError::internal(error.to_string()))
                }
            }
        })
    }
}

/// Extract service name from request
/// 
/// This is a simplified implementation. In a real gateway, this would
/// extract the service name from the routing information or headers.
fn extract_service_name(request: &Request) -> String {
    // Try to get service name from headers first
    if let Some(service_header) = request.headers().get("x-target-service") {
        if let Ok(service_name) = service_header.to_str() {
            return service_name.to_string();
        }
    }
    
    // Fallback: extract from path
    let path = request.uri().path();
    if let Some(service_name) = extract_service_from_path(path) {
        return service_name;
    }
    
    // Default service name
    "default".to_string()
}

/// Extract service name from URL path
/// 
/// Assumes path format like /api/v1/service-name/...
fn extract_service_from_path(path: &str) -> Option<String> {
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    
    // Look for service name in different positions
    if segments.len() >= 3 && segments[0] == "api" {
        // Format: /api/v1/service-name/...
        Some(segments[2].to_string())
    } else if segments.len() >= 2 {
        // Format: /service-name/...
        Some(segments[0].to_string())
    } else {
        None
    }
}

/// Check if response indicates success
/// 
/// This determines whether to record a success or failure for the circuit breaker.
/// HTTP 5xx errors are considered failures, while 4xx errors are considered successes
/// (since they indicate the service is responding, just with a client error).
fn is_success_response(response: &Response) -> bool {
    let status = response.status();
    
    // 2xx and 3xx are successes
    if status.is_success() || status.is_redirection() {
        return true;
    }
    
    // 4xx are considered successes (service is responding, client error)
    if status.is_client_error() {
        return true;
    }
    
    // 5xx are failures (server/service error)
    false
}

/// Create response for when circuit is open
fn create_circuit_open_response(service_name: &str) -> Response {
    let body = format!(
        r#"{{"error": "Service Unavailable", "message": "Circuit breaker is open for service: {}", "code": "CIRCUIT_BREAKER_OPEN"}}"#,
        service_name
    );
    
    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .header("content-type", "application/json")
        .header("x-circuit-breaker", "open")
        .header("retry-after", "60") // Suggest retry after 60 seconds
        .body(body.into())
        .unwrap()
}

/// Circuit breaker service wrapper for direct upstream calls
/// 
/// This can be used to wrap individual upstream service clients with circuit breaker protection.
pub struct CircuitBreakerService<S> {
    inner: S,
    circuit_breaker: Arc<CircuitBreaker>,
}

impl<S> CircuitBreakerService<S> {
    /// Create a new circuit breaker service wrapper
    pub fn new(inner: S, circuit_breaker: Arc<CircuitBreaker>) -> Self {
        Self {
            inner,
            circuit_breaker,
        }
    }
    
    /// Get the underlying circuit breaker
    pub fn circuit_breaker(&self) -> Arc<CircuitBreaker> {
        Arc::clone(&self.circuit_breaker)
    }
}

impl<S, Req> Service<Req> for CircuitBreakerService<S>
where
    S: Service<Req> + Clone + Send + 'static,
    S::Error: std::error::Error + Send + Sync + 'static,
    S::Future: Send,
    Req: Send + 'static,
{
    type Response = S::Response;
    type Error = GatewayError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;
    
    fn poll_ready(&mut self, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(|e| GatewayError::internal(e.to_string()))
    }
    
    fn call(&mut self, request: Req) -> Self::Future {
        let mut inner = self.inner.clone();
        let circuit_breaker = Arc::clone(&self.circuit_breaker);
        
        Box::pin(async move {
            // Check if request can proceed
            match circuit_breaker.can_proceed() {
                Ok(()) => {
                    // Proceed with request
                    match inner.call(request).await {
                        Ok(response) => {
                            circuit_breaker.record_success();
                            Ok(response)
                        }
                        Err(error) => {
                            circuit_breaker.record_failure();
                            Err(GatewayError::internal(error.to_string()))
                        }
                    }
                }
                Err(CircuitBreakerError::CircuitOpen) => {
                    Err(GatewayError::service_unavailable("circuit_breaker", "Circuit breaker is open"))
                }
                Err(error) => {
                    Err(GatewayError::internal(error.to_string()))
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{Method, Uri};
    use tower::ServiceExt;
    use std::convert::Infallible;
    
    // Mock service for testing
    #[derive(Clone)]
    struct MockService {
        should_fail: bool,
        response_status: StatusCode,
    }
    
    impl Service<Request> for MockService {
        type Response = Response;
        type Error = Infallible;
        type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;
        
        fn poll_ready(&mut self, _cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }
        
        fn call(&mut self, _request: Request) -> Self::Future {
            let status = self.response_status;
            let should_fail = self.should_fail;
            
            Box::pin(async move {
                if should_fail {
                    // Simulate service failure
                    std::future::pending().await
                } else {
                    Ok(Response::builder()
                        .status(status)
                        .body("test response".into())
                        .unwrap())
                }
            })
        }
    }
    
    #[tokio::test]
    async fn test_circuit_breaker_middleware_success() {
        let config = CircuitBreakerMiddlewareConfig::default();
        let layer = CircuitBreakerLayer::new(config);
        
        let mock_service = MockService {
            should_fail: false,
            response_status: StatusCode::OK,
        };
        
        let mut service = layer.layer(mock_service);
        
        let request = Request::builder()
            .method(Method::GET)
            .uri("/api/v1/test-service/users")
            .body("".into())
            .unwrap();
        
        let response = service.ready().await.unwrap().call(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    
    #[tokio::test]
    async fn test_circuit_breaker_middleware_opens_on_failures() {
        let mut config = CircuitBreakerMiddlewareConfig::default();
        config.default_config.failure_threshold = 2;
        
        let layer = CircuitBreakerLayer::new(config);
        
        let mock_service = MockService {
            should_fail: false,
            response_status: StatusCode::INTERNAL_SERVER_ERROR,
        };
        
        let mut service = layer.layer(mock_service);
        
        // Send failing requests
        for _ in 0..2 {
            let request = Request::builder()
                .method(Method::GET)
                .uri("/api/v1/test-service/users")
                .body("".into())
                .unwrap();
            
            let response = service.ready().await.unwrap().call(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        }
        
        // Next request should be rejected by circuit breaker
        let request = Request::builder()
            .method(Method::GET)
            .uri("/api/v1/test-service/users")
            .body("".into())
            .unwrap();
        
        let response = service.ready().await.unwrap().call(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(response.headers().contains_key("x-circuit-breaker"));
    }
    
    #[test]
    fn test_extract_service_from_path() {
        assert_eq!(extract_service_from_path("/api/v1/user-service/users"), Some("user-service".to_string()));
        assert_eq!(extract_service_from_path("/user-service/users"), Some("user-service".to_string()));
        assert_eq!(extract_service_from_path("/"), None);
        assert_eq!(extract_service_from_path("/single"), Some("single".to_string()));
    }
    
    #[test]
    fn test_is_success_response() {
        let response_200 = Response::builder().status(200).body("".into()).unwrap();
        assert!(is_success_response(&response_200));
        
        let response_404 = Response::builder().status(404).body("".into()).unwrap();
        assert!(is_success_response(&response_404)); // 4xx considered success
        
        let response_500 = Response::builder().status(500).body("".into()).unwrap();
        assert!(!is_success_response(&response_500)); // 5xx considered failure
    }
}