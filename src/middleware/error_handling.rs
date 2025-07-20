//! # Error Handling Middleware
//!
//! This middleware integrates the error tracking, recovery, and custom error page
//! systems into the request processing pipeline. It automatically tracks errors,
//! attempts recovery when appropriate, and generates custom error responses.

use crate::core::error::GatewayError;
use crate::core::error_tracking::{ErrorTracker, ErrorEvent};
use crate::core::error_recovery::{ErrorRecoveryManager, RecoveryContext, RecoveryResult};
use crate::core::error_pages::{ErrorPageGenerator, ErrorResponseBuilder};
use axum::{
    extract::{Request, State},
    http::HeaderMap,
    middleware::Next,
    response::Response,
};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{info, warn};
use uuid::Uuid;

/// Error handling middleware state
#[derive(Clone)]
pub struct ErrorHandlingState {
    /// Error tracker for collecting error statistics
    pub error_tracker: Arc<ErrorTracker>,
    
    /// Error recovery manager for handling failures
    pub recovery_manager: Arc<tokio::sync::RwLock<ErrorRecoveryManager>>,
    
    /// Error page generator for custom error responses
    pub error_page_generator: Arc<tokio::sync::RwLock<ErrorPageGenerator>>,
}

/// Error handling middleware that integrates all error management systems
pub async fn error_handling_middleware(
    State(state): State<ErrorHandlingState>,
    request: Request,
    next: Next,
) -> Result<Response, GatewayError> {
    let request_id = Uuid::new_v4().to_string();
    let request_path = request.uri().path().to_string();
    let request_method = request.method().to_string();
    let client_ip = extract_client_ip(&request);
    let user_agent = extract_user_agent(&request);
    let headers = request.headers().clone();
    
    // Add request ID to headers for tracing
    let mut request = request;
    request.headers_mut().insert(
        "x-request-id",
        request_id.parse().unwrap_or_else(|_| "unknown".parse().unwrap()),
    );
    
    info!(
        request_id = %request_id,
        method = %request_method,
        path = %request_path,
        "Processing request"
    );
    
    // Process the request through the middleware chain
    let response = next.run(request).await;
    
    // Check if response indicates an error (5xx status codes)
    if response.status().is_server_error() {
        warn!(
            request_id = %request_id,
            status = %response.status(),
            "Server error detected, attempting error handling"
        );
        
        let error = GatewayError::internal(format!("Server error: {}", response.status()));
        handle_request_error(
            error,
            state,
            request_path,
            request_method,
            client_ip,
            user_agent,
            request_id,
            headers,
        ).await
    } else {
        info!(
            request_id = %request_id,
            status = %response.status(),
            "Request completed successfully"
        );
        Ok(response)
    }
}

/// Handle a request error using the integrated error management systems
async fn handle_request_error(
    error: GatewayError,
    state: ErrorHandlingState,
    request_path: String,
    request_method: String,
    client_ip: String,
    user_agent: Option<String>,
    request_id: String,
    headers: HeaderMap,
) -> Result<Response, GatewayError> {
    // Create error event for tracking
    let error_event = ErrorEvent::new(
        &error,
        request_path.clone(),
        request_method.clone(),
        client_ip.clone(),
        user_agent.clone(),
        request_id.clone(),
        None, // trace_id would be extracted from headers in a real implementation
        extract_target_service(&error),
    );
    
    // Track the error
    state.error_tracker.track_error(error_event).await;
    
    // Attempt error recovery if the error is recoverable
    if error.is_retryable() {
        let recovery_context = RecoveryContext {
            request_path: request_path.clone(),
            request_method: request_method.clone(),
            request_headers: headers.clone(),
            request_body: None, // Would need to be captured earlier in real implementation
            request_id: request_id.clone(),
            trace_id: None,
            target_service: extract_target_service(&error),
            metadata: HashMap::new(),
        };
        
        let recovery_manager = state.recovery_manager.read().await;
        match recovery_manager.recover_from_error(&error, recovery_context).await {
            RecoveryResult::Success(response) => {
                info!(
                    request_id = %request_id,
                    "Error recovery successful"
                );
                return Ok(response);
            }
            RecoveryResult::Failed(recovery_error) => {
                warn!(
                    request_id = %request_id,
                    recovery_error = %recovery_error,
                    "Error recovery failed"
                );
                // Continue with error page generation
            }
            RecoveryResult::NotApplicable => {
                info!(
                    request_id = %request_id,
                    "Error recovery not applicable"
                );
                // Continue with error page generation
            }
            RecoveryResult::TimedOut => {
                warn!(
                    request_id = %request_id,
                    "Error recovery timed out"
                );
                // Continue with error page generation
            }
        }
    }
    
    // Generate custom error response
    let error_page_generator = state.error_page_generator.read().await;
    let response = ErrorResponseBuilder::new(error)
        .with_request_path(request_path)
        .with_request_id(request_id.clone())
        .with_header("X-Request-ID", request_id.clone())
        .build(&error_page_generator, &headers);
    
    info!(
        request_id = %request_id,
        status = %response.status(),
        "Generated error response"
    );
    
    Ok(response)
}

/// Extract client IP address from request
fn extract_client_ip(request: &Request) -> String {
    // Check for forwarded headers first
    if let Some(forwarded_for) = request.headers().get("x-forwarded-for") {
        if let Ok(forwarded_str) = forwarded_for.to_str() {
            if let Some(first_ip) = forwarded_str.split(',').next() {
                return first_ip.trim().to_string();
            }
        }
    }
    
    if let Some(real_ip) = request.headers().get("x-real-ip") {
        if let Ok(ip_str) = real_ip.to_str() {
            return ip_str.to_string();
        }
    }
    
    // Fallback to connection info (would need to be passed through extensions in real implementation)
    "unknown".to_string()
}

/// Extract user agent from request headers
fn extract_user_agent(request: &Request) -> Option<String> {
    request
        .headers()
        .get("user-agent")
        .and_then(|ua| ua.to_str().ok())
        .map(|ua| ua.to_string())
}

/// Extract target service from error (if available)
fn extract_target_service(error: &GatewayError) -> Option<String> {
    match error {
        GatewayError::ServiceUnavailable { service, .. } => Some(service.clone()),
        GatewayError::CircuitBreakerOpen { service } => Some(service.clone()),
        _ => None,
    }
}

/// Create error handling middleware layer
pub fn create_error_handling_layer(state: ErrorHandlingState) -> axum::middleware::FromFnLayer<impl Fn(State<ErrorHandlingState>, Request, Next) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, GatewayError>> + Send>> + Clone, ErrorHandlingState, ()> {
    axum::middleware::from_fn_with_state(state, |state, req, next| {
        Box::pin(error_handling_middleware(state, req, next)) as std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, GatewayError>> + Send>>
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::error_tracking::ErrorPatternConfig;
    use crate::core::error_recovery::RecoveryConfig;
    use crate::core::error_pages::ErrorPageConfig;
    use axum::{
        body::Body,
        http::{Method, Uri},
        routing::get,
        Router,
    };
    use axum_test::TestServer;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    async fn create_test_state() -> ErrorHandlingState {
        let error_tracker = Arc::new(ErrorTracker::new(ErrorPatternConfig::default()));
        let recovery_manager = Arc::new(RwLock::new(ErrorRecoveryManager::new(RecoveryConfig::default())));
        let error_page_generator = Arc::new(RwLock::new(
            ErrorPageGenerator::new(ErrorPageConfig::default()).unwrap()
        ));
        
        ErrorHandlingState {
            error_tracker,
            recovery_manager,
            error_page_generator,
        }
    }

    async fn failing_handler() -> Result<&'static str, GatewayError> {
        Err(GatewayError::internal("Test error"))
    }

    async fn timeout_handler() -> Result<&'static str, GatewayError> {
        Err(GatewayError::Timeout { timeout_ms: 5000 })
    }

    #[tokio::test]
    async fn test_error_handling_middleware_with_internal_error() {
        let state = create_test_state().await;
        
        let app = Router::new()
            .route("/test", get(failing_handler))
            .layer(create_error_handling_layer(state.clone()))
            .with_state(state);
        
        let server = TestServer::new(app).unwrap();
        let response = server.get("/test").await;
        
        assert_eq!(response.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
        
        // Verify error was tracked
        let recent_errors = state.error_tracker.get_recent_errors(Some(10));
        assert_eq!(recent_errors.len(), 1);
        assert_eq!(recent_errors[0].error_type, "internal_error");
    }

    #[tokio::test]
    async fn test_error_handling_middleware_with_timeout_error() {
        let state = create_test_state().await;
        
        let app = Router::new()
            .route("/timeout", get(timeout_handler))
            .layer(create_error_handling_layer(state.clone()))
            .with_state(state);
        
        let server = TestServer::new(app).unwrap();
        let response = server.get("/timeout").await;
        
        assert_eq!(response.status_code(), StatusCode::GATEWAY_TIMEOUT);
        
        // Verify error was tracked
        let recent_errors = state.error_tracker.get_recent_errors(Some(10));
        assert_eq!(recent_errors.len(), 1);
        assert_eq!(recent_errors[0].error_type, "timeout");
        assert!(recent_errors[0].retryable);
    }

    #[test]
    fn test_client_ip_extraction() {
        let mut request = Request::builder()
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        
        // Test X-Forwarded-For header
        request.headers_mut().insert(
            "x-forwarded-for",
            "192.168.1.1, 10.0.0.1".parse().unwrap(),
        );
        
        let client_ip = extract_client_ip(&request);
        assert_eq!(client_ip, "192.168.1.1");
        
        // Test X-Real-IP header
        let mut request = Request::builder()
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        
        request.headers_mut().insert(
            "x-real-ip",
            "203.0.113.1".parse().unwrap(),
        );
        
        let client_ip = extract_client_ip(&request);
        assert_eq!(client_ip, "203.0.113.1");
    }

    #[test]
    fn test_user_agent_extraction() {
        let mut request = Request::builder()
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        
        request.headers_mut().insert(
            "user-agent",
            "Mozilla/5.0 (Test Browser)".parse().unwrap(),
        );
        
        let user_agent = extract_user_agent(&request);
        assert_eq!(user_agent, Some("Mozilla/5.0 (Test Browser)".to_string()));
        
        // Test missing user agent
        let request = Request::builder()
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        
        let user_agent = extract_user_agent(&request);
        assert_eq!(user_agent, None);
    }

    #[test]
    fn test_target_service_extraction() {
        let service_error = GatewayError::ServiceUnavailable {
            service: "api-service".to_string(),
            reason: "Connection refused".to_string(),
        };
        
        let target_service = extract_target_service(&service_error);
        assert_eq!(target_service, Some("api-service".to_string()));
        
        let circuit_breaker_error = GatewayError::CircuitBreakerOpen {
            service: "payment-service".to_string(),
        };
        
        let target_service = extract_target_service(&circuit_breaker_error);
        assert_eq!(target_service, Some("payment-service".to_string()));
        
        let internal_error = GatewayError::internal("Generic error");
        let target_service = extract_target_service(&internal_error);
        assert_eq!(target_service, None);
    }
}