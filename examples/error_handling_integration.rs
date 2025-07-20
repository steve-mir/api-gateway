//! # Error Handling Integration Example
//!
//! This example demonstrates how to integrate the comprehensive error handling system
//! into the API Gateway, including error tracking, custom error pages, error recovery,
//! and admin endpoints for error management.

use api_gateway::core::error::{GatewayError, GatewayResult};
use api_gateway::core::error_tracking::{ErrorTracker, ErrorPatternConfig};
use api_gateway::core::error_pages::{ErrorPageGenerator, ErrorPageConfig};
use api_gateway::core::error_recovery::{ErrorRecoveryManager, RecoveryConfig};
use api_gateway::admin::error_tracking::{ErrorTrackingAdminRouter, ErrorTrackingAdminState};
use api_gateway::middleware::error_handling::{ErrorHandlingState, create_error_handling_layer};
use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde_json::json;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, Level};
use tracing_subscriber;

/// Example application state
#[derive(Clone)]
struct AppState {
    error_handling: ErrorHandlingState,
}

/// Example handler that always fails with an internal error
async fn failing_handler() -> Result<Json<serde_json::Value>, GatewayError> {
    Err(GatewayError::internal("This endpoint always fails for demonstration"))
}

/// Example handler that fails with a service unavailable error
async fn service_unavailable_handler() -> Result<Json<serde_json::Value>, GatewayError> {
    Err(GatewayError::ServiceUnavailable {
        service: "example-service".to_string(),
        reason: "Service is temporarily down for maintenance".to_string(),
    })
}

/// Example handler that fails with a timeout error
async fn timeout_handler() -> Result<Json<serde_json::Value>, GatewayError> {
    Err(GatewayError::Timeout { timeout_ms: 5000 })
}

/// Example handler that fails with an authentication error
async fn auth_handler() -> Result<Json<serde_json::Value>, GatewayError> {
    Err(GatewayError::Authentication {
        reason: "Invalid or expired token".to_string(),
    })
}

/// Example handler that fails with a rate limit error
async fn rate_limit_handler() -> Result<Json<serde_json::Value>, GatewayError> {
    Err(GatewayError::RateLimitExceeded {
        limit: 100,
        window: "minute".to_string(),
    })
}

/// Example handler that succeeds
async fn success_handler() -> Result<Json<serde_json::Value>, GatewayError> {
    Ok(Json(json!({
        "message": "Request processed successfully",
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}

/// Create the main application router with error handling
fn create_app_router(state: AppState) -> Router {
    Router::new()
        // Example API endpoints that demonstrate different error types
        .route("/api/success", get(success_handler))
        .route("/api/fail/internal", get(failing_handler))
        .route("/api/fail/service-unavailable", get(service_unavailable_handler))
        .route("/api/fail/timeout", get(timeout_handler))
        .route("/api/fail/auth", get(auth_handler))
        .route("/api/fail/rate-limit", get(rate_limit_handler))
        
        // Health check endpoint
        .route("/health", get(health_check))
        
        // Apply error handling middleware to all routes
        .layer(create_error_handling_layer(state.error_handling.clone()))
        .with_state(state)
}

/// Create the admin router for error management
fn create_admin_router(error_tracking_state: ErrorTrackingAdminState) -> Router {
    Router::new()
        .nest("/admin/errors", ErrorTrackingAdminRouter::create_router(error_tracking_state))
}

/// Health check handler
async fn health_check() -> Result<Json<serde_json::Value>, GatewayError> {
    Ok(Json(json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "version": "1.0.0"
    })))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_target(false)
        .init();

    info!("Starting API Gateway with comprehensive error handling");

    // Create error handling components
    let error_tracker = Arc::new(ErrorTracker::new(ErrorPatternConfig {
        error_rate_threshold: 5.0, // 5 errors per minute
        error_rate_window: 1,       // 1 minute window
        consecutive_error_threshold: 3,
        consecutive_error_window: 2,
        auto_circuit_breaker: true,
        auto_recovery: true,
    }));

    let recovery_manager = Arc::new(RwLock::new(ErrorRecoveryManager::new(RecoveryConfig {
        enabled: true,
        max_attempts: 3,
        recovery_timeout: std::time::Duration::from_secs(10),
        collect_metrics: true,
        ..Default::default()
    })));

    let error_page_generator = Arc::new(RwLock::new(ErrorPageGenerator::new(ErrorPageConfig {
        enabled: true,
        brand_name: "Example API Gateway".to_string(),
        support_contact: Some("support@example.com".to_string()),
        show_details: true, // Enable for development
        ..Default::default()
    })?));

    // Create error handling state
    let error_handling_state = ErrorHandlingState {
        error_tracker: error_tracker.clone(),
        recovery_manager: recovery_manager.clone(),
        error_page_generator: error_page_generator.clone(),
    };

    // Create admin state for error tracking
    let alert_receiver = Arc::new(RwLock::new(error_tracker.subscribe_to_alerts()));
    let error_tracking_admin_state = ErrorTrackingAdminState {
        error_tracker: error_tracker.clone(),
        recovery_manager: recovery_manager.clone(),
        error_page_generator: error_page_generator.clone(),
        alert_receiver,
    };

    // Create application state
    let app_state = AppState {
        error_handling: error_handling_state,
    };

    // Create routers
    let app_router = create_app_router(app_state);
    let admin_router = create_admin_router(error_tracking_admin_state);

    // Start alert monitoring task
    let alert_tracker = error_tracker.clone();
    tokio::spawn(async move {
        let mut alert_receiver = alert_tracker.subscribe_to_alerts();
        while let Ok(alert) = alert_receiver.recv().await {
            info!("Error alert received: {:?}", alert);
            // In a real implementation, you would send notifications, trigger actions, etc.
        }
    });

    info!("Starting servers...");
    info!("Main API server will be available at: http://localhost:3000");
    info!("Admin interface will be available at: http://localhost:3001");
    info!("");
    info!("Try these endpoints to see error handling in action:");
    info!("  GET http://localhost:3000/api/success - Success response");
    info!("  GET http://localhost:3000/api/fail/internal - Internal server error");
    info!("  GET http://localhost:3000/api/fail/service-unavailable - Service unavailable");
    info!("  GET http://localhost:3000/api/fail/timeout - Gateway timeout");
    info!("  GET http://localhost:3000/api/fail/auth - Authentication error");
    info!("  GET http://localhost:3000/api/fail/rate-limit - Rate limit exceeded");
    info!("");
    info!("Admin endpoints:");
    info!("  GET http://localhost:3001/admin/errors - List recent errors");
    info!("  GET http://localhost:3001/admin/errors/stats - Error statistics");
    info!("  GET http://localhost:3001/admin/errors/dashboard - Error dashboard");
    info!("  GET http://localhost:3001/admin/errors/pages/preview/404 - Preview 404 error page");
    info!("  GET http://localhost:3001/admin/errors/pages/preview/500 - Preview 500 error page");

    // Start both servers concurrently
    let main_server = tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
        info!("Main API server listening on {}", listener.local_addr().unwrap());
        axum::serve(listener, app_router).await.unwrap();
    });

    let admin_server = tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind("0.0.0.0:3001").await.unwrap();
        info!("Admin server listening on {}", listener.local_addr().unwrap());
        axum::serve(listener, admin_router).await.unwrap();
    });

    // Wait for both servers
    tokio::try_join!(main_server, admin_server)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum_test::TestServer;

    async fn create_test_app() -> Router {
        let error_tracker = Arc::new(ErrorTracker::new(ErrorPatternConfig::default()));
        let recovery_manager = Arc::new(RwLock::new(ErrorRecoveryManager::new(RecoveryConfig::default())));
        let error_page_generator = Arc::new(RwLock::new(
            ErrorPageGenerator::new(ErrorPageConfig::default()).unwrap()
        ));

        let error_handling_state = ErrorHandlingState {
            error_tracker,
            recovery_manager,
            error_page_generator,
        };

        let app_state = AppState {
            error_handling: error_handling_state,
        };

        create_app_router(app_state)
    }

    #[tokio::test]
    async fn test_success_endpoint() {
        let app = create_test_app().await;
        let server = TestServer::new(app).unwrap();

        let response = server.get("/api/success").await;
        assert_eq!(response.status_code(), StatusCode::OK);

        let body: serde_json::Value = response.json();
        assert_eq!(body["message"], "Request processed successfully");
    }

    #[tokio::test]
    async fn test_internal_error_endpoint() {
        let app = create_test_app().await;
        let server = TestServer::new(app).unwrap();

        let response = server.get("/api/fail/internal").await;
        assert_eq!(response.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_service_unavailable_endpoint() {
        let app = create_test_app().await;
        let server = TestServer::new(app).unwrap();

        let response = server.get("/api/fail/service-unavailable").await;
        assert_eq!(response.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn test_timeout_endpoint() {
        let app = create_test_app().await;
        let server = TestServer::new(app).unwrap();

        let response = server.get("/api/fail/timeout").await;
        assert_eq!(response.status_code(), StatusCode::GATEWAY_TIMEOUT);
    }

    #[tokio::test]
    async fn test_auth_error_endpoint() {
        let app = create_test_app().await;
        let server = TestServer::new(app).unwrap();

        let response = server.get("/api/fail/auth").await;
        assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_rate_limit_endpoint() {
        let app = create_test_app().await;
        let server = TestServer::new(app).unwrap();

        let response = server.get("/api/fail/rate-limit").await;
        assert_eq!(response.status_code(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn test_health_check() {
        let app = create_test_app().await;
        let server = TestServer::new(app).unwrap();

        let response = server.get("/health").await;
        assert_eq!(response.status_code(), StatusCode::OK);

        let body: serde_json::Value = response.json();
        assert_eq!(body["status"], "healthy");
    }

    #[tokio::test]
    async fn test_error_response_contains_request_id() {
        let app = create_test_app().await;
        let server = TestServer::new(app).unwrap();

        let response = server.get("/api/fail/internal").await;
        assert_eq!(response.status_code(), StatusCode::INTERNAL_SERVER_ERROR);

        // Check that response contains request ID header
        assert!(response.headers().contains_key("x-request-id"));
    }

    #[tokio::test]
    async fn test_json_vs_html_error_responses() {
        let app = create_test_app().await;
        let server = TestServer::new(app).unwrap();

        // Test JSON error response
        let response = server
            .get("/api/fail/internal")
            .add_header("accept", "application/json")
            .await;
        assert_eq!(response.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
        
        // Test HTML error response
        let response = server
            .get("/api/fail/internal")
            .add_header("accept", "text/html")
            .await;
        assert_eq!(response.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}