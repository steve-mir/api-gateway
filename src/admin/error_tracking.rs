//! # Admin Error Tracking Module
//!
//! This module provides admin endpoints for error tracking, analysis, and management.
//! It allows administrators to view error statistics, configure error handling,
//! and manage error recovery settings.

use crate::core::error::GatewayError;
use crate::core::error_tracking::{ErrorTracker, ErrorEvent, ErrorStats, ErrorSummary, ErrorPatternConfig, ErrorAlert};
use crate::core::error_recovery::{ErrorRecoveryManager, RecoveryConfig, RecoveryMetrics};
use crate::core::error_pages::{ErrorPageGenerator, ErrorPageConfig};
use axum::{
    extract::{Query, State, Path},
    response::Json,
    routing::{get, post, put, delete},
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::info;

/// Admin state for error tracking
#[derive(Clone)]
pub struct ErrorTrackingAdminState {
    /// Error tracker instance
    pub error_tracker: Arc<ErrorTracker>,
    
    /// Error recovery manager
    pub recovery_manager: Arc<tokio::sync::RwLock<ErrorRecoveryManager>>,
    
    /// Error page generator
    pub error_page_generator: Arc<tokio::sync::RwLock<ErrorPageGenerator>>,
    
    /// Alert receiver for real-time notifications
    pub alert_receiver: Arc<tokio::sync::RwLock<broadcast::Receiver<ErrorAlert>>>,
}

/// Query parameters for error listing
#[derive(Debug, Deserialize)]
pub struct ErrorListQuery {
    /// Limit number of results
    pub limit: Option<usize>,
    
    /// Filter by error type
    pub error_type: Option<String>,
    
    /// Filter by service
    pub service: Option<String>,
    
    /// Filter by status code
    pub status_code: Option<u16>,
    
    /// Filter by time range (hours ago)
    pub hours: Option<u64>,
}

/// Query parameters for error statistics
#[derive(Debug, Deserialize)]
pub struct ErrorStatsQuery {
    /// Time period for statistics (hours)
    pub hours: Option<u64>,
    
    /// Group by field (error_type, service, status_code)
    pub group_by: Option<String>,
}

/// Error configuration update request
#[derive(Debug, Deserialize)]
pub struct ErrorConfigUpdateRequest {
    /// Error pattern configuration
    pub pattern_config: Option<ErrorPatternConfig>,
    
    /// Recovery configuration
    pub recovery_config: Option<RecoveryConfig>,
    
    /// Error page configuration
    pub error_page_config: Option<ErrorPageConfig>,
}

/// Error tracking dashboard data
#[derive(Debug, Serialize)]
pub struct ErrorDashboard {
    /// Error summary for different time periods
    pub summary: HashMap<String, ErrorSummary>,
    
    /// Error statistics by type
    pub error_stats: HashMap<String, ErrorStats>,
    
    /// Service error statistics
    pub service_stats: HashMap<String, ErrorStats>,
    
    /// Recovery metrics
    pub recovery_metrics: RecoveryMetrics,
    
    /// Recent error events
    pub recent_errors: Vec<ErrorEvent>,
    
    /// Active alerts
    pub active_alerts: Vec<ErrorAlert>,
}

/// Create error tracking admin router
pub fn create_error_tracking_admin_router() -> Router<ErrorTrackingAdminState> {
    Router::new()
        // Error tracking endpoints
        .route("/errors", get(list_errors))
        .route("/errors/stats", get(get_error_stats))
        .route("/errors/summary", get(get_error_summary))
        .route("/errors/dashboard", get(get_error_dashboard))
        .route("/errors/clear", delete(clear_error_data))
        
        // Error configuration endpoints
        .route("/errors/config", get(get_error_config))
        .route("/errors/config", put(update_error_config))
        
        // Error recovery endpoints
        .route("/errors/recovery/metrics", get(get_recovery_metrics))
        .route("/errors/recovery/config", get(get_recovery_config))
        .route("/errors/recovery/config", put(update_recovery_config))
        .route("/errors/recovery/reset", post(reset_recovery_metrics))
        
        // Error page endpoints
        .route("/errors/pages/config", get(get_error_page_config))
        .route("/errors/pages/config", put(update_error_page_config))
        .route("/errors/pages/preview/:status_code", get(preview_error_page))
        
        // Alert endpoints
        .route("/errors/alerts", get(get_active_alerts))
        .route("/errors/alerts/stream", get(stream_alerts))
}

/// List recent error events
async fn list_errors(
    State(state): State<ErrorTrackingAdminState>,
    Query(query): Query<ErrorListQuery>,
) -> Result<Json<Vec<ErrorEvent>>, GatewayError> {
    let limit = query.limit.unwrap_or(100);
    let mut errors = state.error_tracker.get_recent_errors(Some(limit));
    
    // Apply filters
    if let Some(error_type) = &query.error_type {
        errors.retain(|e| &e.error_type == error_type);
    }
    
    if let Some(service) = &query.service {
        errors.retain(|e| e.service.as_ref() == Some(service));
    }
    
    if let Some(status_code) = query.status_code {
        errors.retain(|e| e.status_code == status_code);
    }
    
    if let Some(hours) = query.hours {
        let cutoff_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() - (hours * 3600);
        errors.retain(|e| e.timestamp >= cutoff_time);
    }
    
    info!("Retrieved {} error events", errors.len());
    Ok(Json(errors))
}

/// Get error statistics
async fn get_error_stats(
    State(state): State<ErrorTrackingAdminState>,
    Query(query): Query<ErrorStatsQuery>,
) -> Result<Json<HashMap<String, ErrorStats>>, GatewayError> {
    let stats = match query.group_by.as_deref() {
        Some("service") => state.error_tracker.get_service_stats(),
        _ => state.error_tracker.get_error_stats(),
    };
    
    info!("Retrieved error statistics for {} categories", stats.len());
    Ok(Json(stats))
}

/// Get error summary
async fn get_error_summary(
    State(state): State<ErrorTrackingAdminState>,
    Query(query): Query<ErrorStatsQuery>,
) -> Result<Json<ErrorSummary>, GatewayError> {
    let hours = query.hours.unwrap_or(24);
    let summary = state.error_tracker.get_error_summary(hours);
    
    info!("Retrieved error summary for {} hours", hours);
    Ok(Json(summary))
}

/// Get comprehensive error dashboard data
async fn get_error_dashboard(
    State(state): State<ErrorTrackingAdminState>,
) -> Result<Json<ErrorDashboard>, GatewayError> {
    let mut summary = HashMap::new();
    summary.insert("last_hour".to_string(), state.error_tracker.get_error_summary(1));
    summary.insert("last_day".to_string(), state.error_tracker.get_error_summary(24));
    summary.insert("last_week".to_string(), state.error_tracker.get_error_summary(168));
    
    let error_stats = state.error_tracker.get_error_stats();
    let service_stats = state.error_tracker.get_service_stats();
    let recent_errors = state.error_tracker.get_recent_errors(Some(50));
    
    let recovery_metrics = {
        let recovery_manager = state.recovery_manager.read().await;
        recovery_manager.get_metrics()
    };
    
    // Get active alerts (simplified - in practice, you'd maintain an alert store)
    let active_alerts = Vec::new(); // Placeholder for active alerts
    
    let dashboard = ErrorDashboard {
        summary,
        error_stats,
        service_stats,
        recovery_metrics,
        recent_errors,
        active_alerts,
    };
    
    info!("Generated error dashboard data");
    Ok(Json(dashboard))
}

/// Clear all error tracking data
async fn clear_error_data(
    State(state): State<ErrorTrackingAdminState>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    state.error_tracker.clear_all_data();
    
    {
        let recovery_manager = state.recovery_manager.read().await;
        recovery_manager.reset_metrics();
    }
    
    info!("Cleared all error tracking data");
    Ok(Json(serde_json::json!({
        "message": "All error tracking data cleared successfully"
    })))
}

/// Get current error configuration
async fn get_error_config(
    State(state): State<ErrorTrackingAdminState>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let recovery_config = {
        let recovery_manager = state.recovery_manager.read().await;
        recovery_manager.get_config().clone()
    };
    
    let error_page_config = {
        let error_page_generator = state.error_page_generator.read().await;
        error_page_generator.get_config().clone()
    };
    
    let config = serde_json::json!({
        "recovery_config": recovery_config,
        "error_page_config": error_page_config
    });
    
    info!("Retrieved error configuration");
    Ok(Json(config))
}

/// Update error configuration
async fn update_error_config(
    State(state): State<ErrorTrackingAdminState>,
    Json(request): Json<ErrorConfigUpdateRequest>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let mut updated_components = Vec::new();
    
    if let Some(recovery_config) = request.recovery_config {
        let mut recovery_manager = state.recovery_manager.write().await;
        recovery_manager.update_config(recovery_config);
        updated_components.push("recovery_config");
        info!("Updated recovery configuration");
    }
    
    if let Some(error_page_config) = request.error_page_config {
        let mut error_page_generator = state.error_page_generator.write().await;
        error_page_generator.update_config(error_page_config)
            .map_err(|e| GatewayError::internal(format!("Failed to update error page config: {}", e)))?;
        updated_components.push("error_page_config");
        info!("Updated error page configuration");
    }
    
    Ok(Json(serde_json::json!({
        "message": "Configuration updated successfully",
        "updated_components": updated_components
    })))
}

/// Get recovery metrics
async fn get_recovery_metrics(
    State(state): State<ErrorTrackingAdminState>,
) -> Result<Json<RecoveryMetrics>, GatewayError> {
    let recovery_manager = state.recovery_manager.read().await;
    let metrics = recovery_manager.get_metrics();
    
    info!("Retrieved recovery metrics");
    Ok(Json(metrics))
}

/// Get recovery configuration
async fn get_recovery_config(
    State(state): State<ErrorTrackingAdminState>,
) -> Result<Json<RecoveryConfig>, GatewayError> {
    let recovery_manager = state.recovery_manager.read().await;
    let config = recovery_manager.get_config().clone();
    
    info!("Retrieved recovery configuration");
    Ok(Json(config))
}

/// Update recovery configuration
async fn update_recovery_config(
    State(state): State<ErrorTrackingAdminState>,
    Json(config): Json<RecoveryConfig>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let mut recovery_manager = state.recovery_manager.write().await;
    recovery_manager.update_config(config);
    
    info!("Updated recovery configuration");
    Ok(Json(serde_json::json!({
        "message": "Recovery configuration updated successfully"
    })))
}

/// Reset recovery metrics
async fn reset_recovery_metrics(
    State(state): State<ErrorTrackingAdminState>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let recovery_manager = state.recovery_manager.read().await;
    recovery_manager.reset_metrics();
    
    info!("Reset recovery metrics");
    Ok(Json(serde_json::json!({
        "message": "Recovery metrics reset successfully"
    })))
}

/// Get error page configuration
async fn get_error_page_config(
    State(state): State<ErrorTrackingAdminState>,
) -> Result<Json<ErrorPageConfig>, GatewayError> {
    let error_page_generator = state.error_page_generator.read().await;
    let config = error_page_generator.get_config().clone();
    
    info!("Retrieved error page configuration");
    Ok(Json(config))
}

/// Update error page configuration
async fn update_error_page_config(
    State(state): State<ErrorTrackingAdminState>,
    Json(config): Json<ErrorPageConfig>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let mut error_page_generator = state.error_page_generator.write().await;
    error_page_generator.update_config(config)
        .map_err(|e| GatewayError::internal(format!("Failed to update error page config: {}", e)))?;
    
    info!("Updated error page configuration");
    Ok(Json(serde_json::json!({
        "message": "Error page configuration updated successfully"
    })))
}

/// Preview error page for a specific status code
async fn preview_error_page(
    State(state): State<ErrorTrackingAdminState>,
    Path(status_code): Path<u16>,
) -> Result<axum::response::Response, GatewayError> {
    let error_page_generator = state.error_page_generator.read().await;
    
    // Create a sample error for the given status code
    let sample_error = match status_code {
        400 => GatewayError::RequestValidation {
            field: "sample_field".to_string(),
            reason: "Sample validation error".to_string(),
        },
        401 => GatewayError::Authentication {
            reason: "Sample authentication error".to_string(),
        },
        403 => GatewayError::Authorization {
            reason: "Sample authorization error".to_string(),
        },
        404 => GatewayError::internal("Sample not found error"),
        429 => GatewayError::RateLimitExceeded {
            limit: 100,
            window: "minute".to_string(),
        },
        500 => GatewayError::internal("Sample internal server error"),
        502 => GatewayError::LoadBalancing {
            message: "Sample bad gateway error".to_string(),
        },
        503 => GatewayError::ServiceUnavailable {
            service: "sample-service".to_string(),
            reason: "Sample service unavailable".to_string(),
        },
        504 => GatewayError::Timeout { timeout_ms: 5000 },
        _ => GatewayError::internal("Sample error"),
    };
    
    let headers = axum::http::HeaderMap::new();
    let response = error_page_generator.generate_error_response(
        &sample_error,
        &headers,
        Some("/api/sample"),
        Some("preview-request-123"),
    );
    
    info!("Generated error page preview for status code: {}", status_code);
    Ok(response)
}

/// Get active alerts
async fn get_active_alerts(
    State(_state): State<ErrorTrackingAdminState>,
) -> Result<Json<Vec<ErrorAlert>>, GatewayError> {
    // In a real implementation, you would maintain an alert store
    // For now, return empty list
    let alerts = Vec::new();
    
    info!("Retrieved active alerts");
    Ok(Json(alerts))
}

/// Stream alerts in real-time (Server-Sent Events)
async fn stream_alerts(
    State(state): State<ErrorTrackingAdminState>,
) -> Result<axum::response::Sse<impl futures::Stream<Item = Result<axum::response::sse::Event, std::convert::Infallible>>>, GatewayError> {
    use axum::response::sse::{Event, Sse};
    use futures::StreamExt;
    use tokio_stream::wrappers::BroadcastStream;
    
    // Get a new alert receiver
    let alert_receiver = state.error_tracker.subscribe_to_alerts();
    let alert_stream = BroadcastStream::new(alert_receiver);
    
    let event_stream = alert_stream.map(|result| {
        match result {
            Ok(alert) => {
                let event_data = serde_json::to_string(&alert).unwrap_or_default();
                Ok(Event::default().data(event_data))
            }
            Err(_) => {
                // Handle broadcast error (e.g., lagged receiver)
                Ok(Event::default().data("{}"))
            }
        }
    });
    
    info!("Started alert streaming");
    Ok(Sse::new(event_stream))
}

/// Error tracking admin router
pub struct ErrorTrackingAdminRouter;

impl ErrorTrackingAdminRouter {
    /// Create the admin router with the given state
    pub fn create_router(state: ErrorTrackingAdminState) -> Router {
        create_error_tracking_admin_router().with_state(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::error_tracking::ErrorPatternConfig;
    use crate::core::error_recovery::RecoveryConfig;
    use crate::core::error_pages::ErrorPageConfig;
    use axum::http::StatusCode;
    use axum_test::TestServer;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    async fn create_test_state() -> ErrorTrackingAdminState {
        let error_tracker = Arc::new(ErrorTracker::new(ErrorPatternConfig::default()));
        let recovery_manager = Arc::new(RwLock::new(ErrorRecoveryManager::new(RecoveryConfig::default())));
        let error_page_generator = Arc::new(RwLock::new(
            ErrorPageGenerator::new(ErrorPageConfig::default()).unwrap()
        ));
        let alert_receiver = Arc::new(RwLock::new(error_tracker.subscribe_to_alerts()));
        
        ErrorTrackingAdminState {
            error_tracker,
            recovery_manager,
            error_page_generator,
            alert_receiver,
        }
    }

    #[tokio::test]
    async fn test_get_error_stats() {
        let state = create_test_state().await;
        let app = ErrorTrackingAdminRouter::create_router(state);
        let server = TestServer::new(app).unwrap();
        
        let response = server.get("/errors/stats").await;
        assert_eq!(response.status_code(), StatusCode::OK);
    }
    
    #[tokio::test]
    async fn test_get_error_summary() {
        let state = create_test_state().await;
        let app = ErrorTrackingAdminRouter::create_router(state);
        let server = TestServer::new(app).unwrap();
        
        let response = server.get("/errors/summary").await;
        assert_eq!(response.status_code(), StatusCode::OK);
    }
    
    #[tokio::test]
    async fn test_get_error_dashboard() {
        let state = create_test_state().await;
        let app = ErrorTrackingAdminRouter::create_router(state);
        let server = TestServer::new(app).unwrap();
        
        let response = server.get("/errors/dashboard").await;
        assert_eq!(response.status_code(), StatusCode::OK);
    }
    
    #[tokio::test]
    async fn test_preview_error_page() {
        let state = create_test_state().await;
        let app = ErrorTrackingAdminRouter::create_router(state);
        let server = TestServer::new(app).unwrap();
        
        let response = server.get("/errors/pages/preview/404").await;
        assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
        
        let response = server.get("/errors/pages/preview/500").await;
        assert_eq!(response.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}