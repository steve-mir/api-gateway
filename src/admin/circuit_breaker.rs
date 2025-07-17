//! Circuit Breaker Admin Endpoints
//! 
//! This module provides administrative endpoints for managing circuit breakers.
//! It allows administrators to:
//! - View circuit breaker status and metrics
//! - Manually override circuit breaker states
//! - Configure circuit breaker parameters
//! - Reset circuit breaker metrics
//! 
//! ## Security Note
//! These endpoints should be protected with appropriate authentication
//! as they can affect service availability.

use std::sync::Arc;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post, put, delete},
    Router,
};
use serde::{Deserialize, Serialize};


use crate::core::circuit_breaker::{
    CircuitBreakerConfig, CircuitBreakerRegistry, 
    CircuitBreakerState, CircuitBreakerMetricsSnapshot
};
use crate::middleware::circuit_breaker::CircuitBreakerLayer;

/// Admin state for circuit breaker management
#[derive(Clone)]
pub struct CircuitBreakerAdminState {
    /// Circuit breaker registry
    pub registry: Arc<CircuitBreakerRegistry>,
    
    /// Circuit breaker layer for accessing configuration
    pub layer: Option<CircuitBreakerLayer>,
}

impl CircuitBreakerAdminState {
    /// Create new circuit breaker admin state
    pub fn new(registry: Arc<CircuitBreakerRegistry>) -> Self {
        Self {
            registry,
            layer: None,
        }
    }
    
    /// Create with circuit breaker layer
    pub fn with_layer(registry: Arc<CircuitBreakerRegistry>, layer: CircuitBreakerLayer) -> Self {
        Self {
            registry,
            layer: Some(layer),
        }
    }
}

/// Circuit breaker admin router
pub struct CircuitBreakerAdminRouter;

impl CircuitBreakerAdminRouter {
    /// Create circuit breaker admin routes
    pub fn create_router(state: CircuitBreakerAdminState) -> Router {
        Router::new()
            .route("/circuit-breakers", get(list_circuit_breakers))
            .route("/circuit-breakers/:name", get(get_circuit_breaker))
            .route("/circuit-breakers/:name/state", get(get_circuit_breaker_state))
            .route("/circuit-breakers/:name/metrics", get(get_circuit_breaker_metrics))
            .route("/circuit-breakers/:name/config", get(get_circuit_breaker_config))
            .route("/circuit-breakers/:name/config", put(update_circuit_breaker_config))
            .route("/circuit-breakers/:name/force-open", post(force_circuit_breaker_open))
            .route("/circuit-breakers/:name/force-close", post(force_circuit_breaker_close))
            .route("/circuit-breakers/:name/force-half-open", post(force_circuit_breaker_half_open))
            .route("/circuit-breakers/:name/reset-metrics", post(reset_circuit_breaker_metrics))
            .route("/circuit-breakers/:name", delete(remove_circuit_breaker))
            .route("/circuit-breakers/health", get(get_circuit_breakers_health))
            .with_state(state)
    }
}

/// Response for circuit breaker list
#[derive(Debug, Serialize)]
pub struct CircuitBreakerListResponse {
    pub circuit_breakers: Vec<CircuitBreakerSummary>,
    pub total_count: usize,
}

/// Summary information about a circuit breaker
#[derive(Debug, Clone, Serialize)]
pub struct CircuitBreakerSummary {
    pub name: String,
    pub state: String,
    pub failure_rate: f64,
    pub total_requests: u64,
    pub rejected_requests: u64,
    pub state_duration_ms: u64,
}

/// Detailed circuit breaker information
#[derive(Debug, Serialize)]
pub struct CircuitBreakerDetails {
    pub name: String,
    pub state: CircuitBreakerStateInfo,
    pub config: CircuitBreakerConfig,
    pub metrics: CircuitBreakerMetricsSnapshot,
}

/// Circuit breaker state information
#[derive(Debug, Serialize)]
pub struct CircuitBreakerStateInfo {
    pub state_type: String,
    pub failure_count: Option<u32>,
    pub success_count: Option<u32>,
    pub opened_at: Option<String>,
    pub duration_ms: u64,
}

/// Request for updating circuit breaker configuration
#[derive(Debug, Deserialize)]
pub struct UpdateCircuitBreakerConfigRequest {
    pub failure_threshold: Option<u32>,
    pub timeout_seconds: Option<u64>,
    pub success_threshold: Option<u32>,
    pub half_open_max_requests: Option<u32>,
}

/// Query parameters for listing circuit breakers
#[derive(Debug, Deserialize)]
pub struct ListCircuitBreakersQuery {
    pub state: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// Response for manual state change operations
#[derive(Debug, Serialize)]
pub struct StateChangeResponse {
    pub success: bool,
    pub message: String,
    pub new_state: String,
}

/// Health status for all circuit breakers
#[derive(Debug, Serialize)]
pub struct CircuitBreakersHealthResponse {
    pub healthy: bool,
    pub total_circuit_breakers: usize,
    pub open_circuit_breakers: usize,
    pub half_open_circuit_breakers: usize,
    pub closed_circuit_breakers: usize,
    pub overall_failure_rate: f64,
}

/// List all circuit breakers
async fn list_circuit_breakers(
    State(state): State<CircuitBreakerAdminState>,
    Query(query): Query<ListCircuitBreakersQuery>,
) -> Result<Json<CircuitBreakerListResponse>, StatusCode> {
    let circuit_breakers = state.registry.get_all();
    
    let mut summaries: Vec<CircuitBreakerSummary> = circuit_breakers
        .iter()
        .map(|cb| {
            let cb_state = cb.state();
            let metrics = cb.metrics();
            let metrics_snapshot = metrics.snapshot();
            
            CircuitBreakerSummary {
                name: cb.name().to_string(),
                state: format_state(&cb_state),
                failure_rate: metrics.failure_rate(),
                total_requests: metrics_snapshot.total_requests,
                rejected_requests: metrics_snapshot.rejected_requests,
                state_duration_ms: metrics_snapshot.current_state_duration_ms,
            }
        })
        .collect();
    
    // Filter by state if requested
    if let Some(state_filter) = &query.state {
        summaries.retain(|s| s.state.to_lowercase() == state_filter.to_lowercase());
    }
    
    // Apply pagination
    let total_count = summaries.len();
    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(100);
    
    if offset < summaries.len() {
        let end = std::cmp::min(offset + limit, summaries.len());
        summaries = summaries[offset..end].to_vec();
    } else {
        summaries.clear();
    }
    
    Ok(Json(CircuitBreakerListResponse {
        circuit_breakers: summaries,
        total_count,
    }))
}

/// Get detailed information about a specific circuit breaker
async fn get_circuit_breaker(
    State(state): State<CircuitBreakerAdminState>,
    Path(name): Path<String>,
) -> Result<Json<CircuitBreakerDetails>, StatusCode> {
    let circuit_breakers = state.registry.get_all();
    
    let circuit_breaker = circuit_breakers
        .iter()
        .find(|cb| cb.name() == name)
        .ok_or(StatusCode::NOT_FOUND)?;
    
    let cb_state = circuit_breaker.state();
    let config = circuit_breaker.config().clone();
    let metrics = circuit_breaker.metrics();
    let metrics_snapshot = metrics.snapshot();
    
    let state_info = CircuitBreakerStateInfo {
        state_type: format_state(&cb_state),
        failure_count: match cb_state {
            CircuitBreakerState::Closed { failure_count } => Some(failure_count),
            _ => None,
        },
        success_count: match cb_state {
            CircuitBreakerState::HalfOpen { success_count } => Some(success_count),
            _ => None,
        },
        opened_at: match cb_state {
            CircuitBreakerState::Open { opened_at } => {
                Some(format!("{:?}", opened_at))
            }
            _ => None,
        },
        duration_ms: metrics_snapshot.current_state_duration_ms,
    };
    
    Ok(Json(CircuitBreakerDetails {
        name: circuit_breaker.name().to_string(),
        state: state_info,
        config,
        metrics: metrics_snapshot,
    }))
}

/// Get circuit breaker state only
async fn get_circuit_breaker_state(
    State(state): State<CircuitBreakerAdminState>,
    Path(name): Path<String>,
) -> Result<Json<CircuitBreakerStateInfo>, StatusCode> {
    let circuit_breakers = state.registry.get_all();
    
    let circuit_breaker = circuit_breakers
        .iter()
        .find(|cb| cb.name() == name)
        .ok_or(StatusCode::NOT_FOUND)?;
    
    let cb_state = circuit_breaker.state();
    let metrics = circuit_breaker.metrics();
    let metrics_snapshot = metrics.snapshot();
    
    let state_info = CircuitBreakerStateInfo {
        state_type: format_state(&cb_state),
        failure_count: match cb_state {
            CircuitBreakerState::Closed { failure_count } => Some(failure_count),
            _ => None,
        },
        success_count: match cb_state {
            CircuitBreakerState::HalfOpen { success_count } => Some(success_count),
            _ => None,
        },
        opened_at: match cb_state {
            CircuitBreakerState::Open { opened_at } => {
                Some(format!("{:?}", opened_at))
            }
            _ => None,
        },
        duration_ms: metrics_snapshot.current_state_duration_ms,
    };
    
    Ok(Json(state_info))
}

/// Get circuit breaker metrics
async fn get_circuit_breaker_metrics(
    State(state): State<CircuitBreakerAdminState>,
    Path(name): Path<String>,
) -> Result<Json<CircuitBreakerMetricsSnapshot>, StatusCode> {
    let circuit_breakers = state.registry.get_all();
    
    let circuit_breaker = circuit_breakers
        .iter()
        .find(|cb| cb.name() == name)
        .ok_or(StatusCode::NOT_FOUND)?;
    
    let metrics = circuit_breaker.metrics();
    let metrics_snapshot = metrics.snapshot();
    
    Ok(Json(metrics_snapshot))
}

/// Get circuit breaker configuration
async fn get_circuit_breaker_config(
    State(state): State<CircuitBreakerAdminState>,
    Path(name): Path<String>,
) -> Result<Json<CircuitBreakerConfig>, StatusCode> {
    let circuit_breakers = state.registry.get_all();
    
    let circuit_breaker = circuit_breakers
        .iter()
        .find(|cb| cb.name() == name)
        .ok_or(StatusCode::NOT_FOUND)?;
    
    Ok(Json(circuit_breaker.config().clone()))
}

/// Update circuit breaker configuration
/// 
/// Note: This is a simplified implementation. In production, you would want
/// to update the configuration in the registry and persist changes.
async fn update_circuit_breaker_config(
    State(_state): State<CircuitBreakerAdminState>,
    Path(_name): Path<String>,
    Json(_request): Json<UpdateCircuitBreakerConfigRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // This would require more complex configuration management
    // For now, return a placeholder response
    Ok(Json(serde_json::json!({
        "message": "Configuration update not implemented in this version",
        "note": "This would require integration with the configuration management system"
    })))
}

/// Force circuit breaker to open state
async fn force_circuit_breaker_open(
    State(state): State<CircuitBreakerAdminState>,
    Path(name): Path<String>,
) -> Result<Json<StateChangeResponse>, StatusCode> {
    let circuit_breakers = state.registry.get_all();
    
    let circuit_breaker = circuit_breakers
        .iter()
        .find(|cb| cb.name() == name)
        .ok_or(StatusCode::NOT_FOUND)?;
    
    circuit_breaker.force_open();
    
    Ok(Json(StateChangeResponse {
        success: true,
        message: format!("Circuit breaker '{}' forced to open state", name),
        new_state: "open".to_string(),
    }))
}

/// Force circuit breaker to close state
async fn force_circuit_breaker_close(
    State(state): State<CircuitBreakerAdminState>,
    Path(name): Path<String>,
) -> Result<Json<StateChangeResponse>, StatusCode> {
    let circuit_breakers = state.registry.get_all();
    
    let circuit_breaker = circuit_breakers
        .iter()
        .find(|cb| cb.name() == name)
        .ok_or(StatusCode::NOT_FOUND)?;
    
    circuit_breaker.force_close();
    
    Ok(Json(StateChangeResponse {
        success: true,
        message: format!("Circuit breaker '{}' forced to close state", name),
        new_state: "closed".to_string(),
    }))
}

/// Force circuit breaker to half-open state
async fn force_circuit_breaker_half_open(
    State(state): State<CircuitBreakerAdminState>,
    Path(name): Path<String>,
) -> Result<Json<StateChangeResponse>, StatusCode> {
    let circuit_breakers = state.registry.get_all();
    
    let circuit_breaker = circuit_breakers
        .iter()
        .find(|cb| cb.name() == name)
        .ok_or(StatusCode::NOT_FOUND)?;
    
    circuit_breaker.force_half_open();
    
    Ok(Json(StateChangeResponse {
        success: true,
        message: format!("Circuit breaker '{}' forced to half-open state", name),
        new_state: "half-open".to_string(),
    }))
}

/// Reset circuit breaker metrics
async fn reset_circuit_breaker_metrics(
    State(state): State<CircuitBreakerAdminState>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let circuit_breakers = state.registry.get_all();
    
    let circuit_breaker = circuit_breakers
        .iter()
        .find(|cb| cb.name() == name)
        .ok_or(StatusCode::NOT_FOUND)?;
    
    circuit_breaker.reset_metrics();
    
    Ok(Json(serde_json::json!({
        "success": true,
        "message": format!("Metrics reset for circuit breaker '{}'", name)
    })))
}

/// Remove circuit breaker from registry
async fn remove_circuit_breaker(
    State(state): State<CircuitBreakerAdminState>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let removed = state.registry.remove(&name);
    
    if removed.is_some() {
        Ok(Json(serde_json::json!({
            "success": true,
            "message": format!("Circuit breaker '{}' removed", name)
        })))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

/// Get overall health status of all circuit breakers
async fn get_circuit_breakers_health(
    State(state): State<CircuitBreakerAdminState>,
) -> Result<Json<CircuitBreakersHealthResponse>, StatusCode> {
    let circuit_breakers = state.registry.get_all();
    
    let mut open_count = 0;
    let mut half_open_count = 0;
    let mut closed_count = 0;
    let mut total_requests = 0u64;
    let mut total_failures = 0u64;
    
    for cb in &circuit_breakers {
        match cb.state() {
            CircuitBreakerState::Open { .. } => open_count += 1,
            CircuitBreakerState::HalfOpen { .. } => half_open_count += 1,
            CircuitBreakerState::Closed { .. } => closed_count += 1,
        }
        
        let metrics = cb.metrics();
        let snapshot = metrics.snapshot();
        total_requests += snapshot.total_requests;
        total_failures += snapshot.failed_requests;
    }
    
    let overall_failure_rate = if total_requests > 0 {
        (total_failures as f64 / total_requests as f64) * 100.0
    } else {
        0.0
    };
    
    // Consider system healthy if no circuit breakers are open
    let healthy = open_count == 0;
    
    Ok(Json(CircuitBreakersHealthResponse {
        healthy,
        total_circuit_breakers: circuit_breakers.len(),
        open_circuit_breakers: open_count,
        half_open_circuit_breakers: half_open_count,
        closed_circuit_breakers: closed_count,
        overall_failure_rate,
    }))
}

/// Helper function to format circuit breaker state as string
fn format_state(state: &CircuitBreakerState) -> String {
    match state {
        CircuitBreakerState::Closed { .. } => "closed".to_string(),
        CircuitBreakerState::Open { .. } => "open".to_string(),
        CircuitBreakerState::HalfOpen { .. } => "half-open".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{Method, Request};
    use tower::ServiceExt;
    use std::time::Duration;
    
    #[tokio::test]
    async fn test_list_circuit_breakers() {
        let registry = Arc::new(CircuitBreakerRegistry::new());
        
        // Create some test circuit breakers
        let config = CircuitBreakerConfig::default();
        registry.get_or_create("service1", config.clone());
        registry.get_or_create("service2", config);
        
        let state = CircuitBreakerAdminState::new(registry);
        let app = CircuitBreakerAdminRouter::create_router(state);
        
        let request = Request::builder()
            .method(Method::GET)
            .uri("/circuit-breakers")
            .body("".into())
            .unwrap();
        
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    
    #[tokio::test]
    async fn test_get_circuit_breaker_not_found() {
        let registry = Arc::new(CircuitBreakerRegistry::new());
        let state = CircuitBreakerAdminState::new(registry);
        let app = CircuitBreakerAdminRouter::create_router(state);
        
        let request = Request::builder()
            .method(Method::GET)
            .uri("/circuit-breakers/nonexistent")
            .body("".into())
            .unwrap();
        
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
    
    #[tokio::test]
    async fn test_force_circuit_breaker_open() {
        let registry = Arc::new(CircuitBreakerRegistry::new());
        let config = CircuitBreakerConfig::default();
        let cb = registry.get_or_create("test-service", config);
        
        let state = CircuitBreakerAdminState::new(registry);
        let app = CircuitBreakerAdminRouter::create_router(state);
        
        let request = Request::builder()
            .method(Method::POST)
            .uri("/circuit-breakers/test-service/force-open")
            .body("".into())
            .unwrap();
        
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        
        // Verify circuit breaker is now open
        assert!(matches!(cb.state(), CircuitBreakerState::Open { .. }));
    }
    
    #[test]
    fn test_format_state() {
        assert_eq!(format_state(&CircuitBreakerState::Closed { failure_count: 0 }), "closed");
        assert_eq!(format_state(&CircuitBreakerState::Open { opened_at: Instant::now() }), "open");
        assert_eq!(format_state(&CircuitBreakerState::HalfOpen { success_count: 0 }), "half-open");
    }
}