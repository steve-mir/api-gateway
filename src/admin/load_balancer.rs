//! # Load Balancer Admin Endpoints
//!
//! This module provides HTTP endpoints for runtime load balancer management.
//! These endpoints allow administrators to:
//! - Switch between load balancing algorithms
//! - View load balancer statistics
//! - Configure algorithm-specific settings
//! - Monitor load balancer performance
//!
//! ## Security Note
//! These endpoints should be protected with appropriate authentication and authorization
//! as they can modify the gateway's load balancing behavior.

use crate::load_balancing::balancer::{LoadBalancer, LoadBalancerManager, LoadBalancerStats};
use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::{get, post, put},
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Load balancer admin router state
#[derive(Clone)]
pub struct LoadBalancerAdminState {
    pub load_balancer_manager: Arc<LoadBalancerManager>,
}

/// Load balancer admin router
pub struct LoadBalancerAdminRouter;

impl LoadBalancerAdminRouter {
    /// Create the load balancer admin router with all endpoints
    pub fn create_router(state: LoadBalancerAdminState) -> Router {
        Router::new()
            // Algorithm management endpoints
            .route("/algorithm", get(get_current_algorithm))
            .route("/algorithm", put(switch_algorithm))
            .route("/algorithms", get(get_available_algorithms))
            
            // Statistics endpoints
            .route("/stats", get(get_current_stats))
            .route("/stats/all", get(get_all_stats))
            .route("/stats/reset", post(reset_current_stats))
            
            // Health and status endpoints
            .route("/status", get(get_load_balancer_status))
            
            // Configuration endpoints
            .route("/config", get(get_load_balancer_config))
            .route("/config", put(update_load_balancer_config))
            
            .with_state(state)
    }
}

// ============================================================================
// Algorithm Management Endpoints
// ============================================================================

/// Get the current load balancing algorithm
async fn get_current_algorithm(
    State(state): State<LoadBalancerAdminState>,
) -> Result<Json<CurrentAlgorithmResponse>, (StatusCode, Json<ErrorResponse>)> {
    let current_algorithm = state.load_balancer_manager.current_algorithm();
    let available_algorithms = state.load_balancer_manager.available_algorithms();
    
    Ok(Json(CurrentAlgorithmResponse {
        current_algorithm,
        available_algorithms,
    }))
}

/// Switch to a different load balancing algorithm
async fn switch_algorithm(
    State(state): State<LoadBalancerAdminState>,
    Json(request): Json<SwitchAlgorithmRequest>,
) -> Result<Json<SwitchAlgorithmResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.load_balancer_manager.switch_algorithm(&request.algorithm) {
        Ok(()) => Ok(Json(SwitchAlgorithmResponse {
            success: true,
            previous_algorithm: state.load_balancer_manager.current_algorithm(),
            new_algorithm: request.algorithm.clone(),
            message: format!("Successfully switched to {} algorithm", request.algorithm),
        })),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Failed to switch algorithm".to_string(),
                details: Some(e),
            }),
        )),
    }
}

/// Get all available load balancing algorithms
async fn get_available_algorithms(
    State(state): State<LoadBalancerAdminState>,
) -> Result<Json<AvailableAlgorithmsResponse>, (StatusCode, Json<ErrorResponse>)> {
    let algorithms = state.load_balancer_manager.available_algorithms();
    let current = state.load_balancer_manager.current_algorithm();
    
    let algorithm_info = algorithms.into_iter().map(|name| {
        AlgorithmInfo {
            name: name.clone(),
            is_current: name == current,
            description: get_algorithm_description(&name),
            features: get_algorithm_features(&name),
        }
    }).collect();
    
    Ok(Json(AvailableAlgorithmsResponse {
        algorithms: algorithm_info,
    }))
}

// ============================================================================
// Statistics Endpoints
// ============================================================================

/// Get statistics for the current load balancer
async fn get_current_stats(
    State(state): State<LoadBalancerAdminState>,
) -> Result<Json<LoadBalancerStats>, (StatusCode, Json<ErrorResponse>)> {
    let stats = state.load_balancer_manager.get_current_stats().await;
    Ok(Json(stats))
}

/// Get statistics for all load balancers
async fn get_all_stats(
    State(state): State<LoadBalancerAdminState>,
) -> Result<Json<AllStatsResponse>, (StatusCode, Json<ErrorResponse>)> {
    let all_stats = state.load_balancer_manager.get_all_stats().await;
    let current_algorithm = state.load_balancer_manager.current_algorithm();
    
    // Convert HashMap to a new HashMap to avoid lifetime issues
    let stats_map = all_stats.into_iter().collect();
    
    Ok(Json(AllStatsResponse {
        current_algorithm,
        stats: stats_map,
    }))
}

/// Reset statistics for the current load balancer
async fn reset_current_stats(
    State(state): State<LoadBalancerAdminState>,
) -> Result<Json<ResetStatsResponse>, (StatusCode, Json<ErrorResponse>)> {
    state.load_balancer_manager.reset().await;
    
    Ok(Json(ResetStatsResponse {
        success: true,
        algorithm: state.load_balancer_manager.current_algorithm(),
        message: "Statistics reset successfully".to_string(),
    }))
}

// ============================================================================
// Status and Configuration Endpoints
// ============================================================================

/// Get load balancer status and health information
async fn get_load_balancer_status(
    State(state): State<LoadBalancerAdminState>,
) -> Result<Json<LoadBalancerStatusResponse>, (StatusCode, Json<ErrorResponse>)> {
    let current_stats = state.load_balancer_manager.get_current_stats().await;
    let current_algorithm = state.load_balancer_manager.current_algorithm();
    
    // Calculate health metrics
    let total_requests = current_stats.total_requests;
    let failed_selections = current_stats.failed_selections;
    let success_rate = if total_requests > 0 {
        ((total_requests - failed_selections) as f64 / total_requests as f64) * 100.0
    } else {
        100.0
    };
    
    let health_status = if success_rate >= 95.0 {
        "healthy"
    } else if success_rate >= 80.0 {
        "degraded"
    } else {
        "unhealthy"
    };
    
    Ok(Json(LoadBalancerStatusResponse {
        status: health_status.to_string(),
        current_algorithm,
        total_requests,
        failed_selections,
        success_rate,
        active_instances: current_stats.instance_stats.len(),
        uptime: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    }))
}

/// Get load balancer configuration
async fn get_load_balancer_config(
    State(state): State<LoadBalancerAdminState>,
) -> Result<Json<LoadBalancerConfigResponse>, (StatusCode, Json<ErrorResponse>)> {
    let current_algorithm = state.load_balancer_manager.current_algorithm();
    let available_algorithms = state.load_balancer_manager.available_algorithms();
    
    Ok(Json(LoadBalancerConfigResponse {
        current_algorithm,
        available_algorithms,
        algorithm_configs: get_algorithm_configs(),
    }))
}

/// Update load balancer configuration
async fn update_load_balancer_config(
    State(state): State<LoadBalancerAdminState>,
    Json(request): Json<UpdateLoadBalancerConfigRequest>,
) -> Result<Json<UpdateConfigResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Switch algorithm if requested
    if let Some(new_algorithm) = request.algorithm {
        if let Err(e) = state.load_balancer_manager.switch_algorithm(&new_algorithm) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Failed to switch algorithm".to_string(),
                    details: Some(e),
                }),
            ));
        }
    }
    
    // Reset stats if requested
    if request.reset_stats.unwrap_or(false) {
        state.load_balancer_manager.reset().await;
    }
    
    Ok(Json(UpdateConfigResponse {
        success: true,
        current_algorithm: state.load_balancer_manager.current_algorithm(),
        message: "Load balancer configuration updated successfully".to_string(),
    }))
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Get description for a load balancing algorithm
fn get_algorithm_description(algorithm: &str) -> String {
    match algorithm {
        "round_robin" => "Distributes requests evenly across all healthy instances in a circular fashion".to_string(),
        "least_connections" => "Routes requests to the instance with the fewest active connections".to_string(),
        "weighted" => "Distributes requests based on configured instance weights".to_string(),
        "consistent_hash" => "Uses consistent hashing to provide session affinity based on request characteristics".to_string(),
        _ => "Unknown algorithm".to_string(),
    }
}

/// Get features for a load balancing algorithm
fn get_algorithm_features(algorithm: &str) -> Vec<String> {
    match algorithm {
        "round_robin" => vec![
            "Simple and fast".to_string(),
            "Even distribution".to_string(),
            "No state tracking".to_string(),
        ],
        "least_connections" => vec![
            "Connection-aware".to_string(),
            "Handles varying request durations".to_string(),
            "Real-time connection tracking".to_string(),
        ],
        "weighted" => vec![
            "Configurable instance weights".to_string(),
            "Proportional traffic distribution".to_string(),
            "Supports heterogeneous instances".to_string(),
        ],
        "consistent_hash" => vec![
            "Session affinity".to_string(),
            "Stable request routing".to_string(),
            "Minimal disruption on instance changes".to_string(),
        ],
        _ => vec!["Unknown features".to_string()],
    }
}

/// Get default configurations for all algorithms
fn get_algorithm_configs() -> HashMap<String, serde_json::Value> {
    let mut configs = HashMap::new();
    
    configs.insert("round_robin".to_string(), serde_json::json!({
        "description": "No configuration required",
        "parameters": {}
    }));
    
    configs.insert("least_connections".to_string(), serde_json::json!({
        "description": "Tracks active connections per instance",
        "parameters": {
            "connection_timeout": "30s",
            "cleanup_interval": "60s"
        }
    }));
    
    configs.insert("weighted".to_string(), serde_json::json!({
        "description": "Uses instance weights for distribution",
        "parameters": {
            "default_weight": 1,
            "weight_source": "instance_metadata"
        }
    }));
    
    configs.insert("consistent_hash".to_string(), serde_json::json!({
        "description": "Provides session affinity using consistent hashing",
        "parameters": {
            "virtual_nodes": 150,
            "hash_key_sources": ["x-session-id", "x-user-id", "authorization", "client-ip"]
        }
    }));
    
    configs
}

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Serialize)]
struct CurrentAlgorithmResponse {
    current_algorithm: String,
    available_algorithms: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SwitchAlgorithmRequest {
    algorithm: String,
}

#[derive(Debug, Serialize)]
struct SwitchAlgorithmResponse {
    success: bool,
    previous_algorithm: String,
    new_algorithm: String,
    message: String,
}

#[derive(Debug, Serialize)]
struct AvailableAlgorithmsResponse {
    algorithms: Vec<AlgorithmInfo>,
}

#[derive(Debug, Serialize)]
struct AlgorithmInfo {
    name: String,
    is_current: bool,
    description: String,
    features: Vec<String>,
}

#[derive(Debug, Serialize)]
struct AllStatsResponse {
    current_algorithm: String,
    stats: HashMap<String, LoadBalancerStats>,
}

#[derive(Debug, Serialize)]
struct ResetStatsResponse {
    success: bool,
    algorithm: String,
    message: String,
}

#[derive(Debug, Serialize)]
struct LoadBalancerStatusResponse {
    status: String,
    current_algorithm: String,
    total_requests: u64,
    failed_selections: u64,
    success_rate: f64,
    active_instances: usize,
    uptime: u64,
}

#[derive(Debug, Serialize)]
struct LoadBalancerConfigResponse {
    current_algorithm: String,
    available_algorithms: Vec<String>,
    algorithm_configs: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct UpdateLoadBalancerConfigRequest {
    algorithm: Option<String>,
    reset_stats: Option<bool>,
}

#[derive(Debug, Serialize)]
struct UpdateConfigResponse {
    success: bool,
    current_algorithm: String,
    message: String,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
    details: Option<String>,
}