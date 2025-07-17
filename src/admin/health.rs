//! # Health Check Admin Endpoints
//!
//! This module provides administrative endpoints for health check configuration and management.
//! It includes functionality for:
//! - Viewing health check configurations
//! - Adding/removing health checks
//! - Manual health status overrides
//! - Health check statistics and monitoring
//!
//! ## Admin Endpoints
//! - GET /admin/health - Get gateway health status
//! - GET /admin/health/instances - Get all instance health statuses
//! - GET /admin/health/instances/{id} - Get specific instance health
//! - POST /admin/health/instances/{id}/override - Manually override instance health
//! - DELETE /admin/health/instances/{id}/override - Remove manual override
//! - GET /admin/health/config - Get all health check configurations
//! - POST /admin/health/config - Add new health check configuration
//! - PUT /admin/health/config/{name} - Update health check configuration
//! - DELETE /admin/health/config/{name} - Remove health check configuration
//! - GET /admin/health/stats - Get health check statistics

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post, put},
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::info;


use crate::observability::health::{
    HealthChecker, HealthCheckConfig, HealthReport, HealthStats, ServiceStatus,
};

/// Admin state for health check management
#[derive(Clone)]
pub struct HealthAdminState {
    pub health_checker: Arc<HealthChecker>,
}

/// Request to manually override health status
#[derive(Debug, Deserialize)]
pub struct HealthOverrideRequest {
    pub status: ServiceStatus,
    pub reason: Option<String>,
}

/// Response for health override operation
#[derive(Debug, Serialize)]
pub struct HealthOverrideResponse {
    pub success: bool,
    pub message: String,
    pub previous_status: Option<ServiceStatus>,
}

/// Request to create or update health check configuration
#[derive(Debug, Deserialize)]
pub struct HealthConfigRequest {
    pub name: String,
    pub url: String,
    pub method: Option<String>,
    pub headers: Option<HashMap<String, String>>,
    pub body: Option<String>,
    pub interval_seconds: Option<u64>,
    pub timeout_seconds: Option<u64>,
    pub healthy_threshold: Option<u32>,
    pub unhealthy_threshold: Option<u32>,
    pub expected_status_codes: Option<Vec<u16>>,
    pub expected_body_content: Option<String>,
    pub critical: Option<bool>,
    pub enabled: Option<bool>,
}

impl From<HealthConfigRequest> for HealthCheckConfig {
    fn from(req: HealthConfigRequest) -> Self {
        HealthCheckConfig {
            name: req.name,
            url: req.url,
            method: req.method.unwrap_or_else(|| "GET".to_string()),
            headers: req.headers.unwrap_or_default(),
            body: req.body,
            interval: std::time::Duration::from_secs(req.interval_seconds.unwrap_or(30)),
            timeout: std::time::Duration::from_secs(req.timeout_seconds.unwrap_or(5)),
            healthy_threshold: req.healthy_threshold.unwrap_or(2),
            unhealthy_threshold: req.unhealthy_threshold.unwrap_or(3),
            expected_status_codes: req.expected_status_codes.unwrap_or_else(|| vec![200]),
            expected_body_content: req.expected_body_content,
            critical: req.critical.unwrap_or(true),
            enabled: req.enabled.unwrap_or(true),
        }
    }
}

/// Query parameters for health endpoints
#[derive(Debug, Deserialize)]
pub struct HealthQuery {
    pub include_details: Option<bool>,
    pub status_filter: Option<ServiceStatus>,
}

/// Health check admin router
pub struct HealthAdminRouter;

impl HealthAdminRouter {
    /// Create the health admin router
    pub fn create_router(state: HealthAdminState) -> Router {
        Router::new()
            // Gateway health endpoints
            .route("/health", get(get_gateway_health))
            .route("/health/live", get(get_liveness))
            .route("/health/ready", get(get_readiness))
            
            // Instance health endpoints
            .route("/health/instances", get(get_all_instance_health))
            .route("/health/instances/:id", get(get_instance_health))
            .route("/health/instances/:id/override", post(set_health_override))
            .route("/health/instances/:id/override", delete(remove_health_override))
            
            // Health check configuration endpoints
            .route("/health/config", get(get_health_configs))
            .route("/health/config", post(create_health_config))
            .route("/health/config/:name", get(get_health_config))
            .route("/health/config/:name", put(update_health_config))
            .route("/health/config/:name", delete(delete_health_config))
            
            // Health statistics and monitoring
            .route("/health/stats", get(get_health_stats))
            .route("/health/events", get(get_health_events))
            
            .with_state(state)
    }
}

/// Get gateway health status
async fn get_gateway_health(
    State(state): State<HealthAdminState>,
    Query(query): Query<HealthQuery>,
) -> Result<Json<HealthReport>, StatusCode> {
    let report = state.health_checker.get_gateway_health();
    
    if query.include_details.unwrap_or(true) {
        Ok(Json(report))
    } else {
        // Return simplified health status
        let simplified = HealthReport {
            status: report.status,
            timestamp: report.timestamp,
            checks: HashMap::new(),
            version: report.version,
            uptime: report.uptime,
        };
        Ok(Json(simplified))
    }
}

/// Get liveness probe endpoint (always returns healthy if gateway is running)
async fn get_liveness() -> Result<Json<serde_json::Value>, StatusCode> {
    Ok(Json(serde_json::json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().timestamp(),
        "check": "liveness"
    })))
}

/// Get readiness probe endpoint (checks if gateway is ready to serve traffic)
async fn get_readiness(
    State(state): State<HealthAdminState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let report = state.health_checker.get_gateway_health();
    
    let ready = matches!(report.status, ServiceStatus::Healthy | ServiceStatus::Degraded);
    let status_code = if ready { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE };
    
    let response = serde_json::json!({
        "status": if ready { "ready" } else { "not_ready" },
        "timestamp": report.timestamp,
        "check": "readiness",
        "details": report.status
    });
    
    if ready {
        Ok(Json(response))
    } else {
        Err(status_code)
    }
}

/// Get health status for all service instances
async fn get_all_instance_health(
    State(state): State<HealthAdminState>,
    Query(query): Query<HealthQuery>,
) -> Result<Json<HashMap<String, ServiceStatus>>, StatusCode> {
    let configs = state.health_checker.get_instance_configs();
    let mut health_statuses = HashMap::new();
    
    for instance_id in configs.keys() {
        let status = state.health_checker.get_instance_health(instance_id);
        
        // Apply status filter if specified
        if let Some(filter_status) = &query.status_filter {
            if status != *filter_status {
                continue;
            }
        }
        
        health_statuses.insert(instance_id.clone(), status);
    }
    
    Ok(Json(health_statuses))
}

/// Get health status for a specific service instance
async fn get_instance_health(
    State(state): State<HealthAdminState>,
    Path(instance_id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let status = state.health_checker.get_instance_health(&instance_id);
    
    let response = serde_json::json!({
        "instance_id": instance_id,
        "status": status,
        "timestamp": chrono::Utc::now().timestamp()
    });
    
    Ok(Json(response))
}

/// Manually override health status for a service instance
async fn set_health_override(
    State(state): State<HealthAdminState>,
    Path(instance_id): Path<String>,
    Json(request): Json<HealthOverrideRequest>,
) -> Result<Json<HealthOverrideResponse>, StatusCode> {
    let previous_status = Some(state.health_checker.get_instance_health(&instance_id));
    
    state.health_checker.set_manual_override(instance_id.clone(), request.status.clone());
    
    info!(
        "Manual health override set for instance {}: {:?} (reason: {:?})",
        instance_id, request.status, request.reason
    );
    
    let response = HealthOverrideResponse {
        success: true,
        message: format!("Health status override set to {:?}", request.status),
        previous_status,
    };
    
    Ok(Json(response))
}

/// Remove manual health status override for a service instance
async fn remove_health_override(
    State(state): State<HealthAdminState>,
    Path(instance_id): Path<String>,
) -> Result<Json<HealthOverrideResponse>, StatusCode> {
    let previous_status = Some(state.health_checker.get_instance_health(&instance_id));
    
    state.health_checker.remove_manual_override(&instance_id);
    
    info!("Manual health override removed for instance {}", instance_id);
    
    let response = HealthOverrideResponse {
        success: true,
        message: "Health status override removed".to_string(),
        previous_status,
    };
    
    Ok(Json(response))
}

/// Get all health check configurations
async fn get_health_configs(
    State(state): State<HealthAdminState>,
) -> Result<Json<HashMap<String, HealthCheckConfig>>, StatusCode> {
    let mut all_configs = HashMap::new();
    
    // Get instance health check configs
    let instance_configs = state.health_checker.get_instance_configs();
    for (id, config) in instance_configs {
        all_configs.insert(format!("instance:{}", id), config);
    }
    
    // Get gateway health check configs
    let gateway_configs = state.health_checker.get_gateway_configs();
    for (name, config) in gateway_configs {
        all_configs.insert(format!("gateway:{}", name), config);
    }
    
    Ok(Json(all_configs))
}

/// Get a specific health check configuration
async fn get_health_config(
    State(state): State<HealthAdminState>,
    Path(name): Path<String>,
) -> Result<Json<HealthCheckConfig>, StatusCode> {
    // Try to find in instance configs first
    if let Some(config) = state.health_checker.get_instance_configs().get(&name) {
        return Ok(Json(config.clone()));
    }
    
    // Try to find in gateway configs
    if let Some(config) = state.health_checker.get_gateway_configs().get(&name) {
        return Ok(Json(config.clone()));
    }
    
    Err(StatusCode::NOT_FOUND)
}

/// Create a new health check configuration
async fn create_health_config(
    State(state): State<HealthAdminState>,
    Json(request): Json<HealthConfigRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let config: HealthCheckConfig = request.into();
    let name = config.name.clone();
    
    // Determine if this is an instance or gateway health check based on the name
    if name.starts_with("instance:") {
        let instance_id = name.strip_prefix("instance:").unwrap_or(&name);
        state.health_checker.add_instance_health_check(instance_id.to_string(), config);
        info!("Created instance health check configuration: {}", instance_id);
    } else {
        state.health_checker.add_gateway_health_check(name.clone(), config);
        info!("Created gateway health check configuration: {}", name);
    }
    
    let response = serde_json::json!({
        "success": true,
        "message": format!("Health check configuration created: {}", name),
        "name": name
    });
    
    Ok(Json(response))
}

/// Update an existing health check configuration
async fn update_health_config(
    State(state): State<HealthAdminState>,
    Path(name): Path<String>,
    Json(request): Json<HealthConfigRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let config: HealthCheckConfig = request.into();
    
    // Check if the configuration exists
    let exists = state.health_checker.get_instance_configs().contains_key(&name) ||
                 state.health_checker.get_gateway_configs().contains_key(&name);
    
    if !exists {
        return Err(StatusCode::NOT_FOUND);
    }
    
    // Update the configuration
    if name.starts_with("instance:") {
        let instance_id = name.strip_prefix("instance:").unwrap_or(&name);
        state.health_checker.add_instance_health_check(instance_id.to_string(), config);
        info!("Updated instance health check configuration: {}", instance_id);
    } else {
        state.health_checker.add_gateway_health_check(name.clone(), config);
        info!("Updated gateway health check configuration: {}", name);
    }
    
    let response = serde_json::json!({
        "success": true,
        "message": format!("Health check configuration updated: {}", name),
        "name": name
    });
    
    Ok(Json(response))
}

/// Delete a health check configuration
async fn delete_health_config(
    State(state): State<HealthAdminState>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Check if the configuration exists and remove it
    let mut found = false;
    
    if name.starts_with("instance:") {
        let instance_id = name.strip_prefix("instance:").unwrap_or(&name);
        if state.health_checker.get_instance_configs().contains_key(instance_id) {
            state.health_checker.remove_instance_health_check(instance_id);
            found = true;
            info!("Deleted instance health check configuration: {}", instance_id);
        }
    } else if state.health_checker.get_gateway_configs().contains_key(&name) {
        state.health_checker.remove_gateway_health_check(&name);
        found = true;
        info!("Deleted gateway health check configuration: {}", name);
    }
    
    if !found {
        return Err(StatusCode::NOT_FOUND);
    }
    
    let response = serde_json::json!({
        "success": true,
        "message": format!("Health check configuration deleted: {}", name),
        "name": name
    });
    
    Ok(Json(response))
}

/// Get health check statistics
async fn get_health_stats(
    State(state): State<HealthAdminState>,
) -> Result<Json<HealthStats>, StatusCode> {
    let stats = state.health_checker.get_health_stats();
    Ok(Json(stats))
}

/// Get recent health events (simplified implementation)
async fn get_health_events(
    State(_state): State<HealthAdminState>,
) -> Result<Json<Vec<serde_json::Value>>, StatusCode> {
    // This is a simplified implementation
    // In a real implementation, you would store and retrieve actual health events
    let events = vec![
        serde_json::json!({
            "timestamp": chrono::Utc::now().timestamp(),
            "type": "info",
            "message": "Health events endpoint accessed"
        })
    ];
    
    Ok(Json(events))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observability::health::HealthChecker;
    use axum::http::StatusCode;
    use std::sync::Arc;

    fn create_test_state() -> HealthAdminState {
        let health_checker = Arc::new(HealthChecker::new(None));
        HealthAdminState { health_checker }
    }

    #[tokio::test]
    async fn test_get_liveness() {
        let result = get_liveness().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_get_gateway_health() {
        let state = create_test_state();
        let query = HealthQuery {
            include_details: Some(true),
            status_filter: None,
        };
        
        let result = get_gateway_health(State(state), Query(query)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_health_override() {
        let state = create_test_state();
        let instance_id = "test-instance".to_string();
        let request = HealthOverrideRequest {
            status: ServiceStatus::Healthy,
            reason: Some("Test override".to_string()),
        };
        
        let result = set_health_override(
            State(state.clone()),
            Path(instance_id.clone()),
            Json(request),
        ).await;
        
        assert!(result.is_ok());
        
        // Verify the override was set
        let status = state.health_checker.get_instance_health(&instance_id);
        assert_eq!(status, ServiceStatus::Healthy);
    }

    #[tokio::test]
    async fn test_health_config_crud() {
        let state = create_test_state();
        
        // Create config
        let request = HealthConfigRequest {
            name: "test-check".to_string(),
            url: "http://localhost:8080/health".to_string(),
            method: Some("GET".to_string()),
            headers: None,
            body: None,
            interval_seconds: Some(30),
            timeout_seconds: Some(5),
            healthy_threshold: Some(2),
            unhealthy_threshold: Some(3),
            expected_status_codes: Some(vec![200]),
            expected_body_content: None,
            critical: Some(true),
            enabled: Some(true),
        };
        
        let result = create_health_config(State(state.clone()), Json(request)).await;
        assert!(result.is_ok());
        
        // Get config
        let result = get_health_config(State(state.clone()), Path("test-check".to_string())).await;
        assert!(result.is_ok());
        
        // Delete config
        let result = delete_health_config(State(state), Path("test-check".to_string())).await;
        assert!(result.is_ok());
    }
}