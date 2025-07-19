//! # Admin Middleware Management Endpoints
//!
//! This module provides admin endpoints for managing the middleware pipeline,
//! including configuration updates, metrics collection, and runtime management.

use axum::{
    extract::{Path, Query, State},
    // http::StatusCode,
    response::Json,
    routing::{delete, get, post, put},
    Router,
};
use serde::{Deserialize, Serialize};
// use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

use crate::core::error::GatewayError;
use crate::middleware::pipeline_fixed::{
    MiddlewarePipeline, MiddlewarePipelineConfig, MiddlewareConfig, PipelineMetricsSnapshot,
};

/// Admin state for middleware management
#[derive(Debug, Clone)]
pub struct MiddlewareAdminState {
    /// Reference to the middleware pipeline
    pub pipeline: Arc<MiddlewarePipeline>,
    
    /// Configuration history for rollback
    pub config_history: Arc<RwLock<Vec<MiddlewarePipelineConfig>>>,
    
    /// Maximum history entries to keep
    pub max_history_entries: usize,
}

impl MiddlewareAdminState {
    pub fn new(pipeline: Arc<MiddlewarePipeline>) -> Self {
        Self {
            pipeline,
            config_history: Arc::new(RwLock::new(Vec::new())),
            max_history_entries: 10,
        }
    }

    /// Save current configuration to history
    async fn save_to_history(&self, config: MiddlewarePipelineConfig) {
        let mut history = self.config_history.write().await;
        history.push(config);
        
        // Keep only the last N entries
        if history.len() > self.max_history_entries {
            let excess = history.len() - self.max_history_entries;
            history.drain(0..excess);
        }
    }
}

/// Query parameters for middleware listing
#[derive(Debug, Deserialize)]
pub struct MiddlewareListQuery {
    /// Filter by middleware type
    pub middleware_type: Option<String>,
    
    /// Filter by enabled status
    pub enabled: Option<bool>,
    
    /// Include detailed configuration
    pub include_config: Option<bool>,
}

/// Request body for updating middleware configuration
#[derive(Debug, Deserialize)]
pub struct UpdateMiddlewareConfigRequest {
    pub config: MiddlewarePipelineConfig,
}

/// Request body for adding a single middleware
#[derive(Debug, Deserialize)]
pub struct AddMiddlewareRequest {
    pub middleware: MiddlewareConfig,
}

/// Request body for updating a single middleware
#[derive(Debug, Deserialize)]
pub struct UpdateMiddlewareRequest {
    pub middleware: MiddlewareConfig,
}

/// Response for middleware listing
#[derive(Debug, Serialize)]
pub struct MiddlewareListResponse {
    pub middleware: Vec<MiddlewareInfo>,
    pub total_count: usize,
    pub active_count: usize,
}

/// Information about a middleware instance
#[derive(Debug, Serialize)]
pub struct MiddlewareInfo {
    pub name: String,
    pub middleware_type: String,
    pub priority: i32,
    pub enabled: bool,
    pub conditions: Vec<crate::middleware::pipeline_fixed::MiddlewareCondition>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<serde_json::Value>,
}

/// Response for pipeline status
#[derive(Debug, Serialize)]
pub struct PipelineStatusResponse {
    pub active_middleware: Vec<String>,
    pub total_middleware: usize,
    pub pipeline_metrics: PipelineMetricsSnapshot,
    pub last_config_update: Option<String>,
}

/// Response for configuration history
#[derive(Debug, Serialize)]
pub struct ConfigHistoryResponse {
    pub history: Vec<ConfigHistoryEntry>,
    pub current_version: usize,
}

#[derive(Debug, Serialize)]
pub struct ConfigHistoryEntry {
    pub version: usize,
    pub timestamp: String,
    pub middleware_count: usize,
    pub summary: String,
}

/// Create admin router for middleware management
pub fn create_middleware_admin_router() -> Router<MiddlewareAdminState> {
    Router::new()
        .route("/middleware", get(list_middleware))
        .route("/middleware", post(add_middleware))
        .route("/middleware/config", get(get_pipeline_config))
        .route("/middleware/config", put(update_pipeline_config))
        .route("/middleware/config/history", get(get_config_history))
        .route("/middleware/config/rollback/:version", post(rollback_config))
        .route("/middleware/:name", get(get_middleware))
        .route("/middleware/:name", put(update_middleware))
        .route("/middleware/:name", delete(remove_middleware))
        .route("/middleware/:name/enable", post(enable_middleware))
        .route("/middleware/:name/disable", post(disable_middleware))
        .route("/pipeline/status", get(get_pipeline_status))
        .route("/pipeline/metrics", get(get_pipeline_metrics))
        .route("/pipeline/reload", post(reload_pipeline))
}

/// List all middleware in the pipeline
async fn list_middleware(
    State(state): State<MiddlewareAdminState>,
    Query(query): Query<MiddlewareListQuery>,
) -> Result<Json<MiddlewareListResponse>, GatewayError> {
    debug!("Listing middleware with query: {:?}", query);
    
    let config = state.pipeline.get_config().await;
    let active_middleware = state.pipeline.get_active_middleware().await;
    
    let mut middleware_info = Vec::new();
    
    for middleware_config in &config.middleware {
        // Apply filters
        if let Some(ref filter_type) = query.middleware_type {
            if middleware_config.middleware_type != *filter_type {
                continue;
            }
        }
        
        if let Some(filter_enabled) = query.enabled {
            if middleware_config.enabled != filter_enabled {
                continue;
            }
        }
        
        let info = MiddlewareInfo {
            name: middleware_config.name.clone(),
            middleware_type: middleware_config.middleware_type.clone(),
            priority: middleware_config.priority,
            enabled: middleware_config.enabled,
            conditions: middleware_config.conditions.clone(),
            config: if query.include_config.unwrap_or(false) {
                Some(middleware_config.config.clone())
            } else {
                None
            },
        };
        
        middleware_info.push(info);
    }
    
    let response = MiddlewareListResponse {
        total_count: middleware_info.len(),
        active_count: active_middleware.len(),
        middleware: middleware_info,
    };
    
    Ok(Json(response))
}

/// Get information about a specific middleware
async fn get_middleware(
    State(state): State<MiddlewareAdminState>,
    Path(name): Path<String>,
) -> Result<Json<MiddlewareInfo>, GatewayError> {
    debug!("Getting middleware info for: {}", name);
    
    let config = state.pipeline.get_config().await;
    
    for middleware_config in &config.middleware {
        if middleware_config.name == name {
            let info = MiddlewareInfo {
                name: middleware_config.name.clone(),
                middleware_type: middleware_config.middleware_type.clone(),
                priority: middleware_config.priority,
                enabled: middleware_config.enabled,
                conditions: middleware_config.conditions.clone(),
                config: Some(middleware_config.config.clone()),
            };
            
            return Ok(Json(info));
        }
    }
    
    Err(GatewayError::internal(format!("Middleware '{}' not found", name)))
}

/// Add a new middleware to the pipeline
async fn add_middleware(
    State(state): State<MiddlewareAdminState>,
    Json(request): Json<AddMiddlewareRequest>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    info!("Adding middleware: {}", request.middleware.name);
    
    let mut config = state.pipeline.get_config().await;
    
    // Check if middleware already exists
    if config.middleware.iter().any(|m| m.name == request.middleware.name) {
        return Err(GatewayError::Configuration {
            message: format!("Middleware '{}' already exists", request.middleware.name),
        });
    }
    
    // Save current config to history
    state.save_to_history(config.clone()).await;
    
    // Add the new middleware
    config.middleware.push(request.middleware);
    
    // Update the pipeline
    state.pipeline.update_config(config).await?;
    
    Ok(Json(serde_json::json!({
        "message": "Middleware added successfully",
        "status": "success"
    })))
}

/// Update an existing middleware
async fn update_middleware(
    State(state): State<MiddlewareAdminState>,
    Path(name): Path<String>,
    Json(request): Json<UpdateMiddlewareRequest>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    info!("Updating middleware: {}", name);
    
    let mut config = state.pipeline.get_config().await;
    
    // Save current config to history before making changes
    state.save_to_history(config.clone()).await;
    
    // Find and update the middleware
    let mut found = false;
    for middleware_config in &mut config.middleware {
        if middleware_config.name == name {
            *middleware_config = request.middleware;
            found = true;
            break;
        }
    }
    
    if !found {
        return Err(GatewayError::internal(format!("Middleware '{}' not found", name)));
    }
    
    // Update the pipeline
    state.pipeline.update_config(config).await?;
    
    Ok(Json(serde_json::json!({
        "message": "Middleware updated successfully",
        "status": "success"
    })))
}

/// Remove a middleware from the pipeline
async fn remove_middleware(
    State(state): State<MiddlewareAdminState>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    info!("Removing middleware: {}", name);
    
    let mut config = state.pipeline.get_config().await;
    
    // Save current config to history
    state.save_to_history(config.clone()).await;
    
    // Remove the middleware
    let initial_len = config.middleware.len();
    config.middleware.retain(|m| m.name != name);
    
    if config.middleware.len() == initial_len {
        return Err(GatewayError::internal(format!("Middleware '{}' not found", name)));
    }
    
    // Update the pipeline
    state.pipeline.update_config(config).await?;
    
    Ok(Json(serde_json::json!({
        "message": "Middleware removed successfully",
        "status": "success"
    })))
}

/// Enable a middleware
async fn enable_middleware(
    State(state): State<MiddlewareAdminState>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    info!("Enabling middleware: {}", name);
    
    let mut config = state.pipeline.get_config().await;
    
    // Save current config to history before making changes
    state.save_to_history(config.clone()).await;
    
    // Find and enable the middleware
    let mut found = false;
    for middleware_config in &mut config.middleware {
        if middleware_config.name == name {
            if !middleware_config.enabled {
                middleware_config.enabled = true;
                found = true;
            } else {
                return Ok(Json(serde_json::json!({
                    "message": "Middleware is already enabled",
                    "status": "no_change"
                })));
            }
            break;
        }
    }
    
    if !found {
        return Err(GatewayError::internal(format!("Middleware '{}' not found", name)));
    }
    
    // Update the pipeline
    state.pipeline.update_config(config).await?;
    
    Ok(Json(serde_json::json!({
        "message": "Middleware enabled successfully",
        "status": "success"
    })))
}

/// Disable a middleware
async fn disable_middleware(
    State(state): State<MiddlewareAdminState>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    info!("Disabling middleware: {}", name);
    
    let mut config = state.pipeline.get_config().await;
    
    // Save current config to history before making changes
    state.save_to_history(config.clone()).await;
    
    // Find and disable the middleware
    let mut found = false;
    for middleware_config in &mut config.middleware {
        if middleware_config.name == name {
            if middleware_config.enabled {
                middleware_config.enabled = false;
                found = true;
            } else {
                return Ok(Json(serde_json::json!({
                    "message": "Middleware is already disabled",
                    "status": "no_change"
                })));
            }
            break;
        }
    }
    
    if !found {
        return Err(GatewayError::internal(format!("Middleware '{}' not found", name)));
    }
    
    // Update the pipeline
    state.pipeline.update_config(config).await?;
    
    Ok(Json(serde_json::json!({
        "message": "Middleware disabled successfully",
        "status": "success"
    })))
}

/// Get current pipeline configuration
async fn get_pipeline_config(
    State(state): State<MiddlewareAdminState>,
) -> Result<Json<MiddlewarePipelineConfig>, GatewayError> {
    debug!("Getting pipeline configuration");
    
    let config = state.pipeline.get_config().await;
    Ok(Json(config))
}

/// Update the entire pipeline configuration
async fn update_pipeline_config(
    State(state): State<MiddlewareAdminState>,
    Json(request): Json<UpdateMiddlewareConfigRequest>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    info!("Updating pipeline configuration");
    
    // Save current config to history
    let current_config = state.pipeline.get_config().await;
    state.save_to_history(current_config).await;
    
    // Update the pipeline
    state.pipeline.update_config(request.config).await?;
    
    Ok(Json(serde_json::json!({
        "message": "Pipeline configuration updated successfully",
        "status": "success"
    })))
}

/// Get pipeline status
async fn get_pipeline_status(
    State(state): State<MiddlewareAdminState>,
) -> Result<Json<PipelineStatusResponse>, GatewayError> {
    debug!("Getting pipeline status");
    
    let active_middleware = state.pipeline.get_active_middleware().await;
    let config = state.pipeline.get_config().await;
    let metrics = state.pipeline.get_metrics();
    
    let response = PipelineStatusResponse {
        total_middleware: config.middleware.len(),
        active_middleware: active_middleware.clone(),
        pipeline_metrics: metrics,
        last_config_update: Some(chrono::Utc::now().to_rfc3339()),
    };
    
    Ok(Json(response))
}

/// Get pipeline metrics
async fn get_pipeline_metrics(
    State(state): State<MiddlewareAdminState>,
) -> Result<Json<PipelineMetricsSnapshot>, GatewayError> {
    debug!("Getting pipeline metrics");
    
    let metrics = state.pipeline.get_metrics();
    Ok(Json(metrics))
}

/// Reload the pipeline from current configuration
async fn reload_pipeline(
    State(state): State<MiddlewareAdminState>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    info!("Reloading pipeline");
    
    state.pipeline.reload_middleware().await?;
    
    Ok(Json(serde_json::json!({
        "message": "Pipeline reloaded successfully",
        "status": "success"
    })))
}

/// Get configuration history
async fn get_config_history(
    State(state): State<MiddlewareAdminState>,
) -> Result<Json<ConfigHistoryResponse>, GatewayError> {
    debug!("Getting configuration history");
    
    let history = state.config_history.read().await;
    let mut history_entries = Vec::new();
    
    for (index, config) in history.iter().enumerate() {
        let entry = ConfigHistoryEntry {
            version: index + 1,
            timestamp: chrono::Utc::now().to_rfc3339(), // In real implementation, store actual timestamps
            middleware_count: config.middleware.len(),
            summary: format!("{} middleware configured", config.middleware.len()),
        };
        history_entries.push(entry);
    }
    
    let response = ConfigHistoryResponse {
        current_version: history_entries.len(),
        history: history_entries,
    };
    
    Ok(Json(response))
}

/// Rollback to a previous configuration
async fn rollback_config(
    State(state): State<MiddlewareAdminState>,
    Path(version): Path<usize>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    info!("Rolling back to configuration version: {}", version);
    
    let history = state.config_history.read().await;
    
    if version == 0 || version > history.len() {
        return Err(GatewayError::Configuration {
            message: format!("Invalid version: {}. Available versions: 1-{}", version, history.len()),
        });
    }
    
    let config_to_restore = history[version - 1].clone();
    drop(history); // Release the read lock
    
    // Save current config to history before rollback
    let current_config = state.pipeline.get_config().await;
    state.save_to_history(current_config).await;
    
    // Apply the rollback configuration
    state.pipeline.update_config(config_to_restore).await?;
    
    Ok(Json(serde_json::json!({
        "message": format!("Successfully rolled back to version {}", version),
        "status": "success"
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::middleware::pipeline_fixed::{MiddlewarePipelineConfig, PipelineSettings};
    use axum::http::StatusCode;
    use axum_test::TestServer;

    async fn create_test_state() -> MiddlewareAdminState {
        let config = MiddlewarePipelineConfig {
            middleware: vec![],
            settings: PipelineSettings::default(),
        };
        
        let pipeline = Arc::new(MiddlewarePipeline::new(config).await.unwrap());
        MiddlewareAdminState::new(pipeline)
    }

    #[tokio::test]
    async fn test_list_middleware() {
        let state = create_test_state().await;
        let app = create_middleware_admin_router().with_state(state);
        let server = TestServer::new(app).unwrap();

        let response = server.get("/middleware").await;
        assert_eq!(response.status_code(), StatusCode::OK);
        
        let body: MiddlewareListResponse = response.json();
        assert_eq!(body.total_count, 0);
        assert_eq!(body.active_count, 0);
    }

    #[tokio::test]
    async fn test_get_pipeline_status() {
        let state = create_test_state().await;
        let app = create_middleware_admin_router().with_state(state);
        let server = TestServer::new(app).unwrap();

        let response = server.get("/pipeline/status").await;
        assert_eq!(response.status_code(), StatusCode::OK);
        
        let body: PipelineStatusResponse = response.json();
        assert_eq!(body.total_middleware, 0);
        assert_eq!(body.active_middleware.len(), 0);
    }

    #[tokio::test]
    async fn test_get_pipeline_metrics() {
        let state = create_test_state().await;
        let app = create_middleware_admin_router().with_state(state);
        let server = TestServer::new(app).unwrap();

        let response = server.get("/pipeline/metrics").await;
        assert_eq!(response.status_code(), StatusCode::OK);
        
        let body: PipelineMetricsSnapshot = response.json();
        assert_eq!(body.total_executions, 0);
    }
}