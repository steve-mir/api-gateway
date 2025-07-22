//! # Admin Endpoints
//!
//! This module provides HTTP endpoints for runtime configuration management.
//! These endpoints allow administrators to:
//! - View current configuration
//! - Modify configuration at runtime
//! - View configuration change history
//! - Rollback to previous configurations
//!
//! ## Security Note
//! These endpoints should be protected with appropriate authentication and authorization
//! as they can modify the gateway's behavior.

use crate::core::config::GatewayConfig;
use crate::admin::{ConfigAudit, ConfigChange, ConfigChangeType, RuntimeConfigManager, ServiceManagementRouter, ServiceManagementState, LoadBalancerAdminRouter, LoadBalancerAdminState};
use crate::traffic::admin_stub::{TrafficAdminRouter, TrafficAdminState};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post, put},
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Admin router state
#[derive(Clone)]
pub struct AdminState {
    pub config_manager: Arc<RuntimeConfigManager>,
    pub audit: Arc<ConfigAudit>,
    pub service_management: Option<ServiceManagementState>,
    pub load_balancer: Option<LoadBalancerAdminState>,
    pub traffic_management: Option<TrafficAdminState>,
}

/// Admin router for configuration management endpoints
pub struct AdminRouter;

impl AdminRouter {
    /// Create the admin router with all endpoints
    pub fn create_router(state: AdminState) -> Router {
        let mut router = Router::new()
            // Configuration endpoints
            .route("/config", get(get_current_config))
            .route("/config", put(update_full_config))
            .route("/config/validate", post(validate_config))
            
            // Route management endpoints
            .route("/config/routes", get(get_routes))
            .route("/config/routes", post(add_route))
            .route("/config/routes/:route_id", put(update_route))
            .route("/config/routes/:route_id", axum::routing::delete(delete_route))
            
            // Upstream management endpoints
            .route("/config/upstreams", get(get_upstreams))
            .route("/config/upstreams", post(add_upstream))
            .route("/config/upstreams/:upstream_name", put(update_upstream))
            .route("/config/upstreams/:upstream_name", axum::routing::delete(delete_upstream))
            
            // Audit and history endpoints
            .route("/audit/changes", get(get_audit_history))
            .route("/audit/changes/:change_id", get(get_audit_record))
            .route("/audit/statistics", get(get_audit_statistics))
            
            // Rollback endpoints
            .route("/config/rollback/:change_id", post(rollback_to_change))
            .route("/config/rollback/candidates", get(get_rollback_candidates))
            
            // Health and status endpoints
            .route("/status", get(get_admin_status))
            .with_state(state.clone());

        // Add service management routes if service management is enabled
        if let Some(service_management_state) = state.service_management {
            router = router.nest("/services", ServiceManagementRouter::create_router(service_management_state));
        }

        // Add load balancer admin routes if load balancer management is enabled
        if let Some(load_balancer_state) = state.load_balancer {
            router = router.nest("/load-balancer", LoadBalancerAdminRouter::create_router(load_balancer_state));
        }

        // Add traffic management routes if traffic management is enabled
        if let Some(traffic_management_state) = state.traffic_management {
            router = router.nest("/traffic", TrafficAdminRouter::create_router(traffic_management_state));
        }

        router
    }
}

// ============================================================================
// Configuration Management Endpoints
// ============================================================================

/// Get the current gateway configuration
async fn get_current_config(
    State(state): State<AdminState>,
) -> Result<Json<ConfigResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.config_manager.get_current_config().await {
        Ok(config) => Ok(Json(ConfigResponse {
            config,
            last_modified: state.config_manager.get_last_modified().await,
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to get current configuration".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

/// Update the full gateway configuration
async fn update_full_config(
    State(state): State<AdminState>,
    Json(request): Json<UpdateConfigRequest>,
) -> Result<Json<ConfigUpdateResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Validate the new configuration
    if let Err(e) = request.config.validate() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Configuration validation failed".to_string(),
                details: Some(e.to_string()),
            }),
        ));
    }

    match state.config_manager.update_config(
        request.config,
        request.changed_by.unwrap_or_else(|| "admin".to_string()),
        request.description.unwrap_or_else(|| "Full configuration update".to_string()),
        request.metadata.unwrap_or_default(),
    ).await {
        Ok(change_id) => Ok(Json(ConfigUpdateResponse {
            success: true,
            change_id,
            message: "Configuration updated successfully".to_string(),
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to update configuration".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

/// Validate a configuration without applying it
async fn validate_config(
    Json(config): Json<GatewayConfig>,
) -> Result<Json<ValidationResponse>, (StatusCode, Json<ErrorResponse>)> {
    match config.validate() {
        Ok(()) => Ok(Json(ValidationResponse {
            valid: true,
            errors: Vec::new(),
        })),
        Err(e) => Ok(Json(ValidationResponse {
            valid: false,
            errors: vec![e.to_string()],
        })),
    }
}

// ============================================================================
// Route Management Endpoints
// ============================================================================

/// Get all routes
async fn get_routes(
    State(state): State<AdminState>,
) -> Result<Json<RoutesResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.config_manager.get_current_config().await {
        Ok(config) => Ok(Json(RoutesResponse {
            routes: config.routes,
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to get routes".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

/// Add a new route
async fn add_route(
    State(state): State<AdminState>,
    Json(request): Json<AddRouteRequest>,
) -> Result<Json<ConfigUpdateResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.config_manager.add_route(
        request.route,
        request.changed_by.unwrap_or_else(|| "admin".to_string()),
        request.description.unwrap_or_else(|| "Added new route".to_string()),
    ).await {
        Ok(change_id) => Ok(Json(ConfigUpdateResponse {
            success: true,
            change_id,
            message: "Route added successfully".to_string(),
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to add route".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

/// Update an existing route
async fn update_route(
    State(state): State<AdminState>,
    Path(route_id): Path<String>,
    Json(request): Json<UpdateRouteRequest>,
) -> Result<Json<ConfigUpdateResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.config_manager.update_route(
        &route_id,
        request.route,
        request.changed_by.unwrap_or_else(|| "admin".to_string()),
        request.description.unwrap_or_else(|| format!("Updated route {}", route_id)),
    ).await {
        Ok(change_id) => Ok(Json(ConfigUpdateResponse {
            success: true,
            change_id,
            message: "Route updated successfully".to_string(),
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to update route".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

/// Delete a route
async fn delete_route(
    State(state): State<AdminState>,
    Path(route_id): Path<String>,
    Query(params): Query<DeleteRouteParams>,
) -> Result<Json<ConfigUpdateResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.config_manager.delete_route(
        &route_id,
        params.changed_by.unwrap_or_else(|| "admin".to_string()),
        params.description.unwrap_or_else(|| format!("Deleted route {}", route_id)),
    ).await {
        Ok(change_id) => Ok(Json(ConfigUpdateResponse {
            success: true,
            change_id,
            message: "Route deleted successfully".to_string(),
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to delete route".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

// ============================================================================
// Upstream Management Endpoints
// ============================================================================

/// Get all upstreams
async fn get_upstreams(
    State(state): State<AdminState>,
) -> Result<Json<UpstreamsResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.config_manager.get_current_config().await {
        Ok(config) => Ok(Json(UpstreamsResponse {
            upstreams: config.upstreams,
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to get upstreams".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

/// Add a new upstream
async fn add_upstream(
    State(state): State<AdminState>,
    Json(request): Json<AddUpstreamRequest>,
) -> Result<Json<ConfigUpdateResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.config_manager.add_upstream(
        request.name,
        request.upstream,
        request.changed_by.unwrap_or_else(|| "admin".to_string()),
        request.description.unwrap_or_else(|| "Added new upstream".to_string()),
    ).await {
        Ok(change_id) => Ok(Json(ConfigUpdateResponse {
            success: true,
            change_id,
            message: "Upstream added successfully".to_string(),
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to add upstream".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

/// Update an existing upstream
async fn update_upstream(
    State(state): State<AdminState>,
    Path(upstream_name): Path<String>,
    Json(request): Json<UpdateUpstreamRequest>,
) -> Result<Json<ConfigUpdateResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.config_manager.update_upstream(
        &upstream_name,
        request.upstream,
        request.changed_by.unwrap_or_else(|| "admin".to_string()),
        request.description.unwrap_or_else(|| format!("Updated upstream {}", upstream_name)),
    ).await {
        Ok(change_id) => Ok(Json(ConfigUpdateResponse {
            success: true,
            change_id,
            message: "Upstream updated successfully".to_string(),
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to update upstream".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

/// Delete an upstream
async fn delete_upstream(
    State(state): State<AdminState>,
    Path(upstream_name): Path<String>,
    Query(params): Query<DeleteUpstreamParams>,
) -> Result<Json<ConfigUpdateResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.config_manager.delete_upstream(
        &upstream_name,
        params.changed_by.unwrap_or_else(|| "admin".to_string()),
        params.description.unwrap_or_else(|| format!("Deleted upstream {}", upstream_name)),
    ).await {
        Ok(change_id) => Ok(Json(ConfigUpdateResponse {
            success: true,
            change_id,
            message: "Upstream deleted successfully".to_string(),
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to delete upstream".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

// ============================================================================
// Audit and History Endpoints
// ============================================================================

/// Get audit history with pagination
async fn get_audit_history(
    State(state): State<AdminState>,
    Query(params): Query<AuditHistoryParams>,
) -> Result<Json<AuditHistoryResponse>, (StatusCode, Json<ErrorResponse>)> {
    let offset = params.offset.unwrap_or(0);
    let limit = params.limit.unwrap_or(50).min(1000); // Cap at 1000 records

    let records = if let Some(change_type) = params.change_type {
        state.audit.get_records_by_type(change_type).await
    } else if let Some(user) = params.user {
        state.audit.get_records_by_user(&user).await
    } else {
        state.audit.get_records_paginated(offset, limit).await
    };

    Ok(Json(AuditHistoryResponse {
        records,
        offset,
        limit,
        total: state.audit.get_all_records().await.len(),
    }))
}

/// Get a specific audit record
async fn get_audit_record(
    State(state): State<AdminState>,
    Path(change_id): Path<Uuid>,
) -> Result<Json<ConfigChange>, (StatusCode, Json<ErrorResponse>)> {
    match state.audit.get_record_by_id(change_id).await {
        Some(record) => Ok(Json(record)),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Audit record not found".to_string(),
                details: None,
            }),
        )),
    }
}

/// Get audit statistics
async fn get_audit_statistics(
    State(state): State<AdminState>,
) -> Result<Json<crate::admin::audit::AuditStatistics>, (StatusCode, Json<ErrorResponse>)> {
    let stats = state.audit.get_statistics().await;
    Ok(Json(stats))
}

// ============================================================================
// Rollback Endpoints
// ============================================================================

/// Rollback to a specific configuration change
async fn rollback_to_change(
    State(state): State<AdminState>,
    Path(change_id): Path<Uuid>,
    Json(request): Json<RollbackRequest>,
) -> Result<Json<ConfigUpdateResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.config_manager.rollback_to_change(
        change_id,
        request.changed_by.unwrap_or_else(|| "admin".to_string()),
        request.description.unwrap_or_else(|| format!("Rollback to change {}", change_id)),
    ).await {
        Ok(new_change_id) => Ok(Json(ConfigUpdateResponse {
            success: true,
            change_id: new_change_id,
            message: "Configuration rolled back successfully".to_string(),
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to rollback configuration".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

/// Get rollback candidates
async fn get_rollback_candidates(
    State(state): State<AdminState>,
    Query(params): Query<RollbackCandidatesParams>,
) -> Result<Json<RollbackCandidatesResponse>, (StatusCode, Json<ErrorResponse>)> {
    let limit = params.limit.unwrap_or(10).min(100);
    let candidates = state.audit.get_rollback_candidates(limit).await;
    
    Ok(Json(RollbackCandidatesResponse {
        candidates,
    }))
}

// ============================================================================
// Status Endpoints
// ============================================================================

/// Get admin service status
async fn get_admin_status(
    State(state): State<AdminState>,
) -> Result<Json<AdminStatusResponse>, (StatusCode, Json<ErrorResponse>)> {
    let config_last_modified = state.config_manager.get_last_modified().await;
    let audit_stats = state.audit.get_statistics().await;
    
    Ok(Json(AdminStatusResponse {
        status: "healthy".to_string(),
        config_last_modified,
        total_audit_records: audit_stats.total_changes,
        successful_changes: audit_stats.successful_changes,
        failed_changes: audit_stats.failed_changes,
    }))
}

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Serialize)]
struct ConfigResponse {
    config: GatewayConfig,
    last_modified: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
struct UpdateConfigRequest {
    config: GatewayConfig,
    changed_by: Option<String>,
    description: Option<String>,
    metadata: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct ConfigUpdateResponse {
    success: bool,
    change_id: Uuid,
    message: String,
}

#[derive(Debug, Serialize)]
struct ValidationResponse {
    valid: bool,
    errors: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
    details: Option<String>,
}

#[derive(Debug, Serialize)]
struct RoutesResponse {
    routes: Vec<crate::core::config::RouteDefinition>,
}

#[derive(Debug, Deserialize)]
struct AddRouteRequest {
    route: crate::core::config::RouteDefinition,
    changed_by: Option<String>,
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateRouteRequest {
    route: crate::core::config::RouteDefinition,
    changed_by: Option<String>,
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DeleteRouteParams {
    changed_by: Option<String>,
    description: Option<String>,
}

#[derive(Debug, Serialize)]
struct UpstreamsResponse {
    upstreams: HashMap<String, crate::core::config::UpstreamConfig>,
}

#[derive(Debug, Deserialize)]
struct AddUpstreamRequest {
    name: String,
    upstream: crate::core::config::UpstreamConfig,
    changed_by: Option<String>,
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateUpstreamRequest {
    upstream: crate::core::config::UpstreamConfig,
    changed_by: Option<String>,
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DeleteUpstreamParams {
    changed_by: Option<String>,
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AuditHistoryParams {
    offset: Option<usize>,
    limit: Option<usize>,
    change_type: Option<ConfigChangeType>,
    user: Option<String>,
}

#[derive(Debug, Serialize)]
struct AuditHistoryResponse {
    records: Vec<ConfigChange>,
    offset: usize,
    limit: usize,
    total: usize,
}

#[derive(Debug, Deserialize)]
struct RollbackRequest {
    changed_by: Option<String>,
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RollbackCandidatesParams {
    limit: Option<usize>,
}

#[derive(Debug, Serialize)]
struct RollbackCandidatesResponse {
    candidates: Vec<ConfigChange>,
}

#[derive(Debug, Serialize)]
struct AdminStatusResponse {
    status: String,
    config_last_modified: Option<DateTime<Utc>>,
    total_audit_records: usize,
    successful_changes: usize,
    failed_changes: usize,
}