//! # Traffic Management Admin Endpoints
//!
//! This module provides HTTP endpoints for managing traffic configuration,
//! A/B testing, queue management, and graceful shutdown controls.

use crate::traffic::{
    TrafficConfig, TrafficManager, BackpressureConfig, ThrottleConfig, 
    PriorityConfig, ShutdownConfig, SplitConfig, ABTestConfig,
    QueueMetrics, ShapingMetrics
};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post, put, delete},
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Traffic management admin state
#[derive(Clone)]
pub struct TrafficAdminState {
    pub traffic_manager: Arc<TrafficManager>,
}

/// Traffic management admin router
pub struct TrafficAdminRouter;

impl TrafficAdminRouter {
    /// Create the traffic admin router with all endpoints
    pub fn create_router(state: TrafficAdminState) -> Router {
        Router::new()
            // Traffic configuration endpoints
            .route("/config", get(get_traffic_config))
            .route("/config", put(update_traffic_config))
            .route("/config/validate", post(validate_traffic_config))
            
            // Queue management endpoints
            .route("/queue/config", get(get_queue_config))
            .route("/queue/config", put(update_queue_config))
            .route("/queue/metrics", get(get_queue_metrics))
            .route("/queue/clear", post(clear_queue))
            .route("/queue/pause", post(pause_queue))
            .route("/queue/resume", post(resume_queue))
            
            // Traffic shaping endpoints
            .route("/shaping/config", get(get_shaping_config))
            .route("/shaping/config", put(update_shaping_config))
            .route("/shaping/metrics", get(get_shaping_metrics))
            .route("/shaping/reset", post(reset_shaping_counters))
            
            // Priority management endpoints
            .route("/priority/config", get(get_priority_config))
            .route("/priority/config", put(update_priority_config))
            .route("/priority/rules", get(get_priority_rules))
            .route("/priority/rules", post(add_priority_rule))
            .route("/priority/rules/:rule_id", put(update_priority_rule))
            .route("/priority/rules/:rule_id", delete(delete_priority_rule))
            
            // A/B testing endpoints
            .route("/ab-tests", get(get_ab_tests))
            .route("/ab-tests", post(create_ab_test))
            .route("/ab-tests/:test_id", get(get_ab_test))
            .route("/ab-tests/:test_id", put(update_ab_test))
            .route("/ab-tests/:test_id", delete(delete_ab_test))
            .route("/ab-tests/:test_id/start", post(start_ab_test))
            .route("/ab-tests/:test_id/stop", post(stop_ab_test))
            .route("/ab-tests/:test_id/metrics", get(get_ab_test_metrics))
            
            // Traffic splitting endpoints
            .route("/splits", get(get_traffic_splits))
            .route("/splits", post(create_traffic_split))
            .route("/splits/:split_id", get(get_traffic_split))
            .route("/splits/:split_id", put(update_traffic_split))
            .route("/splits/:split_id", delete(delete_traffic_split))
            .route("/splits/:split_id/enable", post(enable_traffic_split))
            .route("/splits/:split_id/disable", post(disable_traffic_split))
            
            // Graceful shutdown endpoints
            .route("/shutdown/config", get(get_shutdown_config))
            .route("/shutdown/config", put(update_shutdown_config))
            .route("/shutdown/status", get(get_shutdown_status))
            .route("/shutdown/initiate", post(initiate_graceful_shutdown))
            .route("/shutdown/cancel", post(cancel_graceful_shutdown))
            .route("/shutdown/drain", post(drain_connections))
            
            // Overall status and metrics
            .route("/status", get(get_traffic_status))
            .route("/metrics", get(get_traffic_metrics))
            .route("/health", get(get_traffic_health))
            
            .with_state(state)
    }
}

// ============================================================================
// Traffic Configuration Endpoints
// ============================================================================

/// Get current traffic configuration
async fn get_traffic_config(
    State(state): State<TrafficAdminState>,
) -> Result<Json<TrafficConfigResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.traffic_manager.get_config().await {
        Ok(config) => Ok(Json(TrafficConfigResponse {
            config,
            last_modified: state.traffic_manager.get_last_modified().await,
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to get traffic configuration".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

/// Update traffic configuration
async fn update_traffic_config(
    State(state): State<TrafficAdminState>,
    Json(request): Json<UpdateTrafficConfigRequest>,
) -> Result<Json<ConfigUpdateResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.traffic_manager.update_config(
        request.config,
        request.changed_by.unwrap_or_else(|| "admin".to_string()),
        request.description.unwrap_or_else(|| "Traffic configuration update".to_string()),
    ).await {
        Ok(change_id) => Ok(Json(ConfigUpdateResponse {
            success: true,
            change_id,
            message: "Traffic configuration updated successfully".to_string(),
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to update traffic configuration".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

/// Validate traffic configuration
async fn validate_traffic_config(
    Json(config): Json<TrafficConfig>,
) -> Result<Json<ValidationResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Perform validation logic here
    let mut errors = Vec::new();
    
    // Validate queue config
    if config.queue.max_queue_size == 0 {
        errors.push("Queue max_queue_size must be greater than 0".to_string());
    }
    
    if config.queue.backpressure_threshold < 0.0 || config.queue.backpressure_threshold > 1.0 {
        errors.push("Backpressure threshold must be between 0.0 and 1.0".to_string());
    }
    
    // Validate shaping config
    if let Some(rps) = config.shaping.global_rps_limit {
        if rps == 0 {
            errors.push("Global RPS limit must be greater than 0".to_string());
        }
    }
    
    Ok(Json(ValidationResponse {
        valid: errors.is_empty(),
        errors,
    }))
}

// ============================================================================
// Queue Management Endpoints
// ============================================================================

/// Get queue configuration
async fn get_queue_config(
    State(state): State<TrafficAdminState>,
) -> Result<Json<QueueConfigResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.traffic_manager.get_queue_config().await {
        Ok(config) => Ok(Json(QueueConfigResponse { config })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to get queue configuration".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

/// Update queue configuration
async fn update_queue_config(
    State(state): State<TrafficAdminState>,
    Json(request): Json<UpdateQueueConfigRequest>,
) -> Result<Json<ConfigUpdateResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.traffic_manager.update_queue_config(
        request.config,
        request.changed_by.unwrap_or_else(|| "admin".to_string()),
    ).await {
        Ok(change_id) => Ok(Json(ConfigUpdateResponse {
            success: true,
            change_id,
            message: "Queue configuration updated successfully".to_string(),
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to update queue configuration".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

/// Get queue metrics
async fn get_queue_metrics(
    State(state): State<TrafficAdminState>,
) -> Result<Json<QueueMetricsResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.traffic_manager.get_queue_metrics().await {
        Ok(metrics) => Ok(Json(QueueMetricsResponse { metrics })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to get queue metrics".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

/// Clear the request queue
async fn clear_queue(
    State(state): State<TrafficAdminState>,
    Json(request): Json<QueueActionRequest>,
) -> Result<Json<QueueActionResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.traffic_manager.clear_queue(
        request.changed_by.unwrap_or_else(|| "admin".to_string()),
        request.reason.unwrap_or_else(|| "Manual queue clear".to_string()),
    ).await {
        Ok(cleared_count) => Ok(Json(QueueActionResponse {
            success: true,
            message: format!("Cleared {} requests from queue", cleared_count),
            affected_count: cleared_count,
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to clear queue".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

/// Pause request queue processing
async fn pause_queue(
    State(state): State<TrafficAdminState>,
    Json(request): Json<QueueActionRequest>,
) -> Result<Json<QueueActionResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.traffic_manager.pause_queue(
        request.changed_by.unwrap_or_else(|| "admin".to_string()),
        request.reason.unwrap_or_else(|| "Manual queue pause".to_string()),
    ).await {
        Ok(()) => Ok(Json(QueueActionResponse {
            success: true,
            message: "Queue processing paused".to_string(),
            affected_count: 0,
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to pause queue".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

/// Resume request queue processing
async fn resume_queue(
    State(state): State<TrafficAdminState>,
    Json(request): Json<QueueActionRequest>,
) -> Result<Json<QueueActionResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.traffic_manager.resume_queue(
        request.changed_by.unwrap_or_else(|| "admin".to_string()),
        request.reason.unwrap_or_else(|| "Manual queue resume".to_string()),
    ).await {
        Ok(()) => Ok(Json(QueueActionResponse {
            success: true,
            message: "Queue processing resumed".to_string(),
            affected_count: 0,
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to resume queue".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

// ============================================================================
// Traffic Shaping Endpoints
// ============================================================================

/// Get traffic shaping configuration
async fn get_shaping_config(
    State(state): State<TrafficAdminState>,
) -> Result<Json<ShapingConfigResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.traffic_manager.get_shaping_config().await {
        Ok(config) => Ok(Json(ShapingConfigResponse { config })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to get shaping configuration".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

/// Update traffic shaping configuration
async fn update_shaping_config(
    State(state): State<TrafficAdminState>,
    Json(request): Json<UpdateShapingConfigRequest>,
) -> Result<Json<ConfigUpdateResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.traffic_manager.update_shaping_config(
        request.config,
        request.changed_by.unwrap_or_else(|| "admin".to_string()),
    ).await {
        Ok(change_id) => Ok(Json(ConfigUpdateResponse {
            success: true,
            change_id,
            message: "Shaping configuration updated successfully".to_string(),
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to update shaping configuration".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

/// Get traffic shaping metrics
async fn get_shaping_metrics(
    State(state): State<TrafficAdminState>,
) -> Result<Json<ShapingMetricsResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.traffic_manager.get_shaping_metrics().await {
        Ok(metrics) => Ok(Json(ShapingMetricsResponse { metrics })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to get shaping metrics".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

/// Reset traffic shaping counters
async fn reset_shaping_counters(
    State(state): State<TrafficAdminState>,
    Json(request): Json<ResetCountersRequest>,
) -> Result<Json<ActionResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.traffic_manager.reset_shaping_counters(
        request.changed_by.unwrap_or_else(|| "admin".to_string()),
    ).await {
        Ok(()) => Ok(Json(ActionResponse {
            success: true,
            message: "Shaping counters reset successfully".to_string(),
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to reset shaping counters".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

// ============================================================================
// Priority Management Endpoints
// ============================================================================

/// Get priority configuration
async fn get_priority_config(
    State(state): State<TrafficAdminState>,
) -> Result<Json<PriorityConfigResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.traffic_manager.get_priority_config().await {
        Ok(config) => Ok(Json(PriorityConfigResponse { config })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to get priority configuration".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

/// Update priority configuration
async fn update_priority_config(
    State(state): State<TrafficAdminState>,
    Json(request): Json<UpdatePriorityConfigRequest>,
) -> Result<Json<ConfigUpdateResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.traffic_manager.update_priority_config(
        request.config,
        request.changed_by.unwrap_or_else(|| "admin".to_string()),
    ).await {
        Ok(change_id) => Ok(Json(ConfigUpdateResponse {
            success: true,
            change_id,
            message: "Priority configuration updated successfully".to_string(),
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to update priority configuration".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

/// Get priority rules
async fn get_priority_rules(
    State(state): State<TrafficAdminState>,
) -> Result<Json<PriorityRulesResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.traffic_manager.get_priority_rules().await {
        Ok(rules) => Ok(Json(PriorityRulesResponse { rules })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to get priority rules".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

/// Add a new priority rule
async fn add_priority_rule(
    State(state): State<TrafficAdminState>,
    Json(request): Json<AddPriorityRuleRequest>,
) -> Result<Json<PriorityRuleResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.traffic_manager.add_priority_rule(
        request.rule,
        request.changed_by.unwrap_or_else(|| "admin".to_string()),
    ).await {
        Ok(rule_id) => Ok(Json(PriorityRuleResponse {
            success: true,
            rule_id,
            message: "Priority rule added successfully".to_string(),
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to add priority rule".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

/// Update an existing priority rule
async fn update_priority_rule(
    State(state): State<TrafficAdminState>,
    Path(rule_id): Path<String>,
    Json(request): Json<UpdatePriorityRuleRequest>,
) -> Result<Json<PriorityRuleResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.traffic_manager.update_priority_rule(
        &rule_id,
        request.rule,
        request.changed_by.unwrap_or_else(|| "admin".to_string()),
    ).await {
        Ok(()) => Ok(Json(PriorityRuleResponse {
            success: true,
            rule_id: rule_id.clone(),
            message: "Priority rule updated successfully".to_string(),
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to update priority rule".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

/// Delete a priority rule
async fn delete_priority_rule(
    State(state): State<TrafficAdminState>,
    Path(rule_id): Path<String>,
    Query(params): Query<DeletePriorityRuleParams>,
) -> Result<Json<ActionResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.traffic_manager.delete_priority_rule(
        &rule_id,
        params.changed_by.unwrap_or_else(|| "admin".to_string()),
    ).await {
        Ok(()) => Ok(Json(ActionResponse {
            success: true,
            message: "Priority rule deleted successfully".to_string(),
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to delete priority rule".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

// ============================================================================
// A/B Testing Endpoints
// ============================================================================

/// Get all A/B tests
async fn get_ab_tests(
    State(state): State<TrafficAdminState>,
    Query(params): Query<ABTestListParams>,
) -> Result<Json<ABTestListResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.traffic_manager.get_ab_tests(
        params.status,
        params.limit.unwrap_or(50),
        params.offset.unwrap_or(0),
    ).await {
        Ok(tests) => Ok(Json(ABTestListResponse { tests })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to get A/B tests".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

/// Create a new A/B test
async fn create_ab_test(
    State(state): State<TrafficAdminState>,
    Json(request): Json<CreateABTestRequest>,
) -> Result<Json<ABTestResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.traffic_manager.create_ab_test(
        request.config,
        request.changed_by.unwrap_or_else(|| "admin".to_string()),
    ).await {
        Ok(test_id) => Ok(Json(ABTestResponse {
            success: true,
            test_id,
            message: "A/B test created successfully".to_string(),
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to create A/B test".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

/// Get a specific A/B test
async fn get_ab_test(
    State(state): State<TrafficAdminState>,
    Path(test_id): Path<String>,
) -> Result<Json<ABTestDetailsResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.traffic_manager.get_ab_test(&test_id).await {
        Ok(Some(test)) => Ok(Json(ABTestDetailsResponse { test })),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "A/B test not found".to_string(),
                details: None,
            }),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to get A/B test".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

/// Update an A/B test
async fn update_ab_test(
    State(state): State<TrafficAdminState>,
    Path(test_id): Path<String>,
    Json(request): Json<UpdateABTestRequest>,
) -> Result<Json<ABTestResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.traffic_manager.update_ab_test(
        &test_id,
        request.config,
        request.changed_by.unwrap_or_else(|| "admin".to_string()),
    ).await {
        Ok(()) => Ok(Json(ABTestResponse {
            success: true,
            test_id: test_id.clone(),
            message: "A/B test updated successfully".to_string(),
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to update A/B test".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

/// Delete an A/B test
async fn delete_ab_test(
    State(state): State<TrafficAdminState>,
    Path(test_id): Path<String>,
    Query(params): Query<DeleteABTestParams>,
) -> Result<Json<ActionResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.traffic_manager.delete_ab_test(
        &test_id,
        params.changed_by.unwrap_or_else(|| "admin".to_string()),
    ).await {
        Ok(()) => Ok(Json(ActionResponse {
            success: true,
            message: "A/B test deleted successfully".to_string(),
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to delete A/B test".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

/// Start an A/B test
async fn start_ab_test(
    State(state): State<TrafficAdminState>,
    Path(test_id): Path<String>,
    Json(request): Json<ABTestActionRequest>,
) -> Result<Json<ActionResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.traffic_manager.start_ab_test(
        &test_id,
        request.changed_by.unwrap_or_else(|| "admin".to_string()),
    ).await {
        Ok(()) => Ok(Json(ActionResponse {
            success: true,
            message: "A/B test started successfully".to_string(),
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to start A/B test".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

/// Stop an A/B test
async fn stop_ab_test(
    State(state): State<TrafficAdminState>,
    Path(test_id): Path<String>,
    Json(request): Json<ABTestActionRequest>,
) -> Result<Json<ActionResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.traffic_manager.stop_ab_test(
        &test_id,
        request.changed_by.unwrap_or_else(|| "admin".to_string()),
    ).await {
        Ok(()) => Ok(Json(ActionResponse {
            success: true,
            message: "A/B test stopped successfully".to_string(),
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to stop A/B test".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

/// Get A/B test metrics
async fn get_ab_test_metrics(
    State(state): State<TrafficAdminState>,
    Path(test_id): Path<String>,
    Query(params): Query<ABTestMetricsParams>,
) -> Result<Json<ABTestMetricsResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.traffic_manager.get_ab_test_metrics(
        &test_id,
        params.start_time,
        params.end_time,
    ).await {
        Ok(metrics) => Ok(Json(ABTestMetricsResponse { metrics })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to get A/B test metrics".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

// ============================================================================
// Traffic Splitting Endpoints
// ============================================================================

/// Get all traffic splits
async fn get_traffic_splits(
    State(state): State<TrafficAdminState>,
) -> Result<Json<TrafficSplitsResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.traffic_manager.get_traffic_splits().await {
        Ok(splits) => Ok(Json(TrafficSplitsResponse { splits })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to get traffic splits".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

/// Create a new traffic split
async fn create_traffic_split(
    State(state): State<TrafficAdminState>,
    Json(request): Json<CreateTrafficSplitRequest>,
) -> Result<Json<TrafficSplitResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.traffic_manager.create_traffic_split(
        request.config,
        request.changed_by.unwrap_or_else(|| "admin".to_string()),
    ).await {
        Ok(split_id) => Ok(Json(TrafficSplitResponse {
            success: true,
            split_id,
            message: "Traffic split created successfully".to_string(),
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to create traffic split".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

/// Get a specific traffic split
async fn get_traffic_split(
    State(state): State<TrafficAdminState>,
    Path(split_id): Path<String>,
) -> Result<Json<TrafficSplitDetailsResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.traffic_manager.get_traffic_split(&split_id).await {
        Ok(Some(split)) => Ok(Json(TrafficSplitDetailsResponse { split })),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Traffic split not found".to_string(),
                details: None,
            }),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to get traffic split".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

/// Update a traffic split
async fn update_traffic_split(
    State(state): State<TrafficAdminState>,
    Path(split_id): Path<String>,
    Json(request): Json<UpdateTrafficSplitRequest>,
) -> Result<Json<TrafficSplitResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.traffic_manager.update_traffic_split(
        &split_id,
        request.config,
        request.changed_by.unwrap_or_else(|| "admin".to_string()),
    ).await {
        Ok(()) => Ok(Json(TrafficSplitResponse {
            success: true,
            split_id: split_id.clone(),
            message: "Traffic split updated successfully".to_string(),
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to update traffic split".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

/// Delete a traffic split
async fn delete_traffic_split(
    State(state): State<TrafficAdminState>,
    Path(split_id): Path<String>,
    Query(params): Query<DeleteTrafficSplitParams>,
) -> Result<Json<ActionResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.traffic_manager.delete_traffic_split(
        &split_id,
        params.changed_by.unwrap_or_else(|| "admin".to_string()),
    ).await {
        Ok(()) => Ok(Json(ActionResponse {
            success: true,
            message: "Traffic split deleted successfully".to_string(),
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to delete traffic split".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

/// Enable a traffic split
async fn enable_traffic_split(
    State(state): State<TrafficAdminState>,
    Path(split_id): Path<String>,
    Json(request): Json<TrafficSplitActionRequest>,
) -> Result<Json<ActionResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.traffic_manager.enable_traffic_split(
        &split_id,
        request.changed_by.unwrap_or_else(|| "admin".to_string()),
    ).await {
        Ok(()) => Ok(Json(ActionResponse {
            success: true,
            message: "Traffic split enabled successfully".to_string(),
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to enable traffic split".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

/// Disable a traffic split
async fn disable_traffic_split(
    State(state): State<TrafficAdminState>,
    Path(split_id): Path<String>,
    Json(request): Json<TrafficSplitActionRequest>,
) -> Result<Json<ActionResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.traffic_manager.disable_traffic_split(
        &split_id,
        request.changed_by.unwrap_or_else(|| "admin".to_string()),
    ).await {
        Ok(()) => Ok(Json(ActionResponse {
            success: true,
            message: "Traffic split disabled successfully".to_string(),
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to disable traffic split".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

// ============================================================================
// Graceful Shutdown Endpoints
// ============================================================================

/// Get shutdown configuration
async fn get_shutdown_config(
    State(state): State<TrafficAdminState>,
) -> Result<Json<ShutdownConfigResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.traffic_manager.get_shutdown_config().await {
        Ok(config) => Ok(Json(ShutdownConfigResponse { config })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to get shutdown configuration".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

/// Update shutdown configuration
async fn update_shutdown_config(
    State(state): State<TrafficAdminState>,
    Json(request): Json<UpdateShutdownConfigRequest>,
) -> Result<Json<ConfigUpdateResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.traffic_manager.update_shutdown_config(
        request.config,
        request.changed_by.unwrap_or_else(|| "admin".to_string()),
    ).await {
        Ok(change_id) => Ok(Json(ConfigUpdateResponse {
            success: true,
            change_id,
            message: "Shutdown configuration updated successfully".to_string(),
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to update shutdown configuration".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

/// Get shutdown status
async fn get_shutdown_status(
    State(state): State<TrafficAdminState>,
) -> Result<Json<ShutdownStatusResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.traffic_manager.get_shutdown_status().await {
        Ok(status) => Ok(Json(ShutdownStatusResponse { status })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to get shutdown status".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

/// Initiate graceful shutdown
async fn initiate_graceful_shutdown(
    State(state): State<TrafficAdminState>,
    Json(request): Json<InitiateShutdownRequest>,
) -> Result<Json<ShutdownActionResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.traffic_manager.initiate_graceful_shutdown(
        request.timeout.unwrap_or(Duration::from_secs(30)),
        request.changed_by.unwrap_or_else(|| "admin".to_string()),
        request.reason.unwrap_or_else(|| "Manual shutdown".to_string()),
    ).await {
        Ok(shutdown_id) => Ok(Json(ShutdownActionResponse {
            success: true,
            shutdown_id,
            message: "Graceful shutdown initiated".to_string(),
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to initiate graceful shutdown".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

/// Cancel graceful shutdown
async fn cancel_graceful_shutdown(
    State(state): State<TrafficAdminState>,
    Json(request): Json<CancelShutdownRequest>,
) -> Result<Json<ActionResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.traffic_manager.cancel_graceful_shutdown(
        request.changed_by.unwrap_or_else(|| "admin".to_string()),
        request.reason.unwrap_or_else(|| "Manual cancellation".to_string()),
    ).await {
        Ok(()) => Ok(Json(ActionResponse {
            success: true,
            message: "Graceful shutdown cancelled".to_string(),
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to cancel graceful shutdown".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

/// Drain connections
async fn drain_connections(
    State(state): State<TrafficAdminState>,
    Json(request): Json<DrainConnectionsRequest>,
) -> Result<Json<DrainConnectionsResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.traffic_manager.drain_connections(
        request.timeout.unwrap_or(Duration::from_secs(10)),
        request.changed_by.unwrap_or_else(|| "admin".to_string()),
    ).await {
        Ok(drained_count) => Ok(Json(DrainConnectionsResponse {
            success: true,
            drained_count,
            message: format!("Drained {} connections", drained_count),
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to drain connections".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

// ============================================================================
// Overall Status and Metrics Endpoints
// ============================================================================

/// Get overall traffic status
async fn get_traffic_status(
    State(state): State<TrafficAdminState>,
) -> Result<Json<TrafficStatusResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.traffic_manager.get_overall_status().await {
        Ok(status) => Ok(Json(TrafficStatusResponse { status })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to get traffic status".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

/// Get comprehensive traffic metrics
async fn get_traffic_metrics(
    State(state): State<TrafficAdminState>,
    Query(params): Query<TrafficMetricsParams>,
) -> Result<Json<TrafficMetricsResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.traffic_manager.get_comprehensive_metrics(
        params.start_time,
        params.end_time,
        params.include_historical.unwrap_or(false),
    ).await {
        Ok(metrics) => Ok(Json(TrafficMetricsResponse { metrics })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to get traffic metrics".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

/// Get traffic health status
async fn get_traffic_health(
    State(state): State<TrafficAdminState>,
) -> Result<Json<TrafficHealthResponse>, (StatusCode, Json<ErrorResponse>)> {
    match state.traffic_manager.get_health_status().await {
        Ok(health) => Ok(Json(TrafficHealthResponse { health })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to get traffic health".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}
// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
    details: Option<String>,
}

#[derive(Debug, Serialize)]
struct ValidationResponse {
    valid: bool,
    errors: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ConfigUpdateResponse {
    success: bool,
    change_id: Uuid,
    message: String,
}

#[derive(Debug, Serialize)]
struct ActionResponse {
    success: bool,
    message: String,
}

// Traffic Configuration Types
#[derive(Debug, Serialize)]
struct TrafficConfigResponse {
    config: TrafficConfig,
    last_modified: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
struct UpdateTrafficConfigRequest {
    config: TrafficConfig,
    changed_by: Option<String>,
    description: Option<String>,
}

// Queue Management Types
#[derive(Debug, Serialize)]
struct QueueConfigResponse {
    config: BackpressureConfig,
}

#[derive(Debug, Deserialize)]
struct UpdateQueueConfigRequest {
    config: BackpressureConfig,
    changed_by: Option<String>,
}

#[derive(Debug, Serialize)]
struct QueueMetricsResponse {
    metrics: QueueMetrics,
}

#[derive(Debug, Deserialize)]
struct QueueActionRequest {
    changed_by: Option<String>,
    reason: Option<String>,
}

#[derive(Debug, Serialize)]
struct QueueActionResponse {
    success: bool,
    message: String,
    affected_count: usize,
}

// Traffic Shaping Types
#[derive(Debug, Serialize)]
struct ShapingConfigResponse {
    config: ThrottleConfig,
}

#[derive(Debug, Deserialize)]
struct UpdateShapingConfigRequest {
    config: ThrottleConfig,
    changed_by: Option<String>,
}

#[derive(Debug, Serialize)]
struct ShapingMetricsResponse {
    metrics: ShapingMetrics,
}

#[derive(Debug, Deserialize)]
struct ResetCountersRequest {
    changed_by: Option<String>,
}

// Priority Management Types
#[derive(Debug, Serialize)]
struct PriorityConfigResponse {
    config: PriorityConfig,
}

#[derive(Debug, Deserialize)]
struct UpdatePriorityConfigRequest {
    config: PriorityConfig,
    changed_by: Option<String>,
}

#[derive(Debug, Serialize)]
struct PriorityRulesResponse {
    rules: Vec<PriorityRule>,
}

#[derive(Debug, Deserialize)]
struct AddPriorityRuleRequest {
    rule: PriorityRule,
    changed_by: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UpdatePriorityRuleRequest {
    rule: PriorityRule,
    changed_by: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DeletePriorityRuleParams {
    changed_by: Option<String>,
}

#[derive(Debug, Serialize)]
struct PriorityRuleResponse {
    success: bool,
    rule_id: String,
    message: String,
}

// A/B Testing Types
#[derive(Debug, Deserialize)]
struct ABTestListParams {
    status: Option<ABTestStatus>,
    limit: Option<usize>,
    offset: Option<usize>,
}

#[derive(Debug, Serialize)]
struct ABTestListResponse {
    tests: Vec<ABTestSummary>,
}

#[derive(Debug, Deserialize)]
struct CreateABTestRequest {
    config: ABTestConfig,
    changed_by: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateABTestRequest {
    config: ABTestConfig,
    changed_by: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DeleteABTestParams {
    changed_by: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ABTestActionRequest {
    changed_by: Option<String>,
}

#[derive(Debug, Serialize)]
struct ABTestResponse {
    success: bool,
    test_id: String,
    message: String,
}

#[derive(Debug, Serialize)]
struct ABTestDetailsResponse {
    test: ABTestDetails,
}

#[derive(Debug, Deserialize)]
struct ABTestMetricsParams {
    start_time: Option<DateTime<Utc>>,
    end_time: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
struct ABTestMetricsResponse {
    metrics: ABTestMetrics,
}

// Traffic Splitting Types
#[derive(Debug, Serialize)]
struct TrafficSplitsResponse {
    splits: Vec<SplitConfig>,
}

#[derive(Debug, Deserialize)]
struct CreateTrafficSplitRequest {
    config: SplitConfig,
    changed_by: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateTrafficSplitRequest {
    config: SplitConfig,
    changed_by: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DeleteTrafficSplitParams {
    changed_by: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TrafficSplitActionRequest {
    changed_by: Option<String>,
}

#[derive(Debug, Serialize)]
struct TrafficSplitResponse {
    success: bool,
    split_id: String,
    message: String,
}

#[derive(Debug, Serialize)]
struct TrafficSplitDetailsResponse {
    split: SplitConfig,
}

// Graceful Shutdown Types
#[derive(Debug, Serialize)]
struct ShutdownConfigResponse {
    config: ShutdownConfig,
}

#[derive(Debug, Deserialize)]
struct UpdateShutdownConfigRequest {
    config: ShutdownConfig,
    changed_by: Option<String>,
}

#[derive(Debug, Serialize)]
struct ShutdownStatusResponse {
    status: ShutdownStatus,
}

#[derive(Debug, Deserialize)]
struct InitiateShutdownRequest {
    timeout: Option<Duration>,
    changed_by: Option<String>,
    reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CancelShutdownRequest {
    changed_by: Option<String>,
    reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DrainConnectionsRequest {
    timeout: Option<Duration>,
    changed_by: Option<String>,
}

#[derive(Debug, Serialize)]
struct ShutdownActionResponse {
    success: bool,
    shutdown_id: String,
    message: String,
}

#[derive(Debug, Serialize)]
struct DrainConnectionsResponse {
    success: bool,
    drained_count: usize,
    message: String,
}

// Overall Status and Metrics Types
#[derive(Debug, Serialize)]
struct TrafficStatusResponse {
    status: TrafficStatus,
}

#[derive(Debug, Deserialize)]
struct TrafficMetricsParams {
    start_time: Option<DateTime<Utc>>,
    end_time: Option<DateTime<Utc>>,
    include_historical: Option<bool>,
}

#[derive(Debug, Serialize)]
struct TrafficMetricsResponse {
    metrics: ComprehensiveTrafficMetrics,
}

#[derive(Debug, Serialize)]
struct TrafficHealthResponse {
    health: TrafficHealthStatus,
}

// Supporting Types (these would typically be defined in other modules)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriorityRule {
    pub id: String,
    pub name: String,
    pub condition: String,
    pub priority: u8,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ABTestStatus {
    Draft,
    Running,
    Paused,
    Completed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ABTestSummary {
    pub id: String,
    pub name: String,
    pub status: ABTestStatus,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub ended_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ABTestDetails {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub config: ABTestConfig,
    pub status: ABTestStatus,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub ended_at: Option<DateTime<Utc>>,
    pub created_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ABTestMetrics {
    pub test_id: String,
    pub total_requests: u64,
    pub variant_metrics: HashMap<String, VariantMetrics>,
    pub conversion_rates: HashMap<String, f64>,
    pub statistical_significance: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariantMetrics {
    pub requests: u64,
    pub conversions: u64,
    pub errors: u64,
    pub avg_response_time: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShutdownStatus {
    pub is_shutting_down: bool,
    pub shutdown_initiated_at: Option<DateTime<Utc>>,
    pub shutdown_timeout: Option<Duration>,
    pub active_connections: usize,
    pub pending_requests: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficStatus {
    pub queue_status: QueueStatus,
    pub shaping_status: ShapingStatus,
    pub priority_status: PriorityStatus,
    pub shutdown_status: ShutdownStatus,
    pub active_ab_tests: usize,
    pub active_splits: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueStatus {
    pub current_size: usize,
    pub max_size: usize,
    pub is_paused: bool,
    pub backpressure_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShapingStatus {
    pub global_rps_current: f64,
    pub global_rps_limit: Option<f64>,
    pub throttling_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriorityStatus {
    pub active_rules: usize,
    pub high_priority_queue_size: usize,
    pub normal_priority_queue_size: usize,
    pub low_priority_queue_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComprehensiveTrafficMetrics {
    pub queue_metrics: QueueMetrics,
    pub shaping_metrics: ShapingMetrics,
    pub priority_metrics: PriorityMetrics,
    pub ab_test_metrics: Vec<ABTestMetrics>,
    pub split_metrics: Vec<SplitMetrics>,
    pub overall_stats: OverallTrafficStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriorityMetrics {
    pub high_priority_processed: u64,
    pub normal_priority_processed: u64,
    pub low_priority_processed: u64,
    pub priority_violations: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SplitMetrics {
    pub split_id: String,
    pub total_requests: u64,
    pub variant_distribution: HashMap<String, u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverallTrafficStats {
    pub total_requests_processed: u64,
    pub total_requests_rejected: u64,
    pub average_response_time: Duration,
    pub error_rate: f64,
    pub uptime: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficHealthStatus {
    pub overall_health: HealthStatus,
    pub queue_health: HealthStatus,
    pub shaping_health: HealthStatus,
    pub priority_health: HealthStatus,
    pub shutdown_health: HealthStatus,
    pub last_check: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HealthStatus {
    Healthy,
    Warning,
    Critical,
    Unknown,
}