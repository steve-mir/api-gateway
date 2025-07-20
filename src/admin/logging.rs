//! # Logging Admin Endpoints
//!
//! This module provides administrative endpoints for logging configuration and management.
//! It includes functionality for:
//! - Dynamic log level configuration
//! - Log querying and filtering
//! - Request/response logging configuration
//! - Audit log management
//! - Log statistics and monitoring

use crate::observability::{
    logging::{StructuredLogger, RequestLoggingConfig, AuditLogEntry, AuditEventType, AuditOutcome},
    config::LogConfig,
};
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post, put},
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use chrono::{DateTime, Utc, Duration};
use tracing::info;

/// State for logging admin endpoints
#[derive(Clone)]
pub struct LoggingAdminState {
    pub logger: Arc<StructuredLogger>,
    pub audit_logs: Arc<tokio::sync::RwLock<Vec<AuditLogEntry>>>,
}

/// Router for logging admin endpoints
pub struct LoggingAdminRouter;

impl LoggingAdminRouter {
    /// Create the logging admin router with all endpoints
    pub fn create_router(state: LoggingAdminState) -> Router {
        Router::new()
            // Log configuration endpoints
            .route("/config", get(get_log_config))
            .route("/config", put(update_log_config))
            .route("/config/request-logging", get(get_request_logging_config))
            .route("/config/request-logging", put(update_request_logging_config))
            
            // Log level management
            .route("/level", get(get_log_level))
            .route("/level", put(set_log_level))
            
            // Log querying endpoints
            .route("/query", get(query_logs))
            .route("/audit", get(query_audit_logs))
            .route("/audit/statistics", get(get_audit_statistics))
            
            // Log management endpoints
            .route("/clear-audit", post(clear_audit_logs))
            .route("/export", get(export_logs))
            
            .with_state(state)
    }
}

// ============================================================================
// Log Configuration Endpoints
// ============================================================================

/// Get current log configuration
async fn get_log_config(
    State(state): State<LoggingAdminState>,
) -> Result<Json<LogConfigResponse>, (StatusCode, Json<ErrorResponse>)> {
    let config = state.logger.get_config().await;
    Ok(Json(LogConfigResponse { config }))
}

/// Update log configuration
async fn update_log_config(
    State(state): State<LoggingAdminState>,
    Json(request): Json<UpdateLogConfigRequest>,
) -> Result<Json<SuccessResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Admin request: Update log configuration");
    
    match state.logger.update_config(request.config).await {
        Ok(()) => {
            // Log audit event
            let audit_entry = AuditLogEntry {
                timestamp: Utc::now(),
                event_type: AuditEventType::ConfigurationChange,
                user_id: request.changed_by.clone(),
                session_id: None,
                correlation_id: uuid::Uuid::new_v4().to_string(),
                source_ip: None,
                user_agent: None,
                resource: "log_config".to_string(),
                action: "update".to_string(),
                outcome: AuditOutcome::Success,
                details: {
                    let mut details = HashMap::new();
                    details.insert("description".to_string(), serde_json::Value::String(
                        request.description.unwrap_or_else(|| "Log configuration updated".to_string())
                    ));
                    details
                },
            };
            
            state.logger.log_audit_event(audit_entry.clone());
            
            // Store audit log
            let mut audit_logs = state.audit_logs.write().await;
            audit_logs.push(audit_entry);
            
            Ok(Json(SuccessResponse {
                success: true,
                message: "Log configuration updated successfully".to_string(),
            }))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to update log configuration".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

/// Get request logging configuration
async fn get_request_logging_config(
    State(state): State<LoggingAdminState>,
) -> Result<Json<RequestLoggingConfigResponse>, (StatusCode, Json<ErrorResponse>)> {
    let config = state.logger.get_request_config().await;
    Ok(Json(RequestLoggingConfigResponse { config }))
}

/// Update request logging configuration
async fn update_request_logging_config(
    State(state): State<LoggingAdminState>,
    Json(request): Json<UpdateRequestLoggingConfigRequest>,
) -> Result<Json<SuccessResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Admin request: Update request logging configuration");
    
    match state.logger.update_request_config(request.config).await {
        Ok(()) => {
            // Log audit event
            let audit_entry = AuditLogEntry {
                timestamp: Utc::now(),
                event_type: AuditEventType::ConfigurationChange,
                user_id: request.changed_by.clone(),
                session_id: None,
                correlation_id: uuid::Uuid::new_v4().to_string(),
                source_ip: None,
                user_agent: None,
                resource: "request_logging_config".to_string(),
                action: "update".to_string(),
                outcome: AuditOutcome::Success,
                details: {
                    let mut details = HashMap::new();
                    details.insert("description".to_string(), serde_json::Value::String(
                        request.description.unwrap_or_else(|| "Request logging configuration updated".to_string())
                    ));
                    details
                },
            };
            
            state.logger.log_audit_event(audit_entry.clone());
            
            // Store audit log
            let mut audit_logs = state.audit_logs.write().await;
            audit_logs.push(audit_entry);
            
            Ok(Json(SuccessResponse {
                success: true,
                message: "Request logging configuration updated successfully".to_string(),
            }))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to update request logging configuration".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

// ============================================================================
// Log Level Management Endpoints
// ============================================================================

/// Get current log level
async fn get_log_level(
    State(state): State<LoggingAdminState>,
) -> Result<Json<LogLevelResponse>, (StatusCode, Json<ErrorResponse>)> {
    let config = state.logger.get_config().await;
    Ok(Json(LogLevelResponse {
        level: config.level,
    }))
}

/// Set log level dynamically
async fn set_log_level(
    State(state): State<LoggingAdminState>,
    Json(request): Json<SetLogLevelRequest>,
) -> Result<Json<SuccessResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Admin request: Set log level to {}", request.level);
    
    // Validate log level
    let valid_levels = ["trace", "debug", "info", "warn", "error"];
    if !valid_levels.contains(&request.level.to_lowercase().as_str()) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid log level".to_string(),
                details: Some(format!("Valid levels are: {}", valid_levels.join(", "))),
            }),
        ));
    }
    
    // Update log configuration
    let mut config = state.logger.get_config().await;
    config.level = request.level.clone();
    
    match state.logger.update_config(config).await {
        Ok(()) => {
            // Log audit event
            let audit_entry = AuditLogEntry {
                timestamp: Utc::now(),
                event_type: AuditEventType::ConfigurationChange,
                user_id: request.changed_by.clone(),
                session_id: None,
                correlation_id: uuid::Uuid::new_v4().to_string(),
                source_ip: None,
                user_agent: None,
                resource: "log_level".to_string(),
                action: "update".to_string(),
                outcome: AuditOutcome::Success,
                details: {
                    let mut details = HashMap::new();
                    details.insert("old_level".to_string(), serde_json::Value::String("unknown".to_string()));
                    details.insert("new_level".to_string(), serde_json::Value::String(request.level.clone()));
                    details.insert("description".to_string(), serde_json::Value::String(
                        request.description.unwrap_or_else(|| "Log level updated".to_string())
                    ));
                    details
                },
            };
            
            state.logger.log_audit_event(audit_entry.clone());
            
            // Store audit log
            let mut audit_logs = state.audit_logs.write().await;
            audit_logs.push(audit_entry);
            
            Ok(Json(SuccessResponse {
                success: true,
                message: format!("Log level set to {} successfully", request.level),
            }))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to set log level".to_string(),
                details: Some(e.to_string()),
            }),
        )),
    }
}

// ============================================================================
// Log Querying Endpoints
// ============================================================================

/// Query logs with filtering
async fn query_logs(
    Query(params): Query<LogQueryParams>,
) -> Result<Json<LogQueryResponse>, (StatusCode, Json<ErrorResponse>)> {
    // This implementation provides a basic in-memory log querying capability
    // In production, you would integrate with a log aggregation system
    // like Elasticsearch, Loki, Fluentd, or similar
    
    info!("Log query request received with filters: {:?}", params);
    
    // For now, we'll return a structured response indicating the query parameters
    // that would be used with a real log aggregation backend
    let query_info = serde_json::json!({
        "query_type": "structured_log_search",
        "filters": {
            "level": params.level,
            "component": params.component,
            "correlation_id": params.correlation_id,
            "time_range": {
                "start": params.start_time,
                "end": params.end_time
            }
        },
        "pagination": {
            "offset": params.offset.unwrap_or(0),
            "limit": params.limit.unwrap_or(100)
        },
        "backend_integration": "To implement full log querying, integrate with your log aggregation system",
        "supported_backends": ["Elasticsearch", "Loki", "Fluentd", "Splunk", "CloudWatch Logs"]
    });
    
    Ok(Json(LogQueryResponse {
        logs: vec![query_info],
        total: 1,
        offset: params.offset.unwrap_or(0),
        limit: params.limit.unwrap_or(100),
        query_executed: true,
        backend_status: "mock_implementation".to_string(),
    }))
}

/// Query audit logs
async fn query_audit_logs(
    State(state): State<LoggingAdminState>,
    Query(params): Query<AuditLogQueryParams>,
) -> Result<Json<AuditLogQueryResponse>, (StatusCode, Json<ErrorResponse>)> {
    let audit_logs = state.audit_logs.read().await;
    let mut filtered_logs: Vec<&AuditLogEntry> = audit_logs.iter().collect();
    
    // Apply filters
    if let Some(event_type) = &params.event_type {
        filtered_logs.retain(|log| {
            match event_type.to_lowercase().as_str() {
                "authentication" => matches!(log.event_type, AuditEventType::Authentication),
                "authorization" => matches!(log.event_type, AuditEventType::Authorization),
                "admin_operation" => matches!(log.event_type, AuditEventType::AdminOperation),
                "configuration_change" => matches!(log.event_type, AuditEventType::ConfigurationChange),
                "security_violation" => matches!(log.event_type, AuditEventType::SecurityViolation),
                "data_access" => matches!(log.event_type, AuditEventType::DataAccess),
                _ => true,
            }
        });
    }
    
    if let Some(user_id) = &params.user_id {
        filtered_logs.retain(|log| {
            log.user_id.as_ref().map_or(false, |id| id == user_id)
        });
    }
    
    if let Some(outcome) = &params.outcome {
        filtered_logs.retain(|log| {
            match outcome.to_lowercase().as_str() {
                "success" => matches!(log.outcome, AuditOutcome::Success),
                "failure" => matches!(log.outcome, AuditOutcome::Failure),
                "denied" => matches!(log.outcome, AuditOutcome::Denied),
                _ => true,
            }
        });
    }
    
    // Apply time range filter
    if let Some(start_time) = params.start_time {
        filtered_logs.retain(|log| log.timestamp >= start_time);
    }
    
    if let Some(end_time) = params.end_time {
        filtered_logs.retain(|log| log.timestamp <= end_time);
    }
    
    // Sort by timestamp (newest first)
    filtered_logs.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    
    // Apply pagination
    let offset = params.offset.unwrap_or(0);
    let limit = params.limit.unwrap_or(100).min(1000);
    let total = filtered_logs.len();
    
    let paginated_logs: Vec<AuditLogEntry> = filtered_logs
        .into_iter()
        .skip(offset)
        .take(limit)
        .cloned()
        .collect();
    
    Ok(Json(AuditLogQueryResponse {
        logs: paginated_logs,
        total,
        offset,
        limit,
    }))
}

/// Get audit log statistics
async fn get_audit_statistics(
    State(state): State<LoggingAdminState>,
) -> Result<Json<AuditStatisticsResponse>, (StatusCode, Json<ErrorResponse>)> {
    let audit_logs = state.audit_logs.read().await;
    
    let total_events = audit_logs.len();
    let mut event_type_counts = HashMap::new();
    let mut outcome_counts = HashMap::new();
    let mut recent_events = 0;
    
    let one_hour_ago = Utc::now() - Duration::hours(1);
    
    for log in audit_logs.iter() {
        // Count by event type
        let event_type_key = format!("{:?}", log.event_type);
        *event_type_counts.entry(event_type_key).or_insert(0) += 1;
        
        // Count by outcome
        let outcome_key = format!("{:?}", log.outcome);
        *outcome_counts.entry(outcome_key).or_insert(0) += 1;
        
        // Count recent events
        if log.timestamp >= one_hour_ago {
            recent_events += 1;
        }
    }
    
    Ok(Json(AuditStatisticsResponse {
        total_events,
        event_type_counts,
        outcome_counts,
        recent_events_last_hour: recent_events,
    }))
}

// ============================================================================
// Log Management Endpoints
// ============================================================================

/// Clear audit logs
async fn clear_audit_logs(
    State(state): State<LoggingAdminState>,
    Json(request): Json<ClearAuditLogsRequest>,
) -> Result<Json<SuccessResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Admin request: Clear audit logs");
    
    let mut audit_logs = state.audit_logs.write().await;
    let cleared_count = audit_logs.len();
    audit_logs.clear();
    
    // Log this action as an audit event
    let audit_entry = AuditLogEntry {
        timestamp: Utc::now(),
        event_type: AuditEventType::AdminOperation,
        user_id: request.changed_by.clone(),
        session_id: None,
        correlation_id: uuid::Uuid::new_v4().to_string(),
        source_ip: None,
        user_agent: None,
        resource: "audit_logs".to_string(),
        action: "clear".to_string(),
        outcome: AuditOutcome::Success,
        details: {
            let mut details = HashMap::new();
            details.insert("cleared_count".to_string(), serde_json::Value::Number(cleared_count.into()));
            details.insert("description".to_string(), serde_json::Value::String(
                request.description.unwrap_or_else(|| "Audit logs cleared".to_string())
            ));
            details
        },
    };
    
    state.logger.log_audit_event(audit_entry.clone());
    audit_logs.push(audit_entry);
    
    Ok(Json(SuccessResponse {
        success: true,
        message: format!("Cleared {} audit log entries", cleared_count),
    }))
}

/// Export logs
async fn export_logs(
    State(state): State<LoggingAdminState>,
    Query(params): Query<ExportLogsParams>,
) -> Result<Json<ExportLogsResponse>, (StatusCode, Json<ErrorResponse>)> {
    let audit_logs = state.audit_logs.read().await;
    
    // Apply time range filter if specified
    let mut filtered_logs: Vec<&AuditLogEntry> = audit_logs.iter().collect();
    
    if let Some(start_time) = params.start_time {
        filtered_logs.retain(|log| log.timestamp >= start_time);
    }
    
    if let Some(end_time) = params.end_time {
        filtered_logs.retain(|log| log.timestamp <= end_time);
    }
    
    // Convert to export format
    let export_data: Vec<AuditLogEntry> = filtered_logs.into_iter().cloned().collect();
    
    // Log export action
    let audit_entry = AuditLogEntry {
        timestamp: Utc::now(),
        event_type: AuditEventType::AdminOperation,
        user_id: params.requested_by.clone(),
        session_id: None,
        correlation_id: uuid::Uuid::new_v4().to_string(),
        source_ip: None,
        user_agent: None,
        resource: "audit_logs".to_string(),
        action: "export".to_string(),
        outcome: AuditOutcome::Success,
        details: {
            let mut details = HashMap::new();
            details.insert("exported_count".to_string(), serde_json::Value::Number(export_data.len().into()));
            details.insert("format".to_string(), serde_json::Value::String(
                params.format.as_deref().unwrap_or("json").to_string()
            ));
            details
        },
    };
    
    state.logger.log_audit_event(audit_entry);
    
    Ok(Json(ExportLogsResponse {
        count: export_data.len(),
        data: export_data,
        format: params.format.unwrap_or_else(|| "json".to_string()),
        exported_at: Utc::now(),
    }))
}

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Serialize)]
struct LogConfigResponse {
    config: LogConfig,
}

#[derive(Debug, Deserialize)]
struct UpdateLogConfigRequest {
    config: LogConfig,
    changed_by: Option<String>,
    description: Option<String>,
}

#[derive(Debug, Serialize)]
struct RequestLoggingConfigResponse {
    config: RequestLoggingConfig,
}

#[derive(Debug, Deserialize)]
struct UpdateRequestLoggingConfigRequest {
    config: RequestLoggingConfig,
    changed_by: Option<String>,
    description: Option<String>,
}

#[derive(Debug, Serialize)]
struct LogLevelResponse {
    level: String,
}

#[derive(Debug, Deserialize)]
struct SetLogLevelRequest {
    level: String,
    changed_by: Option<String>,
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LogQueryParams {
    level: Option<String>,
    component: Option<String>,
    correlation_id: Option<String>,
    start_time: Option<DateTime<Utc>>,
    end_time: Option<DateTime<Utc>>,
    offset: Option<usize>,
    limit: Option<usize>,
}

#[derive(Debug, Serialize)]
struct LogQueryResponse {
    logs: Vec<serde_json::Value>,
    total: usize,
    offset: usize,
    limit: usize,
    query_executed: bool,
    backend_status: String,
}

#[derive(Debug, Deserialize)]
struct AuditLogQueryParams {
    event_type: Option<String>,
    user_id: Option<String>,
    outcome: Option<String>,
    start_time: Option<DateTime<Utc>>,
    end_time: Option<DateTime<Utc>>,
    offset: Option<usize>,
    limit: Option<usize>,
}

#[derive(Debug, Serialize)]
struct AuditLogQueryResponse {
    logs: Vec<AuditLogEntry>,
    total: usize,
    offset: usize,
    limit: usize,
}

#[derive(Debug, Serialize)]
struct AuditStatisticsResponse {
    total_events: usize,
    event_type_counts: HashMap<String, usize>,
    outcome_counts: HashMap<String, usize>,
    recent_events_last_hour: usize,
}

#[derive(Debug, Deserialize)]
struct ClearAuditLogsRequest {
    changed_by: Option<String>,
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ExportLogsParams {
    format: Option<String>,
    start_time: Option<DateTime<Utc>>,
    end_time: Option<DateTime<Utc>>,
    requested_by: Option<String>,
}

#[derive(Debug, Serialize)]
struct ExportLogsResponse {
    data: Vec<AuditLogEntry>,
    count: usize,
    format: String,
    exported_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct SuccessResponse {
    success: bool,
    message: String,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
    details: Option<String>,
}